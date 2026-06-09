"""fleet.registry.models_onboarding — onboarding wizard state machine record.

ORM mirror of the ``onboarding_jobs`` table (see ``migrations/005_onboarding_dns.sql``
and ``docs/chr_fleet/02_DATA_MODEL.md §2.10``). One row per wizard run.

Lifecycle (per ``docs/chr_fleet/06_ONBOARDING_WIZARD.md §6.2``)::

    draft → keys_generated → script_generated → pushed → verifying → active
                                                                  ↘ failed
                                                              failed → script_generated (retry)

Phase-2 deliverable: the model only. Service layer that drives transitions and
generates the WG keypair / RouterOS script ships in Phase 3 (P3-T1..T4).

Database portability
--------------------
The migration file is PostgreSQL-flavoured (BIGSERIAL, JSONB, TIMESTAMPTZ); this
model uses the project's standard portable types so it works against either the
production Postgres schema OR the SQLite test DB used in unit/CI runs. JSON
payloads (``form_input``, ``verify_report``) are stored as text and exposed via
dict properties, matching the convention already in ``app/models.py``.
"""

from __future__ import annotations

from typing import Any

from app.extensions import db
from app.models import TimestampMixin, json_dumps, json_loads

# Import the registry model so ``fleet_chr_nodes`` is registered on the shared
# metadata before this module's FK resolves; also gives us the portable id type
# so the FK column matches the referenced PK type exactly (BIGINT/INTEGER variant).
from fleet.registry.models_chr import BigIntID


#: Allowed transitions for ``OnboardingJob.status``. Pulled out of the model so
#: the Phase-3 service layer can ``import`` it without instantiating SQLAlchemy.
#: Mirrors the state diagram in 06_ONBOARDING_WIZARD.md §6.2 exactly.
ONBOARDING_STATUSES: tuple[str, ...] = (
    "draft",
    "keys_generated",
    "script_generated",
    "pushed",
    "verifying",
    "active",
    "failed",
)

#: Transition graph keyed by current state → set of permitted next states.
#: The Phase-3 service uses this to guard ``update_status`` calls so a wizard
#: can never jump (e.g.) ``draft → active``.
ONBOARDING_TRANSITIONS: dict[str, frozenset[str]] = {
    "draft":            frozenset({"keys_generated", "failed"}),
    "keys_generated":   frozenset({"script_generated", "failed"}),
    "script_generated": frozenset({"pushed", "failed"}),
    "pushed":           frozenset({"verifying", "failed"}),
    "verifying":        frozenset({"active", "failed"}),
    "active":           frozenset(),                              # terminal-success
    "failed":           frozenset({"script_generated"}),          # retry edge
}


def can_transition(current: str, target: str) -> bool:
    """Return True if ``current → target`` is a legal status edge per §6.2."""
    return target in ONBOARDING_TRANSITIONS.get(current, frozenset())


class OnboardingJob(TimestampMixin, db.Model):
    """A single CHR onboarding wizard run.

    Created in the ``draft`` state the moment the wizard form is submitted;
    walks the state machine above as the panel mints keys, renders the
    unified RouterOS script, pushes it via the one-time bootstrap channel,
    and verifies the new node. ``chr_id`` is populated once the
    corresponding ``chr_nodes`` row has been created (this is why the FK is
    nullable in the migration — see §2.10).
    """

    __tablename__ = "fleet_onboarding_jobs"
    __table_args__ = (
        db.Index("idx_onboarding_jobs_status", "status"),
        db.Index("idx_onboarding_jobs_chr_id", "chr_id"),
    )

    # Integer rather than BigInteger so SQLite (used in tests) treats this as
    # ROWID and autoincrements; Postgres production uses BIGSERIAL as declared
    # in the migration — both map cleanly to Python ``int`` either way.
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    # Nullable FK: set once the fleet_chr_nodes row is created (status >=
    # 'pushed' typically). The FK targets the fleet registry node table
    # (fleet_chr_nodes), NOT the legacy CHR-console chr_nodes. ON DELETE SET
    # NULL mirrors migrations/005_onboarding_dns.sql so a decommissioned node
    # leaves the job row intact for audit.
    chr_id = db.Column(
        BigIntID,
        db.ForeignKey("fleet_chr_nodes.id", ondelete="SET NULL"),
        nullable=True,
    )

    status = db.Column(
        db.String(40),
        nullable=False,
        default="draft",
        server_default="draft",
        index=True,
    )

    # JSON-encoded text columns for portability — Postgres production runs
    # via JSONB in the migration; we round-trip through ``json_loads``/
    # ``json_dumps`` here.
    form_input_json = db.Column(db.Text, nullable=False, default="{}", server_default="{}")
    wg_keypair_ref = db.Column(db.Text, nullable=True)
    generated_script_ref = db.Column(db.Text, nullable=True)
    verify_report_json = db.Column(db.Text, nullable=True)

    # ────────────────────────────────────────────────────────────────────
    # JSON property sugar (mirrors the dict-property convention from
    # ``app/models.py`` so callers can treat these as dicts).
    # ────────────────────────────────────────────────────────────────────
    @property
    def form_input(self) -> dict[str, Any]:
        return json_loads(self.form_input_json, {})

    @form_input.setter
    def form_input(self, value: dict[str, Any] | None) -> None:
        self.form_input_json = json_dumps(value or {})

    @property
    def verify_report(self) -> dict[str, Any] | None:
        if self.verify_report_json is None:
            return None
        return json_loads(self.verify_report_json, {})

    @verify_report.setter
    def verify_report(self, value: dict[str, Any] | None) -> None:
        self.verify_report_json = None if value is None else json_dumps(value)

    # ────────────────────────────────────────────────────────────────────
    # State-machine helpers (no DB writes — caller commits)
    # ────────────────────────────────────────────────────────────────────
    def can_advance_to(self, target: str) -> bool:
        """Return True if ``self.status → target`` is permitted by §6.2."""
        return can_transition(self.status, target)

    def advance(self, target: str) -> None:
        """Move to ``target`` if the edge is legal, else raise ``ValueError``.

        Pure in-memory: persistence is the caller's job (commit, audit, etc.).
        """
        if target not in ONBOARDING_STATUSES:
            raise ValueError(f"unknown onboarding status: {target!r}")
        if not self.can_advance_to(target):
            raise ValueError(
                f"illegal onboarding transition: {self.status!r} → {target!r}"
            )
        self.status = target

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<OnboardingJob id={self.id} status={self.status!r} chr_id={self.chr_id}>"
