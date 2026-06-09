"""fleet.brain.models_session — Phase 2 task T3.

SQLAlchemy models for the CHR-fleet **placement** layer:

* :class:`UserFleet` — per-user fleet record keyed by ``user@realm`` carrying
  the ``movable`` flag (governs rebalance, NOT forced failover) and a
  read-only mirror of the authoritative ``Framed-IP-Address`` from
  ``radius-module``. Also holds an optional ``pinned_chr_id`` (sticky
  preference).
* :class:`Session` — ground-truth placement: which user is on which CHR
  right now, plus the RADIUS ``Acct-Session-Id``. Two partial-unique
  indexes enforce goal **G2** (no duplicate ``framed_ip`` active) and
  one-active-session-per-user fleet-wide.
* :class:`PlacementDecision` — brain audit log: every move (new /
  rebalance / forced_failover / manual) records ``from`` / ``to`` and the
  per-factor score breakdown that justified it.

Schema source: ``docs/chr_fleet/02_DATA_MODEL.md`` §§2.6–2.8. The matching
PostgreSQL DDL lives in ``migrations/003_users_sessions.sql`` and is the
production migration path; these models give the panel's dev SQLite
``db.create_all()`` an equivalent shape (with the JSONB column stored as
TEXT JSON — convention used throughout :mod:`app.models`).

Importing this module is enough to register the tables on the shared
``db`` MetaData; the unit test in ``tests/fleet/test_p2_t3_t4.py`` does
exactly that before calling ``db.create_all()``.
"""
from __future__ import annotations

from app.extensions import db
from app.models import TimestampMixin, json_dumps, json_loads


# ──────────────────────────── shared constants ────────────────────────────

#: Allowed values for :attr:`Session.state` (mirrors the CHECK constraint
#: in 003_users_sessions.sql §2.7).
SESSION_STATES: tuple[str, ...] = ("active", "closing", "closed")

#: Allowed values for :attr:`PlacementDecision.kind` (§2.8).
DECISION_KINDS: tuple[str, ...] = (
    "new",                # first placement on connect
    "rebalance",          # cost/load-driven move within margin (movable only)
    "forced_failover",    # CHR went DOWN — movable flag IGNORED
    "manual",             # operator-triggered relocate
)

#: Allowed values for :attr:`PlacementDecision.outcome` (§2.8).
DECISION_OUTCOMES: tuple[str, ...] = ("pending", "applied", "failed", "skipped")


# ──────────────────────────── users_fleet (§2.6) ────────────────────────────
class UserFleet(TimestampMixin, db.Model):
    """Per-user fleet record. Mirrors the RADIUS identity (``user@realm``).

    The :attr:`movable` flag is the contract between the owner and the
    customer — it governs **normal rebalancing only**. During a forced
    failover the brain MUST ignore it (see §05 §5.6).
    """

    __tablename__ = "fleet_users"
    __table_args__ = (
        db.UniqueConstraint("username", name="uq_users_fleet_username"),
        db.Index("idx_users_fleet_customer", "customer_id"),
        db.Index("idx_users_fleet_realm", "realm"),
        # Hot index for the rebalance planner — most users are immovable.
        db.Index("idx_users_movable", "movable"),
    )

    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.BigInteger, nullable=False)
    realm = db.Column(db.String(255), nullable=False)
    # Full ``user@realm`` lowercased — the same key the RADIUS proxy uses.
    username = db.Column(db.String(255), nullable=False)
    movable = db.Column(db.Boolean, nullable=False, default=False)
    # Read-only mirror of radius-module's authoritative Framed-IP-Address
    # mapping. INET in Postgres → 45-char string elsewhere (IPv4-mapped
    # IPv6 is 39 chars; we keep slack for textual edge cases).
    fixed_ip = db.Column(db.String(45), nullable=True)
    # Optional sticky preference: if set + node healthy, the brain will
    # prefer this CHR for the user (still subject to scoring).
    pinned_chr_id = db.Column(
        db.Integer,
        db.ForeignKey("fleet_chr_nodes.id"),
        nullable=True,
    )

    def __repr__(self) -> str:  # pragma: no cover - dev/debug only
        return f"<UserFleet {self.username!r} movable={self.movable}>"


# ──────────────────────────── sessions (§2.7) ────────────────────────────
class Session(db.Model):
    """Ground-truth placement: which CHR is serving this user *right now*.

    Populated by the proxy's ``POST /api/proxy/placement`` hook on
    Acct-Start / Acct-Stop. The two partial-unique indexes are the
    database-level enforcement of:

    * goal **G2** — a fixed IP must not be active on two CHRs at once
      (``uq_active_ip``).
    * one active session per user fleet-wide (``uq_active_session_per_user``).

    The application layer + CoA close the old row before/while inserting
    the new one (see §04 §4.4).
    """

    __tablename__ = "fleet_sessions"
    __table_args__ = (
        # Partial-unique indexes are emitted with a WHERE clause on the
        # Postgres dialect; on SQLite SQLAlchemy honours it as a partial
        # index too (>=3.8), giving the same single-survivor invariant.
        db.Index(
            "uq_active_session_per_user",
            "username",
            unique=True,
            sqlite_where=db.text("state = 'active'"),
            postgresql_where=db.text("state = 'active'"),
        ),
        db.Index(
            "uq_active_ip",
            "framed_ip",
            unique=True,
            sqlite_where=db.text("state = 'active'"),
            postgresql_where=db.text("state = 'active'"),
        ),
        db.Index(
            "idx_sessions_chr",
            "chr_id",
            sqlite_where=db.text("state = 'active'"),
            postgresql_where=db.text("state = 'active'"),
        ),
        db.Index("idx_sessions_user_started", "username", "started_at"),
        db.CheckConstraint(
            "state IN ('active','closing','closed')",
            name="ck_sessions_state",
        ),
    )

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), nullable=False)
    realm = db.Column(db.String(255), nullable=False)
    chr_id = db.Column(
        db.Integer,
        db.ForeignKey("fleet_chr_nodes.id"),
        nullable=False,
    )
    framed_ip = db.Column(db.String(45), nullable=False)
    acct_session_id = db.Column(db.String(80), nullable=False)
    nas_ip = db.Column(db.String(45), nullable=True)
    state = db.Column(db.String(16), nullable=False, default="active")
    started_at = db.Column(db.DateTime, nullable=False, default=db.func.now())
    last_acct_at = db.Column(db.DateTime, nullable=True)
    closed_at = db.Column(db.DateTime, nullable=True)
    bytes_in = db.Column(db.BigInteger, nullable=False, default=0)
    bytes_out = db.Column(db.BigInteger, nullable=False, default=0)

    def __repr__(self) -> str:  # pragma: no cover - dev/debug only
        return (
            f"<Session {self.username!r} chr={self.chr_id} "
            f"ip={self.framed_ip} state={self.state}>"
        )


# ──────────────────────────── placement_decisions (§2.8) ────────────────
class PlacementDecision(db.Model):
    """Brain audit row: one per placement / move attempt.

    ``reason`` holds the full per-factor score breakdown snapshot so every
    decision is explainable after the fact. Stored as TEXT-encoded JSON for
    dialect portability (the production Postgres migration uses a JSONB
    column; the panel's own JSON convention — see :func:`app.models.json_dumps`
    — preserves the same shape under SQLite).
    """

    __tablename__ = "fleet_placement_decisions"
    __table_args__ = (
        db.Index("idx_pd_user", "username", "decided_at"),
        db.Index("idx_pd_kind_decided", "kind", "decided_at"),
        db.CheckConstraint(
            "kind IN ('new','rebalance','forced_failover','manual')",
            name="ck_pd_kind",
        ),
        db.CheckConstraint(
            "outcome IN ('pending','applied','failed','skipped')",
            name="ck_pd_outcome",
        ),
    )

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), nullable=False)
    decided_at = db.Column(db.DateTime, nullable=False, default=db.func.now())
    kind = db.Column(db.String(20), nullable=False)
    from_chr_id = db.Column(
        db.Integer,
        db.ForeignKey("fleet_chr_nodes.id"),
        nullable=True,
    )
    to_chr_id = db.Column(
        db.Integer,
        db.ForeignKey("fleet_chr_nodes.id"),
        nullable=True,
    )
    # JSONB in Postgres → TEXT-JSON elsewhere. Access via :attr:`reason`.
    reason_json = db.Column(db.Text, nullable=False, default="{}")
    outcome = db.Column(db.String(20), nullable=False, default="pending")

    @property
    def reason(self) -> dict:
        """Decoded score-breakdown payload. Always a ``dict``."""
        value = json_loads(self.reason_json, {})
        return value if isinstance(value, dict) else {}

    @reason.setter
    def reason(self, value: dict | None) -> None:
        self.reason_json = json_dumps(value or {})

    def __repr__(self) -> str:  # pragma: no cover - dev/debug only
        return (
            f"<PlacementDecision {self.kind} {self.username!r} "
            f"{self.from_chr_id}->{self.to_chr_id} {self.outcome}>"
        )


__all__ = [
    "UserFleet",
    "Session",
    "PlacementDecision",
    "SESSION_STATES",
    "DECISION_KINDS",
    "DECISION_OUTCOMES",
]
