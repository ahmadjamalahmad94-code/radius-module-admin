"""fleet.notify.models_alert — Phase 2 task T4.

SQLAlchemy models for the CHR-fleet **events + alerts** layer:

* :class:`Event` — append-only health/failover/move/onboarding event log.
  One row per discrete transition or actuator call. ``kind`` is a
  free-form short token (the catalog of known values is enumerated in
  :data:`EVENT_KINDS` so it can evolve with the code, not the schema).
* :class:`Alert` — owner notifications + delivery status. Each row is
  scheduled for ONE channel and ONE recipient. ``dedupe_key`` + the
  partial-unique index (``uq_alert_dedupe``) collapse storms: while a
  queued/sent row with the same key exists, the notifier MUST NOT
  re-enqueue the same message.

Schema source: ``docs/chr_fleet/02_DATA_MODEL.md`` §2.9. The matching
PostgreSQL DDL lives in ``migrations/004_events_alerts.sql`` and is the
production migration path; these models give the panel's dev SQLite
``db.create_all()`` an equivalent shape (with the JSONB ``detail``
column stored as TEXT JSON — same convention as :mod:`app.models`).

Importing this module is enough to register the tables on the shared
``db`` MetaData; the unit test in ``tests/fleet/test_p2_t3_t4.py`` does
exactly that before calling ``db.create_all()``.
"""
from __future__ import annotations

from app.extensions import db
from app.models import json_dumps, json_loads


# ──────────────────────────── shared constants ────────────────────────────

#: Canonical catalog of event ``kind`` values. The schema column itself is
#: free-form TEXT (so producers can introduce a new kind without a
#: migration), but the notifier's rule matrix (P9-T3) MUST handle every
#: value listed here. Keep this list in sync with §02 §2.9.
EVENT_KINDS: tuple[str, ...] = (
    "health_down",
    "health_up",
    "failover_start",
    "failover_done",
    "cap_warn",
    "cap_breach",
    "onboard_ok",
    "onboard_fail",
    "dns_update",
    "coa_sent",
    "move_ok",
    "move_fail",
    "flap_suppressed",
)

#: Allowed values for :attr:`Event.severity` (mirrors the CHECK).
EVENT_SEVERITIES: tuple[str, ...] = ("info", "warn", "crit")

#: Allowed channels for :attr:`Alert.channel`.
ALERT_CHANNELS: tuple[str, ...] = ("sms", "whatsapp", "telegram")

#: Allowed values for :attr:`Alert.status`.
ALERT_STATUSES: tuple[str, ...] = ("queued", "sent", "failed", "suppressed")

#: The two statuses that hold a ``dedupe_key`` slot (used by the partial-
#: unique index and by the notifier's pre-insert check).
ALERT_ACTIVE_STATUSES: frozenset[str] = frozenset({"queued", "sent"})


# ──────────────────────────── events (§2.9) ────────────────────────────
class Event(db.Model):
    """Health / failover / move / onboarding event log row.

    ``chr_id`` may be NULL for fleet-wide events (e.g. ``dns_update`` or
    a ``cap_warn`` aggregated across providers). The ``detail`` payload
    is per-kind structured data — the consumer (notifier / UI) is
    expected to know the shape for the kinds it cares about.
    """

    __tablename__ = "fleet_events"
    __table_args__ = (
        db.Index("idx_events_chr_ts", "chr_id", "ts"),
        db.Index("idx_events_kind",   "kind", "ts"),
        db.CheckConstraint(
            "severity IN ('info','warn','crit')",
            name="ck_events_severity",
        ),
    )

    id = db.Column(db.Integer, primary_key=True)
    ts = db.Column(db.DateTime, nullable=False, default=db.func.now())
    chr_id = db.Column(
        db.Integer,
        db.ForeignKey("fleet_chr_nodes.id"),
        nullable=True,
    )
    kind = db.Column(db.String(40), nullable=False)
    severity = db.Column(db.String(8), nullable=False, default="info")
    # JSONB in Postgres → TEXT-JSON elsewhere. Accessed via :attr:`detail`.
    detail_json = db.Column(db.Text, nullable=False, default="{}")

    @property
    def detail(self) -> dict:
        """Decoded per-kind payload. Always a ``dict``."""
        value = json_loads(self.detail_json, {})
        return value if isinstance(value, dict) else {}

    @detail.setter
    def detail(self, value: dict | None) -> None:
        self.detail_json = json_dumps(value or {})

    def __repr__(self) -> str:  # pragma: no cover - dev/debug only
        return f"<Event {self.kind} chr={self.chr_id} sev={self.severity}>"


# ──────────────────────────── alerts (§2.9) ────────────────────────────
class Alert(db.Model):
    """One scheduled owner notification, single-channel + single-recipient.

    Storm suppression: ``dedupe_key`` + ``uq_alert_dedupe`` enforce
    "while a queued/sent row with the same key exists, no second row for
    the same key may be inserted." A NULL ``dedupe_key`` opts OUT of
    suppression and is used for one-off operator pushes.

    Producers should pick a stable, deterministic dedupe_key per logical
    incident — e.g. ``f"chr:{chr_id}:{kind}"`` so the same condition
    yields the same key across the storm.
    """

    __tablename__ = "fleet_alerts"
    __table_args__ = (
        # Storm guard: partial-unique on dedupe_key over (queued, sent).
        # SQLAlchemy threads ``sqlite_where`` / ``postgresql_where`` into
        # the CREATE INDEX so SQLite (dev) and Postgres (prod) emit the
        # same partial index.
        db.Index(
            "uq_alert_dedupe",
            "dedupe_key",
            unique=True,
            sqlite_where=db.text("status IN ('queued','sent')"),
            postgresql_where=db.text("status IN ('queued','sent')"),
        ),
        db.Index("idx_alerts_status_created",  "status", "created_at"),
        db.Index("idx_alerts_channel_created", "channel", "created_at"),
        db.CheckConstraint(
            "channel IN ('sms','whatsapp','telegram')",
            name="ck_alerts_channel",
        ),
        db.CheckConstraint(
            "status IN ('queued','sent','failed','suppressed')",
            name="ck_alerts_status",
        ),
    )

    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(
        db.Integer,
        db.ForeignKey("fleet_events.id"),
        nullable=True,
    )
    created_at = db.Column(db.DateTime, nullable=False, default=db.func.now())
    channel = db.Column(db.String(20), nullable=False)
    recipient = db.Column(db.String(255), nullable=False)
    body = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(16), nullable=False, default="queued")
    sent_at = db.Column(db.DateTime, nullable=True)
    # NULL = opt out of dedupe (one-off operator pushes). Otherwise the
    # partial-unique index guards the (queued, sent) slot.
    dedupe_key = db.Column(db.String(120), nullable=True)
    retries = db.Column(db.Integer, nullable=False, default=0)

    def __repr__(self) -> str:  # pragma: no cover - dev/debug only
        return (
            f"<Alert {self.channel} {self.recipient!r} {self.status} "
            f"dedupe={self.dedupe_key!r}>"
        )


__all__ = [
    "Event",
    "Alert",
    "EVENT_KINDS",
    "EVENT_SEVERITIES",
    "ALERT_CHANNELS",
    "ALERT_STATUSES",
    "ALERT_ACTIVE_STATUSES",
]
