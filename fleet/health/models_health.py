"""fleet.health.models_health — ORM models for telemetry + rolling health state.

Tables (schema = docs/chr_fleet/02_DATA_MODEL.md §2.4–§2.5, owned by this panel):

  * ``fleet_chr_metrics`` — time-series live samples per node (CPU, sessions, bytes, ping) (doc §2.4)
  * ``fleet_chr_health``  — one rolling health-state row per node, with flap control (doc §2.5)

Both reference ``fleet_chr_nodes`` (defined in fleet.registry.models_chr). We import
that module so the parent table is registered on the shared metadata before these
are created — mirroring the migration order (001 providers+chr_nodes, then 002 here).
The ``fleet_`` table prefix avoids colliding with the panel's existing ``chr_nodes``
table; see fleet.registry.models_chr for the full rationale.

Cross-dialect mapping follows fleet.registry.models_chr (TIMESTAMPTZ->DateTime,
BIGINT->BigIntID, NUMERIC->Numeric). TimescaleDB's ``create_hypertable`` on
chr_metrics is intentionally NOT applied here (optional/prod-only); the
``(chr_id, ts)`` index gives good locality on plain PostgreSQL/SQLite too.
"""
from __future__ import annotations

from app.extensions import db
from app.models import TimestampMixin, utcnow

# Reusing the registry's portable id type also guarantees chr_nodes is registered
# on db.metadata before chr_metrics/chr_health resolve their foreign keys.
from fleet.registry.models_chr import BigIntID

METRIC_SOURCES = ("control", "ping", "proxy")
HEALTH_STATES = ("unknown", "up", "degraded", "down")


class FleetChrMetric(db.Model):
    """One telemetry sample for a node (§2.4).

    ``rx_bytes``/``tx_bytes`` are CUMULATIVE interface counters; bandwidth used per
    billing cycle is derived by diffing them over time (handling reboot resets) —
    that derivation lives in the brain, not here. This table is append-only.
    """

    __tablename__ = "fleet_chr_metrics"
    __table_args__ = (
        db.CheckConstraint(
            "source IN ('control','ping','proxy')", name="ck_fleet_chr_metrics_source"
        ),
        db.Index("idx_fleet_metrics_chr_ts", "chr_id", "ts"),
    )

    id = db.Column(BigIntID, primary_key=True)
    chr_id = db.Column(
        BigIntID,
        db.ForeignKey("fleet_chr_nodes.id", ondelete="CASCADE"),
        nullable=False,
    )
    ts = db.Column(db.DateTime, nullable=False, default=utcnow)
    cpu_pct = db.Column(db.Numeric(5, 2))
    mem_pct = db.Column(db.Numeric(5, 2))
    active_sessions = db.Column(db.Integer)
    rx_bytes = db.Column(db.BigInteger)              # cumulative interface counter
    tx_bytes = db.Column(db.BigInteger)              # cumulative interface counter
    ping_rtt_ms = db.Column(db.Numeric(7, 2))
    ping_loss_pct = db.Column(db.Numeric(5, 2))
    source = db.Column(db.String(16), nullable=False, default="control")  # control|ping|proxy

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"<ChrMetric chr={self.chr_id} ts={self.ts} cpu={self.cpu_pct}>"


class FleetChrHealth(db.Model):
    """Rolling health state + hysteresis/flap control for one node (§2.5).

    Primary-keyed by ``chr_id`` (exactly one current-state row per node, 1:1 with
    chr_nodes). The brain only flips UP->DOWN once ``consecutive_fail`` crosses the
    down threshold AND ``state_since`` respects the cooldown; ``flap_count_1h``
    dampens nodes that bounce repeatedly.
    """

    __tablename__ = "fleet_chr_health"
    __table_args__ = (
        db.CheckConstraint(
            "state IN ('unknown','up','degraded','down')", name="ck_fleet_chr_health_state"
        ),
    )

    chr_id = db.Column(
        BigIntID,
        db.ForeignKey("fleet_chr_nodes.id", ondelete="CASCADE"),
        primary_key=True,
    )
    state = db.Column(db.String(16), nullable=False, default="unknown")
    consecutive_fail = db.Column(db.Integer, nullable=False, default=0)  # failed windows in a row
    consecutive_ok = db.Column(db.Integer, nullable=False, default=0)
    first_fail_at = db.Column(db.DateTime)                              # when current down-streak began
    state_since = db.Column(db.DateTime, nullable=False, default=utcnow)  # for cooldown/hysteresis
    last_transition = db.Column(db.String(32))                         # e.g. 'up->down'
    flap_count_1h = db.Column(db.Integer, nullable=False, default=0)   # transitions in last hour

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"<ChrHealth chr={self.chr_id} {self.state} fails={self.consecutive_fail}>"


__all__ = [
    "FleetChrMetric",
    "FleetChrHealth",
    "METRIC_SOURCES",
    "HEALTH_STATES",
]
