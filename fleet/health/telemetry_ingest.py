"""fleet.health.telemetry_ingest — pure ingest + query layer for CHR telemetry.

This module is the panel-side implementation of the telemetry contract in
``docs/contracts/fleet_api.md §1``. The Flask route in
``fleet.health.routes_telemetry`` is a thin shell around the functions here;
all parsing/validation/persistence/aggregation lives in this module so:

* The brain (Phase 5) and the dashboard can call the same functions from
  inside the app without going through HTTP.
* Tests can exercise the boundary without needing the test client.

Persistence target
------------------
Samples are inserted into ``fleet_chr_metrics`` (``fleet.health.models_health.FleetChrMetric``)
with ``source='proxy'``. The table is append-only time-series; no UPDATEs.

Payload mapping (contract → model)
----------------------------------
The contract is the source of truth and its names are kept verbatim on the
wire. The mapping into the ``FleetChrMetric`` columns is:

  cpu_util          (0.0..1.0)  → cpu_pct          (× 100, NUMERIC(5,2))
  mem_util          (0.0..1.0)  → mem_pct          (× 100, NUMERIC(5,2))
  active_sessions   (int)       → active_sessions
  latency_ms        (float)     → ping_rtt_ms      (carried as ping for §2.4)
  egress_gb_period  (float GB)  → tx_bytes         (× 1e9 bytes, cumulative-ish)

Fields the contract carries but the model does not have a dedicated column for
(``session_capacity``, ``egress_gbps``, ``uptime_seconds``) are accepted by
validation but not persisted as columns in this Phase-4 deliverable — they
remain in the wire payload for the brain to consume live, and adding columns
later is an additive migration. This is documented in the route docstring so
the proxy team is not surprised when introspecting metrics rows.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable

from sqlalchemy import desc

from app.extensions import db
from fleet.config import FLEET
from fleet.health.models_health import FleetChrMetric
from fleet.registry.models_chr import FleetChrNode


# ─────────────────────────────────────────────────────────────────────────────
# Errors
# ─────────────────────────────────────────────────────────────────────────────
class TelemetryValidationError(ValueError):
    """Raised when a payload is malformed. The route converts to 400."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(detail or code)
        self.code = code
        self.detail = detail


class UnknownNodeError(LookupError):
    """Raised when the named node is not enrolled. The route converts to 404."""

    def __init__(self, node: str) -> None:
        super().__init__(node)
        self.node = node


# ─────────────────────────────────────────────────────────────────────────────
# Normalised in-memory shape
# ─────────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class TelemetrySample:
    """Validated payload as seen by the rest of the panel.

    Keeps the contract's field names so call-sites and logs read the same as the
    wire shape. ``metrics`` is a dict (not a dataclass) because individual keys
    are optional per §1 and we want missing-key semantics, not zeroed defaults.
    """

    node: str
    sampled_at: datetime
    metrics: dict[str, Any]
    agent_version: str | None = None


# ─────────────────────────────────────────────────────────────────────────────
# Validation
# ─────────────────────────────────────────────────────────────────────────────
#: Required envelope fields per docs/contracts/fleet_api.md §1.
_REQUIRED_TOP = ("node", "sampled_at", "metrics")

#: Metric keys we recognise. Unknown keys are tolerated (the contract is open
#: to extension); they are simply not persisted. Each entry maps key→validator.
_METRIC_RANGES: dict[str, tuple[type, float | None, float | None]] = {
    "cpu_util":         (float, 0.0, 1.0),
    "mem_util":         (float, 0.0, 1.0),
    "active_sessions":  (int,   0,   None),
    "session_capacity": (int,   0,   None),
    "latency_ms":       (float, 0.0, None),
    "egress_gbps":      (float, 0.0, None),
    "egress_gb_period": (float, 0.0, None),
    "uptime_seconds":   (int,   0,   None),
}


def _parse_iso8601_utc(raw: Any) -> datetime:
    """Parse an ISO-8601 timestamp; tolerate the ``Z`` suffix.

    Returns a NAIVE UTC datetime to match the project's ``utcnow()`` convention
    in ``app.models``. The contract specifies ``Z`` suffix so we reject the
    obviously-wrong shapes loudly rather than silently accepting localtime.
    """
    if not isinstance(raw, str) or not raw.strip():
        raise TelemetryValidationError("bad_request", "sampled_at must be ISO-8601 string")
    text = raw.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError as exc:
        raise TelemetryValidationError("bad_request", f"sampled_at unparseable: {raw!r}") from exc
    if dt.tzinfo is None:
        # Be strict: contract says UTC with Z. Treat naive as a malformed payload.
        raise TelemetryValidationError("bad_request", "sampled_at must include UTC tz (Z)")
    return dt.astimezone(timezone.utc).replace(tzinfo=None)


def _coerce_number(value: Any, kind: type) -> int | float:
    """Convert JSON number / numeric string to int/float; reject everything else."""
    if isinstance(value, bool):
        # JSON ``true``/``false`` are ints under the hood — reject them as
        # metrics so a bug in the emitter is loud.
        raise TelemetryValidationError("bad_request", "boolean is not a valid metric value")
    if kind is int:
        if isinstance(value, int):
            return value
        if isinstance(value, float) and value.is_integer():
            return int(value)
        raise TelemetryValidationError("bad_request", f"expected integer, got {type(value).__name__}")
    if kind is float:
        if isinstance(value, (int, float)):
            return float(value)
        raise TelemetryValidationError("bad_request", f"expected number, got {type(value).__name__}")
    raise TelemetryValidationError("bad_request", "unexpected metric type")  # pragma: no cover


def validate(payload: Any) -> TelemetrySample:
    """Return a ``TelemetrySample`` for a well-formed payload or raise.

    Rules (verbatim from §1):

    * Top-level must contain ``node``, ``sampled_at``, ``metrics``.
    * ``metrics`` is a dict; unknown keys are ignored, known keys are typed
      + range-checked. Any individual metric MAY be omitted.
    * ``sampled_at`` is ISO-8601 with UTC ``Z``.
    * ``agent_version`` is optional (string when present).
    """
    if not isinstance(payload, dict):
        raise TelemetryValidationError("bad_request", "payload must be a JSON object")

    missing = [k for k in _REQUIRED_TOP if k not in payload]
    if missing:
        raise TelemetryValidationError("bad_request", f"missing fields: {','.join(missing)}")

    node = payload.get("node")
    if not isinstance(node, str) or not node.strip():
        raise TelemetryValidationError("bad_request", "node must be a non-empty string")
    node = node.strip()

    sampled_at = _parse_iso8601_utc(payload.get("sampled_at"))

    raw_metrics = payload.get("metrics")
    if not isinstance(raw_metrics, dict):
        raise TelemetryValidationError("bad_request", "metrics must be a JSON object")

    metrics: dict[str, int | float] = {}
    for key, value in raw_metrics.items():
        spec = _METRIC_RANGES.get(key)
        if spec is None:
            # Tolerate forward-compatible keys; the contract reserves room.
            continue
        kind, lo, hi = spec
        coerced = _coerce_number(value, kind)
        if lo is not None and coerced < lo:
            raise TelemetryValidationError("bad_request", f"{key} below minimum {lo}")
        if hi is not None and coerced > hi:
            raise TelemetryValidationError("bad_request", f"{key} above maximum {hi}")
        metrics[key] = coerced

    agent_version = payload.get("agent_version")
    if agent_version is not None and not isinstance(agent_version, str):
        raise TelemetryValidationError("bad_request", "agent_version must be a string when present")

    return TelemetrySample(
        node=node,
        sampled_at=sampled_at,
        metrics=metrics,
        agent_version=(agent_version or None),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Node lookup
# ─────────────────────────────────────────────────────────────────────────────
def _resolve_node(name: str) -> FleetChrNode:
    node = FleetChrNode.query.filter_by(name=name).first()
    if node is None:
        raise UnknownNodeError(name)
    return node


# ─────────────────────────────────────────────────────────────────────────────
# Persistence — append-only
# ─────────────────────────────────────────────────────────────────────────────
_GB_TO_BYTES = 1_000_000_000  # decimal GB → bytes (matches how vendors report egress)


def _to_metric_row(node: FleetChrNode, sample: TelemetrySample) -> FleetChrMetric:
    """Translate the contract metrics into a single ``FleetChrMetric`` row.

    See module docstring for the field mapping. Anything that doesn't have a
    column today is left as ``None`` rather than coerced into the wrong column.
    """
    m = sample.metrics
    row = FleetChrMetric(
        chr_id=node.id,
        ts=sample.sampled_at,
        source="proxy",
        cpu_pct=(m["cpu_util"] * 100.0) if "cpu_util" in m else None,
        mem_pct=(m["mem_util"] * 100.0) if "mem_util" in m else None,
        active_sessions=m.get("active_sessions"),
        rx_bytes=None,
        tx_bytes=(int(m["egress_gb_period"] * _GB_TO_BYTES) if "egress_gb_period" in m else None),
        ping_rtt_ms=m.get("latency_ms"),
        ping_loss_pct=None,
    )
    return row


def ingest(sample: TelemetrySample) -> tuple[FleetChrNode, FleetChrMetric]:
    """Persist a validated sample.

    Returns the matched node + the inserted row so the route can build the
    contract response (which needs the node row for ``drain`` + health). The
    caller is responsible for ``db.session.commit()`` — we add to the session
    and return; the route commits once, alongside any audit row it logs.
    """
    node = _resolve_node(sample.node)
    row = _to_metric_row(node, sample)
    db.session.add(row)
    return node, row


def ingest_payload(payload: Any) -> tuple[FleetChrNode, FleetChrMetric, TelemetrySample]:
    """One-shot: validate → ingest. Used by the route.

    Returning the parsed ``TelemetrySample`` as well lets the route emit
    response fields without re-parsing.
    """
    sample = validate(payload)
    node, row = ingest(sample)
    return node, row, sample


# ─────────────────────────────────────────────────────────────────────────────
# Query helpers — for the dashboard + the future brain (Phase 5)
# ─────────────────────────────────────────────────────────────────────────────
def latest_metrics(node: int | str) -> FleetChrMetric | None:
    """Most-recent telemetry row for ``node`` (id or registry name); ``None``
    if the node has never reported."""
    chr_id = _id_for(node)
    if chr_id is None:
        return None
    return (
        FleetChrMetric.query
        .filter_by(chr_id=chr_id)
        .order_by(desc(FleetChrMetric.ts), desc(FleetChrMetric.id))
        .first()
    )


def rolling_window(node: int | str, n: int = 10) -> dict[str, float | int | None]:
    """Aggregate the last ``n`` samples for ``node`` into the brain-friendly
    shape (averages + headline current sessions).

    Output keys::

        {
          "samples":              <int, 0..n>,
          "avg_cpu_pct":          float | None,
          "avg_mem_pct":          float | None,
          "avg_active_sessions":  float | None,
          "avg_latency_ms":       float | None,
          "last_active_sessions": int   | None,
          "last_ts":              datetime | None,
        }

    ``None`` is preserved for missing columns rather than zero — a scorer that
    treats ``None`` as neutral (per §1) sees the correct cardinality. The
    function is the canonical aggregate so the dashboard and the brain show the
    same numbers; tests pin it to a deterministic dataset.
    """
    if n <= 0:
        raise ValueError("rolling window size must be >= 1")
    chr_id = _id_for(node)
    if chr_id is None:
        return _empty_window()

    rows: list[FleetChrMetric] = (
        FleetChrMetric.query
        .filter_by(chr_id=chr_id)
        .order_by(desc(FleetChrMetric.ts), desc(FleetChrMetric.id))
        .limit(n)
        .all()
    )
    if not rows:
        return _empty_window()
    return {
        "samples":              len(rows),
        "avg_cpu_pct":          _avg(r.cpu_pct for r in rows),
        "avg_mem_pct":          _avg(r.mem_pct for r in rows),
        "avg_active_sessions":  _avg(r.active_sessions for r in rows),
        "avg_latency_ms":       _avg(r.ping_rtt_ms for r in rows),
        "last_active_sessions": rows[0].active_sessions,
        "last_ts":              rows[0].ts,
    }


def _empty_window() -> dict[str, float | int | None]:
    return {
        "samples": 0,
        "avg_cpu_pct": None,
        "avg_mem_pct": None,
        "avg_active_sessions": None,
        "avg_latency_ms": None,
        "last_active_sessions": None,
        "last_ts": None,
    }


def _avg(values: Iterable[Any]) -> float | None:
    nums = [float(v) for v in values if v is not None]
    if not nums:
        return None
    return sum(nums) / len(nums)


def _id_for(node: int | str) -> int | None:
    if isinstance(node, int):
        return node
    row = FleetChrNode.query.filter_by(name=node).first()
    return row.id if row else None


# ─────────────────────────────────────────────────────────────────────────────
# Directives + health for the response envelope
# ─────────────────────────────────────────────────────────────────────────────
def directives_for(node: FleetChrNode, sample: TelemetrySample) -> dict[str, bool]:
    """Compute the ``directives`` block of the §1 response.

    * ``shed``: cpu_util at/above the configured shed threshold. We use the
      just-arrived sample (not a rolling average) — the contract says ``shed``
      is true *once* cpu crosses the threshold; the brain hysteresis is applied
      later by the health state machine.
    * ``drain``: comes off the node row (admin-set, see fleet_chr_nodes.drain).
    """
    cpu = sample.metrics.get("cpu_util")
    shed_threshold_ratio = FLEET.health.cpu_shed_threshold_pct / 100.0
    shed = bool(cpu is not None and cpu >= shed_threshold_ratio)
    drain = bool(node.drain)
    return {"shed": shed, "drain": drain}


def health_for(node: FleetChrNode, sample: TelemetrySample) -> str:
    """Best-effort post-sample health string.

    Phase-4 task B (this module) does not own the hysteresis state machine —
    task A (``fleet.health.health_state``) does. Until that lands we return
    the cheapest sensible answer:

    * "shedding" if the directives say shed.
    * "down" if the node row is already disabled.
    * "up" otherwise.

    When task A merges, this helper will defer to its ``state_of(name)`` API.
    """
    if not node.enabled:
        return "down"
    if directives_for(node, sample)["shed"]:
        return "shedding"
    return "up"


__all__ = [
    "TelemetryValidationError",
    "UnknownNodeError",
    "TelemetrySample",
    "validate",
    "ingest",
    "ingest_payload",
    "latest_metrics",
    "rolling_window",
    "directives_for",
    "health_for",
]
