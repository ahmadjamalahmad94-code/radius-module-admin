"""fleet.ui.dashboard_data — read-only adapter for the fleet dashboard view.

Single source the dashboard goes through to fetch the per-node health + metrics
roll-up. Centralising it here means:

1. The template + route stay declarative; they just consume the returned dict
   shapes and never write SQL.
2. When Phase-4 task **A/B** (telemetry ingest + health monitor) ships its
   proper query helpers — e.g. ``fleet.health.queries.latest_metric_for(chr_id)``
   — only THIS module needs to flip from the direct-read fallback to the
   helper. The route/template stay untouched.

Until that ships we read the raw tables:

* ``FleetChrHealth`` is 1:1 with chr_nodes (PK = chr_id), so a single SELECT
  IN(<ids>) covers everything.
* ``FleetChrMetric`` is append-only time-series. We pull the latest row per
  node via a per-group ``max(ts)`` correlated subquery — portable across SQLite
  (tests) + PostgreSQL (prod). This is O(N) row scans on SQLite; acceptable for
  the ≤50-node dashboard cap, and the proper helper will use ``DISTINCT ON``
  on PG / a window function on SQLite.

All returned dicts use **plain Python types** (no ORM rows leak out); the
template is free to render them without touching the session. Numerics come
back as Decimals where the column was Decimal — Jinja prints them cleanly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Iterable

from sqlalchemy import and_, func, select

from app.extensions import db
from fleet.health.models_health import HEALTH_STATES, FleetChrHealth, FleetChrMetric
from fleet.registry.models_chr import FleetChrNode


# ────────────────────────────────────────────────────────────────────────────
# View-model shapes (plain dataclasses → easy to pass into Jinja / jsonify)
# ────────────────────────────────────────────────────────────────────────────


@dataclass
class HealthView:
    """Per-node rolling health row as the dashboard sees it.

    ``state`` is always one of ``HEALTH_STATES`` — including the default
    "unknown" when no row exists yet (we synthesise the shape so the template
    has stable field access without ``{% if x is defined %}`` clutter).
    """

    state: str = "unknown"
    consecutive_fail: int = 0
    consecutive_ok: int = 0
    state_since: datetime | None = None
    last_transition: str | None = None
    flap_count_1h: int = 0


@dataclass
class MetricsView:
    """Latest telemetry sample for a node.

    All fields are nullable — a brand-new node has no metric row yet, and
    individual sensors may be omitted by the agent (see the frozen
    `/api/proxy/telemetry` contract in ``docs/contracts/fleet_api.md``).
    """

    ts: datetime | None = None
    cpu_pct: float | None = None
    mem_pct: float | None = None
    active_sessions: int | None = None
    rx_bytes: int | None = None
    tx_bytes: int | None = None
    ping_rtt_ms: float | None = None
    ping_loss_pct: float | None = None
    source: str | None = None


@dataclass
class NodeView:
    """The fleet dashboard's per-row payload — node + health + latest metric.

    Kept as a plain composition so the template renders ``view.health.state``
    etc. without juggling tuples or ``getattr(node, ...)``.
    """

    node: FleetChrNode
    health: HealthView = field(default_factory=HealthView)
    metric: MetricsView = field(default_factory=MetricsView)

    @property
    def last_seen_at(self) -> datetime | None:
        """The freshest "we heard from this node" timestamp — prefer the metric
        ts (newest by definition) then fall back to the node's registry
        ``last_seen_at`` (set by the control-plane ping). ``None`` if neither."""
        return self.metric.ts or self.node.last_seen_at


# ────────────────────────────────────────────────────────────────────────────
# Loader — one DB hit per table, joined in Python by chr_id.
# ────────────────────────────────────────────────────────────────────────────


def build_node_views(nodes: Iterable[FleetChrNode]) -> list[NodeView]:
    """Return one ``NodeView`` per input node, in input order.

    Two extra queries total regardless of input size (no N+1):
      1. ``SELECT * FROM fleet_chr_health WHERE chr_id IN (...)``
      2. Latest metric per chr_id via correlated ``max(ts)`` subquery.
    """
    nodes_list = list(nodes)
    if not nodes_list:
        return []
    chr_ids = [n.id for n in nodes_list]

    health_by_chr: dict[int, FleetChrHealth] = {
        h.chr_id: h
        for h in FleetChrHealth.query.filter(FleetChrHealth.chr_id.in_(chr_ids)).all()
    }

    # Latest metric per node: subquery picks the max(ts) for each chr_id, the
    # outer join brings the row back. Portable to SQLite + PostgreSQL; on PG
    # the proper helper from fleet.health (Phase-4 A/B) will replace this with
    # DISTINCT ON for index-friendliness.
    latest_ts_subq = (
        select(FleetChrMetric.chr_id, func.max(FleetChrMetric.ts).label("max_ts"))
        .where(FleetChrMetric.chr_id.in_(chr_ids))
        .group_by(FleetChrMetric.chr_id)
        .subquery()
    )
    latest_rows = (
        db.session.query(FleetChrMetric)
        .join(
            latest_ts_subq,
            and_(
                FleetChrMetric.chr_id == latest_ts_subq.c.chr_id,
                FleetChrMetric.ts == latest_ts_subq.c.max_ts,
            ),
        )
        .all()
    )
    metric_by_chr: dict[int, FleetChrMetric] = {m.chr_id: m for m in latest_rows}

    views: list[NodeView] = []
    for node in nodes_list:
        h = health_by_chr.get(node.id)
        m = metric_by_chr.get(node.id)
        views.append(
            NodeView(
                node=node,
                health=_health_to_view(h),
                metric=_metric_to_view(m),
            )
        )
    return views


def get_node_view(node: FleetChrNode) -> NodeView:
    """Single-node convenience — used by the AJAX check_now response."""
    return build_node_views([node])[0]


# ────────────────────────────────────────────────────────────────────────────
# Plain-Python conversion (so jsonify + Jinja both get clean values)
# ────────────────────────────────────────────────────────────────────────────


def _health_to_view(h: FleetChrHealth | None) -> HealthView:
    if h is None:
        return HealthView()
    return HealthView(
        state=h.state if h.state in HEALTH_STATES else "unknown",
        consecutive_fail=int(h.consecutive_fail or 0),
        consecutive_ok=int(h.consecutive_ok or 0),
        state_since=h.state_since,
        last_transition=h.last_transition,
        flap_count_1h=int(h.flap_count_1h or 0),
    )


def _metric_to_view(m: FleetChrMetric | None) -> MetricsView:
    if m is None:
        return MetricsView()
    return MetricsView(
        ts=m.ts,
        cpu_pct=float(m.cpu_pct) if m.cpu_pct is not None else None,
        mem_pct=float(m.mem_pct) if m.mem_pct is not None else None,
        active_sessions=int(m.active_sessions) if m.active_sessions is not None else None,
        rx_bytes=int(m.rx_bytes) if m.rx_bytes is not None else None,
        tx_bytes=int(m.tx_bytes) if m.tx_bytes is not None else None,
        ping_rtt_ms=float(m.ping_rtt_ms) if m.ping_rtt_ms is not None else None,
        ping_loss_pct=float(m.ping_loss_pct) if m.ping_loss_pct is not None else None,
        source=m.source,
    )


# ────────────────────────────────────────────────────────────────────────────
# Aggregate roll-ups for the KPI strip — health-driven, not registry-driven.
# ────────────────────────────────────────────────────────────────────────────


def health_state_counts(views: Iterable[NodeView]) -> dict[str, int]:
    """Aggregate health states across the fleet for the KPI strip.

    The existing KPIs counted ``node.status`` (registry lifecycle:
    provisioning/disabled/...). Phase-4 surfaces the *health* dimension
    (unknown/up/degraded/down) which is what the operator actually wants at a
    glance. Both are exposed in the template so neither view is lost.
    """
    counts = {s: 0 for s in HEALTH_STATES}
    for v in views:
        counts[v.health.state] = counts.get(v.health.state, 0) + 1
    return counts


# ────────────────────────────────────────────────────────────────────────────
# check_now — request a fresh health evaluation for a single node.
#
# Phase-4 task A/B owns the real monitor. The expected callable is:
#
#   from fleet.health.monitor import check_now
#   result = check_now(chr_id)   # returns a dict with at least {"ok": bool}
#
# Until that lands, we degrade gracefully WITHOUT lying about the state:
#   * if a metric arrived in the last STALE_AFTER_S seconds → bump
#     consecutive_ok, transition unknown/down→up.
#   * otherwise → bump consecutive_fail; once it crosses DOWN_THRESHOLD
#     transition up/unknown→down.
#
# Mirrors the simplest spirit of the §2.5 state machine so the dashboard's
# "فحص الآن" button does something meaningful even before the monitor ships,
# and the wiring (form → POST → row refresh) is verified end-to-end.
# ────────────────────────────────────────────────────────────────────────────


# Seam constants. Tunable via app config; defaults match common health-check
# windows so the fallback is sensible without further configuration.
STALE_AFTER_S = 90       # last metric older than this counts as a miss
DOWN_THRESHOLD = 3        # consecutive_fail to flip up→down


def check_now(chr_id: int, *, now: datetime | None = None) -> dict:
    """Re-evaluate one node's health, persisting any transition.

    Strategy:
      1. If ``fleet.health.monitor.check_now`` exists, delegate to it (lets
         the real monitor land later without touching this file).
      2. Else, run the inline fallback against the latest metric row.

    Returns ``{"ok": True, "checked": "monitor"|"fallback",
               "state": "<state>", "transition": "...|null"}``.
    """
    delegated = _try_delegate_to_monitor(chr_id)
    if delegated is not None:
        return delegated
    return _fallback_check(chr_id, now=now or datetime.utcnow())


def _try_delegate_to_monitor(chr_id: int) -> dict | None:
    """Soft import so a missing monitor module never breaks the dashboard.

    The real monitor (``fleet.health.monitor.check_now``) returns a
    ``RunSummary`` dataclass — NOT a dict. Before this fix the wrapper
    only special-cased dicts and fell through to ``{"ok": True,
    "checked": "monitor"}`` for the dataclass, so the dashboard JS read
    no ``state`` and the toast said «الحالة الآن: غير معروفة عبر مراقب
    الصحّة» even when the monitor had just marked the node ``up``.
    Unpack the outcome for ``chr_id`` into the shape the UI expects.
    """
    try:
        from fleet.health.monitor import check_now as monitor_check_now  # type: ignore[attr-defined]
    except Exception:
        return None
    try:
        result = monitor_check_now(chr_id)
    except Exception as exc:  # pragma: no cover - defensive
        return {"ok": False, "checked": "monitor", "error": str(exc)[:160]}
    if isinstance(result, dict):
        result.setdefault("checked", "monitor")
        return result
    # Dataclass path (RunSummary). Find the outcome row for our node.
    outcomes = list(getattr(result, "outcomes", ()) or ())
    outcome = next((o for o in outcomes if int(getattr(o, "chr_id", -1)) == int(chr_id)), None)

    # Fold in the persisted FleetChrHealth row so consecutive counters
    # land in the same response shape as the fallback path uses.
    health = db.session.get(FleetChrHealth, chr_id)
    if outcome is None and health is None:
        return {"ok": True, "checked": "monitor",
                "state": "unknown", "error": "monitor reported no outcome"}

    state = (
        getattr(outcome, "state", None)
        or (health.state if health is not None else "unknown")
    )
    transition_obj = getattr(outcome, "transition", None) if outcome is not None else None
    transition = (
        f"{transition_obj.from_state}->{transition_obj.to_state}"
        if transition_obj is not None else None
    )
    return {
        "ok": bool(outcome.ok) if outcome is not None else (state == "up"),
        "checked": "monitor",
        "state": state,
        "latency_ms": getattr(outcome, "latency_ms", None) if outcome is not None else None,
        "consecutive_fail": int(health.consecutive_fail or 0) if health is not None else 0,
        "consecutive_ok":   int(health.consecutive_ok or 0)   if health is not None else 0,
        "transition": transition,
    }


def _fallback_check(chr_id: int, *, now: datetime) -> dict:
    """Conservative re-evaluation when no monitor is wired yet."""
    node = db.session.get(FleetChrNode, chr_id)
    if node is None:
        return {"ok": False, "checked": "fallback", "error": "node not found"}

    # Newest metric row (single row — no need to load the full series).
    latest: FleetChrMetric | None = (
        FleetChrMetric.query
        .filter(FleetChrMetric.chr_id == chr_id)
        .order_by(FleetChrMetric.ts.desc())
        .first()
    )

    # Lazy-create the health row so the next check has somewhere to land.
    health = db.session.get(FleetChrHealth, chr_id)
    if health is None:
        health = FleetChrHealth(chr_id=chr_id, state="unknown", state_since=now)
        db.session.add(health)

    is_fresh = bool(latest and latest.ts and (now - latest.ts) <= timedelta(seconds=STALE_AFTER_S))
    transition: str | None = None

    if is_fresh:
        health.consecutive_ok = (health.consecutive_ok or 0) + 1
        health.consecutive_fail = 0
        health.first_fail_at = None
        if health.state != "up":
            transition = f"{health.state}->up"
            health.state = "up"
            health.state_since = now
            health.last_transition = transition
    else:
        health.consecutive_fail = (health.consecutive_fail or 0) + 1
        health.consecutive_ok = 0
        if health.first_fail_at is None:
            health.first_fail_at = now
        if health.state != "down" and health.consecutive_fail >= DOWN_THRESHOLD:
            transition = f"{health.state}->down"
            health.state = "down"
            health.state_since = now
            health.last_transition = transition

    db.session.commit()
    return {
        "ok": True,
        "checked": "fallback",
        "state": health.state,
        "consecutive_fail": int(health.consecutive_fail or 0),
        "consecutive_ok": int(health.consecutive_ok or 0),
        "transition": transition,
        "stale_after_s": STALE_AFTER_S,
        "metric_age_s": int((now - latest.ts).total_seconds()) if (latest and latest.ts) else None,
    }


__all__ = [
    "HealthView",
    "MetricsView",
    "NodeView",
    "build_node_views",
    "get_node_view",
    "health_state_counts",
    "check_now",
    "STALE_AFTER_S",
    "DOWN_THRESHOLD",
]
