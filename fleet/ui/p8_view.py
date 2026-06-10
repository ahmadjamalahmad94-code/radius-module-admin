"""fleet.ui.p8_view — read-only view models for the Phase-8 rebalance UI.

This module owns the READ side of the rebalance/failover page: it shapes
``fleet_placement_decisions`` + ``fleet_events`` + per-node telemetry into
the small set of dataclasses the template renders.

Pure functions only. No DB writes here; the route module owns mutations
(``rebalance_now``, ``evacuate_node``) and reads through these helpers.
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable, Sequence

from sqlalchemy import desc

from app.extensions import db
from app.models import utcnow

from fleet.brain.models_session import PlacementDecision
from fleet.health.models_health import FleetChrMetric
from fleet.notify.models_alert import Event
from fleet.registry.models_chr import FleetChrNode


# ─────────────────────────────────────────────────────────────────────────────
# Per-node headroom
# ─────────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class NodeHeadroom:
    """Spare-session capacity for one CHR.

    The template renders this as a single horizontal bar split into
    "used" + "free" so the operator can see at a glance if the fleet
    can absorb a failover of any one node.
    """

    node_id: int
    name: str
    status: str
    enabled: bool
    drain: bool
    active_sessions: int        # latest sample (or denorm if no metric yet)
    max_sessions: int           # declared from onboarding
    free_sessions: int          # max - active, clamped at 0
    utilization_pct: int        # 0..100 used capacity
    public_ip: str

    @property
    def at_risk(self) -> bool:
        """True if utilisation is high enough that one peer failing would
        not fit elsewhere. The 70% threshold mirrors the
        ``cpu_shed_threshold_pct`` default in fleet.config.HealthConfig
        for visual consistency, not policy."""
        return self.utilization_pct >= 70

    @property
    def at_capacity(self) -> bool:
        return self.max_sessions > 0 and self.active_sessions >= self.max_sessions


def _latest_metric_active_sessions(chr_id: int) -> int | None:
    row = (
        FleetChrMetric.query
        .filter(FleetChrMetric.chr_id == chr_id)
        .order_by(desc(FleetChrMetric.ts), desc(FleetChrMetric.id))
        .first()
    )
    if row is None:
        return None
    return row.active_sessions


def headroom_for(node: FleetChrNode) -> NodeHeadroom:
    latest = _latest_metric_active_sessions(node.id)
    active = int(latest if latest is not None else (node.active_sessions or 0))
    max_sessions = int(node.max_sessions or 0)
    free = max(0, max_sessions - active)
    if max_sessions > 0:
        util = max(0, min(100, math.floor((active * 100) / max_sessions)))
    else:
        util = 0
    return NodeHeadroom(
        node_id=int(node.id),
        name=node.name or f"chr-{node.id}",
        status=str(node.status or "unknown"),
        enabled=bool(node.enabled),
        drain=bool(node.drain),
        active_sessions=active,
        max_sessions=max_sessions,
        free_sessions=free,
        utilization_pct=int(util),
        public_ip=str(node.public_ip or ""),
    )


def all_headrooms() -> list[NodeHeadroom]:
    """Headroom row for every node, sorted by utilisation desc.

    Order is so a busy / over-cap node sits at the top — that's what
    the operator wants to see first.
    """
    nodes = FleetChrNode.query.order_by(FleetChrNode.name.asc()).all()
    rows = [headroom_for(n) for n in nodes]
    rows.sort(key=lambda r: (-r.utilization_pct, r.name))
    return rows


@dataclass(frozen=True)
class FleetCapacity:
    """Fleet-wide capacity totals used by the headline summary card."""

    nodes: int
    healthy_nodes: int                # status == 'up' + enabled + not drain
    total_capacity: int
    total_active: int
    total_free: int
    utilization_pct: int
    biggest_node_load: int            # active_sessions on the most-loaded node
    can_absorb_biggest: bool          # free elsewhere ≥ biggest_node_load


def fleet_capacity(headrooms: Sequence[NodeHeadroom] | None = None) -> FleetCapacity:
    rows = list(headrooms) if headrooms is not None else all_headrooms()
    nodes = len(rows)
    healthy = sum(
        1 for r in rows if r.enabled and not r.drain and r.status in ("up", "degraded")
    )
    total_cap = sum(r.max_sessions for r in rows)
    total_active = sum(r.active_sessions for r in rows)
    total_free = max(0, total_cap - total_active)
    if total_cap > 0:
        util = max(0, min(100, math.floor((total_active * 100) / total_cap)))
    else:
        util = 0
    biggest = max((r.active_sessions for r in rows), default=0)
    # "can_absorb": if we lost the biggest node, do the others have enough
    # remaining headroom to take its load?
    others_free = total_free  # already excludes used; biggest node's free is part of it
    others_free_excl_biggest = others_free
    # find the node with biggest load and subtract its own free from the pool
    for r in rows:
        if r.active_sessions == biggest:
            others_free_excl_biggest = max(0, total_free - r.free_sessions)
            break
    can_absorb = (biggest == 0) or (others_free_excl_biggest >= biggest)
    return FleetCapacity(
        nodes=nodes, healthy_nodes=healthy,
        total_capacity=total_cap,
        total_active=total_active,
        total_free=total_free,
        utilization_pct=util,
        biggest_node_load=biggest,
        can_absorb_biggest=can_absorb,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Plans / decisions feed
# ─────────────────────────────────────────────────────────────────────────────
#: Decision ``kind`` values this page surfaces. ``new`` is not a rebalance,
#: so we omit it; placement_decision uses ``manual`` for operator-forced
#: moves which we count alongside rebalances.
_PLAN_KINDS: tuple[str, ...] = ("rebalance", "forced_failover", "manual")

#: Events that belong on the rebalance feed (vs general fleet events).
_PLAN_EVENT_KINDS: frozenset[str] = frozenset({
    "rebalance_planned",
    "rebalance_started",
    "rebalance_completed",
    "rebalance_failed",
    "failover_started",
    "failover_completed",
    "evacuation_started",
    "evacuation_completed",
})


@dataclass(frozen=True)
class DecisionRow:
    """One placement decision row formatted for the template."""

    id: int
    username: str
    decided_at: datetime
    kind: str
    outcome: str
    from_node: str
    to_node: str
    reason: dict


@dataclass(frozen=True)
class PlanGroup:
    """One "plan" = a batch of decisions that share an audit fingerprint.

    The orchestrator records each plan as a sequence of
    ``fleet_placement_decisions`` rows tagged with ``plan_id`` inside
    ``reason_json``. We group those into a single PlanGroup so the
    template can show "plan abc12345 — 7 moves, 6 applied, 1 failed".
    Decisions without a recorded ``plan_id`` are grouped by
    (kind, decided_at minute) as a fallback so legacy rows still
    aggregate sensibly.
    """

    plan_id: str
    kind: str                  # rebalance | forced_failover | manual
    earliest: datetime
    latest: datetime
    decisions: list[DecisionRow] = field(default_factory=list)
    trigger: str = ""
    source_node: str = ""

    @property
    def moves_attempted(self) -> int:
        return len(self.decisions)

    @property
    def moves_applied(self) -> int:
        return sum(1 for d in self.decisions if d.outcome == "applied")

    @property
    def moves_failed(self) -> int:
        return sum(1 for d in self.decisions if d.outcome == "failed")

    @property
    def moves_pending(self) -> int:
        return sum(1 for d in self.decisions if d.outcome == "pending")

    @property
    def moves_skipped(self) -> int:
        return sum(1 for d in self.decisions if d.outcome == "skipped")

    @property
    def headline_outcome(self) -> str:
        """Single-cell summary used for the row's status pill."""
        if self.moves_failed and not (self.moves_applied or self.moves_pending):
            return "failed"
        if self.moves_pending:
            return "pending"
        if self.moves_applied and not self.moves_failed:
            return "applied"
        if self.moves_failed:
            return "partial"
        return "skipped"


def _name_of(node_lookup: dict[int, FleetChrNode], chr_id: int | None) -> str:
    if not chr_id:
        return ""
    node = node_lookup.get(chr_id)
    return node.name if node else f"chr#{chr_id}"


def recent_plans(*, limit: int = 50) -> list[PlanGroup]:
    """Return the most recent plan groups, newest first.

    ``limit`` caps how many decision ROWS we consider — the resulting
    plan count is naturally smaller. 50 rows comfortably covers the
    last few rebalance batches without dragging the page on a busy
    fleet; the route can override.
    """
    rows = (
        PlacementDecision.query
        .filter(PlacementDecision.kind.in_(_PLAN_KINDS))
        .order_by(desc(PlacementDecision.decided_at))
        .limit(limit)
        .all()
    )
    if not rows:
        return []

    node_lookup = {n.id: n for n in FleetChrNode.query.all()}
    groups: dict[str, PlanGroup] = {}

    for row in rows:
        reason = row.reason or {}
        plan_id = str(reason.get("plan_id") or "")
        if not plan_id:
            # Fallback grouping: same kind + same minute bucket.
            bucket = row.decided_at.strftime("%Y%m%d%H%M") if row.decided_at else "—"
            plan_id = f"legacy:{row.kind}:{bucket}"
        dec = DecisionRow(
            id=int(row.id),
            username=str(row.username or ""),
            decided_at=row.decided_at or utcnow(),
            kind=str(row.kind or "rebalance"),
            outcome=str(row.outcome or "pending"),
            from_node=_name_of(node_lookup, row.from_chr_id),
            to_node=_name_of(node_lookup, row.to_chr_id),
            reason=reason,
        )
        grp = groups.get(plan_id)
        if grp is None:
            grp = PlanGroup(
                plan_id=plan_id,
                kind=dec.kind,
                earliest=dec.decided_at,
                latest=dec.decided_at,
                decisions=[dec],
                trigger=str(reason.get("trigger") or ""),
                source_node=str(reason.get("source_node") or ""),
            )
            groups[plan_id] = grp
        else:
            # PlanGroup is frozen — rebuild with updated fields.
            new_decisions = grp.decisions + [dec]
            earliest = min(grp.earliest, dec.decided_at)
            latest = max(grp.latest, dec.decided_at)
            groups[plan_id] = PlanGroup(
                plan_id=grp.plan_id, kind=grp.kind,
                earliest=earliest, latest=latest,
                decisions=new_decisions,
                trigger=grp.trigger or str(reason.get("trigger") or ""),
                source_node=grp.source_node or str(reason.get("source_node") or ""),
            )

    ordered = sorted(groups.values(), key=lambda g: g.latest, reverse=True)
    return ordered


# ─────────────────────────────────────────────────────────────────────────────
# Events feed
# ─────────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class EventRow:
    id: int
    ts: datetime
    kind: str
    severity: str
    node_name: str
    detail: dict


def recent_events(*, limit: int = 30) -> list[EventRow]:
    rows = (
        Event.query
        .filter(Event.kind.in_(tuple(_PLAN_EVENT_KINDS)))
        .order_by(desc(Event.ts))
        .limit(limit)
        .all()
    )
    if not rows:
        return []
    node_lookup = {n.id: n for n in FleetChrNode.query.all()}
    return [
        EventRow(
            id=int(ev.id), ts=ev.ts or utcnow(),
            kind=str(ev.kind), severity=str(ev.severity or "info"),
            node_name=_name_of(node_lookup, ev.chr_id),
            detail=ev.detail or {},
        )
        for ev in rows
    ]


__all__ = [
    "NodeHeadroom",
    "FleetCapacity",
    "DecisionRow",
    "PlanGroup",
    "EventRow",
    "all_headrooms",
    "fleet_capacity",
    "headroom_for",
    "recent_events",
    "recent_plans",
]
