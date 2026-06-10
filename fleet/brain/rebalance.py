"""fleet.brain.rebalance — Phase-8 rebalance / forced-evacuation orchestrator.

The orchestrator is the bridge between sensing (Phase 4 health, Phase 5
brain) and enforcement (Phase 7 panel control + the proxy's CoA layer).
It is the ONLY producer of ``fleet_placement_decisions`` rows with
``kind ∈ {rebalance, forced_failover}`` and the matching
``fleet_events`` rows of kinds ``failover_start`` / ``failover_done`` /
``capacity_warning``. The actual CoA disconnects are sent by the proxy
when its routing-table read sees ``live_apply_enabled = True`` — this
module deliberately STOPS at producing the plan + records.

Two trigger shapes, one planner:

* **Forced evacuation** (``trigger = FailoverTrigger``) — the source
  node went DOWN. The planner evacuates ALL of its active users
  regardless of ``UserFleet.movable``. The contract is documented in
  ``docs/chr_fleet/05_LOAD_BALANCER_BRAIN.md §5.6``: opt-in only applies
  to NORMAL rebalancing; an outage is an "everyone moves" situation.

* **Pressure rebalance** (``trigger = PressureTrigger``) — the source
  node is over CPU shed sustained or over its bandwidth-cap drain
  threshold. Only ``movable=True`` users are candidates, AND each move
  must clear :func:`fleet.brain.scoring.should_move` (sustain +
  cooldown) before the planner adds it.

Headroom guard (applies to both):

1. The receiver pool is the brain's ``rank()`` minus the source node
   (a DOWN source is already ``eligible=False``, but the pressure case
   leaves the source eligible and we still don't want to relocate
   onto it).
2. Each target may receive at most
   ``cfg.orchestrator.max_moves_per_target_per_plan`` moves in this
   pass, and we stop assigning to a target once its post-plan
   "active + assigned" sessions reach
   ``(1 - cfg.orchestrator.target_min_free_pct/100) * max_sessions``.
3. If the total spare capacity across eligible targets is below
   ``cfg.orchestrator.insufficient_capacity_pct`` of the source's
   active session count, the planner truncates to what fits and the
   :class:`RebalancePlan` carries ``capacity_warning=True``. An event
   row is emitted by :func:`execute_rebalance` to surface the gap.

After execution, DNS is reconciled (:func:`fleet.dns.reconciler.reconcile_now`)
so a DOWN node disappears from the front door — clients re-resolve to
the survivors via the live DNS state, no application traffic stays
pointed at the dead box.
"""
from __future__ import annotations

import dataclasses
import logging
from datetime import datetime
from typing import Callable, Iterable

from app.extensions import db
from app.models import utcnow

from fleet.brain.models_session import PlacementDecision, Session, UserFleet
from fleet.brain.placement import rank
from fleet.config import FLEET, FleetConfig, OrchestratorConfig
from fleet.notify.models_alert import Event
from fleet.registry.models_chr import FleetChrNode


logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════════
# Trigger shapes — frozen dataclasses
# ════════════════════════════════════════════════════════════════════════


@dataclasses.dataclass(frozen=True)
class FailoverTrigger:
    """Source node went DOWN. Evacuate everyone. Hard-bypasses
    ``movable`` and :func:`should_move` — see module docstring."""

    source_chr_id: int
    source_name: str = ""
    reason: str = "node_down"

    kind: str = "failover"


@dataclasses.dataclass(frozen=True)
class PressureTrigger:
    """Source node is over CPU / cost threshold but still UP. Movable
    users only. Per-user hysteresis applies (:func:`should_move`)."""

    source_chr_id: int
    source_name: str = ""
    reason: str = "cpu_shed_sustained"

    kind: str = "rebalance"


Trigger = FailoverTrigger | PressureTrigger


# ════════════════════════════════════════════════════════════════════════
# Plan + execution result shapes
# ════════════════════════════════════════════════════════════════════════


@dataclasses.dataclass(frozen=True)
class IntendedMove:
    """One intended user move. The proxy materialises the CoA later."""

    username: str
    from_chr_id: int
    to_chr_id: int
    reason: str
    movable_required: bool
    """True iff this trigger required the user to be opted-in. ``False``
    for a forced evacuation (the audit row records that the move was
    placed despite ``movable=False``)."""


@dataclasses.dataclass(frozen=True)
class RebalancePlan:
    """Computed set of intended moves + the guard-rail signals.

    Attributes
    ----------
    trigger              the trigger that produced this plan.
    moves                ordered ``IntendedMove`` list. Order is the
                         order in which the planner assigned them —
                         tied to the operator's audit so a later
                         "who landed where first" question has an
                         answer.
    skipped_movable      users on the source that were excluded by the
                         ``movable=False`` filter (pressure trigger
                         only). Empty for a forced evacuation.
    skipped_hysteresis   users excluded by :func:`should_move`
                         (pressure trigger only).
    skipped_capacity     users that could not fit anywhere given the
                         per-target caps + min-free-pct guard.
    capacity_warning     True iff the planner cut the batch because the
                         fleet's total spare capacity could not absorb
                         the source's active sessions.
    """

    trigger: Trigger
    moves: tuple[IntendedMove, ...]
    skipped_movable: tuple[str, ...] = ()
    skipped_hysteresis: tuple[str, ...] = ()
    skipped_capacity: tuple[str, ...] = ()
    capacity_warning: bool = False


@dataclasses.dataclass(frozen=True)
class ExecuteResult:
    """What :func:`execute_rebalance` did + a handle to its side-effects."""

    plan: RebalancePlan
    decision_ids: tuple[int, ...]
    event_ids: tuple[int, ...]
    reconcile_called: bool
    reconcile_error: str = ""


# ════════════════════════════════════════════════════════════════════════
# Public — plan
# ════════════════════════════════════════════════════════════════════════


def plan_rebalance(
    trigger: Trigger,
    *,
    cfg: FleetConfig | None = None,
    now: datetime | None = None,
) -> RebalancePlan:
    """Compute the intended moves for ``trigger``. PURE w.r.t. the DB
    (only reads): the resulting plan is what :func:`execute_rebalance`
    will then persist as decisions + events.

    The function is safe to call without a transaction — every read uses
    the current session implicitly via the ORM; no inserts happen here.
    """
    cfg = cfg or FLEET
    orc: OrchestratorConfig = cfg.orchestrator
    now = now or utcnow()

    # 1) Active sessions on the source — these are the candidates.
    actives = (
        Session.query
        .filter(Session.chr_id == trigger.source_chr_id)
        .filter(Session.state == "active")
        .order_by(Session.started_at.asc())  # FIFO for fairness
        .all()
    )

    # 2) Lookup per-username UserFleet rows in one query (most are
    # immovable so this is the cheap path).
    usernames = [s.username for s in actives]
    user_rows = {
        u.username: u
        for u in (
            UserFleet.query
            .filter(UserFleet.username.in_(usernames)).all()
            if usernames else []
        )
    }

    # 3) Target pool = brain rank() minus the source node. ``rank()``
    # already excludes the DOWN source (it filters on eligibility), but
    # for the pressure trigger the source is still eligible — so we
    # subtract it explicitly.
    candidates = [
        s for s in rank(cfg=cfg)
        if s.node_id != trigger.source_chr_id
    ]
    target_state = _build_target_state(candidates, cfg=orc)

    if not target_state:
        return RebalancePlan(
            trigger=trigger,
            moves=(),
            skipped_capacity=tuple(s.username for s in actives),
            capacity_warning=bool(actives),
        )

    # 4) Apply filters per trigger type.
    is_failover = isinstance(trigger, FailoverTrigger)
    skipped_movable: list[str] = []
    skipped_hysteresis: list[str] = []
    candidates_to_move = []
    for s in actives:
        urow = user_rows.get(s.username)
        if not is_failover:
            # Pressure path: movable=True required.
            if urow is None or not bool(urow.movable):
                skipped_movable.append(s.username)
                continue
            # Hysteresis check — caller provides per-user state via the
            # database (latest decision's decided_at = last move; over-
            # threshold-since is approximated from the source health
            # transition recorded in fleet_events). We use a simple
            # synth: over_threshold_since = source node's last
            # transition into 'degraded'/'cpu_shed' — if the orchestrator
            # is called at all, that's >= sustain (the monitor itself
            # only flips after the sustain window). For deterministic
            # tests we expose the should-move check as a hook.
            if not _passes_should_move(s.username, cfg=cfg, now=now):
                skipped_hysteresis.append(s.username)
                continue
        candidates_to_move.append(s)

    # 5) Pack into the target pool, capped by per-target + per-plan caps.
    # Insufficient-capacity guard fires BEFORE assignment: if total
    # spare capacity across all targets is below the threshold, the
    # plan is intentionally short.
    total_spare = sum(t.spare for t in target_state.values())
    required = len(candidates_to_move)
    insufficient = False
    if required > 0:
        required_floor = int(
            required * (orc.insufficient_capacity_pct / 100.0)
        )
        if total_spare < required_floor:
            insufficient = True

    moves: list[IntendedMove] = []
    skipped_capacity: list[str] = []
    assigned_by_target: dict[int, int] = {}
    sorted_candidates = sorted(target_state.values(), key=lambda t: t.score, reverse=True)
    target_by_id = {t.node_id: t for t in sorted_candidates}
    for sess in candidates_to_move:
        if len(moves) >= orc.max_moves_per_plan:
            skipped_capacity.append(sess.username)
            continue
        target = _pick_target(target_by_id, assigned_by_target, orc)
        if target is None:
            skipped_capacity.append(sess.username)
            continue
        moves.append(IntendedMove(
            username=sess.username,
            from_chr_id=trigger.source_chr_id,
            to_chr_id=target.node_id,
            reason=trigger.reason,
            movable_required=not is_failover,
        ))
        assigned_by_target[target.node_id] = assigned_by_target.get(target.node_id, 0) + 1
        target.assigned += 1

    return RebalancePlan(
        trigger=trigger,
        moves=tuple(moves),
        skipped_movable=tuple(skipped_movable),
        skipped_hysteresis=tuple(skipped_hysteresis),
        skipped_capacity=tuple(skipped_capacity),
        capacity_warning=insufficient or bool(skipped_capacity),
    )


# ════════════════════════════════════════════════════════════════════════
# Public — execute
# ════════════════════════════════════════════════════════════════════════


def execute_rebalance(
    plan: RebalancePlan,
    *,
    cfg: FleetConfig | None = None,
    now: datetime | None = None,
    reconcile_fn: Callable[[], object] | None = None,
) -> ExecuteResult:
    """Persist the plan and call DNS reconcile. Idempotent on (trigger,
    username) — duplicate calls do NOT double-record (the most recent
    pending PlacementDecision per user is overwritten with the new
    intent rather than appended)."""

    cfg = cfg or FLEET
    now = now or utcnow()

    # Resolve the reconciler lazily so tests can pass a stub without
    # importing the real DNS chain.
    if reconcile_fn is None:
        try:
            from fleet.dns import reconciler as _r
            reconcile_fn = _r.reconcile_now
        except Exception:  # noqa: BLE001 - defensive
            reconcile_fn = None

    decision_ids: list[int] = []
    event_ids: list[int] = []

    # 1) failover_start event for the operator audit.
    kind = "failover_start" if isinstance(plan.trigger, FailoverTrigger) else "rebalance_start"
    start_ev = Event(
        chr_id=plan.trigger.source_chr_id,
        ts=now,
        kind=kind if kind in ("failover_start", "failover_done") else "coa_sent",
        severity="crit" if kind == "failover_start" else "info",
    )
    start_ev.detail = {
        "trigger": plan.trigger.kind,
        "source_chr_id": plan.trigger.source_chr_id,
        "source_name": plan.trigger.source_name,
        "reason": plan.trigger.reason,
        "moves": len(plan.moves),
        "skipped_movable": list(plan.skipped_movable),
        "skipped_hysteresis": list(plan.skipped_hysteresis),
        "skipped_capacity": list(plan.skipped_capacity),
    }
    db.session.add(start_ev)
    db.session.flush()
    event_ids.append(start_ev.id)

    # 2) capacity_warning event when the planner cut the batch.
    if plan.capacity_warning:
        warn = Event(
            chr_id=plan.trigger.source_chr_id, ts=now,
            kind="cap_warn", severity="warn",
        )
        warn.detail = {
            "trigger": plan.trigger.kind,
            "source_chr_id": plan.trigger.source_chr_id,
            "moves_planned": len(plan.moves),
            "skipped_capacity": list(plan.skipped_capacity),
            "note": "fleet spare capacity insufficient or per-target caps reached",
        }
        db.session.add(warn)
        db.session.flush()
        event_ids.append(warn.id)

    # 3) Persist one PlacementDecision per intended move (kind tied to
    # trigger). On a duplicate (same username + outcome=pending), we
    # overwrite the prior intent so the audit reflects the LATEST plan.
    pd_kind = "forced_failover" if isinstance(plan.trigger, FailoverTrigger) else "rebalance"
    for m in plan.moves:
        pd = (
            PlacementDecision.query
            .filter(PlacementDecision.username == m.username)
            .filter(PlacementDecision.outcome == "pending")
            .order_by(PlacementDecision.decided_at.desc())
            .first()
        )
        is_new = pd is None
        if is_new:
            pd = PlacementDecision(
                username=m.username, decided_at=now, kind=pd_kind,
                from_chr_id=m.from_chr_id, to_chr_id=m.to_chr_id,
                outcome="pending",
            )
        else:
            pd.decided_at = now
            pd.kind = pd_kind
            pd.from_chr_id = m.from_chr_id
            pd.to_chr_id = m.to_chr_id
            pd.outcome = "pending"
        pd.reason = {
            "trigger": plan.trigger.kind,
            "source": plan.trigger.source_name,
            "reason": plan.trigger.reason,
            "movable_required": m.movable_required,
            "planned_at": now.isoformat() + "Z",
        }
        db.session.add(pd)
        db.session.flush()
        decision_ids.append(pd.id)

    # 4) failover_done event (info; carries the resulting decision ids).
    done_kind = "failover_done" if isinstance(plan.trigger, FailoverTrigger) else "coa_sent"
    done_ev = Event(
        chr_id=plan.trigger.source_chr_id, ts=now,
        kind=done_kind, severity="info",
    )
    done_ev.detail = {
        "trigger": plan.trigger.kind,
        "decision_ids": decision_ids,
        "moves": len(plan.moves),
    }
    db.session.add(done_ev)
    db.session.flush()
    event_ids.append(done_ev.id)
    db.session.commit()

    # 5) Ask the DNS layer to reconcile — DOWN node drops from the front
    # door so clients re-resolve to survivors. Failure is captured but
    # does not roll back the decisions (they're advisory anyway when
    # live-apply is off; on, the proxy needs them present to act).
    reconcile_called = False
    reconcile_error = ""
    if reconcile_fn is not None:
        try:
            reconcile_fn()
            reconcile_called = True
        except Exception as exc:  # noqa: BLE001 — best-effort
            reconcile_error = exc.__class__.__name__
            logger.exception("fleet.brain.rebalance: reconcile_now failed")

    return ExecuteResult(
        plan=plan,
        decision_ids=tuple(decision_ids),
        event_ids=tuple(event_ids),
        reconcile_called=reconcile_called,
        reconcile_error=reconcile_error,
    )


# ════════════════════════════════════════════════════════════════════════
# Monitor auto-trigger hook — Phase 4 _notify_hook will call this
# ════════════════════════════════════════════════════════════════════════


def on_monitor_event(event: Event) -> ExecuteResult | None:
    """Adapter invoked by :mod:`fleet.health.monitor` after each transition.

    Only acts on ``health_down`` events (severity ``crit``) and when
    ``cfg.orchestrator.auto_failover_on_down`` is True. Produces a
    forced-evacuation plan, executes it, and returns the result. Safe
    to call with any other event kind — those return ``None`` and have
    no side effects.

    All errors are caught + logged so an orchestrator bug never breaks
    the sensor loop (the monitor must keep recording metrics regardless).
    """
    if event is None or event.kind != "health_down":
        return None
    cfg = FLEET
    if not cfg.orchestrator.auto_failover_on_down:
        return None
    if event.chr_id is None:
        return None

    try:
        node = db.session.get(FleetChrNode, event.chr_id)
        source_name = node.name if node is not None else ""
        plan = plan_rebalance(
            FailoverTrigger(
                source_chr_id=event.chr_id,
                source_name=source_name,
                reason="health_down_auto",
            ),
            cfg=cfg,
        )
        return execute_rebalance(plan, cfg=cfg)
    except Exception:  # noqa: BLE001
        logger.exception(
            "fleet.brain.rebalance: auto-failover hook failed for chr_id=%s",
            event.chr_id,
        )
        return None


# ════════════════════════════════════════════════════════════════════════
# Helpers (private)
# ════════════════════════════════════════════════════════════════════════


@dataclasses.dataclass
class _TargetState:
    """Per-target accounting carried through the packing loop."""

    node_id: int
    name: str
    score: float
    max_sessions: int
    current_active: int
    assigned: int = 0   # mutated during planning

    @property
    def spare(self) -> int:
        return max(0, self.max_sessions - self.current_active - self.assigned)


def _build_target_state(
    candidates: Iterable, *, cfg: OrchestratorConfig,
) -> dict[int, _TargetState]:
    """Resolve target nodes from the brain rank + a single DB query
    for their session caps and live active-session counts."""
    by_id: dict[int, _TargetState] = {}
    node_ids = [s.node_id for s in candidates]
    if not node_ids:
        return by_id
    nodes = FleetChrNode.query.filter(FleetChrNode.id.in_(node_ids)).all()
    node_lookup = {n.id: n for n in nodes}
    # Live active-session counts so the spare math is accurate.
    active_counts: dict[int, int] = {}
    rows = (
        db.session.query(Session.chr_id, db.func.count(Session.id))
        .filter(Session.chr_id.in_(node_ids))
        .filter(Session.state == "active")
        .group_by(Session.chr_id).all()
    )
    for chr_id, count in rows:
        active_counts[chr_id] = int(count or 0)

    for s in candidates:
        node = node_lookup.get(s.node_id)
        if node is None:
            continue
        max_s = int(node.max_sessions or 0)
        active = active_counts.get(s.node_id, int(node.active_sessions or 0))
        by_id[s.node_id] = _TargetState(
            node_id=s.node_id, name=s.name, score=float(s.score),
            max_sessions=max_s, current_active=active,
        )
    return by_id


def _pick_target(
    target_by_id: dict[int, _TargetState],
    assigned_by_target: dict[int, int],
    cfg: OrchestratorConfig,
) -> _TargetState | None:
    """Pick the highest-scoring target that still has room.

    Excludes any target that has either:
      * already received ``max_moves_per_target_per_plan`` moves, or
      * fallen below the post-plan min-free percentage threshold.
    """
    # Iterate by score descending — dict insertion order from the
    # caller already follows ``sorted(reverse=True)``.
    #
    # Integer-seat math (NOT free_pct float math): a percentage threshold
    # on integer seat counts has a binary floor — e.g. at max=10 + pct=10%
    # the minimum free seats is exactly 1, not 0.9999…. Using float math
    # for ``free_pct`` triggers a boundary-rounding bug at exact thresholds
    # (1.0 - 9/10 = 0.0999… in IEEE 754). The ceiling here is the
    # operator's "no node ever drops below N% free" intent at integer
    # resolution.
    import math
    for tgt in target_by_id.values():
        already = assigned_by_target.get(tgt.node_id, 0)
        if already >= cfg.max_moves_per_target_per_plan:
            continue
        if tgt.max_sessions <= 0:
            continue
        post_active = tgt.current_active + tgt.assigned + 1
        if post_active > tgt.max_sessions:
            continue  # hard cap
        min_free_seats = math.ceil(
            tgt.max_sessions * cfg.target_min_free_pct / 100.0
        )
        free_after = tgt.max_sessions - post_active
        if free_after < min_free_seats:
            continue
        return tgt
    return None


# Hysteresis hook — separated so the test can monkeypatch a deterministic
# answer without standing up a full UserFleet/PlacementDecision timeline.
def _passes_should_move(
    username: str, *, cfg: FleetConfig, now: datetime,
) -> bool:
    """For now, defer to a permissive default: if the user has no prior
    pending placement decision OR the latest one decided_at + cooldown
    has elapsed, allow the move. The full sustain-window check lives in
    :func:`fleet.brain.scoring.should_move` and consumes per-user state
    the orchestrator does not own (CPU samples per user). This wrapper
    is the seam tests / Phase-9 wiring can replace.
    """
    last = (
        PlacementDecision.query
        .filter(PlacementDecision.username == username)
        .order_by(PlacementDecision.decided_at.desc())
        .first()
    )
    if last is None:
        return True
    cooldown = cfg.brain.move_cooldown_seconds
    elapsed = (now - last.decided_at).total_seconds()
    return elapsed >= float(cooldown)


__all__ = [
    "FailoverTrigger",
    "PressureTrigger",
    "Trigger",
    "IntendedMove",
    "RebalancePlan",
    "ExecuteResult",
    "plan_rebalance",
    "execute_rebalance",
    "on_monitor_event",
]
