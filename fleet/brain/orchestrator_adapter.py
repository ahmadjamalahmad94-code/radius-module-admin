"""fleet.brain.orchestrator_adapter — single import surface for the rebalance
orchestrator (Phase-8 task A).

Why this exists
---------------
Phase-8 splits into two parallel tasks:

* **Task A** owns the engine — ``fleet/brain/rebalance.py`` with
  ``plan_rebalance(trigger: str) -> RebalancePlan`` and
  ``execute_rebalance(plan: RebalancePlan) -> RebalanceResult``.
* **Task B** (this branch) owns the UI — a dashboard that surfaces recent
  plans + headroom + the "run now" / "evacuate this node" buttons.

To let B ship without waiting on A, every UI call goes through this
adapter. At call time the adapter tries ``from fleet.brain import
plan_rebalance, execute_rebalance``; if either symbol is missing it
falls back to an in-process stub that returns a useful "engine not
available yet" envelope so the UI still functions — buttons are visible,
audit rows still get written, decisions/events read from the DB still
render. The wire/contract shape stays identical either way.

Frozen contract (what the real engine MUST conform to)
------------------------------------------------------
::

    plan_rebalance(trigger: str) -> RebalancePlan
    execute_rebalance(plan)      -> RebalanceResult

    RebalancePlan duck-typed via:
        .plan_id          str            stable identifier (e.g. uuid hex)
        .trigger          str            "manual" | "scheduled" | "headroom" |
                                          "forced_failover:<node_name>"
        .kind             str            "rebalance" | "forced_failover"
        .reason           str            short human label
        .source_node      str | None     name of the node being evacuated (failover)
        .moves            list[Move]     proposed moves (may be empty)
        .created_at       datetime       naive UTC
        .estimate_summary str            short human description

    Move duck-typed via:
        .username, .realm, .from_node, .to_node, .reason

    RebalanceResult duck-typed via:
        .plan_id          str
        .applied          bool           True iff live-apply was on AND
                                          execute called the actuator
        .moves_attempted  int
        .moves_applied    int
        .moves_failed     int
        .moves_skipped    int
        .message          str
        .raw              dict           free-form engine debug payload

When the adapter falls back to the stub, plans are returned with
``moves=[]`` and a clear message so the UI shows
"engine not available" without crashing.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable

from app.models import utcnow


# ─────────────────────────────────────────────────────────────────────────────
# Stable types
# ─────────────────────────────────────────────────────────────────────────────
TRIGGERS: tuple[str, ...] = (
    "manual",
    "scheduled",
    "headroom",
    "forced_failover",
)


@dataclass(frozen=True)
class Move:
    username: str
    realm: str = ""
    from_node: str = ""
    to_node: str = ""
    reason: str = ""


@dataclass(frozen=True)
class RebalancePlan:
    plan_id: str
    trigger: str
    kind: str                 # "rebalance" | "forced_failover"
    reason: str = ""
    source_node: str | None = None
    moves: list[Move] = field(default_factory=list)
    created_at: datetime = field(default_factory=utcnow)
    estimate_summary: str = ""


@dataclass(frozen=True)
class RebalanceResult:
    plan_id: str
    applied: bool
    moves_attempted: int
    moves_applied: int
    moves_failed: int
    moves_skipped: int
    message: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


# ─────────────────────────────────────────────────────────────────────────────
# Backend resolution
# ─────────────────────────────────────────────────────────────────────────────
#: Module-level marker that flips between "real" and "stub" as soon as the
#: first call resolves. The UI inspects this to render a small badge so the
#: operator knows whether the engine is hot or the stub is in play.
ORCHESTRATOR_BACKEND: str = "unresolved"


def _resolve() -> tuple[Callable[..., Any] | None, Callable[..., Any] | None]:
    """Look up ``(plan_rebalance, execute_rebalance)`` from the real engine,
    or return ``(None, None)`` so the stub can step in.

    Lazy + idempotent: a test that monkey-patches the engine mid-run is
    honoured. Tries the conventional locations in order so whichever sub-
    module the orchestrator picks works without UI changes.
    """
    global ORCHESTRATOR_BACKEND
    for path in (
        "fleet.brain.rebalance",
        "fleet.brain",   # if Task A re-exports from the package root
    ):
        try:
            mod = __import__(path, fromlist=("plan_rebalance", "execute_rebalance"))
        except ImportError:
            continue
        plan_fn = getattr(mod, "plan_rebalance", None)
        exec_fn = getattr(mod, "execute_rebalance", None)
        if callable(plan_fn) and callable(exec_fn):
            ORCHESTRATOR_BACKEND = "real"
            return plan_fn, exec_fn
    ORCHESTRATOR_BACKEND = "stub"
    return None, None


# ─────────────────────────────────────────────────────────────────────────────
# Coercion — keep the UI safe from a future engine that drifts
# ─────────────────────────────────────────────────────────────────────────────
def _coerce_move(raw: Any) -> Move:
    return Move(
        username=str(getattr(raw, "username", "") or ""),
        realm=str(getattr(raw, "realm", "") or ""),
        from_node=str(getattr(raw, "from_node", "") or ""),
        to_node=str(getattr(raw, "to_node", "") or ""),
        reason=str(getattr(raw, "reason", "") or ""),
    )


def _coerce_plan(raw: Any) -> RebalancePlan:
    if raw is None:
        return _stub_plan("manual", reason="engine_returned_none")
    moves = [_coerce_move(m) for m in (getattr(raw, "moves", None) or [])]
    created = getattr(raw, "created_at", None) or utcnow()
    return RebalancePlan(
        plan_id=str(getattr(raw, "plan_id", "") or _fresh_id()),
        trigger=str(getattr(raw, "trigger", "manual") or "manual"),
        kind=str(getattr(raw, "kind", "rebalance") or "rebalance"),
        reason=str(getattr(raw, "reason", "") or ""),
        source_node=getattr(raw, "source_node", None),
        moves=moves,
        created_at=created,
        estimate_summary=str(getattr(raw, "estimate_summary", "") or ""),
    )


def _coerce_result(raw: Any, *, plan_id: str) -> RebalanceResult:
    if raw is None:
        return RebalanceResult(
            plan_id=plan_id, applied=False,
            moves_attempted=0, moves_applied=0, moves_failed=0, moves_skipped=0,
            message="engine returned no result",
        )
    return RebalanceResult(
        plan_id=str(getattr(raw, "plan_id", plan_id) or plan_id),
        applied=bool(getattr(raw, "applied", False)),
        moves_attempted=int(getattr(raw, "moves_attempted", 0) or 0),
        moves_applied=int(getattr(raw, "moves_applied", 0) or 0),
        moves_failed=int(getattr(raw, "moves_failed", 0) or 0),
        moves_skipped=int(getattr(raw, "moves_skipped", 0) or 0),
        message=str(getattr(raw, "message", "") or ""),
        raw=dict(getattr(raw, "raw", {}) or {}),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Stub backend — keeps the dashboard functional before Task A merges
# ─────────────────────────────────────────────────────────────────────────────
def _fresh_id() -> str:
    return secrets.token_hex(6)


def _stub_plan(trigger: str, *, source_node: str | None = None, reason: str = "") -> RebalancePlan:
    kind = "forced_failover" if source_node else "rebalance"
    return RebalancePlan(
        plan_id=_fresh_id(),
        trigger=trigger,
        kind=kind,
        reason=reason or "engine_unavailable",
        source_node=source_node,
        moves=[],
        created_at=utcnow(),
        estimate_summary="المُنسِّق غير متاح — الخطة فارغة.",
    )


def _stub_execute(plan: RebalancePlan) -> RebalanceResult:
    return RebalanceResult(
        plan_id=plan.plan_id, applied=False,
        moves_attempted=0, moves_applied=0, moves_failed=0, moves_skipped=0,
        message="المُنسِّق غير متاح — لم يُنفَّذ أي نقل.",
        raw={"backend": "stub"},
    )


# ─────────────────────────────────────────────────────────────────────────────
# Public API — what the UI imports
# ─────────────────────────────────────────────────────────────────────────────
def plan_rebalance(trigger: str = "manual") -> RebalancePlan:
    """Ask the engine for a fresh plan, or return a stub envelope.

    ``trigger`` is the operator-facing label that travels into every
    audit row + recorded plan_id, so this exact value shows up later in
    "what triggered this run?" rows.
    """
    plan_fn, _ = _resolve()
    if plan_fn is None:
        return _stub_plan(trigger)
    try:
        raw = plan_fn(trigger=trigger)
    except TypeError:
        # Tolerate positional-only engines.
        raw = plan_fn(trigger)
    return _coerce_plan(raw)


def execute_rebalance(plan: RebalancePlan) -> RebalanceResult:
    """Execute the plan via the engine, or return a stub no-op result.

    The UI calls this immediately after ``plan_rebalance()`` in the manual
    "run now" path, and after a stub-constructed failover plan in the
    "evacuate this node" path.
    """
    _, exec_fn = _resolve()
    if exec_fn is None:
        return _stub_execute(plan)
    raw = exec_fn(plan)
    return _coerce_result(raw, plan_id=plan.plan_id)


def plan_forced_failover(node_name: str, *, trigger: str = "manual") -> RebalancePlan:
    """Ask the engine for a failover plan for one node, or fall back to
    a stub. The engine API for this is documented as
    ``plan_rebalance(trigger=f"forced_failover:{node}")`` so we synthesise
    the trigger here.
    """
    label = f"forced_failover:{node_name}"
    plan = plan_rebalance(label)
    # If the engine returned a non-failover plan (some engines may not
    # differentiate), tag it for the UI so the audit + display still
    # shows "إخلاء قسري".
    if plan.kind != "forced_failover" or not plan.source_node:
        return RebalancePlan(
            plan_id=plan.plan_id, trigger=label,
            kind="forced_failover", reason=plan.reason or "manual_evacuate",
            source_node=node_name, moves=plan.moves,
            created_at=plan.created_at,
            estimate_summary=plan.estimate_summary,
        )
    return plan


def is_available() -> bool:
    """True iff the real orchestrator is wired up. UI shows a banner when
    this returns False."""
    plan_fn, exec_fn = _resolve()
    return plan_fn is not None and exec_fn is not None


def backend_label() -> str:
    """The current backend marker (call after at least one resolve attempt)."""
    # Force a resolve if we have not done one yet.
    _resolve()
    return ORCHESTRATOR_BACKEND


__all__ = [
    "TRIGGERS",
    "Move",
    "RebalancePlan",
    "RebalanceResult",
    "ORCHESTRATOR_BACKEND",
    "plan_rebalance",
    "execute_rebalance",
    "plan_forced_failover",
    "is_available",
    "backend_label",
]
