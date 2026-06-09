"""fleet.brain.scoring — Phase 5 Task A (load-balancer scoring engine).

Pure-function scoring layer. Decoupled from the DB so it's trivial to test
and so the DB-bound :mod:`fleet.brain.placement` (Task B) can swap in
in-memory candidates without touching this module.

╔════════════════════════════════════════════════════════════════════════╗
║                        SCORE FORMULA (frozen)                          ║
╠════════════════════════════════════════════════════════════════════════╣
║                                                                        ║
║   eligible := health != "down"                                         ║
║              AND node.enabled                                          ║
║              AND NOT node.drain                                        ║
║              AND node.status != "disabled"                             ║
║              AND egress_usage_ratio < cost_metered_drain_ratio         ║
║                                                                        ║
║   When eligible == False the node is reported with score = 0.0 and     ║
║   excluded from rank() / best_node() / top_n() entirely.               ║
║                                                                        ║
║   Otherwise:                                                           ║
║                                                                        ║
║     factor_health   = 1.0 if state == "up"                             ║
║                      else 0.5 if state in ("degraded", "unknown")       ║
║                      else 0.0  # 'down' is excluded above              ║
║                                                                        ║
║     factor_cpu      = max(0.0, 1.0 - cpu_pct / 100)                    ║
║                       * (1 - cpu_shed_penalty if cpu >= shed else 1)   ║
║                                                                        ║
║     factor_capacity = max(0.0, 1 - active_sessions / max_sessions)     ║
║                                                                        ║
║     factor_cost     = cost_open_score                if provider open  ║
║                       else piecewise-linear by egress_usage_ratio      ║
║                       between (0, warn, alarm, drain) anchors          ║
║                                                                        ║
║   raw_score = w.health    * factor_health                              ║
║             + w.cpu_headroom * factor_cpu                              ║
║             + w.capacity  * factor_capacity                            ║
║             + w.cost      * factor_cost                                ║
║                                                                        ║
║   score    = raw_score * float(node.weight)                            ║
║                                                                        ║
║   ``reasons`` (dict) carries the per-factor breakdown — each weighted  ║
║   contribution + a few flags (``shedding``, ``near_cap``, ``tier``)    ║
║   for explainability in the UI / placement_decisions audit row.        ║
║                                                                        ║
╚════════════════════════════════════════════════════════════════════════╝

The fill-unlimited-first preference is NOT in the formula above — it
lives in :mod:`fleet.brain.placement` as a two-tier sort (Tier 0 =
unlimited nodes with capacity headroom, Tier 1 = everything else
eligible). Keeping it out of the score keeps the score monotonic and
explainable: "node A scored 1.42, node B scored 1.38, both eligible".

Frozen public surface (Task B builds against these — do not break):

  * :class:`NodeScore`                                  — output dataclass
  * :func:`score_node(node, health, latest_metrics, provider, cfg)` -> NodeScore
  * :func:`should_move(user_state, cfg)`                — rebalance hysteresis
  * :class:`UserSessionState`                           — input to should_move

The :func:`rank`, :func:`best_node`, :func:`top_n` functions live in
:mod:`fleet.brain.placement` (DB-bound; re-exported here for the
contract-level import surface).
"""
from __future__ import annotations

import dataclasses
from datetime import datetime
from typing import Any

from fleet.config import BrainConfig, FleetConfig, ScoringWeights


# ════════════════════════════════════════════════════════════════════════
# Result type — kept frozen so Task B can rely on it
# ════════════════════════════════════════════════════════════════════════


@dataclasses.dataclass(frozen=True)
class NodeScore:
    """One node's score from a single brain pass.

    Attributes
    ----------
    node_id   stable id of the node (``fleet_chr_nodes.id``).
    name      operator-given label; useful for logs/audit.
    eligible  True iff the node may receive new placements right now
              (health up/degraded/unknown, enabled, not draining,
              not over the metered cap).
    score     final combined score; higher = better pick. 0.0 when not
              eligible. NOT clamped to [0, 1] — the upper bound depends
              on the weight set, and consumers should rank by raw value.
    reasons   per-factor breakdown for explainability:

              ``health``    weighted health contribution
              ``cpu``       weighted CPU-headroom contribution
              ``capacity``  weighted session-headroom contribution
              ``cost``      weighted cost contribution
              ``weight``    the ``node.weight`` multiplier we applied
              ``shedding``  True iff CPU ≥ shed threshold (heavy penalty)
              ``near_cap``  True iff metered usage ≥ warn ratio
              ``tier``      0 = unlimited + has-headroom (Tier 0),
                            1 = everything else eligible.
              ``ineligible_reason``  short code when eligible=False:
                            "down" | "disabled" | "draining" | "over_cap".

    The dataclass is frozen so callers can hash / compare scores and so
    Task B can use a ``NodeScore`` in a placement_decisions.reason JSON
    payload without worrying about mutation between record and audit.
    """

    node_id: int
    name: str
    eligible: bool
    score: float
    reasons: dict[str, Any]


# ════════════════════════════════════════════════════════════════════════
# Movement hysteresis input
# ════════════════════════════════════════════════════════════════════════


@dataclasses.dataclass(frozen=True)
class UserSessionState:
    """Snapshot of a single user's "should this session move?" inputs.

    All-pure: the rebalance loop assembles this from whatever sources it
    has (live metric on the user's current node, last move record from
    ``fleet_placement_decisions``) and hands it to :func:`should_move`.

    Attributes
    ----------
    user                 stable user identity (``user@realm``); informational.
    current_chr_id       node the user is currently on.
    over_threshold_since timestamp of the FIRST observation that the user's
                         current node was over-threshold. None if currently
                         under-threshold.
    last_moved_at        when the user was last moved by the brain. None if
                         never moved (a fresh user).
    now                  observation clock — caller passes this so tests and
                         a real loop both see the same shape.
    """

    user: str
    current_chr_id: int
    over_threshold_since: datetime | None
    last_moved_at: datetime | None
    now: datetime


# ════════════════════════════════════════════════════════════════════════
# Per-factor curves (pure)
# ════════════════════════════════════════════════════════════════════════


def _f_health(state: str | None) -> tuple[float, str]:
    """Health factor + a marker for the reasons dict.

    ``down`` is excluded BEFORE we get here (eligibility filter), so a
    'down' state here means the caller bypassed eligibility — score it 0.
    """
    if state == "up":
        return 1.0, "up"
    if state in ("degraded", "unknown", None):
        return 0.5, state or "unknown"
    return 0.0, state  # safety net


def _f_cpu(cpu_pct: float | None, cfg: BrainConfig) -> tuple[float, bool]:
    """Linear headroom curve with a heavy step at the shed threshold.

    cpu_pct None ⇒ neutral 0.5 (no signal — don't penalise blindly, but
    don't pretend it's idle either).
    """
    if cpu_pct is None:
        return 0.5, False
    cpu = max(0.0, min(100.0, float(cpu_pct)))
    base = max(0.0, 1.0 - cpu / 100.0)
    shedding = cpu >= cfg.cpu_shed_threshold_pct
    if shedding:
        # Heavy penalty. The (1 - penalty) factor collapses the CPU axis
        # to a fraction of its base value — by default 15% of headroom
        # remains, so a shedding node falls dramatically below its peers
        # even before weight scaling.
        return base * (1.0 - cfg.cpu_shed_penalty), True
    return base, False


def _f_capacity(active: int | None, max_sessions: int) -> float:
    """Free-session ratio. max_sessions == 0 ⇒ treat as full (0.0)."""
    if not max_sessions or max_sessions <= 0:
        return 0.0
    a = max(0, int(active or 0))
    free_ratio = 1.0 - (a / float(max_sessions))
    return max(0.0, min(1.0, free_ratio))


def _f_cost(
    *,
    provider_cost_model: str,
    egress_used_gb: float,
    cap_tb: float | None,
    cfg: BrainConfig,
) -> tuple[float, bool, float]:
    """Cost factor + (near_cap flag, usage_ratio) for the reasons dict.

    For an open provider (or a metered provider with no cap declared)
    the factor is ``cfg.cost_open_score`` — flat ceiling, no penalty.

    For metered providers the factor follows a piecewise-linear curve
    anchored at (0, warn, alarm, drain) — all four anchors are tunables
    in :class:`BrainConfig` so the operator can sharpen or soften the
    "spill" behaviour without code changes.

    Returns ``(factor, near_cap, usage_ratio)``. ``usage_ratio`` is also
    surfaced in the reasons dict so the UI can render it.
    """
    model = (provider_cost_model or "open").lower()
    if model == "open" or not cap_tb or cap_tb <= 0:
        return cfg.cost_open_score, False, 0.0

    cap_gb = float(cap_tb) * 1024.0
    used = max(0.0, float(egress_used_gb or 0.0))
    ratio = used / cap_gb if cap_gb > 0 else 1.0
    ratio = min(max(ratio, 0.0), 2.0)  # clamp wild values for plotting sanity

    if ratio >= cfg.cost_metered_drain_ratio:
        return cfg.cost_metered_score_at_drain, True, ratio

    # Piecewise-linear interpolation between the four anchor points.
    # Each branch interpolates ``ratio`` within its segment.
    if ratio < cfg.cost_metered_warn_ratio:
        # 0 .. warn
        span = cfg.cost_metered_warn_ratio
        t = ratio / span if span > 0 else 0.0
        f = _lerp(cfg.cost_metered_score_at_zero,
                  cfg.cost_metered_score_at_warn, t)
        return f, False, ratio
    if ratio < cfg.cost_metered_alarm_ratio:
        # warn .. alarm
        span = cfg.cost_metered_alarm_ratio - cfg.cost_metered_warn_ratio
        t = (ratio - cfg.cost_metered_warn_ratio) / span if span > 0 else 0.0
        f = _lerp(cfg.cost_metered_score_at_warn,
                  cfg.cost_metered_score_at_alarm, t)
        return f, True, ratio
    # alarm .. drain
    span = cfg.cost_metered_drain_ratio - cfg.cost_metered_alarm_ratio
    t = (ratio - cfg.cost_metered_alarm_ratio) / span if span > 0 else 0.0
    f = _lerp(cfg.cost_metered_score_at_alarm,
              cfg.cost_metered_score_at_drain, t)
    return f, True, ratio


def _lerp(a: float, b: float, t: float) -> float:
    return float(a) + (float(b) - float(a)) * max(0.0, min(1.0, float(t)))


# ════════════════════════════════════════════════════════════════════════
# Eligibility
# ════════════════════════════════════════════════════════════════════════


def _eligibility(
    *, node, health, provider, egress_usage_ratio: float, cfg: BrainConfig,
) -> tuple[bool, str | None]:
    """Apply the hard-exclusion rules. Returns (eligible, reason_code)."""
    health_state = getattr(health, "state", None) if health is not None else None
    if health_state == "down":
        return False, "down"
    if not bool(getattr(node, "enabled", True)):
        return False, "disabled"
    status = (getattr(node, "status", "") or "").lower()
    if status in ("disabled", "decommissioned", "decommissioning"):
        return False, "disabled"
    if bool(getattr(node, "drain", False)):
        return False, "draining"
    # Metered nodes at / past the drain ratio are treated as fully drained.
    if (provider is not None
            and (getattr(provider, "cost_model", "open") or "").lower() == "metered"
            and egress_usage_ratio >= cfg.cost_metered_drain_ratio):
        return False, "over_cap"
    return True, None


# ════════════════════════════════════════════════════════════════════════
# Frozen public function
# ════════════════════════════════════════════════════════════════════════


def score_node(node, health, latest_metrics, provider, cfg: FleetConfig) -> NodeScore:
    """Score one node. PURE — does not touch the DB.

    Parameters
    ----------
    node             a :class:`FleetChrNode` (or any duck-typed object with
                     ``id``, ``name``, ``enabled``, ``drain``, ``status``,
                     ``max_sessions``, ``active_sessions``, ``used_tb_cycle``,
                     ``weight``).
    health           a :class:`FleetChrHealth` (or None if never probed).
    latest_metrics   a :class:`FleetChrMetric` (or None) — the most recent
                     sample for ``cpu_pct`` / ``active_sessions``. Falls
                     back to the denormalized values on ``node`` when the
                     metric is missing or stale.
    provider         the node's :class:`FleetProvider`.
    cfg              full :class:`FleetConfig` (uses ``cfg.scoring`` weights
                     and ``cfg.brain`` thresholds).

    Returns
    -------
    NodeScore        eligible=False score is 0.0 with ``ineligible_reason``
                     set; consumers should filter on ``eligible`` before
                     ranking.
    """
    weights: ScoringWeights = cfg.scoring
    brain: BrainConfig = cfg.brain

    # ── sample selection: prefer the live metric, fall back to denorm ────
    cpu_pct = _coalesce(
        getattr(latest_metrics, "cpu_pct", None),
        getattr(node, "cpu_pct", None),
    )
    active = _coalesce_int(
        getattr(latest_metrics, "active_sessions", None),
        getattr(node, "active_sessions", None),
        default=0,
    )
    max_sessions = int(getattr(node, "max_sessions", 0) or 0)

    # ── cost inputs (provider-effective cap; node override wins if set) ──
    provider_cost_model = (getattr(provider, "cost_model", "open") or "open").lower()
    node_cap_tb = getattr(node, "bandwidth_cap_tb", None)
    eff_cap_tb = float(node_cap_tb) if node_cap_tb not in (None, "") else (
        float(getattr(provider, "monthly_cap_tb", 0) or 0.0)
    )
    # Convert the panel's "used_tb_cycle" to GB so the curve has a single
    # unit; tests + tunables are stated in GB-relative ratios.
    used_tb_cycle = getattr(node, "used_tb_cycle", None)
    used_gb = float(used_tb_cycle) * 1024.0 if used_tb_cycle not in (None, "") else 0.0
    cost_factor, near_cap, usage_ratio = _f_cost(
        provider_cost_model=provider_cost_model,
        egress_used_gb=used_gb,
        cap_tb=eff_cap_tb if eff_cap_tb > 0 else None,
        cfg=brain,
    )

    # ── eligibility ─────────────────────────────────────────────────────
    eligible, reason_code = _eligibility(
        node=node, health=health, provider=provider,
        egress_usage_ratio=usage_ratio, cfg=brain,
    )
    node_weight = float(getattr(node, "weight", 1.0) or 1.0)

    if not eligible:
        return NodeScore(
            node_id=int(getattr(node, "id", 0) or 0),
            name=str(getattr(node, "name", "") or ""),
            eligible=False,
            score=0.0,
            reasons={
                "health": 0.0, "cpu": 0.0, "capacity": 0.0, "cost": 0.0,
                "weight": node_weight, "shedding": False, "near_cap": near_cap,
                "usage_ratio": usage_ratio, "tier": 1,
                "ineligible_reason": reason_code,
            },
        )

    # ── per-factor curves ───────────────────────────────────────────────
    health_state = getattr(health, "state", None) if health is not None else None
    f_health, health_label = _f_health(health_state)
    f_cpu, shedding = _f_cpu(cpu_pct, brain)
    f_capacity = _f_capacity(active, max_sessions)

    # ── weighted combination ────────────────────────────────────────────
    contrib_health = weights.health * f_health
    contrib_cpu = weights.cpu_headroom * f_cpu
    contrib_capacity = weights.capacity * f_capacity
    contrib_cost = weights.cost * cost_factor
    raw = contrib_health + contrib_cpu + contrib_capacity + contrib_cost
    final = raw * node_weight

    # Tier (Task-B's two-tier sort key): Tier 0 = unlimited with headroom;
    # everything else eligible = Tier 1. We compute it HERE so the audit
    # row records the tier the brain saw, even if Task B disables the
    # two-tier sort via ``cfg.brain.fill_unlimited_first = False``.
    tier = _classify_tier(
        provider_cost_model=provider_cost_model,
        active=active, max_sessions=max_sessions,
        cfg=brain,
    )

    return NodeScore(
        node_id=int(getattr(node, "id", 0) or 0),
        name=str(getattr(node, "name", "") or ""),
        eligible=True,
        score=round(final, 6),
        reasons={
            "health":   round(contrib_health, 6),
            "cpu":      round(contrib_cpu, 6),
            "capacity": round(contrib_capacity, 6),
            "cost":     round(contrib_cost, 6),
            "weight":   node_weight,
            "shedding": shedding,
            "near_cap": near_cap,
            "usage_ratio": round(usage_ratio, 6),
            "tier":     tier,
            "health_state": health_label,
        },
    )


def _classify_tier(
    *, provider_cost_model: str, active: int, max_sessions: int, cfg: BrainConfig,
) -> int:
    """Two-tier preference for the ``fill_unlimited_first`` rule.

    Tier 0: provider is 'open' AND the node has at least
    ``fill_spill_headroom_pct`` percent of its session capacity free.
    Tier 1: everything else eligible.
    """
    if not cfg.fill_unlimited_first:
        return 0
    if provider_cost_model != "open":
        return 1
    if max_sessions <= 0:
        return 1
    free_pct = 100.0 * (1.0 - (max(0, active) / max_sessions))
    return 0 if free_pct >= cfg.fill_spill_headroom_pct else 1


# ════════════════════════════════════════════════════════════════════════
# Movement hysteresis — frozen public function
# ════════════════════════════════════════════════════════════════════════


def should_move(user_state: UserSessionState, cfg: FleetConfig) -> bool:
    """True iff the rebalance loop SHOULD signal a CoA move for this user.

    Two independent gates — both must be open:

    1. **Sustain gate** — the user must have been over-threshold for at
       least ``cfg.brain.move_sustain_seconds``. If
       ``over_threshold_since`` is None or the elapsed time is shorter
       than the sustain window, the answer is False. A flap that drops
       under-threshold within the window cancels the move entirely (the
       caller will reset ``over_threshold_since`` to None when the user
       stops being over-threshold).

    2. **Cooldown gate** — if the user has been moved before, the time
       since their last move must be at least
       ``cfg.brain.move_cooldown_seconds``. Caps ping-pong even when a
       single flapping node keeps tripping the sustain window.

    New placements bypass this entirely — they just pick best eligible
    via :func:`fleet.brain.placement.best_node`.
    """
    brain = cfg.brain
    if user_state.over_threshold_since is None:
        return False
    elapsed = (user_state.now - user_state.over_threshold_since).total_seconds()
    if elapsed < float(brain.move_sustain_seconds):
        return False
    if user_state.last_moved_at is not None:
        since_move = (user_state.now - user_state.last_moved_at).total_seconds()
        if since_move < float(brain.move_cooldown_seconds):
            return False
    return True


# ════════════════════════════════════════════════════════════════════════
# Helpers
# ════════════════════════════════════════════════════════════════════════


def _coalesce(*vals):
    for v in vals:
        if v is not None:
            try:
                return float(v)
            except (TypeError, ValueError):
                continue
    return None


def _coalesce_int(*vals, default: int = 0) -> int:
    for v in vals:
        if v is None:
            continue
        try:
            return int(v)
        except (TypeError, ValueError):
            continue
    return default


__all__ = [
    "NodeScore",
    "UserSessionState",
    "score_node",
    "should_move",
]
