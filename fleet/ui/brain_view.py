"""fleet.ui.brain_view — explainable ranking view for the dashboard.

Phase-5 task C deliverable. Surfaces *why* a node ranks where it does in the
brain's preference order — for each CHR node the owner sees:

* its current **score** + **rank**,
* whether the brain considers it **eligible** for new placements,
* a per-factor **breakdown** (health / cpu / cost / capacity) in Arabic with
  chip-style indicators, including the human reason for exclusion when
  ineligible (مفصول، مُعطّلة يدوياً، السعة ممتلئة، إلخ).

API CONSUMED — `fleet.brain.rank`
---------------------------------
We import the brain through a soft import so the dashboard works on every
branch in the parallel build matrix:

    try:
        from fleet.brain import rank as brain_rank
    except Exception:
        brain_rank = None

When the brain agent (Phase-5 task A) lands the real implementation, the
expected shape (per this file's task brief) is::

    NodeScore:
      .node_id   int
      .name      str
      .eligible  bool
      .score     float
      .reasons   dict[str, Any]   # per-factor breakdown

And:: ``rank() -> list[NodeScore]`` sorted best-first.

This module accepts ANY object exposing those attributes (works with a
``dataclass`` or a plain ``SimpleNamespace`` — we never call class-level
methods on them). The route consumes ``ranked_view_for(nodes)`` which
delegates to the brain when present and falls back to a local computation
otherwise, so the screen always shows useful information.

FALLBACK SCORING
----------------
Mirrors the documented ``fleet.config.ScoringWeights`` so the ordering the
owner sees matches the spirit of the real brain to within rounding:

    score = w.cpu_headroom        * (1 - cpu_util)
          + w.latency             * (1 - normalised(ping_rtt_ms))
          + w.session_headroom    * (1 - sessions_used_ratio)
          + w.cost                * cost_pref      # cheaper → higher
          # stickiness is a per-user signal; the fleet-level brain ranking
          # at-rest ignores it (the dashboard shows the placement-agnostic order).

Eligibility:
    * health.state in {'up'} or (state=='unknown' AND no health row at all)
      treated as eligible-best-effort,
    * node.enabled AND not node.drain,
    * cpu_util < cpu_shed_threshold_pct (otherwise still ranked but flagged
      as "near shed").

Each factor returns ``{label, level, detail}`` so the template renders chip
classes (ok/warn/bad/info) without putting business logic in Jinja.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from fleet.config import FLEET
from fleet.health.models_health import HEALTH_STATES
from fleet.registry.models_chr import FleetChrNode
from fleet.ui.dashboard_data import NodeView


# ────────────────────────────────────────────────────────────────────────────
# Soft import — the real brain wins when its branch lands at merge.
# ────────────────────────────────────────────────────────────────────────────
try:  # pragma: no cover - just an import probe
    from fleet.brain import rank as brain_rank  # type: ignore[attr-defined]
except Exception:  # noqa: BLE001 - any import error means "not available yet"
    brain_rank = None  # type: ignore[assignment]


# ────────────────────────────────────────────────────────────────────────────
# View shapes the template renders against
# ────────────────────────────────────────────────────────────────────────────


@dataclass
class FactorChip:
    """One labelled fact about a node ("CPU 37٪", "كلفة: مفتوحة", ...).

    ``level`` ∈ {"ok", "warn", "bad", "info"} — drives the chip CSS class so
    the colour follows the meaning, not the factor key.
    """

    key: str                  # internal key ("health", "cpu", "cost", "capacity")
    label: str                # Arabic label rendered as the chip text
    level: str = "info"       # ok / warn / bad / info
    detail: str = ""          # optional Arabic detail line under the chip


@dataclass
class RankedNode:
    """One row in «ترتيب الأسطول»."""

    rank: int                       # 1-based; lowest = best
    node_id: int
    name: str
    public_ip: str
    provider_name: str | None
    # Raw weighted score from the brain (or fallback). Higher = better. NOT
    # bounded — the brain returns whatever its formula produced (e.g. 2.82),
    # and the fallback returns a value in [0, 1]. This is the SORT KEY and
    # MUST NOT be rendered directly under a «من 100» framing — use
    # ``score_pct`` for the UI.
    score: float
    # Display score on a 0..100 scale, computed AFTER sorting by
    # ``_assign_display_scores`` so it's coherent across the whole list:
    #   top node    → 100
    #   other nodes → round(score / top * 100)   (clamped to [0, 100])
    # Order is preserved because we never re-sort on this field. The number,
    # the «من 100» label, and the progress-bar width all bind to this value
    # — never to ``score * 100`` (which can blow past 100 on the brain path).
    score_pct: int = 0
    eligible: bool = True
    excluded_reason: str | None = None     # Arabic short phrase when not eligible
    factors: list[FactorChip] = field(default_factory=list)
    source: str = "fallback"        # "real" once fleet.brain.rank lands


# ────────────────────────────────────────────────────────────────────────────
# Public entry point — used by the route.
# ────────────────────────────────────────────────────────────────────────────


def ranked_view_for(node_views: list[NodeView]) -> tuple[list[RankedNode], str]:
    """Return (ranked list, source label) for the dashboard.

    The source label tells the UI banner whether the ordering came from the
    real brain or the local fallback so the owner is never misled about
    where the numbers came from.

    Display normalisation: after building the list we stamp each row's
    ``score_pct`` with a 0–100 value relative to the top score. The raw
    ``score`` (used for sorting) is left untouched — ordering is preserved.
    """
    real_scores = _try_brain_rank(node_views)
    if real_scores is not None:
        # "real" = ordering came from fleet.brain.rank (unified with the
        # placement adapter's BRAIN_BACKEND == "real"). "fallback" = local stub.
        ranked = _merge_brain_scores(real_scores, node_views)
        source = "real"
    else:
        ranked = _fallback_rank(node_views)
        source = "fallback"
    _assign_display_scores(ranked)
    return ranked, source


def _assign_display_scores(ranked: list[RankedNode]) -> None:
    """Stamp ``score_pct`` (0..100) on every row, relative to the top score.

    The top eligible row (or the top overall row when nothing is eligible)
    anchors 100. Other rows scale down by ratio. Excluded rows still receive
    a percentage so the operator can see "this would have been #2 if it were
    eligible". Always clamped to [0, 100]; if the anchor is ≤ 0 every row
    falls back to 0 (no divide-by-zero).
    """
    if not ranked:
        return
    # Prefer an eligible row as the anchor (it's the score that means "best
    # node currently in rotation"). Fall back to the overall top when no
    # row is eligible.
    eligible_scores = [r.score for r in ranked if r.eligible]
    top = max(eligible_scores) if eligible_scores else max(r.score for r in ranked)
    for r in ranked:
        if top is None or top <= 0:
            r.score_pct = 0
        else:
            pct = round((r.score / top) * 100)
            r.score_pct = max(0, min(100, int(pct)))


def brain_available() -> bool:
    """Lightweight introspection for the UI banner."""
    return brain_rank is not None


# ────────────────────────────────────────────────────────────────────────────
# Real-brain path
# ────────────────────────────────────────────────────────────────────────────


def _try_brain_rank(node_views: list[NodeView]) -> list[Any] | None:
    """Call the brain's ``rank()`` if importable. Returns ``None`` on any
    failure so the dashboard transparently falls back."""
    if brain_rank is None:
        return None
    try:
        result = brain_rank()  # contract: list[NodeScore], best-first
    except Exception:  # noqa: BLE001 - keep the dashboard alive
        return None
    if not isinstance(result, list):
        return None
    return result


def _merge_brain_scores(scores: list[Any], node_views: list[NodeView]) -> list[RankedNode]:
    """Map ``NodeScore`` objects onto our render shape; pad with locally-known
    nodes the brain may have omitted (eg. drained ones) so the operator sees
    the full fleet ordered + excluded section."""
    view_by_id = {v.node.id: v for v in node_views}
    seen_ids: set[int] = set()
    out: list[RankedNode] = []

    for rank_idx, ns in enumerate(scores, start=1):
        node_id = int(getattr(ns, "node_id", 0) or 0)
        seen_ids.add(node_id)
        view = view_by_id.get(node_id)
        node = view.node if view else None
        eligible = bool(getattr(ns, "eligible", True))
        reasons = getattr(ns, "reasons", None) or {}
        out.append(
            RankedNode(
                rank=rank_idx,
                node_id=node_id,
                name=str(getattr(ns, "name", "") or (node.name if node else f"#{node_id}")),
                public_ip=(node.public_ip if node else ""),
                provider_name=(node.provider.name if node and node.provider else None),
                score=float(getattr(ns, "score", 0.0) or 0.0),
                eligible=eligible,
                excluded_reason=_brain_excluded_reason(ns, view),
                factors=_factors_from_brain_reasons(reasons, view),
                source="real",
            )
        )

    # Tail: any node the brain didn't return — render it as excluded so the
    # operator still sees it (and why we think the brain dropped it).
    next_rank = len(out) + 1
    for v in node_views:
        if v.node.id in seen_ids:
            continue
        out.append(_fallback_one(next_rank, v, force_eligible=False, source="real"))
        next_rank += 1

    return out


def _brain_excluded_reason(ns: Any, view: NodeView | None) -> str | None:
    """Pick the human-friendly Arabic reason from a NodeScore.reasons dict.

    Common keys we support: ``excluded_reason`` (free text), ``unhealthy``,
    ``shed``, ``drain``, ``disabled``, ``full``. Anything else falls back to
    a local guess from the view's health/registry state.
    """
    if bool(getattr(ns, "eligible", True)):
        return None
    reasons = getattr(ns, "reasons", None) or {}
    if isinstance(reasons, dict):
        if reasons.get("excluded_reason"):
            return str(reasons["excluded_reason"])[:80]
        for key, label in _BRAIN_EXCLUSION_LABELS.items():
            if reasons.get(key):
                return label
    return _local_excluded_reason(view) or "مستبعد من الترتيب"


_BRAIN_EXCLUSION_LABELS = {
    "unhealthy": "مفصول",
    "down":      "مفصول",
    "shed":      "قرب الحدّ (تخفيف الحمل)",
    "drain":     "منزوح (لا يقبل جلسات جديدة)",
    "disabled":  "مُعطّل يدوياً",
    "full":      "السعة ممتلئة",
}


def _factors_from_brain_reasons(reasons: Any, view: NodeView | None) -> list[FactorChip]:
    """Render the brain's per-factor dict into Arabic chips.

    We accept either:
      * a top-level dict whose keys map directly (health/cpu/cost/capacity)
        to chip dicts ``{label, level, detail}``, or
      * a flat numeric dict (e.g. ``{"cpu_util": 0.37, ...}``) which we
        translate into chips ourselves.
    """
    if not isinstance(reasons, dict) or not reasons:
        return _factors_from_view(view) if view else []
    chips: list[FactorChip] = []
    factor_seen: set[str] = set()
    for key in ("health", "cpu", "cost", "capacity"):
        raw = reasons.get(key)
        if isinstance(raw, dict) and ("label" in raw or "level" in raw):
            chips.append(FactorChip(
                key=key,
                label=str(raw.get("label") or key),
                level=str(raw.get("level") or "info"),
                detail=str(raw.get("detail") or ""),
            ))
            factor_seen.add(key)
    # Fill in any factor the brain omitted from our locally-derived view so
    # the chip strip is always the same shape — easier for the operator to
    # scan across rows.
    if view is not None:
        for chip in _factors_from_view(view):
            if chip.key not in factor_seen:
                chips.append(chip)
    return chips


# ────────────────────────────────────────────────────────────────────────────
# Fallback path — runs when the brain isn't importable yet
# ────────────────────────────────────────────────────────────────────────────


def _fallback_rank(node_views: list[NodeView]) -> list[RankedNode]:
    """Local scoring + ranking. Same order the brain *should* produce given
    the documented weights — close enough to make the dashboard meaningful
    before fleet.brain ships."""
    scored: list[tuple[float, NodeView]] = [
        (_compute_score(v), v) for v in node_views
    ]
    # Best-first, then by name for deterministic tie-breaks.
    scored.sort(key=lambda x: (-x[0], x[1].node.name))
    ranked: list[RankedNode] = []
    for idx, (score, view) in enumerate(scored, start=1):
        ranked.append(_fallback_one(idx, view, score=score))
    return ranked


def _fallback_one(
    rank: int,
    view: NodeView,
    *,
    score: float | None = None,
    force_eligible: bool | None = None,
    source: str = "fallback",
) -> RankedNode:
    score = _compute_score(view) if score is None else score
    eligible, reason = _eligibility(view)
    if force_eligible is False:
        eligible = False
    n = view.node
    return RankedNode(
        rank=rank,
        node_id=n.id,
        name=n.name,
        public_ip=n.public_ip,
        provider_name=n.provider.name if n.provider else None,
        score=score,
        eligible=eligible,
        excluded_reason=None if eligible else reason,
        factors=_factors_from_view(view),
        source=source,
    )


# ────────────────────────────────────────────────────────────────────────────
# Score computation — mirrors fleet.config.ScoringWeights
# ────────────────────────────────────────────────────────────────────────────


# Used to normalise ping_rtt_ms into a [0..1] penalty. 200 ms ≈ poor.
_RTT_PENALTY_CAP_MS = 200.0
# Used to scale "cost preference". 0 cost → 1.0; expensive open-ended → 0.0.
_COST_PENALTY_CAP_PRICE = 20.0  # $/TB above which we floor the cost score


def _compute_score(view: NodeView) -> float:
    """Return a [0..1]-ish weighted score (higher is better).

    Missing signals are treated as *neutral* (0.5) so a brand-new node with
    no telemetry doesn't crash to the bottom — same convention as the brain
    contract in docs/contracts/fleet_api.md §1: "missing metrics treated as
    neutral, does not penalise"."""
    w = FLEET.scoring
    m = view.metric
    n = view.node

    # CPU headroom (1 - util). cpu_pct is 0..100.
    cpu_util = (m.cpu_pct or 50.0) / 100.0
    cpu_headroom = max(0.0, 1.0 - cpu_util)

    # Latency. Lower RTT → higher score.
    rtt = m.ping_rtt_ms
    if rtt is None:
        latency_pref = 0.5
    else:
        latency_pref = max(0.0, 1.0 - min(rtt, _RTT_PENALTY_CAP_MS) / _RTT_PENALTY_CAP_MS)

    # Session headroom (1 - used / capacity).
    capacity = int(n.max_sessions or 0)
    used = int(m.active_sessions if m.active_sessions is not None else (n.active_sessions or 0))
    if capacity > 0:
        session_headroom = max(0.0, 1.0 - min(1.0, used / capacity))
    else:
        session_headroom = 0.5

    # Cost preference. open/inherit-open → 1.0; metered → scaled by price.
    cost_pref = _cost_preference(n)

    score = (
        w.cpu_headroom     * cpu_headroom
        + w.latency        * latency_pref
        + w.session_headroom * session_headroom
        + w.cost           * cost_pref
    )
    # Normalise so the chip bar can render as a percent.
    total_weight = w.cpu_headroom + w.latency + w.session_headroom + w.cost
    return score / total_weight if total_weight > 0 else 0.0


def _cost_preference(node: FleetChrNode) -> float:
    """Return a [0..1] preference: cheaper / less constrained → higher."""
    model = (node.cost_model or "inherit").lower()
    if model == "inherit":
        model = (node.provider.cost_model if node.provider else "open").lower()
    if model == "open":
        return 1.0
    # metered: bias by price (lower price → higher score).
    price = node.price_per_tb if node.price_per_tb is not None else (
        node.provider.price_per_tb if node.provider else None
    )
    if price is None:
        return 0.7  # neutral-ish; we don't know the price
    p = float(price)
    if p <= 0:
        return 1.0
    return max(0.0, 1.0 - min(p, _COST_PENALTY_CAP_PRICE) / _COST_PENALTY_CAP_PRICE)


# ────────────────────────────────────────────────────────────────────────────
# Eligibility + chip generation
# ────────────────────────────────────────────────────────────────────────────


def _eligibility(view: NodeView) -> tuple[bool, str | None]:
    """Return (eligible, arabic_reason_if_not)."""
    n = view.node
    h = view.health
    if not bool(n.enabled):
        return False, "مُعطّل يدوياً"
    if bool(n.drain):
        return False, "منزوح (لا يقبل جلسات جديدة)"
    if (n.status or "").lower() == "disabled":
        return False, "مُعطّل في السجل"
    if h.state == "down":
        return False, "مفصول"
    if h.state == "degraded":
        # Degraded is not auto-excluded but flagged "قرب الحدّ".
        return True, None
    return True, None


def _factors_from_view(view: NodeView) -> list[FactorChip]:
    return [
        _factor_health(view),
        _factor_cpu(view),
        _factor_capacity(view),
        _factor_cost(view),
    ]


def _factor_health(view: NodeView) -> FactorChip:
    state = view.health.state if view.health.state in HEALTH_STATES else "unknown"
    label = {
        "up":       "الصحّة: متّصلة",
        "degraded": "الصحّة: متدهورة",
        "down":     "الصحّة: مفصول",
        "unknown":  "الصحّة: غير معروفة",
    }[state]
    level = {"up": "ok", "degraded": "warn", "down": "bad", "unknown": "info"}[state]
    detail = ""
    if view.health.last_transition:
        detail = f"آخر تحوّل: {view.health.last_transition}"
    return FactorChip(key="health", label=label, level=level, detail=detail)


def _factor_cpu(view: NodeView) -> FactorChip:
    cpu = view.metric.cpu_pct
    threshold = FLEET.health.cpu_shed_threshold_pct
    if cpu is None:
        return FactorChip(key="cpu", label="المعالج: لا توجد قياسات", level="info")
    if cpu >= threshold:
        return FactorChip(
            key="cpu",
            label=f"المعالج: {cpu:.0f}٪ — قرب الحدّ",
            level="bad",
            detail=f"حدّ تخفيف الحمل {threshold:.0f}٪",
        )
    if cpu >= threshold * 0.7:
        return FactorChip(key="cpu", label=f"المعالج: {cpu:.0f}٪", level="warn")
    return FactorChip(key="cpu", label=f"المعالج: {cpu:.0f}٪", level="ok")


def _factor_capacity(view: NodeView) -> FactorChip:
    cap = int(view.node.max_sessions or 0)
    used = int(view.metric.active_sessions if view.metric.active_sessions is not None
               else (view.node.active_sessions or 0))
    if cap <= 0:
        return FactorChip(key="capacity", label="السعة: غير محدّدة", level="info")
    ratio = used / cap
    pct = round(ratio * 100)
    if ratio >= 1.0:
        return FactorChip(key="capacity", label=f"السعة: ممتلئة ({used}/{cap})", level="bad")
    if ratio >= 0.85:
        return FactorChip(key="capacity", label=f"السعة: {used}/{cap} — قرب الحدّ", level="warn",
                          detail=f"{pct}٪ من السعة")
    return FactorChip(key="capacity", label=f"السعة: {used}/{cap}", level="ok",
                      detail=f"{pct}٪ من السعة")


def _factor_cost(view: NodeView) -> FactorChip:
    n = view.node
    model = (n.cost_model or "inherit").lower()
    if model == "inherit":
        provider_model = (n.provider.cost_model if n.provider else "open").lower()
        if provider_model == "open":
            return FactorChip(key="cost", label="الكلفة: مفتوحة (موروثة)", level="ok",
                              detail=f"من {n.provider.name}" if n.provider else "")
        # metered via provider
        return _cost_chip_metered(
            price=n.provider.price_per_tb if n.provider else None,
            cap_tb=n.provider.monthly_cap_tb if n.provider else None,
            used_tb=float(n.used_tb_cycle or 0),
            overage_allowed=bool(n.provider.overage_allowed) if n.provider else False,
            from_label="موروثة من المزود",
        )
    if model == "open":
        return FactorChip(key="cost", label="الكلفة: مفتوحة (غير محدودة)", level="ok")
    # node-level metered
    return _cost_chip_metered(
        price=n.price_per_tb,
        cap_tb=n.bandwidth_cap_tb,
        used_tb=float(n.used_tb_cycle or 0),
        overage_allowed=bool(n.overage_allowed),
        from_label="على مستوى العقدة",
    )


def _cost_chip_metered(
    *,
    price: Any,
    cap_tb: Any,
    used_tb: float,
    overage_allowed: bool,
    from_label: str,
) -> FactorChip:
    price_str = f"{float(price):.2f}$/TB" if price is not None else "السعر غير محدّد"
    cap = float(cap_tb) if cap_tb is not None else None
    if cap is None or cap <= 0:
        return FactorChip(key="cost", label=f"الكلفة: محدودة، {price_str}", level="info",
                          detail=from_label)
    ratio = used_tb / cap
    pct = round(ratio * 100)
    if ratio >= 1.0:
        suffix = "تجاوز السقف" + (" — مدفوع" if overage_allowed else " — ممنوع")
        return FactorChip(key="cost",
                          label=f"الكلفة: محدودة — {suffix}",
                          level="warn" if overage_allowed else "bad",
                          detail=f"{used_tb:.1f}/{cap:.0f} TB · {price_str}")
    if ratio >= 0.85:
        return FactorChip(key="cost",
                          label=f"الكلفة: محدودة — قرب الحدّ ({pct}٪)",
                          level="warn",
                          detail=f"{used_tb:.1f}/{cap:.0f} TB · {price_str}")
    return FactorChip(key="cost",
                      label=f"الكلفة: محدودة — ضمن السقف ({pct}٪)",
                      level="ok",
                      detail=f"{used_tb:.1f}/{cap:.0f} TB · {price_str}")


def _local_excluded_reason(view: NodeView | None) -> str | None:
    if view is None:
        return None
    eligible, reason = _eligibility(view)
    return None if eligible else reason


__all__ = [
    "FactorChip",
    "RankedNode",
    "ranked_view_for",
    "brain_available",
]
