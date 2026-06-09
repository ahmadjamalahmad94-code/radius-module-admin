"""fleet.brain.placement — DB-bound rank()/best_node()/top_n() on top of scoring.

The pure :mod:`fleet.brain.scoring` engine doesn't touch the DB; this
module bridges it to the panel's models. It:

1. Loads every enabled :class:`FleetChrNode` (joined with its
   :class:`FleetProvider`).
2. Looks up each node's rolling :class:`FleetChrHealth` row and the most
   recent :class:`FleetChrMetric` sample (window-clamped — stale samples
   are dropped per ``BrainConfig.fill_*`` knobs, falling back to the
   denormalized snapshot on the node row).
3. Calls :func:`scoring.score_node` for each.
4. Returns an ordered list per the **two-tier preference**:

       sort key = (tier, -score)

   * **Tier 0** — open/unlimited providers whose nodes still have at
     least ``BrainConfig.fill_spill_headroom_pct`` of session capacity
     free.
   * **Tier 1** — everything else eligible (unlimited nodes near full,
     all metered nodes).

   That ordering encodes "fill unlimited first, spill to metered only
   when unlimited is full" without distorting the per-factor score
   (within a tier the rank is pure score desc).

   Set ``cfg.brain.fill_unlimited_first = False`` to disable the tiering
   and revert to pure score-only ranking.

Realm filter
------------
``rank(realm=...)`` accepts a string but is a no-op today — realm→nodes
mapping is a future phase (P6 DNS / P7 routing). Accepting the parameter
freezes the signature so Task B and later phases can wire the filter
without breaking callers.
"""
from __future__ import annotations

from typing import Iterable, Sequence

from sqlalchemy import desc

from app.extensions import db

from fleet.brain.scoring import NodeScore, score_node
from fleet.config import FLEET, FleetConfig
from fleet.health.models_health import FleetChrHealth, FleetChrMetric
from fleet.registry.models_chr import FleetChrNode, FleetProvider


# ════════════════════════════════════════════════════════════════════════
# Public surface — FROZEN for Task B
# ════════════════════════════════════════════════════════════════════════


def rank(
    realm: str | None = None,
    *,
    cfg: FleetConfig | None = None,
) -> list[NodeScore]:
    """All eligible nodes, best first.

    Ineligible nodes are EXCLUDED entirely (not returned with score=0).
    Within the result, the two-tier sort above applies.

    The ``realm`` parameter is currently ignored (frozen for future
    realm→nodes routing). It is part of the frozen signature.
    """
    cfg = cfg or FLEET
    candidates = list(_load_candidates(cfg=cfg))
    scored = [score_node(*c, cfg=cfg) for c in candidates]
    eligible = [s for s in scored if s.eligible]
    eligible.sort(key=_sort_key)
    return eligible


def best_node(
    realm: str | None = None,
    *,
    cfg: FleetConfig | None = None,
) -> NodeScore | None:
    """Return the single best eligible node, or None if the fleet is empty."""
    results = rank(realm=realm, cfg=cfg)
    return results[0] if results else None


def top_n(
    realm: str | None = None,
    n: int = 3,
    *,
    cfg: FleetConfig | None = None,
) -> list[NodeScore]:
    """The top ``n`` eligible nodes, best first.

    ``n`` is clamped to at most :attr:`DnsConfig.top_n_cap` so the DNS
    publisher can rely on a stable upper bound. Passing ``n <= 0``
    returns an empty list (a useful no-op for callers building dynamic
    queries).
    """
    cfg = cfg or FLEET
    if n is None or n <= 0:
        return []
    n = min(int(n), int(cfg.dns.top_n_cap))
    return rank(realm=realm, cfg=cfg)[:n]


# ════════════════════════════════════════════════════════════════════════
# DB hydration
# ════════════════════════════════════════════════════════════════════════


def _load_candidates(
    *, cfg: FleetConfig,
) -> Iterable[tuple[FleetChrNode, FleetChrHealth | None, FleetChrMetric | None, FleetProvider]]:
    """Yield ``(node, health, latest_metric, provider)`` per enabled node.

    The metric lookup uses a per-node "latest by ts" query. For O(N)
    queries that's fine at fleet sizes the project expects (tens of
    nodes); when the fleet grows past a few hundred this becomes a hot
    path and Task B may swap in a single windowed query.
    """
    nodes: Sequence[FleetChrNode] = (
        db.session.query(FleetChrNode)
        .filter(FleetChrNode.enabled.is_(True))
        .order_by(FleetChrNode.id.asc())
        .all()
    )
    for node in nodes:
        health = db.session.get(FleetChrHealth, node.id)
        metric = (
            db.session.query(FleetChrMetric)
            .filter(FleetChrMetric.chr_id == node.id)
            # Prefer telemetry/control samples (they carry the cpu+sessions
            # we actually score on). 'ping' samples land here too but they
            # have no CPU; scoring falls back to the denormalized node row
            # when fields are None.
            .order_by(desc(FleetChrMetric.ts), desc(FleetChrMetric.id))
            .first()
        )
        provider = node.provider or db.session.get(FleetProvider, node.provider_id)
        yield node, health, metric, provider


# ════════════════════════════════════════════════════════════════════════
# Sort key
# ════════════════════════════════════════════════════════════════════════


def _sort_key(s: NodeScore) -> tuple[int, float]:
    """Two-tier preference: (tier asc, score desc → negate for ascending sort)."""
    tier = int(s.reasons.get("tier", 1))
    return (tier, -float(s.score))


__all__ = [
    "rank",
    "best_node",
    "top_n",
]
