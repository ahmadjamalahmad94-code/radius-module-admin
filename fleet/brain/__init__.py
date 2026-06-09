"""fleet.brain — scoring + placement decisions: rank nodes, shed on CPU pressure, rebalance within margin.

Phase-5 gate wiring: the scoring engine (task A) lives in two submodules —
``scoring.py`` (``score_node``, ``should_move``, ``NodeScore``) and
``placement.py`` (``rank``, ``best_node``, ``top_n``). Tasks B (placement-decision
endpoint / ``brain_adapter``) and C (ranking dashboard / ``brain_view``) import
these from the PACKAGE ROOT (``from fleet.brain import best_node, top_n, rank``),
so we re-export them here. This is what flips B's ``BRAIN_BACKEND`` and C's
``ranking_source`` from the local stub/fallback to ``"real"``.

Import order is safe: ``placement`` imports ``scoring`` as a submodule (never the
package root) and ``brain_adapter`` resolves the brain lazily, so re-exporting
here introduces no import cycle.
"""

from fleet.brain.scoring import NodeScore, score_node, should_move
from fleet.brain.placement import best_node, rank, top_n

__all__ = [
    "score_node",
    "should_move",
    "NodeScore",
    "rank",
    "best_node",
    "top_n",
]
