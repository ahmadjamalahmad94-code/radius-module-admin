"""fleet.brain.brain_adapter — single import surface for placement reads.

The proxy-facing read endpoint (``GET /api/proxy/placement-decision``, see
``fleet.brain.routes_placement_decision``) does not implement scoring — it
delegates to the brain. The brain itself is being built in parallel (Phase-5
task A); to let this task ship its endpoint + contract independently, the
adapter is the *only* place that knows whether the real brain has landed yet.

Two interchangeable backends sit behind a stable, dataclass-typed surface:

* **real**: if ``fleet.brain`` exposes ``best_node`` + ``top_n`` (and
  optionally ``NodeScore``) at import time, the adapter calls those.
* **stub**: otherwise, a tiny local implementation ranks ``fleet_chr_nodes``
  by their denormalised ``score`` column over the eligible set
  (``status='up'`` and ``enabled`` and not ``drain``) — same shape, lower
  fidelity. When the real brain lands, ``BRAIN_BACKEND`` flips to ``"real"``
  with no other code changes anywhere.

The adapter is the boundary the route asserts against; tests pin both
backends so a future brain whose return type drifts from ``(name, score,
reasons)`` will fail loudly here rather than corrupt the wire shape.

Frozen contract (matches the task brief)::

    best_node(realm: str | None = None)               -> NodeScore | None
    top_n   (realm: str | None = None, n: int = 3)    -> list[NodeScore]

    @dataclass(frozen=True)
    class NodeScore:
        name:    str            # fleet_chr_nodes.name
        score:   float          # higher = better placement
        reasons: dict[str, Any] # per-factor breakdown
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from app.extensions import db
from fleet.registry.models_chr import FleetChrNode


# ─────────────────────────────────────────────────────────────────────────────
# Stable wire-facing type
# ─────────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class NodeScore:
    """One ranked node — the unit shared with the placement-decision response.

    ``reasons`` is whatever per-factor breakdown the brain wants to show the
    proxy/operator; the adapter never edits it, only forwards it. The route
    serialises it verbatim into the response.
    """

    name: str
    score: float
    reasons: dict[str, Any] = field(default_factory=dict)


# ─────────────────────────────────────────────────────────────────────────────
# Backend resolution
# ─────────────────────────────────────────────────────────────────────────────
#: Marker set by ``_resolve_brain()``. Useful for the dashboard +
#: integration tests to know which backend is live ("real" or "stub").
BRAIN_BACKEND: str = "unresolved"


def _resolve_brain() -> tuple[Callable[..., Any] | None, Callable[..., Any] | None]:
    """Return ``(best_node, top_n)`` from the real brain, or ``(None, None)``.

    Lazy + idempotent: re-imports each call so a test fixture that swaps the
    brain backend mid-run is honoured. The cost is one ``importlib`` cache
    hit per call after the first import — negligible vs. one DB hit.
    """
    global BRAIN_BACKEND
    try:
        import fleet.brain as _brain  # noqa: PLC0415 - intentional lazy import
    except ImportError:  # pragma: no cover - skeleton always importable today
        BRAIN_BACKEND = "stub"
        return None, None

    real_best = getattr(_brain, "best_node", None)
    real_top_n = getattr(_brain, "top_n", None)
    if callable(real_best) and callable(real_top_n):
        BRAIN_BACKEND = "real"
        return real_best, real_top_n
    BRAIN_BACKEND = "stub"
    return None, None


def _coerce(raw: Any) -> NodeScore | None:
    """Convert a brain result (real NodeScore *or* duck-typed object *or*
    ``None``) into the adapter's frozen ``NodeScore``."""
    if raw is None:
        return None
    if isinstance(raw, NodeScore):
        return raw
    # Duck-typed — the real brain may use its own dataclass.
    name = getattr(raw, "name", None)
    score = getattr(raw, "score", None)
    reasons = getattr(raw, "reasons", None) or {}
    if not isinstance(name, str) or name == "":
        raise TypeError(f"brain returned a node with no .name: {raw!r}")
    if not isinstance(score, (int, float)):
        raise TypeError(f"brain returned a node with non-numeric .score: {raw!r}")
    # Phase-5 gate: mark the backend so the real-brain path carries ``source``
    # in its reasons too (the stub already does). Keeps the wire shape uniform
    # across backends — the route serialises ``reasons`` verbatim.
    coerced = dict(reasons)
    coerced["source"] = "real"
    return NodeScore(name=name, score=float(score), reasons=coerced)


def _coerce_many(raws: Iterable[Any]) -> list[NodeScore]:
    out: list[NodeScore] = []
    for r in raws:
        ns = _coerce(r)
        if ns is not None:
            # Position in the ranked list — matches the stub's ``rank`` key so
            # downstream consumers see the same reasons shape either way.
            ns.reasons.setdefault("rank", len(out))
            out.append(ns)
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Local stub — only used until the real brain lands
# ─────────────────────────────────────────────────────────────────────────────
#: The set the stub considers eligible. Matches the brain's documented
#: shed/drain rules at the registry level (excludes draining + disabled +
#: non-UP nodes). The real brain may apply finer thresholds; the stub is
#: deliberately permissive so it works on a partly-populated dev DB.
_ELIGIBLE_STATUSES = ("up",)


def _stub_query(realm: str | None) -> list[FleetChrNode]:
    """Eligible nodes for the stub backend. ``realm`` is accepted but
    intentionally unused — the stub has no per-realm allow-list awareness;
    the real brain owns that signal. Documented in §6 of the contract."""
    q = (
        FleetChrNode.query
        .filter(FleetChrNode.status.in_(_ELIGIBLE_STATUSES))
        .filter(FleetChrNode.enabled.is_(True))
        .filter(FleetChrNode.drain.is_(False))
    )
    nodes = q.all()
    # Order in Python so ``None``-valued scores sink to the end deterministically
    # (NULL ordering differs across SQLite and Postgres).
    def _key(n: FleetChrNode) -> tuple[int, float, str]:
        has_score = 0 if n.score is None else 1
        score = float(n.score) if n.score is not None else 0.0
        return (-has_score, -score, n.name)
    nodes.sort(key=_key)
    return nodes


def _node_to_score(node: FleetChrNode, *, rank: int) -> NodeScore:
    return NodeScore(
        name=node.name,
        score=float(node.score) if node.score is not None else 0.0,
        reasons={
            "source": "stub",
            "rationale": "score_desc_over_healthy_fleet",
            "rank": rank,
            "status": node.status,
            "drain": bool(node.drain),
            "enabled": bool(node.enabled),
        },
    )


def _stub_best_node(realm: str | None) -> NodeScore | None:
    rows = _stub_query(realm)
    if not rows:
        return None
    return _node_to_score(rows[0], rank=0)


def _stub_top_n(realm: str | None, n: int) -> list[NodeScore]:
    if n <= 0:
        return []
    rows = _stub_query(realm)[:n]
    return [_node_to_score(r, rank=i) for i, r in enumerate(rows)]


# ─────────────────────────────────────────────────────────────────────────────
# Public API — what the route imports
# ─────────────────────────────────────────────────────────────────────────────
def best_node(realm: str | None = None) -> NodeScore | None:
    """Return the single best eligible node for ``realm`` (or globally).

    Delegates to ``fleet.brain.best_node`` if available; otherwise consults
    the in-module stub. ``None`` means "no eligible node" — the route maps
    that to ``{"ok": true, "decision": null, "top_n": []}``.
    """
    real_best, _ = _resolve_brain()
    if real_best is not None:
        return _coerce(real_best(realm=realm))
    return _stub_best_node(realm)


def top_n(realm: str | None = None, n: int = 3) -> list[NodeScore]:
    """Return up to ``n`` best eligible nodes, best-first.

    Matches the frozen brain signature. ``n=0`` is accepted and yields
    an empty list (used by callers that only want the headline decision).
    """
    if n is None or n < 0:
        n = 0
    _, real_top = _resolve_brain()
    if real_top is not None:
        return _coerce_many(real_top(realm=realm, n=n) or [])
    return _stub_top_n(realm, n)


__all__ = [
    "NodeScore",
    "best_node",
    "top_n",
    "BRAIN_BACKEND",
]
