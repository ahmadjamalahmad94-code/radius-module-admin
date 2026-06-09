"""fleet.brain.placement_query — proxy-facing placement-decision read service.

Implements the read side of the brain that the proxy's ``resolve_decision``
calls. The endpoint (``GET /api/proxy/placement-decision``, contract §6) is
a thin Flask shell over this module so the same calls work in-process
(tests, dashboard) without going through HTTP.

What this module does
---------------------
1. Calls the brain adapter (which routes to the real brain when available,
   else a stub) to get the headline ``decision`` and the ``top_n`` ranking.
2. Persists each served decision into ``fleet_placement_decisions`` so we
   have an audit trail of what the proxy was told. This is **advisory**:
   no session is moved here — the row's ``kind='new'`` + ``outcome='pending'``
   reflects that the brain proposed it but the proxy must actuate (via §2
   placement ingest) before it counts as applied.

What this module does NOT do
----------------------------
* It does not implement scoring (that's the brain, task A).
* It does not run CoA (that's Phase 7).
* It does not move sessions (this is a read endpoint).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.extensions import db
from app.models import utcnow
from fleet.brain.brain_adapter import NodeScore, best_node, top_n
from fleet.brain.models_session import PlacementDecision
from fleet.registry.models_chr import FleetChrNode


# ─────────────────────────────────────────────────────────────────────────────
# Errors
# ─────────────────────────────────────────────────────────────────────────────
class PlacementQueryError(ValueError):
    """Raised on malformed query params. The route converts to 400."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(detail or code)
        self.code = code
        self.detail = detail


# ─────────────────────────────────────────────────────────────────────────────
# Result envelope
# ─────────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class PlacementDecisionResult:
    """In-memory shape the route serialises straight onto the wire (§6)."""

    decision: NodeScore | None
    candidates: list[NodeScore]


# ─────────────────────────────────────────────────────────────────────────────
# Validation
# ─────────────────────────────────────────────────────────────────────────────
def _clean_realm(realm: str | None) -> str | None:
    """Normalise realm: empty/whitespace → ``None``; everything else trimmed.

    The contract makes ``realm`` optional (omit ⇒ global ranking). We keep
    that behaviour but reject obvious garbage so the proxy team sees a 400
    rather than silent semantics.
    """
    if realm is None:
        return None
    cleaned = realm.strip()
    if not cleaned:
        return None
    if len(cleaned) > 80:
        raise PlacementQueryError("bad_request", "realm too long (>80 chars)")
    # Realm names map to ``proxy_realm_routes.realm`` which is 80 chars;
    # disallow characters that have no business in a realm label.
    for ch in cleaned:
        if not (ch.isalnum() or ch in "-_.@"):
            raise PlacementQueryError("bad_request", f"realm contains invalid char {ch!r}")
    return cleaned


def _clean_current_node(name: str | None) -> str | None:
    if name is None:
        return None
    cleaned = name.strip()
    if not cleaned:
        return None
    if len(cleaned) > 120:
        raise PlacementQueryError("bad_request", "current_node too long (>120 chars)")
    return cleaned


def _clean_n(raw: str | None, default: int = 3) -> int:
    if raw is None or raw == "":
        return default
    try:
        n = int(raw)
    except (TypeError, ValueError) as exc:
        raise PlacementQueryError("bad_request", f"n must be an integer, got {raw!r}") from exc
    if n < 1 or n > 32:
        raise PlacementQueryError("bad_request", "n must be in [1, 32]")
    return n


# ─────────────────────────────────────────────────────────────────────────────
# Persistence — audit row per served decision
# ─────────────────────────────────────────────────────────────────────────────
#: Pseudonym used as ``fleet_placement_decisions.username`` when the proxy
#: asks for a per-realm decision (no specific user attached to the read).
#: The decisions table requires a non-null ``username`` and uses it as the
#: audit key; using a stable, prefixed pseudonym lets ops grep them out.
_REALM_QUERY_PSEUDO_USERNAME = "__proxy_realm_query__"


def record_decision(
    *,
    realm: str | None,
    current_node: str | None,
    decision: NodeScore | None,
    candidates: list[NodeScore],
) -> PlacementDecision:
    """Append one ``fleet_placement_decisions`` row for the served result.

    Schema notes
    ------------
    * ``kind='new'`` — every served decision is the brain's *proposal*; if
      the proxy actuates it later it shows up via the §2 placement ingest
      flow with the corresponding ``reason``.
    * ``outcome='pending'`` — read endpoint never claims a decision was
      applied; that's the proxy's job to report back.
    * ``from_chr_id`` / ``to_chr_id`` are looked up by name; unknown names
      leave the column NULL (the row's ``reason_json`` still carries the
      name for forensic value).

    Caller commits — we add to the session and return so the route commits
    once for the whole request.
    """
    username = (
        f"realm:{realm}" if realm else _REALM_QUERY_PSEUDO_USERNAME
    )
    from_id = _id_by_name(current_node)
    to_id = _id_by_name(decision.name) if decision is not None else None

    reason_payload: dict[str, Any] = {
        "realm": realm,
        "current_node": current_node,
        "decision": (
            None if decision is None
            else {"name": decision.name, "score": decision.score, "reasons": decision.reasons}
        ),
        "top_n": [
            {"name": c.name, "score": c.score, "reasons": c.reasons}
            for c in candidates
        ],
    }

    row = PlacementDecision(
        username=username,
        decided_at=utcnow(),
        kind="new",
        from_chr_id=from_id,
        to_chr_id=to_id,
        outcome="pending",
    )
    row.reason = reason_payload
    db.session.add(row)
    return row


def _id_by_name(name: str | None) -> int | None:
    if not name:
        return None
    node = FleetChrNode.query.filter_by(name=name).first()
    return node.id if node else None


# ─────────────────────────────────────────────────────────────────────────────
# The one function the route + dashboard share
# ─────────────────────────────────────────────────────────────────────────────
def serve_decision(
    *,
    realm: str | None = None,
    current_node: str | None = None,
    n: int = 3,
    record: bool = True,
) -> PlacementDecisionResult:
    """Compute + (optionally) record the brain's placement proposal.

    Parameters
    ----------
    realm:
        Optional realm constraint. ``None`` ⇒ global ranking. The brain
        adapter is free to interpret realm membership; the local stub
        ignores it (documented in §6).
    current_node:
        The node the proxy says this realm/user is currently on. Only used
        for the audit row (the brain may also use it for stickiness in a
        future revision).
    n:
        Size of ``top_n``. The decision (1st place) is the same node that
        appears first in ``top_n`` unless ``n=0``.
    record:
        Whether to insert the audit row. ``True`` for HTTP serving; tests
        set ``False`` when exercising pure compute without DB side-effects.

    Returns
    -------
    ``PlacementDecisionResult`` with ``.decision`` (``NodeScore | None``)
    and ``.candidates`` (``list[NodeScore]``, possibly empty).
    """
    cleaned_realm = _clean_realm(realm)
    cleaned_current = _clean_current_node(current_node)

    # Brain calls. The adapter handles real-vs-stub backend selection.
    headline = best_node(realm=cleaned_realm)
    candidates = top_n(realm=cleaned_realm, n=n)

    # Self-consistency: when both populated, headline must lead top_n.
    # If the real brain ever violates that, surface it as a 500-class bug
    # rather than silently disagree on the wire — the adapter's
    # NodeScore comparison is name-based.
    if headline is not None and candidates and candidates[0].name != headline.name:
        # Defensive fix: trust ``best_node``; rewrite candidates head.
        candidates = [headline, *(c for c in candidates if c.name != headline.name)][:max(n, 1)]

    result = PlacementDecisionResult(decision=headline, candidates=candidates)
    if record:
        record_decision(
            realm=cleaned_realm,
            current_node=cleaned_current,
            decision=headline,
            candidates=candidates,
        )
    return result


__all__ = [
    "PlacementDecisionResult",
    "PlacementQueryError",
    "serve_decision",
    "record_decision",
    "_clean_realm",
    "_clean_current_node",
    "_clean_n",
]
