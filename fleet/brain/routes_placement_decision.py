"""fleet.brain.routes_placement_decision — GET /api/proxy/placement-decision.

Implements the read endpoint the proxy's ``resolve_decision`` calls. Freezes
``docs/contracts/fleet_api.md §6``. Same auth as §1 telemetry: ``X-Proxy-Token``
HMAC; we reuse ``app.api.proxy_api._verify_proxy_token`` verbatim — **no new
auth surface**.

Why a separate blueprint?
-------------------------
The route lives on ``/api/proxy`` for proxy-team locality but in its own
``fleet.brain`` blueprint so the existing ``app/api/proxy_api.py`` stays
untouched. The §1 telemetry route did the same, for the same reason: each
fleet task can ship its own routes without editing a shared file.
"""

from __future__ import annotations

from flask import Blueprint, jsonify, request

from app.api.proxy_api import _verify_proxy_token
from app.extensions import db
from fleet.brain.brain_adapter import NodeScore
from fleet.brain.placement_query import (
    PlacementQueryError,
    _clean_n,
    serve_decision,
)


bp = Blueprint("fleet_placement_decision_api", __name__, url_prefix="/api/proxy")


def _err(code: str, http: int, detail: str = ""):
    body: dict = {"ok": False, "error": code}
    if detail:
        body["detail"] = detail
    return jsonify(body), http


def _serialise_node(ns: NodeScore) -> dict:
    """One ``top_n`` element per contract §6."""
    return {"node": ns.name, "score": ns.score, "reasons": ns.reasons}


@bp.get("/placement-decision")
def proxy_placement_decision():
    """GET /api/proxy/placement-decision — brain's headline placement (contract §6).

    Query params
    ------------
    * ``realm`` (optional, str): constrain ranking to a realm. Empty / absent
      ⇒ global ranking. Trimmed; rejected if longer than 80 chars or contains
      non ``[a-z0-9-_.@]`` characters.
    * ``current_node`` (optional, str): the node the proxy says is currently
      serving this realm. Used only for the audit row (stickiness lives in
      the brain).
    * ``n`` (optional, int 1–32, default 3): size of the ``top_n`` array.

    Response (success)::

        {
          "ok": true,
          "decision": "chr-exit-02" | null,
          "top_n": [
            {"node": "chr-exit-02", "score": 0.91, "reasons": {...}},
            ...
          ]
        }

    Error envelope (failure)::

        { "ok": false, "error": "<code>", "detail": "<text, optional>" }

    Status mapping
    --------------
    * 200 — successful response, including the "no eligible node" case
      (``decision: null``, ``top_n: []``).
    * 401 — bad/missing ``X-Proxy-Token``.
    * 400 — malformed query params (bad realm characters, n out of range).
    * 500 — only if persistence itself crashes (envelope: ``server_error``).
    """
    # ── Auth ────────────────────────────────────────────────────────────────
    if not _verify_proxy_token():
        return _err("unauthorized", 401)

    # ── Parse params ───────────────────────────────────────────────────────
    try:
        n = _clean_n(request.args.get("n"))
        realm = request.args.get("realm")
        current_node = request.args.get("current_node")
        result = serve_decision(
            realm=realm,
            current_node=current_node,
            n=n,
            record=True,
        )
    except PlacementQueryError as exc:
        return _err(exc.code, 400, exc.detail)

    # ── Persist audit row ──────────────────────────────────────────────────
    try:
        db.session.commit()
    except Exception:  # pragma: no cover - defensive; happy path is tested
        db.session.rollback()
        return _err("server_error", 500, "placement decision persist failed")

    # ── Wire shape (contract §6) ───────────────────────────────────────────
    payload = {
        "ok": True,
        "decision": result.decision.name if result.decision is not None else None,
        "top_n": [_serialise_node(c) for c in result.candidates],
    }
    return jsonify(payload), 200


__all__ = ["bp"]
