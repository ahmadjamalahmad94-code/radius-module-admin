"""fleet.health.routes_telemetry — POST /api/proxy/telemetry endpoint.

Implements ``docs/contracts/fleet_api.md §1`` against the panel. The route
itself is intentionally thin: auth + JSON parse + delegate to
``fleet.health.telemetry_ingest``, then build the contract-shaped response.

Auth
----
Reuses the panel's existing ``X-Proxy-Token`` HMAC scheme
(``app.api.proxy_api._verify_proxy_token``) verbatim. **No new auth is
introduced** — that is the explicit §0 promise of the contract doc. Per-node
secrets are reserved for Phase 10 (see docs/chr_fleet/09_OWNER_INPUTS_AND_RISKS).

Why a separate blueprint rather than tacking onto ``proxy_api_bp``? Two reasons:
keeps the file ownership boundary clean for parallel Phase-4 agents, and lets
Phase-5 register its placement-ingest route as the sibling
``fleet.brain.routes_placement`` on the same URL prefix without forcing both
teams to edit ``app/api/proxy_api.py``.
"""

from __future__ import annotations

from datetime import datetime, timezone

from flask import Blueprint, jsonify, request

from app.api.proxy_api import _verify_proxy_token
from app.extensions import db
from fleet.health.telemetry_ingest import (
    TelemetryValidationError,
    UnknownNodeError,
    directives_for,
    health_for,
    ingest_payload,
)

# Same URL prefix as the rest of the proxy ingest surface (§1 path).
bp = Blueprint("fleet_telemetry_api", __name__, url_prefix="/api/proxy")


def _iso(dt: datetime) -> str:
    """Render a naive UTC datetime in the contract's ``...Z`` shape."""
    return dt.replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _err(code: str, http: int, detail: str = ""):
    body = {"ok": False, "error": code}
    if detail:
        body["detail"] = detail
    return jsonify(body), http


@bp.post("/telemetry")
def proxy_telemetry():
    """POST /api/proxy/telemetry — per-node health + load sample (contract §1).

    Auth: ``X-Proxy-Token`` HMAC (see app.api.proxy_api). Missing/bad → 401.

    Body: see ``docs/contracts/fleet_api.md §1`` — ``node`` + ``sampled_at``
    + ``metrics`` object are required; ``agent_version`` optional. Unknown
    metric keys are tolerated for forward compatibility.

    Response envelope (success)::

        {
          "ok": true,
          "node":        "chr-exit-01",
          "accepted_at": "2026-06-09T19:40:00Z",
          "health":      "up" | "shedding" | "down",
          "directives":  {"shed": false, "drain": false}
        }

    Error responses use the common envelope ``{"ok": false, "error": <code>}``
    with HTTP statuses:

      * ``unauthorized``     — 401 (bad/missing X-Proxy-Token)
      * ``bad_request``      — 400 (malformed payload, including non-JSON body)
      * ``unknown_node``     — 404 (node not enrolled in the registry)
      * ``server_error``     — 500 (only if persistence itself crashes)

    A malformed payload is **never** a 500 — every validation error is mapped
    to 400 in this handler.
    """
    # ── Auth ────────────────────────────────────────────────────────────────
    if not _verify_proxy_token():
        return _err("unauthorized", 401)

    # ── JSON body ──────────────────────────────────────────────────────────
    # ``silent=True`` so a non-JSON body returns 400, not 500.
    payload = request.get_json(silent=True)
    if payload is None:
        return _err("bad_request", 400, "request body must be JSON")

    # ── Validate + persist ─────────────────────────────────────────────────
    try:
        node, _row, sample = ingest_payload(payload)
    except TelemetryValidationError as exc:
        return _err(exc.code, 400, exc.detail)
    except UnknownNodeError as exc:
        return _err("unknown_node", 404, f"node {exc.node!r} is not enrolled")

    # Commit append-only insert. Any unexpected SQLAlchemy error is mapped to
    # ``server_error`` so the client gets the documented envelope.
    try:
        db.session.commit()
    except Exception:  # pragma: no cover - defensive; happy path is tested
        db.session.rollback()
        return _err("server_error", 500, "telemetry persist failed")

    # ── Response ────────────────────────────────────────────────────────────
    return jsonify({
        "ok": True,
        "node": node.name,
        "accepted_at": _iso(sample.sampled_at),
        "health": health_for(node, sample),
        "directives": directives_for(node, sample),
    }), 200


__all__ = ["bp"]
