"""fleet.control.routes_enforcement — Phase 7 enforcement-outcome ingest.

The proxy POSTs to ``/api/proxy/enforcement`` every time it applies a
fleet-issued action (move via CoA, single-session-kill, manual kick) so
the panel can:

* Close the previous :class:`Session` row and (on a move) open a new one
  on the target node — fleet_sessions is the panel's ground-truth of
  who-is-on-which-CHR.
* Stamp the matching :class:`PlacementDecision` row with the realised
  outcome (``applied`` / ``failed``) — closes the loop between what the
  brain decided and what actually shipped.
* Append a :class:`Event` row (kind ``coa_sent`` / ``move_ok`` /
  ``move_fail``) for the operator audit log.

Contract is documented (and frozen) in ``docs/contracts/fleet_api.md §1.4
"Enforcement outcome ingest"``. Authentication reuses the existing
``X-Proxy-Token`` HMAC (mod_proxy_api.``_verify_proxy_token``); no new
secret is introduced. Malformed payloads return HTTP 400 with the
``bad_request`` machine code so a misbehaving proxy version is visible
in the panel logs instead of silently corrupting state.

Idempotency
-----------
The proxy may retry on a flaky link, so the endpoint is idempotent by
``acct_session_id`` (the RADIUS-side session id): replaying the same
outcome for the same session is a no-op. Without that guard a network
hiccup could double-count failover moves in the placement audit.
"""
from __future__ import annotations

from datetime import datetime, timezone

from flask import Blueprint, jsonify, request

from app.api.proxy_api import _verify_proxy_token
from app.extensions import db
from app.models import utcnow

from fleet.brain.models_session import PlacementDecision, Session
from fleet.notify.models_alert import Event
from fleet.registry.models_chr import FleetChrNode


bp = Blueprint("fleet_enforcement_api", __name__, url_prefix="/api/proxy")


# ════════════════════════════════════════════════════════════════════════
# Vocab (kept here so the docs + tests + handler agree on one source)
# ════════════════════════════════════════════════════════════════════════

#: The action the proxy actually applied.
ACTIONS: tuple[str, ...] = (
    "move",                 # CoA disconnect on source + client reconnects via DNS
    "kick",                 # admin/system tear-down with no rebalance intent
    "single_session_kill",  # G1 enforcement: drop one of two simultaneous
)

#: The realised result of the action.
RESULTS: tuple[str, ...] = ("applied", "failed")

#: Map (action, result) → (event_kind, event_severity).
_EVENT_MAP = {
    ("move", "applied"):   ("move_ok",   "info"),
    ("move", "failed"):    ("move_fail", "warn"),
    ("kick", "applied"):   ("coa_sent",  "info"),
    ("kick", "failed"):    ("move_fail", "warn"),
    ("single_session_kill", "applied"): ("coa_sent",  "info"),
    ("single_session_kill", "failed"):  ("move_fail", "warn"),
}


# ════════════════════════════════════════════════════════════════════════
# Endpoint
# ════════════════════════════════════════════════════════════════════════


@bp.post("/enforcement")
def enforcement_ingest():
    """POST /api/proxy/enforcement — see ``docs/contracts/fleet_api.md §1.4``.

    Request body (JSON)::

        {
          "node":             "chr-exit-02",         // required: target CHR (where the user landed)
          "user":             "bob@client5",         // required
          "action":           "move",                // required: one of ACTIONS
          "result":           "applied",             // required: one of RESULTS
          "ts":               "2026-06-09T19:40:35Z",// required: when the proxy applied it
          "acct_session_id":  "8f2c-...",            // optional but recommended: idempotency key
          "previous_node":    "chr-exit-01",         // optional: source CHR (move only)
          "reason":           "rebalance",           // optional: free-form short string
          "detail":           "..."                  // optional: error text on failure
        }

    Response shapes::

        200 { "ok": true,  "session_id": 17, "decision_id": 9,
              "event_id": 42, "idempotent": false }
        200 { "ok": true,  "idempotent": true }     // replay of same acct_session_id
        400 { "ok": false, "error": "bad_request",  "detail": "..." }
        401 { "ok": false, "error": "unauthorized" }
        404 { "ok": false, "error": "unknown_node", "detail": "chr-exit-02" }
    """
    if not _verify_proxy_token():
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    body = request.get_json(silent=True) or {}
    ok, problem = _validate(body)
    if not ok:
        try:
            from app.services.proxy_api_debug import dlog
            dlog("enforcement", accepted=False, reason="bad_request", detail=problem)
        except Exception:  # noqa: BLE001
            pass
        return jsonify({"ok": False, "error": "bad_request", "detail": problem}), 400

    node_name = str(body["node"]).strip()
    user = str(body["user"]).strip().lower()
    action = str(body["action"]).strip()
    result = str(body["result"]).strip()
    ts = _parse_ts(body["ts"])
    acct_session_id = str(body.get("acct_session_id") or "").strip()
    previous_node = str(body.get("previous_node") or "").strip() or None
    reason = str(body.get("reason") or "").strip() or None
    detail_text = str(body.get("detail") or "").strip()

    node = FleetChrNode.query.filter_by(name=node_name).one_or_none()
    if node is None:
        return jsonify({"ok": False, "error": "unknown_node", "detail": node_name}), 404
    prev_node_id = None
    if previous_node:
        prev_row = FleetChrNode.query.filter_by(name=previous_node).one_or_none()
        prev_node_id = prev_row.id if prev_row is not None else None

    # ── Idempotency guard: if an Event with the same acct_session_id +
    # action + result was already recorded, do not double-record.
    if acct_session_id:
        existing = (
            Event.query
            .filter(Event.kind.in_(("coa_sent", "move_ok", "move_fail")))
            .filter(Event.detail_json.contains(f'"acct_session_id": "{acct_session_id}"'))
            .first()
        )
        if existing is not None:
            return jsonify({"ok": True, "idempotent": True})

    # 1. Sessions table: close any prior active session for this user, then
    # (on success) open a new one rooted at the target node. We never
    # half-publish: failures DO NOT mutate the session graph beyond
    # closing the source. This is the "one active session per user"
    # invariant enforced by the DB-level partial unique index.
    closed_session_id, opened_session_id = _update_sessions(
        user=user, target_node_id=node.id, prev_node_id=prev_node_id,
        action=action, result=result, ts=ts,
        acct_session_id=acct_session_id,
    )

    # 2. Placement decision: stamp the outcome on the most recent
    # matching decision row for this user (so the audit closes the loop).
    decision_id = _stamp_decision(
        user=user, target_node_id=node.id, prev_node_id=prev_node_id,
        action=action, result=result, ts=ts, reason=reason,
        detail_text=detail_text,
    )

    # 3. Event row for the operator audit / Phase-9 notifier.
    event_kind, severity = _EVENT_MAP.get((action, result), ("move_fail", "warn"))
    ev = Event(chr_id=node.id, ts=ts, kind=event_kind, severity=severity)
    ev.detail = {
        "user": user,
        "node": node_name,
        "previous_node": previous_node or "",
        "action": action,
        "result": result,
        "reason": reason or "",
        "acct_session_id": acct_session_id,
        "detail": detail_text,
    }
    db.session.add(ev)
    db.session.commit()

    # Phase-9 owner alert dispatch — best-effort, never breaks the ingest.
    try:
        from fleet.notify.notifier import dispatch_event
        dispatch_event(ev)
        db.session.commit()
    except Exception:
        pass

    try:
        from app.services.proxy_api_debug import dlog
        dlog(
            "enforcement",
            accepted=True, action=action, result=result,
            user=user, node=node_name,
            previous_node=previous_node or "",
            acct_session_id=acct_session_id or "",
            decision_id=decision_id, event_id=ev.id,
        )
    except Exception:  # noqa: BLE001
        pass
    return jsonify({
        "ok": True,
        "idempotent": False,
        "session_id": opened_session_id or closed_session_id,
        "decision_id": decision_id,
        "event_id": ev.id,
    })


# ════════════════════════════════════════════════════════════════════════
# Validation
# ════════════════════════════════════════════════════════════════════════


def _validate(body: dict) -> tuple[bool, str]:
    """Return ``(True, "")`` if body is well-formed, else ``(False, reason)``."""
    if not isinstance(body, dict):
        return False, "body must be a JSON object"
    for field in ("node", "user", "action", "result", "ts"):
        if not body.get(field):
            return False, f"missing field: {field}"
    if str(body["action"]).strip() not in ACTIONS:
        return False, f"action must be one of {ACTIONS}"
    if str(body["result"]).strip() not in RESULTS:
        return False, f"result must be one of {RESULTS}"
    ts = _parse_ts(body["ts"])
    if ts is None:
        return False, "ts must be ISO-8601"
    return True, ""


def _parse_ts(raw) -> datetime | None:
    if not raw:
        return None
    try:
        s = str(raw).strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
    except (TypeError, ValueError):
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


# ════════════════════════════════════════════════════════════════════════
# DB writers
# ════════════════════════════════════════════════════════════════════════


def _update_sessions(
    *, user: str, target_node_id: int, prev_node_id: int | None,
    action: str, result: str, ts: datetime, acct_session_id: str,
) -> tuple[int | None, int | None]:
    """Apply the outcome to the sessions table.

    * On ``applied`` action ``move`` or ``kick``: close the user's
      currently-active session (if any) and — for ``move`` only —
      insert a fresh active row on the target node.
    * On ``failed``: close the source session so we don't lie about
      where the user is (the user is likely disconnected on the source
      while the brain plans a retry). We do NOT open a new row.

    Returns ``(closed_id, opened_id)``. Either may be None.
    """
    active = (
        Session.query
        .filter(Session.username == user, Session.state == "active")
        .order_by(Session.started_at.desc())
        .first()
    )
    closed_id = None
    opened_id = None

    if active is not None and (
        action in ("move", "kick", "single_session_kill")
    ):
        active.state = "closed"
        active.closed_at = ts
        db.session.add(active)
        closed_id = active.id

    # Only ``applied move`` actually opens the new placement row. ``kick``
    # and ``single_session_kill`` deliberately do not open a new row —
    # the user is being disconnected, not relocated.
    if action == "move" and result == "applied":
        framed_ip = (active.framed_ip if active is not None else "0.0.0.0")
        realm = (active.realm if active is not None else "")
        new_row = Session(
            username=user, realm=realm, chr_id=target_node_id,
            framed_ip=framed_ip,
            acct_session_id=(acct_session_id or f"p7-{user}-{int(ts.timestamp())}"),
            state="active", started_at=ts, last_acct_at=ts,
        )
        db.session.add(new_row)
        db.session.flush()
        opened_id = new_row.id

    return closed_id, opened_id


def _stamp_decision(
    *, user: str, target_node_id: int, prev_node_id: int | None,
    action: str, result: str, ts: datetime, reason: str | None,
    detail_text: str,
) -> int | None:
    """Find the most recent pending decision for this user and stamp it.

    If no pending decision exists, we INSERT a synthetic decision row so
    the placement audit is complete even when the brain didn't pre-record
    the move (e.g. ``single_session_kill`` is reactive, not planned).
    """
    pd = (
        PlacementDecision.query
        .filter(PlacementDecision.username == user)
        .filter(PlacementDecision.outcome == "pending")
        .order_by(PlacementDecision.decided_at.desc())
        .first()
    )
    new_outcome = "applied" if result == "applied" else "failed"
    if pd is not None:
        pd.outcome = new_outcome
        # Merge the realised outcome into the reason snapshot so a single
        # audit row tells the whole story.
        existing = pd.reason
        pd.reason = {
            **existing,
            "applied_at": ts.isoformat() + "Z",
            "applied_action": action,
            "applied_result": result,
            "applied_detail": detail_text,
        }
        db.session.add(pd)
        return pd.id

    # No pending decision — synthesise one. Kind defaults to "manual"
    # because a reactive enforcement (e.g. single-session-kill on a race)
    # is operator-or-system-initiated, not a scheduled rebalance.
    kind = "manual"
    if action == "move":
        kind = "rebalance"
    if reason == "forced_failover":
        kind = "forced_failover"
    new = PlacementDecision(
        username=user, decided_at=ts, kind=kind,
        from_chr_id=prev_node_id, to_chr_id=target_node_id,
        outcome=new_outcome,
    )
    new.reason = {
        "reason": reason or "",
        "applied_at": ts.isoformat() + "Z",
        "applied_action": action,
        "applied_result": result,
        "applied_detail": detail_text,
        "synthetic": True,
    }
    db.session.add(new)
    db.session.flush()
    return new.id


__all__ = ["bp", "ACTIONS", "RESULTS"]
