"""CHR Fleet Phase 7 — panel verification.

Covers four surfaces:

1. **Live-apply settings store** — flag persists, default OFF, toggle
   via the UI-only POST handler, audit row written.
2. **Routing-table flag** — additive field appears in the existing
   ``GET /api/proxy/routing-table`` response, tracks the settings
   store, missing/error path collapses to False.
3. **Movable-flag CRUD** — per-user toggle endpoint and the seed form.
4. **Enforcement-outcome ingest** — auth gate, malformed payload → 400,
   unknown node → 404, happy path records (Session, PlacementDecision,
   Event) and is idempotent by ``acct_session_id``.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time

import pytest

from app.extensions import db
from app.models import Setting

from fleet.brain.models_session import PlacementDecision, Session, UserFleet
from fleet.control.live_apply_settings import (
    SETTING_KEY as LIVE_APPLY_KEY,
    is_enabled as live_apply_is_enabled,
    load_view as live_apply_view,
    set_enabled as live_apply_set_enabled,
)
from fleet.notify.models_alert import Event
from fleet.registry.models_chr import FleetChrNode, FleetProvider


# ════════════════════════════════════════════════════════════════════════
# Fixtures
# ════════════════════════════════════════════════════════════════════════


_NODE_SEQ: list[int] = [0]


def _provider() -> FleetProvider:
    p = FleetProvider.query.first()
    if p is not None:
        return p
    p = FleetProvider(name="acme", cost_model="open", price_per_tb=0,
                      overage_allowed=False, billing_cycle_day=1)
    db.session.add(p); db.session.commit()
    return p


def _node(name: str) -> FleetChrNode:
    _NODE_SEQ[0] += 1
    h = _NODE_SEQ[0]
    n = FleetChrNode(
        provider_id=_provider().id, name=name,
        public_ip=f"203.0.113.{h}", wg_mgmt_ip=f"10.99.0.{h}",
        wg_mgmt_pubkey="x" * 44,
        max_sessions=500, link_speed_mbps=1000,
        weight=1.0, enabled=True, status="up",
    )
    db.session.add(n); db.session.commit()
    return n


def _user(username: str = "alice@client5", *, movable: bool = False) -> UserFleet:
    u = UserFleet(customer_id=1, realm="client5",
                  username=username, movable=movable)
    db.session.add(u); db.session.commit()
    return u


def _admin_login(client) -> None:
    """Manually install an admin session — the existing _login route is
    deliberately not exercised by this suite (other suites already do)."""
    from app.models import Admin
    a = Admin.query.first()
    if a is None:
        a = Admin(username="p7_test", active=True, is_super_admin=True)
        a.set_password("x" * 12)
        db.session.add(a); db.session.commit()
    with client.session_transaction() as sess:
        sess["admin_id"] = a.id
        sess["admin_name"] = a.full_name or a.username
        # CSRF token written under the same key the verifier reads.
        sess["_csrf_token"] = "p7-csrf-token"


def _csrf() -> dict:
    return {"_csrf_token": "p7-csrf-token"}


_NONCE_SEQ: list[int] = [0]


def _proxy_token(app, *, ts: int | None = None, nonce: str | None = None) -> str:
    """Build a valid ``X-Proxy-Token`` for the proxy / enforcement endpoints.

    Each call produces a unique nonce by default so the proxy_api replay
    cache (``_NONCE_CACHE`` in ``app.api.proxy_api``) does not reject the
    second request in the suite as a replay. Pass an explicit ``nonce``
    when you need a deterministic value (e.g. simulating a retry).
    """
    secret = app.config["RADIUS_PROXY_SHARED_SECRET"]
    if not secret:
        secret = "test-shared-secret"
        app.config["RADIUS_PROXY_SHARED_SECRET"] = secret
    if ts is None:
        ts = int(time.time())
    if nonce is None:
        _NONCE_SEQ[0] += 1
        nonce = f"p7-nonce-{_NONCE_SEQ[0]}"
    nonce_with_ts = f"{ts}:{nonce}"
    mac = hmac.new(secret.encode(), nonce_with_ts.encode(),
                   hashlib.sha256).hexdigest()
    return f"{ts}:{nonce}:{mac}"


# ════════════════════════════════════════════════════════════════════════
# 1. Live-apply settings store
# ════════════════════════════════════════════════════════════════════════


def test_live_apply_default_off(app):
    assert live_apply_is_enabled() is False
    view = live_apply_view()
    assert view["enabled"] is False


def test_live_apply_persists_after_set(app):
    live_apply_set_enabled(True)
    assert live_apply_is_enabled() is True
    # Reach into the underlying Setting row to confirm wire format.
    row = db.session.get(Setting, LIVE_APPLY_KEY)
    assert row is not None and row.value == "1"

    live_apply_set_enabled(False)
    assert live_apply_is_enabled() is False
    row = db.session.get(Setting, LIVE_APPLY_KEY)
    assert row is not None and row.value == "0"


def test_live_apply_audit_called(app):
    seen = []
    def fake_audit(action, etype, eid, msg, payload):
        seen.append((action, etype, eid, payload))

    live_apply_set_enabled(True, actor_audit=fake_audit, actor_label="admin")
    assert seen and seen[0][0] == "fleet_live_apply_toggled"
    assert seen[0][3]["to"] == "1"
    assert seen[0][3]["actor"] == "admin"


# ════════════════════════════════════════════════════════════════════════
# 2. Routing-table flag (additive)
# ════════════════════════════════════════════════════════════════════════


def test_routing_table_carries_live_apply_default_false(app, client):
    token = _proxy_token(app)
    r = client.get("/api/proxy/routing-table",
                   headers={"X-Proxy-Token": token})
    assert r.status_code == 200
    body = r.get_json()
    assert body["ok"] is True
    assert "live_apply_enabled" in body
    assert body["live_apply_enabled"] is False


def test_routing_table_reflects_toggle(app, client):
    live_apply_set_enabled(True)
    token = _proxy_token(app)
    r = client.get("/api/proxy/routing-table",
                   headers={"X-Proxy-Token": token})
    assert r.status_code == 200
    assert r.get_json()["live_apply_enabled"] is True


def test_routing_table_requires_auth(app, client):
    r = client.get("/api/proxy/routing-table")
    assert r.status_code == 401


# ════════════════════════════════════════════════════════════════════════
# 3. UI: live-apply toggle + movable flag
# ════════════════════════════════════════════════════════════════════════


def test_dashboard_renders(app, client):
    _admin_login(client)
    r = client.get("/admin/fleet/p7/")
    assert r.status_code == 200
    body = r.data.decode("utf-8", errors="replace")
    assert "التطبيق الحي" in body
    assert "قابلية النقل" in body


def test_ui_live_apply_toggle_persists_and_redirects(app, client):
    _admin_login(client)
    r = client.post(
        "/admin/fleet/p7/live-apply",
        data={"desired": "on", **_csrf()},
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert live_apply_is_enabled() is True

    # Flip back.
    r = client.post(
        "/admin/fleet/p7/live-apply",
        data={"desired": "off", **_csrf()},
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert live_apply_is_enabled() is False


def test_ui_live_apply_rejects_bogus_value(app, client):
    _admin_login(client)
    r = client.post(
        "/admin/fleet/p7/live-apply",
        data={"desired": "maybe", **_csrf()},
        follow_redirects=False,
    )
    # Still a redirect (flash carries the error), but no change.
    assert r.status_code == 302
    assert live_apply_is_enabled() is False


def test_ui_seed_user_then_toggle_movable(app, client):
    _admin_login(client)
    r = client.post(
        "/admin/fleet/p7/users",
        data={"username": "bob@client5", "realm": "client5",
              "customer_id": "7", "movable": "off", **_csrf()},
        follow_redirects=False,
    )
    assert r.status_code == 302
    u = UserFleet.query.filter_by(username="bob@client5").one()
    assert u.movable is False

    r = client.post(
        f"/admin/fleet/p7/users/{u.id}/movable",
        data={"desired": "on", **_csrf()},
        follow_redirects=False,
    )
    assert r.status_code == 302
    db.session.refresh(u)
    assert u.movable is True


def test_ui_movable_404_on_unknown_user(app, client):
    _admin_login(client)
    r = client.post(
        "/admin/fleet/p7/users/9999/movable",
        data={"desired": "on", **_csrf()},
    )
    assert r.status_code == 404


def test_ui_seed_user_validates_inputs(app, client):
    _admin_login(client)
    r = client.post(
        "/admin/fleet/p7/users",
        data={"username": "", "realm": "x", "customer_id": "1", **_csrf()},
        follow_redirects=False,
    )
    # Flash + redirect, no row created.
    assert r.status_code == 302
    assert UserFleet.query.count() == 0


# ════════════════════════════════════════════════════════════════════════
# 4. Enforcement-outcome ingest
# ════════════════════════════════════════════════════════════════════════


def test_enforcement_requires_auth(app, client):
    r = client.post("/api/proxy/enforcement",
                    data=json.dumps({"node": "x", "user": "x"}),
                    content_type="application/json")
    assert r.status_code == 401


def test_enforcement_malformed_returns_400(app, client):
    token = _proxy_token(app)
    r = client.post(
        "/api/proxy/enforcement",
        data=json.dumps({"node": "x"}),  # missing required fields
        content_type="application/json",
        headers={"X-Proxy-Token": token},
    )
    assert r.status_code == 400
    body = r.get_json()
    assert body["ok"] is False and body["error"] == "bad_request"


def test_enforcement_unknown_node_returns_404(app, client):
    token = _proxy_token(app)
    payload = {
        "node": "never-enrolled",
        "user": "alice@client5",
        "action": "move", "result": "applied",
        "ts": "2026-06-10T12:00:00Z",
    }
    r = client.post(
        "/api/proxy/enforcement",
        data=json.dumps(payload),
        content_type="application/json",
        headers={"X-Proxy-Token": token},
    )
    assert r.status_code == 404
    assert r.get_json()["error"] == "unknown_node"


def test_enforcement_records_move_applied(app, client):
    src = _node("chr-src")
    dst = _node("chr-dst")
    # Seed a pending decision so we can assert it gets stamped.
    pd = PlacementDecision(
        username="alice@client5", kind="rebalance",
        from_chr_id=src.id, to_chr_id=dst.id, outcome="pending",
    )
    pd.reason = {"score_before": 1.0}
    db.session.add(pd); db.session.commit()

    # Seed an existing active session on the source.
    s = Session(username="alice@client5", realm="client5",
                chr_id=src.id, framed_ip="10.0.0.1",
                acct_session_id="old-1")
    db.session.add(s); db.session.commit()

    token = _proxy_token(app, nonce="n-move-1")
    payload = {
        "node": "chr-dst",
        "user": "alice@client5",
        "action": "move", "result": "applied",
        "previous_node": "chr-src",
        "acct_session_id": "new-acct-1",
        "ts": "2026-06-10T12:00:00Z",
        "reason": "rebalance",
    }
    r = client.post(
        "/api/proxy/enforcement",
        data=json.dumps(payload),
        content_type="application/json",
        headers={"X-Proxy-Token": token},
    )
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert body["ok"] is True and body["idempotent"] is False
    assert body["session_id"] and body["decision_id"] and body["event_id"]

    # Session graph: old session closed, new session active on the target.
    closed = db.session.get(Session, s.id)
    assert closed.state == "closed"
    active = (
        Session.query
        .filter_by(username="alice@client5", state="active")
        .one()
    )
    assert active.chr_id == dst.id

    # Decision stamped applied + reason merged.
    fresh = db.session.get(PlacementDecision, pd.id)
    assert fresh.outcome == "applied"
    assert fresh.reason["applied_action"] == "move"

    # Event written with correct kind.
    ev = (
        Event.query.filter_by(chr_id=dst.id, kind="move_ok").one()
    )
    assert ev.detail["user"] == "alice@client5"


def test_enforcement_idempotent_on_replay(app, client):
    dst = _node("chr-x")
    token = _proxy_token(app, nonce="dup-1")
    payload = {
        "node": "chr-x", "user": "alice@client5",
        "action": "move", "result": "applied",
        "acct_session_id": "dup-session-1",
        "ts": "2026-06-10T12:00:00Z",
    }
    r1 = client.post(
        "/api/proxy/enforcement",
        data=json.dumps(payload),
        content_type="application/json",
        headers={"X-Proxy-Token": token},
    )
    assert r1.status_code == 200
    assert r1.get_json()["idempotent"] is False

    # Replay — a fresh proxy token (different nonce) but the same
    # acct_session_id. The endpoint must not double-record.
    token2 = _proxy_token(app, nonce="dup-2")
    r2 = client.post(
        "/api/proxy/enforcement",
        data=json.dumps(payload),
        content_type="application/json",
        headers={"X-Proxy-Token": token2},
    )
    assert r2.status_code == 200
    assert r2.get_json()["idempotent"] is True
    # Only ONE move_ok event for this user → no duplicate.
    assert Event.query.filter_by(chr_id=dst.id, kind="move_ok").count() == 1


def test_enforcement_failed_move_closes_source_only(app, client):
    src = _node("chr-fail-src")
    dst = _node("chr-fail-dst")
    s = Session(username="carol@client5", realm="client5",
                chr_id=src.id, framed_ip="10.0.0.5",
                acct_session_id="orig-2")
    db.session.add(s); db.session.commit()

    token = _proxy_token(app, nonce="fail-1")
    payload = {
        "node": "chr-fail-dst", "user": "carol@client5",
        "action": "move", "result": "failed",
        "previous_node": "chr-fail-src",
        "acct_session_id": "broken-1",
        "ts": "2026-06-10T12:05:00Z",
        "detail": "CoA timed out",
    }
    r = client.post(
        "/api/proxy/enforcement",
        data=json.dumps(payload),
        content_type="application/json",
        headers={"X-Proxy-Token": token},
    )
    assert r.status_code == 200

    db.session.refresh(s)
    assert s.state == "closed"
    # No active session was opened on the failed target.
    assert Session.query.filter_by(username="carol@client5",
                                   state="active").count() == 0
    # Event recorded as move_fail with severity warn.
    ev = Event.query.filter_by(chr_id=dst.id, kind="move_fail").one()
    assert ev.severity == "warn"
    assert ev.detail["detail"] == "CoA timed out"


def test_enforcement_synthesises_decision_when_none_pending(app, client):
    dst = _node("chr-react")
    token = _proxy_token(app, nonce="react-1")
    payload = {
        "node": "chr-react", "user": "dave@client5",
        "action": "single_session_kill", "result": "applied",
        "acct_session_id": "react-1",
        "ts": "2026-06-10T12:10:00Z",
        "reason": "dup_session",
    }
    r = client.post(
        "/api/proxy/enforcement",
        data=json.dumps(payload),
        content_type="application/json",
        headers={"X-Proxy-Token": token},
    )
    assert r.status_code == 200
    body = r.get_json()
    pd = db.session.get(PlacementDecision, body["decision_id"])
    assert pd is not None
    assert pd.reason["synthetic"] is True
    assert pd.kind == "manual"   # single_session_kill is reactive


# ════════════════════════════════════════════════════════════════════════
# 5. Smoke
# ════════════════════════════════════════════════════════════════════════


def test_create_app_boots(app):
    from sqlalchemy import inspect
    tables = set(inspect(db.engine).get_table_names())
    assert {"fleet_chr_nodes", "fleet_users", "fleet_sessions",
            "fleet_placement_decisions", "fleet_events",
            "settings"}.issubset(tables)
