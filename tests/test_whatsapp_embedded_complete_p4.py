"""Embedded Signup P4 — state-validated, idempotent completion callback.

Exercises POST /portal/whatsapp/embedded/complete end-to-end (route → service):
state/nonce enforcement, Meta-error handling, encrypted-token storage, attempt
finalization, the spec audit taxonomy, idempotent replay, tenant isolation, and
no token/secret leakage. No Meta network is touched (Graph points monkeypatched).
"""
from __future__ import annotations

from datetime import timedelta

from app.extensions import db
from app.models import (
    AuditLog,
    Customer,
    CustomerUser,
    WhatsAppEmbeddedSignupAttempt,
    WhatsAppTenantAccount,
    utcnow,
)
from app.services.customer_control import get_or_create_service_entitlement
from app.services.whatsapp import embedded_signup as es
from app.services.whatsapp import settings as wa_settings
from app.services.whatsapp.crypto import decrypt_secret

START_URL = "/portal/whatsapp/embedded/complete"
START_SESSION_URL = "/portal/whatsapp/embedded/start"
LIVE_TOKEN = "EAAB-live-token-secret-0001"
APP_SECRET = "test-app-secret"


# ───────────────────────── helpers ─────────────────────────

def _customer(username="p4-owner", email="p4@example.test", grant=True):
    c = Customer(company_name="P4 ISP", contact_name="Owner", email=email, status="active")
    db.session.add(c)
    db.session.flush()
    u = CustomerUser(customer_id=c.id, username=username, email=email,
                     full_name="Owner", role_key="owner", active=True)
    u.set_password("Secret123!", increment_version=False)
    u.password_version = 1
    db.session.add(u)
    if grant:
        ent = get_or_create_service_entitlement(c, "whatsapp_gateway")
        ent.enabled = True
        ent.status = "active"
    db.session.commit()
    return c.id


def _login(client, username="p4-owner"):
    return client.post("/portal/login", data={"username": username, "password": "Secret123!"})


def _mock_meta(monkeypatch, *, fail_exchange=False):
    counts = {"oauth": 0}

    def fake_get(path, params):
        if path == "oauth/access_token":
            counts["oauth"] += 1
            if fail_exchange:
                raise es.EmbeddedSignupError("auth_failed", "تعذّر إكمال الربط.")
            return {"access_token": LIVE_TOKEN, "expires_in": 0}
        if path == "debug_token":
            return {"data": {"scopes": ["whatsapp_business_management"]}}
        if path.startswith("PNID"):
            return {"display_phone_number": "+970 599 123456", "verified_name": "P4 Net",
                    "quality_rating": "GREEN", "messaging_limit_tier": "TIER_1K"}
        if path.startswith("WABA"):
            return {"name": "P4 WABA", "owner_business_info": {"id": "BIZ-1"}}
        return {}

    monkeypatch.setattr(es, "_graph_get", fake_get)
    monkeypatch.setattr(es, "_graph_post", lambda path, data: {"success": True})
    return counts


def _start(client):
    j = client.post(START_SESSION_URL, json={}).get_json()
    return j["state"], j["nonce"]


def _complete(client, *, code="CODE-1", waba="WABA-1", pnid="PNID-1", state=None, nonce=None):
    body = {"code": code, "waba_id": waba, "phone_number_id": pnid}
    if state is not None:
        body["state"] = state
    if nonce is not None:
        body["nonce"] = nonce
    return client.post(START_URL, json=body)


# ───────────────────────── 1. state rejection ─────────────────────────

def test_complete_rejects_invalid_state(client, app, monkeypatch):
    with app.app_context():
        _customer()
    _login(client)
    _mock_meta(monkeypatch)
    _start(client)
    resp = _complete(client, state="bogus-state", nonce="x")
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "invalid_state"
    with app.app_context():
        assert AuditLog.query.filter_by(action="embedded_signup_failed").count() == 1
        # no connection was created
        assert WhatsAppTenantAccount.query.count() == 0


def test_complete_rejects_expired_state(client, app, monkeypatch):
    with app.app_context():
        cid = _customer()
    _login(client)
    _mock_meta(monkeypatch)
    state, nonce = _start(client)
    with app.app_context():
        att = WhatsAppEmbeddedSignupAttempt.query.filter_by(customer_id=cid).one()
        att.expires_at = utcnow() - timedelta(seconds=1)
        db.session.commit()
    resp = _complete(client, state=state, nonce=nonce)
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "expired_state"
    with app.app_context():
        att = WhatsAppEmbeddedSignupAttempt.query.filter_by(customer_id=cid).one()
        assert att.status == "expired"


def test_complete_rejects_wrong_nonce(client, app, monkeypatch):
    with app.app_context():
        _customer()
    _login(client)
    _mock_meta(monkeypatch)
    state, _ = _start(client)
    resp = _complete(client, state=state, nonce="not-the-real-nonce")
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "invalid_state"


def test_complete_rejects_reused_consumed_state(client, app, monkeypatch):
    # A consumed (completed) attempt with NO live connection must be rejected,
    # not treated as an idempotent replay.
    with app.app_context():
        cid = _customer()
        issued = es.start_session(cid)
        att = WhatsAppEmbeddedSignupAttempt.query.filter_by(customer_id=cid).one()
        es._finalize_attempt(att, status="completed")  # consumed, but no account connected
        state = issued["state"]
    _login(client)
    _mock_meta(monkeypatch)
    resp = _complete(client, state=state, nonce="x")
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "invalid_state"


# ───────────────────────── 2. Meta error ─────────────────────────

def test_complete_meta_error_first_time_no_phantom_account(client, app, monkeypatch):
    # A failed FIRST exchange audits failed + fails the attempt, but does NOT
    # create a phantom error account (there is nothing to connect).
    with app.app_context():
        cid = _customer()
    _login(client)
    _mock_meta(monkeypatch, fail_exchange=True)
    state, nonce = _start(client)
    resp = _complete(client, state=state, nonce=nonce)
    assert resp.status_code == 400
    body = resp.get_json()
    assert body["error"] == "auth_failed"
    assert "token" not in body.get("message", "").lower()
    with app.app_context():
        assert AuditLog.query.filter_by(action="embedded_signup_failed").count() == 1
        att = WhatsAppEmbeddedSignupAttempt.query.filter_by(customer_id=cid).one()
        assert att.status == "failed"
        assert WhatsAppTenantAccount.query.filter_by(customer_id=cid).count() == 0


def test_complete_meta_error_on_reconnect_preserves_live_connection(client, app, monkeypatch):
    # When an account is already connected, a FAILED reconnect audits failed but
    # leaves the live connection intact (status connected, old token preserved) —
    # old credentials are replaced ONLY after a new connection succeeds.
    with app.app_context():
        cid = _customer()
    _login(client)
    _mock_meta(monkeypatch)
    s1, n1 = _start(client)
    assert _complete(client, state=s1, nonce=n1).status_code == 200   # connected
    _mock_meta(monkeypatch, fail_exchange=True)                       # now fail
    s2, n2 = _start(client)
    resp = _complete(client, state=s2, nonce=n2)
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "auth_failed"
    with app.app_context():
        assert AuditLog.query.filter_by(action="embedded_signup_failed").count() == 1
        latest = (WhatsAppEmbeddedSignupAttempt.query
                  .filter_by(customer_id=cid)
                  .order_by(WhatsAppEmbeddedSignupAttempt.id.desc()).first())
        assert latest.status == "failed"
        acc = wa_settings.get_account(cid)
        # The working connection survives the failed reconnect.
        assert acc is not None and acc.connection_status == "connected"
        assert decrypt_secret(acc.access_token_encrypted) == LIVE_TOKEN


# ───────────────────────── 3. success ─────────────────────────

def test_complete_success_stores_token_completes_attempt_and_audits(client, app, monkeypatch):
    with app.app_context():
        cid = _customer()
    _login(client)
    _mock_meta(monkeypatch)
    state, nonce = _start(client)
    resp = _complete(client, state=state, nonce=nonce)
    assert resp.status_code == 200
    assert resp.get_json()["ok"] is True
    with app.app_context():
        acc = wa_settings.get_account(cid)
        assert acc.connection_status == "connected"
        assert acc.onboarding_method == "embedded"
        # token stored ENCRYPTED and decrypts back to the live token
        assert acc.access_token_encrypted and acc.access_token_encrypted != LIVE_TOKEN
        assert decrypt_secret(acc.access_token_encrypted) == LIVE_TOKEN
        att = WhatsAppEmbeddedSignupAttempt.query.filter_by(customer_id=cid).one()
        assert att.status == "completed" and att.completed_at is not None
        assert AuditLog.query.filter_by(action="embedded_signup_succeeded").count() == 1
        assert AuditLog.query.filter_by(action="whatsapp_embedded_connected").count() == 1  # legacy alias


# ───────────────────────── 4. idempotent replay ─────────────────────────

def test_idempotent_replay_no_duplicate_connection(client, app, monkeypatch):
    with app.app_context():
        cid = _customer()
    _login(client)
    counts = _mock_meta(monkeypatch)
    state, nonce = _start(client)
    first = _complete(client, state=state, nonce=nonce)
    assert first.status_code == 200
    # Replay the exact same callback (same state).
    second = _complete(client, state=state, nonce=nonce)
    assert second.status_code == 200
    assert second.get_json().get("idempotent") is True
    assert counts["oauth"] == 1                       # NO second code exchange
    with app.app_context():
        assert WhatsAppTenantAccount.query.filter_by(customer_id=cid).count() == 1
        assert wa_settings.get_account(cid).connection_status == "connected"


# ───────────────────────── 5. tenant isolation ─────────────────────────

def test_foreign_customer_state_is_rejected(client, app, monkeypatch):
    with app.app_context():
        cid_a = _customer(username="a-owner", email="a@example.test")
        _customer(username="b-owner", email="b@example.test")
    # customer A starts a session
    _login(client, "a-owner")
    _mock_meta(monkeypatch)
    state_a, nonce_a = _start(client)
    # customer B tries to complete with A's state
    _login(client, "b-owner")
    resp = _complete(client, state=state_a, nonce=nonce_a)
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "invalid_state"
    with app.app_context():
        # B has no connection; A's attempt remains pending (untouched)
        assert WhatsAppTenantAccount.query.count() == 0
        att = WhatsAppEmbeddedSignupAttempt.query.filter_by(customer_id=cid_a).one()
        assert att.status == "pending"


# ───────────────────────── 6. no leakage ─────────────────────────

def test_no_token_or_secret_in_responses(client, app, monkeypatch):
    with app.app_context():
        _customer()
    _login(client)
    _mock_meta(monkeypatch)
    state, nonce = _start(client)
    ok = _complete(client, state=state, nonce=nonce).get_data(as_text=True)
    assert LIVE_TOKEN not in ok
    assert APP_SECRET not in ok
    # a failed (state) response likewise leaks nothing
    bad = _complete(client, state="nope", nonce="nope").get_data(as_text=True)
    assert LIVE_TOKEN not in bad and APP_SECRET not in bad


# ───────────────────────── 7. legacy safe-degrade ─────────────────────────

def test_legacy_no_state_still_completes(client, app, monkeypatch):
    # No state supplied + META_EMBEDDED_REQUIRE_STATE default False → legacy path.
    with app.app_context():
        cid = _customer()
    _login(client)
    _mock_meta(monkeypatch)
    resp = _complete(client)  # no state/nonce
    assert resp.status_code == 200
    with app.app_context():
        assert wa_settings.get_account(cid).connection_status == "connected"


def test_require_state_flag_rejects_missing_state(client, app, monkeypatch):
    with app.app_context():
        _customer()
    _login(client)
    _mock_meta(monkeypatch)
    monkeypatch.setitem(app.config, "META_EMBEDDED_REQUIRE_STATE", True)
    resp = _complete(client)  # no state
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "missing_state"
