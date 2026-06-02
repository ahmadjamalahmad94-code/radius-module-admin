"""Meta WhatsApp Embedded Signup — service + route + UI tests.

No Meta network is ever touched: embedded_signup._graph_get/_graph_post are
monkeypatched. Reuses the customer-portal login + entitlement pattern from
test_whatsapp_portal.py. TestingConfig ships deterministic META_* creds and a
valid WHATSAPP_FERNET_KEY.
"""
from __future__ import annotations

import pytest

from app.extensions import db
from app.models import Customer, CustomerUser, WhatsAppTenantAccount
from app.services.customer_control import get_or_create_service_entitlement
from app.services.whatsapp import embedded_signup as es
from app.services.whatsapp import settings as wa_settings
from app.services.whatsapp.crypto import decrypt_secret

COMPLETE_URL = "/portal/whatsapp/embedded/complete"
LIVE_TOKEN = "EAAB-embedded-live-token-value-1234567890"


# ───────────────────────── fixtures / helpers ─────────────────────────

def _customer(company="ES ISP", username="es-owner", email="es@example.test", grant=True):
    c = Customer(company_name=company, contact_name="Owner", email=email, status="active")
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


def _login(client, username="es-owner"):
    return client.post("/portal/login", data={"username": username, "password": "Secret123!"})


def _csrf(client) -> str:
    with client.session_transaction() as s:
        return s.get("_csrf_token", "")


def _mock_meta(monkeypatch, *, token=LIVE_TOKEN, fail_exchange=False, no_token=False):
    """Install canned Graph responses; record POSTs in the returned dict."""
    posts: dict = {}

    def fake_get(path, params):
        if path == "oauth/access_token":
            if fail_exchange:
                raise es.EmbeddedSignupError("auth_failed", "تعذّر إكمال الربط.")
            return {} if no_token else {"access_token": token, "expires_in": 0}
        if path == "debug_token":
            return {"data": {"scopes": ["whatsapp_business_management", "whatsapp_business_messaging"]}}
        if path.startswith("PNID"):
            return {"display_phone_number": "+970 599 123456", "verified_name": "ES Net",
                    "quality_rating": "GREEN", "messaging_limit_tier": "TIER_1K"}
        if path.startswith("WABA"):
            return {"name": "ES WABA", "owner_business_info": {"id": "BIZ-1"}}
        return {}

    def fake_post(path, data):
        posts[path] = data
        return {"success": True}

    monkeypatch.setattr(es, "_graph_get", fake_get)
    monkeypatch.setattr(es, "_graph_post", fake_post)
    return posts


def _post_complete(client, *, code="CODE-1", waba="WABA-1", pnid="PNID-1"):
    return client.post(
        COMPLETE_URL,
        json={"code": code, "waba_id": waba, "phone_number_id": pnid},
        headers={"X-CSRFToken": _csrf(client), "X-Requested-With": "XMLHttpRequest"},
    )


# ───────────────────────── 1. availability gating ─────────────────────────

def test_embedded_available_true_with_test_creds(app):
    with app.app_context():
        assert es.embedded_signup_available() is True
        cfg = es.public_config()
        assert cfg["app_id"] == "test-app-id" and cfg["config_id"] == "test-config-id"
        assert "app_secret" not in cfg  # secret never exposed


def test_embedded_unavailable_without_app_id(app, monkeypatch):
    with app.app_context():
        monkeypatch.setitem(app.config, "META_APP_ID", "")
        assert es.embedded_signup_available() is False


# ───────────────────────── 2. service: success / encryption ─────────────────────────

def test_complete_signup_persists_encrypted_and_connected(app, monkeypatch):
    with app.app_context():
        cid = _customer()
        posts = _mock_meta(monkeypatch)
        out = es.complete_signup(cid, code="C", waba_id="WABA-1", phone_number_id="PNID-1")
        assert out["ok"] and out["status"] == "connected"
        assert "WABA-1/subscribed_apps" in posts  # app subscribed → webhooks flow

        acc = wa_settings.get_account(cid)
        assert acc.connection_status == "connected"
        assert acc.onboarding_method == "embedded"
        assert acc.phone_number_id == "PNID-1"
        assert acc.whatsapp_business_account_id == "WABA-1"
        assert acc.meta_business_id == "BIZ-1"
        assert "whatsapp_business_messaging" in (acc.scopes or "")
        # token stored ENCRYPTED, recoverable, never plaintext
        assert acc.access_token_encrypted and acc.access_token_encrypted != LIVE_TOKEN
        assert decrypt_secret(acc.access_token_encrypted) == LIVE_TOKEN


# ───────────────────────── 3. service: failures ─────────────────────────

def test_exchange_failure_raises_safe_error(app, monkeypatch):
    with app.app_context():
        cid = _customer()
        _mock_meta(monkeypatch, fail_exchange=True)
        with pytest.raises(es.EmbeddedSignupError) as ei:
            es.complete_signup(cid, code="C", waba_id="WABA-1", phone_number_id="PNID-1")
        assert "auth_failed" == ei.value.code
        assert LIVE_TOKEN not in str(ei.value)
        assert wa_settings.get_account(cid) is None  # nothing persisted on failure


def test_no_token_returned_raises(app, monkeypatch):
    with app.app_context():
        cid = _customer()
        _mock_meta(monkeypatch, no_token=True)
        with pytest.raises(es.EmbeddedSignupError):
            es.complete_signup(cid, code="C", waba_id="WABA-1", phone_number_id="PNID-1")


def test_missing_assets_raises(app, monkeypatch):
    with app.app_context():
        cid = _customer()
        _mock_meta(monkeypatch)
        with pytest.raises(es.EmbeddedSignupError) as ei:
            es.complete_signup(cid, code="C", waba_id="", phone_number_id="")
        assert ei.value.code == "missing_assets"


def test_error_classifier_never_leaks_secret():
    err = es._classify({"error": {"code": 190, "message": "token EAAB-secret leaked"}})
    assert err.code == "auth_failed"
    assert "secret" not in str(err) and "EAAB" not in str(err)


# ───────────────────────── 4. reconnect / disconnect ─────────────────────────

def test_reconnect_updates_same_account(app, monkeypatch):
    with app.app_context():
        cid = _customer()
        _mock_meta(monkeypatch)
        es.complete_signup(cid, code="C1", waba_id="WABA-1", phone_number_id="PNID-1")
        es.complete_signup(cid, code="C2", waba_id="WABA-9", phone_number_id="PNID-9")
        accounts = WhatsAppTenantAccount.query.filter_by(customer_id=cid).all()
        assert len(accounts) == 1  # one account per customer (reconnect updates)
        assert accounts[0].phone_number_id == "PNID-9"
        assert accounts[0].connection_status == "connected"


def test_disconnect_clears_secrets(app, monkeypatch):
    with app.app_context():
        cid = _customer()
        _mock_meta(monkeypatch)
        es.complete_signup(cid, code="C", waba_id="WABA-1", phone_number_id="PNID-1")
        assert es.disconnect(cid) is True
        acc = wa_settings.get_account(cid)
        assert acc.connection_status == "disconnected"
        assert not acc.access_token_encrypted


# ───────────────────────── 5. route: auth / permissions ─────────────────────────

def test_route_unauthenticated_401(client, app):
    r = client.post(COMPLETE_URL, json={"code": "x"})
    assert r.status_code in (401, 400)  # 401 unauthorized (400 if CSRF rejects first)
    if r.status_code == 401:
        assert r.get_json()["error"] == "unauthorized"


def test_route_locked_customer_403(client, app, monkeypatch):
    with app.app_context():
        _customer(company="Locked", username="locked-es", email="l@example.test", grant=False)
    _login(client, "locked-es")
    _mock_meta(monkeypatch)
    r = _post_complete(client)
    assert r.status_code == 403
    assert r.get_json()["error"] == "locked"


def test_route_unavailable_503(client, app, monkeypatch):
    with app.app_context():
        _customer(username="noenv-es", email="n@example.test")
    _login(client, "noenv-es")
    monkeypatch.setitem(app.config, "META_APP_ID", "")  # disables availability
    r = _post_complete(client)
    assert r.status_code == 503
    assert r.get_json()["error"] == "unavailable"


# ───────────────────────── 6. route: success / error JSON ─────────────────────────

def test_route_success_returns_json_and_persists(client, app, monkeypatch):
    with app.app_context():
        cid = _customer(username="ok-es", email="ok@example.test")
    _login(client, "ok-es")
    _mock_meta(monkeypatch)
    r = _post_complete(client, waba="WABA-1", pnid="PNID-1")
    assert r.status_code == 200
    body = r.get_json()
    assert body["ok"] is True and body["status"] == "connected"
    assert body["display_phone_number"] == "+970 599 123456"
    assert "redirect" in body
    with app.app_context():
        acc = wa_settings.get_account(cid)
        assert acc.connection_status == "connected" and acc.onboarding_method == "embedded"


def test_route_failure_returns_friendly_json_and_marks_error(client, app, monkeypatch):
    with app.app_context():
        cid = _customer(username="err-es", email="e@example.test")
    _login(client, "err-es")
    _mock_meta(monkeypatch, fail_exchange=True)
    r = _post_complete(client)
    assert r.status_code == 400
    body = r.get_json()
    assert body["ok"] is False
    assert "تعذّر" in body["message"]  # friendly Arabic, no jargon
    assert "token" not in body["message"].lower()


# ───────────────────────── 7. tenant isolation ─────────────────────────

def test_route_uses_session_customer_not_body(client, app, monkeypatch):
    with app.app_context():
        cid_a = _customer(company="A", username="a-es", email="a@example.test")
        cid_b = _customer(company="B", username="b-es", email="b@example.test")
    _login(client, "a-es")
    _mock_meta(monkeypatch)
    # Forge customer_id = B in the body — must be ignored (session = A).
    r = client.post(
        COMPLETE_URL,
        json={"code": "C", "waba_id": "WABA-1", "phone_number_id": "PNID-1", "customer_id": cid_b},
        headers={"X-CSRFToken": _csrf(client)},
    )
    assert r.status_code == 200
    with app.app_context():
        assert wa_settings.get_account(cid_a) is not None  # A connected
        assert wa_settings.get_account(cid_b) is None       # B untouched


# ───────────────────────── 8. UI render states ─────────────────────────

def test_ui_shows_embedded_cta_when_available(client, app):
    with app.app_context():
        _customer(username="ui-es", email="ui@example.test")
    _login(client, "ui-es")
    body = client.get("/portal").get_data(as_text=True)
    assert "ربط واتساب الرسمي" in body          # hero card title
    assert "data-wa-embedded-launch" in body      # the CTA button hook
    assert "WA_EMBEDDED_SIGNUP" in body           # the SDK message listener
    assert "إعداد متقدم" in body                   # manual path moved to advanced


def test_ui_connected_state_after_signup(client, app, monkeypatch):
    with app.app_context():
        cid = _customer(username="conn-es", email="c2@example.test")
    _login(client, "conn-es")
    _mock_meta(monkeypatch)
    _post_complete(client, waba="WABA-1", pnid="PNID-1")
    body = client.get("/portal").get_data(as_text=True)
    assert "واتساب متصل" in body                   # connected banner
    assert "فصل الحساب" in body                     # disconnect action
    assert "+970 599 123456" in body                # connected number shown


def test_ui_hides_cta_when_unavailable(client, app, monkeypatch):
    with app.app_context():
        _customer(username="noui-es", email="nu@example.test")
    _login(client, "noui-es")
    monkeypatch.setitem(app.config, "META_APP_ID", "")
    body = client.get("/portal").get_data(as_text=True)
    assert "data-wa-embedded-launch" not in body    # no CTA
    assert "غير مُهيأ بعد" in body                   # graceful fallback note


# ───────────────────────── 9. webhook app-secret fallback ─────────────────────────

def test_webhook_signature_uses_app_secret_for_embedded(app, monkeypatch):
    import hashlib
    import hmac
    from app.services.whatsapp import webhook as wa_webhook

    with app.app_context():
        cid = _customer(username="wh-es", email="wh@example.test")
        _mock_meta(monkeypatch)
        es.complete_signup(cid, code="C", waba_id="WABA-1", phone_number_id="PNID-1")

        raw = b'{"entry":[{"changes":[{"value":{"metadata":{"phone_number_id":"PNID-1"},"statuses":[]}}]}]}'
        secret = app.config["META_APP_SECRET"]
        good = "sha256=" + hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
        bad = "sha256=" + "0" * 64

        acc = wa_settings.get_account(cid)
        assert wa_webhook._signature_ok(acc, good, raw) is True     # app-secret verified
        assert wa_webhook._signature_ok(acc, bad, raw) is False     # mismatch rejected
