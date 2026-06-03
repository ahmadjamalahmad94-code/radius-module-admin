"""Embedded Signup P5 — status / sync / disconnect / reconnect lifecycle.

Covers the portal Refresh-status action (validate_connection → synced audit),
reconnect semantics (creds replaced only after a new success; reconnected audit),
and soft-disconnect (audited + idempotent), all tenant-isolated and token-safe.
No Meta network is touched (Graph points + provider probe are monkeypatched).
"""
from __future__ import annotations

from app.extensions import db
from app.models import (
    AuditLog,
    Customer,
    CustomerUser,
    WhatsAppTenantAccount,
)
from app.services.customer_control import get_or_create_service_entitlement
from app.services.whatsapp import embedded_signup as es
from app.services.whatsapp import settings as wa_settings
from app.services.whatsapp.crypto import decrypt_secret
from app.services.whatsapp.providers import MetaCloudWhatsAppProvider, WhatsAppProviderError

DISPATCH = "/portal/whatsapp"
START_SESSION = "/portal/whatsapp/embedded/start"
COMPLETE = "/portal/whatsapp/embedded/complete"
LIVE_TOKEN = "EAAB-live-token-secret-9999"
APP_SECRET = "test-app-secret"


# ───────────────────────── helpers ─────────────────────────

def _customer(username="p5-owner", email="p5@example.test", grant=True):
    c = Customer(company_name="P5 ISP", contact_name="Owner", email=email, status="active")
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


def _login(client, username="p5-owner"):
    return client.post("/portal/login", data={"username": username, "password": "Secret123!"})


def _mock_es_graph(monkeypatch):
    def fake_get(path, params):
        if path == "oauth/access_token":
            return {"access_token": LIVE_TOKEN, "expires_in": 0}
        if path == "debug_token":
            return {"data": {"scopes": ["whatsapp_business_management"]}}
        if path.startswith("PNID"):
            return {"display_phone_number": "+970 599 123456", "verified_name": "P5 Net",
                    "quality_rating": "GREEN", "messaging_limit_tier": "TIER_1K"}
        if path.startswith("WABA"):
            return {"name": "P5 WABA", "owner_business_info": {"id": "BIZ-1"}}
        return {}
    monkeypatch.setattr(es, "_graph_get", fake_get)
    monkeypatch.setattr(es, "_graph_post", lambda path, data: {"success": True})


def _connect(cid):
    return es.complete_signup(cid, code="C", waba_id="WABA-1", phone_number_id="PNID-1")


def _start(client):
    j = client.post(START_SESSION, json={}).get_json()
    return j["state"], j["nonce"]


def _complete(client, *, code, waba, pnid, state, nonce):
    return client.post(COMPLETE, json={"code": code, "waba_id": waba, "phone_number_id": pnid,
                                       "state": state, "nonce": nonce})


# ───────────────────────── 1. refresh status ─────────────────────────

def test_refresh_status_success_syncs_and_audits(client, app, monkeypatch):
    with app.app_context():
        cid = _customer()
        _mock_es_graph(monkeypatch)
        _connect(cid)
    # Re-probe returns fresh metadata (a new display number proves the sync ran).
    monkeypatch.setattr(MetaCloudWhatsAppProvider, "validate_credentials",
                        lambda self, account: {"display_phone_number": "+970 599 777777",
                                               "business_display_name": "P5 Net",
                                               "quality_rating": "GREEN",
                                               "messaging_limit_tier": "TIER_1K"})
    _login(client)
    r = client.post(DISPATCH, data={"action": "refresh_status"}, follow_redirects=True)
    assert r.status_code == 200
    assert LIVE_TOKEN not in r.get_data(as_text=True)
    with app.app_context():
        acc = wa_settings.get_account(cid)
        assert acc.connection_status == "connected"
        assert acc.last_sync_at is not None
        assert acc.display_phone_number == "+970 599 777777"   # synced
        assert AuditLog.query.filter_by(action="whatsapp_connection_synced").count() == 1


def test_refresh_status_failure_sets_error_and_safe_message(client, app, monkeypatch):
    with app.app_context():
        cid = _customer()
        _mock_es_graph(monkeypatch)
        _connect(cid)

    def boom(self, account):
        raise WhatsAppProviderError("invalid_token", "تعذّر التحقق من الرقم.")
    monkeypatch.setattr(MetaCloudWhatsAppProvider, "validate_credentials", boom)
    _login(client)
    r = client.post(DISPATCH, data={"action": "refresh_status"}, follow_redirects=True)
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert LIVE_TOKEN not in body and APP_SECRET not in body
    with app.app_context():
        acc = wa_settings.get_account(cid)
        assert acc.connection_status == "error"
        assert acc.last_error_code == "invalid_token"


def test_refresh_status_without_account_is_safe(client, app):
    with app.app_context():
        _customer()
    _login(client)
    r = client.post(DISPATCH, data={"action": "refresh_status"}, follow_redirects=True)
    assert r.status_code == 200  # friendly flash, no crash


# ───────────────────────── 2. reconnect ─────────────────────────

def test_reconnect_replaces_creds_only_after_success(client, app, monkeypatch):
    with app.app_context():
        cid = _customer()
    _login(client)
    _mock_es_graph(monkeypatch)
    s1, n1 = _start(client)
    assert _complete(client, code="C1", waba="WABA-1", pnid="PNID-1", state=s1, nonce=n1).status_code == 200
    # Reconnect with new assets — succeeds → replaces creds + audits reconnected.
    s2, n2 = _start(client)
    assert _complete(client, code="C2", waba="WABA-9", pnid="PNID-9", state=s2, nonce=n2).status_code == 200
    with app.app_context():
        accs = WhatsAppTenantAccount.query.filter_by(customer_id=cid).all()
        assert len(accs) == 1                       # still one account
        assert accs[0].phone_number_id == "PNID-9"  # creds replaced after success
        assert accs[0].connection_status == "connected"
        assert AuditLog.query.filter_by(action="whatsapp_connection_reconnected").count() == 1
        assert AuditLog.query.filter_by(action="embedded_signup_succeeded").count() == 2


def test_failed_reconnect_leaves_old_connection_intact(client, app, monkeypatch):
    with app.app_context():
        cid = _customer()
    _login(client)
    _mock_es_graph(monkeypatch)
    s1, n1 = _start(client)
    assert _complete(client, code="C1", waba="WABA-1", pnid="PNID-1", state=s1, nonce=n1).status_code == 200

    # Now make the exchange fail and attempt a reconnect.
    def fail_get(path, params):
        if path == "oauth/access_token":
            raise es.EmbeddedSignupError("auth_failed", "تعذّر إكمال الربط.")
        return {}
    monkeypatch.setattr(es, "_graph_get", fail_get)
    s2, n2 = _start(client)
    assert _complete(client, code="C2", waba="WABA-9", pnid="PNID-9", state=s2, nonce=n2).status_code == 400
    with app.app_context():
        acc = wa_settings.get_account(cid)
        assert acc.connection_status == "connected"            # old connection intact
        assert acc.phone_number_id == "PNID-1"                 # old creds preserved
        assert decrypt_secret(acc.access_token_encrypted) == LIVE_TOKEN


# ───────────────────────── 3. disconnect ─────────────────────────

def test_disconnect_audited_and_idempotent(app, monkeypatch):
    with app.app_context():
        cid = _customer()
        _mock_es_graph(monkeypatch)
        _connect(cid)
        assert es.disconnect(cid) is True
        # repeat — safe no-op, no second audit row
        assert es.disconnect(cid) is True
        acc = wa_settings.get_account(cid)
        assert acc.connection_status == "disconnected"
        assert not acc.access_token_encrypted
        assert AuditLog.query.filter_by(action="whatsapp_connection_disconnected").count() == 1
        assert AuditLog.query.filter_by(action="whatsapp_embedded_disconnected").count() == 1  # legacy


def test_disconnect_via_route_is_tenant_scoped(client, app, monkeypatch):
    with app.app_context():
        cid_a = _customer(username="a5", email="a5@example.test")
        cid_b = _customer(username="b5", email="b5@example.test")
        _mock_es_graph(monkeypatch)
        _connect(cid_a)
        _connect(cid_b)
    _login(client, "a5")
    client.post(DISPATCH, data={"action": "disconnect"}, follow_redirects=True)
    with app.app_context():
        assert wa_settings.get_account(cid_a).connection_status == "disconnected"
        assert wa_settings.get_account(cid_b).connection_status == "connected"  # B untouched
