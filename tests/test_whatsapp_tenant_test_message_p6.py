"""Embedded Signup P6 — portal test message through the connected TENANT account.

Asserts the portal `send_test` action sends via the per-customer (embedded)
credentials — never the house Cloud API — selects an approved template with a
hello_world default, audits whatsapp_tenant_test_message_sent/failed, gives
friendly Arabic feedback, stays tenant-isolated, and never leaks the token.
No Meta network is touched (Graph + provider send are monkeypatched).
"""
from __future__ import annotations

from app.extensions import db
from app.models import AuditLog, Customer, CustomerUser
from app.services.customer_control import get_or_create_service_entitlement
from app.services.whatsapp import cloud_settings as wac
from app.services.whatsapp import embedded_signup as es
from app.services.whatsapp import settings as wa_settings
from app.services.whatsapp.providers import MetaCloudWhatsAppProvider, WhatsAppProviderError

DISPATCH = "/portal/whatsapp"
TENANT_TOKEN = "EAAB-tenant-token-secret-6666"
PHONE = "0599123456"


# ───────────────────────── helpers ─────────────────────────

def _customer(username="p6-owner", email="p6@example.test", grant=True):
    c = Customer(company_name="P6 ISP", contact_name="Owner", email=email, status="active")
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


def _login(client, username="p6-owner"):
    return client.post("/portal/login", data={"username": username, "password": "Secret123!"})


def _mock_es_graph(monkeypatch):
    def fake_get(path, params):
        if path == "oauth/access_token":
            return {"access_token": TENANT_TOKEN, "expires_in": 0}
        if path == "debug_token":
            return {"data": {"scopes": ["whatsapp_business_management"]}}
        if path.startswith("PNID"):
            return {"display_phone_number": "+970 599 123456", "verified_name": "P6 Net",
                    "quality_rating": "GREEN", "messaging_limit_tier": "TIER_1K"}
        if path.startswith("WABA"):
            return {"name": "P6 WABA", "owner_business_info": {"id": "BIZ-1"}}
        return {}
    monkeypatch.setattr(es, "_graph_get", fake_get)
    monkeypatch.setattr(es, "_graph_post", lambda path, data: {"success": True})


def _connect_with_template(cid, *, extra_hello_world=False):
    """Connect (embedded) + enable + add an approved otp (and optional hello_world)."""
    es.complete_signup(cid, code="C", waba_id="WABA-1", phone_number_id="PNID-1")
    wa_settings.update_settings(cid, enabled=True)
    wa_settings.upsert_template(cid, local_key="otp", provider_template_name="otp_ar",
                               language="ar", status="approved")
    if extra_hello_world:
        wa_settings.upsert_template(cid, local_key="hello_world", provider_template_name="hello_world",
                                   language="en", status="approved")


def _patch_send_capture(monkeypatch, *, fail=False):
    captured: dict = {}

    def fake_send(self, account, *, recipient, template_name, language, variables=None):
        captured["customer_id"] = account.customer_id
        from app.services.whatsapp.crypto import decrypt_secret
        captured["token"] = decrypt_secret(account.access_token_encrypted)
        captured["template_name"] = template_name
        if fail:
            raise WhatsAppProviderError("template_paused", "القالب موقوف مؤقتًا.")
        return {"provider_message_id": "wamid.PORTAL"}

    monkeypatch.setattr(MetaCloudWhatsAppProvider, "send_template_message", fake_send)
    # House path must never be touched by the tenant test send.
    def _house_boom(*a, **k):  # noqa: ANN001
        raise AssertionError("house cloud send must not be called")
    monkeypatch.setattr(wac, "send_test_message", _house_boom)
    return captured


# ───────────────────────── tests ─────────────────────────

def test_portal_send_test_uses_tenant_account_not_house(client, app, monkeypatch):
    with app.app_context():
        cid = _customer()
        _mock_es_graph(monkeypatch)
        _connect_with_template(cid)
    captured = _patch_send_capture(monkeypatch)
    _login(client)
    r = client.post(DISPATCH, data={"action": "send_test", "recipient": PHONE},
                    follow_redirects=True)
    assert r.status_code == 200
    assert captured["customer_id"] == cid
    assert captured["token"] == TENANT_TOKEN          # tenant creds, not house
    assert TENANT_TOKEN not in r.get_data(as_text=True)


def test_portal_send_test_success_audit_and_flash(client, app, monkeypatch):
    with app.app_context():
        cid = _customer()
        _mock_es_graph(monkeypatch)
        _connect_with_template(cid)
    _patch_send_capture(monkeypatch)
    _login(client)
    r = client.post(DISPATCH, data={"action": "send_test", "recipient": PHONE},
                    follow_redirects=True)
    assert "تم إرسال رسالة التجربة بنجاح" in r.get_data(as_text=True)
    with app.app_context():
        assert AuditLog.query.filter_by(action="whatsapp_tenant_test_message_sent").count() == 1


def test_portal_send_test_failure_audit_and_safe_flash(client, app, monkeypatch):
    with app.app_context():
        cid = _customer()
        _mock_es_graph(monkeypatch)
        _connect_with_template(cid)
    _patch_send_capture(monkeypatch, fail=True)
    _login(client)
    r = client.post(DISPATCH, data={"action": "send_test", "recipient": PHONE},
                    follow_redirects=True)
    body = r.get_data(as_text=True)
    assert "تعذّر إرسال رسالة التجربة" in body
    assert TENANT_TOKEN not in body
    with app.app_context():
        assert AuditLog.query.filter_by(action="whatsapp_tenant_test_message_failed").count() == 1


def test_portal_send_test_defaults_to_hello_world(client, app, monkeypatch):
    with app.app_context():
        cid = _customer()
        _mock_es_graph(monkeypatch)
        _connect_with_template(cid, extra_hello_world=True)
    captured = _patch_send_capture(monkeypatch)
    _login(client)
    # No template chosen → defaults to hello_world.
    client.post(DISPATCH, data={"action": "send_test", "recipient": PHONE}, follow_redirects=True)
    assert captured["template_name"] == "hello_world"


def test_portal_send_test_honours_explicit_template(client, app, monkeypatch):
    with app.app_context():
        cid = _customer()
        _mock_es_graph(monkeypatch)
        _connect_with_template(cid, extra_hello_world=True)
    captured = _patch_send_capture(monkeypatch)
    _login(client)
    client.post(DISPATCH, data={"action": "send_test", "recipient": PHONE, "template_key": "otp"},
                follow_redirects=True)
    assert captured["template_name"] == "otp_ar"


def test_portal_send_test_no_approved_template_is_friendly(client, app, monkeypatch):
    with app.app_context():
        cid = _customer()
        _mock_es_graph(monkeypatch)
        es.complete_signup(cid, code="C", waba_id="WABA-1", phone_number_id="PNID-1")
        wa_settings.update_settings(cid, enabled=True)   # connected but NO approved template
    _login(client)
    r = client.post(DISPATCH, data={"action": "send_test", "recipient": PHONE}, follow_redirects=True)
    assert "لا يوجد قالب واتساب معتمد" in r.get_data(as_text=True)
    with app.app_context():
        assert AuditLog.query.filter_by(action="whatsapp_tenant_test_message_sent").count() == 0


def test_portal_send_test_is_tenant_scoped(client, app, monkeypatch):
    with app.app_context():
        cid_a = _customer(username="a6", email="a6@example.test")
        _customer(username="b6", email="b6@example.test")
        _mock_es_graph(monkeypatch)
        _connect_with_template(cid_a)
    captured = _patch_send_capture(monkeypatch)
    _login(client, "a6")   # session = A
    client.post(DISPATCH, data={"action": "send_test", "recipient": PHONE}, follow_redirects=True)
    # The send used A's account, never another tenant's.
    assert captured["customer_id"] == cid_a
