"""Embedded Signup P3 — customer-portal onboarding UX (rendered states).

Asserts the "ربط واتساب الرسمي" card renders the right state + spec Arabic copy,
the connected detail panel (masked WABA/Phone IDs + timestamps + the four
actions), the admin-config-incomplete warning, the relabelled/collapsed advanced
section, and that the launcher is externalized (CSP-clean — no inline FB.login).
No Meta network is touched (Graph points are monkeypatched).
"""
from __future__ import annotations

from app.extensions import db
from app.models import Customer, CustomerUser
from app.services.customer_control import get_or_create_service_entitlement
from app.services.whatsapp import embedded_signup as es
from app.services.whatsapp import settings as wa_settings

PORTAL = "/portal"


# ───────────────────────── helpers ─────────────────────────

def _customer(username="ux-owner", email="ux@example.test", grant=True):
    c = Customer(company_name="UX ISP", contact_name="Owner", email=email, status="active")
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


def _login(client, username="ux-owner"):
    return client.post("/portal/login", data={"username": username, "password": "Secret123!"})


def _mock_meta(monkeypatch):
    def fake_get(path, params):
        if path == "oauth/access_token":
            return {"access_token": "EAAB-live-token-0001", "expires_in": 0}
        if path == "debug_token":
            return {"data": {"scopes": ["whatsapp_business_management"]}}
        if path.startswith("PNID"):
            return {"display_phone_number": "+970 599 123456", "verified_name": "UX Net",
                    "quality_rating": "GREEN", "messaging_limit_tier": "TIER_1K"}
        if path.startswith("WABA"):
            return {"name": "UX WABA", "owner_business_info": {"id": "BIZ-1"}}
        return {}

    monkeypatch.setattr(es, "_graph_get", fake_get)
    monkeypatch.setattr(es, "_graph_post", lambda path, data: {"success": True})


def _body(client):
    return client.get(PORTAL).get_data(as_text=True)


# ───────────────────────── 1. not connected ─────────────────────────

def test_not_connected_renders_card_and_cta(client, app):
    with app.app_context():
        _customer()
    _login(client)
    body = _body(client)
    assert "ربط واتساب الرسمي" in body
    assert 'data-wa-state="not_connected"' in body
    assert "اربط واتساب الرسمي لإرسال الإشعارات من رقمك المعتمد." in body
    assert "اربط رقم واتساب الرسمي بخطوات بسيطة دون نسخ رموز أو الدخول إلى إعدادات Meta المعقدة." in body
    assert "data-wa-embedded-launch" in body            # the CTA hook
    assert "ربط واتساب" in body                          # CTA label


# ───────────────────────── 2. admin-config-incomplete warning ─────────────────────────

def test_missing_config_shows_admin_warning_not_a_button(client, app, monkeypatch):
    with app.app_context():
        _customer()
    _login(client)
    monkeypatch.setitem(app.config, "META_APP_ID", "")   # flag on, creds missing
    body = _body(client)
    assert 'data-wa-state="needs_attention"' in body
    assert "إعداد الربط عبر Meta غير مكتمل من لوحة الإدارة." in body
    assert "data-wa-embedded-launch" not in body          # never a broken button
    assert "غير مُهيأ بعد" in body                          # graceful fallback note


# ───────────────────────── 3. connect flow → connected detail panel ─────────────────────────

def test_connected_detail_panel_after_signup(client, app, monkeypatch):
    with app.app_context():
        cid = _customer()
        _mock_meta(monkeypatch)
        es.complete_signup(cid, code="CODE", waba_id="WABA-1", phone_number_id="PNID-1")
    _login(client)
    body = _body(client)
    assert 'data-wa-state="connected"' in body
    assert "واتساب متصل" in body
    assert "+970 599 123456" in body                       # display phone number
    assert "••••BA-1" in body                              # masked WABA id (last 4)
    assert "••••ID-1" in body                              # masked phone number id
    assert "آخر مزامنة" in body                            # last_sync_at row
    # The four connected actions.
    assert "اختبار رسالة" in body                          # send test message
    assert "تحديث الحالة" in body                          # refresh status
    assert "إعادة الربط" in body                           # reconnect
    assert "فصل الحساب" in body                            # disconnect
    # The refresh action reuses the working validate endpoint.
    assert 'name="action" value="validate"' in body


# ───────────────────────── 4. error state ─────────────────────────

def test_error_state_copy(client, app, monkeypatch):
    with app.app_context():
        cid = _customer()
        _mock_meta(monkeypatch)
        es.complete_signup(cid, code="CODE", waba_id="WABA-1", phone_number_id="PNID-1")
        wa_settings.set_connection_status(cid, "error", error_code="auth_failed",
                                          error_message="bad")
    _login(client)
    body = _body(client)
    assert 'data-wa-state="error"' in body
    assert "تعذّر إكمال الربط. حاول إعادة الاتصال أو تواصل مع الدعم." in body


# ───────────────────────── 5. disconnected state ─────────────────────────

def test_disconnected_state(client, app, monkeypatch):
    with app.app_context():
        cid = _customer()
        _mock_meta(monkeypatch)
        es.complete_signup(cid, code="CODE", waba_id="WABA-1", phone_number_id="PNID-1")
        es.disconnect(cid)
    _login(client)
    body = _body(client)
    assert 'data-wa-state="disconnected"' in body
    assert "تم فصل واتساب" in body
    assert "ربط واتساب" in body                            # reconnect CTA


# ───────────────────────── 6. advanced section relabel + collapsed ─────────────────────────

def test_advanced_section_relabelled_and_collapsed(client, app):
    with app.app_context():
        _customer()
    _login(client)
    body = _body(client)
    assert "إعداد متقدم — إعداد يدوي للمسؤول فقط" in body
    # Collapsed by default: the <details> carries no `open` attribute.
    assert '<details class="wa-advanced" id="wa-advanced">' in body
    # The manual form is still present in the DOM (just collapsed).
    assert 'name="action" value="save_credentials"' in body


# ───────────────────────── 7. externalized launcher (CSP-clean) ─────────────────────────

def test_launcher_is_externalized_and_boot_present(client, app):
    with app.app_context():
        _customer()
    _login(client)
    body = _body(client)
    assert "js/whatsapp_embedded.js" in body               # external script
    assert "data-wa-embedded-boot" in body                 # boot JSON island
    assert "WA_EMBEDDED_SIGNUP" in body                    # message type for the SDK listener
    # CSP-clean: the OAuth/login flow is NOT inlined in the page.
    assert "FB.login" not in body
    assert "connect.facebook.net" not in body
