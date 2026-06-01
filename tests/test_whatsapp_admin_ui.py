"""WhatsApp Gateway admin UI tests.

Mirrors the admin-session login used by ``test_customer_control_layer.py`` and
relies on the shared ``app`` / ``client`` fixtures in ``tests/conftest.py``
(``create_app(TestingConfig)`` + ``seed_defaults`` -> default ``admin`` user,
TestingConfig ships a valid ``WHATSAPP_FERNET_KEY``).

No Meta network is ever touched: the provider's
``send_template_message`` + ``validate_credentials`` are monkeypatched.
"""
from __future__ import annotations

from app.extensions import db
from app.models import Customer
from app.services.whatsapp import settings as wa_settings
from app.services.whatsapp.crypto import decrypt_secret
from app.services.whatsapp.providers import MetaCloudWhatsAppProvider

PLAINTEXT_TOKEN = "EAABsbCS1iHgBO_super_secret_meta_token_value_123456"


def _login(client):
    return client.post("/login", data={"username": "admin", "password": "admin12345"})


def _make_customer(name: str = "WA ISP") -> Customer:
    customer = Customer(company_name=name, contact_name="Owner", email=f"{name.replace(' ', '').lower()}@example.test")
    db.session.add(customer)
    db.session.commit()
    return customer


def _csrf(client) -> str:
    # The admin login page renders a form with the session CSRF token; once we
    # have a session, any GET that includes csrf_input exposes the same token.
    with client.session_transaction() as sess:
        return sess.get("_csrf_token", "")


# ---------------------------------------------------------------------------
# Read pages render for an authenticated admin
# ---------------------------------------------------------------------------
def test_gateway_dashboard_renders(client, app):
    with app.app_context():
        _make_customer()
    _login(client)
    resp = client.get("/admin/whatsapp-gateway")
    assert resp.status_code == 200
    assert "بوابة واتساب".encode() in resp.data


def test_message_log_renders(client, app):
    _login(client)
    resp = client.get("/admin/whatsapp-gateway/messages")
    assert resp.status_code == 200
    assert "سجل الرسائل".encode() in resp.data


def test_webhooks_page_renders(client, app):
    _login(client)
    resp = client.get("/admin/whatsapp-gateway/webhooks")
    assert resp.status_code == 200
    assert "أحداث الـ Webhook".encode() in resp.data


def test_customer_whatsapp_page_renders_sections(client, app):
    with app.app_context():
        customer = _make_customer()
        cid = customer.id
    _login(client)
    resp = client.get(f"/admin/customers/{cid}/whatsapp")
    assert resp.status_code == 200
    body = resp.data
    # Connection + settings + credentials sections are present.
    assert "حالة الربط".encode() in body
    assert "إعدادات الخدمة".encode() in body
    assert "بيانات الربط".encode() in body


# ---------------------------------------------------------------------------
# Save credentials: token stored ENCRYPTED, never shown in plaintext/ciphertext
# ---------------------------------------------------------------------------
def test_save_credentials_encrypts_token_and_never_shows_it(client, app):
    with app.app_context():
        customer = _make_customer()
        cid = customer.id
    _login(client)
    token = _csrf(client)

    resp = client.post(
        f"/admin/customers/{cid}/whatsapp/credentials",
        data={
            "_csrf_token": token,
            "meta_business_id": "BIZ123",
            "whatsapp_business_account_id": "WABA456",
            "phone_number_id": "PNID789",
            "display_phone_number": "+970599000000",
            "business_display_name": "Acme ISP",
            "access_token": PLAINTEXT_TOKEN,
        },
        follow_redirects=True,
    )
    assert resp.status_code == 200

    # Stored ciphertext decrypts back to the plaintext (it WAS encrypted).
    with app.app_context():
        account = wa_settings.get_account(cid)
        assert account is not None
        assert account.access_token_encrypted
        assert account.access_token_encrypted != PLAINTEXT_TOKEN  # not stored raw
        assert decrypt_secret(account.access_token_encrypted) == PLAINTEXT_TOKEN
        ciphertext = account.access_token_encrypted

    # The page must NOT render the plaintext token nor the raw ciphertext —
    # only the masked preview.
    page = client.get(f"/admin/customers/{cid}/whatsapp")
    assert page.status_code == 200
    assert PLAINTEXT_TOKEN.encode() not in page.data
    assert ciphertext.encode() not in page.data
    # The masked preview (first 4 + … + last 3) is present.
    assert PLAINTEXT_TOKEN[:4].encode() in page.data


# ---------------------------------------------------------------------------
# Save settings persists
# ---------------------------------------------------------------------------
def test_save_settings_persists(client, app):
    with app.app_context():
        customer = _make_customer()
        cid = customer.id
    _login(client)
    token = _csrf(client)

    resp = client.post(
        f"/admin/customers/{cid}/whatsapp/settings",
        data={
            "_csrf_token": token,
            "plan_code": "whatsapp_pro",
            "monthly_message_limit": "1234",
            "daily_message_limit": "200",
            "per_minute_limit": "25",
            "allow_otp": "1",
            "require_subscriber_opt_in": "1",
        },
        follow_redirects=True,
    )
    assert resp.status_code == 200
    with app.app_context():
        settings_row = wa_settings.get_settings(cid)
        # plan changed -> preset applied, so plan_code is whatsapp_pro.
        assert settings_row.plan_code == "whatsapp_pro"
        assert settings_row.allow_otp is True


# ---------------------------------------------------------------------------
# Enable / disable toggles settings.enabled
# ---------------------------------------------------------------------------
def test_enable_then_disable_toggles_enabled(client, app):
    with app.app_context():
        customer = _make_customer()
        cid = customer.id
    _login(client)
    token = _csrf(client)

    client.post(
        f"/admin/customers/{cid}/whatsapp/service",
        data={"_csrf_token": token, "action": "enable"},
        follow_redirects=True,
    )
    with app.app_context():
        assert wa_settings.get_settings(cid).enabled is True

    client.post(
        f"/admin/customers/{cid}/whatsapp/service",
        data={"_csrf_token": token, "action": "disable"},
        follow_redirects=True,
    )
    with app.app_context():
        assert wa_settings.get_settings(cid).enabled is False


# ---------------------------------------------------------------------------
# Validate credentials uses the provider WITHOUT touching the network
# ---------------------------------------------------------------------------
def test_validate_credentials_monkeypatched_marks_connected(client, app, monkeypatch):
    with app.app_context():
        customer = _make_customer()
        cid = customer.id
        wa_settings.upsert_account(
            cid,
            phone_number_id="PNID789",
            access_token=PLAINTEXT_TOKEN,
        )

    def _fake_validate(self, account):  # no network
        return {
            "ok": True,
            "display_phone_number": "+970599111222",
            "business_display_name": "Verified ISP",
            "quality_rating": "GREEN",
            "messaging_limit_tier": "TIER_1K",
        }

    monkeypatch.setattr(MetaCloudWhatsAppProvider, "validate_credentials", _fake_validate)

    _login(client)
    token = _csrf(client)
    resp = client.post(
        f"/admin/customers/{cid}/whatsapp/validate",
        data={"_csrf_token": token},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    with app.app_context():
        account = wa_settings.get_account(cid)
        assert account.connection_status == "connected"
        assert account.display_phone_number == "+970599111222"


def test_send_test_message_monkeypatched_no_network(client, app, monkeypatch):
    sent = {"count": 0}

    def _fake_send(self, account, *, recipient, template_name, language, variables=None):
        sent["count"] += 1
        return {"provider_message_id": "wamid.TEST123"}

    monkeypatch.setattr(MetaCloudWhatsAppProvider, "send_template_message", _fake_send)

    with app.app_context():
        customer = _make_customer()
        cid = customer.id
        wa_settings.upsert_account(cid, phone_number_id="PNID789", access_token=PLAINTEXT_TOKEN)
        wa_settings.set_connection_status(cid, "connected")
        wa_settings.update_settings(cid, enabled=True)
        wa_settings.upsert_template(cid, local_key="otp", provider_template_name="otp_ar", status="approved")

    _login(client)
    token = _csrf(client)
    resp = client.post(
        f"/admin/customers/{cid}/whatsapp/test",
        data={"_csrf_token": token, "recipient": "0599000111", "template_key": "otp"},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    # drain_once ran and used the patched provider (no real Meta call).
    assert sent["count"] == 1


# ---------------------------------------------------------------------------
# Non-admin (no session) is redirected / denied
# ---------------------------------------------------------------------------
def test_non_admin_is_redirected_from_gateway(client, app):
    resp = client.get("/admin/whatsapp-gateway")
    assert resp.status_code in (301, 302)
    assert "/login" in resp.headers.get("Location", "")


def test_non_admin_is_redirected_from_customer_page(client, app):
    with app.app_context():
        customer = _make_customer()
        cid = customer.id
    resp = client.get(f"/admin/customers/{cid}/whatsapp")
    assert resp.status_code in (301, 302)
    assert "/login" in resp.headers.get("Location", "")
