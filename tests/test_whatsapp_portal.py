"""Customer-portal WhatsApp tests — now an INTEGRATED dashboard pane.

The WhatsApp experience used to live on a standalone page (``/portal/whatsapp``);
it now lives inside the customer dashboard sidebar as a ``data-pp-pane="whatsapp"``
pane, reached via the ``رسائل واتساب للمشتركين`` nav button (``data-pp-view``).
The old GET URL is kept but now 302-redirects into the dashboard with
``?view=whatsapp`` so the SPA router activates the pane. POST actions still hit
``/portal/whatsapp`` (the action handler) and PRG-redirect back to that pane.

Mirrors the customer-portal login flow used by ``test_customer_control_layer.py``
(create an ACTIVE ``CustomerUser`` under an active ``Customer``, then POST
``/portal/login`` to seed the portal session). Relies on the shared ``app`` /
``client`` fixtures in ``tests/conftest.py`` (``create_app(TestingConfig)`` +
``seed_defaults`` — TestingConfig ships a valid ``WHATSAPP_FERNET_KEY`` and
disables CSRF).

No Meta network is ever touched: the provider's ``validate_credentials`` is
monkeypatched in the one test that exercises validation.
"""
from __future__ import annotations

from app.extensions import db
from app.models import Customer, CustomerUser
from app.services.customer_control import get_or_create_service_entitlement
from app.services.whatsapp import settings as wa_settings
from app.services.whatsapp.crypto import decrypt_secret
from app.services.whatsapp.providers import MetaCloudWhatsAppProvider

PLAINTEXT_TOKEN = "EAABsbCS1iHgBO_portal_secret_meta_token_value_987654"

#: Where the WhatsApp UI now lives (the customer dashboard).
DASH_URL = "/portal"
#: The dashboard with the WhatsApp pane pre-selected (PRG target).
DASH_WA_URL = "/portal?view=whatsapp"
#: Legacy standalone URL — GET redirects to the dashboard pane; POST is the
#: action handler that PRG-redirects back to the pane.
LEGACY_URL = "/portal/whatsapp"
#: The illustrated Meta guide heading (must be present in the pane).
GUIDE_HEADING = "كيف أحصل على البيانات والاشتراك من Meta؟"


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------
def _make_customer_with_user(
    *,
    company: str,
    username: str,
    email: str,
    password: str = "Secret123!",
    grant_whatsapp: bool = False,
) -> tuple[int, int]:
    """Create an active Customer + active owner CustomerUser.

    Optionally grant the ``whatsapp_gateway`` entitlement (enabled + active),
    matching how the admin grants a service. Returns ``(customer_id, user_id)``.
    """
    customer = Customer(company_name=company, contact_name="Owner", email=email, status="active")
    db.session.add(customer)
    db.session.flush()
    user = CustomerUser(
        customer_id=customer.id,
        username=username,
        email=email,
        full_name="Owner",
        role_key="owner",
        active=True,
    )
    user.set_password(password, increment_version=False)
    user.password_version = 1
    db.session.add(user)
    if grant_whatsapp:
        ent = get_or_create_service_entitlement(customer, "whatsapp_gateway")
        ent.enabled = True
        ent.status = "active"
    db.session.commit()
    return customer.id, user.id


def _portal_login(client, username: str, password: str = "Secret123!"):
    return client.post(
        "/portal/login",
        data={"username": username, "password": password},
        follow_redirects=False,
    )


def _csrf(client) -> str:
    with client.session_transaction() as sess:
        return sess.get("_csrf_token", "")


# ---------------------------------------------------------------------------
# The dashboard now hosts the WhatsApp pane: nav button + pane + guide
# ---------------------------------------------------------------------------
def test_dashboard_has_whatsapp_nav_pane_and_guide(client, app):
    with app.app_context():
        _make_customer_with_user(
            company="Pane ISP", username="pane-owner", email="pane@example.test",
            grant_whatsapp=True,
        )
    _portal_login(client, "pane-owner")

    resp = client.get(DASH_URL)
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    # Sidebar nav button switches to the WhatsApp pane…
    assert 'data-pp-view="whatsapp"' in body
    assert "رسائل واتساب للمشتركين" in body
    # …the pane itself is present…
    assert 'data-pp-pane="whatsapp"' in body
    # …and the illustrated Meta guide heading is rendered in it.
    assert GUIDE_HEADING in body


# ---------------------------------------------------------------------------
# Legacy GET /portal/whatsapp now 302-redirects into the dashboard pane
# ---------------------------------------------------------------------------
def test_legacy_whatsapp_get_redirects_to_dashboard_pane(client, app):
    with app.app_context():
        _make_customer_with_user(
            company="Legacy ISP", username="legacy-owner", email="legacy@example.test",
            grant_whatsapp=True,
        )
    _portal_login(client, "legacy-owner")

    resp = client.get(LEGACY_URL, follow_redirects=False)
    assert resp.status_code in (301, 302)
    location = resp.headers.get("Location", "")
    # Lands on the dashboard with the WhatsApp pane selected.
    assert "/portal" in location
    assert "view=whatsapp" in location


# ---------------------------------------------------------------------------
# Locked vs granted (rendered inside the dashboard pane)
# ---------------------------------------------------------------------------
def test_locked_customer_sees_locked_message_and_no_credentials_form(client, app):
    with app.app_context():
        _make_customer_with_user(
            company="Locked ISP", username="locked-owner", email="locked@example.test",
            grant_whatsapp=False,
        )
    _portal_login(client, "locked-owner")

    resp = client.get(DASH_URL)
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    # The WhatsApp pane still exists (always shown in the sidebar)…
    assert 'data-pp-pane="whatsapp"' in body
    # …with the locked banner…
    assert "هذه الخدمة غير مفعلة في خطتك الحالية. يمكنك طلب تفعيلها من الإدارة." in body
    # …and the credentials wizard (its save button) is NOT rendered.
    assert "حفظ بيانات الربط" not in body
    assert 'name="action" value="save_credentials"' not in body


def test_granted_customer_sees_wizard_step1_in_pane(client, app):
    with app.app_context():
        _make_customer_with_user(
            company="Granted ISP", username="granted-owner", email="granted@example.test",
            grant_whatsapp=True,
        )
    _portal_login(client, "granted-owner")

    resp = client.get(DASH_URL)
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    # Pane + step-1 form present.
    assert 'data-pp-pane="whatsapp"' in body
    assert "1. أدخل بيانات Meta" in body
    assert 'name="action" value="save_credentials"' in body
    assert "حفظ بيانات الربط" in body
    # Locked message is absent.
    assert "هذه الخدمة غير مفعلة في خطتك الحالية" not in body


# ---------------------------------------------------------------------------
# Save credentials encrypts the token and never shows it (POST → pane PRG)
# ---------------------------------------------------------------------------
def test_save_credentials_redirects_to_pane_and_never_shows_plaintext(client, app):
    with app.app_context():
        cid, _uid = _make_customer_with_user(
            company="Creds ISP", username="creds-owner", email="creds@example.test",
            grant_whatsapp=True,
        )
    _portal_login(client, "creds-owner")
    token = _csrf(client)

    # POST goes to the legacy action URL; it must PRG-redirect to the pane.
    resp = client.post(
        LEGACY_URL,
        data={
            "_csrf_token": token,
            "action": "save_credentials",
            "meta_business_id": "BIZ123",
            "whatsapp_business_account_id": "WABA456",
            "phone_number_id": "PNID789",
            "display_phone_number": "+970599000000",
            "business_display_name": "Creds ISP",
            "access_token": PLAINTEXT_TOKEN,
        },
        follow_redirects=False,
    )
    assert resp.status_code in (301, 302)
    assert "view=whatsapp" in resp.headers.get("Location", "")

    # Stored ciphertext decrypts back (it WAS encrypted, not stored raw).
    with app.app_context():
        account = wa_settings.get_account(cid)
        assert account is not None
        assert account.access_token_encrypted
        assert account.access_token_encrypted != PLAINTEXT_TOKEN
        assert decrypt_secret(account.access_token_encrypted) == PLAINTEXT_TOKEN
        ciphertext = account.access_token_encrypted

    # The dashboard pane must never render the plaintext token nor the raw
    # ciphertext — only the masked preview (token field stays write-only).
    page = client.get(DASH_URL)
    assert page.status_code == 200
    page_body = page.get_data(as_text=True)
    assert PLAINTEXT_TOKEN not in page_body
    assert ciphertext not in page_body
    # The write-only token input carries no value= attribute populated with a secret.
    assert 'name="access_token" value=""' in page_body


# ---------------------------------------------------------------------------
# Validate via monkeypatched provider marks connected (POST → pane PRG)
# ---------------------------------------------------------------------------
def test_validate_monkeypatched_marks_connected_and_advances_step(client, app, monkeypatch):
    with app.app_context():
        cid, _uid = _make_customer_with_user(
            company="Validate ISP", username="validate-owner", email="validate@example.test",
            grant_whatsapp=True,
        )
        wa_settings.upsert_account(cid, phone_number_id="PNID789", access_token=PLAINTEXT_TOKEN)

    def _fake_validate(self, account):  # no network
        return {
            "ok": True,
            "display_phone_number": "+970599111222",
            "business_display_name": "Verified ISP",
            "quality_rating": "GREEN",
            "messaging_limit_tier": "TIER_1K",
        }

    monkeypatch.setattr(MetaCloudWhatsAppProvider, "validate_credentials", _fake_validate)

    _portal_login(client, "validate-owner")
    token = _csrf(client)

    # Before validation we are on step 2 (creds saved, not connected) — the
    # dashboard pane shows an active wizard step.
    before = client.get(DASH_URL).get_data(as_text=True)
    assert 'class="wa-step is-active"' in before  # an active step exists

    resp = client.post(
        LEGACY_URL,
        data={"_csrf_token": token, "action": "validate"},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert "تم التحقق من الربط بنجاح." in resp.get_data(as_text=True)

    with app.app_context():
        account = wa_settings.get_account(cid)
        assert account.connection_status == "connected"
        assert account.display_phone_number == "+970599111222"


# ---------------------------------------------------------------------------
# Enable events flips settings.enabled True (POST action still works)
# ---------------------------------------------------------------------------
def test_enable_events_sets_enabled_true(client, app):
    with app.app_context():
        cid, _uid = _make_customer_with_user(
            company="Enable ISP", username="enable-owner", email="enable@example.test",
            grant_whatsapp=True,
        )
        assert wa_settings.get_settings(cid).enabled is False

    _portal_login(client, "enable-owner")
    token = _csrf(client)

    resp = client.post(
        LEGACY_URL,
        data={
            "_csrf_token": token,
            "action": "enable_events",
            "enabled": "1",
            "allow_otp": "1",
            "allow_expiry_notice": "1",
        },
        follow_redirects=False,
    )
    # PRG back to the dashboard WhatsApp pane.
    assert resp.status_code in (301, 302)
    assert "view=whatsapp" in resp.headers.get("Location", "")
    with app.app_context():
        settings_row = wa_settings.get_settings(cid)
        assert settings_row.enabled is True
        assert settings_row.allow_otp is True


# ---------------------------------------------------------------------------
# Locked customer cannot mutate via POST (still gated)
# ---------------------------------------------------------------------------
def test_locked_customer_post_is_blocked(client, app):
    with app.app_context():
        cid, _uid = _make_customer_with_user(
            company="Locked POST ISP", username="locked-post", email="lockedpost@example.test",
            grant_whatsapp=False,
        )
    _portal_login(client, "locked-post")
    token = _csrf(client)

    resp = client.post(
        LEGACY_URL,
        data={
            "_csrf_token": token,
            "action": "save_credentials",
            "phone_number_id": "SHOULD-NOT-SAVE",
            "access_token": PLAINTEXT_TOKEN,
        },
        follow_redirects=False,
    )
    assert resp.status_code in (301, 302)
    with app.app_context():
        # Nothing was written for the locked customer.
        assert wa_settings.get_account(cid) is None


# ---------------------------------------------------------------------------
# Isolation: a forged customer_id in the form is ignored — the route uses the
# SESSION customer, so customer B's account is never touched.
# ---------------------------------------------------------------------------
def test_customer_cannot_affect_another_customer_account(client, app):
    with app.app_context():
        cid_a, _ua = _make_customer_with_user(
            company="Tenant A", username="tenant-a", email="a@example.test",
            grant_whatsapp=True,
        )
        cid_b, _ub = _make_customer_with_user(
            company="Tenant B", username="tenant-b", email="b@example.test",
            grant_whatsapp=True,
        )

    # Log in as tenant A and POST credentials while forging customer_id = B.
    _portal_login(client, "tenant-a")
    token = _csrf(client)
    resp = client.post(
        LEGACY_URL,
        data={
            "_csrf_token": token,
            "action": "save_credentials",
            "customer_id": str(cid_b),  # forged — must be ignored
            "phone_number_id": "PNID-A-ONLY",
            "access_token": PLAINTEXT_TOKEN,
        },
        follow_redirects=True,
    )
    assert resp.status_code == 200

    with app.app_context():
        # The session customer (A) got the account…
        account_a = wa_settings.get_account(cid_a)
        assert account_a is not None
        assert account_a.phone_number_id == "PNID-A-ONLY"
        # …and tenant B was never touched.
        account_b = wa_settings.get_account(cid_b)
        assert account_b is None


# ---------------------------------------------------------------------------
# Not logged in -> redirect to the portal login (both the dashboard and the
# legacy WhatsApp URL bounce to login).
# ---------------------------------------------------------------------------
def test_not_logged_in_get_redirects_to_portal_login(client, app):
    resp = client.get(LEGACY_URL, follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert "/portal/login" in resp.headers.get("Location", "")
