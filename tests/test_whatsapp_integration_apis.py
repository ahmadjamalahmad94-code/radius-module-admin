"""Tests for the 5 signed WhatsApp integration APIs in app/api/routes.py.

These endpoints are called by the radius_module runtime over a signed HMAC
contract — the SAME guard triad the other ``/api/integration/hoberadius/...``
endpoints use:

* HTTPS required (426 when not secure),
* HMAC signature required (401 on unsigned / bad signature),
* license -> customer resolution.

The provider is ALWAYS mocked here (``MetaCloudWhatsAppProvider.send_*`` are
monkeypatched), so the best-effort inline drain inside ``enqueue``/``test``
never touches Meta / the network.

Coverage:
* unsigned / bad-signature request to each of the 5 endpoints -> 401,
* a correctly-signed request -> ok for status + enqueue + subscriber-sync +
  message-status,
* enqueue (connected + enabled + approved template + opted-in subscriber) ->
  ok:true with the row sent; a second identical idempotency_key ->
  already_exists:true and NO duplicate row,
* NO access token (plaintext or stored ciphertext) appears in the status body,
* customer isolation: customer A cannot read customer B's message by
  idempotency_key (-> not_found).
"""
from __future__ import annotations

import time
from datetime import timedelta

import pytest

from app import create_app, seed_defaults
from app.config import TestingConfig
from app.extensions import db
from app.license_signing import sign_license_payload  # kept as test util only
from app.models import AuditLog, Customer, License, Plan, WhatsAppMessageQueue, utcnow
from app.services.license_service import generate_license_key
from app.services.whatsapp import cloud_settings as wac
from app.services.whatsapp import settings as wa_settings
from app.services.whatsapp.crypto import decrypt_secret
from app.services.whatsapp.providers import MetaCloudWhatsAppProvider, WhatsAppProviderError


HTTPS_BASE = "https://license-panel.test"
PHONE = "+970599000000"
# normalize_phone_for_whatsapp returns E.164 with the leading "+".
NORMALIZED_PHONE = "+970599000000"
# A distinctive token so we can assert it (and its ciphertext) never leak.
DUMMY_TOKEN = "EAABdummyTOKENsecretLEAK123"


# --------------------------------------------------------------------------- app

@pytest.fixture()
def app():
    """Bearer-only app — legacy signed-mode flags were retired with the
    linking-auth removal (docs/SIMPLE_LINK_CONTRACT.md)."""
    app = create_app(TestingConfig)
    with app.app_context():
        db.create_all()
        seed_defaults(app)
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


# --------------------------------------------------------------------------- helpers

def _make_customer_with_license(company_name: str) -> tuple[int, int, str]:
    """Create a customer + active license. Returns (customer_id, license_id, key)."""
    customer = Customer(company_name=company_name, contact_name="Owner")
    plan = Plan.query.filter_by(slug="pro").one()
    now = utcnow()
    db.session.add(customer)
    db.session.flush()
    lic = License(
        customer_id=customer.id,
        plan_id=plan.id,
        license_key=generate_license_key(),
        status="active",
        starts_at=now - timedelta(days=1),
        expires_at=now + timedelta(days=30),
        grace_until=now + timedelta(days=37),
        max_fingerprints=3,
    )
    db.session.add(lic)
    db.session.commit()
    return customer.id, lic.id, lic.license_key


def _provision_whatsapp(customer_id: int, *, opted_in_subscriber: str | None = None) -> None:
    """Give the customer a connected account, enabled settings, an approved
    ``otp`` template, and (optionally) an opted-in subscriber."""
    wa_settings.upsert_account(
        customer_id,
        phone_number_id="123456789012345",
        display_phone_number="+970599000000",
        business_display_name="Acme ISP",
        access_token=DUMMY_TOKEN,
    )
    wa_settings.set_connection_status(customer_id, "connected")
    wa_settings.update_settings(customer_id, enabled=True)
    wa_settings.upsert_template(
        customer_id,
        local_key="otp",
        provider_template_name="otp_ar",
        language="ar",
        status="approved",
    )
    if opted_in_subscriber is not None:
        wa_settings.upsert_subscriber_prefs(
            customer_id,
            [{"subscriber_id": opted_in_subscriber, "phone": PHONE, "whatsapp_opt_in": True}],
        )


def _signed(app, license_key: str, *, nonce: str, extra: dict | None = None) -> dict:
    """Build a bearer-auth integration body.

    Function name kept (callers across this file say ``_signed``); in the
    bearer-only world the body's ``license_key`` IS the credential. The
    ``sign_license_payload`` import is kept as a test helper because a few
    optional ``extra`` payloads still include a ``signature`` field, but the
    panel ignores it now."""
    del app
    payload = {
        "license_key": license_key,
        "server_fingerprint": f"fp-{nonce}",
        "hostname": "radius-runtime",
        "version": "test",
        "timestamp": int(time.time()),
        "nonce": nonce,
    }
    if extra:
        payload.update(extra)
    return payload


def _post_signed(client, app, path: str, license_key: str, *, nonce: str, extra: dict | None = None):
    return client.post(path, json=_signed(app, license_key, nonce=nonce, extra=extra), base_url=HTTPS_BASE)


# Re-export so static checkers don't strike the helper as unused. Some
# legacy fixtures still call sign_license_payload to construct
# back-compat sample data — keep it discoverable.
_ = sign_license_payload


def _patch_provider_ok(monkeypatch) -> dict:
    """Monkeypatch the provider send so the inline drain succeeds without Meta."""
    calls = {"n": 0}

    def fake_send_template(self, account, *, recipient, template_name, language, variables=None):
        calls["n"] += 1
        calls["recipient"] = recipient
        calls["template_name"] = template_name
        return {"provider_message_id": "wamid.TESTOK"}

    monkeypatch.setattr(MetaCloudWhatsAppProvider, "send_template_message", fake_send_template)
    return calls


# Every endpoint + a minimal body that would otherwise succeed if signed.
ENDPOINTS = [
    ("/api/integration/hoberadius/whatsapp/status", {}),
    (
        "/api/integration/hoberadius/whatsapp/messages/enqueue",
        {"source_event_type": "otp", "recipient_phone": PHONE, "template_key": "otp", "idempotency_key": "k-enq"},
    ),
    (
        "/api/integration/hoberadius/whatsapp/messages/test",
        {"recipient_phone": PHONE, "idempotency_key": "k-test"},
    ),
    (
        "/api/integration/hoberadius/whatsapp/subscriber-preferences/sync",
        {"subscribers": [{"subscriber_id": "s1", "phone": PHONE, "whatsapp_opt_in": True}]},
    ),
    (
        "/api/integration/hoberadius/whatsapp/messages/status",
        {"idempotency_key": "k-enq"},
    ),
]


# --------------------------------------------------------------------------- auth guard

@pytest.mark.parametrize("path,extra", ENDPOINTS)
def test_unsigned_request_is_rejected_401(client, app, path, extra):
    """No signature AND no valid bearer key -> 401.

    Simple-link (docs/SIMPLE_LINK_CONTRACT.md): a VALID body license key now
    bearer-authenticates an unsigned request, so the rejection is exercised
    with a key that doesn't resolve — that must still 401 — and the bearer
    acceptance with the real key is asserted alongside.
    """
    customer_id, _license_id, license_key = _make_customer_with_license("Unsigned Co")
    _provision_whatsapp(customer_id)

    body = {"license_key": "HBR-2026-NONE-NONE-NONE", "server_fingerprint": "fp-unsigned"}
    body.update(extra)
    # Even over HTTPS, no signature + unresolvable key must be rejected.
    res = client.post(path, json=body, base_url=HTTPS_BASE)
    assert res.status_code == 401
    assert res.get_json()["ok"] is False

    # Bearer mode: the same unsigned request with the VALID key authenticates
    # (business-level responses vary per endpoint — what matters is: not 401).
    body_ok = {"license_key": license_key, "server_fingerprint": "fp-unsigned"}
    body_ok.update(extra)
    res_ok = client.post(path, json=body_ok, base_url=HTTPS_BASE)
    assert res_ok.status_code != 401


@pytest.mark.parametrize("path,extra", ENDPOINTS)
def test_garbage_signature_is_ignored_in_bearer_mode(client, app, path, extra):
    """Bearer-only contract (docs/SIMPLE_LINK_CONTRACT.md): the legacy
    ``signature`` field is no longer part of authentication. So a garbage
    signature must be IGNORED when the body's ``license_key`` is valid (the
    request authenticates → NOT 401); the SAME garbage signature with an
    unresolvable key must still be rejected (401).

    This replaces the pre-migration "tampered signature -> 401" assertion,
    which contradicted bearer-only auth (a valid key authenticates regardless
    of any signature, exactly as ``_signed``'s docstring and the bearer-only
    ``verify_license_signature`` describe).
    """
    customer_id, _license_id, license_key = _make_customer_with_license("BadSig Co")
    _provision_whatsapp(customer_id)

    # Valid key + garbage signature -> signature ignored, request authenticates.
    body = _signed(app, license_key, nonce=f"bad-{path}", extra=extra)
    body["signature"] = "deadbeef" * 8  # ignored in bearer mode
    res = client.post(path, json=body, base_url=HTTPS_BASE)
    assert res.status_code != 401

    # Unresolvable key + garbage signature -> still rejected (auth is the key).
    bad = _signed(app, "HBR-2026-NONE-NONE-NONE", nonce=f"bad2-{path}", extra=extra)
    bad["signature"] = "deadbeef" * 8
    res_bad = client.post(path, json=bad, base_url=HTTPS_BASE)
    assert res_bad.status_code == 401
    assert res_bad.get_json()["ok"] is False


# --------------------------------------------------------------------------- status

def test_status_signed_returns_ok_and_no_token(client, app):
    customer_id, _license_id, license_key = _make_customer_with_license("Status Co")
    _provision_whatsapp(customer_id)

    res = _post_signed(client, app, "/api/integration/hoberadius/whatsapp/status", license_key, nonce="status-1")
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is True
    assert body["enabled"] is True
    assert body["account_status"] == "connected"
    # Normalized 3-state badge for the radius client (Connected/Needs action/Disconnected).
    assert body["integration_status"] == "connected"
    assert body["display_phone_number"] == "+970599000000"
    assert body["business_display_name"] == "Acme ISP"
    assert body["limits"]["daily"]["limit"] == 100
    assert body["limits"]["monthly"]["limit"] == 500
    assert body["allowed_events"]["otp"] is True
    assert body["allowed_events"]["password_reset"] is True
    # The approved otp template is advertised.
    assert any(t["local_key"] == "otp" and t["status"] == "approved" for t in body["templates"])


def test_status_response_never_contains_token(client, app):
    """Neither the plaintext token nor its stored ciphertext may appear."""
    customer_id, _license_id, license_key = _make_customer_with_license("NoLeak Co")
    _provision_whatsapp(customer_id)

    account = wa_settings.get_account(customer_id)
    ciphertext = account.access_token_encrypted
    assert ciphertext  # sanity: a token really is stored

    res = _post_signed(client, app, "/api/integration/hoberadius/whatsapp/status", license_key, nonce="noleak-1")
    raw = res.get_data(as_text=True)
    assert DUMMY_TOKEN not in raw
    assert ciphertext not in raw
    # The masked preview helper must not be echoed by this endpoint either.
    assert "access_token" not in raw


def test_status_onboarding_state_connected(client, app):
    customer_id, _license_id, license_key = _make_customer_with_license("OB Connected")
    _provision_whatsapp(customer_id)
    body = _post_signed(client, app, "/api/integration/hoberadius/whatsapp/status",
                        license_key, nonce="ob-conn").get_json()
    assert body["onboarding_state"] == "connected"
    assert isinstance(body["embedded_available"], bool)


def test_status_onboarding_state_needs_setup_when_never_connected(client, app):
    customer_id, _license_id, license_key = _make_customer_with_license("OB Needs Setup")
    # No account provisioned at all.
    body = _post_signed(client, app, "/api/integration/hoberadius/whatsapp/status",
                        license_key, nonce="ob-needs").get_json()
    assert body["onboarding_state"] == "needs_setup"
    assert body["account_status"] == "disconnected"


def test_status_onboarding_state_not_connected_when_disconnected(client, app):
    customer_id, _license_id, license_key = _make_customer_with_license("OB Not Connected")
    wa_settings.upsert_account(customer_id, phone_number_id="123", access_token=DUMMY_TOKEN)
    wa_settings.set_connection_status(customer_id, "disconnected")
    body = _post_signed(client, app, "/api/integration/hoberadius/whatsapp/status",
                        license_key, nonce="ob-notconn").get_json()
    assert body["onboarding_state"] == "not_connected"


# --------------------------------------------------------------------------- enqueue

def test_enqueue_signed_queues_and_sends_then_is_idempotent(client, app, monkeypatch):
    calls = _patch_provider_ok(monkeypatch)
    customer_id, _license_id, license_key = _make_customer_with_license("Enqueue Co")
    _provision_whatsapp(customer_id, opted_in_subscriber="sub-1")

    extra = {
        "source_event_type": "otp",
        "recipient_phone": PHONE,
        "template_key": "otp",
        "subscriber_id": "sub-1",
        "variables": ["123456"],
        "idempotency_key": "enq-otp-1",
    }
    res = _post_signed(
        client, app, "/api/integration/hoberadius/whatsapp/messages/enqueue",
        license_key, nonce="enq-1", extra=extra,
    )
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is True
    assert body["already_exists"] is False
    # Inline drain ran and the provider mock sent it.
    assert body["status"] == "sent"
    assert calls["n"] == 1
    assert calls["template_name"] == "otp_ar"
    assert calls["recipient"] == NORMALIZED_PHONE
    first_id = body["message_id"]

    with app.app_context():
        assert WhatsAppMessageQueue.query.count() == 1

    # A second identical idempotency_key -> already_exists, NO duplicate row.
    res2 = _post_signed(
        client, app, "/api/integration/hoberadius/whatsapp/messages/enqueue",
        license_key, nonce="enq-2", extra=extra,
    )
    assert res2.status_code == 200
    body2 = res2.get_json()
    assert body2["ok"] is True
    assert body2["already_exists"] is True
    assert body2["message_id"] == first_id
    # Provider was NOT called again (the row is already sent, not queued).
    assert calls["n"] == 1

    with app.app_context():
        assert WhatsAppMessageQueue.query.count() == 1


def test_enqueue_policy_rejection_returns_ok_false_not_500(client, app, monkeypatch):
    """Service disabled -> business rejection (HTTP 200, ok:false), not a 5xx."""
    _patch_provider_ok(monkeypatch)
    customer_id, _license_id, license_key = _make_customer_with_license("Disabled Co")
    # Account connected but the service is left DISABLED -> policy blocks.
    wa_settings.upsert_account(customer_id, phone_number_id="999", access_token=DUMMY_TOKEN)
    wa_settings.set_connection_status(customer_id, "connected")

    extra = {
        "source_event_type": "otp",
        "recipient_phone": PHONE,
        "template_key": "otp",
        "idempotency_key": "enq-disabled-1",
    }
    res = _post_signed(
        client, app, "/api/integration/hoberadius/whatsapp/messages/enqueue",
        license_key, nonce="enq-disabled", extra=extra,
    )
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is False
    assert body["error_code"] == "service_disabled"
    assert body["message_ar"]
    with app.app_context():
        assert WhatsAppMessageQueue.query.count() == 0


# --------------------------------------------------------------------------- test message

def test_test_message_signed_uses_approved_template(client, app, monkeypatch):
    calls = _patch_provider_ok(monkeypatch)
    customer_id, _license_id, license_key = _make_customer_with_license("TestMsg Co")
    _provision_whatsapp(customer_id)

    extra = {"recipient_phone": PHONE, "idempotency_key": "test-1"}
    res = _post_signed(
        client, app, "/api/integration/hoberadius/whatsapp/messages/test",
        license_key, nonce="test-1", extra=extra,
    )
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is True
    assert body["status"] == "sent"
    assert calls["n"] == 1


def test_test_message_without_approved_template_is_rejected(client, app, monkeypatch):
    _patch_provider_ok(monkeypatch)
    customer_id, _license_id, license_key = _make_customer_with_license("NoTemplate Co")
    # Connected + enabled, but NO approved template.
    wa_settings.upsert_account(customer_id, phone_number_id="999", access_token=DUMMY_TOKEN)
    wa_settings.set_connection_status(customer_id, "connected")
    wa_settings.update_settings(customer_id, enabled=True)

    extra = {"recipient_phone": PHONE, "idempotency_key": "test-noapprove-1"}
    res = _post_signed(
        client, app, "/api/integration/hoberadius/whatsapp/messages/test",
        license_key, nonce="test-noapprove", extra=extra,
    )
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is False
    assert body["error_code"] == "template_not_approved"
    assert body["message_ar"] == "لا يوجد قالب واتساب معتمد لإرسال رسالة تجربة."


def test_test_message_sends_via_tenant_account_not_house(client, app, monkeypatch):
    """The send uses the connected TENANT account's token, never house creds."""
    captured: dict = {}

    def fake_send_template(self, account, *, recipient, template_name, language, variables=None):
        captured["customer_id"] = account.customer_id
        captured["token"] = decrypt_secret(account.access_token_encrypted)
        captured["template_name"] = template_name
        return {"provider_message_id": "wamid.TENANT"}

    monkeypatch.setattr(MetaCloudWhatsAppProvider, "send_template_message", fake_send_template)
    # The house Cloud API path must never be invoked by this endpoint.
    def _house_boom(*a, **k):  # noqa: ANN001
        raise AssertionError("house cloud_settings.send_test_message must not be called")
    monkeypatch.setattr(wac, "send_test_message", _house_boom)

    customer_id, _license_id, license_key = _make_customer_with_license("Tenant Co")
    _provision_whatsapp(customer_id)
    res = _post_signed(
        client, app, "/api/integration/hoberadius/whatsapp/messages/test",
        license_key, nonce="tenant-1", extra={"recipient_phone": PHONE, "idempotency_key": "tenant-1"},
    )
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is True and body["status"] == "sent"
    assert body["provider_message_id"] == "wamid.TENANT"
    assert captured["customer_id"] == customer_id
    assert captured["token"] == DUMMY_TOKEN          # the TENANT token, not house creds


def test_test_message_emits_sent_audit(client, app, monkeypatch):
    _patch_provider_ok(monkeypatch)
    customer_id, _license_id, license_key = _make_customer_with_license("Sent Audit Co")
    _provision_whatsapp(customer_id)
    _post_signed(
        client, app, "/api/integration/hoberadius/whatsapp/messages/test",
        license_key, nonce="sent-aud", extra={"recipient_phone": PHONE, "idempotency_key": "sent-aud"},
    )
    assert AuditLog.query.filter_by(action="whatsapp_tenant_test_message_sent").count() == 1
    assert AuditLog.query.filter_by(action="whatsapp_tenant_test_message_failed").count() == 0


def test_test_message_failure_emits_failed_audit_and_safe_message(client, app, monkeypatch):
    def fake_send_fail(self, account, *, recipient, template_name, language, variables=None):
        raise WhatsAppProviderError("template_paused", "القالب موقوف مؤقتًا.")
    monkeypatch.setattr(MetaCloudWhatsAppProvider, "send_template_message", fake_send_fail)

    customer_id, _license_id, license_key = _make_customer_with_license("Fail Audit Co")
    _provision_whatsapp(customer_id)
    res = _post_signed(
        client, app, "/api/integration/hoberadius/whatsapp/messages/test",
        license_key, nonce="fail-aud", extra={"recipient_phone": PHONE, "idempotency_key": "fail-aud"},
    )
    body = res.get_json()
    assert body["ok"] is False
    assert body["error_code"] == "template_paused"
    assert body["message_ar"] == "القالب موقوف مؤقتًا."
    # never leak the token (plaintext or ciphertext) in the response
    raw = res.get_data(as_text=True)
    assert DUMMY_TOKEN not in raw
    assert AuditLog.query.filter_by(action="whatsapp_tenant_test_message_failed").count() == 1


def test_test_message_defaults_to_hello_world(client, app, monkeypatch):
    calls = _patch_provider_ok(monkeypatch)
    customer_id, _license_id, license_key = _make_customer_with_license("HW Co")
    wa_settings.upsert_account(customer_id, phone_number_id="999", access_token=DUMMY_TOKEN)
    wa_settings.set_connection_status(customer_id, "connected")
    wa_settings.update_settings(customer_id, enabled=True)
    # Both otp and hello_world are approved → hello_world wins as the default.
    wa_settings.upsert_template(customer_id, local_key="otp", provider_template_name="otp_ar",
                                language="ar", status="approved")
    wa_settings.upsert_template(customer_id, local_key="hello_world", provider_template_name="hello_world",
                                language="en", status="approved")
    _post_signed(
        client, app, "/api/integration/hoberadius/whatsapp/messages/test",
        license_key, nonce="hw-1", extra={"recipient_phone": PHONE, "idempotency_key": "hw-1"},
    )
    assert calls["template_name"] == "hello_world"


# --------------------------------------------------------------------------- subscriber sync

def test_subscriber_sync_signed_upserts_and_counts(client, app):
    customer_id, _license_id, license_key = _make_customer_with_license("Sync Co")
    _provision_whatsapp(customer_id)

    extra = {
        "subscribers": [
            {"subscriber_id": "100", "phone": "+970599111111", "whatsapp_opt_in": True, "allow_service_notices": True},
            {"subscriber_id": "101", "phone": "+970599222222", "whatsapp_opt_in": False, "allow_maintenance": True},
        ]
    }
    res = _post_signed(
        client, app, "/api/integration/hoberadius/whatsapp/subscriber-preferences/sync",
        license_key, nonce="sync-1", extra=extra,
    )
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is True
    assert body["synced"] == 2

    with app.app_context():
        pref = wa_settings.get_subscriber_pref(customer_id, "100")
        assert pref is not None
        assert pref.whatsapp_opt_in is True


# --------------------------------------------------------------------------- message status + isolation

def test_message_status_signed_returns_state(client, app, monkeypatch):
    _patch_provider_ok(monkeypatch)
    customer_id, _license_id, license_key = _make_customer_with_license("MsgStatus Co")
    _provision_whatsapp(customer_id, opted_in_subscriber="sub-1")

    enqueue_extra = {
        "source_event_type": "otp",
        "recipient_phone": PHONE,
        "template_key": "otp",
        "subscriber_id": "sub-1",
        "idempotency_key": "status-msg-1",
    }
    enq = _post_signed(
        client, app, "/api/integration/hoberadius/whatsapp/messages/enqueue",
        license_key, nonce="status-enq", extra=enqueue_extra,
    )
    assert enq.get_json()["ok"] is True

    res = _post_signed(
        client, app, "/api/integration/hoberadius/whatsapp/messages/status",
        license_key, nonce="status-q", extra={"idempotency_key": "status-msg-1"},
    )
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is True
    assert body["status"] == "sent"
    assert body["provider_message_id"] == "wamid.TESTOK"
    assert body["attempts"] == 0


def test_message_status_not_found_returns_ok_false(client, app):
    _customer_id, _license_id, license_key = _make_customer_with_license("Missing Co")
    res = _post_signed(
        client, app, "/api/integration/hoberadius/whatsapp/messages/status",
        license_key, nonce="missing-1", extra={"idempotency_key": "does-not-exist"},
    )
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is False
    assert body["error_code"] == "not_found"


def test_message_status_is_customer_isolated(client, app, monkeypatch):
    """Customer A must NOT be able to read customer B's message by its key."""
    _patch_provider_ok(monkeypatch)

    # Customer B owns a message with idempotency_key "b-secret-key".
    cust_b_id, _b_lic_id, b_license_key = _make_customer_with_license("Customer B")
    _provision_whatsapp(cust_b_id, opted_in_subscriber="sub-b")
    b_extra = {
        "source_event_type": "otp",
        "recipient_phone": PHONE,
        "template_key": "otp",
        "subscriber_id": "sub-b",
        "idempotency_key": "b-secret-key",
    }
    enq_b = _post_signed(
        client, app, "/api/integration/hoberadius/whatsapp/messages/enqueue",
        b_license_key, nonce="b-enq", extra=b_extra,
    )
    assert enq_b.get_json()["ok"] is True

    # Customer A signs with ITS OWN license and asks for B's key -> not_found.
    cust_a_id, _a_lic_id, a_license_key = _make_customer_with_license("Customer A")
    _provision_whatsapp(cust_a_id)
    res = _post_signed(
        client, app, "/api/integration/hoberadius/whatsapp/messages/status",
        a_license_key, nonce="a-query", extra={"idempotency_key": "b-secret-key"},
    )
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is False
    assert body["error_code"] == "not_found"

    # And B can still read its own message.
    res_b = _post_signed(
        client, app, "/api/integration/hoberadius/whatsapp/messages/status",
        b_license_key, nonce="b-query", extra={"idempotency_key": "b-secret-key"},
    )
    assert res_b.get_json()["ok"] is True
    assert res_b.get_json()["status"] == "sent"


def test_enqueue_is_customer_isolated_on_shared_idempotency_key(client, app, monkeypatch):
    """Two customers may reuse the SAME idempotency_key VALUE; each must get its
    own row and never read back the other tenant's message_id/status. (Keys are
    scoped per-customer because the DB column is globally unique.)"""
    _patch_provider_ok(monkeypatch)
    cust_a_id, _a_lic, a_key = _make_customer_with_license("Iso A")
    _provision_whatsapp(cust_a_id, opted_in_subscriber="sa")
    cust_b_id, _b_lic, b_key = _make_customer_with_license("Iso B")
    _provision_whatsapp(cust_b_id, opted_in_subscriber="sb")

    shared = {"source_event_type": "otp", "recipient_phone": PHONE,
              "template_key": "otp", "idempotency_key": "shared-key"}
    a = _post_signed(client, app, "/api/integration/hoberadius/whatsapp/messages/enqueue",
                     a_key, nonce="iso-a", extra={**shared, "subscriber_id": "sa"})
    b = _post_signed(client, app, "/api/integration/hoberadius/whatsapp/messages/enqueue",
                     b_key, nonce="iso-b", extra={**shared, "subscriber_id": "sb"})
    abody, bbody = a.get_json(), b.get_json()
    assert abody["ok"] is True and bbody["ok"] is True
    # B reused A's key value but must get its OWN new row — not A's.
    assert bbody["already_exists"] is False
    assert bbody["message_id"] != abody["message_id"]
    with app.app_context():
        assert WhatsAppMessageQueue.query.count() == 2
        assert db.session.get(WhatsAppMessageQueue, abody["message_id"]).customer_id == cust_a_id
        assert db.session.get(WhatsAppMessageQueue, bbody["message_id"]).customer_id == cust_b_id
