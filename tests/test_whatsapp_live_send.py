"""LIVE Meta WhatsApp send-path proof — Phase 1.

These tests hit the REAL Meta Graph API to prove a tenant's manually-entered
credentials actually work end-to-end. They are **skip-gated** on environment
variables so they NEVER run in CI / offline and NEVER bake a shared number in:

* ``WHATSAPP_ACCESS_TOKEN``     — the tenant's (test) System User token,
* ``WHATSAPP_PHONE_NUMBER_ID``  — the tenant's phone number id,
* ``WHATSAPP_TEST_RECIPIENT``   — a WhatsApp number allowed to receive a test
  (only required for the actual send test; e.g. the developer's own number).

Per the project's config-from-UI rule these env vars are FOR TESTING ONLY — real
per-tenant credentials are entered in the UI. The provider always reads the
token + phone_number_id from the (per-tenant) account object passed in, so this
exercises exactly the production send path — there is no global/shared number.

Run locally:
    WHATSAPP_ACCESS_TOKEN=... WHATSAPP_PHONE_NUMBER_ID=... \
    WHATSAPP_TEST_RECIPIENT=9665XXXXXXXX \
    python -m pytest tests/test_whatsapp_live_send.py -v
"""
from __future__ import annotations

import os

import pytest

from app.services.whatsapp.crypto import encrypt_secret
from app.services.whatsapp.providers import (
    MetaCloudWhatsAppProvider,
    WhatsAppProviderError,
)

LIVE_TOKEN = os.environ.get("WHATSAPP_ACCESS_TOKEN", "").strip()
LIVE_PHONE_NUMBER_ID = os.environ.get("WHATSAPP_PHONE_NUMBER_ID", "").strip()
LIVE_RECIPIENT = os.environ.get("WHATSAPP_TEST_RECIPIENT", "").strip()

_HAVE_CREDS = bool(LIVE_TOKEN and LIVE_PHONE_NUMBER_ID)
_HAVE_RECIPIENT = bool(_HAVE_CREDS and LIVE_RECIPIENT)

# Meta ships this approved template with every WABA — the canonical "do my
# creds work" send that needs no template approval and no body variables.
HELLO_WORLD = "hello_world"
HELLO_WORLD_LANG = "en_US"


class _TenantAccountShim:
    """In-memory stand-in for a WhatsAppTenantAccount.

    Holds ONLY the two fields the provider reads — the Fernet-encrypted access
    token and the phone_number_id — exactly as a real per-tenant row would.
    Built from env creds so the test mirrors a tenant whose creds were entered
    via the UI (which stores the token encrypted, never in clear).
    """

    def __init__(self, token: str, phone_number_id: str) -> None:
        self.access_token_encrypted = encrypt_secret(token) if token else None
        self.phone_number_id = phone_number_id or ""


@pytest.mark.skipif(
    not _HAVE_CREDS,
    reason="set WHATSAPP_ACCESS_TOKEN + WHATSAPP_PHONE_NUMBER_ID to run the live validate check",
)
def test_live_validate_credentials_against_meta(app):
    """The tenant's token + phone_number_id resolve a real phone node at Meta.

    This is the safe (no message sent) proof that the manually-entered creds are
    valid — it reads the phone number node, the same call the «فحص الربط»
    (validate) button makes.
    """
    with app.app_context():
        account = _TenantAccountShim(LIVE_TOKEN, LIVE_PHONE_NUMBER_ID)
        result = MetaCloudWhatsAppProvider().validate_credentials(account)
        assert result["ok"] is True
        # A live phone node returns its display number; assert we got SOMETHING
        # back (Meta may restrict verified_name on a messaging-only token).
        assert result.get("display_phone_number")


@pytest.mark.skipif(
    not _HAVE_RECIPIENT,
    reason="also set WHATSAPP_TEST_RECIPIENT to run the live hello_world send",
)
def test_live_send_hello_world_template(app):
    """End-to-end: send the approved ``hello_world`` template from the TENANT's
    own number to a real recipient and get back a wamid — the definitive proof
    that the per-tenant send path works against Meta.
    """
    with app.app_context():
        account = _TenantAccountShim(LIVE_TOKEN, LIVE_PHONE_NUMBER_ID)
        try:
            result = MetaCloudWhatsAppProvider().send_template_message(
                account,
                recipient=LIVE_RECIPIENT,
                template_name=HELLO_WORLD,
                language=HELLO_WORLD_LANG,
            )
        except WhatsAppProviderError as exc:  # surface Meta's reason, never the token
            pytest.fail(f"live send failed: {exc.code} — {exc.message}")
        assert result.get("provider_message_id"), "Meta returned no message id"
        assert str(result["provider_message_id"]).startswith("wamid.")
