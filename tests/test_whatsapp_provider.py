from __future__ import annotations

import types

import pytest

from app.services.whatsapp.crypto import encrypt_secret
from app.services.whatsapp.providers import (
    MetaCloudWhatsAppProvider,
    WhatsAppProviderError,
)

# The decrypted access token used throughout. The token-leak guard asserts this
# exact string never escapes into an exception's str().
RAW_TOKEN = "EAABtestTOKEN1234567890"


def _stub_account(app):
    """Build a lightweight stand-in for WhatsAppTenantAccount.

    No DB row is needed: the provider only reads ``access_token_encrypted`` and
    ``phone_number_id``. The token is encrypted inside the app context so the
    Fernet key from TestingConfig is used.
    """
    with app.app_context():
        encrypted = encrypt_secret(RAW_TOKEN)
    return types.SimpleNamespace(
        access_token_encrypted=encrypted,
        phone_number_id="123456789012345",
        whatsapp_business_account_id="987654321098765",
        display_phone_number=None,
        business_display_name=None,
        quality_rating=None,
        messaging_limit_tier=None,
    )


# --------------------------------------------------------------------------- send


def test_send_template_message_success(app, monkeypatch):
    provider = MetaCloudWhatsAppProvider()
    account = _stub_account(app)

    captured = {}

    def fake_request(self, method, path, token, *, json_body=None, params=None):
        captured["method"] = method
        captured["path"] = path
        captured["json_body"] = json_body
        return 200, {"messages": [{"id": "wamid.TEST123"}]}

    monkeypatch.setattr(MetaCloudWhatsAppProvider, "_request", fake_request)

    with app.app_context():
        result = provider.send_template_message(
            account,
            recipient="+970599000000",
            template_name="welcome",
            language="ar",
            variables=["Ahmad", "5GB"],
        )

    assert result["provider_message_id"] == "wamid.TEST123"
    # Sanity-check the request shape the provider built.
    assert captured["method"] == "POST"
    assert captured["path"] == "123456789012345/messages"
    body = captured["json_body"]
    assert body["messaging_product"] == "whatsapp"
    assert body["type"] == "template"
    assert body["template"]["name"] == "welcome"
    assert body["template"]["language"] == {"code": "ar"}
    params = body["template"]["components"][0]["parameters"]
    assert params == [
        {"type": "text", "text": "Ahmad"},
        {"type": "text", "text": "5GB"},
    ]


def test_send_template_message_with_dict_variables(app, monkeypatch):
    provider = MetaCloudWhatsAppProvider()
    account = _stub_account(app)

    def fake_request(self, method, path, token, *, json_body=None, params=None):
        return 200, {"messages": [{"id": "wamid.DICT"}]}

    monkeypatch.setattr(MetaCloudWhatsAppProvider, "_request", fake_request)

    with app.app_context():
        result = provider.send_template_message(
            account,
            recipient="+970599000000",
            template_name="invoice",
            language="ar",
            variables={"name": "Sara", "amount": "100"},
        )
    assert result["provider_message_id"] == "wamid.DICT"


def test_send_text_message_success(app, monkeypatch):
    provider = MetaCloudWhatsAppProvider()
    account = _stub_account(app)

    captured = {}

    def fake_request(self, method, path, token, *, json_body=None, params=None):
        captured["json_body"] = json_body
        return 200, {"messages": [{"id": "wamid.TEXT1"}]}

    monkeypatch.setattr(MetaCloudWhatsAppProvider, "_request", fake_request)

    with app.app_context():
        result = provider.send_text_message(
            account, recipient="+970599000000", body="مرحبا"
        )

    assert result["provider_message_id"] == "wamid.TEXT1"
    assert captured["json_body"]["type"] == "text"
    assert captured["json_body"]["text"] == {"body": "مرحبا"}


# ----------------------------------------------------------------- retry classes


def test_send_template_retryable_failure_propagates(app, monkeypatch):
    """A 429-style failure must propagate with retryable=True."""
    provider = MetaCloudWhatsAppProvider()
    account = _stub_account(app)

    def fake_request(self, method, path, token, *, json_body=None, params=None):
        raise WhatsAppProviderError(
            "meta_rate_limited",
            "تم تجاوز حد الإرسال مؤقتًا، أعد المحاولة لاحقًا.",
            retryable=True,
            http_status=429,
        )

    monkeypatch.setattr(MetaCloudWhatsAppProvider, "_request", fake_request)

    with app.app_context():
        with pytest.raises(WhatsAppProviderError) as exc_info:
            provider.send_template_message(
                account,
                recipient="+970599000000",
                template_name="welcome",
                language="ar",
                variables=["x"],
            )
    assert exc_info.value.retryable is True
    assert exc_info.value.http_status == 429


def test_send_template_non_retryable_failure_propagates(app, monkeypatch):
    """A 400 invalid-recipient failure must propagate with retryable=False."""
    provider = MetaCloudWhatsAppProvider()
    account = _stub_account(app)

    def fake_request(self, method, path, token, *, json_body=None, params=None):
        # Simulate _request having already normalized a 400 invalid recipient.
        raise self.normalize_error(
            400,
            {"error": {"code": 100, "message": "Invalid parameter: 'to'"}},
        )

    monkeypatch.setattr(MetaCloudWhatsAppProvider, "_request", fake_request)

    with app.app_context():
        with pytest.raises(WhatsAppProviderError) as exc_info:
            provider.send_template_message(
                account,
                recipient="not-a-number",
                template_name="welcome",
                language="ar",
                variables=["x"],
            )
    assert exc_info.value.retryable is False


# --------------------------------------------------------------- validate creds


def test_validate_credentials_success(app, monkeypatch):
    provider = MetaCloudWhatsAppProvider()
    account = _stub_account(app)

    def fake_request(self, method, path, token, *, json_body=None, params=None):
        assert method == "GET"
        return 200, {
            "display_phone_number": "+970599000000",
            "verified_name": "ISP",
            "quality_rating": "GREEN",
            "messaging_limit_tier": "TIER_1K",
        }

    monkeypatch.setattr(MetaCloudWhatsAppProvider, "_request", fake_request)

    with app.app_context():
        result = provider.validate_credentials(account)

    assert result["ok"] is True
    assert result["display_phone_number"] == "+970599000000"
    assert result["business_display_name"] == "ISP"
    assert result["quality_rating"] == "GREEN"
    assert result["messaging_limit_tier"] == "TIER_1K"


def test_health_check_ok(app, monkeypatch):
    provider = MetaCloudWhatsAppProvider()
    account = _stub_account(app)

    def fake_request(self, method, path, token, *, json_body=None, params=None):
        return 200, {"id": "123456789012345"}

    monkeypatch.setattr(MetaCloudWhatsAppProvider, "_request", fake_request)

    with app.app_context():
        result = provider.health_check(account)
    assert result["ok"] is True
    assert result["status"] == "connected"


def test_health_check_unreachable_returns_not_ok(app, monkeypatch):
    provider = MetaCloudWhatsAppProvider()
    account = _stub_account(app)

    def fake_request(self, method, path, token, *, json_body=None, params=None):
        raise WhatsAppProviderError(
            "meta_unreachable", "تعذّر الاتصال بخدمة Meta.", retryable=True
        )

    monkeypatch.setattr(MetaCloudWhatsAppProvider, "_request", fake_request)

    with app.app_context():
        result = provider.health_check(account)
    assert result["ok"] is False
    assert result["retryable"] is True


# ------------------------------------------------------------------- webhooks


def test_parse_webhook_status_payload(app):
    provider = MetaCloudWhatsAppProvider()
    payload = {
        "object": "whatsapp_business_account",
        "entry": [
            {
                "id": "987654321098765",
                "changes": [
                    {
                        "field": "messages",
                        "value": {
                            "messaging_product": "whatsapp",
                            "metadata": {
                                "display_phone_number": "+970599000000",
                                "phone_number_id": "123456789012345",
                            },
                            "statuses": [
                                {
                                    "id": "wamid.DELIVERED1",
                                    "status": "delivered",
                                    "timestamp": "1700000000",
                                    "recipient_id": "970599000000",
                                }
                            ],
                        },
                    }
                ],
            }
        ],
    }

    events = provider.parse_webhook(payload)
    assert len(events) == 1
    event = events[0]
    assert event["event_type"] == "message_status"
    assert event["provider_message_id"] == "wamid.DELIVERED1"
    assert event["status"] == "delivered"
    assert event["recipient"] == "970599000000"


def test_parse_webhook_inbound_message(app):
    provider = MetaCloudWhatsAppProvider()
    payload = {
        "entry": [
            {
                "changes": [
                    {
                        "value": {
                            "messages": [
                                {
                                    "from": "970599000000",
                                    "id": "wamid.INBOUND1",
                                    "type": "text",
                                    "text": {"body": "Hello"},
                                }
                            ]
                        }
                    }
                ]
            }
        ]
    }
    events = provider.parse_webhook(payload)
    assert len(events) == 1
    assert events[0]["event_type"] == "inbound_message"
    assert events[0]["from"] == "970599000000"
    assert events[0]["text"] == "Hello"


def test_parse_webhook_malformed_never_raises(app):
    provider = MetaCloudWhatsAppProvider()
    for payload in (None, {}, {"entry": "nope"}, {"entry": [{"changes": [1, 2]}]}, "garbage"):
        events = provider.parse_webhook(payload)
        assert isinstance(events, list)
        assert events  # always at least one event
        # An unrecognized shape collapses to a single unknown event.
        if payload in (None, {}, "garbage") or payload == {"entry": "nope"}:
            assert events == [{"event_type": "unknown"}]


# --------------------------------------------------------------- normalize_error


def test_normalize_error_429_is_retryable(app):
    provider = MetaCloudWhatsAppProvider()
    err = provider.normalize_error(429, {"error": {"message": "rate limited"}})
    assert isinstance(err, WhatsAppProviderError)
    assert err.retryable is True
    assert err.http_status == 429


def test_normalize_error_400_is_not_retryable(app):
    provider = MetaCloudWhatsAppProvider()
    err = provider.normalize_error(400, {"error": {"code": 100, "message": "bad"}})
    assert err.retryable is False
    assert err.http_status == 400


def test_normalize_error_5xx_is_retryable(app):
    provider = MetaCloudWhatsAppProvider()
    err = provider.normalize_error(503, {})
    assert err.retryable is True


def test_normalize_error_auth_is_not_retryable(app):
    provider = MetaCloudWhatsAppProvider()
    err = provider.normalize_error(401, {"error": {"message": "bad token"}})
    assert err.retryable is False


# --------------------------------------------------------------- TOKEN-LEAK GUARD


def test_token_never_leaks_into_exception_string(app, monkeypatch):
    """Force an error path and assert the decrypted token never appears in str(exc)."""
    provider = MetaCloudWhatsAppProvider()
    account = _stub_account(app)

    # Echo the (decrypted) token back through the error body and message, the
    # most adversarial case. The provider must still scrub it: normalize_error
    # only surfaces curated text, never the body/token.
    def fake_request(self, method, path, token, *, json_body=None, params=None):
        assert token == RAW_TOKEN  # the provider did decrypt and pass it through
        raise self.normalize_error(
            400,
            {"error": {"code": 100, "message": f"leaked {token} here"}},
        )

    monkeypatch.setattr(MetaCloudWhatsAppProvider, "_request", fake_request)

    with app.app_context():
        with pytest.raises(WhatsAppProviderError) as exc_info:
            provider.send_text_message(account, recipient="+970599000000", body="hi")

    exc = exc_info.value
    assert RAW_TOKEN not in str(exc)
    assert RAW_TOKEN not in exc.message
    assert RAW_TOKEN not in repr(exc)


def test_missing_token_raises_without_leaking(app):
    """An account with no token raises a clean missing_token error."""
    provider = MetaCloudWhatsAppProvider()
    account = types.SimpleNamespace(
        access_token_encrypted="", phone_number_id="123"
    )
    with app.app_context():
        with pytest.raises(WhatsAppProviderError) as exc_info:
            provider.validate_credentials(account)
    assert exc_info.value.code == "missing_token"
    assert RAW_TOKEN not in str(exc_info.value)
