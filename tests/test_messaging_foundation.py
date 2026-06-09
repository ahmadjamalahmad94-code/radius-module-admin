"""Unit + smoke tests for the unified messaging foundation.

Cover:

* Channel adapters' send() path with a MOCKED HTTP client (no real network).
* settings_store: encrypt-at-rest, mask-on-read, enable/disable flag.
* router.send: dispatch + clean failure codes (not_configured / disabled).
* layers: notify_owner respects owner prefs; message_customer routes to
  WhatsApp + SMS using the customer's dial_code/phone.
* admin/messaging blueprint: settings page renders + test-send endpoint returns
  JSON.
"""
from __future__ import annotations

import json

import pytest
from flask import url_for

from app.extensions import db
from app.models import Admin, Customer, Setting
from app.services import messaging
from app.services.messaging import channels as m_channels
from app.services.messaging import layers as m_layers
from app.services.messaging import router as m_router
from app.services.messaging import settings_store as m_store
from app.services.messaging.adapters import (
    ADAPTERS,
    AdapterResult,
    NotConfiguredError,
    SmsAdapter,
    TelegramAdapter,
    WhatsAppAdapter,
)
from app.services.messaging.adapters import _http as adapter_http


# ───────────────────────── helpers ─────────────────────────

def _login_admin(client, app):
    with app.app_context():
        admin = Admin.query.filter_by(username="admin").first()
        assert admin is not None
        admin_id = admin.id
    with client.session_transaction() as s:
        s["admin_id"] = admin_id


def _csrf(client, url):
    client.get(url)
    with client.session_transaction() as s:
        return s.get("_csrf_token", "")


def _set_sms_creds(enabled=True, base_url="https://sms.example.com/send",
                   api_key="sk_test_abc", sender_id="ACME"):
    """Persist SMS creds directly via the store (avoids form CSRF)."""
    from app.services.whatsapp.crypto import encrypt_secret
    db.session.add(Setting(key="messaging.sms.base_url", value=base_url))
    db.session.add(Setting(key="messaging.sms.api_key", value=encrypt_secret(api_key)))
    db.session.add(Setting(key="messaging.sms.sender_id", value=sender_id))
    db.session.add(Setting(key="messaging.sms.enabled", value="1" if enabled else "0"))


def _set_tg_creds(enabled=True, bot_token="123:abc", chat_id="999"):
    from app.services.whatsapp.crypto import encrypt_secret
    db.session.add(Setting(key="messaging.telegram.bot_token", value=encrypt_secret(bot_token)))
    db.session.add(Setting(key="messaging.telegram.default_chat_id", value=chat_id))
    db.session.add(Setting(key="messaging.telegram.enabled", value="1" if enabled else "0"))


# ───────────────────────── 1. settings_store ─────────────────────────

def test_secrets_are_encrypted_at_rest(app):
    """Saving via save_channel writes ciphertext, NOT plaintext."""
    with app.app_context():
        class _Form(dict):
            def get(self, k, d=None): return dict.get(self, k, d)
            def getlist(self, k): return []
        form = _Form(enabled="1", base_url="https://x.com", api_key="SECRET-VALUE", sender_id="BR")
        messaging.save_channel("sms", form, actor_audit=lambda *a, **k: None)
        db.session.commit()
        row = db.session.get(Setting, "messaging.sms.api_key")
        assert row is not None
        assert row.value  # something stored
        assert "SECRET-VALUE" not in row.value  # never plaintext
        # round-trip via resolved_credentials
        plain = m_store.resolved_credentials("sms")
        assert plain["api_key"] == "SECRET-VALUE"
        assert plain["base_url"] == "https://x.com"


def test_get_channel_state_masks_secret(app):
    with app.app_context():
        _set_sms_creds(api_key="0123456789abcdef")
        db.session.commit()
        state = messaging.get_channel_state("sms")
        assert state["enabled"] is True
        assert state["configured"] is True
        api_field = state["fields"]["api_key"]
        assert api_field["value"] == ""           # never prefill secret
        assert api_field["masked"] != "0123456789abcdef"
        assert "…" in api_field["masked"]
        assert state["fields"]["base_url"]["value"] == "https://sms.example.com/send"


def test_owner_prefs_roundtrip(app):
    with app.app_context():
        class _Form:
            def __init__(self, channels, events, phone, chat):
                self._channels = channels
                self._events = events
                self._phone = phone
                self._chat = chat
            def get(self, k, d=None):
                return {"owner_phone": self._phone,
                        "owner_telegram_chat_id": self._chat}.get(k, d)
            def getlist(self, k):
                if k == "owner_channels": return list(self._channels)
                if k == "owner_events": return list(self._events)
                return []
        messaging.save_owner_prefs(
            _Form(["sms", "telegram"], ["customer_created"], "970599000111", "42"),
            actor_audit=lambda *a, **k: None,
        )
        db.session.commit()
        prefs = messaging.get_owner_prefs()
        assert prefs["channels"] == ["sms", "telegram"]
        assert prefs["events"] == ["customer_created"]
        assert prefs["owner_phone"] == "970599000111"
        assert prefs["owner_telegram_chat_id"] == "42"


# ───────────────────────── 2. adapters with mocked HTTP ─────────────────────────

def _capture_post(monkeypatch, status=200, body=None, error=""):
    """Replace adapter_http.post_json with a recording stub.

    Returns the ``calls`` list — each entry is ``(url, payload, headers)``.
    """
    calls = []

    def _fake_post_json(url, payload=None, *, form=None, headers=None, timeout=15.0):
        calls.append((url, payload or form, dict(headers or {})))
        return adapter_http.HttpResult(status, body if body is not None else {"id": "msg_1"}, error=error)

    monkeypatch.setattr(adapter_http, "post_json", _fake_post_json)
    return calls


def test_sms_adapter_sends_via_http(monkeypatch):
    calls = _capture_post(monkeypatch, body={"message_id": "abc-123"})
    creds = {"base_url": "https://sms.example.com/send", "api_key": "sk", "sender_id": "ME"}
    result = SmsAdapter().send(creds, "970599000111", "hello")
    assert result.ok
    assert result.provider_message_id == "abc-123"
    assert calls and calls[0][0] == "https://sms.example.com/send"
    assert calls[0][1]["to"] == "970599000111"
    assert calls[0][1]["message"] == "hello"
    assert calls[0][2].get("Authorization") == "Bearer sk"


def test_sms_adapter_returns_failure_on_http_error(monkeypatch):
    _capture_post(monkeypatch, status=500, body={"error": "boom"})
    creds = {"base_url": "https://sms.example.com", "api_key": "sk", "sender_id": ""}
    result = SmsAdapter().send(creds, "970599000111", "hi")
    assert result.ok is False
    assert "500" in result.message


def test_sms_adapter_raises_when_not_configured():
    with pytest.raises(NotConfiguredError):
        SmsAdapter().send({"base_url": "", "api_key": "", "sender_id": ""}, "to", "txt")


def test_telegram_adapter_sends_via_bot_api(monkeypatch):
    calls = _capture_post(monkeypatch,
                          body={"ok": True, "result": {"message_id": 17}})
    creds = {"bot_token": "BOT", "default_chat_id": "999"}
    result = TelegramAdapter().send(creds, "999", "ping")
    assert result.ok
    assert result.provider_message_id == "17"
    assert calls and "api.telegram.org/botBOT/sendMessage" in calls[0][0]
    assert calls[0][1] == {"chat_id": "999", "text": "ping"}


def test_telegram_adapter_uses_default_chat_id_when_to_blank(monkeypatch):
    calls = _capture_post(monkeypatch,
                          body={"ok": True, "result": {"message_id": 1}})
    creds = {"bot_token": "BOT", "default_chat_id": "@me"}
    result = TelegramAdapter().send(creds, "", "p")
    assert result.ok
    assert calls[0][1]["chat_id"] == "@me"


def test_whatsapp_adapter_uses_compat_layer(monkeypatch, app):
    """The WhatsApp adapter shouldn't hit the network directly — it calls
    through ``_compat_whatsapp.send_text`` which we stub here."""
    captured = {}

    def _fake_send_text(*, token, phone_number_id, to, text):
        captured.update(dict(token=token, phone_number_id=phone_number_id, to=to, text=text))
        return {"ok": True, "provider_message_id": "wamid.STUB"}

    from app.services.messaging import _compat_whatsapp
    monkeypatch.setattr(_compat_whatsapp, "send_text", _fake_send_text)

    with app.app_context():
        creds = {"mode": "direct", "phone_number_id": "PNID", "access_token": "TOK"}
        result = WhatsAppAdapter().send(creds, "970599000111", "hi")
    assert result.ok
    assert result.provider_message_id == "wamid.STUB"
    assert captured == {"token": "TOK", "phone_number_id": "PNID", "to": "970599000111", "text": "hi"}


# ───────────────────────── 3. router ─────────────────────────

def test_router_returns_disabled_when_channel_off(app):
    with app.app_context():
        _set_sms_creds(enabled=False)
        db.session.commit()
        result = messaging.send("sms", "970599000111", "x")
        assert result.ok is False
        assert result.code == "disabled"


def test_router_returns_not_configured_when_creds_empty(app):
    with app.app_context():
        db.session.add(Setting(key="messaging.sms.enabled", value="1"))
        db.session.commit()
        result = messaging.send("sms", "970599000111", "x")
        assert result.ok is False
        assert result.code == "not_configured"


def test_router_returns_unknown_channel(app):
    with app.app_context():
        result = messaging.send("imessage", "1", "x")
        assert result.code == "unknown_channel"


def test_router_dispatches_to_adapter(app, monkeypatch):
    with app.app_context():
        _set_sms_creds()
        db.session.commit()
        _capture_post(monkeypatch, body={"id": "X"})
        result = messaging.send("sms", "970599000111", "hello")
        assert result.ok
        assert result.channel == "sms"
        assert result.code == "ok"


# ───────────────────────── 4. layers ─────────────────────────

def test_notify_owner_skips_when_event_disabled(app, monkeypatch):
    """An event NOT in the owner's prefs must be a complete no-op."""
    with app.app_context():
        _set_sms_creds()
        db.session.add(Setting(
            key="messaging.owner_prefs",
            value=json.dumps({"channels": ["sms"], "events": ["payment_request_created"],
                              "owner_phone": "970599000111", "owner_telegram_chat_id": ""}),
        ))
        db.session.commit()
        # capture would fail the test only if a send actually happens
        sent = _capture_post(monkeypatch)
        results = messaging.notify_owner("customer_created", "x")
        assert results == []
        assert sent == []


def test_notify_owner_sends_when_event_enabled(app, monkeypatch):
    with app.app_context():
        _set_sms_creds()
        db.session.add(Setting(
            key="messaging.owner_prefs",
            value=json.dumps({"channels": ["sms"], "events": ["customer_created"],
                              "owner_phone": "970599000111", "owner_telegram_chat_id": ""}),
        ))
        db.session.commit()
        sent = _capture_post(monkeypatch, body={"id": "msg-X"})
        results = messaging.notify_owner("customer_created", detail="عميل: Acme",
                                          extra={"id": 7})
        assert len(results) == 1
        assert results[0].ok
        assert sent and sent[0][1]["to"] == "970599000111"
        # message body carries the event label + detail
        assert "Acme" in sent[0][1]["message"]


def test_notify_owner_records_no_recipient_when_phone_blank(app, monkeypatch):
    with app.app_context():
        _set_sms_creds()
        db.session.add(Setting(
            key="messaging.owner_prefs",
            value=json.dumps({"channels": ["sms"], "events": ["customer_created"],
                              "owner_phone": "", "owner_telegram_chat_id": ""}),
        ))
        db.session.commit()
        sent = _capture_post(monkeypatch)
        results = messaging.notify_owner("customer_created", "x")
        assert len(results) == 1
        assert results[0].code == "no_recipient"
        assert sent == []


def test_message_customer_routes_to_sms_and_whatsapp(app, monkeypatch):
    """Default channels = (whatsapp, sms). SMS goes via HTTP, WhatsApp via the
    compat shim — both are mocked."""
    sms_calls = _capture_post(monkeypatch, body={"id": "S"})
    from app.services.messaging import _compat_whatsapp
    wa_calls = []

    def _fake_send_text(*, token, phone_number_id, to, text):
        wa_calls.append((token, phone_number_id, to, text))
        return {"ok": True, "provider_message_id": "W"}

    monkeypatch.setattr(_compat_whatsapp, "send_text", _fake_send_text)

    with app.app_context():
        _set_sms_creds()
        # configure WhatsApp in direct mode
        from app.services.whatsapp.crypto import encrypt_secret
        db.session.add(Setting(key="messaging.whatsapp.mode", value="direct"))
        db.session.add(Setting(key="messaging.whatsapp.phone_number_id", value="PNID"))
        db.session.add(Setting(key="messaging.whatsapp.access_token", value=encrypt_secret("TOK")))
        db.session.add(Setting(key="messaging.whatsapp.enabled", value="1"))
        db.session.commit()
        cust = Customer(company_name="Acme", phone="599000111", dial_code="+970")
        db.session.add(cust)
        db.session.commit()
        results = messaging.message_customer(cust, "hi friend")

    # one result per channel; both succeed
    assert {r.channel for r in results} == {"sms", "whatsapp"}
    assert all(r.ok for r in results)
    # SMS recipient = dial_code + local phone (no '+', no leading zero)
    assert sms_calls[0][1]["to"] == "970599000111"
    # WhatsApp uses the same composed number
    assert wa_calls[0][2] == "970599000111"


def test_message_customer_no_recipient_when_phone_blank(app):
    with app.app_context():
        _set_sms_creds()
        db.session.commit()
        cust = Customer(company_name="Empty Co", phone="", dial_code="+970")
        db.session.add(cust)
        db.session.commit()
        results = messaging.message_customer(cust, "hi", channels=["sms"])
        assert len(results) == 1
        assert results[0].code == "no_recipient"


# ───────────────────────── 5. blueprint / page render ─────────────────────────

def test_messaging_settings_page_renders(client, app):
    _login_admin(client, app)
    with app.test_request_context():
        url = url_for("admin_messaging.settings")
    body = client.get(url).get_data(as_text=True)
    # the three channel cards + the owner section
    assert "قنوات التواصل والإشعارات" in body
    assert "SMS" in body
    assert "واتساب" in body or "WhatsApp" in body
    assert "تيليجرام" in body
    assert "إشعارات المالك" in body


def test_test_send_returns_not_configured_when_keys_missing(client, app):
    _login_admin(client, app)
    with app.test_request_context():
        page = url_for("admin_messaging.settings")
        test_url = url_for("admin_messaging.settings_test_channel", channel="sms")
    token = _csrf(client, page)
    r = client.post(test_url,
                    data={"_csrf_token": token, "recipient": "970599000111"},
                    headers={"X-Requested-With": "XMLHttpRequest"})
    assert r.status_code == 200
    payload = r.get_json()
    assert payload["ok"] is False
    # default state = channel disabled; either code is acceptable foundation behavior
    assert payload["code"] in ("disabled", "not_configured")
    assert isinstance(payload["message"], str) and payload["message"]


def test_save_channel_form_persists_enable_flag(client, app):
    _login_admin(client, app)
    with app.test_request_context():
        page = url_for("admin_messaging.settings")
        save_url = url_for("admin_messaging.settings_save_channel", channel="telegram")
    token = _csrf(client, page)
    r = client.post(save_url, data={
        "_csrf_token": token,
        "enabled": "1",
        "bot_token": "BOTSECRET",
        "default_chat_id": "777",
    })
    assert r.status_code in (301, 302)
    with app.app_context():
        assert db.session.get(Setting, "messaging.telegram.enabled").value == "1"
        assert db.session.get(Setting, "messaging.telegram.default_chat_id").value == "777"
        # secret stored encrypted (the Setting value is NOT the plaintext)
        assert db.session.get(Setting, "messaging.telegram.bot_token").value != "BOTSECRET"
