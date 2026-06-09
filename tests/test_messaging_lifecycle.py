"""Tests for the lifecycle messaging layer + send-credentials hooks.

Cover:

* Lifecycle storage: per-event enable toggle, custom template override, the
  ``is_enabled`` / ``get_template`` round-trip, and the default-when-blank rule.
* ``build_credentials_text`` substitutes username/password/portal/company.
* ``send_credentials`` is a no-op when the credentials event is disabled, when
  the customer has no phone, AND it never logs the plaintext password.
* ``dispatch_lifecycle`` is silent for an unknown / disabled event.
* End-to-end routes: customer-user create + customer-user password set both
  call ``message_customer`` with the right composed text — verified by
  monkeypatching the adapter HTTP layer (no real sends).

Adapter HTTP is mocked through ``adapters._http.post_json`` (the single
network call site), so no network ever happens in this suite.
"""
from __future__ import annotations

import logging

import pytest
from flask import url_for

from app.extensions import db
from app.models import Admin, Customer, CustomerUser, Setting
from app.services import messaging
from app.services.messaging import lifecycle as lc
from app.services.messaging.adapters import _http as adapter_http


# ───────────────────────── helpers ─────────────────────────

def _login_admin(client, app):
    with app.app_context():
        admin_id = Admin.query.filter_by(username="admin").first().id
    with client.session_transaction() as s:
        s["admin_id"] = admin_id


def _csrf(client, url):
    client.get(url)
    with client.session_transaction() as s:
        return s.get("_csrf_token", "")


def _enable_sms_channel():
    """Plant the minimal config so the SMS channel is enabled + configured."""
    from app.services.whatsapp.crypto import encrypt_secret
    db.session.add(Setting(key="messaging.sms.base_url", value="https://sms.example.com/send"))
    db.session.add(Setting(key="messaging.sms.api_key", value=encrypt_secret("sk_test")))
    db.session.add(Setting(key="messaging.sms.sender_id", value="ME"))
    db.session.add(Setting(key="messaging.sms.enabled", value="1"))


def _capture_sms(monkeypatch, status=200, body=None):
    """Record every adapter POST and return the call list."""
    calls = []

    def _fake_post_json(url, payload=None, *, form=None, headers=None, timeout=15.0):
        calls.append({"url": url, "payload": payload or form, "headers": dict(headers or {})})
        return adapter_http.HttpResult(status, body if body is not None else {"id": "X"})

    monkeypatch.setattr(adapter_http, "post_json", _fake_post_json)
    return calls


def _customer(app, *, company="Acme Co", phone="599123456", dial="+970",
              runtime_url="https://acme.portal/"):
    cust = Customer(company_name=company, phone=phone, dial_code=dial,
                    runtime_url=runtime_url)
    db.session.add(cust)
    db.session.commit()
    return cust


# ───────────────────────── 1. lifecycle storage ─────────────────────────

def test_lifecycle_event_defaults(app):
    """Out of the box every catalogued event has a label + default template."""
    with app.app_context():
        for eid, ev in lc.LIFECYCLE_EVENTS.items():
            assert ev.label
            assert ev.default_template.strip()
            assert lc.is_enabled(eid) is ev.default_enabled


def test_lifecycle_save_and_roundtrip(app):
    with app.app_context():
        lc.save_event("welcome", enabled=False, template="مرحباً {company}!",
                      actor_audit=lambda *a, **k: None)
        db.session.commit()
        assert lc.is_enabled("welcome") is False
        assert lc.get_template("welcome") == "مرحباً {company}!"
        state = lc.get_event_state("welcome")
        assert state["enabled"] is False
        assert state["is_custom"] is True


def test_lifecycle_blank_template_means_default(app):
    """Saving a blank template clears the override (falls back to default)."""
    with app.app_context():
        ev = lc.LIFECYCLE_EVENTS["welcome"]
        lc.save_event("welcome", enabled=True, template="custom",
                      actor_audit=lambda *a, **k: None)
        db.session.commit()
        assert lc.get_template("welcome") == "custom"
        lc.save_event("welcome", enabled=True, template="   ",
                      actor_audit=lambda *a, **k: None)
        db.session.commit()
        assert lc.get_template("welcome") == ev.default_template


def test_render_substitutes_variables(app):
    with app.app_context():
        text = lc.render("credentials", username="alice", password="p@ss",
                         portal_url="https://x", company="Acme")
        assert "alice" in text
        assert "p@ss" in text
        assert "Acme" in text


def test_render_unknown_placeholder_kept_intact(app):
    """A custom template that names an unknown var doesn't blow up — the
    placeholder is left as-is. This avoids breaking the dispatch on a typo."""
    with app.app_context():
        lc.save_event("welcome", enabled=True,
                      template="Hello {company} {mystery}",
                      actor_audit=lambda *a, **k: None)
        db.session.commit()
        text = lc.render("welcome", company="Acme")
        assert "Acme" in text
        assert "{mystery}" in text


def test_audit_never_logs_template_body(app):
    """The audit metadata for a save call MUST NOT contain the template body."""
    captured = []
    def _audit(action, entity_type, entity_id, summary, metadata=None):
        captured.append({"metadata": metadata})

    with app.app_context():
        lc.save_event("credentials", enabled=True,
                      template="DO_NOT_LOG_THIS_BODY {username} {password}",
                      actor_audit=_audit)
        db.session.commit()
    assert captured
    meta = captured[0]["metadata"]
    assert "DO_NOT_LOG_THIS_BODY" not in str(meta)


# ───────────────────────── 2. build_credentials_text ─────────────────────────

def test_build_credentials_text_includes_username_and_password(app):
    with app.app_context():
        cust = _customer(app)
        text = lc.build_credentials_text(username="alice", password="p@ssw0rd!",
                                         customer=cust)
        assert "alice" in text
        assert "p@ssw0rd!" in text
        assert "Acme Co" in text
        assert "https://acme.portal/" in text


def test_build_credentials_text_handles_blank_portal_url(app):
    with app.app_context():
        cust = _customer(app, runtime_url="")
        text = lc.build_credentials_text(username="alice", password="x",
                                         customer=cust)
        # Should not error; portal_url just renders empty
        assert "alice" in text
        assert "x" in text


# ───────────────────────── 3. send_credentials gating ─────────────────────────

def test_send_credentials_no_op_when_disabled(app, monkeypatch):
    """Disabling the ``credentials`` event must skip dispatch entirely."""
    with app.app_context():
        _enable_sms_channel()
        lc.save_event("credentials", enabled=False, template="",
                      actor_audit=lambda *a, **k: None)
        db.session.commit()
        cust = _customer(app)
        calls = _capture_sms(monkeypatch)
        results = messaging.send_credentials(cust, username="alice", password="x")
        assert results == []
        assert calls == []


def test_send_credentials_routes_to_sms_and_whatsapp(app, monkeypatch):
    """Default channels = (whatsapp, sms); SMS uses HTTP, WhatsApp uses the
    compat shim — both mocked. The composed text carries the credentials."""
    from app.services.whatsapp.crypto import encrypt_secret
    from app.services.messaging import _compat_whatsapp
    wa = []

    def _fake_send_text(*, token, phone_number_id, to, text):
        wa.append({"to": to, "text": text})
        return {"ok": True, "provider_message_id": "W"}

    monkeypatch.setattr(_compat_whatsapp, "send_text", _fake_send_text)

    with app.app_context():
        _enable_sms_channel()
        # WhatsApp in "direct" mode
        db.session.add(Setting(key="messaging.whatsapp.mode", value="direct"))
        db.session.add(Setting(key="messaging.whatsapp.phone_number_id", value="PN"))
        db.session.add(Setting(key="messaging.whatsapp.access_token", value=encrypt_secret("TOK")))
        db.session.add(Setting(key="messaging.whatsapp.enabled", value="1"))
        db.session.commit()
        cust = _customer(app)
        sms_calls = _capture_sms(monkeypatch)
        results = messaging.send_credentials(cust, username="alice",
                                              password="hunter2", channels=["sms", "whatsapp"])

    assert {r.channel for r in results} == {"sms", "whatsapp"}
    assert all(r.ok for r in results)
    # SMS recipient is the composed E.164-ish number
    assert sms_calls[0]["payload"]["to"] == "970599123456"
    assert "alice" in sms_calls[0]["payload"]["message"]
    assert "hunter2" in sms_calls[0]["payload"]["message"]
    assert wa[0]["to"] == "970599123456"
    assert "alice" in wa[0]["text"]
    assert "hunter2" in wa[0]["text"]


def test_send_credentials_does_not_log_password(app, monkeypatch, caplog):
    """The plaintext password must NOT appear in any log record produced by
    the dispatch path — even when the adapter raises."""
    from app.services.messaging.adapters import sms as sms_mod
    # Force the adapter to crash so the layer's error handling runs.
    def _boom(*a, **k):
        raise RuntimeError("synthetic adapter crash")
    monkeypatch.setattr(sms_mod.SmsAdapter, "send", _boom)

    with app.app_context():
        _enable_sms_channel()
        db.session.commit()
        cust = _customer(app)
        with caplog.at_level(logging.DEBUG):
            results = messaging.send_credentials(cust, username="alice",
                                                  password="SUPERSECRET-do-not-log",
                                                  channels=["sms"])
    # The result records the crash but the password must not leak into logs.
    assert any("SUPERSECRET-do-not-log" in r.message for r in results) is False
    for rec in caplog.records:
        assert "SUPERSECRET-do-not-log" not in (rec.getMessage() or "")


# ───────────────────────── 4. dispatch_lifecycle gating ─────────────────────────

def test_dispatch_lifecycle_no_op_when_event_disabled(app, monkeypatch):
    with app.app_context():
        _enable_sms_channel()
        lc.save_event("welcome", enabled=False, template="",
                      actor_audit=lambda *a, **k: None)
        db.session.commit()
        cust = _customer(app)
        calls = _capture_sms(monkeypatch)
        results = messaging.dispatch_lifecycle("welcome", cust)
        assert results == []
        assert calls == []


def test_dispatch_lifecycle_sends_when_enabled(app, monkeypatch):
    with app.app_context():
        _enable_sms_channel()
        lc.save_event("welcome", enabled=True,
                      template="Welcome {company}", actor_audit=lambda *a, **k: None)
        db.session.commit()
        cust = _customer(app)
        calls = _capture_sms(monkeypatch)
        results = messaging.dispatch_lifecycle("welcome", cust, channels=["sms"])
        assert len(results) == 1
        assert results[0].ok
        assert calls[0]["payload"]["message"] == "Welcome Acme Co"


def test_dispatch_lifecycle_unknown_event_is_noop(app):
    with app.app_context():
        cust = _customer(app)
        results = messaging.dispatch_lifecycle("not_a_real_event", cust)
        assert results == []


# ───────────────────────── 5. route hooks (end-to-end) ─────────────────────────

def test_customer_user_create_sends_credentials(client, app, monkeypatch):
    """Creating a customer-user via the admin route triggers send_credentials."""
    _login_admin(client, app)
    sms_calls = _capture_sms(monkeypatch)
    with app.app_context():
        _enable_sms_channel()
        # Disable WhatsApp so this test only checks SMS path
        db.session.add(Setting(key="messaging.whatsapp.enabled", value="0"))
        db.session.commit()
        cust = _customer(app)
        cust_id = cust.id

    with app.test_request_context():
        page = url_for("admin.customer_user_new", customer_id=cust_id)
        post = url_for("admin.customer_user_create", customer_id=cust_id)
    token = _csrf(client, page)
    r = client.post(post, data={
        "_csrf_token": token,
        "username": "alice",
        "email": "alice@acme.test",
        "full_name": "Alice",
        "role_key": "owner",
        "password": "supersecret12",
        "active": "1",
    }, follow_redirects=False)
    assert r.status_code in (301, 302), r.get_data(as_text=True)[:300]
    # The SMS adapter saw exactly one outbound message carrying the credentials
    assert len(sms_calls) == 1
    body = sms_calls[0]["payload"]["message"]
    assert "alice" in body
    assert "supersecret12" in body
    assert "Acme Co" in body


def test_customer_user_password_set_sends_credentials(client, app, monkeypatch):
    """Admin-initiated password reset triggers send_credentials with the
    NEW password."""
    _login_admin(client, app)
    sms_calls = _capture_sms(monkeypatch)
    with app.app_context():
        _enable_sms_channel()
        db.session.add(Setting(key="messaging.whatsapp.enabled", value="0"))
        cust = _customer(app)
        # seed a user
        cu = CustomerUser(customer_id=cust.id, username="bob", email="b@x", active=True,
                          role_key="owner", password_version=1)
        cu.set_password("oldpassword")
        db.session.add(cu)
        db.session.commit()
        cust_id, cu_id = cust.id, cu.id

    with app.test_request_context():
        page = url_for("admin.customer_user_new", customer_id=cust_id)
        post = url_for("admin.customer_user_password_set",
                       customer_id=cust_id, user_id=cu_id)
    token = _csrf(client, page)
    r = client.post(post, data={
        "_csrf_token": token,
        "password": "brandnew123",
        "password_confirm": "brandnew123",
    }, follow_redirects=False)
    assert r.status_code in (301, 302)
    assert len(sms_calls) == 1
    body = sms_calls[0]["payload"]["message"]
    assert "bob" in body
    assert "brandnew123" in body


def test_customer_user_update_without_password_does_not_send(client, app, monkeypatch):
    """Editing a user WITHOUT changing the password must NOT send creds."""
    _login_admin(client, app)
    sms_calls = _capture_sms(monkeypatch)
    with app.app_context():
        _enable_sms_channel()
        db.session.add(Setting(key="messaging.whatsapp.enabled", value="0"))
        cust = _customer(app)
        cu = CustomerUser(customer_id=cust.id, username="carol", email="c@x", active=True,
                          role_key="owner", password_version=1)
        cu.set_password("origpw1234")
        db.session.add(cu)
        db.session.commit()
        cust_id, cu_id = cust.id, cu.id

    with app.test_request_context():
        page = url_for("admin.customer_user_edit", customer_id=cust_id, user_id=cu_id)
        post = url_for("admin.customer_user_update", customer_id=cust_id, user_id=cu_id)
    token = _csrf(client, page)
    r = client.post(post, data={
        "_csrf_token": token,
        "username": "carol",
        "email": "c@x",
        "full_name": "Carol",
        "role_key": "owner",
        "password": "",   # blank ⇒ no change
        "active": "1",
    }, follow_redirects=False)
    assert r.status_code in (301, 302)
    assert sms_calls == []


def test_customer_create_fires_welcome_lifecycle(client, app, monkeypatch):
    """End-to-end: customer creation through the admin route dispatches the
    welcome lifecycle when enabled (it's on by default)."""
    _login_admin(client, app)
    sms_calls = _capture_sms(monkeypatch)
    with app.app_context():
        _enable_sms_channel()
        db.session.add(Setting(key="messaging.whatsapp.enabled", value="0"))
        # Disable owner-broadcast to keep the assertion focused on welcome only.
        import json
        db.session.add(Setting(
            key="messaging.owner_prefs",
            value=json.dumps({"channels": [], "events": [],
                              "owner_phone": "", "owner_telegram_chat_id": ""}),
        ))
        db.session.commit()

    with app.test_request_context():
        page = url_for("admin.customer_new")
        post = url_for("admin.customer_create")
    token = _csrf(client, page)
    r = client.post(post, data={
        "_csrf_token": token,
        "company_name": "Helo Co",
        "contact_name": "Owner",
        "email": "owner@helo.test",
        "phone": "599000222",
        "dial_code": "+970",
        "country": "Palestine",
        "country_iso": "PS",
        "city": "Hebron",
        "currency": "USD",
    }, follow_redirects=False)
    assert r.status_code in (301, 302), r.get_data(as_text=True)[:300]
    # One SMS for the welcome lifecycle. Body should reference the company.
    assert len(sms_calls) >= 1
    assert any("Helo Co" in c["payload"]["message"] for c in sms_calls)


# ───────────────────────── 6. lifecycle settings UI ─────────────────────────

def test_messaging_settings_page_renders_lifecycle_section(client, app):
    _login_admin(client, app)
    with app.test_request_context():
        url = url_for("admin_messaging.settings")
    body = client.get(url).get_data(as_text=True)
    assert "رسائل دورة حياة العميل" in body
    # at least the credentials event card
    assert "إرسال بيانات الدخول" in body
    assert "{username}" in body or "username" in body  # variable hint


def test_save_lifecycle_event_form(client, app):
    _login_admin(client, app)
    with app.test_request_context():
        page = url_for("admin_messaging.settings")
        post = url_for("admin_messaging.settings_save_lifecycle", event_id="welcome")
    token = _csrf(client, page)
    r = client.post(post, data={
        "_csrf_token": token,
        "enabled": "1",
        "template": "Hi {company}!",
    })
    assert r.status_code in (301, 302)
    with app.app_context():
        assert lc.is_enabled("welcome") is True
        assert lc.get_template("welcome") == "Hi {company}!"
