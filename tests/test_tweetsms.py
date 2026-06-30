"""TweetSMS (tweetsms.ps) — OWNER→customer SMS.

Covers the pure adapter (URL build for both auth modes, success + every error
code → Arabic, Arabic URL-encoding, balance), the 60-char segment counter, the
encrypted/masked settings store, the per-recipient send service with logging,
and the admin routes (settings save, reveal, balance, test, customer single +
bulk send). No real api_key or network is used anywhere — HTTP is injected.
"""
from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import pytest

from app.extensions import db
from app.models import Admin, Customer, Setting, SmsLog
from app.services.tweetsms import adapter, segment_info, settings as tss
from app.services.tweetsms import service as tsvc


# ════════════════════════════════════════════════════════════════════════════
# Pure adapter
# ════════════════════════════════════════════════════════════════════════════

def test_build_send_url_api_key_and_params():
    url = adapter.build_send_url(
        {"api_key": "SECRET_KEY_XYZ"}, "970599123456", "hello", "MyBrand")
    parsed = urlparse(url)
    q = parse_qs(parsed.query)
    assert parsed.netloc == "www.tweetsms.ps"
    assert q["comm"] == ["sendsms"]
    assert q["api_key"] == ["SECRET_KEY_XYZ"]
    assert q["to"] == ["970599123456"]
    assert q["message"] == ["hello"]
    assert q["sender"] == ["MyBrand"]
    assert "user" not in q and "pass" not in q


def test_build_send_url_user_pass_mode():
    url = adapter.build_send_url(
        {"user": "owner", "pass": "pw123"}, "970599123456", "hi", "Brand")
    q = parse_qs(urlparse(url).query)
    assert q["user"] == ["owner"]
    assert q["pass"] == ["pw123"]
    assert "api_key" not in q


def test_build_send_url_url_encodes_arabic():
    arabic = "مرحبا بك"
    url = adapter.build_send_url({"api_key": "K"}, "970599", arabic, "Brand")
    # The raw query must be percent-encoded (no raw Arabic bytes in the URL)…
    assert "%D9" in url or "%D8" in url
    assert arabic not in url
    # …yet decode back to the original Arabic.
    q = parse_qs(urlparse(url).query)
    assert q["message"] == [arabic]


def test_build_send_url_multiple_recipients_joined():
    url = adapter.build_send_url({"api_key": "K"}, ["970599", "970598"], "hi", "B")
    q = parse_qs(urlparse(url).query)
    assert q["to"] == ["970599,970598"]


def test_parse_success_triple():
    out = adapter.parse_send_response("1:884422:970599123456")
    assert out.ok is True
    r = out.first
    assert r.ok and r.code == "1"
    assert r.sms_id == "884422"
    assert r.to == "970599123456"
    assert r.message == adapter.SUCCESS_MESSAGE


@pytest.mark.parametrize("code,fragment", [
    ("-110", "بيانات الدخول"),
    ("-113", "الرصيد"),
    ("-115", "المُرسِل غير متاح"),
    ("-116", "المُرسِل غير صالح"),
    ("-100", "ناقصة"),
])
def test_parse_global_error_codes_to_arabic(code, fragment):
    out = adapter.parse_send_response(code)
    assert out.ok is False
    assert fragment in out.error
    assert fragment in out.first.message


@pytest.mark.parametrize("code,fragment", [
    ("-2", "غير صالح"),
    ("-999", "فشل المزوّد"),
    ("u", "غير معروفة"),
])
def test_parse_per_message_error_codes(code, fragment):
    out = adapter.parse_send_response(f"{code}:0:970599000000")
    assert out.ok is False
    assert fragment in out.first.message
    assert out.first.code == code


def test_parse_multiline_mixed_results():
    out = adapter.parse_send_response("1:111:970599000001\n-2:0:badnum")
    assert out.ok is True  # at least one success
    assert len(out.results) == 2
    assert out.results[0].ok is True
    assert out.results[1].ok is False


def test_parse_balance_success_and_error():
    ok, bal, msg = adapter.parse_balance_response("1234")
    assert ok and bal == "1234"
    ok2, bal2, msg2 = adapter.parse_balance_response("Balance:55.5")
    assert ok2 and bal2 == "55.5"
    ok3, _b, msg3 = adapter.parse_balance_response("-110")
    assert not ok3 and "بيانات الدخول" in msg3


def test_send_sms_uses_injected_http_and_never_throws():
    captured = {}

    def fake_get(url, timeout):
        captured["url"] = url
        return "1:999:970599123456"

    out = adapter.send_sms({"api_key": "K"}, "970599123456", "hi", "Brand",
                           http_get=fake_get)
    assert out.ok and out.first.sms_id == "999"
    assert "comm=sendsms" in captured["url"]


def test_send_sms_network_failure_is_graceful():
    def boom(url, timeout):
        raise OSError("connection refused")

    out = adapter.send_sms({"api_key": "K"}, "970599", "hi", "B", http_get=boom)
    assert out.ok is False
    assert adapter.CONNECT_FAIL_PREFIX in out.error


# ════════════════════════════════════════════════════════════════════════════
# Segment counter (60-char rule)
# ════════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("n,expected_segments,over", [
    (0, 0, False),
    (1, 1, False),
    (60, 1, False),
    (61, 2, True),
    (120, 2, True),
    (121, 3, True),
])
def test_segment_info_60_char_logic(n, expected_segments, over):
    info = segment_info("ا" * n)
    assert info.length == n
    assert info.limit == 60
    assert info.segments == expected_segments
    assert info.over_limit is over


# ════════════════════════════════════════════════════════════════════════════
# Settings store — encrypted + masked
# ════════════════════════════════════════════════════════════════════════════

class _Form(dict):
    def get(self, k, default=""):
        return dict.get(self, k, default)


def _audit_noop(*a, **k):
    return None


def test_settings_save_encrypts_and_masks(app):
    with app.app_context():
        tss.validate_and_save(
            _Form(api_key="MY_SECRET_KEY_1234", sender="HobeRadius"),
            actor_audit=_audit_noop)
        db.session.commit()

        # Stored ciphertext must NOT equal the plaintext.
        raw = db.session.get(Setting, "tweetsms.api_key").value
        assert raw and raw != "MY_SECRET_KEY_1234"

        # resolved() decrypts it back; state masks it (never clear).
        assert tss.resolved()["api_key"] == "MY_SECRET_KEY_1234"
        state = tss.get_state()
        assert state["fields"]["api_key"]["present"] is True
        assert "value" not in state["fields"]["api_key"] or state["fields"]["api_key"]["value"] == ""
        assert "MY_SECRET" not in state["fields"]["api_key"]["masked"]
        assert state["configured"] is True


def test_settings_save_requires_some_auth(app):
    with app.app_context():
        with pytest.raises(tss.TweetSmsSettingsError):
            tss.validate_and_save(_Form(sender="Brand"), actor_audit=_audit_noop)


def test_settings_secret_blank_keeps_existing(app):
    with app.app_context():
        tss.validate_and_save(_Form(api_key="KEEPME", sender="B"), actor_audit=_audit_noop)
        db.session.commit()
        # Re-save with a blank api_key (only sender changes) → secret preserved.
        tss.validate_and_save(_Form(api_key="", sender="B2"), actor_audit=_audit_noop)
        db.session.commit()
        assert tss.resolved()["api_key"] == "KEEPME"
        assert tss.resolved()["sender"] == "B2"


def test_settings_reveal_returns_clear(app):
    with app.app_context():
        tss.validate_and_save(_Form(api_key="REVEALME", sender="B"), actor_audit=_audit_noop)
        db.session.commit()
        assert tss.reveal("api_key", actor_audit=_audit_noop) == "REVEALME"
        with pytest.raises(tss.TweetSmsSettingsError):
            tss.reveal("sender", actor_audit=_audit_noop)  # non-secret not revealable


# ════════════════════════════════════════════════════════════════════════════
# Service — per-recipient send + logging
# ════════════════════════════════════════════════════════════════════════════

def _configure(app):
    with app.app_context():
        tss.validate_and_save(_Form(api_key="K", sender="Brand"), actor_audit=_audit_noop)
        db.session.commit()


def test_service_send_per_recipient_results_and_logs(app):
    _configure(app)
    seen = []

    def fake_get(url, timeout):
        seen.append(url)
        return "1:555:970599123456"

    with app.app_context():
        result = tsvc.send_to_recipients(
            [{"phone": "0599123456", "label": "Acme", "customer_id": None}],
            "مرحبا", http_get=fake_get)
        assert result["ok"] is True
        assert result["sent"] == 1 and result["failed"] == 0
        r0 = result["results"][0]
        assert r0["ok"] and r0["sms_id"] == "555"
        # phone normalized to international, no '+', dialed in the URL.
        assert "970599123456" in seen[0]
        # a log row was written (status sent) without any api_key.
        log = SmsLog.query.first()
        assert log.status == "sent" and log.provider_sms_id == "555"


def test_service_invalid_phone_reported_without_send(app):
    _configure(app)
    calls = []

    def fake_get(url, timeout):
        calls.append(url)
        return "1:1:x"

    with app.app_context():
        result = tsvc.send_to_recipients(
            [{"phone": "not-a-number", "label": "Bad"}], "hi", http_get=fake_get)
        assert result["ok"] is False
        assert result["results"][0]["status"] == "invalid"
        assert calls == []  # no network call for an invalid number
        assert SmsLog.query.filter_by(status="invalid").count() == 1


def test_service_not_configured_short_circuits(app):
    with app.app_context():
        result = tsvc.send_to_recipients([{"phone": "0599123456"}], "hi")
        assert result["ok"] is False
        assert "TweetSMS" in result["error"]


# ════════════════════════════════════════════════════════════════════════════
# Admin routes
# ════════════════════════════════════════════════════════════════════════════

def _login_super(client):
    admin = Admin.query.filter_by(is_super_admin=True).first() or Admin.query.first()
    with client.session_transaction() as s:
        s["admin_id"] = admin.id
        s["is_super_admin"] = True
    return client


def _make_operator():
    """A real, active, NON-super admin (the gate reads Admin.is_super_admin)."""
    op = Admin(username="operator1", full_name="Op", email="op@test", active=True,
               is_super_admin=False)
    op.set_password("password123")
    db.session.add(op)
    db.session.commit()
    return op


def _login_operator(client):
    op = _make_operator()
    with client.session_transaction() as s:
        s["admin_id"] = op.id
        s["is_super_admin"] = False
    return op


@pytest.fixture()
def customer(app):
    c = Customer(company_name="SMS Co", phone="0599123456", status="active")
    db.session.add(c)
    db.session.commit()
    return c


def test_route_settings_save_and_balance(app, client, monkeypatch):
    _login_super(client)
    r = client.post("/admin/settings/tweetsms",
                    data={"api_key": "ROUTEKEY", "sender": "Brand"},
                    follow_redirects=False)
    assert r.status_code in (301, 302)
    with app.app_context():
        assert tss.resolved()["api_key"] == "ROUTEKEY"

    monkeypatch.setattr(adapter, "check_balance",
                        lambda creds, **k: (True, "777", ""))
    rb = client.post("/admin/settings/tweetsms/balance")
    assert rb.status_code == 200
    assert rb.get_json()["ok"] is True
    assert rb.get_json()["balance"] == "777"


def test_route_reveal_requires_super_admin(app, client):
    # Configure first as super.
    _login_super(client)
    client.post("/admin/settings/tweetsms", data={"api_key": "TOPSECRET", "sender": "B"})
    rr = client.post("/admin/settings/tweetsms/reveal", data={"field": "api_key"})
    assert rr.get_json()["ok"] is True
    assert rr.get_json()["value"] == "TOPSECRET"

    # A real non-super admin is rejected.
    with app.app_context():
        _login_operator(client)
    rr2 = client.post("/admin/settings/tweetsms/reveal", data={"field": "api_key"},
                      headers={"Accept": "application/json"})
    assert rr2.status_code == 403


def test_route_customer_send_sms_shows_per_recipient(app, client, customer, monkeypatch):
    _login_super(client)
    client.post("/admin/settings/tweetsms", data={"api_key": "K", "sender": "Brand"})

    def fake_send(creds, to, message, sender, **k):
        return adapter.parse_send_response("1:42:" + (to if isinstance(to, str) else ""))

    monkeypatch.setattr(adapter, "send_sms", fake_send)
    r = client.post(f"/admin/customers/{customer.id}/sms",
                    data={"message": "مرحبا بعميلنا"}, follow_redirects=True)
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "✓" in body  # per-recipient success marker in the flash
    with app.app_context():
        assert SmsLog.query.filter_by(customer_id=customer.id, status="sent").count() == 1


def test_route_bulk_sms_selected_customers(app, client, monkeypatch):
    _login_super(client)
    client.post("/admin/settings/tweetsms", data={"api_key": "K", "sender": "Brand"})
    with app.app_context():
        c1 = Customer(company_name="A", phone="0599000001", status="active")
        c2 = Customer(company_name="B", phone="0599000002", status="active")
        db.session.add_all([c1, c2])
        db.session.commit()
        ids = [c1.id, c2.id]

    monkeypatch.setattr(adapter, "send_sms",
                        lambda creds, to, message, sender, **k: adapter.parse_send_response("1:7:" + str(to)))
    r = client.post("/admin/customers/sms/bulk",
                    data={"customer_ids": [str(i) for i in ids], "message": "تعميم"},
                    follow_redirects=True)
    assert r.status_code == 200
    with app.app_context():
        assert SmsLog.query.filter_by(status="sent").count() == 2


def test_route_send_requires_super_admin(app, client, customer):
    # Logged in but NOT super → forbidden / redirect, no send.
    with app.app_context():
        _login_operator(client)
    r = client.post(f"/admin/customers/{customer.id}/sms",
                    data={"message": "x"}, follow_redirects=False)
    assert r.status_code in (302, 403)
    with app.app_context():
        assert SmsLog.query.count() == 0
