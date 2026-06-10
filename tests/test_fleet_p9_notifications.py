"""CHR Fleet Phase 9 — owner notifications.

Cover:

* Rule matrix: each event kind produces a non-empty Arabic body + stable
  dedupe_key + severity.
* Dispatcher: writes an Alert row per configured channel, calls the
  messaging channel router with the composed body, marks ``sent`` on OK.
* Storm guard: a second event with the same dedupe_key while the first is
  ``queued/sent`` re-uses the existing row (no duplicate Alert).
* Settings gate: ``set_kind_enabled(kind, False)`` makes dispatch a no-op.
* No recipient configured ⇒ Alert is written with ``status='suppressed'``
  rather than crashing (so the operator sees WHY no message went out).
* UI: alerts list and settings pages render; per-kind toggle round-trips.

The messaging adapter HTTP call (``messaging.adapters._http.post_json``)
is monkey-patched everywhere — no real network ever happens.
"""
from __future__ import annotations

import json

import pytest
from flask import url_for

from werkzeug.datastructures import MultiDict

from app.extensions import db
from app.models import Admin, Setting
from app.services.messaging.adapters import _http as adapter_http
from fleet.notify import rules, settings_store
from fleet.notify.models_alert import Alert, Event
from fleet.notify.notifier import dispatch_event


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
    """Plant the minimum SMS creds so the messaging router can deliver."""
    from app.services.whatsapp.crypto import encrypt_secret
    db.session.add(Setting(key="messaging.sms.base_url", value="https://sms.example.com/send"))
    db.session.add(Setting(key="messaging.sms.api_key", value=encrypt_secret("sk_test")))
    db.session.add(Setting(key="messaging.sms.sender_id", value="ME"))
    db.session.add(Setting(key="messaging.sms.enabled", value="1"))
    db.session.add(Setting(
        key="messaging.owner_prefs",
        value=json.dumps({
            "channels": ["sms"], "events": [],
            "owner_phone": "970599000111", "owner_telegram_chat_id": "",
        }),
    ))
    # Fleet uses ONLY sms in this test (avoid WA configured by default)
    settings_store.set_channels(["sms"])


def _capture_sms(monkeypatch, status=200, body=None):
    calls = []

    def _fake_post_json(url, payload=None, *, form=None, headers=None, timeout=15.0):
        calls.append({"url": url, "payload": payload or form, "headers": dict(headers or {})})
        return adapter_http.HttpResult(status, body if body is not None else {"id": "X"})

    monkeypatch.setattr(adapter_http, "post_json", _fake_post_json)
    return calls


def _mk_event(kind, *, chr_id=1, severity="info", detail=None):
    ev = Event(chr_id=chr_id, kind=kind, severity=severity)
    ev.detail = detail or {}
    db.session.add(ev)
    db.session.commit()
    return ev


# ───────────────────────── 1. rule matrix ─────────────────────────

@pytest.mark.parametrize("kind", list(rules.KIND_LABELS.keys()))
def test_every_catalogued_kind_has_a_spec(app, kind):
    """Every entry in KIND_LABELS resolves through spec_for with a
    non-empty Arabic title + body."""
    with app.app_context():
        ev = _mk_event(kind, detail={"node_name": "chr-01", "fqdn": "edge.example.com",
                                      "user": "alice", "previous_node": "chr-02",
                                      "fill_pct": 92, "session_count": 7})
        spec = rules.spec_for(ev)
        assert spec.title.strip()
        assert spec.body.strip()
        assert spec.severity in ("info", "warn", "crit")


def test_health_down_dedupe_key_includes_chr(app):
    with app.app_context():
        ev = _mk_event("health_down", severity="crit", chr_id=7,
                       detail={"node_name": "chr-07", "latency_ms": None})
        spec = rules.spec_for(ev)
        assert "chr-07" in spec.body
        assert spec.dedupe_key == "chr:7:health_down"
        assert spec.severity == "crit"


def test_dns_suppressed_carries_fqdn(app):
    with app.app_context():
        ev = _mk_event("dns_suppressed", chr_id=None, severity="warn",
                       detail={"fqdn": "edge.example.com",
                               "reason": "publishable_set_empty"})
        spec = rules.spec_for(ev)
        assert "edge.example.com" in spec.body
        assert spec.dedupe_key == "dns:edge.example.com:dns_suppressed"


def test_unknown_kind_falls_back_to_generic(app):
    with app.app_context():
        ev = _mk_event("brand_new_kind", severity="info",
                       detail={})
        spec = rules.spec_for(ev)
        assert spec.kind == "brand_new_kind"
        assert spec.body  # non-empty
        assert spec.default_enabled is False  # opt-in for unknown


# ───────────────────────── 2. dispatch + alert row ─────────────────────────

def test_dispatch_writes_alert_and_calls_channel(app, monkeypatch):
    """A health_down event with the kind enabled produces one queued
    Alert that gets sent via the channel router."""
    with app.app_context():
        _enable_sms_channel()
        db.session.commit()
        sms = _capture_sms(monkeypatch)
        ev = _mk_event("health_down", severity="crit", chr_id=11,
                       detail={"node_name": "chr-11", "latency_ms": 1200})
        alerts = dispatch_event(ev)
        db.session.commit()
        # Capture attrs while session is alive.
        assert len(alerts) == 1
        a = alerts[0]
        assert a.channel == "sms"
        assert a.status == "sent"
        assert a.recipient == "970599000111"
        assert "chr-11" in a.body
        assert sms and "chr-11" in sms[0]["payload"]["message"]


def test_dispatch_dedupes_storm(app, monkeypatch):
    """Two health_down events for the same chr while the slot is held →
    a single Alert row across both calls."""
    with app.app_context():
        _enable_sms_channel()
        db.session.commit()
        _capture_sms(monkeypatch)
        ev1 = _mk_event("health_down", severity="crit", chr_id=22,
                        detail={"node_name": "chr-22"})
        first = dispatch_event(ev1)
        db.session.commit()
        ev2 = _mk_event("health_down", severity="crit", chr_id=22,
                        detail={"node_name": "chr-22"})
        second = dispatch_event(ev2)
        db.session.commit()
        rows = Alert.query.filter(Alert.dedupe_key == "chr:22:health_down").all()
        assert len(first) == 1 and len(second) == 1
        assert first[0].id == second[0].id
        assert len(rows) == 1


def test_dispatch_noop_when_kind_disabled(app, monkeypatch):
    with app.app_context():
        _enable_sms_channel()
        settings_store.set_kind_enabled("health_down", False)
        db.session.commit()
        sms = _capture_sms(monkeypatch)
        ev = _mk_event("health_down", severity="crit", chr_id=33,
                       detail={"node_name": "chr-33"})
        alerts = dispatch_event(ev)
        db.session.commit()
    assert alerts == []
    assert sms == []
    with app.app_context():
        assert Alert.query.count() == 0


def test_dispatch_writes_suppressed_when_no_recipient(app, monkeypatch):
    """When the owner phone is blank we still record an Alert so the UI
    explains WHY nothing went out — but with status='suppressed'."""
    with app.app_context():
        # SMS configured but owner phone empty
        from app.services.whatsapp.crypto import encrypt_secret
        db.session.add(Setting(key="messaging.sms.base_url", value="https://sms.example.com"))
        db.session.add(Setting(key="messaging.sms.api_key", value=encrypt_secret("sk")))
        db.session.add(Setting(key="messaging.sms.enabled", value="1"))
        db.session.add(Setting(
            key="messaging.owner_prefs",
            value=json.dumps({"channels": ["sms"], "events": [],
                              "owner_phone": "", "owner_telegram_chat_id": ""}),
        ))
        settings_store.set_channels(["sms"])
        db.session.commit()
        sms = _capture_sms(monkeypatch)
        ev = _mk_event("health_down", severity="crit", chr_id=44,
                       detail={"node_name": "chr-44"})
        alerts = dispatch_event(ev)
        db.session.commit()
        assert len(alerts) == 1
        assert alerts[0].status == "suppressed"
        assert sms == []  # never tried to send


def test_dispatch_marks_failed_when_send_returns_failed(app, monkeypatch):
    """Network 500 from the SMS provider → Alert.status='failed'."""
    with app.app_context():
        _enable_sms_channel()
        db.session.commit()
        _capture_sms(monkeypatch, status=500, body={"error": "boom"})
        ev = _mk_event("health_down", severity="crit", chr_id=55,
                       detail={"node_name": "chr-55"})
        alerts = dispatch_event(ev)
        db.session.commit()
        assert len(alerts) == 1
        assert alerts[0].status == "failed"


# ───────────────────────── 3. settings store ─────────────────────────

def test_kind_default_enable_respects_defaults(app):
    with app.app_context():
        # default-on
        assert settings_store.is_kind_enabled("health_down") is True
        # default-off
        assert settings_store.is_kind_enabled("move_ok") is False


def test_kind_toggle_roundtrip(app):
    with app.app_context():
        settings_store.set_kind_enabled("dns_update", True)
        db.session.commit()
        assert settings_store.is_kind_enabled("dns_update") is True
        settings_store.set_kind_enabled("dns_update", False)
        db.session.commit()
        assert settings_store.is_kind_enabled("dns_update") is False


def test_channels_saves_only_allowed(app):
    with app.app_context():
        settings_store.set_channels(["sms", "imessage", "telegram"])
        db.session.commit()
        assert "imessage" not in settings_store.get_channels()
        assert "sms" in settings_store.get_channels()


# ───────────────────────── 4. UI routes ─────────────────────────

def test_alerts_list_page_renders_empty(client, app):
    _login_admin(client, app)
    with app.test_request_context():
        url = url_for("fleet_notify_ui.alerts_list")
    body = client.get(url).get_data(as_text=True)
    assert "تنبيهات الأسطول" in body
    assert "لا توجد تنبيهات" in body


def test_alerts_list_page_shows_recent_row(client, app, monkeypatch):
    _login_admin(client, app)
    with app.app_context():
        _enable_sms_channel()
        db.session.commit()
        _capture_sms(monkeypatch)
        ev = _mk_event("health_down", severity="crit", chr_id=99,
                       detail={"node_name": "chr-99", "latency_ms": None})
        dispatch_event(ev)
        db.session.commit()
    with app.test_request_context():
        url = url_for("fleet_notify_ui.alerts_list")
    body = client.get(url).get_data(as_text=True)
    assert "chr-99" in body
    assert "sms" in body
    assert "sent" in body


def test_alerts_settings_page_renders_kinds(client, app):
    _login_admin(client, app)
    with app.test_request_context():
        url = url_for("fleet_notify_ui.alerts_settings")
    body = client.get(url).get_data(as_text=True)
    # Catalogued labels appear
    assert "سقوط عقدة" in body
    assert "تحذير سعة" in body
    # form action exists
    assert "/admin/fleet/alerts/settings" in body


def test_alerts_settings_save_persists_toggles(client, app):
    _login_admin(client, app)
    with app.test_request_context():
        page = url_for("fleet_notify_ui.alerts_settings")
        save = url_for("fleet_notify_ui.alerts_settings_save")
    token = _csrf(client, page)
    r = client.post(save, data=MultiDict([
        ("_csrf_token", token),
        ("enabled_kinds", "dns_update"),
        ("enabled_kinds", "health_down"),
        ("channels", "sms"),
    ]))
    assert r.status_code in (301, 302)
    with app.app_context():
        assert settings_store.is_kind_enabled("dns_update") is True
        assert settings_store.is_kind_enabled("health_down") is True
        # An unchecked kind is now OFF (overriding any default)
        assert settings_store.is_kind_enabled("cap_warn") is False
        assert settings_store.get_channels() == ["sms"]


def test_alert_ack_clears_active_status(client, app, monkeypatch):
    _login_admin(client, app)
    with app.app_context():
        _enable_sms_channel()
        db.session.commit()
        _capture_sms(monkeypatch)
        ev = _mk_event("health_down", severity="crit", chr_id=77,
                       detail={"node_name": "chr-77"})
        alerts = dispatch_event(ev)
        db.session.commit()
        alert_id = alerts[0].id

    with app.test_request_context():
        page = url_for("fleet_notify_ui.alerts_list")
        ack_url = url_for("fleet_notify_ui.alert_ack", alert_id=alert_id)
    token = _csrf(client, page)
    r = client.post(ack_url, data={"_csrf_token": token})
    assert r.status_code in (301, 302)
    with app.app_context():
        row = db.session.get(Alert, alert_id)
        assert row.status == "suppressed"
