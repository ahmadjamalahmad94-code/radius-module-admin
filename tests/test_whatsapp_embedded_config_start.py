"""Embedded Signup P2 — config endpoint, start-session endpoint, state helpers.

Covers the safe GET config, the POST start-session (state/nonce issuance into
``whatsapp_embedded_signup_attempts``), the ``_consume_state`` validation helper,
and the additive audit taxonomy. No Meta network is touched (the start/config
paths make no Graph calls; the audit-taxonomy test monkeypatches the Graph
points like the main embedded-signup suite).
"""
from __future__ import annotations

import pytest

from app.extensions import db
from app.models import (
    AuditLog,
    Customer,
    CustomerUser,
    WhatsAppEmbeddedSignupAttempt,
)
from app.services.customer_control import get_or_create_service_entitlement
from app.services.whatsapp import embedded_signup as es

CONFIG_URL = "/portal/whatsapp/embedded/config"
START_URL = "/portal/whatsapp/embedded/start"


# ───────────────────────── fixtures / helpers ─────────────────────────

def _customer(company="ES ISP", username="es-owner", email="es@example.test", grant=True):
    c = Customer(company_name=company, contact_name="Owner", email=email, status="active")
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


def _login(client, username="es-owner"):
    return client.post("/portal/login", data={"username": username, "password": "Secret123!"})


def _mock_meta(monkeypatch, *, token="EAAB-tok-123456"):
    def fake_get(path, params):
        if path == "oauth/access_token":
            return {"access_token": token, "expires_in": 0}
        if path == "debug_token":
            return {"data": {"scopes": ["whatsapp_business_management"]}}
        if path.startswith("PNID"):
            return {"display_phone_number": "+970 599 123456", "verified_name": "ES Net",
                    "quality_rating": "GREEN", "messaging_limit_tier": "TIER_1K"}
        if path.startswith("WABA"):
            return {"name": "ES WABA", "owner_business_info": {"id": "BIZ-1"}}
        return {}

    def fake_post(path, data):
        return {"success": True}

    monkeypatch.setattr(es, "_graph_get", fake_get)
    monkeypatch.setattr(es, "_graph_post", fake_post)


# ───────────────────────── 1. GET config ─────────────────────────

def test_config_unauthenticated_401(client):
    resp = client.get(CONFIG_URL)
    assert resp.status_code == 401


def test_config_returns_safe_values_only(client):
    _customer()
    _login(client)
    resp = client.get(CONFIG_URL)
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["ok"] is True and body["enabled"] is True
    assert body["app_id"] == "test-app-id"
    assert body["config_id"] == "test-config-id"
    assert "graph_version" in body
    # The app secret must NEVER appear anywhere in the payload.
    assert "app_secret" not in body
    assert "test-app-secret" not in resp.get_data(as_text=True)


def test_config_disabled_reports_unavailable(client, monkeypatch, app):
    _customer()
    _login(client)
    monkeypatch.setitem(app.config, "META_APP_ID", "")
    resp = client.get(CONFIG_URL)
    body = resp.get_json()
    assert body["ok"] is True and body["enabled"] is False
    assert body["app_id"] == "" and body["config_id"] == ""


# ───────────────────────── 2. POST start session ─────────────────────────

def test_start_unauthenticated_401(client):
    assert client.post(START_URL, json={}).status_code == 401


def test_start_locked_without_entitlement_403(client):
    _customer(grant=False)
    _login(client)
    resp = client.post(START_URL, json={})
    assert resp.status_code == 403
    assert resp.get_json()["error"] == "locked"


def test_start_unavailable_503_when_not_configured(client, monkeypatch, app):
    _customer()
    _login(client)
    monkeypatch.setitem(app.config, "META_APP_ID", "")
    resp = client.post(START_URL, json={})
    assert resp.status_code == 503
    assert resp.get_json()["error"] == "unavailable"


def test_start_creates_pending_attempt_and_audits(client):
    cid = _customer()
    _login(client)
    resp = client.post(START_URL, json={})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["ok"] is True
    assert body["state"] and body["nonce"]
    assert body["config"]["app_id"] == "test-app-id"
    assert "app_secret" not in body["config"]

    attempt = WhatsAppEmbeddedSignupAttempt.query.filter_by(customer_id=cid).one()
    assert attempt.status == "pending"
    assert attempt.expires_at is not None
    assert attempt.initiated_by is not None
    # Only hashes are stored — never the raw state/nonce.
    assert attempt.state_hash and attempt.state_hash != body["state"]
    assert attempt.nonce_hash and attempt.nonce_hash != body["nonce"]
    assert AuditLog.query.filter_by(action="embedded_signup_started").count() == 1


def test_start_invalidates_prior_pending_attempt(client):
    cid = _customer()
    _login(client)
    client.post(START_URL, json={})
    client.post(START_URL, json={})
    attempts = WhatsAppEmbeddedSignupAttempt.query.filter_by(customer_id=cid).all()
    assert len(attempts) == 2
    statuses = sorted(a.status for a in attempts)
    assert statuses == ["expired", "pending"]


def test_start_is_tenant_scoped_ignores_body_customer_id(client):
    cid = _customer()
    other = _customer(company="Other", username="other-owner", email="other@example.test")
    _login(client)  # logs in as es-owner (cid)
    client.post(START_URL, json={"customer_id": other})
    # The attempt belongs to the SESSION customer, never the body customer_id.
    assert WhatsAppEmbeddedSignupAttempt.query.filter_by(customer_id=cid).count() == 1
    assert WhatsAppEmbeddedSignupAttempt.query.filter_by(customer_id=other).count() == 0


# ───────────────────────── 3. _consume_state helper ─────────────────────────

def test_consume_state_valid_returns_pending_attempt(app):
    with app.app_context():
        cid = _customer()
        issued = es.start_session(cid)
        attempt = es._consume_state(cid, issued["state"], nonce=issued["nonce"])
        assert attempt.status == "pending"
        assert attempt.customer_id == cid


def test_consume_state_rejects_foreign_customer(app):
    with app.app_context():
        cid = _customer()
        other = _customer(company="O", username="o", email="o@example.test")
        issued = es.start_session(cid)
        with pytest.raises(es.EmbeddedSignupError) as exc:
            es._consume_state(other, issued["state"])
        assert exc.value.code == "invalid_state"


def test_consume_state_rejects_unknown_state(app):
    with app.app_context():
        cid = _customer()
        es.start_session(cid)
        with pytest.raises(es.EmbeddedSignupError):
            es._consume_state(cid, "not-a-real-state")


def test_consume_state_rejects_and_marks_expired(app):
    with app.app_context():
        from app.models import utcnow
        from datetime import timedelta
        cid = _customer()
        issued = es.start_session(cid)
        attempt = WhatsAppEmbeddedSignupAttempt.query.filter_by(customer_id=cid).one()
        attempt.expires_at = utcnow() - timedelta(seconds=1)
        db.session.commit()
        with pytest.raises(es.EmbeddedSignupError) as exc:
            es._consume_state(cid, issued["state"])
        assert exc.value.code == "expired_state"
        db.session.refresh(attempt)
        assert attempt.status == "expired"


def test_consume_state_rejects_reused_attempt(app):
    with app.app_context():
        cid = _customer()
        issued = es.start_session(cid)
        attempt = es._consume_state(cid, issued["state"])
        es._finalize_attempt(attempt, status="completed")
        with pytest.raises(es.EmbeddedSignupError):
            es._consume_state(cid, issued["state"])


def test_consume_state_rejects_wrong_nonce(app):
    with app.app_context():
        cid = _customer()
        issued = es.start_session(cid)
        with pytest.raises(es.EmbeddedSignupError):
            es._consume_state(cid, issued["state"], nonce="wrong-nonce")


# ───────────────────────── 4. additive audit taxonomy ─────────────────────────

def test_complete_emits_new_and_legacy_audit(app, monkeypatch):
    with app.app_context():
        cid = _customer()
        _mock_meta(monkeypatch)
        es.complete_signup(cid, code="CODE", waba_id="WABA-1", phone_number_id="PNID-1")
        assert AuditLog.query.filter_by(action="embedded_signup_succeeded").count() == 1
        assert AuditLog.query.filter_by(action="whatsapp_embedded_connected").count() == 1


def test_disconnect_emits_new_and_legacy_audit(app, monkeypatch):
    with app.app_context():
        cid = _customer()
        _mock_meta(monkeypatch)
        es.complete_signup(cid, code="CODE", waba_id="WABA-1", phone_number_id="PNID-1")
        es.disconnect(cid)
        assert AuditLog.query.filter_by(action="whatsapp_connection_disconnected").count() == 1
        assert AuditLog.query.filter_by(action="whatsapp_embedded_disconnected").count() == 1
