"""Central FCM push authority — licensing panel side.

Proves the centralized design:
  • the owner uploads a Firebase service-account credential → stored securely
    (instance/ file + encrypted DB recovery copy + masked status), never echoed;
  • the ONE global app registers its FCM token centrally (over the signed
    bridge, bearer license_key) → kept keyed to the resolved customer;
  • a radius instance forwards a push → licensing dispatches FCM to that
    customer's devices (the actual send is mocked — no network, no real key);
  • invalid tokens FCM reports are pruned.

No real Firebase key is used anywhere (the fake credential carries a dummy
PEM marker so validation passes without a usable key).
"""
from __future__ import annotations

import json
import uuid
from datetime import timedelta

import pytest

from app import create_app, seed_defaults
from app.config import TestingConfig
from app.extensions import db
from app.models import Customer, DeviceToken, License, Plan, Setting, utcnow
from app.services.license_service import generate_license_key

HTTPS = {"base_url": "https://license-panel.test"}


def _app():
    app = create_app(TestingConfig)
    with app.app_context():
        db.create_all()
        seed_defaults(app)
    return app


def _mk_license(customer_status: str = "active") -> License:
    customer = Customer(company_name=f"FCM {uuid.uuid4().hex[:6]}", status=customer_status)
    plan = Plan.query.filter_by(slug="pro").first()
    db.session.add(customer)
    db.session.flush()
    lic = License(
        customer_id=customer.id,
        plan_id=plan.id,
        license_key=generate_license_key(),
        status="active",
        starts_at=utcnow() - timedelta(days=1),
        expires_at=utcnow() + timedelta(days=30),
        grace_until=utcnow() + timedelta(days=37),
    )
    db.session.add(lic)
    db.session.commit()
    return lic


def _fake_service_account(project_id: str = "hoberadius") -> bytes:
    """A structurally-valid service-account JSON with a DUMMY key (no real
    secret). Passes validate_service_account (type + required fields + the
    'PRIVATE KEY' marker) without being a usable credential."""
    return json.dumps({
        "type": "service_account",
        "project_id": project_id,
        "private_key_id": "x" * 40,
        "private_key": "-----BEGIN PRIVATE KEY-----\nFAKEKEYNOTREAL\n-----END PRIVATE KEY-----\n",
        "client_email": f"firebase-adminsdk-abc12@{project_id}.iam.gserviceaccount.com",
        "client_id": "123456789",
        "token_uri": "https://oauth2.googleapis.com/token",
    }).encode("utf-8")


# ─────────────────────────────────────────────────────────────────────────
# Credential storage (mirror of the Google Drive model)
# ─────────────────────────────────────────────────────────────────────────

def test_validate_rejects_non_service_account():
    app = _app()
    with app.app_context():
        from app.services import firebase_fcm
        ok, _data, err = firebase_fcm.validate_service_account(b'{"type":"authorized_user"}')
        assert ok is False and "service_account" in err
        ok2, _d2, err2 = firebase_fcm.validate_service_account(b"not json {{{")
        assert ok2 is False and err2


def test_store_credential_secure_and_masked():
    app = _app()
    with app.app_context():
        from app.services import firebase_fcm
        info = firebase_fcm.store_uploaded(_fake_service_account())
        assert info["project_id"] == "hoberadius"

        # Secret file written under instance/firebase/, not echoed anywhere.
        path = firebase_fcm.stored_file_path()
        assert path.is_file()
        assert "FAKEKEYNOTREAL" in path.read_text(encoding="utf-8")

        # Encrypted recovery copy stored in settings — NOT plaintext JSON.
        enc = db.session.get(Setting, "firebase_admin_sdk_json_enc")
        assert enc is not None and enc.value
        assert "FAKEKEYNOTREAL" not in enc.value  # ciphertext, not the raw key

        # Masked status exposes only identity fields; email is masked.
        st = firebase_fcm.status()
        assert st["configured"] is True
        assert st["project_id"] == "hoberadius"
        assert st["client_email"].endswith("@hoberadius.iam.gserviceaccount.com")
        assert "firebase-adminsdk-abc12" not in st["client_email"] or "…" in st["client_email"]


def test_clear_credential_removes_file_and_settings():
    app = _app()
    with app.app_context():
        from app.services import firebase_fcm
        firebase_fcm.store_uploaded(_fake_service_account())
        assert firebase_fcm.is_configured() is True
        firebase_fcm.clear()
        assert firebase_fcm.is_configured() is False
        assert firebase_fcm.stored_file_path().is_file() is False


def test_resolve_path_restores_from_encrypted_db_copy():
    app = _app()
    with app.app_context():
        from app.services import firebase_fcm
        firebase_fcm.store_uploaded(_fake_service_account())
        # Simulate a lost instance volume: delete the file, keep the DB copy.
        firebase_fcm.stored_file_path().unlink()
        assert firebase_fcm.stored_file_path().is_file() is False
        restored = firebase_fcm.resolve_credential_path()
        assert restored and firebase_fcm.stored_file_path().is_file()


# ─────────────────────────────────────────────────────────────────────────
# Device-token registry service
# ─────────────────────────────────────────────────────────────────────────

def test_device_token_registry_upsert_and_prune():
    app = _app()
    with app.app_context():
        from app.services import device_tokens
        lic = _mk_license()
        cid = lic.customer_id
        device_tokens.register(cid, "tok-A", platform="android", app_version="1.0")
        device_tokens.register(cid, "tok-B", platform="ios")
        # Idempotent on token — re-register refreshes, does not duplicate.
        device_tokens.register(cid, "tok-A", platform="android", app_version="1.1")
        assert device_tokens.count_for_customer(cid) == 2
        assert set(device_tokens.tokens_for_customer(cid)) == {"tok-A", "tok-B"}
        assert device_tokens.prune(["tok-A"]) == 1
        assert device_tokens.tokens_for_customer(cid) == ["tok-B"]
        assert device_tokens.unregister("tok-B") == 1
        assert device_tokens.count_for_customer(cid) == 0


# ─────────────────────────────────────────────────────────────────────────
# Bridge endpoint: app registers its FCM token centrally
# ─────────────────────────────────────────────────────────────────────────

def test_register_token_endpoint_stores_for_customer():
    app = _app()
    with app.app_context():
        lic = _mk_license()
        cid = lic.customer_id
        client = app.test_client()
        res = client.post(
            "/api/integration/hoberadius/push/register-token",
            json={"license_key": lic.license_key, "token": "fcm-xyz",
                  "platform": "android", "app_version": "2.3.0"},
            **HTTPS,
        )
        assert res.status_code == 201, res.get_json()
        assert res.get_json()["devices"] == 1
        row = DeviceToken.query.filter_by(token="fcm-xyz").first()
        assert row is not None and row.customer_id == cid


def test_register_token_requires_https():
    app = _app()
    with app.app_context():
        lic = _mk_license()
        client = app.test_client()
        res = client.post(
            "/api/integration/hoberadius/push/register-token",
            json={"license_key": lic.license_key, "token": "fcm-xyz"},
        )
        assert res.status_code == 426


def test_register_token_unknown_license_404():
    app = _app()
    with app.app_context():
        client = app.test_client()
        res = client.post(
            "/api/integration/hoberadius/push/register-token",
            json={"license_key": "HBR-2026-NONE-NONE-NONE", "token": "fcm-xyz"},
            **HTTPS,
        )
        assert res.status_code in (401, 404)


def test_unregister_token_endpoint():
    app = _app()
    with app.app_context():
        from app.services import device_tokens
        lic = _mk_license()
        device_tokens.register(lic.customer_id, "fcm-bye")
        client = app.test_client()
        res = client.post(
            "/api/integration/hoberadius/push/unregister-token",
            json={"license_key": lic.license_key, "token": "fcm-bye"},
            **HTTPS,
        )
        assert res.status_code == 200
        assert res.get_json()["removed"] == 1


# ─────────────────────────────────────────────────────────────────────────
# Bridge endpoint: radius forwards a push → licensing DISPATCHES FCM
# (the actual send is mocked — proves licensing is the dispatcher)
# ─────────────────────────────────────────────────────────────────────────

def test_push_send_sync_dispatches_fcm_to_customer_devices(monkeypatch):
    app = _app()
    with app.app_context():
        from app.services import device_tokens, firebase_fcm
        lic = _mk_license()
        device_tokens.register(lic.customer_id, "tok-1", platform="android")
        device_tokens.register(lic.customer_id, "tok-2", platform="ios")

        sent_calls = {}

        def _fake_send(tokens, title, body, data=None):
            sent_calls["tokens"] = list(tokens)
            sent_calls["title"] = title
            sent_calls["body"] = body
            sent_calls["data"] = dict(data or {})
            return {"ok": True, "reason": "sent", "sent": len(tokens),
                    "failed": 0, "invalid_tokens": []}

        monkeypatch.setattr(firebase_fcm, "send_to_tokens", _fake_send)

        client = app.test_client()
        res = client.post(
            "/api/integration/hoberadius/push/send",
            json={"license_key": lic.license_key, "title": "تنبيه",
                  "body": "اختبار الدفع المركزي", "type": "system",
                  "link": "/admin/radius/notifications", "mode": "sync"},
            **HTTPS,
        )
        assert res.status_code == 200, res.get_json()
        out = res.get_json()
        assert out["ok"] is True and out["sent"] == 2 and out["devices"] == 2
        # Licensing dispatched FCM to exactly this customer's two tokens.
        assert set(sent_calls["tokens"]) == {"tok-1", "tok-2"}
        assert sent_calls["title"] == "تنبيه"
        assert sent_calls["data"].get("link") == "/admin/radius/notifications"
        assert sent_calls["data"].get("type") == "system"


def test_push_send_prunes_invalid_tokens(monkeypatch):
    app = _app()
    with app.app_context():
        from app.services import device_tokens, firebase_fcm
        lic = _mk_license()
        device_tokens.register(lic.customer_id, "tok-good")
        device_tokens.register(lic.customer_id, "tok-dead")

        def _fake_send(tokens, title, body, data=None):
            return {"ok": True, "reason": "sent", "sent": 1, "failed": 1,
                    "invalid_tokens": ["tok-dead"]}

        monkeypatch.setattr(firebase_fcm, "send_to_tokens", _fake_send)
        client = app.test_client()
        res = client.post(
            "/api/integration/hoberadius/push/send",
            json={"license_key": lic.license_key, "title": "x", "body": "y", "mode": "sync"},
            **HTTPS,
        )
        assert res.status_code == 200
        # The dead token was pruned from the central registry.
        assert device_tokens.tokens_for_customer(lic.customer_id) == ["tok-good"]


def test_push_send_no_tokens_reason(monkeypatch):
    app = _app()
    with app.app_context():
        from app.services import firebase_fcm
        lic = _mk_license()
        # No devices registered → no_tokens, sender never invoked.
        called = {"n": 0}
        monkeypatch.setattr(firebase_fcm, "send_to_tokens",
                            lambda *a, **k: called.__setitem__("n", called["n"] + 1) or {})
        client = app.test_client()
        res = client.post(
            "/api/integration/hoberadius/push/send",
            json={"license_key": lic.license_key, "title": "x", "body": "y", "mode": "sync"},
            **HTTPS,
        )
        assert res.status_code == 200
        assert res.get_json()["status"] == "no_tokens"
        assert called["n"] == 0


def test_push_send_async_queues_202():
    app = _app()
    with app.app_context():
        lic = _mk_license()
        client = app.test_client()
        res = client.post(
            "/api/integration/hoberadius/push/send",
            json={"license_key": lic.license_key, "title": "x", "body": "y"},
            **HTTPS,
        )
        assert res.status_code == 202
        assert res.get_json()["status"] == "queued"


def test_push_send_requires_https():
    app = _app()
    with app.app_context():
        lic = _mk_license()
        client = app.test_client()
        res = client.post(
            "/api/integration/hoberadius/push/send",
            json={"license_key": lic.license_key, "title": "x", "body": "y"},
        )
        assert res.status_code == 426
