from __future__ import annotations

import time
from datetime import timedelta

from app import create_app, seed_defaults
from app.config import TestingConfig
from app.extensions import db
from app.license_signing import sign_license_payload
from app.models import Customer, License, Plan, utcnow
from app.services.license_service import generate_license_key


SIGNING_SECRET = "test-license-signing-secret-at-least-32"


def make_signed_app(**overrides):
    return create_app(
        TestingConfig,
        LICENSE_CHECK_HMAC_SECRET=SIGNING_SECRET,
        LICENSE_CHECK_SIGNATURE_REQUIRED=True,
        LICENSE_CHECK_ALLOW_UNSIGNED=False,
        **overrides,
    )


def make_license() -> License:
    customer = Customer(company_name="Signed Customer")
    plan = Plan.query.filter_by(slug="pro").first()
    db.session.add(customer)
    db.session.flush()
    lic = License(
        customer_id=customer.id,
        plan_id=plan.id,
        license_key=generate_license_key(),
        status="active",
        starts_at=utcnow() - timedelta(days=1),
        expires_at=utcnow() + timedelta(days=10),
        grace_until=utcnow() + timedelta(days=17),
        max_fingerprints=1,
    )
    db.session.add(lic)
    db.session.commit()
    return lic


def signed_payload(license_key: str, *, nonce: str = "nonce-1", timestamp: int | None = None):
    payload = {
        "license_key": license_key,
        "server_fingerprint": f"fp-{nonce}",
        "hostname": "client-vps-1",
        "version": "1.0.0",
        "timestamp": int(timestamp or time.time()),
        "nonce": nonce,
    }
    payload["signature"] = sign_license_payload(payload, SIGNING_SECRET)
    return payload


def test_valid_signed_license_check_preserves_response_contract():
    app = make_signed_app()
    with app.app_context():
        db.create_all()
        seed_defaults(app)
        lic = make_license()
        client = app.test_client()

        res = client.post("/api/license/check", json=signed_payload(lic.license_key))
        body = res.get_json()

        assert res.status_code == 200
        assert body["active"] is True
        assert body["status"] == "active"
        assert body["mode"] == "active"
        assert set(["expires_at", "grace_until", "plan", "features"]).issubset(body.keys())


def test_invalid_signature_is_denied_without_license_lookup_details():
    app = make_signed_app()
    with app.app_context():
        db.create_all()
        seed_defaults(app)
        lic = make_license()
        client = app.test_client()
        payload = signed_payload(lic.license_key)
        payload["signature"] = "0" * 64

        res = client.post("/api/license/check", json=payload)
        body = res.get_json()

        assert res.status_code == 401
        assert body == {
            "active": False,
            "status": "denied",
            "mode": "denied",
            "message": "License check authorization failed.",
        }


def test_missing_signature_in_strict_mode_is_denied():
    app = make_signed_app()
    with app.app_context():
        db.create_all()
        seed_defaults(app)
        lic = make_license()
        client = app.test_client()

        res = client.post("/api/license/check", json={
            "license_key": lic.license_key,
            "server_fingerprint": "fp-missing",
        })

        assert res.status_code == 401
        assert res.get_json()["mode"] == "denied"


def test_signed_timestamp_too_old_or_future_is_denied():
    app = make_signed_app(LICENSE_CHECK_MAX_CLOCK_SKEW_SECONDS=60)
    with app.app_context():
        db.create_all()
        seed_defaults(app)
        lic = make_license()
        client = app.test_client()

        old_res = client.post("/api/license/check", json=signed_payload(
            lic.license_key,
            nonce="old",
            timestamp=int(time.time()) - 120,
        ))
        future_res = client.post("/api/license/check", json=signed_payload(
            lic.license_key,
            nonce="future",
            timestamp=int(time.time()) + 120,
        ))

        assert old_res.status_code == 401
        assert future_res.status_code == 401


def test_replayed_nonce_is_denied():
    app = make_signed_app()
    with app.app_context():
        db.create_all()
        seed_defaults(app)
        lic = make_license()
        client = app.test_client()
        payload = signed_payload(lic.license_key, nonce="replay-1")

        first = client.post("/api/license/check", json=payload)
        second = client.post("/api/license/check", json=payload)

        assert first.status_code == 200
        assert second.status_code == 401
        assert second.get_json()["message"] == "License check authorization failed."


def test_unsigned_compatibility_mode_keeps_existing_client_working():
    app = create_app(TestingConfig, LICENSE_CHECK_ALLOW_UNSIGNED=True, LICENSE_CHECK_SIGNATURE_REQUIRED=False)
    with app.app_context():
        db.create_all()
        seed_defaults(app)
        lic = make_license()
        client = app.test_client()

        res = client.post("/api/license/check", json={
            "license_key": lic.license_key,
            "server_fingerprint": "fp-unsigned",
        })

        assert res.status_code == 200
        assert res.get_json()["status"] == "active"
