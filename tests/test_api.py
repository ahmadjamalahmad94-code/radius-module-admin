from __future__ import annotations

from datetime import timedelta

from app.extensions import db
from app.models import Customer, License, LicenseCheck, Plan, utcnow
from app.services.license_service import generate_license_key


def test_health_endpoint_returns_ok(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.get_json()["ok"] is True


def test_license_check_requires_key_only(client):
    # Simple-link: the fingerprint is optional now — only the key is required.
    res = client.post("/api/license/check", json={})
    assert res.status_code == 422
    body = res.get_json()
    assert body["active"] is False
    assert body["mode"] == "denied"

    # Key without fingerprint is no longer a 422 — it resolves normally
    # (unknown key → 200 with active=False / not_found).
    res = client.post("/api/license/check", json={"license_key": "HBR-2026-ABCD-EFGH-1234"})
    assert res.status_code == 200
    body = res.get_json()
    assert body["active"] is False
    assert body["status"] == "not_found"


def test_license_check_rejects_oversized_payload(client):
    res = client.post("/api/license/check", json={
        "license_key": "HBR-2026-ABCD-EFGH-1234",
        "server_fingerprint": "x" * 256,
    })

    assert res.status_code == 422
    assert res.get_json()["status"] == "invalid_request"


def test_license_check_uses_observed_ip_not_body_ip(client, app):
    with app.app_context():
        customer = Customer(company_name="API Smoke")
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

        res = client.post("/api/license/check", json={
            "license_key": lic.license_key,
            "server_fingerprint": "fp-observed",
            "ip_address": "203.0.113.200",
        }, environ_base={"REMOTE_ADDR": "198.51.100.10"})

        assert res.status_code == 200
        check = LicenseCheck.query.filter_by(license_id=lic.id).first()
        assert check.ip_address == "198.51.100.10"


def test_proxy_headers_are_ignored_unless_enabled(app):
    with app.app_context():
        client = app.test_client()
        client.post("/api/license/check", json={
            "license_key": "HBR-2026-NONE-NONE-NONE",
            "server_fingerprint": "fp-proxy",
        }, headers={"X-Forwarded-For": "203.0.113.55"}, environ_base={"REMOTE_ADDR": "198.51.100.20"})

        check = LicenseCheck.query.order_by(LicenseCheck.id.desc()).first()
        assert check.ip_address == "198.51.100.20"


def test_proxy_headers_are_used_when_enabled():
    from app import create_app, seed_defaults
    from app.config import TestingConfig

    app = create_app(TestingConfig, TRUST_PROXY_HEADERS=True)
    with app.app_context():
        db.create_all()
        seed_defaults(app)
        client = app.test_client()
        client.post("/api/license/check", json={
            "license_key": "HBR-2026-NONE-NONE-NONE",
            "server_fingerprint": "fp-proxy",
        }, headers={"X-Forwarded-For": "203.0.113.55"}, environ_base={"REMOTE_ADDR": "198.51.100.20"})

        check = LicenseCheck.query.order_by(LicenseCheck.id.desc()).first()
        assert check.ip_address == "203.0.113.55"


def test_api_404_returns_json(client):
    res = client.get("/api/missing")

    assert res.status_code == 404
    assert res.get_json()["error"] == "not_found"
