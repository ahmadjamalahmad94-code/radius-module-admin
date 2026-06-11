"""Bearer-mode license-check surface.

After the legacy-linking-auth removal, the panel only authenticates via the
license key in the request body (docs/SIMPLE_LINK_CONTRACT.md). All HMAC
signature / clock-skew / replay-nonce tests were dropped along with the
code they covered. What remains: confirm the bearer path keeps the public
response contract intact, and that unknown keys never authenticate.
"""
from __future__ import annotations

from datetime import timedelta

from app import create_app, seed_defaults
from app.config import TestingConfig
from app.extensions import db
from app.license_signing import (
    canonical_license_payload,
    mask_license_key,
    sign_license_payload,
)
from app.models import Customer, License, Plan, utcnow
from app.services.license_service import generate_license_key


def make_app():
    app = create_app(TestingConfig)
    with app.app_context():
        db.create_all()
        seed_defaults(app)
    return app


def make_license() -> License:
    customer = Customer(company_name="Bearer Customer")
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


def test_valid_license_check_preserves_response_contract():
    app = make_app()
    with app.app_context():
        lic = make_license()
        client = app.test_client()
        res = client.post("/api/license/check", json={"license_key": lic.license_key})
        body = res.get_json()
        assert res.status_code == 200
        assert body["active"] is True
        assert body["status"] == "active"
        assert body["mode"] == "active"
        assert {"expires_at", "grace_until", "plan", "features"}.issubset(body.keys())


def test_unknown_license_key_is_denied():
    app = make_app()
    with app.app_context():
        client = app.test_client()
        res = client.post("/api/license/check", json={"license_key": "HBR-2026-NONE-NONE-NONE"})
        # Endpoint returns 200 active=False for a not_found result; integration
        # variants 401. Either way, never grants access.
        if res.status_code == 200:
            assert res.get_json()["active"] is False
        else:
            assert res.status_code == 401


def test_canonical_payload_and_signature_helpers_stable():
    """Utility kept around for legacy test fixtures + radius-module sign-once
    backups. We don't ship a signed link path anymore, but the helpers must
    keep producing deterministic, sortable canonical JSON + a 64-hex digest
    so any downstream tool that imports them keeps working."""
    payload = {"license_key": "HBR-2026-AAAA-BBBB-CCCC", "nonce": "n1", "timestamp": 1700000000}
    canonical_a = canonical_license_payload(payload)
    canonical_b = canonical_license_payload({"timestamp": 1700000000, "nonce": "n1", "license_key": "HBR-2026-AAAA-BBBB-CCCC"})
    assert canonical_a == canonical_b  # order-independent
    sig = sign_license_payload(payload, "any-secret-32-bytes-for-the-helper")
    assert len(sig) == 64
    assert all(ch in "0123456789abcdef" for ch in sig)


def test_mask_license_key_never_leaks_full_value():
    full = "HBR-2026-AAAA-BBBB-CCCC"
    masked = mask_license_key(full)
    assert full not in masked
    assert masked.endswith("CCCC")
