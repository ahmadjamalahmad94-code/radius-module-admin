"""SEC C1 — the identity-sync response is signed with the license key.

A radius instance must be able to prove that a bridge response carrying
admin_super_overrides / owner_admins really came from this panel (which knows
the customer's license key) and not from a rogue/repointed endpoint. We attach
an HMAC-SHA256 `_bridge_sig` keyed by the license key; the customer recomputes
it with its own key.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from datetime import timedelta

import pytest

from app import create_app, seed_defaults
from app.config import TestingConfig
from app.extensions import db
from app.license_signing import (
    attach_bridge_signature,
    canonical_bridge_response,
    sign_bridge_response,
)
from app.models import Customer, License, Plan, utcnow
from app.services.license_service import generate_license_key


def _expected(payload: dict, key: str) -> str:
    body = {k: v for k, v in payload.items() if k != "_bridge_sig"}
    msg = json.dumps(body, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return hmac.new(key.strip().upper().encode("utf-8"),
                    msg.encode("utf-8"), hashlib.sha256).hexdigest()


def test_sign_matches_reference_algorithm():
    payload = {"ok": True, "users": [{"username": "a"}], "version": 3,
               "owner_admins": ["a"], "unicode": "عربي"}
    key = "HBR-ABCD-1234"
    assert sign_bridge_response(payload, key) == _expected(payload, key)


def test_signature_excludes_the_sig_field_itself():
    payload = {"ok": True, "version": 1}
    signed = attach_bridge_signature(dict(payload), "HBR-K-1")
    # Re-signing the object that now contains _bridge_sig yields the same hash
    # (the field is stripped before hashing).
    assert sign_bridge_response(signed, "HBR-K-1") == signed["_bridge_sig"]


def test_wrong_key_produces_different_signature():
    payload = {"ok": True, "version": 1}
    assert sign_bridge_response(payload, "HBR-A-1") != sign_bridge_response(payload, "HBR-B-2")


def test_attach_is_noop_without_key():
    payload = {"ok": True}
    out = attach_bridge_signature(payload, "")
    assert "_bridge_sig" not in out


def test_canonical_is_key_order_independent():
    a = {"b": 2, "a": 1, "_bridge_sig": "x"}
    b = {"a": 1, "b": 2}
    assert canonical_bridge_response(a) == canonical_bridge_response(b)


@pytest.fixture
def app():
    app = create_app(TestingConfig)
    with app.app_context():
        db.create_all()
        seed_defaults(app)
    return app


def test_identity_sync_endpoint_returns_valid_signature(app):
    """End-to-end: the live route attaches a signature that verifies against
    the resolved license key."""
    with app.app_context():
        customer = Customer(company_name=f"Sig {uuid.uuid4().hex[:6]}", status="active")
        plan = Plan.query.filter_by(slug="pro").first()
        db.session.add(customer)
        db.session.flush()
        lic = License(
            customer_id=customer.id, plan_id=plan.id,
            license_key=generate_license_key(), status="active",
            starts_at=utcnow() - timedelta(days=1),
            expires_at=utcnow() + timedelta(days=30),
            grace_until=utcnow() + timedelta(days=37),
        )
        db.session.add(lic)
        db.session.commit()
        key = lic.license_key

    client = app.test_client()
    res = client.post(
        "/api/integration/hoberadius/identity-sync",
        json={"license_key": key},
        base_url="https://localhost",
    )
    assert res.status_code == 200, res.get_json()
    payload = res.get_json()
    assert "_bridge_sig" in payload
    assert payload["_bridge_sig"] == _expected(payload, key)
