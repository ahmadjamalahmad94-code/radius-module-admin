from __future__ import annotations

import re
from datetime import timedelta
from decimal import Decimal

import pytest

from app.extensions import db
from app.models import Customer, License, LicenseCheck, Plan, utcnow
from app.services.license_service import check_license, generate_license_key, renew_license


def make_customer() -> Customer:
    customer = Customer(company_name="Acme ISP", contact_name="Admin", email="admin@example.test")
    db.session.add(customer)
    db.session.commit()
    return customer


def make_license(*, status="active", expires_delta=timedelta(days=10), grace_delta=timedelta(days=17), max_fingerprints=1, fingerprints=None) -> License:
    customer = make_customer()
    plan = Plan.query.filter_by(slug="pro").first()
    now = utcnow()
    lic = License(
        customer_id=customer.id,
        plan_id=plan.id,
        license_key=generate_license_key(),
        status=status,
        starts_at=now - timedelta(days=1),
        expires_at=now + expires_delta,
        grace_until=now + grace_delta if grace_delta is not None else None,
        max_fingerprints=max_fingerprints,
    )
    lic.fingerprints = fingerprints or []
    db.session.add(lic)
    db.session.commit()
    return lic


def test_license_key_generation_format_and_uniqueness(app):
    keys = {generate_license_key() for _ in range(50)}
    assert len(keys) == 50
    assert all(re.match(r"^HBR-\d{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$", key) for key in keys)


def test_active_license_check_returns_active(app):
    lic = make_license()
    result = check_license(
        license_key=lic.license_key,
        fingerprint="server-1",
        hostname="client-vps",
        version="1.0.0",
        ip_address="10.0.0.10",
    )
    assert result.active is True
    assert result.mode == "active"
    assert result.status == "active"
    assert db.session.get(License, lic.id).fingerprints == ["server-1"]
    assert LicenseCheck.query.filter_by(license_id=lic.id, result="active").count() == 1


def test_expired_license_after_grace_returns_limited(app):
    lic = make_license(expires_delta=timedelta(days=-10), grace_delta=timedelta(days=-1))
    result = check_license(license_key=lic.license_key, fingerprint="server-1")
    assert result.active is False
    assert result.status == "expired"
    assert result.mode == "limited"


@pytest.mark.parametrize("status", ["suspended", "revoked"])
def test_suspended_and_revoked_license_returns_denied(app, status):
    lic = make_license(status=status)
    result = check_license(license_key=lic.license_key, fingerprint="server-1")
    assert result.active is False
    assert result.status == status
    assert result.mode == "denied"


def test_first_fingerprint_binding_works(app):
    lic = make_license(max_fingerprints=2)
    assert lic.fingerprints == []
    result = check_license(license_key=lic.license_key, fingerprint="first-fp")
    assert result.active is True
    assert db.session.get(License, lic.id).fingerprints == ["first-fp"]


def test_fingerprint_limit_exceeded_returns_denied(app):
    lic = make_license(max_fingerprints=1, fingerprints=["known-fp"])
    result = check_license(license_key=lic.license_key, fingerprint="new-fp")
    assert result.active is False
    assert result.result == "fingerprint_denied"
    assert result.mode == "denied"
    assert db.session.get(License, lic.id).fingerprints == ["known-fp"]


def test_renewal_extends_expiry(app):
    lic = make_license(expires_delta=timedelta(days=2))
    old_expiry = lic.expires_at
    renewal = renew_license(
        lic,
        months=1,
        amount=Decimal("79.00"),
        method="manual",
        payment_status="paid",
        notes="test renewal",
        actor_admin_id=None,
    )
    refreshed = db.session.get(License, lic.id)
    assert refreshed.expires_at > old_expiry
    assert refreshed.status == "active"
    assert renewal.period_end == refreshed.expires_at

