"""Shared seed helpers for the notification-backbone tests.

Reuses the root ``app`` / ``client`` fixtures (tests/conftest.py).
"""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.extensions import db
from app.models import (
    Customer,
    License,
    LicensePaymentRequest,
    Plan,
    ServiceAllocation,
    WhatsAppServiceSettings,
    WhatsAppUsageCounter,
)

# A fixed clock so countdown thresholds are deterministic.
BASE_NOW = datetime(2026, 6, 1, 12, 0, 0)

_seq = {"n": 0}


def _next() -> int:
    _seq["n"] += 1
    return _seq["n"]


def seed_customer(name: str = "عميل اختبار", *, phone: str = "599123456",
                  dial: str = "+970") -> Customer:
    c = Customer(company_name=f"{name}-{_next()}", status="active",
                 phone=phone, dial_code=dial)
    db.session.add(c)
    db.session.commit()
    return c


def seed_plan() -> Plan:
    p = Plan.query.filter_by(slug="test-plan").first()
    if p:
        return p
    p = Plan(name="خطة اختبار", slug="test-plan", monthly_price=10)
    db.session.add(p)
    db.session.commit()
    return p


def seed_license(customer: Customer, *, expires_at: datetime,
                 status: str = "active") -> License:
    p = seed_plan()
    lic = License(
        customer_id=customer.id, plan_id=p.id,
        license_key=f"HBR-TST-{_next():04d}-{_next():04d}"[:32],
        status=status, expires_at=expires_at,
    )
    db.session.add(lic)
    db.session.commit()
    return lic


def seed_ip_change(customer: Customer, *, expires_at: datetime,
                   status: str = "active") -> ServiceAllocation:
    a = ServiceAllocation(
        customer_id=customer.id, service_type="ip_change", status=status,
        speed_limit_mbps=100, expires_at=expires_at,
    )
    db.session.add(a)
    db.session.commit()
    return a


def seed_whatsapp(customer: Customer, *, limit: int = 500,
                  sent: int = 0, period_key: str = "2026-06") -> None:
    cfg = WhatsAppServiceSettings(customer_id=customer.id, enabled=True,
                                  monthly_message_limit=limit)
    db.session.add(cfg)
    counter = WhatsAppUsageCounter(customer_id=customer.id, period_type="monthly",
                                   period_key=period_key, sent_count=sent)
    db.session.add(counter)
    db.session.commit()
    return counter


def set_usage(counter: WhatsAppUsageCounter, sent: int) -> None:
    counter.sent_count = sent
    db.session.commit()


def seed_payment_request(customer: Customer, *, amount: int = 25,
                         status: str = "pending",
                         expires_at: datetime | None = None) -> LicensePaymentRequest:
    req = LicensePaymentRequest(
        customer_id=customer.id, purpose="renewal", amount=amount, currency="USD",
        reference_code=f"REF-{_next():06d}", status=status, expires_at=expires_at,
    )
    db.session.add(req)
    db.session.commit()
    return req


@pytest.fixture()
def auth_client(app, client):
    """A test client with a logged-in (super) admin session."""
    from app.models import Admin

    admin = Admin.query.first()
    if admin is not None and hasattr(admin, "is_super_admin"):
        admin.is_super_admin = True
        db.session.commit()
    with client.session_transaction() as sess:
        sess["admin_id"] = admin.id if admin else 1
    return client
