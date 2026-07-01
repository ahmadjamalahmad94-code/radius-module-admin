"""Regression: licensing NAS-used counts REGISTERED NAS, not the admin roster.

The customer licensing page («التراخيص والاشتراكات») showed an inflated "أجهزة
NAS مُستخدَمة" because the panel derived the count from the customer's admin
roster (``radius_admins_for_customer`` → ``CustomerRadiusAdmin`` rows) rather
than the customer's REGISTERED NAS devices. A customer with 0 registered NAS but
many admin/operator accounts (and a big imported ``radacct`` history) showed a
large NAS-used number.

The fix: the customer radius reports its real ``COUNT(nas_devices)`` in the
heartbeat ``inventory`` block; the panel persists it on
``CustomerRadiusInstance.reported_nas_count`` and the usage bar displays THAT.

These tests assert:
  * the heartbeat persists the reported registered counts;
  * the display helper returns the reported NAS count, independent of how many
    admin-roster rows exist (0 registered ⇒ 0, even with 30 roster rows);
  * registering N ⇒ N;
  * before any heartbeat (sentinel -1) NAS-used is 0, not the roster count.
"""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.extensions import db
from app.models import (
    Customer,
    CustomerRadiusAdmin,
    CustomerRadiusInstance,
    License,
    Plan,
)

HEARTBEAT_URL = "/api/integration/hoberadius/instance-ops/heartbeat"
LICENSE_KEY = "HBR-NAS-USAGE-TESTKEY"


def _seed_customer(*, roster_admins: int = 0, max_nas: int = 50):
    cust = Customer(company_name="ACME", email="acme@example.com", phone="")
    db.session.add(cust)
    db.session.flush()

    inst = CustomerRadiusInstance(
        customer_id=cust.id,
        instance_name=f"client{cust.id}-radius",
        realm=f"client{cust.id}",
        radius_auth_ip="187.77.70.18",
        radius_auth_port=1812,
        radius_acct_port=1813,
        status="online",
    )
    db.session.add(inst)

    plan = Plan(name="p", slug=f"p{cust.id}", monthly_price=0)
    if hasattr(plan, "max_nas"):
        plan.max_nas = max_nas
    db.session.add(plan)
    db.session.flush()

    lic = License(
        customer_id=cust.id,
        plan_id=plan.id,
        license_key=LICENSE_KEY,
        status="active",
        starts_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(days=30),
    )
    db.session.add(lic)

    # Admin roster — the WRONG source that used to inflate NAS-used.
    for i in range(roster_admins):
        db.session.add(CustomerRadiusAdmin(
            customer_id=cust.id,
            radius_admin_id=1000 + i,
            username=f"op{i}",
        ))
    db.session.commit()
    return cust, inst, lic


def _heartbeat(client, inventory):
    return client.post(HEARTBEAT_URL, json={
        "license_key": LICENSE_KEY,
        "server_fingerprint": "fp-test",
        "radius_auth_ip": "187.77.70.18",
        "inventory": inventory,
    })


def test_heartbeat_persists_reported_registered_nas(app, client):
    cust, inst, _ = _seed_customer(roster_admins=30)

    r = _heartbeat(client, {"nas_count": 0, "subscribers_total": 1589})
    assert r.status_code == 200, r.get_data(as_text=True)

    db.session.refresh(inst)
    # 0 registered NAS despite 30 roster admins + big history → stored 0.
    assert inst.reported_nas_count == 0
    assert inst.reported_subscribers_count == 1589
    assert inst.inventory_reported_at is not None


def test_display_nas_used_ignores_admin_roster(app, client):
    from app.admin.routes import _registered_nas_used

    cust, inst, _ = _seed_customer(roster_admins=30)
    # Sanity: the roster really has 30 rows (the old inflated source).
    from app.services.customer_control import radius_admins_for_customer
    assert len(radius_admins_for_customer(cust)) == 30

    _heartbeat(client, {"nas_count": 0})
    db.session.refresh(cust)
    # Display value tracks REGISTERED NAS (0), NOT the 30-row roster.
    assert _registered_nas_used(cust) == 0


def test_display_nas_used_equals_registered_count(app, client):
    from app.admin.routes import _registered_nas_used

    cust, inst, _ = _seed_customer(roster_admins=5)
    _heartbeat(client, {"nas_count": 3})
    db.session.refresh(cust)
    assert _registered_nas_used(cust) == 3


def test_nas_used_is_zero_before_first_heartbeat(app):
    from app.admin.routes import _registered_nas_used

    cust, inst, _ = _seed_customer(roster_admins=12)
    # No heartbeat yet → sentinel -1 → display 0 (never the 12-row roster).
    assert inst.reported_nas_count == -1
    assert _registered_nas_used(cust) == 0


def test_subscribers_used_falls_back_until_reported(app, client):
    from app.admin.routes import _registered_subscribers_used

    cust, inst, _ = _seed_customer()
    # Before a report, fall back to the provided portal-user count.
    assert _registered_subscribers_used(cust, fallback=1) == 1
    # After a report, use the real registered count.
    _heartbeat(client, {"subscribers_total": 1589})
    db.session.refresh(cust)
    assert _registered_subscribers_used(cust, fallback=1) == 1589


def test_blank_inventory_does_not_regress_stored_value(app, client):
    cust, inst, _ = _seed_customer()
    _heartbeat(client, {"nas_count": 4})
    db.session.refresh(inst)
    assert inst.reported_nas_count == 4
    # A later heartbeat with no inventory must leave the good value untouched.
    r = client.post(HEARTBEAT_URL, json={
        "license_key": LICENSE_KEY, "server_fingerprint": "fp-test",
    })
    assert r.status_code == 200
    db.session.refresh(inst)
    assert inst.reported_nas_count == 4
