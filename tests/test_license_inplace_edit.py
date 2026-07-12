"""In-place license edit (same key): change plan, extend by days / set expiry,
recompute grace, set max_fingerprints & status — without minting a new key.
"""
from __future__ import annotations

from datetime import timedelta

from app.extensions import db
from app.models import Customer, License, Plan, utcnow
from app.services.license_service import generate_license_key


def _login(client):
    return client.post("/login", data={"username": "admin", "password": "admin12345"})


def _customer_with_license() -> License:
    customer = Customer(company_name="Edit Co", contact_name="Owner", email="e@example.com")
    plan = Plan.query.filter_by(slug="pro").one()
    now = utcnow()
    db.session.add(customer)
    db.session.flush()
    lic = License(
        customer_id=customer.id, plan_id=plan.id, license_key=generate_license_key(),
        status="active", starts_at=now - timedelta(days=1),
        expires_at=now + timedelta(days=10), grace_until=now + timedelta(days=17),
        max_fingerprints=3,
    )
    db.session.add(lic)
    db.session.commit()
    return lic


def test_edit_changes_plan_extends_days_and_keeps_key(client):
    _login(client)
    lic = _customer_with_license()
    lic_id, key, old_expiry = lic.id, lic.license_key, lic.expires_at
    other = Plan.query.filter(Plan.id != lic.plan_id).first()

    # form renders
    r = client.get(f"/admin/licenses/{lic_id}/edit")
    assert r.status_code == 200
    assert key in r.get_data(as_text=True)

    # change plan + add 45 days + bump fingerprints; grace auto-recomputed
    r = client.post(f"/admin/licenses/{lic_id}/edit", data={
        "plan_id": str(other.id),
        "add_days": "45",
        "auto_grace": "1",
        "max_fingerprints": "5",
        "status": "active",
        "notes": "renewed via edit",
    })
    assert r.status_code in (302, 303)

    u = db.session.get(License, lic_id)
    assert u.license_key == key                       # SAME key preserved
    assert u.plan_id == other.id                      # plan (offer) changed
    assert u.max_fingerprints == 5
    assert (u.expires_at - old_expiry).days == 45     # extended exactly 45 days
    assert u.grace_until > u.expires_at               # grace trails new expiry
    assert u.renewals.count() >= 1                    # logged in سجل التجديدات


def test_edit_sets_explicit_expiry_date(client):
    _login(client)
    lic = _customer_with_license()
    lic_id = lic.id
    target = (utcnow() + timedelta(days=120)).replace(microsecond=0)

    r = client.post(f"/admin/licenses/{lic_id}/edit", data={
        "plan_id": str(lic.plan_id),
        "expires_at": target.strftime("%Y-%m-%dT%H:%M"),
        "auto_grace": "1",
        "max_fingerprints": "3",
        "status": "trial",
    })
    assert r.status_code in (302, 303)

    u = db.session.get(License, lic_id)
    assert u.status == "trial"
    assert abs((u.expires_at - target).total_seconds()) < 120   # honored the set date


def test_extend_preset_one_month(client):
    _login(client)
    lic = _customer_with_license()
    lic_id, old_expiry = lic.id, lic.expires_at
    r = client.post(f"/admin/licenses/{lic_id}/edit", data={
        "plan_id": str(lic.plan_id), "auto_grace": "1",
        "max_fingerprints": "3", "status": "active", "extend_preset": "1m",
    })
    assert r.status_code in (302, 303)
    u = db.session.get(License, lic_id)
    assert 28 <= (u.expires_at - old_expiry).days <= 31        # one calendar month


def test_extend_preset_one_year(client):
    _login(client)
    lic = _customer_with_license()
    lic_id, old_expiry = lic.id, lic.expires_at
    r = client.post(f"/admin/licenses/{lic_id}/edit", data={
        "plan_id": str(lic.plan_id), "auto_grace": "1",
        "max_fingerprints": "3", "status": "active", "extend_preset": "1y",
    })
    assert r.status_code in (302, 303)
    u = db.session.get(License, lic_id)
    assert 360 <= (u.expires_at - old_expiry).days <= 366      # ~one year


def test_extend_months_and_days_combine(client):
    _login(client)
    lic = _customer_with_license()
    lic_id, old_expiry = lic.id, lic.expires_at
    r = client.post(f"/admin/licenses/{lic_id}/edit", data={
        "plan_id": str(lic.plan_id), "auto_grace": "1",
        "max_fingerprints": "3", "status": "active",
        "extend_months": "3", "add_days": "20",
    })
    assert r.status_code in (302, 303)
    u = db.session.get(License, lic_id)
    assert 108 <= (u.expires_at - old_expiry).days <= 113      # 3 months + 20 days
