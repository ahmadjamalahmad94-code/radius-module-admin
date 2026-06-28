"""Invariant: a set-up customer file (active, or with a license) always has an
active portal user — provisioned at creation/approval and backfilled on deploy.
This is what makes radius «ربط جوجل درايف» → portal-SSO → /portal work with no
manual step.
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from app.extensions import db
from app.models import Admin, Customer, CustomerUser, License, Plan, utcnow
from app.services.customer_control import backfill_portal_users, ensure_active_portal_user
from app.services.license_service import generate_license_key


def _login_super(client):
    admin = Admin.query.first()
    with client.session_transaction() as s:
        s["admin_id"] = admin.id
        s["is_super_admin"] = True
    return client


def _customer(company="Co", email="a@b.test", status="active") -> Customer:
    c = Customer(company_name=company, contact_name="Owner", email=email, status=status)
    db.session.add(c)
    db.session.commit()
    return c


def _license(customer) -> License:
    plan = Plan.query.filter_by(slug="pro").one()
    now = utcnow()
    lic = License(customer_id=customer.id, plan_id=plan.id, license_key=generate_license_key(),
                  status="active", starts_at=now - timedelta(days=1), expires_at=now + timedelta(days=30),
                  grace_until=now + timedelta(days=37), max_fingerprints=3)
    db.session.add(lic)
    db.session.commit()
    return lic


def _active_users(cid):
    return CustomerUser.query.filter_by(customer_id=cid, active=True).all()


# ── helper ───────────────────────────────────────────────────────────────────
def test_ensure_creates_then_is_idempotent(app):
    with app.app_context():
        c = _customer()
        u1 = ensure_active_portal_user(c); db.session.commit()
        u2 = ensure_active_portal_user(c); db.session.commit()
        assert u1.id == u2.id
        assert len(_active_users(c.id)) == 1
        assert u1.role_key == "owner" and u1.active is True


# ── creation chokepoint (admin) ──────────────────────────────────────────────
def test_admin_customer_create_provisions_portal_user(app, client):
    with app.app_context():
        _login_super(client)
        r = client.post("/admin/customers/new", data={
            "company_name": "Created Co", "email": "created@x.test", "phone": "+970590000001",
        }, follow_redirects=False)
        assert r.status_code in (301, 302)
        c = Customer.query.filter_by(company_name="Created Co").first()
        assert c is not None
        assert len(_active_users(c.id)) == 1


# ── approval chokepoint ──────────────────────────────────────────────────────
def test_customer_approve_guarantees_active_user(app, client):
    with app.app_context():
        c = _customer(status="pending")  # no users at all
        _login_super(client)
        r = client.post(f"/admin/customers/{c.id}/approve", follow_redirects=False)
        assert r.status_code in (301, 302)
        db.session.refresh(c)
        assert c.status == "active"
        assert len(_active_users(c.id)) == 1


# ── backfill (existing customers) ────────────────────────────────────────────
def test_backfill_provisions_active_and_licensed_customers(app):
    with app.app_context():
        active_no_user = _customer("Active Co", "active@x.test", status="active")
        licensed = _customer("Licensed Co", "lic@x.test", status="suspended")
        _license(licensed)  # suspended but has a license → in scope
        pending_signup = _customer("Pending Co", "pend@x.test", status="pending")  # no license → skip

        n = backfill_portal_users()
        assert n == 2
        assert len(_active_users(active_no_user.id)) == 1
        assert len(_active_users(licensed.id)) == 1
        assert len(_active_users(pending_signup.id)) == 0  # untouched (awaits approval)


def test_backfill_is_idempotent_and_skips_existing(app):
    with app.app_context():
        c = _customer("Has User", "hu@x.test", status="active")
        existing = CustomerUser(customer_id=c.id, username="existing", email="hu@x.test",
                                full_name="U", role_key="owner", active=True)
        existing.set_password("pw-123456")
        db.session.add(existing)
        db.session.commit()
        before_hash = existing.password_hash

        assert backfill_portal_users() == 0          # nothing to do
        assert backfill_portal_users() == 0          # still idempotent
        db.session.refresh(existing)
        assert existing.password_hash == before_hash  # never reset
        assert len(_active_users(c.id)) == 1
