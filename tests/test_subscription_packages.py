"""Commercial subscription packages + configurable duration-discount engine."""
from __future__ import annotations

import pytest

from app.extensions import db
from app.models import Admin, Customer, License, Plan
from app.services import subscription_pricing as sp
from app.services.customer_control import build_runtime_contract_for_license


def _admin(client):
    a = Admin.query.first()
    with client.session_transaction() as s:
        s["admin_id"] = a.id


# ── packages ─────────────────────────────────────────────────────────────────
def test_six_packages_seeded(app):
    with app.app_context():
        pkgs = sp.subscription_packages()
        by_slug = {p.slug: p for p in pkgs}
        assert by_slug["pkg_cafes"].max_users == 50 and float(by_slug["pkg_cafes"].monthly_price) == 10
        assert by_slug["pkg_starter"].max_users == 100 and float(by_slug["pkg_starter"].monthly_price) == 17
        assert by_slug["pkg_networks"].max_users == 250 and float(by_slug["pkg_networks"].monthly_price) == 25
        assert by_slug["pkg_large"].max_users == 500 and float(by_slug["pkg_large"].monthly_price) == 35
        assert by_slug["pkg_companies"].max_users == 1000 and float(by_slug["pkg_companies"].monthly_price) == 50
        assert by_slug["pkg_unlimited"].max_users == 0 and float(by_slug["pkg_unlimited"].monthly_price) == 100
        # unlimited sorts last
        assert pkgs[-1].slug == "pkg_unlimited"


def test_ensure_idempotent_no_clobber(app):
    with app.app_context():
        p = Plan.query.filter_by(slug="pkg_cafes").one()
        p.monthly_price = 12  # owner edits price
        db.session.commit()
        sp.ensure_subscription_packages()  # re-run
        assert float(Plan.query.filter_by(slug="pkg_cafes").one().monthly_price) == 12  # not clobbered
        assert Plan.query.filter_by(slug="pkg_cafes").count() == 1


# ── discount engine ──────────────────────────────────────────────────────────
def test_default_discounts_and_quote(app):
    with app.app_context():
        assert sp.discount_percent_for(3) == 10
        assert sp.discount_percent_for(6) == 15
        assert sp.discount_percent_for(12) == 20
        assert sp.discount_percent_for(5) == 0  # no tier
        q = sp.quote(50, 12)
        assert q.subtotal == 600 and q.total == 480 and q.percent == 20
        assert q.effective_monthly == 40 and q.savings == 120


def test_discounts_are_editable(app):
    with app.app_context():
        sp.set_discount_tiers([
            {"months": 3, "percent": 12, "enabled": True},
            {"months": 6, "percent": 18, "enabled": False},   # disabled
            {"months": 12, "percent": 25, "enabled": True},
        ])
        db.session.commit()
        assert sp.discount_percent_for(3) == 12
        assert sp.discount_percent_for(6) == 0     # disabled → no discount
        assert sp.discount_percent_for(12) == 25
        assert sp.quote(100, 12).total == 900      # 1200 × 0.75


def test_discount_validation(app):
    with app.app_context():
        with pytest.raises(sp.PricingError):
            sp.set_discount_tiers([{"months": 0, "percent": 10}])
        with pytest.raises(sp.PricingError):
            sp.set_discount_tiers([{"months": 3, "percent": 150}])


# ── capacity flows to the contract as subscribers.max_active ─────────────────
def test_package_capacity_is_max_active_in_contract(app, client):
    _admin(client)
    with app.app_context():
        c = Customer(company_name="Co", email="co@x.com", status="active")
        db.session.add(c)
        db.session.commit()
        cid = c.id
        plan = Plan.query.filter_by(slug="pkg_networks").one()  # 250 cap
        pid = plan.id
    client.post(f"/admin/customers/{cid}/assign-package",
                data={"plan_id": pid, "months": 6}, follow_redirects=False)
    with app.app_context():
        lic = License.query.filter_by(customer_id=cid).first()
        assert lic.plan.slug == "pkg_networks"
        # 6-month term
        assert (lic.expires_at - lic.starts_at).days >= 179
        ct = build_runtime_contract_for_license(lic, license_active=True, status="active")
        # canonical instance-wide concurrent-online ceiling
        assert ct["limits"]["active_online"]["max"] == 250
        assert ct["limits"]["active_online"]["scope"] == "instance"
        assert ct["limits"]["active_online"]["counts"] == "all_session_types"
        # back-compat mirror
        assert ct["limits"]["subscribers"]["max_active"] == 250
        assert ct["limits"]["subscribers"]["max_total"] == 250


def test_unlimited_package_capacity_zero(app):
    with app.app_context():
        from datetime import timedelta
        from app.models import utcnow
        c = Customer(company_name="Big", email="big@x.com", status="active")
        db.session.add(c)
        db.session.flush()
        plan = Plan.query.filter_by(slug="pkg_unlimited").one()
        lic = License(customer_id=c.id, plan_id=plan.id, license_key="LK-UNL", status="active",
                      starts_at=utcnow() - timedelta(days=1), expires_at=utcnow() + timedelta(days=30),
                      grace_until=utcnow() + timedelta(days=37))
        db.session.add(lic)
        db.session.commit()
        ct = build_runtime_contract_for_license(lic, license_active=True, status="active")
        assert ct["limits"]["active_online"]["max"] == 0       # 0 = unlimited concurrent online
        assert ct["limits"]["subscribers"]["max_active"] == 0  # back-compat mirror


# ── trial concurrent-online ceiling ──────────────────────────────────────────
def test_trial_emits_concurrent_online_cap(app):
    with app.app_context():
        from app.services.trial_plan import apply_trial_to_customer
        c = Customer(company_name="TrialCo", email="trialco@x.com", status="active")
        db.session.add(c)
        db.session.commit()
        lic = apply_trial_to_customer(c)["license"]
        ct = build_runtime_contract_for_license(lic, license_active=True, status="active")
        assert ct["limits"]["active_online"]["max"] == 100  # 100 concurrent online


# ── pages render ─────────────────────────────────────────────────────────────
def test_pricing_and_discount_pages_render(app, client):
    _admin(client)
    assert client.get("/admin/packages").status_code == 200
    assert client.get("/admin/discounts").status_code == 200


def test_discount_save_route(app, client):
    _admin(client)
    client.post("/admin/discounts", data={
        "months": ["3", "12"], "percent": ["8", "30"], "enabled_0": "on", "enabled_1": "on",
    }, follow_redirects=True)
    with app.app_context():
        assert sp.discount_percent_for(3) == 8
        assert sp.discount_percent_for(12) == 30
