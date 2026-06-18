"""«العرض المجاني» (Free Trial) plan + preset.

Verifies the trial plan seeds, the free/paid classification, that assignment
creates a 14-day license + the per-service tier set, and that it flows into the
capacity contract: free services enabled, paid services off (tier=paid, NOT
suspended → the radius shows them locked-with-upgrade), subscribers capped at
100 active.
"""
from __future__ import annotations

import pytest

from app.extensions import db
from app.models import Admin, Customer, License, Plan
from app.services.customer_control import (
    build_runtime_contract_for_license, customer_service_map,
)
from app.services.trial_plan import (
    TRIAL_ACTIVE_SUBSCRIBERS_CAP, TRIAL_DURATION_DAYS, TRIAL_PAID_SERVICES,
    TRIAL_PLAN_SLUG, apply_trial_to_customer, ensure_trial_plan, trial_tier_for,
)


def _customer(name="تجريبي شركة"):
    c = Customer(company_name=name, email="trial@example.com", status="active")
    db.session.add(c)
    db.session.commit()
    return c


# ── plan seed ─────────────────────────────────────────────────────────────--
def test_trial_plan_seeded_and_idempotent(app):
    with app.app_context():
        p1 = Plan.query.filter_by(slug=TRIAL_PLAN_SLUG).one()  # seeded by seed_defaults
        assert p1.max_users == TRIAL_ACTIVE_SUBSCRIBERS_CAP
        assert float(p1.monthly_price) == 0.0
        p2 = ensure_trial_plan()
        assert p2.id == p1.id  # idempotent — no duplicate
        assert Plan.query.filter_by(slug=TRIAL_PLAN_SLUG).count() == 1


# ── classification ───────────────────────────────────────────────────────────
def test_trial_tier_classification(app):
    with app.app_context():
        assert trial_tier_for("subscribers") == "free_limited"
        for paid in TRIAL_PAID_SERVICES:
            assert trial_tier_for(paid) == "paid", paid
        # a representative sample of free-on-us services
        for free in ("cards", "reports", "routers", "backups", "customer_portal",
                     "finance_center", "store" if False else "card_marketplace",
                     "audit_logs", "communications", "vouchers", "distributors"):
            assert trial_tier_for(free) == "free_unlimited", free
        # exactly the six paid keys
        assert TRIAL_PAID_SERVICES == frozenset({
            "ip_change_vpn", "public_ip_change", "remote_support",
            "remote_health_fix", "whatsapp_gateway", "multi_tenant"})


# ── assignment: 14-day license ───────────────────────────────────────────────
def test_apply_creates_14day_active_license(app):
    with app.app_context():
        c = _customer()
        res = apply_trial_to_customer(c)
        lic = res["license"]
        assert lic.plan.slug == TRIAL_PLAN_SLUG
        assert lic.status == "active" and lic.license_key
        span_days = (lic.expires_at - lic.starts_at).days
        assert span_days == TRIAL_DURATION_DAYS == 14
        # idempotent — re-applying reuses the same license, refreshes the term.
        first_id = lic.id
        res2 = apply_trial_to_customer(c)
        assert res2["license"].id == first_id
        assert License.query.filter_by(customer_id=c.id, plan_id=res["plan"].id).count() == 1


# ── assignment: entitlement tiers ────────────────────────────────────────────
def test_apply_sets_service_tiers(app):
    with app.app_context():
        c = _customer()
        apply_trial_to_customer(c)
        ents = customer_service_map(c)
        # subscribers: free_limited + 100 cap (active + total)
        subs = ents["subscribers"]
        assert subs.config.get("tier") == "free_limited" and subs.enabled is True
        assert subs.limits.get("max_active") == 100 and subs.limits.get("max_total") == 100
        # a free-on-us service: free_unlimited + enabled
        assert ents["cards"].config.get("tier") == "free_unlimited" and ents["cards"].enabled is True
        # a paid service: paid + OFF + NOT suspended (→ locked-with-upgrade, not hard stop)
        wa = ents["whatsapp_gateway"]
        assert wa.config.get("tier") == "paid"
        assert wa.enabled is False and wa.status != "suspended"


# ── flows into the capacity contract ─────────────────────────────────────────
def test_trial_contract_emission(app):
    with app.app_context():
        c = _customer()
        lic = apply_trial_to_customer(c)["license"]
        ct = build_runtime_contract_for_license(lic, license_active=True, status="active")

        # license block: active 14-day
        assert ct["license"]["active"] is True and ct["license"]["activated"] is True
        assert ct["license"]["expires_at"]

        svc = ct["services"]
        # free → enabled
        assert svc["cards"]["enabled"] is True and svc["cards"]["tier"] == "free_unlimited"
        assert svc["reports"]["enabled"] is True
        # subscribers → enabled, free_limited, 100 cap
        assert svc["subscribers"]["enabled"] is True
        assert svc["subscribers"]["limits"]["max_active"] == 100
        # paid → OFF with tier=paid, and NOT suspended (radius shows upgrade, not 403)
        wa = svc["whatsapp_gateway"]
        assert wa["enabled"] is False and wa["tier"] == "paid" and wa["status"] != "suspended"

        # top-level limits carry the subscribers cap
        assert ct["limits"]["subscribers"]["max_total"] == 100
        assert ct["limits"]["subscribers"]["max_active"] == 100


def test_trial_sections_active_no_hard_disable(app):
    """Every radius section has at least one free service under the trial, so no
    provider_grants gate is hard-`disabled` (paid sub-features lock per-service,
    not by hiding the whole section)."""
    with app.app_context():
        c = _customer()
        lic = apply_trial_to_customer(c)["license"]
        grants = build_runtime_contract_for_license(lic, license_active=True, status="active")["provider_grants"]
        assert all(g["status"] != "disabled" for g in grants.values())
        # subscribers + communications sections are active (free capabilities)
        assert grants["subscribers"]["status"] == "active"
        assert grants["communications"]["status"] == "active"  # free comms; whatsapp locked per-service


# ── admin assign route ───────────────────────────────────────────────────────
def test_admin_apply_trial_route(app, client):
    with app.app_context():
        c = _customer()
        cid = c.id
        admin = Admin.query.first()
    with client.session_transaction() as s:
        s["admin_id"] = admin.id
    res = client.post(f"/admin/customers/{cid}/apply-trial", follow_redirects=True)
    assert res.status_code == 200
    with app.app_context():
        c = db.session.get(Customer, cid)
        lic = License.query.filter_by(customer_id=cid).first()
        assert lic is not None and lic.plan.slug == TRIAL_PLAN_SLUG
        ents = customer_service_map(c)
        assert ents["subscribers"].config.get("tier") == "free_limited"
        assert ents["whatsapp_gateway"].config.get("tier") == "paid"


def test_admin_apply_trial_requires_login(client):
    r = client.post("/admin/customers/1/apply-trial")
    assert r.status_code in (301, 302) and "/login" in r.headers.get("Location", "")
