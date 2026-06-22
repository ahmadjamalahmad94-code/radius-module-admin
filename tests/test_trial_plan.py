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
        # free-on-us, NO caps → free_unlimited
        for free in ("reports", "customer_portal", "communications", "audit_logs",
                     "loop_detection", "vouchers", "accounting"):
            assert trial_tier_for(free) == "free_unlimited", free
        # free-on-us WITH caps → free_limited (caps respected). Includes whatsapp
        # (BYO number, pays Meta directly) and the router/network limit services.
        for capped in ("cards", "routers", "nas", "ip_pools", "whatsapp_gateway",
                       "device_health", "distributors", "subscribers"):
            assert trial_tier_for(capped) == "free_limited", capped
        # exactly the paid keys — «تغيير عنوان الإنترنت» is ONE merged key
        # (ip_change_vpn); public_ip_change is no longer a separate paid card.
        assert TRIAL_PAID_SERVICES == frozenset({
            "ip_change_vpn", "remote_support",
            "remote_health_fix", "multi_tenant"})
        assert "public_ip_change" not in TRIAL_PAID_SERVICES
        assert "whatsapp_gateway" not in TRIAL_PAID_SERVICES


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
        # a free-on-us no-cap service: free_unlimited + enabled
        assert ents["reports"].config.get("tier") == "free_unlimited" and ents["reports"].enabled is True
        # whatsapp: FREE (BYO + pays Meta) — free_limited with its message/template caps
        wa = ents["whatsapp_gateway"]
        assert wa.config.get("tier") == "free_limited" and wa.enabled is True
        assert wa.limits.get("max_messages_monthly") and wa.limits.get("max_templates")
        # router/network limit services free_limited with caps
        assert ents["routers"].config.get("tier") == "free_limited" and ents["routers"].limits.get("max_total")
        assert ents["device_health"].config.get("tier") == "free_limited" and ents["device_health"].limits.get("max_devices")
        assert ents["loop_detection"].config.get("tier") == "free_unlimited" and ents["loop_detection"].enabled is True
        # a paid service: paid + OFF + NOT suspended (→ locked-with-«طلب تفعيل»)
        vpn = ents["ip_change_vpn"]
        assert vpn.config.get("tier") == "paid"
        assert vpn.enabled is False and vpn.status != "suspended"


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
        # free → enabled (cards has caps → free_limited; reports no caps → free_unlimited)
        assert svc["cards"]["enabled"] is True and svc["cards"]["tier"] == "free_limited"
        assert svc["reports"]["enabled"] is True and svc["reports"]["tier"] == "free_unlimited"
        # whatsapp FREE (BYO) → enabled, free_limited with caps
        assert svc["whatsapp_gateway"]["enabled"] is True
        assert svc["whatsapp_gateway"]["tier"] == "free_limited"
        assert svc["whatsapp_gateway"]["limits"]["max_messages_monthly"]
        # loop-detection + device-health free network services present + enabled
        assert svc["loop_detection"]["enabled"] is True
        assert svc["device_health"]["enabled"] is True and svc["device_health"]["limits"]["max_devices"]
        # subscribers → enabled, free_limited, 100 cap
        assert svc["subscribers"]["enabled"] is True
        assert svc["subscribers"]["limits"]["max_active"] == 100
        # paid (IP-change) → OFF with tier=paid, NOT suspended (radius shows «طلب تفعيل», not 403)
        vpn = svc["ip_change_vpn"]
        assert vpn["enabled"] is False and vpn["status"] != "suspended"

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
        assert ents["whatsapp_gateway"].config.get("tier") == "free_limited"  # BYO, free
        assert ents["ip_change_vpn"].config.get("tier") == "paid"


def test_admin_apply_trial_requires_login(client):
    r = client.post("/admin/customers/1/apply-trial")
    assert r.status_code in (301, 302) and "/login" in r.headers.get("Location", "")
