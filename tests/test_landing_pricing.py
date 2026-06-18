"""Public-landing «الباقات والأسعار» pricing section — CMS/editable-data driven.

The landing must show the six packages + the free-trial entry card + the
duration-discount badges, all pulled LIVE from the editable packages/discounts
data (so admin edits reflect on hoberadius.com), plus the nav link/anchor and
the renew-CTA pricing URL exposed in the capacity contract.
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from app.extensions import db
from app.models import Customer, License, Plan, utcnow
from app.services import subscription_pricing as sp

HTTPS = {"base_url": "https://license-panel.test"}


def _body(client):
    r = client.get("/")
    assert r.status_code == 200
    return r.get_data(as_text=True)


# ── the section renders from the editable data ───────────────────────────────
def test_landing_shows_six_packages_and_trial(app, client):
    body = _body(client)
    assert 'id="pricing"' in body                     # the section anchor
    assert 'href="#pricing"' in body                  # nav link
    for name in ("حزمة الكافيهات", "حزمة البداية", "حزمة الشبكات",
                 "حزمة الكبار", "حزمة الشركات", "حزمة لا محدودة"):
        assert name in body, f"missing package {name}"
    assert "العرض المجاني" in body                     # trial entry card
    # concurrent-online framing
    assert "اتصال متزامن" in body


def test_landing_shows_discount_badges(app, client):
    body = _body(client)
    # default tiers 10/15/20 % render as badges
    assert "−10%" in body and "−15%" in body and "−20%" in body


def test_landing_pricing_reflects_admin_edits(app, client):
    """CMS-managed: editing a package price + a discount tier shows on the landing."""
    with app.app_context():
        plan = Plan.query.filter_by(slug="pkg_cafes").one()
        plan.monthly_price = 13           # owner edits the price
        db.session.commit()
        sp.set_discount_tiers([{"months": 12, "percent": 30, "enabled": True}])
        db.session.commit()
    body = _body(client)
    assert "13$" in body                  # the edited price
    assert "−30%" in body                 # the edited discount badge
    # the removed default tiers no longer show
    assert "−10%" not in body


# ── the renew-CTA pricing URL ────────────────────────────────────────────────
def test_pricing_route_redirects_to_anchor(app, client):
    r = client.get("/pricing")
    assert r.status_code in (301, 302)
    assert r.headers["Location"].endswith("#pricing")


def test_capacity_contract_exposes_pricing_url(app, client):
    with app.app_context():
        plan = Plan.query.filter_by(slug="pro").one()
        c = Customer(company_name="PriceCo", email="price@x.com", status="active")
        db.session.add(c)
        db.session.flush()
        lic = License(customer_id=c.id, plan_id=plan.id, license_key="HBR-PRICING-URL",
                      status="active", starts_at=utcnow() - timedelta(days=1),
                      expires_at=utcnow() + timedelta(days=365),
                      grace_until=utcnow() + timedelta(days=372))
        db.session.add(lic)
        db.session.commit()
    data = client.post("/api/integration/hoberadius/capacity-contract",
                       json={"license_key": "HBR-PRICING-URL"}, **HTTPS).get_json()
    assert "pricing_url" in data
    assert data["pricing_url"].endswith("/pricing") or "#pricing" in data["pricing_url"]
