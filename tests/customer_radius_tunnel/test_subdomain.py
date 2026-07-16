"""Per-customer subdomain (§11) + panel-enforced speed (§12).

Pins the contracts from ``docs/CUSTOMER_RADIUS_TUNNEL_DESIGN.md``:

  * Subdomain auto-assignment is deterministic + idempotent; FQDN
    composes against the zone-base Setting.
  * Default speed is the LOCKED floor (5 Mbps each direction); a
    customer with no unlock and no plan unlock gets 5M/5M.
  * Per-customer override beats per-plan override beats LOCKED floor.
  * The §9 type-policy ceiling binds — an unlock above the per-type cap
    is clamped to the policy value.
  * ``radius_transport`` ignores the customer unlock entirely (the §9
    policy is the only signal).
  * The RADIUS attribute string goes through the SAME shared
    ``rate_limit_string`` formatter the per-direction sibling rolls out.
"""
from __future__ import annotations

import pytest

from app.extensions import db
from app.models import Customer, License, Plan
from app.services.customer_subdomain import (
    DEFAULT_ZONE_BASE,
    assign_subdomain,
    customer_fqdn,
    get_zone_base,
    set_zone_base,
)


# ════════════════════════════════════════════════════════════════════════
# Helpers
# ════════════════════════════════════════════════════════════════════════
def _make_customer(*, customer_id: int | None = None) -> Customer:
    c = Customer(
        company_name=f"Test {customer_id or 'n'}",
        email=f"c{customer_id or 'n'}@example.com",
        phone="",
    )
    db.session.add(c)
    db.session.flush()
    if customer_id is not None:
        c.id = customer_id
        db.session.flush()
    return c


_PLAN_SEQ = [0]


def _make_plan(*, slug: str, unlock_mbps: int = 0) -> Plan:
    """Mint a plan with a slug guaranteed unique from seed_defaults rows
    (which already include 'pro', 'basic', etc.). We prefix
    deterministically so each test gets its own row."""
    _PLAN_SEQ[0] += 1
    unique_slug = f"crt-{slug}-{_PLAN_SEQ[0]}"
    p = Plan(name=unique_slug, slug=unique_slug, monthly_price=0,
             speed_unlock_mbps=unlock_mbps)
    db.session.add(p)
    db.session.flush()
    return p


def _attach_license(customer: Customer, plan: Plan) -> License:
    from datetime import datetime, timedelta
    lic = License(
        customer_id=customer.id, plan_id=plan.id,
        license_key=f"HBR-TEST-{customer.id}-{plan.id}",
        status="active",
        starts_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(days=30),
    )
    db.session.add(lic); db.session.commit()
    return lic


# ════════════════════════════════════════════════════════════════════════
# §11 — subdomain
# ════════════════════════════════════════════════════════════════════════
class TestSubdomain:
    def test_default_zone_base(self, app):
        assert get_zone_base() == DEFAULT_ZONE_BASE
        assert DEFAULT_ZONE_BASE == "hoberadius.com"

    def test_assign_subdomain_idempotent(self, app):
        c = _make_customer(customer_id=5)
        assigned = assign_subdomain(c)
        assert assigned == "client5"
        # Second call must NOT re-mint
        again = assign_subdomain(c)
        assert again == "client5"
        # Operator-set vanity name is preserved.
        c.subdomain = "vip-customer"
        db.session.commit()
        assert assign_subdomain(c) == "vip-customer"

    def test_customer_fqdn_default_composition(self, app):
        c = _make_customer(customer_id=7)
        # Without an explicit assign call we still get the deterministic
        # value (read paths don't write).
        assert customer_fqdn(c) == "client7.hoberadius.com"

    def test_customer_fqdn_after_zone_change(self, app):
        c = _make_customer(customer_id=5)
        assign_subdomain(c)
        set_zone_base("staging.hoberadius.com")
        assert customer_fqdn(c) == "client5.staging.hoberadius.com"

    def test_zone_base_rejects_invalid(self, app):
        with pytest.raises(ValueError):
            set_zone_base("")
        with pytest.raises(ValueError):
            set_zone_base("bad space.com")
        with pytest.raises(ValueError):
            set_zone_base("under_score.com")  # underscores aren't valid DNS labels


