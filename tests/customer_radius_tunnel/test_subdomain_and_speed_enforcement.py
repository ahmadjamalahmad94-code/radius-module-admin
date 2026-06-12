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
from app.services.bandwidth_policy import set_policy, set_symmetric
from app.services.customer_speed_enforcement import (
    LOCKED_DEFAULT_MBPS,
    mikrotik_rate_limit_for,
    resolve_speed_for,
    set_customer_unlock,
    set_plan_unlock,
)
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


# ════════════════════════════════════════════════════════════════════════
# §12 — speed enforcement (the monetization control)
# ════════════════════════════════════════════════════════════════════════
class TestSpeedEnforcementDefault:
    def test_unknown_type_raises(self, app):
        c = _make_customer(customer_id=10)
        with pytest.raises(ValueError):
            resolve_speed_for(c, "vpn_telnet")

    def test_locked_default_is_5_each_way(self, app):
        c = _make_customer(customer_id=11)
        eff = resolve_speed_for(c, "vpn_sstp")
        assert eff.download_mbps == LOCKED_DEFAULT_MBPS == 5
        assert eff.upload_mbps == 5
        assert eff.source == "locked"
        assert eff.rate_limit() == "5M/5M"

    def test_mikrotik_rate_limit_for_returns_locked_default(self, app):
        c = _make_customer(customer_id=12)
        assert mikrotik_rate_limit_for(c, "vpn_sstp") == "5M/5M"


class TestSpeedEnforcementUnlock:
    def test_customer_override_beats_plan_and_floor(self, app):
        plan = _make_plan(slug="basic", unlock_mbps=20)
        c = _make_customer(customer_id=20)
        _attach_license(c, plan)
        set_customer_unlock(c, 50)
        eff = resolve_speed_for(c, "vpn_sstp")
        assert eff.download_mbps == 50 and eff.upload_mbps == 50
        assert eff.source == "customer"

    def test_plan_unlock_applies_when_customer_zero(self, app):
        plan = _make_plan(slug="pro", unlock_mbps=50)
        c = _make_customer(customer_id=21)
        _attach_license(c, plan)
        eff = resolve_speed_for(c, "vpn_sstp")
        assert eff.download_mbps == 50
        assert eff.source == "plan"

    def test_unlock_clamped_by_type_ceiling(self, app):
        """The §9 ceiling binds even a generous unlock — fat-finger guard."""
        c = _make_customer(customer_id=22)
        set_customer_unlock(c, 500)
        # vpn_pptp defaults to 50/50 (§9.1). 500 clamps to 50.
        eff = resolve_speed_for(c, "vpn_pptp")
        assert eff.download_mbps == 50 and eff.upload_mbps == 50
        assert eff.source == "type_policy_ceiling"

    def test_unlock_below_ceiling_passes_through(self, app):
        c = _make_customer(customer_id=23)
        set_customer_unlock(c, 50)
        eff = resolve_speed_for(c, "vpn_sstp")   # default 100/100
        assert eff.download_mbps == 50 and eff.upload_mbps == 50
        assert eff.source == "customer"

    def test_radius_transport_ignores_customer_unlock(self, app):
        """The unlock is about user-traffic speed; radius_transport
        carries only auth/acct/CoA — always the §9 policy cap."""
        c = _make_customer(customer_id=24)
        set_customer_unlock(c, 100)
        eff = resolve_speed_for(c, "radius_transport")
        assert eff.download_mbps == 5
        assert eff.upload_mbps == 5
        assert eff.source == "type_policy_ceiling"

    def test_type_policy_change_propagates(self, app):
        """Owner raises vpn_sstp policy to 200; an unlocked-to-150
        customer now gets 150M/150M (still under the ceiling)."""
        set_symmetric("vpn_sstp", mbps=200)
        c = _make_customer(customer_id=25)
        set_customer_unlock(c, 150)
        eff = resolve_speed_for(c, "vpn_sstp")
        assert eff.download_mbps == 150
        assert eff.source == "customer"

    def test_asymmetric_type_policy_clamps_each_direction(self, app):
        """Asymmetric policy applies its ceiling independently per
        direction — matches what the per-direction sibling expects."""
        set_policy("vpn_ipsec", download_mbps=80, upload_mbps=40)
        c = _make_customer(customer_id=26)
        set_customer_unlock(c, 100)
        eff = resolve_speed_for(c, "vpn_ipsec")
        assert eff.download_mbps == 80
        assert eff.upload_mbps == 40
        assert eff.source == "type_policy_ceiling"
        # Wire shape: "<upload>M/<download>M".
        assert eff.rate_limit() == "40M/80M"


class TestSpeedEnforcementSettersValidate:
    def test_negative_rejected(self, app):
        c = _make_customer(customer_id=30)
        with pytest.raises(ValueError):
            set_customer_unlock(c, -1)
        plan = _make_plan(slug="x")
        with pytest.raises(ValueError):
            set_plan_unlock(plan, -1)

    def test_unrealistic_rejected(self, app):
        c = _make_customer(customer_id=31)
        with pytest.raises(ValueError):
            set_customer_unlock(c, 100_000)

    def test_zero_clears_to_floor(self, app):
        """Setting customer unlock to 0 falls back to plan/floor."""
        plan = _make_plan(slug="tier", unlock_mbps=10)
        c = _make_customer(customer_id=32)
        _attach_license(c, plan)
        set_customer_unlock(c, 50)
        assert resolve_speed_for(c, "vpn_sstp").download_mbps == 50
        # Clear → falls back to plan unlock.
        set_customer_unlock(c, 0)
        assert resolve_speed_for(c, "vpn_sstp").download_mbps == 10
        # Clear plan too → locked floor.
        set_plan_unlock(plan, 0)
        assert resolve_speed_for(c, "vpn_sstp").download_mbps == LOCKED_DEFAULT_MBPS
