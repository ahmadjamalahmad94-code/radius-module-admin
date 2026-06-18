"""«العرض المجاني» (Free Trial) plan + preset.

A reusable trial the owner assigns to a customer. It carries:
  * a **14-day** license term,
  * a **100 active-subscribers** cap,
  * a per-service tier set: almost everything FREE («مجانية مطلقة»), subscribers
    FREE-but-capped («مجانية محدودة» @ 100), and only genuinely-costly services
    PAID («مدفوعة» → reach the radius as ``locked_upgrade``, a visible upsell).

It reuses the existing Plan + License + CustomerServiceEntitlement + service-tier
machinery, so it FLOWS INTO the capacity contract with no contract-builder
changes: free entitlements serialize as enabled (the free-tier override), paid
ones stay off → ``provider_grants`` emits them as ``locked_upgrade``.

FINE-TUNING: the free/paid split is just two constants below — edit
``TRIAL_PAID_SERVICES`` (and ``TRIAL_CAPPED_SERVICES``) to reclassify. Everything
not listed paid is free.
"""
from __future__ import annotations

from datetime import timedelta
from typing import Any, Optional

from ..extensions import db
from ..models import Customer, License, Plan, utcnow
from .customer_control import (
    SERVICE_TIER_FREE_LIMITED,
    SERVICE_TIER_FREE_UNLIMITED,
    SERVICE_TIER_PAID,
    get_or_create_service_entitlement,
    service_catalog_items,
)
from .license_service import generate_license_key

# ── trial preset (edit these to fine-tune) ───────────────────────────────────
TRIAL_PLAN_SLUG = "trial"
TRIAL_PLAN_NAME = "العرض المجاني"
TRIAL_DURATION_DAYS = 14
#: 100 ACTIVE subscribers. The subscribers limit field is ``max_total`` today;
#: we ALSO emit ``max_active`` so the radius can enforce the active cap
#: explicitly (note: until a dedicated active-cap field exists, max_total
#: carries the same number).
TRIAL_ACTIVE_SUBSCRIBERS_CAP = 100

#: The ONLY services the trial leaves PAID (everything else is free). Edit here
#: to reclassify — owner-approved baseline.
TRIAL_PAID_SERVICES: frozenset[str] = frozenset({
    "ip_change_vpn",
    "public_ip_change",
    "remote_support",
    "remote_health_fix",
    "whatsapp_gateway",   # customer pays Meta directly
    "multi_tenant",
})

#: Services that are FREE but quantity-capped under the trial (→ free_limited).
TRIAL_CAPPED_SERVICES: dict[str, dict[str, int]] = {
    "subscribers": {
        "max_total": TRIAL_ACTIVE_SUBSCRIBERS_CAP,
        "max_active": TRIAL_ACTIVE_SUBSCRIBERS_CAP,
    },
}


def trial_tier_for(service_key: str) -> str:
    """The trial tier for a service: paid set → paid; capped set → free_limited;
    everything else → free_unlimited (free on us)."""
    if service_key in TRIAL_PAID_SERVICES:
        return SERVICE_TIER_PAID
    if service_key in TRIAL_CAPPED_SERVICES:
        return SERVICE_TIER_FREE_LIMITED
    return SERVICE_TIER_FREE_UNLIMITED


def ensure_trial_plan() -> Plan:
    """Idempotently create the «العرض المجاني» Plan (slug ``trial``). Carries the
    100-subscriber cap; the 14-day term is applied per-license on assignment."""
    plan = Plan.query.filter_by(slug=TRIAL_PLAN_SLUG).first()
    if plan is None:
        plan = Plan(
            name=TRIAL_PLAN_NAME, slug=TRIAL_PLAN_SLUG,
            monthly_price=0, currency="USD",
            max_users=TRIAL_ACTIVE_SUBSCRIBERS_CAP,
            max_nas=2, max_admins=2, max_devices=5,
            status="active",
        )
        plan.features = {}  # per-service tiers come from entitlements, not features
        db.session.add(plan)
        db.session.flush()
    return plan


def apply_trial_to_customer(customer: Customer, *, days: int = TRIAL_DURATION_DAYS,
                            actor_admin_id: Optional[int] = None) -> dict[str, Any]:
    """Assign the free trial to ``customer``: a 14-day license on the trial plan
    + the per-service tier set. Idempotent — re-running refreshes the term and
    re-applies the tiers. Returns a summary dict.
    """
    plan = ensure_trial_plan()
    now = utcnow()
    expires = now + timedelta(days=int(days))

    # Reuse an existing trial license for this customer; else mint one. We never
    # touch a non-trial license — assigning a trial is explicit.
    lic = (License.query
           .filter_by(customer_id=customer.id, plan_id=plan.id)
           .order_by(License.id.desc()).first())
    if lic is None:
        lic = License(customer_id=customer.id, plan_id=plan.id,
                      license_key=generate_license_key(), status="active",
                      starts_at=now, expires_at=expires, grace_until=expires)
        db.session.add(lic)
    else:
        lic.status = "active"
        lic.starts_at = now
        lic.expires_at = expires
        lic.grace_until = expires
    db.session.flush()

    summary = {"free": 0, "free_limited": 0, "paid": 0}
    for item in service_catalog_items():
        key = item.service_key
        tier = trial_tier_for(key)
        ent = get_or_create_service_entitlement(customer, key)
        # Write the tier EXPLICITLY (not via the helper, which pops the default
        # "paid" to avoid clutter). The trial must pin paid services to paid as
        # an explicit per-customer override that wins over any catalog default —
        # otherwise a catalog whose default was flipped to free would silently
        # turn a paid trial service on.
        cfg = dict(ent.config or {})
        cfg["tier"] = tier
        ent.config = cfg
        ent.license_id = lic.id
        if tier == SERVICE_TIER_PAID:
            # off + not suspended → the contract emits this as locked_upgrade
            ent.enabled = False
            ent.status = "disabled"
            ent.limits = {}
            summary["paid"] += 1
        elif tier == SERVICE_TIER_FREE_LIMITED:
            ent.enabled = True
            ent.status = "active"
            ent.limits = dict(TRIAL_CAPPED_SERVICES.get(key, {}))
            summary["free_limited"] += 1
        else:  # free_unlimited
            ent.enabled = True
            ent.status = "active"
            ent.limits = {}
            summary["free"] += 1
        ent.updated_by_admin_id = actor_admin_id

    db.session.commit()
    return {
        "license": lic,
        "plan": plan,
        "license_key": lic.license_key,
        "expires_at": expires,
        "days": int(days),
        "active_subscribers_cap": TRIAL_ACTIVE_SUBSCRIBERS_CAP,
        "summary": summary,
    }


__all__ = [
    "TRIAL_PLAN_SLUG", "TRIAL_PLAN_NAME", "TRIAL_DURATION_DAYS",
    "TRIAL_ACTIVE_SUBSCRIBERS_CAP", "TRIAL_PAID_SERVICES", "TRIAL_CAPPED_SERVICES",
    "trial_tier_for", "ensure_trial_plan", "apply_trial_to_customer",
]
