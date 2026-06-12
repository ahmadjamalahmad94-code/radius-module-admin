"""Panel-enforced per-connection speed — design §12 (THE business model).

The subscriber is free to generate unlimited connections, but is NOT
free to set the speed: every Access-Accept the proxy emits carries a
``Mikrotik-Rate-Limit`` attribute the panel computed centrally, so the
subscriber CANNOT override it on their MikroTik.

The default is **5 Mbps each direction**. The owner opens a customer
to 10 / 50 / 100 by bumping ``customers.speed_unlock_mbps`` (or
``plans.speed_unlock_mbps`` for a tier default). The resolution rule
collapses to the locked floor when nothing is set, so a fresh customer
who has not paid for an upgrade still gets a working — but capped —
connection.

The §9 per-connection-type bandwidth policy is the **ceiling** that
binds even a generous unlock: a customer unlocked to 200 Mbps against a
PPTP type-policy of 50 Mbps still emits 50M/50M. This protects the
operator from a fat-finger that could otherwise saturate the uplink.

Per-direction emission is delegated to the SAME
``app.services.speed_profiles.rate_limit_string`` helper the
``feat/bandwidth-per-direction`` sibling rolls out (850 → ``850M/850M``,
asymmetric pairs emit as ``<upload>M/<download>M``).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from app.models import Customer, License, Plan
from app.services.bandwidth_policy import SUPPORTED_TYPES, TypePolicy, policy_for


logger = logging.getLogger(__name__)


#: Locked default — every unauthorised customer/plan defaults to this
#: per-direction Mbps cap. Documented in §12.1 as the floor; the resolver
#: collapses ``0`` (back-compat sentinel) to this value.
LOCKED_DEFAULT_MBPS: int = 5

#: Suggested unlock tiers the UI offers — informational; the resolver
#: accepts any positive integer the owner enters.
UNLOCK_TIERS: tuple[int, ...] = (5, 10, 50, 100)


@dataclass(frozen=True)
class EffectiveSpeed:
    """The resolved per-direction Mbps for one (customer, type) pair.

    ``source`` records which lever the operator pulled, so the customer
    page can show «الفعّال: 50M (Plan)» vs «الفعّال: 5M (Locked)» —
    no surprise when the owner reads the page.
    """

    download_mbps: int
    upload_mbps: int
    source: str   # "locked" | "plan" | "customer" | "type_policy_ceiling"
    type_policy: TypePolicy

    def rate_limit(self) -> str:
        """Wire shape — delegate to the shared formatter."""
        from app.services.speed_profiles import rate_limit_string
        return rate_limit_string(self.download_mbps, self.upload_mbps)

    def as_dict(self) -> dict:
        return {
            "download_mbps": self.download_mbps,
            "upload_mbps": self.upload_mbps,
            "source": self.source,
            "rate_limit": self.rate_limit(),
        }


def _plan_unlock_for(customer: Customer) -> int:
    """Find the plan unlock attached to the customer (via their most
    recent license).

    Returns ``0`` when no license or plan is attached (the resolver
    falls back to the locked floor). We pick the **most recently
    created** license — operators who change a customer's plan create a
    new license, so this matches the per-deal lever the doc describes.
    """
    if customer is None or not getattr(customer, "id", None):
        return 0
    try:
        lic = (
            customer.licenses
            .order_by(License.created_at.desc())
            .first()
        )
    except Exception:  # noqa: BLE001 - defensive: relationship may be unbound
        return 0
    if lic is None or lic.plan is None:
        return 0
    return int(getattr(lic.plan, "speed_unlock_mbps", 0) or 0)


def resolve_speed_for(
    customer: Customer, connection_type: str,
) -> EffectiveSpeed:
    """Return the effective per-direction Mbps the panel will emit for
    ``connection_type`` on ``customer``.

    Resolution order, customer-wins:

      1. ``customer.speed_unlock_mbps`` when > 0  → source = ``customer``
      2. ``plan.speed_unlock_mbps`` when > 0      → source = ``plan``
      3. ``LOCKED_DEFAULT_MBPS`` (5)              → source = ``locked``

    The §9 per-type policy is then applied as a ceiling — if the
    customer/plan unlock exceeds it, the emitted Mbps drops to the
    policy cap and ``source = "type_policy_ceiling"``.

    Exception: ``connection_type == "radius_transport"`` ignores the
    customer unlock entirely (the RADIUS plane carries only
    auth/acct/CoA — the unlock is about user-traffic speed, not the
    control plane) and returns the policy value directly with source
    ``"type_policy_ceiling"``.
    """
    if connection_type not in SUPPORTED_TYPES:
        raise ValueError(
            f"unknown connection_type={connection_type!r}; "
            f"expected one of {SUPPORTED_TYPES}",
        )
    type_pol = policy_for(connection_type)

    # radius_transport ignores the customer unlock by design (§12.2).
    if connection_type == "radius_transport":
        return EffectiveSpeed(
            download_mbps=type_pol.download_mbps,
            upload_mbps=type_pol.upload_mbps,
            source="type_policy_ceiling",
            type_policy=type_pol,
        )

    cust_unlock = int(getattr(customer, "speed_unlock_mbps", 0) or 0)
    plan_unlock = _plan_unlock_for(customer)
    if cust_unlock > 0:
        unlock, source = cust_unlock, "customer"
    elif plan_unlock > 0:
        unlock, source = plan_unlock, "plan"
    else:
        unlock, source = LOCKED_DEFAULT_MBPS, "locked"

    # Ceiling binds — the §9 type policy upper-bounds the customer/plan
    # unlock to protect the operator (fat-finger guard).
    bounded_down = min(unlock, type_pol.download_mbps)
    bounded_up   = min(unlock, type_pol.upload_mbps)
    bounded_by_ceiling = (
        bounded_down < unlock or bounded_up < unlock
    )
    final_source = "type_policy_ceiling" if bounded_by_ceiling else source
    return EffectiveSpeed(
        download_mbps=bounded_down,
        upload_mbps=bounded_up,
        source=final_source,
        type_policy=type_pol,
    )


def mikrotik_rate_limit_for(
    customer: Customer, connection_type: str,
) -> str:
    """Return the ``Mikrotik-Rate-Limit`` attribute value for the
    Access-Accept (e.g. ``"5M/5M"``). Empty string if neither
    direction resolves to a positive value (the proxy then OMITS the
    attribute rather than sending a malformed string)."""
    eff = resolve_speed_for(customer, connection_type)
    return eff.rate_limit()


def set_customer_unlock(customer: Customer, mbps: int, *, commit: bool = True) -> int:
    """Persist a new per-customer unlock. Validation:
    * ``0`` clears the customer override → resolver falls back to plan.
    * Positive int up to 10_000 accepted; > 10_000 is almost certainly a
      typo (the largest reasonable cap on a 1 G uplink) so we reject it
      to surface mistakes early instead of writing them through.
    """
    if not isinstance(mbps, int) or mbps < 0:
        raise ValueError("mbps must be a non-negative integer")
    if mbps > 10_000:
        raise ValueError("mbps unrealistically high (>10000); refusing to persist")
    previous = int(customer.speed_unlock_mbps or 0)
    customer.speed_unlock_mbps = int(mbps)
    if commit:
        from app.extensions import db
        db.session.commit()
    logger.info(
        "customer_speed: customer_id=%s unlock %s -> %s",
        customer.id, previous, mbps,
    )
    return mbps


def set_plan_unlock(plan: Plan, mbps: int, *, commit: bool = True) -> int:
    """Persist a new per-plan unlock — same validation as the customer
    setter."""
    if not isinstance(mbps, int) or mbps < 0:
        raise ValueError("mbps must be a non-negative integer")
    if mbps > 10_000:
        raise ValueError("mbps unrealistically high (>10000); refusing to persist")
    previous = int(plan.speed_unlock_mbps or 0)
    plan.speed_unlock_mbps = int(mbps)
    if commit:
        from app.extensions import db
        db.session.commit()
    logger.info(
        "customer_speed: plan_id=%s unlock %s -> %s",
        plan.id, previous, mbps,
    )
    return mbps


__all__ = [
    "LOCKED_DEFAULT_MBPS",
    "UNLOCK_TIERS",
    "EffectiveSpeed",
    "mikrotik_rate_limit_for",
    "resolve_speed_for",
    "set_customer_unlock",
    "set_plan_unlock",
]
