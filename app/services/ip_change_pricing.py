"""«تغيير العنوان الكامل» (full IP change) — Phase 2 pricing + monthly term + provisioning glue.

Licensing-panel side of the paid IP-change service. This module is the THIN new
layer over the already-built pieces (CustomerVpnEntitlement, vpn_tunnels.
provision_tunnel, fleet_node_router, the pull bridge); it does NOT re-implement
provisioning or the bridge.

Owner's confirmed model:
  * price is PER-Mbps of (symmetric) SPEED, admin-configurable;
  * DATA IS UNLIMITED;
  * MONTHLY validity (renews monthly);
  * on approval an SSTP user is provisioned (rate-limit = purchased Mbps) on a
    hosted CHR — manual (admin picks) or auto (brain by priority/availability) —
    and the credentials + server IP + speed reach the customer via the existing
    pull bridge (vpn/tunnels → ack).
"""
from __future__ import annotations

import calendar
from datetime import datetime
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Optional

from ..extensions import db
from ..models import Customer, License, Setting, utcnow

#: Admin-configurable price (USD) per Mbps of symmetric speed, per month.
PRICE_PER_MBPS_SETTING = "ip_change.price_per_mbps"
DEFAULT_PRICE_PER_MBPS = Decimal("0.50")
_MAX_PRICE_PER_MBPS = Decimal("100000")


class IpChangePricingError(ValueError):
    """Invalid pricing input (Arabic message)."""


# ── pricing (admin-configurable) ─────────────────────────────────────────────
def get_price_per_mbps() -> Decimal:
    """The configured price per Mbps/month, or the documented default."""
    row = db.session.get(Setting, PRICE_PER_MBPS_SETTING)
    if not row or not (row.value or "").strip():
        return DEFAULT_PRICE_PER_MBPS
    try:
        v = Decimal(row.value.strip())
        return v if v >= 0 else DEFAULT_PRICE_PER_MBPS
    except (InvalidOperation, ValueError):
        return DEFAULT_PRICE_PER_MBPS


def set_price_per_mbps(value) -> Decimal:
    """Validate + persist the price per Mbps. Raises :class:`IpChangePricingError`."""
    try:
        v = Decimal(str(value).strip())
    except (InvalidOperation, ValueError, AttributeError) as exc:
        raise IpChangePricingError("سعر الميجابت يجب أن يكون رقمًا.") from exc
    if v < 0 or v > _MAX_PRICE_PER_MBPS:
        raise IpChangePricingError(f"سعر الميجابت يجب أن يكون بين 0 و{_MAX_PRICE_PER_MBPS}.")
    row = db.session.get(Setting, PRICE_PER_MBPS_SETTING)
    if row is None:
        row = Setting(key=PRICE_PER_MBPS_SETTING)
        db.session.add(row)
    row.value = format(v, "f")
    db.session.flush()
    return v


def normalize_request_desired_limits(body: dict) -> dict:
    """Map a customer-pushed IP-change request body into the ``desired_limits``
    the inbox / approval UI / pricing read.

    The customer panel sends ``requested_speed_mbps`` + ``billing=monthly`` +
    ``data=unlimited`` (top-level or already inside ``desired_limits``). We
    surface the speed symmetrically as ``speed_mbps`` / ``download_mbps`` /
    ``upload_mbps`` so the approval form pre-fills it and ``monthly_price`` can
    compute the quote, and we stamp the monthly/unlimited intent.
    """
    src = body if isinstance(body, dict) else {}
    desired = dict(src.get("desired_limits") or {}) if isinstance(src.get("desired_limits"), dict) else {}
    raw = (src.get("requested_speed_mbps")
           or desired.get("requested_speed_mbps")
           or desired.get("speed_mbps")
           or desired.get("download_mbps") or 0)
    try:
        speed = int(float(raw or 0))
    except (TypeError, ValueError):
        speed = 0
    if speed > 0:
        desired["speed_mbps"] = speed
        desired.setdefault("download_mbps", speed)
        desired.setdefault("upload_mbps", speed)
    desired["billing"] = str(src.get("billing") or desired.get("billing") or "monthly")
    desired["data"] = str(src.get("data") or desired.get("data") or "unlimited")
    return desired


def monthly_price(speed_mbps) -> Decimal:
    """Monthly price for a symmetric line of ``speed_mbps`` = speed × price/Mbps."""
    try:
        s = Decimal(str(speed_mbps or 0))
    except (InvalidOperation, ValueError):
        s = Decimal(0)
    if s < 0:
        s = Decimal(0)
    return (s * get_price_per_mbps()).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


# ── monthly term ─────────────────────────────────────────────────────────────
def add_one_month(dt: datetime) -> datetime:
    """Add one calendar month, clamping the day (e.g. Jan-31 → Feb-28)."""
    y, m = dt.year, dt.month + 1
    if m > 12:
        y += 1
        m = 1
    day = min(dt.day, calendar.monthrange(y, m)[1])
    return dt.replace(year=y, month=m, day=day)


def monthly_expiry(from_dt: Optional[datetime] = None) -> datetime:
    """One month from ``from_dt`` (default now) — the monthly validity window."""
    return add_one_month(from_dt or utcnow())


def renew_ip_change(customer: Customer) -> datetime:
    """Renew the customer's IP-change entitlement by one month and keep it active.
    Extends from the current expiry when still in the future, else from now."""
    from .vpn_entitlements import get_or_create_customer_vpn_entitlement
    ent = get_or_create_customer_vpn_entitlement(customer)
    now = utcnow()
    base = ent.expires_at if (ent.expires_at and ent.expires_at > now) else now
    ent.expires_at = add_one_month(base)
    ent.status = "active"
    ent.enabled = True
    db.session.add(ent)
    return ent.expires_at


def mark_expired_if_due(customer: Customer) -> bool:
    """On non-renewal: if past expiry, mark the entitlement expired (the revert
    is handled customer-side). Returns True when it flipped to expired."""
    from .vpn_entitlements import get_or_create_customer_vpn_entitlement
    ent = get_or_create_customer_vpn_entitlement(customer)
    if ent.expires_at and ent.expires_at < utcnow() and ent.status != "expired":
        ent.status = "expired"
        ent.enabled = False
        db.session.add(ent)
        return True
    return False


# ── provisioning glue (reuses vpn_tunnels.provision_tunnel) ──────────────────
def active_sstp_tunnel(customer: Customer):
    """The customer's current active SSTP tunnel, if any (avoid double-provision)."""
    from ..models import CustomerVpnTunnel
    return (CustomerVpnTunnel.query
            .filter_by(customer_id=customer.id, tunnel_type="sstp")
            .filter(CustomerVpnTunnel.status == "active")
            .order_by(CustomerVpnTunnel.id.desc())
            .first())


def provision_ip_change(customer: Customer, license_obj: License | None, *,
                        speed_mbps: int, fleet_chr_node_id: Optional[int] = None,
                        admin_id: Optional[int] = None):
    """Provision (or reuse) the SSTP user for an approved IP-change request:
    rate-limit = symmetric ``speed_mbps``, UNLIMITED data (monthly_quota_gb=None),
    on the chosen CHR (``fleet_chr_node_id``) or auto (brain) when None.

    Reuses :func:`vpn_tunnels.provision_tunnel` (which creates /ppp/profile +
    /ppp/secret on the CHR and stores the encrypted credential). Idempotent-ish:
    if an active SSTP tunnel already exists for the customer it is returned as-is
    (re-approval doesn't stack duplicate tunnels). Raises the underlying
    VpnTunnelError / FleetNodeUnavailable on failure — the caller surfaces it.
    """
    from . import vpn_tunnels as vt
    existing = active_sstp_tunnel(customer)
    if existing is not None:
        return existing
    speed = int(speed_mbps or 0)
    return vt.provision_tunnel(
        customer, license_obj,
        tunnel_type="sstp",
        download_mbps=speed, upload_mbps=speed,
        monthly_quota_gb=None,            # DATA UNLIMITED (owner)
        source="admin_manual",
        created_by_admin_id=admin_id,
        fleet_chr_node_id=fleet_chr_node_id,   # manual pick or None → auto/brain
        enforce_allowance=False,
    )


__all__ = [
    "PRICE_PER_MBPS_SETTING", "DEFAULT_PRICE_PER_MBPS", "IpChangePricingError",
    "get_price_per_mbps", "set_price_per_mbps", "monthly_price",
    "normalize_request_desired_limits",
    "add_one_month", "monthly_expiry", "renew_ip_change", "mark_expired_if_due",
    "active_sstp_tunnel", "provision_ip_change",
]
