from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Any

from ..models import Customer, CustomerVpnEntitlement, License, VpnServicePlan, utcnow

SERVICE_KEY = "ip_change_vpn"
VALID_ENTITLEMENT_STATUSES = {"active", "suspended", "expired", "disabled"}
PLAN_CODE_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")


class VpnEntitlementValidationError(ValueError):
    pass


@dataclass
class EffectiveVpnEntitlement:
    enabled: bool
    status: str
    plan_code: str | None = None
    download_mbps: int | None = None
    upload_mbps: int | None = None
    max_vpn_users: int | None = None
    max_locations: int | None = None
    traffic_quota_gb: int | None = None
    expires_at: datetime | None = None


def clean_vpn_plan_code(value: str) -> str:
    code = (value or "").strip().lower()
    if not PLAN_CODE_RE.match(code):
        raise VpnEntitlementValidationError("التعريف الداخلي لباقة الشبكة الخاصة غير صحيح.")
    return code


def validate_vpn_speed(value: Any, field_name: str = "speed") -> int:
    return _positive_int(value, field_name)


def validate_positive_limit(value: Any, field_name: str) -> int:
    return _positive_int(value, field_name)


def validate_entitlement_status(value: str) -> str:
    status = (value or "disabled").strip().lower()
    if status not in VALID_ENTITLEMENT_STATUSES:
        raise VpnEntitlementValidationError("حالة الشبكة الخاصة غير مسموحة.")
    return status


def parse_optional_positive_int(value: Any, field_name: str) -> int | None:
    raw = "" if value is None else str(value).strip()
    if not raw:
        return None
    return _positive_int(raw, field_name)


def parse_optional_decimal(value: Any, field_name: str) -> Decimal | None:
    raw = "" if value is None else str(value).strip()
    if not raw:
        return None
    try:
        amount = Decimal(raw)
    except (InvalidOperation, TypeError) as exc:
        raise VpnEntitlementValidationError(f"الحقل {field_name} يجب أن يكون رقمًا صحيحًا.") from exc
    if amount < 0:
        raise VpnEntitlementValidationError(f"الحقل {field_name} لا يمكن أن يكون سالبًا.")
    return amount


def validate_vpn_plan(plan: VpnServicePlan) -> None:
    if not (plan.name or "").strip():
        raise VpnEntitlementValidationError("اسم باقة الشبكة الخاصة مطلوب.")
    plan.code = clean_vpn_plan_code(plan.code)
    plan.download_mbps = validate_vpn_speed(plan.download_mbps, "download_mbps")
    plan.upload_mbps = validate_vpn_speed(plan.upload_mbps, "upload_mbps")
    plan.max_vpn_users = validate_positive_limit(plan.max_vpn_users, "max_vpn_users")
    plan.max_locations = validate_positive_limit(plan.max_locations or 1, "max_locations")
    if plan.traffic_quota_gb is not None:
        plan.traffic_quota_gb = validate_positive_limit(plan.traffic_quota_gb, "traffic_quota_gb")


def validate_customer_vpn_entitlement(entitlement: CustomerVpnEntitlement) -> None:
    entitlement.status = validate_entitlement_status(entitlement.status)
    if entitlement.enabled or entitlement.status == "active":
        entitlement.download_mbps = validate_vpn_speed(entitlement.download_mbps, "download_mbps")
        entitlement.upload_mbps = validate_vpn_speed(entitlement.upload_mbps, "upload_mbps")
        entitlement.max_vpn_users = validate_positive_limit(entitlement.max_vpn_users, "max_vpn_users")
        entitlement.max_locations = validate_positive_limit(entitlement.max_locations or 1, "max_locations")
        entitlement.enabled = True
        entitlement.status = "active"
    else:
        if entitlement.download_mbps is not None:
            entitlement.download_mbps = validate_vpn_speed(entitlement.download_mbps, "download_mbps")
        if entitlement.upload_mbps is not None:
            entitlement.upload_mbps = validate_vpn_speed(entitlement.upload_mbps, "upload_mbps")
        if entitlement.max_vpn_users is not None:
            entitlement.max_vpn_users = validate_positive_limit(entitlement.max_vpn_users, "max_vpn_users")
        if entitlement.max_locations is not None:
            entitlement.max_locations = validate_positive_limit(entitlement.max_locations, "max_locations")


def get_customer_vpn_entitlement(customer: Customer) -> CustomerVpnEntitlement | None:
    return CustomerVpnEntitlement.query.filter_by(customer_id=customer.id).first()


def get_or_create_customer_vpn_entitlement(customer: Customer) -> CustomerVpnEntitlement:
    entitlement = get_customer_vpn_entitlement(customer)
    if entitlement:
        return entitlement
    return CustomerVpnEntitlement(customer_id=customer.id, enabled=False, status="disabled", max_locations=1)


def apply_plan_defaults(entitlement: CustomerVpnEntitlement, plan: VpnServicePlan | None) -> None:
    if not plan:
        return
    entitlement.vpn_plan_id = plan.id
    entitlement.download_mbps = plan.download_mbps
    entitlement.upload_mbps = plan.upload_mbps
    entitlement.max_vpn_users = plan.max_vpn_users
    entitlement.max_locations = plan.max_locations or 1


def find_best_customer_license(customer: Customer) -> License | None:
    now = utcnow()
    active = customer.licenses.filter(
        License.status == "active",
        License.expires_at >= now,
    ).order_by(License.expires_at.desc()).first()
    if active:
        return active
    return customer.licenses.order_by(License.created_at.desc()).first()


def license_allows_vpn_services(lic: License | None) -> bool:
    if not lic or lic.status in {"suspended", "revoked"}:
        return False
    if lic.expires_at and lic.expires_at < utcnow():
        return bool(lic.grace_until and lic.grace_until >= utcnow())
    return True


def build_effective_vpn_entitlement(
    lic: License | None,
    *,
    license_allows_services: bool = True,
) -> EffectiveVpnEntitlement:
    if not lic or not license_allows_services:
        return EffectiveVpnEntitlement(enabled=False, status="disabled")

    entitlement = CustomerVpnEntitlement.query.filter_by(customer_id=lic.customer_id).first()
    if not entitlement:
        return EffectiveVpnEntitlement(enabled=False, status="disabled")

    try:
        status = validate_entitlement_status(entitlement.status)
    except VpnEntitlementValidationError:
        status = "disabled"
    if entitlement.expires_at and entitlement.expires_at < utcnow():
        status = "expired"
    if not entitlement.enabled and status != "active":
        return EffectiveVpnEntitlement(
            enabled=False,
            status=status,
            plan_code=entitlement.vpn_plan.code if entitlement.vpn_plan else None,
            expires_at=entitlement.expires_at,
        )
    if not entitlement.enabled:
        return EffectiveVpnEntitlement(enabled=False, status="disabled")
    if status != "active":
        return EffectiveVpnEntitlement(
            enabled=False,
            status=status,
            plan_code=entitlement.vpn_plan.code if entitlement.vpn_plan else None,
            expires_at=entitlement.expires_at,
        )

    plan = entitlement.vpn_plan
    download_mbps = entitlement.download_mbps or (plan.download_mbps if plan else None)
    upload_mbps = entitlement.upload_mbps or (plan.upload_mbps if plan else None)
    max_vpn_users = entitlement.max_vpn_users or (plan.max_vpn_users if plan else None)
    max_locations = entitlement.max_locations or (plan.max_locations if plan else 1)
    # The per-customer APPROVED traffic quota (from the «طلب تفعيل») wins over
    # the plan default; NULL on both ⇒ unlimited.
    traffic_quota_gb = (getattr(entitlement, "traffic_quota_gb", None)
                        or (plan.traffic_quota_gb if plan else None))

    try:
        download_mbps = validate_vpn_speed(download_mbps, "download_mbps")
        upload_mbps = validate_vpn_speed(upload_mbps, "upload_mbps")
        max_vpn_users = validate_positive_limit(max_vpn_users, "max_vpn_users")
        max_locations = validate_positive_limit(max_locations, "max_locations")
    except VpnEntitlementValidationError:
        return EffectiveVpnEntitlement(enabled=False, status="disabled")

    return EffectiveVpnEntitlement(
        enabled=True,
        status="active",
        plan_code=plan.code if plan else None,
        download_mbps=download_mbps,
        upload_mbps=upload_mbps,
        max_vpn_users=max_vpn_users,
        max_locations=max_locations,
        traffic_quota_gb=traffic_quota_gb,
        expires_at=entitlement.expires_at,
    )


def serialize_vpn_contract(effective: EffectiveVpnEntitlement) -> dict[str, Any]:
    if not effective.enabled:
        data: dict[str, Any] = {
            "enabled": False,
            "status": effective.status,
        }
        if effective.status in {"suspended", "expired"}:
            if effective.plan_code:
                data["plan_code"] = effective.plan_code
            if effective.expires_at:
                data["expires_at"] = _iso_z(effective.expires_at)
        return data

    return {
        "enabled": True,
        "status": "active",
        "plan_code": effective.plan_code,
        "download_mbps": effective.download_mbps,
        "upload_mbps": effective.upload_mbps,
        "max_vpn_users": effective.max_vpn_users,
        "max_locations": effective.max_locations,
        "traffic_quota_gb": effective.traffic_quota_gb,
        "expires_at": _iso_z(effective.expires_at),
        "enforcement_mode": "customer_runtime",
        "runtime_hint": "wireguard_tc_or_chr_queue",
    }


def vpn_services_contract_for_license(
    lic: License | None,
    *,
    license_allows_services: bool = True,
) -> dict[str, Any]:
    effective = build_effective_vpn_entitlement(lic, license_allows_services=license_allows_services)
    return {SERVICE_KEY: serialize_vpn_contract(effective)}


def _positive_int(value: Any, field_name: str) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise VpnEntitlementValidationError(f"{field_name} must be a positive integer.") from exc
    if number <= 0:
        raise VpnEntitlementValidationError(f"{field_name} must be a positive integer.")
    return number


def _iso_z(value: datetime | None) -> str | None:
    if not value:
        return None
    return value.replace(microsecond=0).isoformat() + "Z"
