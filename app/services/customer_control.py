from __future__ import annotations

import json
import re
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Any

from ..extensions import db
from ..models import (
    AuditLog,
    Customer,
    CustomerServiceEntitlement,
    CustomerServiceRequest,
    CustomerUser,
    License,
    ServiceCatalogItem,
    json_loads,
    utcnow,
)
from .vpn_entitlements import SERVICE_KEY as VPN_SERVICE_KEY
from .vpn_entitlements import vpn_services_contract_for_license

SERVICE_STATUS_ALLOWLIST = {"active", "suspended", "expired", "disabled"}
ROLE_KEYS = {"owner", "admin", "support", "billing", "viewer"}
SERVICE_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,79}$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.@-]{3,80}$")


class CustomerControlValidationError(ValueError):
    pass


DEFAULT_SERVICE_CATALOG = [
    {
        "service_key": VPN_SERVICE_KEY,
        "name": "IP Change / VPN Service",
        "name_ar": "خدمة تغيير IP / VPN",
        "description": "Commercial entitlement only. The customer runtime applies WireGuard/tc/CHR queue enforcement locally.",
        "category": "network",
        "default_enabled": False,
        "sort_order": 10,
        "price_monthly": Decimal("10.00"),
    },
    {
        "service_key": "customer_portal",
        "name": "Customer Portal",
        "name_ar": "بوابة العميل",
        "description": "Customer-facing portal for services, payment requests, and account visibility.",
        "category": "core",
        "default_enabled": True,
        "sort_order": 20,
        "price_monthly": None,
    },
    {
        "service_key": "cards",
        "name": "Card Marketplace",
        "name_ar": "الكروت",
        "description": "Create and manage prepaid cards in the customer RADIUS runtime.",
        "category": "radius",
        "default_enabled": True,
        "sort_order": 30,
        "price_monthly": None,
    },
    {
        "service_key": "subscribers",
        "name": "Subscribers",
        "name_ar": "المشتركين",
        "description": "Subscriber account management and RADIUS access lifecycle.",
        "category": "radius",
        "default_enabled": True,
        "sort_order": 40,
        "price_monthly": None,
    },
    {
        "service_key": "nas",
        "name": "NAS / Routers",
        "name_ar": "أجهزة الشبكة",
        "description": "Managed NAS/router records available to the customer installation.",
        "category": "radius",
        "default_enabled": True,
        "sort_order": 50,
        "price_monthly": None,
    },
    {
        "service_key": "profiles",
        "name": "Profiles and Plans",
        "name_ar": "البروفايلات والباقات",
        "description": "Package/profile management in the customer RADIUS runtime.",
        "category": "radius",
        "default_enabled": True,
        "sort_order": 60,
        "price_monthly": None,
    },
    {
        "service_key": "reports",
        "name": "Reports",
        "name_ar": "التقارير",
        "description": "Operational and accounting reports exposed by the customer runtime.",
        "category": "analytics",
        "default_enabled": False,
        "sort_order": 70,
        "price_monthly": None,
    },
    {
        "service_key": "backups",
        "name": "Backups",
        "name_ar": "النسخ الاحتياطي",
        "description": "Backup upload and restore coordination between runtime and license panel.",
        "category": "ops",
        "default_enabled": False,
        "sort_order": 80,
        "price_monthly": None,
    },
]


def seed_service_catalog() -> None:
    for item in DEFAULT_SERVICE_CATALOG:
        existing = ServiceCatalogItem.query.filter_by(service_key=item["service_key"]).first()
        if existing:
            continue
        db.session.add(ServiceCatalogItem(**item))


def clean_service_key(value: str) -> str:
    key = str(value or "").strip().lower()
    if not SERVICE_KEY_RE.match(key):
        raise CustomerControlValidationError("معرّف الخدمة يجب أن يكون أحرفًا إنجليزية صغيرة وأرقامًا وشرطات سفلية فقط.")
    return key


def clean_username(value: str) -> str:
    username = str(value or "").strip()
    if not USERNAME_RE.match(username):
        raise CustomerControlValidationError("اسم المستخدم يجب أن يكون من 3 إلى 80 حرفًا ويتكوّن من حروف وأرقام والنقطة والشرطة السفلية وعلامة @.")
    return username


def clean_role_key(value: str) -> str:
    role = str(value or "owner").strip().lower()
    if role not in ROLE_KEYS:
        raise CustomerControlValidationError("الدور المختار غير مسموح به.")
    return role


def clean_service_status(value: str) -> str:
    status = str(value or "disabled").strip().lower()
    if status not in SERVICE_STATUS_ALLOWLIST:
        raise CustomerControlValidationError("حالة الخدمة غير مسموحة.")
    return status


def parse_json_object(raw: Any, *, field: str) -> dict[str, Any]:
    if raw in (None, ""):
        return {}
    if isinstance(raw, dict):
        return _sanitize_json_object(raw)
    try:
        parsed = json.loads(str(raw))
    except (TypeError, ValueError) as exc:
        raise CustomerControlValidationError(f"الحقل {field} يجب أن يكون كائن JSON صحيحًا.") from exc
    if not isinstance(parsed, dict):
        raise CustomerControlValidationError(f"الحقل {field} يجب أن يكون كائن JSON صحيحًا.")
    return _sanitize_json_object(parsed)


def parse_optional_decimal(raw: Any, *, field: str) -> Decimal | None:
    if raw in (None, ""):
        return None
    try:
        parsed = Decimal(str(raw))
    except (InvalidOperation, TypeError) as exc:
        raise CustomerControlValidationError(f"الحقل {field} يجب أن يكون رقمًا.") from exc
    if parsed < 0:
        raise CustomerControlValidationError(f"الحقل {field} لا يمكن أن يكون سالبًا.")
    return parsed


def parse_optional_datetime(raw: Any) -> datetime | None:
    text = str(raw or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", ""))
    except ValueError:
        raise CustomerControlValidationError("تاريخ ووقت الانتهاء غير صحيح.")


def get_or_create_service_entitlement(customer: Customer, service_key: str) -> CustomerServiceEntitlement:
    key = clean_service_key(service_key)
    entitlement = CustomerServiceEntitlement.query.filter_by(customer_id=customer.id, service_key=key).first()
    if entitlement:
        return entitlement
    item = ServiceCatalogItem.query.filter_by(service_key=key).first()
    entitlement = CustomerServiceEntitlement(
        customer_id=customer.id,
        service_key=key,
        enabled=bool(item.default_enabled) if item else False,
        status="active" if item and item.default_enabled else "disabled",
        price_monthly=item.price_monthly if item else None,
    )
    db.session.add(entitlement)
    return entitlement


def customer_users_version(customer: Customer) -> int:
    versions = [
        int(user.password_version or 0)
        for user in customer.users.order_by(CustomerUser.id.asc()).all()
    ]
    return max(versions or [0])


def service_catalog_items() -> list[ServiceCatalogItem]:
    return ServiceCatalogItem.query.order_by(ServiceCatalogItem.sort_order.asc(), ServiceCatalogItem.service_key.asc()).all()


def customer_service_map(customer: Customer) -> dict[str, CustomerServiceEntitlement]:
    return {
        item.service_key: item
        for item in customer.service_entitlements.order_by(CustomerServiceEntitlement.service_key.asc()).all()
    }


def build_runtime_contract_for_license(
    lic: License | None,
    *,
    license_active: bool,
    status: str | None = None,
) -> dict[str, Any]:
    license_status = status or (lic.status if lic else "not_found")
    customer = lic.customer if lic else None
    services = _services_contract(customer, lic, license_active=license_active, license_status=license_status)
    return {
        "license": {
            "active": bool(license_active),
            "status": license_status,
            "license_key": lic.license_key if lic else None,
            "expires_at": iso_z(lic.expires_at) if lic else None,
            "grace_until": iso_z(lic.grace_until) if lic else None,
        },
        "customer": {
            "id": customer.id if customer else None,
            "company_name": customer.company_name if customer else "",
            "runtime_url": customer.runtime_url if customer else "",
        },
        "services": services,
        "limits": _limits_contract(lic),
        "customer_users_version": customer_users_version(customer) if customer else 0,
    }


def build_identity_sync_contract(lic: License, *, license_active: bool, status: str) -> dict[str, Any]:
    customer = lic.customer
    if not license_active:
        return {
            "ok": False,
            "status": status,
            "customer_id": customer.id,
            "license_key": lic.license_key,
            "version": customer_users_version(customer),
            "users": [],
        }
    users = []
    for user in customer.users.order_by(CustomerUser.id.asc()).all():
        users.append({
            "external_user_id": user.id,
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "role_key": user.role_key,
            "active": bool(user.active),
            "password_hash": user.password_hash,
            "password_hash_scheme": user.password_hash_scheme,
            "password_version": int(user.password_version or 0),
            "updated_at": iso_z(user.updated_at),
        })
    return {
        "ok": True,
        "customer_id": customer.id,
        "license_key": lic.license_key,
        "version": customer_users_version(customer),
        "users": users,
    }


def create_customer_service_request(
    *,
    customer: Customer,
    service_key: str,
    request_type: str = "activation",
    notes: str = "",
    desired_limits: dict[str, Any] | None = None,
    customer_user_id: int | None = None,
) -> CustomerServiceRequest:
    key = clean_service_key(service_key)
    if not ServiceCatalogItem.query.filter_by(service_key=key).first():
        raise CustomerControlValidationError("لم يتم العثور على الخدمة المطلوبة.")
    row = CustomerServiceRequest(
        customer_id=customer.id,
        customer_user_id=customer_user_id,
        service_key=key,
        request_type=str(request_type or "activation").strip()[:40],
        status="pending",
        notes=str(notes or "").strip()[:2000],
    )
    row.desired_limits = desired_limits or {}
    db.session.add(row)
    return row


def audit_customer_control(
    *,
    actor_admin_id: int | None,
    action: str,
    entity_type: str,
    entity_id: str,
    summary: str,
    metadata: dict[str, Any] | None = None,
) -> None:
    row = AuditLog(
        actor_admin_id=actor_admin_id,
        action=action,
        entity_type=entity_type,
        entity_id=str(entity_id),
        summary=summary,
    )
    row.meta = metadata or {}
    db.session.add(row)


def _services_contract(
    customer: Customer | None,
    lic: License | None,
    *,
    license_active: bool,
    license_status: str,
) -> dict[str, Any]:
    catalog = {item.service_key: item for item in service_catalog_items()}
    entitlement_map = customer_service_map(customer) if customer else {}
    services: dict[str, Any] = {}
    plan_features = lic.plan.features if lic and lic.plan else {}

    for key, item in catalog.items():
        if key == VPN_SERVICE_KEY:
            continue
        entitlement = entitlement_map.get(key)
        default_enabled = bool(item.default_enabled)
        if key in plan_features:
            default_enabled = bool(plan_features.get(key))
        services[key] = _serialize_service(
            key=key,
            catalog_item=item,
            entitlement=entitlement,
            default_enabled=default_enabled,
            license_active=license_active,
            license_status=license_status,
        )

    vpn_contract = vpn_services_contract_for_license(lic, license_allows_services=license_active).get(VPN_SERVICE_KEY, {
        "enabled": False,
        "status": "disabled",
    })
    generic_vpn = entitlement_map.get(VPN_SERVICE_KEY)
    if generic_vpn and not generic_vpn.enabled and generic_vpn.status in {"disabled", "suspended"}:
        vpn_contract = {
            "enabled": False,
            "status": generic_vpn.status,
        }
    services[VPN_SERVICE_KEY] = vpn_contract
    return services


def _serialize_service(
    *,
    key: str,
    catalog_item: ServiceCatalogItem,
    entitlement: CustomerServiceEntitlement | None,
    default_enabled: bool,
    license_active: bool,
    license_status: str,
) -> dict[str, Any]:
    enabled = bool(default_enabled)
    status = "active" if enabled else "disabled"
    limits: dict[str, Any] = {}
    config: dict[str, Any] = {}
    expires_at = None
    plan_code = ""

    if entitlement:
        try:
            status = clean_service_status(entitlement.status)
        except CustomerControlValidationError:
            status = "disabled"
        enabled = bool(entitlement.enabled) and status == "active"
        limits = entitlement.limits
        config = entitlement.config
        expires_at = entitlement.expires_at
        plan_code = entitlement.plan_code or ""
        if expires_at and expires_at < utcnow():
            enabled = False
            status = "expired"

    if not license_active:
        enabled = False
        if status == "active":
            status = license_status if license_status in SERVICE_STATUS_ALLOWLIST else "disabled"

    payload: dict[str, Any] = {
        "enabled": enabled,
        "status": status,
    }
    if plan_code:
        payload["plan_code"] = plan_code
    if limits:
        payload["limits"] = limits
    if config:
        payload["config"] = config
    if expires_at:
        payload["expires_at"] = iso_z(expires_at)
    payload["label"] = catalog_item.name_ar or catalog_item.name or key
    return payload


def _limits_contract(lic: License | None) -> dict[str, Any]:
    if not lic or not lic.plan:
        return {}
    return {
        "subscribers": {"max_total": int(lic.plan.max_users or 0)},
        "nas": {"max_total": int(lic.plan.max_nas or 0)},
        "admins": {"max_total": int(lic.plan.max_admins or 0)},
        "devices": {"max_total": int(lic.plan.max_devices or 0)},
    }


def _sanitize_json_object(raw: dict[str, Any]) -> dict[str, Any]:
    def clean(value: Any) -> Any:
        if isinstance(value, dict):
            return {str(k)[:80]: clean(v) for k, v in value.items()}
        if isinstance(value, list):
            return [clean(v) for v in value[:100]]
        if isinstance(value, (str, int, float, bool)) or value is None:
            return value
        return str(value)

    return {str(key)[:80]: clean(value) for key, value in raw.items()}


def iso_z(value: datetime | None) -> str | None:
    if not value:
        return None
    return value.replace(microsecond=0).isoformat() + "Z"
