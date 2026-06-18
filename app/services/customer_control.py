from __future__ import annotations

import json
import re
import secrets
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Any

from sqlalchemy import func

from ..extensions import db
from ..models import (
    AuditLog,
    Customer,
    CustomerServiceEntitlement,
    CustomerRadiusAdmin,
    CustomerServiceRequest,
    CustomerServiceRequestMessage,
    CustomerUser,
    License,
    ServiceCatalogItem,
    json_loads,
    utcnow,
)
from .vpn_entitlements import SERVICE_KEY as VPN_SERVICE_KEY
from .vpn_entitlements import vpn_services_contract_for_license

SERVICE_STATUS_ALLOWLIST = {"active", "suspended", "expired", "disabled"}
SERVICE_REQUEST_STATUS_ALLOWLIST = {
    "pending",
    "under_review",
    "payment_pending",
    "trial_active",
    "approved",
    "active",
    "rejected",
    "cancelled",
    "completed",
}
SERVICE_REQUEST_SENDER_TYPES = {"customer", "admin", "system"}
ROLE_KEYS = {"owner", "admin", "support", "billing", "viewer"}
SERVICE_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,79}$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.@-]{3,80}$")


class CustomerControlValidationError(ValueError):
    pass


def normalize_contact_email(value: str | None) -> str:
    return str(value or "").strip().lower()[:180]


def normalize_contact_phone(value: str | None) -> str:
    raw = str(value or "").strip()[:80]
    if not raw:
        return ""
    prefix = "+" if raw.startswith("+") else ""
    digits = re.sub(r"\D+", "", raw)
    return f"{prefix}{digits}" if digits else ""


def validate_unique_customer_contact(customer: Customer, email: str, phone: str) -> None:
    normalized_email = normalize_contact_email(email)
    normalized_phone = normalize_contact_phone(phone)

    with db.session.no_autoflush:
        if normalized_email:
            customer_email_query = Customer.query.filter(func.lower(Customer.email) == normalized_email)
            if customer.id:
                customer_email_query = customer_email_query.filter(Customer.id != customer.id)
            if customer_email_query.first():
                raise CustomerControlValidationError("البريد الإلكتروني مستخدم لعميل آخر.")

            user_email_query = CustomerUser.query.filter(func.lower(CustomerUser.email) == normalized_email)
            if customer.id:
                user_email_query = user_email_query.filter(CustomerUser.customer_id != customer.id)
            if user_email_query.first():
                raise CustomerControlValidationError("البريد الإلكتروني مستخدم في حساب عميل آخر.")

        if normalized_phone:
            rows = Customer.query.with_entities(Customer.id, Customer.phone).all()
            for row in rows:
                if customer.id and row.id == customer.id:
                    continue
                if normalize_contact_phone(row.phone) == normalized_phone:
                    raise CustomerControlValidationError("رقم الجوال مستخدم لعميل آخر.")


def validate_unique_customer_user_email(customer_user: CustomerUser, email: str) -> None:
    normalized_email = normalize_contact_email(email)
    if not normalized_email:
        return

    with db.session.no_autoflush:
        duplicate_user = CustomerUser.query.filter(func.lower(CustomerUser.email) == normalized_email)
        if customer_user.id:
            duplicate_user = duplicate_user.filter(CustomerUser.id != customer_user.id)
        if duplicate_user.first():
            raise CustomerControlValidationError("البريد الإلكتروني مستخدم بالفعل.")

        duplicate_customer = Customer.query.filter(func.lower(Customer.email) == normalized_email)
        if customer_user.customer_id:
            duplicate_customer = duplicate_customer.filter(Customer.id != customer_user.customer_id)
        if duplicate_customer.first():
            raise CustomerControlValidationError("البريد الإلكتروني مستخدم لعميل آخر.")


DEFAULT_SERVICE_CATALOG = [
    {
        "service_key": VPN_SERVICE_KEY,
        "name": "خدمة تغيير العنوان والشبكة الخاصة",
        "name_ar": "خدمة تغيير العنوان والشبكة الخاصة",
        "description": "صلاحية تجارية تحدد السرعة والمستخدمين والمواقع. الريدياس عند العميل هو الذي يطبق السرعة محليًا.",
        "category": "network",
        "default_enabled": False,
        "sort_order": 10,
        "price_monthly": Decimal("10.00"),
    },
    {
        "service_key": "public_ip_change",
        "name": "تغيير عنوان الإنترنت العام",
        "name_ar": "تغيير عنوان الإنترنت العام",
        "description": "طلب تجاري لتغيير عنوان الإنترنت العام المرتبط بنسخة العميل عند توفره.",
        "category": "network",
        "default_enabled": False,
        "sort_order": 12,
        "price_monthly": None,
    },
    {
        "service_key": "customer_portal",
        "name": "بوابة العميل",
        "name_ar": "بوابة العميل",
        "description": "صفحة العميل التي تعرض الترخيص والخدمات وطلبات الدفع وطلبات الترقية.",
        "category": "core",
        "default_enabled": True,
        "sort_order": 20,
        "price_monthly": None,
    },
    {
        "service_key": "remote_support",
        "name": "دعم فني عن بعد",
        "name_ar": "دعم فني عن بعد",
        "description": "خدمة تدخل دعم فني لتشخيص مشكلة النسخة التشغيلية وإصلاحها.",
        "category": "support",
        "default_enabled": False,
        "sort_order": 25,
        "price_monthly": None,
    },
    {
        "service_key": "remote_health_fix",
        "name": "صيانة النسخة عن بعد",
        "name_ar": "صيانة النسخة عن بعد",
        "description": "فحص صحة النسخة ومراجعة الأخطاء التشغيلية بدون تغيير إعدادات العميل إلا بموافقة.",
        "category": "support",
        "default_enabled": False,
        "sort_order": 27,
        "price_monthly": None,
    },
    {
        "service_key": "cards",
        "name": "الكروت",
        "name_ar": "الكروت",
        "description": "إنشاء وإدارة كروت الشحن والبيع والطباعة داخل الريدياس.",
        "category": "radius",
        "default_enabled": True,
        "sort_order": 30,
        "price_monthly": None,
    },
    {
        "service_key": "subscribers",
        "name": "المشتركين",
        "name_ar": "المشتركين",
        "description": "إدارة حسابات المشتركين وتفعيلهم وتجديدهم داخل الريدياس.",
        "category": "radius",
        "default_enabled": True,
        "sort_order": 40,
        "price_monthly": None,
    },
    {
        "service_key": "nas",
        "name": "أجهزة الشبكة",
        "name_ar": "أجهزة الشبكة",
        "description": "إدارة أجهزة الشبكة والراوترات التي يتصل بها الريدياس.",
        "category": "radius",
        "default_enabled": True,
        "sort_order": 50,
        "price_monthly": None,
    },
    {
        "service_key": "profiles",
        "name": "الباقات والبروفايلات",
        "name_ar": "الباقات والبروفايلات",
        "description": "تعريف باقات السرعة والصلاحيات التي يستخدمها المشترك أو الكرت.",
        "category": "radius",
        "default_enabled": True,
        "sort_order": 60,
        "price_monthly": None,
    },
    {
        "service_key": "routers",
        "name": "إدارة الراوترات",
        "name_ar": "إدارة الراوترات",
        "description": "لوحات مراقبة الراوتر، الصحة، النسخ، التنبيهات، وخدمات MikroTik من الريدياس.",
        "category": "network",
        "default_enabled": True,
        "sort_order": 70,
        "price_monthly": None,
    },
    {
        "service_key": "sessions",
        "name": "الجلسات والمتصلون",
        "name_ar": "الجلسات والمتصلون",
        "description": "عرض الجلسات النشطة وسجل الدخول وحالة الاتصال.",
        "category": "radius",
        "default_enabled": True,
        "sort_order": 80,
        "price_monthly": None,
    },
    {
        "service_key": "accounting",
        "name": "الحسابات والتحصيل",
        "name_ar": "الحسابات والتحصيل",
        "description": "دفعات المشتركين، الديون، القروض، المحافظ، وسجل الحركة المالية.",
        "category": "billing",
        "default_enabled": True,
        "sort_order": 90,
        "price_monthly": None,
    },
    {
        "service_key": "invoices",
        "name": "الفواتير",
        "name_ar": "الفواتير",
        "description": "إصدار وإدارة فواتير العملاء والمشتركين.",
        "category": "billing",
        "default_enabled": False,
        "sort_order": 100,
        "price_monthly": None,
    },
    {
        "service_key": "payment_collection",
        "name": "تحصيل المدفوعات",
        "name_ar": "تحصيل المدفوعات",
        "description": "طلبات التحصيل والمراجعة والمطابقة المالية داخل الريدياس.",
        "category": "billing",
        "default_enabled": False,
        "sort_order": 110,
        "price_monthly": None,
    },
    {
        "service_key": "finance_center",
        "name": "المركز المالي",
        "name_ar": "المركز المالي",
        "description": "المحافظ، الإيرادات، الديون، القروض، ودفتر القيود داخل الريدياس.",
        "category": "billing",
        "default_enabled": False,
        "sort_order": 115,
        "price_monthly": None,
    },
    {
        "service_key": "vouchers",
        "name": "الكوبونات",
        "name_ar": "الكوبونات",
        "description": "إدارة كوبونات الخصم أو التحصيل المرتبطة بحسابات العملاء.",
        "category": "billing",
        "default_enabled": False,
        "sort_order": 118,
        "price_monthly": None,
    },
    {
        "service_key": "print_templates",
        "name": "قوالب الطباعة",
        "name_ar": "قوالب الطباعة",
        "description": "تصميم وطباعة قوالب الكروت والإيصالات.",
        "category": "radius",
        "default_enabled": True,
        "sort_order": 120,
        "price_monthly": None,
    },
    {
        "service_key": "subscriber_groups",
        "name": "مجموعات المشتركين",
        "name_ar": "مجموعات المشتركين",
        "description": "تجميع المشتركين وتطبيق خدمات أو حدود مشتركة عليهم.",
        "category": "radius",
        "default_enabled": True,
        "sort_order": 130,
        "price_monthly": None,
    },
    {
        "service_key": "card_marketplace",
        "name": "سوق البطاقات",
        "name_ar": "سوق البطاقات",
        "description": "بيع البطاقات الإلكترونية وربطها بالمستخدمين ونقاط البيع.",
        "category": "sales",
        "default_enabled": False,
        "sort_order": 132,
        "price_monthly": None,
    },
    {
        "service_key": "card_users",
        "name": "مستخدمو البطاقات",
        "name_ar": "مستخدمو البطاقات",
        "description": "إدارة حسابات مستخدمي البطاقات الإلكترونية وشحنها ومتابعتها.",
        "category": "sales",
        "default_enabled": False,
        "sort_order": 134,
        "price_monthly": None,
    },
    {
        "service_key": "cards_recharge",
        "name": "بطاقات الشحن المسبق",
        "name_ar": "بطاقات الشحن المسبق",
        "description": "إدارة دفعات بطاقات الشحن المسبق ومراجعة حركتها.",
        "category": "sales",
        "default_enabled": False,
        "sort_order": 136,
        "price_monthly": None,
    },
    {
        "service_key": "admins",
        "name": "مدراء الريدياس والصلاحيات",
        "name_ar": "مدراء الريدياس والصلاحيات",
        "description": "إدارة مدراء الريدياس والأدوار والصلاحيات المحلية.",
        "category": "security",
        "default_enabled": True,
        "sort_order": 140,
        "price_monthly": None,
    },
    {
        "service_key": "setup_wizard",
        "name": "معالج التجهيز",
        "name_ar": "معالج التجهيز",
        "description": "تجهيز راوترات وخدمات Hotspot أو Broadband خطوة بخطوة.",
        "category": "network",
        "default_enabled": True,
        "sort_order": 150,
        "price_monthly": None,
    },
    {
        "service_key": "ip_pools",
        "name": "نطاقات العناوين",
        "name_ar": "نطاقات العناوين",
        "description": "إدارة نطاقات العناوين التي يستخدمها الريدياس والراوترات.",
        "category": "network",
        "default_enabled": True,
        "sort_order": 155,
        "price_monthly": None,
    },
    {
        "service_key": "network_policies",
        "name": "سياسات الشبكة",
        "name_ar": "سياسات الشبكة",
        "description": "إدارة سياسات الشبكة، السماح والحجب، ومراجعة التأثير قبل التطبيق.",
        "category": "network",
        "default_enabled": False,
        "sort_order": 160,
        "price_monthly": None,
    },
    {
        "service_key": "router_diagnostics",
        "name": "تشخيص الراوترات",
        "name_ar": "تشخيص الراوترات",
        "description": "فحوصات الراوترات، المشاكل، الصحة، والتنبيهات الذكية.",
        "category": "network",
        "default_enabled": False,
        "sort_order": 165,
        "price_monthly": None,
    },
    {
        "service_key": "bandwidth_control",
        "name": "السرعات والجدولة",
        "name_ar": "السرعات والجدولة",
        "description": "أدوات ضبط السرعات وجدولة تغييرات السرعة للمشتركين.",
        "category": "network",
        "default_enabled": True,
        "sort_order": 170,
        "price_monthly": None,
    },
    {
        "service_key": "site_exit",
        "name": "خروج المواقع",
        "name_ar": "خروج المواقع",
        "description": "خدمات توجيه أو فصل مواقع محددة حسب سياسة العميل.",
        "category": "network",
        "default_enabled": False,
        "sort_order": 180,
        "price_monthly": None,
    },
    {
        # Runs on the customer's own MikroTik/VPS → free-on-us (no provider cost).
        "service_key": "loop_detection",
        "name": "كشف الحلقات (Loop Detection)",
        "name_ar": "كشف الحلقات (Loop Detection)",
        "description": "اكتشاف الحلقات (loops) في شبكة العميل وتنبيهه — يعمل على راوتر/خادم العميل.",
        "category": "network",
        "default_enabled": True,
        "sort_order": 182,
        "price_monthly": None,
    },
    {
        # Limit-based monitoring («معمولات بحدود») on the customer's own VPS → free.
        "service_key": "device_health",
        "name": "صحة الأجهزة",
        "name_ar": "صحة الأجهزة",
        "description": "مراقبة صحة أجهزة الشبكة (CPU/ذاكرة/اتصال) ضمن حدّ عدد الأجهزة المراقَبة.",
        "category": "network",
        "default_enabled": True,
        "sort_order": 184,
        "price_monthly": None,
    },
    {
        "service_key": "communications",
        "name": "الرسائل والتنبيهات",
        "name_ar": "الرسائل والتنبيهات",
        "description": "إرسال رسائل وتنبيهات للمشتركين ومتابعة الحملات والقوالب.",
        "category": "communications",
        "default_enabled": False,
        "sort_order": 190,
        "price_monthly": None,
    },
    {
        "service_key": "whatsapp_gateway",
        "name": "WhatsApp Gateway",
        "name_ar": "رسائل واتساب للمشتركين",
        "description": "إرسال إشعارات واتساب للمشتركين عبر رقم واتساب التجاري الخاص بالعميل، مع حدود إرسال وقوالب معتمدة وموافقة المشرف على التفعيل.",
        "category": "communications",
        "default_enabled": False,
        "sort_order": 192,
        "price_monthly": None,
    },
    {
        # HYBRID: FREE when the customer uses their OWN SMS gateway API (BYO,
        # pays their provider directly — costs us nothing). The customer may
        # ALSO buy message packages from us via «طلب حزمة رسائل» (paid add-on);
        # the granted package credits flow into the contract as sms_package_credits.
        "service_key": "sms_gateway",
        "name": "SMS Gateway",
        "name_ar": "رسائل SMS للمشتركين",
        "description": "إرسال رسائل SMS عبر بوابة العميل الخاصة (مجانًا — يدفع لمزوّده مباشرة)، "
                       "أو بشراء حزم رسائل من المزوّد عبر «طلب حزمة رسائل».",
        "category": "communications",
        "default_enabled": False,
        "sort_order": 194,
        "price_monthly": None,
    },
    {
        "service_key": "operations_center",
        "name": "مركز العمليات",
        "name_ar": "مركز العمليات",
        "description": "متابعة التشغيل اليومي والمشاكل والمهام التي تحتاج تدخلًا.",
        "category": "ops",
        "default_enabled": False,
        "sort_order": 195,
        "price_monthly": None,
    },
    {
        "service_key": "risk_events",
        "name": "الأحداث والمخاطر",
        "name_ar": "الأحداث والمخاطر",
        "description": "مركز أحداث الأمان والمخاطر والتحقيقات داخل الريدياس.",
        "category": "security",
        "default_enabled": False,
        "sort_order": 198,
        "price_monthly": None,
    },
    {
        "service_key": "customer_support",
        "name": "الدعم والتذاكر",
        "name_ar": "الدعم والتذاكر",
        "description": "إدارة تذاكر الدعم ومتابعة طلبات العملاء.",
        "category": "support",
        "default_enabled": False,
        "sort_order": 200,
        "price_monthly": None,
    },
    {
        "service_key": "reports",
        "name": "التقارير",
        "name_ar": "التقارير",
        "description": "تقارير التشغيل، الجلسات، الدخول، المحاسبة، والأرشيف.",
        "category": "analytics",
        "default_enabled": False,
        "sort_order": 210,
        "price_monthly": None,
    },
    {
        "service_key": "backups",
        "name": "النسخ الاحتياطي",
        "name_ar": "النسخ الاحتياطي",
        "description": "تنسيق النسخ الاحتياطية والاستعادة للريدياس والراوترات.",
        "category": "ops",
        "default_enabled": False,
        "sort_order": 220,
        "price_monthly": None,
    },
    {
        "service_key": "lifecycle",
        "name": "الأرشفة التلقائية",
        "name_ar": "الأرشفة التلقائية",
        "description": "سياسات الأرشفة والتنظيف الدوري للعناصر القديمة.",
        "category": "ops",
        "default_enabled": False,
        "sort_order": 225,
        "price_monthly": None,
    },
    {
        "service_key": "audit_logs",
        "name": "سجل التدقيق",
        "name_ar": "سجل التدقيق",
        "description": "عرض سجل العمليات والمراجعة الأمنية داخل الريدياس.",
        "category": "security",
        "default_enabled": True,
        "sort_order": 230,
        "price_monthly": None,
    },
    {
        "service_key": "distributors",
        "name": "الموزعون",
        "name_ar": "الموزعون",
        "description": "إدارة الموزعين وربطهم بالكروت والمشتركين المسموحين.",
        "category": "sales",
        "default_enabled": False,
        "sort_order": 240,
        "price_monthly": None,
    },
    {
        "service_key": "radius_customer_portals",
        "name": "بوابات عملاء الريدياس",
        "name_ar": "بوابات عملاء الريدياس",
        "description": "إدارة بوابات دخول المشتركين وبوابات البطاقات داخل الريدياس.",
        "category": "support",
        "default_enabled": False,
        "sort_order": 245,
        "price_monthly": None,
    },
    {
        "service_key": "remote_access",
        "name": "الوصول البعيد",
        "name_ar": "الوصول البعيد",
        "description": "أدوات الوصول البعيد الآمن للراوترات أو الأجهزة عند الحاجة.",
        "category": "network",
        "default_enabled": False,
        "sort_order": 250,
        "price_monthly": None,
    },
    {
        "service_key": "integration_bridge",
        "name": "جسر التكامل",
        "name_ar": "جسر التكامل",
        "description": "مزامنة الترخيص والهوية والعقد التشغيلي بين اللوحة والريدياس.",
        "category": "integration",
        "default_enabled": True,
        "sort_order": 260,
        "price_monthly": None,
    },
    {
        "service_key": "webhooks",
        "name": "إشعارات الربط",
        "name_ar": "إشعارات الربط",
        "description": "إعدادات إشعارات الربط والتكامل الخارجي عند الحاجة.",
        "category": "integration",
        "default_enabled": False,
        "sort_order": 270,
        "price_monthly": None,
    },
    {
        "service_key": "integration_tokens",
        "name": "مفاتيح الواجهة",
        "name_ar": "مفاتيح الواجهة",
        "description": "إدارة مفاتيح الواجهة المخصصة للتكاملات الآمنة.",
        "category": "integration",
        "default_enabled": False,
        "sort_order": 280,
        "price_monthly": None,
    },
    {
        "service_key": "multi_tenant",
        "name": "المستأجرون",
        "name_ar": "المستأجرون",
        "description": "إدارة أكثر من مستأجر أو شركة داخل نفس نسخة الريدياس.",
        "category": "ops",
        "default_enabled": False,
        "sort_order": 290,
        "price_monthly": None,
    },
]

# ════════════════════════════════════════════════════════════════════
# Per-subscriber service tier (free vs. paid).
#
# Owner-controlled per CUSTOMER and per SERVICE from the admin side. Storage
# is the existing CustomerServiceEntitlement.config dict — no schema change.
#
# Customer panel rendering:
#   • free_unlimited → green "مجاني" badge; the customer sees the service as
#     ready, no activation button. The runtime contract reports enabled=True.
#   • free_limited  → teal "مجاني · حتى N" badge (N = entitlement.limits cap);
#     also enabled=True in the runtime contract, but the existing limits gate.
#   • paid (default) → behavior is unchanged: the customer requests
#     activation/upgrade and pays before it goes live.
# ════════════════════════════════════════════════════════════════════
SERVICE_TIER_PAID = "paid"
SERVICE_TIER_FREE_UNLIMITED = "free_unlimited"
SERVICE_TIER_FREE_LIMITED = "free_limited"
SERVICE_TIER_VALUES = (SERVICE_TIER_PAID, SERVICE_TIER_FREE_UNLIMITED, SERVICE_TIER_FREE_LIMITED)
SERVICE_TIER_DEFAULT = SERVICE_TIER_PAID

#: Services that are FULLY HIDDEN until the provider explicitly grants them —
#: NOT shown, NOT available, NOT even a «طلب تفعيل» upsell (distinct from the
#: paid/locked_upgrade state). «الجهات» (multi_tenant) is the first: when granted
#: the provider sets entity_count + a per-entity limit set (config-stored). The
#: contract carries ``visibility`` = "hidden" | "granted" for these.
HIDDEN_UNTIL_GRANTED_SERVICES = {"multi_tenant"}

#: Per-entity limit fields for «الجهات» — each granted entity/tenant gets its
#: own caps. Editable here; the provider sets values per-customer on grant.
ENTITY_LIMIT_FIELDS = (
    ("max_subscribers", "أقصى مشتركين لكل جهة"),
    ("max_cards", "أقصى كروت لكل جهة"),
    ("max_nas", "أقصى أجهزة شبكة لكل جهة"),
)

SERVICE_TIER_LABELS = {
    SERVICE_TIER_PAID: "مدفوعة",
    SERVICE_TIER_FREE_UNLIMITED: "مجانية مطلقة",
    SERVICE_TIER_FREE_LIMITED: "مجانية محدودة",
}

# Short label used inside the customer card (compact).
SERVICE_TIER_BADGE_LABELS = {
    SERVICE_TIER_PAID: "مدفوعة",
    SERVICE_TIER_FREE_UNLIMITED: "مجانية",
    SERVICE_TIER_FREE_LIMITED: "مجانية · محدودة",
}

# Color hint (matches the portal_pro tone tokens — green / teal / violet).
SERVICE_TIER_BADGE_TONE = {
    SERVICE_TIER_PAID: "violet",
    SERVICE_TIER_FREE_UNLIMITED: "green",
    SERVICE_TIER_FREE_LIMITED: "teal",
}


def clean_service_tier(value: str | None) -> str:
    """Normalize a tier value; fall back to the safe default when unknown."""
    tier = str(value or "").strip().lower()
    return tier if tier in SERVICE_TIER_VALUES else SERVICE_TIER_DEFAULT


def service_tier_for_entitlement(entitlement: CustomerServiceEntitlement | None) -> str:
    """Read the tier stored on an entitlement's config; default = paid."""
    if entitlement is None:
        return SERVICE_TIER_DEFAULT
    try:
        config = entitlement.config or {}
    except Exception:  # pragma: no cover — defensive against broken JSON
        return SERVICE_TIER_DEFAULT
    return clean_service_tier(config.get("tier"))


def set_service_tier_on_entitlement(entitlement: CustomerServiceEntitlement, tier: str) -> None:
    """Persist a tier onto an entitlement's config, leaving sibling keys intact."""
    cleaned = clean_service_tier(tier)
    config = dict(entitlement.config or {})
    if cleaned == SERVICE_TIER_DEFAULT:
        config.pop("tier", None)
    else:
        config["tier"] = cleaned
    entitlement.config = config


def service_tier_is_free(tier: str | None) -> bool:
    return clean_service_tier(tier) in (SERVICE_TIER_FREE_UNLIMITED, SERVICE_TIER_FREE_LIMITED)


# ─────────────────────────────────────────────────────────────────────────
# Per-customer HIDDEN flag (orthogonal to the tier).
#
# «مخفي» removes the service ENTIRELY from that customer's portal — even a
# free/basic service — to declutter a beginner's view. It is a VIEW state:
# hiding never suspends a working service (the runtime contract still
# carries it, flagged ``hidden: true`` so the radius client can mirror the
# hide in ITS UI). SUSPENDED (entitlement.status) is the functional stop —
# independent and explicitly controlled. Stored as config["hidden"] so the
# underlying tier survives un-hide.
# ─────────────────────────────────────────────────────────────────────────

def service_is_hidden(entitlement: CustomerServiceEntitlement | None) -> bool:
    if entitlement is None:
        return False
    try:
        return bool((entitlement.config or {}).get("hidden"))
    except Exception:  # pragma: no cover — defensive against broken JSON
        return False


def set_service_hidden(entitlement: CustomerServiceEntitlement, hidden: bool) -> None:
    config = dict(entitlement.config or {})
    if hidden:
        config["hidden"] = True
    else:
        config.pop("hidden", None)
    entitlement.config = config


# ─────────────────────────────────────────────────────────────────────────
# Catalog-level default policy (feat/services-catalog-policy).
#
# The owner sets a GLOBAL default tier per service on the dedicated
# «الخدمات» page: مجاني مطلق / مجاني محدود (+ basic quantities) / مدفوع غير
# مفعّل. Stored inside ``ServiceCatalogItem.metadata_json`` (the existing
# property-backed dict) — zero schema migration, fully idempotent. The
# per-subscriber tier on ``CustomerServiceEntitlement.config["tier"]`` (the
# /admin/customers/<id>/service-tiers page) is an OVERRIDE that always wins
# when explicitly set; the catalog default fills the gap for everyone else.
# ─────────────────────────────────────────────────────────────────────────

_CATALOG_TIER_KEY = "default_tier"
_CATALOG_LIMITS_KEY = "default_limits"


def catalog_default_tier(item: "ServiceCatalogItem | None") -> str:
    """The owner's catalog-level default tier for a service (paid when unset)."""
    if item is None:
        return SERVICE_TIER_DEFAULT
    try:
        return clean_service_tier(item.catalog_metadata.get(_CATALOG_TIER_KEY))
    except Exception:  # pragma: no cover — defensive against broken JSON
        return SERVICE_TIER_DEFAULT


def catalog_default_limits(item: "ServiceCatalogItem | None") -> dict[str, Any]:
    """Basic quantities for a catalog free-limited default ({} otherwise)."""
    if item is None:
        return {}
    try:
        raw = item.catalog_metadata.get(_CATALOG_LIMITS_KEY) or {}
    except Exception:  # pragma: no cover
        return {}
    if not isinstance(raw, dict):
        return {}
    return {
        str(k): int(v)
        for k, v in raw.items()
        if _is_non_negative_int(v)
    }


def set_catalog_policy(item: "ServiceCatalogItem", tier: str, limits: dict[str, Any] | None = None) -> None:
    """Persist the owner's catalog default policy onto the catalog item.

    ``limits`` only meaningful for free_limited; stored verbatim (validated
    ints) so the «ترقية» baseline is explicit. Paid default clears both keys
    (paid is the implicit default — keeps metadata clean)."""
    cleaned = clean_service_tier(tier)
    data = item.catalog_metadata
    if cleaned == SERVICE_TIER_DEFAULT:
        data.pop(_CATALOG_TIER_KEY, None)
        data.pop(_CATALOG_LIMITS_KEY, None)
    else:
        data[_CATALOG_TIER_KEY] = cleaned
        if cleaned == SERVICE_TIER_FREE_LIMITED:
            data[_CATALOG_LIMITS_KEY] = {
                str(k): int(v)
                for k, v in (limits or {}).items()
                if _is_non_negative_int(v)
            }
        else:
            data.pop(_CATALOG_LIMITS_KEY, None)
    item.catalog_metadata = data


def entitlement_has_explicit_tier(entitlement: CustomerServiceEntitlement | None) -> bool:
    """True when the per-subscriber page explicitly set a tier (override)."""
    if entitlement is None:
        return False
    try:
        config = entitlement.config or {}
    except Exception:  # pragma: no cover
        return False
    return "tier" in config


def effective_service_tier(
    entitlement: CustomerServiceEntitlement | None,
    catalog_item: "ServiceCatalogItem | None",
) -> tuple[str, str]:
    """Resolve the tier that actually applies + its source.

    Returns ``(tier, source)`` where source is ``"override"`` (explicit
    per-subscriber choice) or ``"catalog"`` (the owner's global default).
    """
    if entitlement_has_explicit_tier(entitlement):
        return service_tier_for_entitlement(entitlement), "override"
    return catalog_default_tier(catalog_item), "catalog"


SERVICE_LIMIT_FIELDS = {
    "subscribers": [("max_total", "أقصى عدد مشتركين", "عدد المشتركين المسموح إنشاؤهم.")],
    "backups": [("max_count", "أقصى عدد نسخ احتياطية محفوظة", "عند تجاوز العدد يُحذف الأقدم تلقائيًا (نسخ الريدياس وملف العميل). يُحدَّد حسب الإصدار والرسوم.")],
    "cards": [
        ("generate_per_batch", "أقصى كروت في الدفعة", "الحد الأعلى عند توليد دفعة كروت واحدة."),
        ("monthly_generated", "أقصى كروت شهريًا", "إجمالي الكروت المسموح توليدها خلال الشهر."),
    ],
    "nas": [("max_total", "أقصى عدد أجهزة شبكة", "عدد أجهزة الشبكة أو الراوترات المسموح ربطها.")],
    "routers": [("max_total", "أقصى عدد راوترات", "عدد الراوترات المدارة من لوحة الريدياس.")],
    "profiles": [("max_total", "أقصى عدد باقات", "عدد الباقات أو البروفايلات المسموح إنشاؤها.")],
    "print_templates": [("max_active", "أقصى قوالب طباعة فعالة", "عدد قوالب الطباعة النشطة.")],
    "admins": [("max_total", "أقصى عدد مدراء", "عدد حسابات الإدارة المحلية في الريدياس.")],
    "card_marketplace": [("max_sellers", "أقصى عدد بائعين", "عدد بائعي البطاقات الإلكترونيين.")],
    "card_users": [("max_total", "أقصى عدد مستخدمي بطاقات", "عدد حسابات مستخدمي البطاقات.")],
    "cards_recharge": [("monthly_generated", "أقصى بطاقات شحن شهريًا", "إجمالي بطاقات الشحن المسبق خلال الشهر.")],
    "ip_pools": [("max_total", "أقصى عدد نطاقات", "عدد نطاقات العناوين المسموحة.")],
    "device_health": [("max_devices", "أقصى عدد أجهزة مراقَبة", "عدد أجهزة الشبكة التي تُراقب صحتها.")],
    "finance_center": [("max_wallets", "أقصى عدد محافظ", "عدد المحافظ المالية داخل الريدياس.")],
    "whatsapp_gateway": [
        ("max_messages_monthly", "حد الرسائل الشهري", "أقصى عدد رسائل واتساب المسموح إرسالها خلال الشهر (الافتراضي 500)."),
        ("max_messages_daily", "حد الرسائل اليومي", "أقصى عدد رسائل واتساب المسموح إرسالها خلال اليوم (الافتراضي 100)."),
        ("max_templates", "حد القوالب", "أقصى عدد قوالب واتساب المعتمدة للعميل (الافتراضي 20)."),
    ],
    "sms_gateway": [
        ("max_messages_monthly", "حد الرسائل الشهري (بوابة العميل)", "أقصى عدد رسائل SMS عبر بوابة العميل الخاصة شهريًا."),
        ("max_messages_daily", "حد الرسائل اليومي (بوابة العميل)", "أقصى عدد رسائل SMS عبر بوابة العميل الخاصة يوميًا."),
        ("sms_package_credits", "رصيد حزم الرسائل المشتراة", "رصيد رسائل SMS المشتراة من المزوّد (يُضاف عند اعتماد طلب حزمة)."),
    ],
    "distributors": [("max_total", "أقصى عدد موزعين", "عدد الموزعين المسموح إدارتهم.")],
    "multi_tenant": [("max_total", "أقصى عدد مستأجرين", "عدد الشركات أو المستأجرين داخل النسخة.")],
}


# ─────────────────────────────────────────────────────────────────────────
# SMART per-type spec metadata (feat/services-catalog-policy).
#
# Enriches each service's spec fields with sensible defaults / bounds /
# steps / units so the portal's «طلب تفعيل» and «ترقية» modals render
# genuinely per-type intelligent forms (only relevant fields, sane ranges).
# The radius-module client mirrors the same flow via the bridge — contract
# in docs/SERVICE_SPEC_REQUEST_CONTRACT.md.
# ─────────────────────────────────────────────────────────────────────────

SERVICE_SPEC_META: dict[str, dict[str, dict[str, Any]]] = {
    "subscribers": {"max_total": {"min": 10, "max": 100000, "step": 10, "default": 100, "unit": "مشترك"}},
    "backups": {"max_count": {"min": 1, "max": 365, "step": 1, "default": 30, "unit": "نسخة"}},
    "cards": {
        "generate_per_batch": {"min": 10, "max": 10000, "step": 10, "default": 100, "unit": "كرت/دفعة"},
        "monthly_generated": {"min": 100, "max": 200000, "step": 100, "default": 1000, "unit": "كرت/شهر"},
    },
    "nas": {"max_total": {"min": 1, "max": 500, "step": 1, "default": 3, "unit": "جهاز"}},
    "routers": {"max_total": {"min": 1, "max": 500, "step": 1, "default": 3, "unit": "راوتر"}},
    "profiles": {"max_total": {"min": 1, "max": 500, "step": 1, "default": 10, "unit": "باقة"}},
    "print_templates": {"max_active": {"min": 1, "max": 100, "step": 1, "default": 5, "unit": "قالب"}},
    "admins": {"max_total": {"min": 1, "max": 100, "step": 1, "default": 3, "unit": "مدير"}},
    "card_marketplace": {"max_sellers": {"min": 1, "max": 1000, "step": 1, "default": 5, "unit": "بائع"}},
    "card_users": {"max_total": {"min": 10, "max": 100000, "step": 10, "default": 100, "unit": "مستخدم"}},
    "cards_recharge": {"monthly_generated": {"min": 100, "max": 200000, "step": 100, "default": 1000, "unit": "بطاقة/شهر"}},
    "ip_pools": {"max_total": {"min": 1, "max": 100, "step": 1, "default": 2, "unit": "نطاق"}},
    "device_health": {"max_devices": {"min": 1, "max": 1000, "step": 1, "default": 50, "unit": "جهاز"}},
    "finance_center": {"max_wallets": {"min": 1, "max": 100, "step": 1, "default": 3, "unit": "محفظة"}},
    "whatsapp_gateway": {
        "max_messages_monthly": {"min": 100, "max": 100000, "step": 100, "default": 500, "unit": "رسالة/شهر"},
        "max_messages_daily": {"min": 10, "max": 10000, "step": 10, "default": 100, "unit": "رسالة/يوم"},
        "max_templates": {"min": 1, "max": 200, "step": 1, "default": 20, "unit": "قالب"},
    },
    "sms_gateway": {
        "max_messages_monthly": {"min": 100, "max": 200000, "step": 100, "default": 1000, "unit": "رسالة/شهر"},
        "max_messages_daily": {"min": 10, "max": 20000, "step": 10, "default": 200, "unit": "رسالة/يوم"},
        "sms_package_credits": {"min": 0, "max": 1000000, "step": 100, "default": 0, "unit": "رسالة"},
    },
    "distributors": {"max_total": {"min": 1, "max": 1000, "step": 1, "default": 5, "unit": "موزع"}},
    "multi_tenant": {"max_total": {"min": 1, "max": 100, "step": 1, "default": 2, "unit": "مستأجر"}},
}

# Request-only spec fields for service types whose specs are NOT entitlement
# limit fields — e.g. bandwidth-flavoured services request per-direction
# speed + quota. They travel in ``desired_limits`` like everything else;
# enforcement stays with the service's own provisioning (VPN contract).
SERVICE_REQUEST_EXTRA_FIELDS: dict[str, list[dict[str, Any]]] = {
    "ip_change_vpn": [
        {"key": "download_mbps", "label": "سرعة التحميل المطلوبة", "hint": "Mbps باتجاه التنزيل (لكل اتجاه سرعة مستقلة).",
         "min": 1, "max": 1000, "step": 1, "default": 50, "unit": "Mbps ↓"},
        {"key": "upload_mbps", "label": "سرعة الرفع المطلوبة", "hint": "Mbps باتجاه الرفع.",
         "min": 1, "max": 1000, "step": 1, "default": 50, "unit": "Mbps ↑"},
        {"key": "max_vpn_users", "label": "عدد مستخدمي VPN", "hint": "عدد المستخدمين المتزامنين على الخدمة.",
         "min": 1, "max": 1000, "step": 1, "default": 5, "unit": "مستخدم"},
        {"key": "quota_gb", "label": "حصة البيانات الشهرية", "hint": "اتركها فارغة لطلب حصة غير محدودة.",
         "min": 1, "max": 100000, "step": 10, "default": None, "unit": "GB/شهر"},
    ],
    "sms_gateway": [
        # «طلب حزمة رسائل» — the paid SMS package size to buy from the provider.
        # On approval the granted count is CREDITED to sms_package_credits.
        {"key": "package_messages", "label": "حجم حزمة الرسائل المطلوبة",
         "hint": "عدد رسائل SMS التي ترغب بشرائها من المزوّد (تُضاف إلى رصيدك عند الاعتماد).",
         "min": 100, "max": 1000000, "step": 100, "default": 1000, "unit": "رسالة"},
    ],
}


def service_spec_fields(service_key: str) -> list[dict[str, Any]]:
    """The SMART spec-form schema for one service type.

    Returns ``[{key,label,hint,min,max,step,default,unit}, …]`` — the
    union of the service's entitlement limit fields (enriched with
    ``SERVICE_SPEC_META`` bounds/defaults) and its request-only extras.
    This is what the portal modals render and what the request endpoint
    parses; the radius client mirrors the same schema via the bridge.
    """
    key = str(service_key or "")
    meta_map = SERVICE_SPEC_META.get(key, {})
    out: list[dict[str, Any]] = []
    for field_key, field_label, field_hint in SERVICE_LIMIT_FIELDS.get(key, []):
        meta = meta_map.get(field_key, {})
        out.append({
            "key": field_key,
            "label": field_label,
            "hint": field_hint,
            "min": int(meta.get("min", 0)),
            "max": meta.get("max"),
            "step": int(meta.get("step", 1)),
            "default": meta.get("default"),
            "unit": str(meta.get("unit", "")),
        })
    out.extend(dict(extra) for extra in SERVICE_REQUEST_EXTRA_FIELDS.get(key, []))
    return out


ROLE_LABELS = {
    "owner": "مالك الحساب",
    "admin": "مدير",
    "support": "دعم فني",
    "billing": "محاسبة",
    "viewer": "مشاهدة فقط",
}

SERVICE_REQUEST_TYPE_LABELS = {
    "activation": "طلب تفعيل",
    "upgrade": "طلب ترقية",
    "change": "طلب تعديل",
    "support": "طلب مساعدة",
}

SERVICE_REQUEST_STATUS_LABELS = {
    "pending": "جديد",
    "under_review": "قيد المراجعة",
    "payment_pending": "بانتظار الدفع",
    "trial_active": "تجربة مفعلة",
    "approved": "موافق عليه",
    "active": "مفعل",
    "rejected": "مرفوض",
    "cancelled": "ملغي",
    "completed": "مكتمل",
}

PAYMENT_PURPOSE_LABELS = {
    "new_subscription": "اشتراك جديد",
    "renewal": "تجديد",
    "upgrade": "ترقية",
    "capacity_increase": "رفع حدود",
    "setup_fee": "رسوم تجهيز",
    "failed": "تعذر التنفيذ",
}

AUDIT_ACTION_LABELS = {
    "login": "تسجيل دخول",
    "logout": "تسجيل خروج",
    "customer_created": "إنشاء عميل",
    "customer_updated": "تحديث عميل",
    "customer_deleted": "حذف عميل",
    "customer_approved": "اعتماد عميل",
    "customer_user_created": "إنشاء مستخدم عميل",
    "customer_user_updated": "تحديث مستخدم عميل",
    "customer_user_disabled": "تعطيل مستخدم عميل",
    "customer_user_enabled": "تفعيل مستخدم عميل",
    "customer_user_password_changed": "تغيير كلمة مرور عميل",
    "customer_user_password_changed_from_runtime": "تغيير كلمة المرور من الريدياس",
    "customer_user_password_changed_from_portal": "تغيير كلمة المرور من بوابة العميل",
    "radius_admin_force_super_enabled": "فرض سوبر يوزر على أدمن الراديوس",
    "radius_admin_force_super_disabled": "إلغاء فرض سوبر يوزر عن أدمن الراديوس",
    "customer_user_password_set_by_admin": "تعيين كلمة مرور من الإدارة",
    "customer_service_entitlement_updated": "تحديث خدمة عميل",
    "customer_service_payment_request_created": "إنشاء طلب دفع خدمة",
    "customer_service_request_created": "إنشاء طلب خدمة",
    "customer_service_request_updated": "تحديث طلب خدمة",
    "customer_service_request_replied": "إضافة رد على طلب خدمة",
    "customer_service_request_payment_requested": "طلب دفع لخدمة",
    "customer_service_request_payment_confirmed": "تأكيد دفع خدمة",
    "customer_service_request_trial_opened": "فتح تجربة خدمة",
    "customer_service_request_approved": "اعتماد طلب خدمة",
    "customer_service_request_rejected": "رفض طلب خدمة",
    "customer_vpn_entitlement_updated": "تحديث خدمة الشبكة الخاصة للعميل",
    "customer_vpn_tunnel_provisioned": "تزويد نفق VPN",
    "customer_vpn_tunnel_revoked": "إلغاء نفق VPN",
    "customer_vpn_tunnel_status_changed": "تغيير حالة نفق VPN",
    "chr_settings_saved": "حفظ إعدادات CHR",
    "chr_test_success": "نجاح اختبار CHR",
    "chr_test_failed": "فشل اختبار CHR",
    "chr_secret_revealed": "كشف كلمة مرور CHR",
    "plan_created": "إنشاء خطة",
    "plan_updated": "تحديث خطة",
    "plan_deleted": "حذف خطة",
    "vpn_service_plan_created": "إنشاء باقة الشبكة الخاصة",
    "vpn_service_plan_updated": "تحديث باقة الشبكة الخاصة",
    "vpn_service_plan_disabled": "تعطيل باقة الشبكة الخاصة",
    "vpn_service_plan_enabled": "تفعيل باقة الشبكة الخاصة",
    "license_generated": "توليد ترخيص",
    "license_renewed": "تجديد ترخيص",
    "license_active": "تفعيل ترخيص",
    "license_suspended": "تعليق ترخيص",
    "license_revoked": "إلغاء ترخيص",
    "fingerprint_added": "إضافة بصمة خادم",
    "fingerprint_removed": "حذف بصمة خادم",
    "fingerprints_reset": "إعادة ضبط البصمات",
    "settings_updated": "تحديث الإعدادات",
    "payment_settings_updated": "تحديث إعدادات الدفع",
    "payment_request_created": "إنشاء طلب دفع",
    "license_payment_approved": "قبول دفع",
    "license_payment_rejected": "رفض دفع",
    "license_payments_expired": "إنهاء طلبات دفع منتهية",
    "payment_capacity_followup": "متابعة رفع حدود",
    "payment_setup_fee_recorded": "تسجيل رسوم تجهيز",
    "payment_license_renewed": "تجديد ترخيص من دفع",
    "payment_license_upgraded": "ترقية ترخيص من دفع",
    "payment_license_created": "إنشاء ترخيص من دفع",
}

ENTITY_TYPE_LABELS = {
    "admin": "مدير",
    "customer": "عميل",
    "customer_user": "مستخدم عميل",
    "customer_radius_admin": "أدمن راديوس",
    "customer_service_entitlement": "خدمة عميل",
    "customer_service_request": "طلب خدمة",
    "customer_vpn_entitlement": "خدمة الشبكة الخاصة للعميل",
    "customer_vpn_tunnel": "نفق VPN مركزي",
    "chr_settings": "إعدادات CHR",
    "plan": "خطة",
    "vpn_service_plan": "باقة الشبكة الخاصة",
    "license": "ترخيص",
    "settings": "إعدادات",
    "platform_payment_settings": "إعدادات الدفع",
    "license_payment_request": "طلب دفع",
    "provisioning_order": "أمر تجهيز",
    "batch": "دفعة",
}


def seed_service_catalog() -> None:
    for item in DEFAULT_SERVICE_CATALOG:
        existing = ServiceCatalogItem.query.filter_by(service_key=item["service_key"]).first()
        if existing:
            existing.name = item["name"]
            existing.name_ar = item["name_ar"]
            existing.description = item["description"]
            existing.category = item["category"]
            existing.default_enabled = item["default_enabled"]
            existing.sort_order = item["sort_order"]
            if existing.price_monthly in (None, Decimal("0")) and item["price_monthly"] is not None:
                existing.price_monthly = item["price_monthly"]
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
        raise CustomerControlValidationError(f"الحقل {field} يحتوي صيغة إعدادات غير صحيحة.") from exc
    if not isinstance(parsed, dict):
        raise CustomerControlValidationError(f"الحقل {field} يحتوي صيغة إعدادات غير صحيحة.")
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


def service_label(service_key: str) -> str:
    item = ServiceCatalogItem.query.filter_by(service_key=str(service_key or "")).first()
    if item:
        return item.name_ar or item.name or item.service_key
    return str(service_key or "—")


def role_label(role_key: str) -> str:
    return ROLE_LABELS.get(str(role_key or "").strip(), str(role_key or "—"))


def service_request_type_label(value: str) -> str:
    return SERVICE_REQUEST_TYPE_LABELS.get(str(value or "").strip(), str(value or "—"))


def service_request_status_label(value: str) -> str:
    return SERVICE_REQUEST_STATUS_LABELS.get(str(value or "").strip(), str(value or "—"))


def clean_service_request_status(value: str) -> str:
    status = str(value or "pending").strip().lower()
    if status not in SERVICE_REQUEST_STATUS_ALLOWLIST:
        raise CustomerControlValidationError("حالة طلب الخدمة غير مسموحة.")
    return status


def clean_service_request_sender_type(value: str) -> str:
    sender_type = str(value or "system").strip().lower()
    if sender_type not in SERVICE_REQUEST_SENDER_TYPES:
        raise CustomerControlValidationError("نوع مرسل الرسالة غير مسموح.")
    return sender_type


def generate_service_request_reference() -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    for _ in range(100):
        suffix = "".join(secrets.choice(alphabet) for _ in range(8))
        reference = f"SR-{suffix}"
        if not CustomerServiceRequest.query.filter_by(public_reference=reference).first():
            return reference
    raise RuntimeError("service_request_reference_collision")


def add_service_request_message(
    service_request: CustomerServiceRequest,
    *,
    body: str,
    sender_type: str = "system",
    event_type: str = "message",
    admin_id: int | None = None,
    customer_user_id: int | None = None,
    internal: bool = False,
    metadata: dict[str, Any] | None = None,
) -> CustomerServiceRequestMessage:
    text = str(body or "").strip()
    if not text:
        raise CustomerControlValidationError("نص الرسالة مطلوب.")
    message = CustomerServiceRequestMessage(
        service_request_id=service_request.id,
        customer_id=service_request.customer_id,
        admin_id=admin_id,
        customer_user_id=customer_user_id,
        sender_type=clean_service_request_sender_type(sender_type),
        event_type=str(event_type or "message").strip()[:60],
        body=text[:4000],
        internal=bool(internal),
    )
    message.message_metadata = metadata or {}
    db.session.add(message)
    return message


def visible_service_request_messages(service_request: CustomerServiceRequest):
    return service_request.messages.filter_by(internal=False).order_by(CustomerServiceRequestMessage.created_at.asc()).all()


def payment_purpose_label(value: str) -> str:
    return PAYMENT_PURPOSE_LABELS.get(str(value or "").strip(), str(value or "—"))


def audit_action_label(value: str) -> str:
    return AUDIT_ACTION_LABELS.get(str(value or "").strip(), "إجراء إداري")


def entity_type_label(value: str) -> str:
    return ENTITY_TYPE_LABELS.get(str(value or "").strip(), "سجل إداري")


def audit_summary_label(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return "—"
    replacements = (
        ("Admin logged out", "تم تسجيل خروج المدير"),
        ("Updated system settings", "تم تحديث إعدادات النظام"),
        ("Updated license payment settings", "تم تحديث إعدادات دفع التراخيص"),
    )
    for source, target in replacements:
        if text == source:
            return target
    if text.startswith("Admin ") and text.endswith(" logged in"):
        return "تم تسجيل دخول المدير " + text.removeprefix("Admin ").removesuffix(" logged in")
    prefix_map = {
        "Created customer ": "تم إنشاء العميل ",
        "Updated customer ": "تم تحديث العميل ",
        "Deleted customer ": "تم حذف العميل ",
        "Created plan ": "تم إنشاء الخطة ",
        "Updated plan ": "تم تحديث الخطة ",
        "Deleted plan ": "تم حذف الخطة ",
        "Created VPN service plan ": "تم إنشاء باقة الشبكة الخاصة ",
        "Updated VPN service plan ": "تم تحديث باقة الشبكة الخاصة ",
        "Disabled VPN service plan ": "تم تعطيل باقة الشبكة الخاصة ",
        "Enabled VPN service plan ": "تم تفعيل باقة الشبكة الخاصة ",
        "Generated license ": "تم توليد الترخيص ",
        "Added fingerprint to ": "تمت إضافة بصمة خادم إلى ",
        "Removed fingerprint from ": "تم حذف بصمة خادم من ",
        "Fingerprints reset for ": "تمت إعادة ضبط البصمات للترخيص ",
        "Created payment request ": "تم إنشاء طلب الدفع ",
        "Approved payment ": "تم قبول الدفع ",
        "Rejected payment ": "تم رفض الدفع ",
        "Updated VPN entitlement for ": "تم تحديث خدمة الشبكة الخاصة للعميل ",
    }
    for source, target in prefix_map.items():
        if text.startswith(source):
            return target + text[len(source):]
    if text.startswith("Renewed ") and " for " in text:
        license_key, months = text.removeprefix("Renewed ").split(" for ", 1)
        return f"تم تجديد الترخيص {license_key} لمدة {months.replace('month(s)', 'شهر')}"
    if text.startswith("License ") and " changed to " in text:
        license_key, status = text.removeprefix("License ").split(" changed to ", 1)
        return f"تغيرت حالة الترخيص {license_key} إلى {status}"
    if text.startswith("Expired ") and " pending payment request" in text:
        count = text.removeprefix("Expired ").split(" pending payment request", 1)[0]
        return f"تم إنهاء {count} طلب دفع منتهي"
    if any(("A" <= ch <= "Z") or ("a" <= ch <= "z") for ch in text):
        return "تفاصيل محفوظة في السجل"
    return text


def service_limit_fields(service_key: str) -> list[tuple[str, str, str]]:
    return list(SERVICE_LIMIT_FIELDS.get(str(service_key or ""), []))


def service_limit_summary(limits: dict[str, Any] | None) -> str:
    data = limits or {}
    if not data:
        return "لا توجد حدود خاصة"
    labels = {
        "max_total": "الحد الأقصى",
        "max_count": "أقصى عدد النسخ",
        "generate_per_batch": "الكروت في الدفعة",
        "monthly_generated": "الكروت شهريًا",
        "max_active": "العناصر الفعالة",
        "max_sellers": "البائعون",
        "max_wallets": "المحافظ",
    }
    parts = []
    for key, value in data.items():
        if value in (None, ""):
            continue
        # value may itself be a dict (e.g. nested limit); flatten to its number
        if isinstance(value, dict):
            value = value.get("max_count") or value.get("max_total") or next(iter(value.values()), "")
            if value in (None, ""):
                continue
        parts.append(f"{labels.get(str(key), str(key))}: {value}")
    return "، ".join(parts) if parts else "لا توجد حدود خاصة"


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
    limits = _limits_contract(lic, customer)
    # Gate-keyed view of the per-service state for the radius web-admin gate
    # (its 14 section keys), aggregated from the ~45 provider services above.
    from .provider_service_gate import build_provider_grants
    provider_grants = build_provider_grants(services)
    contract = {
        # The radius lifecycle gate reads this to decide activated-vs-locked.
        # We emit redundant aliases (status/state, active/activated) so whichever
        # field the gate keys on, an active license unlocks the panel. ``state``
        # mirrors ``status``; ``activated`` is True whenever a license record
        # exists (it was activated at least once) — distinct from ``active``
        # which is the live validity (expiry/suspension) check.
        "license": {
            "active": bool(license_active),
            "activated": lic is not None,
            "status": license_status,
            "state": license_status,
            "license_key": lic.license_key if lic else None,
            "expires_at": iso_z(lic.expires_at) if lic else None,
            "grace_until": iso_z(lic.grace_until) if lic else None,
        },
        "customer": {
            "id": customer.id if customer else None,
            "company_name": customer.company_name if customer else "",
            "runtime_url": customer.runtime_url if customer else "",
            "portal_config": customer.portal_config if customer else {},
        },
        "services": services,
        # provider_grants is the radius gate's source of truth: each of its 14
        # section keys → {enabled, status, hidden, limits?}. A section the owner
        # disabled/hid/limited now reaches the radius under a key its gate reads.
        "provider_grants": provider_grants,
        "limits": limits,
        "customer_users_version": customer_users_version(customer) if customer else 0,
        # The bridge_token rotation block was retired with the linking-auth
        # cleanup — there is nothing to rotate; the license key IS the
        # credential and the customer-radius reads it directly from the
        # owner's panel.
    }
    # Change-detection fingerprint over the parts the radius enforces, so it can
    # cheaply tell the contract changed (e.g. after the owner saves the tariff)
    # and re-apply on its next sync without diffing the whole payload.
    contract["fingerprint"] = _contract_fingerprint(
        services, provider_grants, limits, contract["customer_users_version"])
    return contract


def _contract_fingerprint(services: dict, provider_grants: dict, limits: dict,
                          users_version: int) -> str:
    """Stable sha256 over the enforced parts of the contract (order-insensitive)."""
    import hashlib
    import json
    blob = json.dumps(
        {"services": services, "provider_grants": provider_grants,
         "limits": limits, "customer_users_version": users_version},
        sort_keys=True, ensure_ascii=False, default=str,
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


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
            "admin_super_overrides": [],
        }
    users = []
    for user in customer.users.order_by(CustomerUser.id.asc()).all():
        users.append({
            "external_user_id": user.id,
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "role_key": user.role_key,
            # علم السوبر الصريح المرسل للراديوس: يضبط is_super_admin=1 دائماً ولا
            # يعتمد على تخمين role_key. يبقى owner سوبراً ضمنياً للتوافق.
            "is_super": user.is_effective_super,
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
        # تعليمات فرض السوبر على أدمن الراديوس المحليين (غير المُدارين بالهوية).
        # الراديوس يطبّقها idempotent في كل مزامنة: يضبط is_super_admin=1 لهؤلاء
        # دون المساس بكلمة المرور أو مزوّد الهوية، فلا ينكسر الدخول المحلي.
        "admin_super_overrides": build_admin_super_overrides(customer),
    }


def build_admin_super_overrides(customer: Customer) -> list[dict[str, Any]]:
    """قائمة تعليمات فرض السوبر على أدمن الراديوس المحليين لهذا العميل.

    تُرسل ضمن عقد مزامنة الهوية ليطبّقها الراديوس على أدمنياته المحلية. تشمل فقط
    الصفوف المفعّل عليها ``force_super`` في اللوحة. المطابقة على الراديوس بالـ
    ``radius_admin_id`` أولاً ثم ``username`` احتياطاً.
    """
    rows = (
        CustomerRadiusAdmin.query
        .filter_by(customer_id=customer.id, force_super=True)
        .order_by(CustomerRadiusAdmin.radius_admin_id.asc())
        .all()
    )
    return [
        {
            "radius_admin_id": row.radius_admin_id,
            "username": row.username,
            "is_super": True,
        }
        for row in rows
    ]


def radius_admins_for_customer(customer: Customer) -> list[CustomerRadiusAdmin]:
    """لقطة أدمن الراديوس المخزّنة لهذا العميل (للعرض في تفاصيل العميل).

    الأدمن الرئيسي أولاً كي يظهر في صدارة القائمة.
    """
    return (
        CustomerRadiusAdmin.query
        .filter_by(customer_id=customer.id)
        .order_by(CustomerRadiusAdmin.is_primary.desc(), CustomerRadiusAdmin.radius_admin_id.asc())
        .all()
    )


def import_radius_admins(
    customer: Customer,
    license_obj: License | None,
    admins: list[Any],
) -> int:
    """تحديث لقطة أدمن الراديوس من بلاغ الراديوس (القناة العكسية للجسر).

    upsert idempotent بالمفتاح (customer_id, radius_admin_id). الحقل المملوك
    للّوحة ``force_super`` لا يُداس هنا أبداً — الراديوس يبلّغ بحالته الواقعة فقط،
    واللوحة هي من تتحكم بالفرض. يتجاهل العناصر بلا معرّف رقمي صالح.
    """
    if not isinstance(admins, list):
        return 0
    now = utcnow()
    imported = 0
    for raw in admins[:200]:  # سقف دفاعي على حجم الدفعة.
        if not isinstance(raw, dict):
            continue
        try:
            radius_admin_id = int(raw.get("id") if raw.get("id") is not None else raw.get("radius_admin_id"))
        except (TypeError, ValueError):
            continue
        row = CustomerRadiusAdmin.query.filter_by(
            customer_id=customer.id, radius_admin_id=radius_admin_id
        ).first()
        if row is None:
            row = CustomerRadiusAdmin(customer_id=customer.id, radius_admin_id=radius_admin_id)
            db.session.add(row)
        if license_obj is not None:
            row.license_id = license_obj.id
        row.username = str(raw.get("username") or "").strip()[:80]
        row.role = str(raw.get("role") or "").strip()[:40]
        row.is_super_admin = bool(raw.get("is_super_admin"))
        row.is_primary = bool(raw.get("is_primary"))
        row.enabled = bool(raw.get("enabled", True))
        row.managed_by_license_admin = bool(raw.get("managed_by_license_admin"))
        row.external_identity_provider = str(raw.get("external_identity_provider") or "").strip()[:40]
        row.last_seen_at = now
        imported += 1
    return imported


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
    req_type = str(request_type or "activation").strip()[:40]
    svc_name = service_label(key)
    row = CustomerServiceRequest(
        public_reference=generate_service_request_reference(),
        customer_id=customer.id,
        customer_user_id=customer_user_id,
        service_key=key,
        request_type=req_type,
        title=f"{service_request_type_label(req_type)} - {svc_name}",
        status="pending",
        notes=str(notes or "").strip()[:2000],
    )
    row.desired_limits = desired_limits or {}
    db.session.add(row)
    db.session.flush()
    add_service_request_message(
        row,
        sender_type="customer" if customer_user_id else "system",
        customer_user_id=customer_user_id,
        event_type="created",
        body=str(notes or "").strip() or f"تم فتح طلب {service_request_type_label(req_type)} لخدمة {svc_name}.",
    )
    add_service_request_message(
        row,
        sender_type="system",
        event_type="notification",
        internal=True,
        body=(
            "تم تجهيز إشعار داخلي للإدارة والعميل. "
            "إرسال الرسائل النصية يعتمد على مزود الرسائل عند ربطه من الإعدادات."
        ),
        metadata={
            "customer_phone": customer.phone,
            "service_key": key,
            "request_type": req_type,
        },
    )
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

    # ── EFFECTIVE TIER (feat/services-catalog-policy) ──────────────────
    # Explicit per-subscriber tier (the /service-tiers page) always wins;
    # otherwise the owner's CATALOG default («الخدمات» page) applies. The
    # catalog default for everything is paid until the owner says otherwise,
    # so pre-existing behaviour is unchanged for untouched services.
    tier, tier_source = effective_service_tier(entitlement, catalog_item)

    # Free-limited basic quantities: an explicit per-subscriber limits dict
    # wins; otherwise the catalog's basic quantities flow into the contract
    # so the radius side enforces them and the portal can display them.
    if tier == SERVICE_TIER_FREE_LIMITED and not limits:
        catalog_limits = catalog_default_limits(catalog_item)
        if catalog_limits:
            limits = catalog_limits

    # ── FREE TIER OVERRIDE ─────────────────────────────────────────────
    # When this service is free for the subscriber (per-subscriber override
    # OR catalog default), the service is available regardless of the
    # entitlement.enabled flag — the owner's tier choice is the source of
    # truth. (Paid tier keeps the old gating: the customer must request
    # activation + pay.) An explicit SUSPENSION always beats the free tier:
    # suspended is the functional stop and only the owner lifts it — a free
    # tier must never silently resurrect a suspended service.
    if service_tier_is_free(tier) and license_active and status != "suspended":
        if not (expires_at and expires_at < utcnow()):
            enabled = True
            status = "active"

    if not license_active:
        enabled = False
        if status == "active":
            status = license_status if license_status in SERVICE_STATUS_ALLOWLIST else "disabled"

    payload: dict[str, Any] = {
        "enabled": enabled,
        "status": status,
        "tier": tier,
        "tier_source": tier_source,
        "tier_label": SERVICE_TIER_BADGE_LABELS.get(tier, SERVICE_TIER_BADGE_LABELS[SERVICE_TIER_DEFAULT]),
        "tier_tone": SERVICE_TIER_BADGE_TONE.get(tier, "violet"),
        # free_limited is upgradable by design («قابلة للتطوير») — the portal
        # shows a ترقية CTA; paid-disabled keeps the طلب تفعيل CTA.
        "upgradable": tier == SERVICE_TIER_FREE_LIMITED,
        # DECLUTTER flag («إخفاء للترتيب»): a VIEW-only tidiness choice — the
        # provider hides a service this customer doesn't need so their panel is
        # clean. The radius removes it from the CUSTOMER's panel nav (operator
        # view) AND the end-user portal, but it is NOT a commercial block: no
        # 403, fully reversible, functionality untouched. Distinct from a
        # «موقوفة» suspend (status=="suspended" → gate "disabled" → hide+403).
        "hidden": service_is_hidden(entitlement),
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

    # ── FULLY-HIDDEN-UNTIL-GRANTED («الجهات»/multi_tenant) ─────────────────
    # A distinct state from locked_upgrade: the customer doesn't see it AT ALL
    # (no sidebar item, no «طلب تفعيل») until the provider explicitly grants it.
    # When granted, the provider sets entity_count + per-entity limit set, which
    # ride in entitlement.config and flow out here. The radius reads
    # ``visibility`` ("hidden" | "granted") to decide whether to render anything.
    if key in HIDDEN_UNTIL_GRANTED_SERVICES:
        granted = bool(entitlement and entitlement.enabled and status == "active"
                       and (config or {}).get("visibility") == "granted")
        payload["visibility"] = "granted" if granted else "hidden"
        if not granted:
            payload["enabled"] = False
            payload["status"] = "hidden"
            payload["upgradable"] = False
            payload["hidden"] = True
            payload.pop("limits", None)
        else:
            payload["entity_count"] = int((config or {}).get("entity_count") or 0)
            payload["per_entity_limits"] = (config or {}).get("per_entity_limits") or {}

    return payload


def _limits_contract(lic: License | None, customer: Customer | None = None) -> dict[str, Any]:
    if not lic or not lic.plan:
        return {}
    # The plan capacity the provider SELLS is the instance-wide CONCURRENT-ONLINE
    # ceiling: the max number of simultaneously-connected (live/online) sessions
    # across ALL session types — cards + subscribers + broadband/PPPoE + hotspot.
    # Every live session = 1 active. It is NOT the number of accounts created.
    #
    # Canonical contract field: ``limits.active_online.max`` — the radius MUST
    # enforce this as the global concurrent-online cap (reject/disconnect new
    # online sessions once the live count across all types hits it). 0 ⇒ unlimited
    # («حزمة لا محدودة»). We also mirror it onto ``subscribers.max_active``/
    # ``max_total`` for back-compat with older radius builds; the authoritative
    # instance-wide ceiling is ``active_online.max``.
    _cap = int(lic.plan.max_users or 0)
    limits = {
        "active_online": {"max": _cap, "scope": "instance", "counts": "all_session_types"},
        "subscribers": {"max_total": _cap, "max_active": _cap},
        "nas": {"max_total": int(lic.plan.max_nas or 0)},
        "admins": {"max_total": int(lic.plan.max_admins or 0)},
        "devices": {"max_total": int(lic.plan.max_devices or 0)},
    }
    if not customer:
        return limits
    entitlement_map = customer_service_map(customer)
    catalog_map = {item.service_key: item for item in service_catalog_items()}
    for service_key in SERVICE_LIMIT_FIELDS:
        entitlement = entitlement_map.get(service_key)
        # Catalog free-limited default (feat/services-catalog-policy): when
        # the owner made a service «مجاني محدود» globally and the subscriber
        # has no explicit entitlement limits, the catalog's basic quantities
        # are the enforced caps — carried in the contract exactly like
        # entitlement limits so the radius side gates identically.
        eff_tier, _src = effective_service_tier(entitlement, catalog_map.get(service_key))
        if eff_tier == SERVICE_TIER_FREE_LIMITED:
            catalog_caps = catalog_default_limits(catalog_map.get(service_key))
            entitlement_limits = (entitlement.limits if entitlement else {}) or {}
            merged = dict(catalog_caps)
            merged.update({
                key: int(value)
                for key, value in entitlement_limits.items()
                if _is_non_negative_int(value)
            })
            if merged:
                limits.setdefault(service_key, {})
                limits[service_key].update(merged)
            continue
        if not entitlement or not entitlement.enabled or entitlement.status != "active":
            continue
        service_limits = entitlement.limits
        if not service_limits:
            continue
        limits.setdefault(service_key, {})
        limits[service_key].update({
            key: int(value)
            for key, value in service_limits.items()
            if _is_non_negative_int(value)
        })
    # Backup retention cap always travels in the contract (local backups exist
    # regardless of the paid panel-upload service). Admin-set per customer via
    # the backups service limits; defaults to 60 when unset.
    bk_ent = entitlement_map.get("backups")
    bk_max = 0
    if bk_ent and bk_ent.limits:
        try:
            bk_max = int(bk_ent.limits.get("max_count") or 0)
        except (TypeError, ValueError):
            bk_max = 0
    limits.setdefault("backups", {})["max_count"] = bk_max if bk_max > 0 else 60
    return limits


def _is_non_negative_int(value: Any) -> bool:
    try:
        return int(value) >= 0
    except (TypeError, ValueError):
        return False


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
