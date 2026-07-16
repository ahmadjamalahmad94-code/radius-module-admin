"""RBAC لمديري اللوحة — أربعة أدوار مُنفَّذة فعليًا (إعادة تصميم 2026-07).

قبل هذا كانت الأدوار الأربع في الواجهة تنهار كلها إلى ``Admin.is_super_admin``
الثنائية (تسميات بلا أثر). هنا نعطيها أسنانًا:

الأدوار (``Admin.role_key``):
* ``super_admin`` — كل شيء، يتجاوز كل الفحوص (المالك/المسؤول العام).
* ``operator``  — إدارة العملاء/التراخيص/البطاقات/الجلسات؛ لا إعدادات ولا مشرفين ولا خزنة.
* ``support``   — عرض + فصل الجلسات فقط؛ لا تعديل ولا حذف ولا إعدادات.
* ``viewer``    — عرض فقط.

الإنفاذ **مركزيّ** (before_request على البلوبرنتات الإدارية) لتفادي وسم 168
مسارًا يدويًا: تُصنَّف نقطة النهاية إلى قدرة مطلوبة، ثم يُطابَق دور المدير معها.
القاعدة العامة: القراءة (GET) = ``view`` لأي مدير مُفعَّل؛ الكتابة
(POST/PATCH/PUT/DELETE) تتطلب قدرة المجال؛ المجالات الحساسة كلها super.
"""
from __future__ import annotations

# ── الأدوار ──────────────────────────────────────────────────────────────
ROLE_SUPER = "super_admin"
ROLE_OPERATOR = "operator"
ROLE_SUPPORT = "support"
ROLE_VIEWER = "viewer"

ROLE_KEYS = (ROLE_SUPER, ROLE_OPERATOR, ROLE_SUPPORT, ROLE_VIEWER)

ROLE_LABELS_AR = {
    ROLE_SUPER: "مشرف عام",
    ROLE_OPERATOR: "مشرف تشغيلي",
    ROLE_SUPPORT: "دعم فني",
    ROLE_VIEWER: "مشاهد",
}

# ── القدرات ──────────────────────────────────────────────────────────────
CAP_VIEW = "view"
CAP_DISCONNECT = "disconnect_session"
CAP_MANAGE_CUSTOMERS = "manage_customers"
CAP_MANAGE_LICENSES = "manage_licenses"
CAP_MANAGE_SETTINGS = "manage_settings"   # إعدادات/مشرفون/خزنة/تحديثات — super فقط

ROLE_CAPS: dict[str, frozenset[str]] = {
    ROLE_SUPER: frozenset({
        CAP_VIEW, CAP_DISCONNECT, CAP_MANAGE_CUSTOMERS,
        CAP_MANAGE_LICENSES, CAP_MANAGE_SETTINGS,
    }),
    ROLE_OPERATOR: frozenset({
        CAP_VIEW, CAP_DISCONNECT, CAP_MANAGE_CUSTOMERS, CAP_MANAGE_LICENSES,
    }),
    ROLE_SUPPORT: frozenset({CAP_VIEW, CAP_DISCONNECT}),
    ROLE_VIEWER: frozenset({CAP_VIEW}),
}


def role_of(admin) -> str:
    """دور المدير المُطبَّع. ``is_super_admin`` يفوز دائمًا (المالك لا يُحبس)."""
    if admin is None:
        return ROLE_VIEWER
    if getattr(admin, "is_super_admin", False):
        return ROLE_SUPER
    key = (getattr(admin, "role_key", "") or "").strip().lower()
    return key if key in ROLE_KEYS else ROLE_OPERATOR


def can(admin, capability: str) -> bool:
    return capability in ROLE_CAPS.get(role_of(admin), frozenset())


def super_from_role(role_key: str) -> bool:
    """تزامن ``is_super_admin`` مع الدور المختار (مصدر حقيقة واحد)."""
    return (role_key or "").strip().lower() == ROLE_SUPER


def clean_role(role_key: str) -> str:
    key = (role_key or "").strip().lower()
    return key if key in ROLE_KEYS else ROLE_OPERATOR


# ── تصنيف نقطة النهاية إلى قدرة مطلوبة ───────────────────────────────────
# نقاط النهاية الحساسة (super فقط) — بادئات endpoint. أي كتابة عليها ترفض
# لغير المسؤول العام حتى لو نُسي @super_admin_required.
_SUPER_ONLY_PREFIXES = (
    "admin.settings", "admin.sections_settings", "admin.updates",
    "admin.update_", "admin_messaging.", "admin_landing.",
    "admin_vault.", "admin.settings_admins", "admin_chr.",
)
_SUPER_ONLY_SUBSTR = ("vault", "tweetsms", "whatsapp_cloud", "whatsapp_embedded", "panel_admins")

# نقاط النهاية التي تُعدّل الجلسات (يسمح بها support) — بالتطابق الجزئي.
_DISCONNECT_SUBSTR = ("disconnect", "kick", "reconcile")

_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


# خدمة ذاتية لحساب المدير نفسه (2FA) — أي مدير مُفعَّل يديرها ولو غير super.
_SELF_SERVICE_ENDPOINTS = frozenset({
    "admin.settings_security", "admin.settings_2fa_begin",
    "admin.settings_2fa_enable", "admin.settings_2fa_disable",
})


def required_capability(endpoint: str, method: str) -> str:
    """القدرة اللازمة لخدمة (endpoint, method). القراءة دائمًا ``view``."""
    ep = endpoint or ""
    if ep in _SELF_SERVICE_ENDPOINTS:
        return CAP_VIEW
    if (method or "GET").upper() not in _WRITE_METHODS:
        return CAP_VIEW
    # الكتابة على مجال حساس ⇒ super
    if ep.startswith(_SUPER_ONLY_PREFIXES) or any(s in ep for s in _SUPER_ONLY_SUBSTR):
        return CAP_MANAGE_SETTINGS
    # كتابة تخص الجلسات ⇒ support يكفي
    if any(s in ep for s in _DISCONNECT_SUBSTR):
        return CAP_DISCONNECT
    # كتابة على التراخيص/المدفوعات/الخطط
    if ep.startswith(("admin.license", "admin.plan", "admin.subscription",
                      "admin.discount", "admin.payment")) or "payment" in ep:
        return CAP_MANAGE_LICENSES
    # بقية الكتابة = إدارة عملاء/بنية عامة ⇒ operator
    return CAP_MANAGE_CUSTOMERS
