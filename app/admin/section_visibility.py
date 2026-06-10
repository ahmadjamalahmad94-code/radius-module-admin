"""
section_visibility.py — helper لإظهار/إخفاء أقسام السايدبار.
يخزن الإعدادات في جدول settings الموجود باستخدام البادئة "sv:".
"""
from __future__ import annotations

from typing import Set

# البادئة المستخدمة لمفاتيح الإعدادات
_PREFIX = "sv:"

# الأقسام والصفحات الافتراضية (كلها مرئية بالبداية)
DEFAULT_SECTIONS: dict[str, bool] = {
    # العملاء
    "customers":         True,
    "customers.list":    True,
    "customers.add":     True,
    # التراخيص
    "licenses":          True,
    "licenses.list":     True,
    "licenses.create":   True,
    "licenses.plans":    True,
    # VPN
    "vpn":               True,
    "vpn.tunnels":       True,
    # البنية التحتية
    "infra":             True,
    "infra.chr":         True,
    "infra.proxy":       True,
    "infra.macros":      True,
    # السجلات
    "logs":              True,
    "logs.audit":        True,
    "logs.health":       True,
    # الإعدادات
    "settings":          True,
    "settings.general":  True,
    "settings.admins":   True,
    "settings.whatsapp": True,
}


def get_hidden_sections() -> Set[str]:
    """يُعيد مجموعة مفاتيح الأقسام المخفية."""
    try:
        from ..extensions import db
        from ..models import Setting

        rows = (
            Setting.query
            .filter(Setting.key.like(f"{_PREFIX}%"))
            .all()
        )
        return {
            row.key[len(_PREFIX):]
            for row in rows
            if row.value == "0"
        }
    except Exception:
        return set()


def save_visibility(data: dict) -> None:
    """
    يحفظ حالة الإظهار/الإخفاء.
    data: {section_key: True/False, ...}
    """
    from ..extensions import db
    from ..models import Setting

    for key, visible in data.items():
        if key not in DEFAULT_SECTIONS:
            continue
        setting_key = f"{_PREFIX}{key}"
        row = Setting.query.get(setting_key)
        if row is None:
            row = Setting(key=setting_key)
            db.session.add(row)
        row.value = "1" if visible else "0"

    db.session.commit()


# ────────────────────────────────────────────────────────────────────────────
# FIX #4 of mock-inventory remediation — server-side enforcement.
#
# Until now, hiding a section only removed its sidebar link; direct URLs
# still returned 200. ``endpoint_to_section()`` maps a Flask endpoint to
# the most-specific section key it belongs to, and ``is_endpoint_hidden()``
# answers "is this endpoint blocked by the current visibility settings".
#
# Conservative pass-through list: endpoints that must NEVER be blockable
# (login, the visibility settings page itself, the dashboard, the i18n
# switcher) — otherwise the operator could lock themselves out of the
# panel by hiding the wrong tile and have no way to recover.
# ────────────────────────────────────────────────────────────────────────────


#: Endpoints that are always reachable regardless of visibility settings.
ALWAYS_VISIBLE_ENDPOINTS = frozenset({
    # Static + auth
    "static",
    "auth.login",
    "auth.login_post",
    "auth.logout",
    # Root + universal admin
    "admin.dashboard",
    "admin.sections_settings",   # the visibility editor itself — safety valve
    "admin.settings_page",
    "admin.settings_section_save",
    "admin.settings_admins",
    "admin.settings_admins_post",
    # API + integration (server-to-server; not user-visible)
    # (matched by prefix below)
})

#: Endpoints that are always reachable regardless of visibility settings
#: (URL-prefix variant). These are owned by side-channel blueprints whose
#: routes must keep working even if the matching nav tile is hidden.
ALWAYS_VISIBLE_PREFIXES = (
    "api.",
    "proxy_api.",
    "public.",
)


#: Map Flask endpoints → the section-visibility key that gates them.
#: Only the keys in ``DEFAULT_SECTIONS`` are honored as gates; an endpoint
#: that maps to a key NOT in DEFAULT_SECTIONS is treated as always-visible.
#: Order matters for the `endpoint_to_section()` fallback (longest prefix wins).
_ENDPOINT_PREFIX_MAP = (
    # Customers
    ("admin.customers_list",            "customers.list"),
    ("admin.customer_new",              "customers.add"),
    ("admin.customer_create",           "customers.add"),
    ("admin.customer_",                 "customers"),       # any other customer.* route
    # Licenses
    ("admin.licenses_list",             "licenses.list"),
    ("admin.license_new",               "licenses.create"),
    ("admin.license_create",            "licenses.create"),
    ("admin.plans_list",                "licenses.plans"),
    ("admin.plan_",                     "licenses.plans"),
    ("admin.license_",                  "licenses"),
    # VPN
    ("admin.vpn_",                      "vpn.tunnels"),
    ("admin.customer_vpn_",             "vpn.tunnels"),
    ("admin_chr.",                      "infra.chr"),
    # Infra
    ("admin_infra.chr",                 "infra.chr"),
    ("admin_infra.proxy",               "infra.proxy"),
    ("admin_infra.",                    "infra"),
    # Logs
    ("admin.audit_logs",                "logs.audit"),
    ("admin.checks_list",               "logs.health"),
    ("admin.renewals_list",             "logs"),
    # Settings sub-pages
    ("admin.settings_whatsapp",         "settings.whatsapp"),
    ("admin.whatsapp_",                 "settings.whatsapp"),
)


def endpoint_to_section(endpoint: str) -> str | None:
    """Return the section-visibility key for ``endpoint``, or ``None`` if no
    gate applies (the endpoint is treated as always reachable)."""
    if not endpoint:
        return None
    if endpoint in ALWAYS_VISIBLE_ENDPOINTS:
        return None
    for prefix in ALWAYS_VISIBLE_PREFIXES:
        if endpoint.startswith(prefix):
            return None
    # Longest-prefix-first lookup.
    for prefix, section in sorted(_ENDPOINT_PREFIX_MAP, key=lambda p: -len(p[0])):
        if endpoint == prefix or endpoint.startswith(prefix):
            return section
    return None


def is_endpoint_hidden(endpoint: str) -> bool:
    """``True`` if ``endpoint`` is currently blocked by visibility settings.

    A section is blocked when the section itself OR any of its parents is in
    ``get_hidden_sections()`` — e.g. hiding the umbrella ``infra`` group
    also blocks ``infra.chr`` and ``infra.proxy``.
    """
    section = endpoint_to_section(endpoint)
    if not section:
        return False
    hidden = get_hidden_sections()
    if not hidden:
        return False
    parts = section.split(".")
    for i in range(1, len(parts) + 1):
        candidate = ".".join(parts[:i])
        if candidate in hidden:
            return True
    return False
