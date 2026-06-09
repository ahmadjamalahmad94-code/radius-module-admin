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
