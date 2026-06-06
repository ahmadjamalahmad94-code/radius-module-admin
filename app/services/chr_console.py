"""وحدة تحكّم CHR المركزية — طبقة خدمة رقيقة فوق :class:`RouterOSClient`.

تعطي اللوحةَ تحكّمًا كاملًا في CHR المملوك مركزيًا هنا (إدارة مستخدمي الأنفاق على
``/ppp/secret``، مستخدمي/هويات IPsec، عرض الجلسات النشطة والواجهات ومورد النظام،
وإجراءات إدارية آمنة). القواعد:

* المكان الوحيد الذي يلمس الشبكة هو :func:`chr_settings.build_client` ← REST.
* القراءات لا ترفع أبدًا عند تعذّر الوصول — تعيد ``{"ok": False, "message": …}``
  برسالة عربية كي لا تنهار الصفحة وتُظهر الحالة فقط.
* التعديلات (تعطيل/تفعيل/حذف/إعادة تشغيل) حسّاسة: تحصرها طبقة المسار بمسؤول عام
  مع تأكيد صريح وتدقيق؛ هنا نكتفي بتنفيذها وإرجاع نتيجة منظّمة.
* لا تُعاد ولا تُسجَّل أي أسرار CHR (كلمة مرور admin) — هذه الوحدة لا تقرأها أصلًا.
"""
from __future__ import annotations

from flask import current_app

from . import chr_settings
from .routeros_client import RouterOSError


def enabled() -> bool:
    """الوحدة مفعّلة فقط حين يكون علم الإعداد مرفوعًا وتزويد CHR مفعّلًا."""
    return bool(current_app.config.get("CHR_CONSOLE_ENABLED", True)) and chr_settings.enabled()


def _client():
    return chr_settings.build_client()


def _fail(exc) -> dict:
    """يحوّل أي خطأ اتصال/إعداد إلى نتيجة منظّمة برسالة عربية (دون كشف تفاصيل خام)."""
    code = getattr(exc, "code", "error")
    message = getattr(exc, "message", None) or str(exc)
    return {"ok": False, "code": code, "message": message}


# ───────────────────────── reads (never raise) ─────────────────────────

def status() -> dict:
    """فحص حيوية + معلومات نظام موجزة. يعيد ``ok=False`` عند تعذّر الوصول."""
    try:
        info = _client().test_connection()
    except chr_settings.ChrSettingsError as exc:
        return {"ok": False, "code": "not_configured", "message": str(exc)}
    except RouterOSError as exc:
        return _fail(exc)
    return {"ok": True, **info}


def overview() -> dict:
    """لقطة كاملة للوحدة: النظام + الأعداد + قوائم (PPP/IPsec/واجهات/جلسات).

    لا يرفع: عند تعذّر الوصول يعيد ``{"ok": False, "message": …}`` فقط، فتعرض
    الصفحة شارة «تعذّر الوصول» دون أي انهيار.
    """
    try:
        client = _client()
    except chr_settings.ChrSettingsError as exc:
        return {"ok": False, "code": "not_configured", "message": str(exc)}
    try:
        resource = client.system_resource()
        identity = client.system_identity()
        ppp_secrets = client.list_ppp_secrets()
        ppp_active = client.list_ppp_active()
        ipsec_users = client.list_ipsec_users()
        ipsec_identities = client.list_ipsec_identities()
        ipsec_active = client.list_ipsec_active_peers()
        interfaces = client.list_interfaces()
    except RouterOSError as exc:
        return _fail(exc)
    return {
        "ok": True,
        "system": {
            "identity": str(identity.get("name") or ""),
            "version": str(resource.get("version") or ""),
            "board_name": str(resource.get("board-name") or ""),
            "uptime": str(resource.get("uptime") or ""),
            "cpu_load": str(resource.get("cpu-load") or ""),
            "free_memory": str(resource.get("free-memory") or ""),
            "total_memory": str(resource.get("total-memory") or ""),
        },
        "ppp_secrets": ppp_secrets,
        "ppp_active": ppp_active,
        "ipsec_users": ipsec_users,
        "ipsec_identities": ipsec_identities,
        "ipsec_active": ipsec_active,
        "interfaces": interfaces,
        "counts": {
            "ppp_secrets": len(ppp_secrets),
            "ppp_active": len(ppp_active),
            "ipsec_users": len(ipsec_users),
            "ipsec_active": len(ipsec_active),
            "interfaces": len(interfaces),
        },
    }


# ───────────────────────── mutations (route guards + audits) ─────────────────────────

def _do(action) -> dict:
    """ينفّذ تعديلًا ويغلّف الأخطاء في نتيجة منظّمة (لا يرفع)."""
    try:
        action(_client())
    except chr_settings.ChrSettingsError as exc:
        return {"ok": False, "code": "not_configured", "message": str(exc)}
    except RouterOSError as exc:
        return _fail(exc)
    return {"ok": True}


def set_ppp_secret_disabled(secret_id: str, disabled: bool) -> dict:
    return _do(lambda c: c.set_ppp_secret_disabled(secret_id, disabled))


def remove_ppp_secret(secret_id: str) -> dict:
    return _do(lambda c: c.remove_ppp_secret(secret_id))


def set_ipsec_user_disabled(user_id: str, disabled: bool) -> dict:
    return _do(lambda c: c.set_ipsec_user_disabled(user_id, disabled))


def remove_ipsec_user(user_id: str) -> dict:
    return _do(lambda c: c.remove_ipsec_user(user_id))


def reboot() -> dict:
    return _do(lambda c: c.reboot())
