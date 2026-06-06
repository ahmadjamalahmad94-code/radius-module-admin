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


# أكواد تعني «القائمة غير مُهيّأة/غير موجودة على هذا CHR» لا «عطل حقيقي». حين تكون
# بقية الأقسام تعمل (الاتصال/المصادقة سليمة) نعامل هذه على أنها قائمة فارغة (حالة
# فارغة) بدل إظهار خطأ «Bad Request» لقائمة لم تُهيّأ بعد.
_SOFT_EMPTY_CODES = ("request_invalid", "not_found")


def _section(label: str, fetch, *, soft_empty: bool = False) -> dict:
    """يجلب قسمًا واحدًا مستقلًّا. أي فشل (شبكة/مصادقة) يبقى محصورًا في هذا القسم
    فيُعرَض «غير متاح» دون إسقاط بقية الوحدة. يعيد {available, rows, error, code}.

    ``soft_empty=True``: إن رفض CHR هذه القائمة بـ 400/404 (قائمة غير مُهيّأة على هذا
    الجهاز) نعيدها كقائمة فارغة (حالة فارغة) لا كخطأ — يُحجز الخطأ للأعطال الحقيقية."""
    try:
        rows = fetch()
    except RouterOSError as exc:
        if soft_empty and exc.code in _SOFT_EMPTY_CODES:
            return {"available": True, "rows": [], "error": "", "code": exc.code,
                    "label": label, "soft_empty": True}
        return {"available": False, "rows": [], "error": exc.message, "code": exc.code, "label": label}
    return {"available": True, "rows": rows, "error": "", "code": "", "label": label}


def _system_section(client) -> dict:
    """قسم النظام/الهوية مستقلّ أيضًا (نفس مسارات اختبار الاتصال الناجح)."""
    try:
        resource = client.system_resource()
        identity = client.system_identity()
    except RouterOSError as exc:
        return {"available": False, "error": exc.message, "code": exc.code}
    return {
        "available": True,
        "error": "",
        "identity": str(identity.get("name") or ""),
        "version": str(resource.get("version") or ""),
        "board_name": str(resource.get("board-name") or ""),
        "uptime": str(resource.get("uptime") or ""),
        "cpu_load": str(resource.get("cpu-load") or ""),
        "free_memory": str(resource.get("free-memory") or ""),
        "total_memory": str(resource.get("total-memory") or ""),
    }


def overview() -> dict:
    """لقطة الوحدة. **كل قسم يُجلب مستقلًّا**: إن رفض CHR نداءً واحدًا (مثلاً 400 على
    مسار REST معيّن) يبقى الخطأ محصورًا في قسمه ويُعرَض «غير متاح»، وتظل بقية الأقسام
    تعمل — لا تنهار الوحدة كلها برسالة واحدة. لا يرفع أبدًا.

    * ``ok=False`` فقط حين لا يكون CHR مضبوطًا (تعذّر بناء العميل).
    * ``reachable=False`` حين كان مضبوطًا لكن لم يستجب أي قسم (انقطاع كامل).
    """
    try:
        client = _client()
    except chr_settings.ChrSettingsError as exc:
        return {"ok": False, "reachable": False, "code": "not_configured", "message": str(exc)}

    system = _system_section(client)
    sections = {
        "ppp_secrets": _section("مستخدمو الأنفاق (PPP)", client.list_ppp_secrets),
        "ppp_active": _section("جلسات PPP النشطة", client.list_ppp_active),
        # قائمة مستخدمي IPsec قد تكون غير مُهيّأة على بعض أجهزة CHR فترجع 400/404؛
        # نعاملها كفارغة (حالة فارغة) لا كعطل. رؤية IKEv2 تبقى عبر الهويات والجلسات.
        "ipsec_users": _section("مستخدمو IPsec", client.list_ipsec_users, soft_empty=True),
        "ipsec_identities": _section("هويات IPsec", client.list_ipsec_identities),
        "ipsec_active": _section("جلسات IPsec النشطة", client.list_ipsec_active_peers),
        "interfaces": _section("الواجهات", client.list_interfaces),
    }
    reachable = system.get("available") or any(s["available"] for s in sections.values())
    return {
        "ok": True,
        "reachable": bool(reachable),
        "system": system,
        "sections": sections,
        "counts": {key: len(sec["rows"]) for key, sec in sections.items()},
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
