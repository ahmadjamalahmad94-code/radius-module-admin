"""وحدة تحكّم CHR — طبقة خدمة رقيقة فوق :class:`RouterOSClient`.

Zero-central edition: every function is per-NODE. The legacy singleton
``chr_settings.build_client()`` is gone — callers pass a fleet node id
(or ``None`` to let the brain pick the best one) and the resulting
RouterOS client is wired with the node's own credentials via
:mod:`app.services.fleet_node_router`.

Rules:
    * The only place that touches the network is the per-node client.
    * Reads never raise on unreachability — they return
      ``{"ok": False, "message": …}`` with an Arabic operator-facing
      string so the page can render the state without crashing.
    * Mutations (disable/enable/remove/reboot) are sensitive: the route
      layer gates them on super-admin + explicit confirmation + audit;
      here we just execute and return a structured result.
    * No CHR secrets (admin password) are ever returned or logged.
"""
from __future__ import annotations

from flask import current_app

from . import fleet_node_router
from .fleet_node_router import FleetNodeUnavailable
from .routeros_client import RouterOSError


def enabled() -> bool:
    """The console module is on when the feature flag is up AND the
    fleet has at least one eligible node to talk to.

    Replaces the legacy ``chr_settings.enabled()`` check: the fleet is
    the source of truth now, so "is there a node at all?" is the
    readiness gate.
    """
    if not bool(current_app.config.get("CHR_CONSOLE_ENABLED", True)):
        return False
    return bool(fleet_node_router.available_nodes())


def _client_for(node_id):
    """Resolve a node + build its client. Brain-picks when id is missing."""
    return fleet_node_router.resolve_and_client(node_id)


def _fail(exc) -> dict:
    """يحوّل أي خطأ اتصال/إعداد إلى نتيجة منظّمة برسالة عربية (دون كشف تفاصيل خام)."""
    code = getattr(exc, "code", "error")
    message = getattr(exc, "message", None) or str(exc)
    return {"ok": False, "code": code, "message": message}


# ───────────────────────── reads (never raise) ─────────────────────────

def status(node_id=None) -> dict:
    """فحص حيوية + معلومات نظام موجزة. يعيد ``ok=False`` عند تعذّر الوصول."""
    try:
        node, client = _client_for(node_id)
        info = client.test_connection()
    except FleetNodeUnavailable as exc:
        return {"ok": False, "code": exc.reason_code, "message": exc.message}
    except RouterOSError as exc:
        return _fail(exc)
    return {"ok": True, "node_id": node.id, "node_name": node.name, **info}


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


def overview(node_id=None) -> dict:
    """لقطة الوحدة لعقدة محدّدة — أو الأفضل تلقائيًا.

    * ``ok=False`` فقط حين لا تكون العقدة جاهزة (تعذّر بناء العميل).
    * ``reachable=False`` حين كانت مضبوطة لكن لم يستجب أي قسم.
    """
    try:
        node, client = _client_for(node_id)
    except FleetNodeUnavailable as exc:
        return {
            "ok": False, "reachable": False,
            "code": exc.reason_code, "message": exc.message,
            "node_id": None, "node_name": "",
        }

    system = _system_section(client)
    sections = {
        "ppp_secrets": _section("مستخدمو الأنفاق (PPP)", client.list_ppp_secrets),
        "ppp_active": _section("جلسات PPP النشطة", client.list_ppp_active),
        # قائمة مستخدمي IPsec قد تكون غير مُهيّأة على بعض أجهزة CHR فترجع 400/404؛
        # نعاملها كفارغة (حالة فارغة) لا كعطل.
        "ipsec_users": _section("مستخدمو IPsec", client.list_ipsec_users, soft_empty=True),
        "ipsec_identities": _section("هويات IPsec", client.list_ipsec_identities),
        "ipsec_active": _section("جلسات IPsec النشطة", client.list_ipsec_active_peers),
        "interfaces": _section("الواجهات", client.list_interfaces),
    }
    reachable = system.get("available") or any(s["available"] for s in sections.values())
    return {
        "ok": True,
        "node_id": node.id,
        "node_name": node.name,
        "reachable": bool(reachable),
        "system": system,
        "sections": sections,
        "counts": {key: len(sec["rows"]) for key, sec in sections.items()},
    }


# ───────────────────────── mutations (route guards + audits) ─────────────────────────

def _do(node_id, action) -> dict:
    """ينفّذ تعديلًا ويغلّف الأخطاء في نتيجة منظّمة (لا يرفع)."""
    try:
        _node, client = _client_for(node_id)
        action(client)
    except FleetNodeUnavailable as exc:
        return {"ok": False, "code": exc.reason_code, "message": exc.message}
    except RouterOSError as exc:
        return _fail(exc)
    return {"ok": True}


def set_ppp_secret_disabled(secret_id: str, disabled: bool, node_id=None) -> dict:
    return _do(node_id, lambda c: c.set_ppp_secret_disabled(secret_id, disabled))


def remove_ppp_secret(secret_id: str, node_id=None) -> dict:
    return _do(node_id, lambda c: c.remove_ppp_secret(secret_id))


def set_ipsec_user_disabled(user_id: str, disabled: bool, node_id=None) -> dict:
    return _do(node_id, lambda c: c.set_ipsec_user_disabled(user_id, disabled))


def remove_ipsec_user(user_id: str, node_id=None) -> dict:
    return _do(node_id, lambda c: c.remove_ipsec_user(user_id))


def reboot(node_id=None) -> dict:
    return _do(node_id, lambda c: c.reboot())
