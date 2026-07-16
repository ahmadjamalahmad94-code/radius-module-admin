"""ملخّص حالة عامّ آمن للخصوصية (إعادة تصميم 2026-07، المرحلة 3).

يشتقّ حالة تشغيلية مجمَّعة من صحّة عُقد الأسطول دون كشف أي بيانات داخلية
(لا أسماء عُقد، لا IP، لا بيانات عملاء) — فقط عدّادات ومكوّنات عالية المستوى
لعرضها على صفحة `/status` العامّة.
"""
from __future__ import annotations

# حالات المكوّن العامّة (مرتبة تنازليًا بالخطورة).
OK = "operational"
DEGRADED = "degraded"
DOWN = "down"
UNKNOWN = "unknown"

_LABELS_AR = {
    OK: "تعمل بشكل طبيعي",
    DEGRADED: "أداء منخفض",
    DOWN: "متوقفة",
    UNKNOWN: "غير معروفة",
}


def component_label(state: str) -> str:
    return _LABELS_AR.get(state, _LABELS_AR[UNKNOWN])


def _aggregate_from_counts(up: int, degraded: int, down: int, total: int) -> str:
    if total == 0:
        return UNKNOWN
    if down and down >= total:
        return DOWN
    if degraded or down:
        return DEGRADED
    return OK


def status_summary() -> dict:
    """ملخّص عام: حالة كليّة + مكوّنات + عدّاد «X من Y» فقط.

    لا يرمي أبدًا — أي خطأ في القراءة يعطي حالة ``unknown`` كي تبقى الصفحة
    العامّة متاحة حتى لو تعطّلت طبقة الأسطول.
    """
    try:
        from fleet.registry.models_chr import FleetChrNode  # noqa: PLC0415

        rows = FleetChrNode.query.with_entities(FleetChrNode.status).all()
        statuses = [(s or "").strip().lower() for (s,) in rows]
        # نتجاهل المعطّلة يدويًا من الحساب (ليست عطلًا).
        active = [s for s in statuses if s != "disabled"]
        total = len(active)
        up = sum(1 for s in active if s == "up")
        degraded = sum(1 for s in active if s in ("degraded", "provisioning"))
        down = sum(1 for s in active if s == "down")
    except Exception:  # noqa: BLE001
        total = up = degraded = down = 0

    edge = _aggregate_from_counts(up, degraded, down, total)

    components = [
        {"key": "panel", "name": "لوحة التحكم والـ API",
         "state": OK},  # الطلب وصل ⇒ اللوحة تعمل
        {"key": "edge", "name": "شبكة عُقد الحافة (RADIUS/VPN)",
         "state": edge, "up": up, "total": total},
    ]
    overall = OK
    for c in components:
        if c["state"] == DOWN:
            overall = DOWN
            break
        if c["state"] in (DEGRADED, UNKNOWN):
            overall = DEGRADED
    return {"overall": overall, "components": components}
