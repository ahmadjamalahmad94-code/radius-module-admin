"""fleet.sync.stages — the eight REAL onboarding/sync stages.

Each stage is a pure function ``(node, ctx) -> StageOutcome`` that runs an
ACTUAL check (no fake progress). Wherever possible we reuse the checks the
operator already trusts from the troubleshoot page and wg-verify, so the
progress UI and the troubleshoot verdict can never disagree.

``ctx`` carries the once-per-job reconcile facts the service precomputes:
  * ``panel_apply``        — fleet.sync.wg_apply.ApplyResult (dict)
  * ``desired_panel_names``— set of node names in the desired wg-mgmt set
  * ``desired_proxy_names``— set of node names in the desired wg-data set

Stages 5 & 6 are the only ones that touch the CHR over REST; 7 & 8 are derived
from the DB/config so a single tick never makes more than the two unavoidable
control-plane calls.
"""
from __future__ import annotations

from dataclasses import dataclass

from app.api.proxy_api import _derive_wg_data_ip


@dataclass(frozen=True)
class StageOutcome:
    state: str          # done | warn | failed
    reason_ar: str = ""
    value: str = ""

    def as_update(self) -> dict:
        return {"state": self.state, "reason": self.reason_ar, "value": self.value}


# Stable stage keys + Arabic labels, in pipeline order. The keys never change
# (UI/tests pin them); labels are display-only.
STAGES: tuple[tuple[str, str], ...] = (
    ("keys",       "توليد المفاتيح"),
    ("panel_peer", "تسجيل peer على اللوحة"),
    ("proxy_peer", "تسجيل peer على البروكسي"),
    ("script",     "توليد/تطبيق السكربت"),
    ("wg_mgmt",    "مصافحة wg-mgmt"),
    ("wg_data",    "مصافحة wg-data"),
    ("routing",    "النشر بجدول التوجيه"),
    ("radius",     "فحص RADIUS"),
)

#: Stages whose failure is HARD (stops the node's pipeline → "where it stopped").
#: A stage that returns ``warn`` never blocks regardless of this set.
HARD_STAGES = frozenset({"keys", "panel_peer", "proxy_peer", "script", "wg_mgmt", "wg_data"})


def _eligible(node) -> bool:
    return bool(node.enabled) and not bool(node.drain) and node.status != "disabled"


# ── stage 1: keys ────────────────────────────────────────────────────────────
def stage_keys(node, ctx) -> StageOutcome:
    mgmt = (node.wg_mgmt_pubkey or "").strip()
    data = (node.wg_data_pubkey or "").strip()
    if mgmt and data:
        return StageOutcome("done", "مفاتيح wg-mgmt و wg-data مولّدة ومخزّنة.",
                            f"mgmt={mgmt[:8]}… data={data[:8]}…")
    if not mgmt:
        return StageOutcome("failed", "مفتاح wg-mgmt غير مسجّل على العقدة — أعد الإضافة من المعالج.")
    return StageOutcome("failed",
                        "مفتاح wg-data غير مسجّل — أعد توليد مفاتيح العقدة (إضافة جديدة) لنشر نظير البروكسي.")


# ── stage 2: panel peer ──────────────────────────────────────────────────────
def stage_panel_peer(node, ctx) -> StageOutcome:
    if not _eligible(node):
        return StageOutcome("warn", "العقدة مُعطّلة/مُستنزَفة — مستبعدة عمداً من نظراء اللوحة.")
    if node.name not in ctx.get("desired_panel_names", set()):
        return StageOutcome("failed",
                            "تعذّر بناء نظير اللوحة — تحقّق من عنوان wg-mgmt (10.99.0.x) ومفتاح العقدة.")
    apply = ctx.get("panel_apply") or {}
    pub = (node.wg_mgmt_pubkey or "").strip()
    if not apply.get("available"):
        return StageOutcome(
            "warn",
            "نظير اللوحة جاهز للتطبيق، لكن أداة المزامنة على مضيف اللوحة غير مثبّتة بعد "
            "(تثبيت لمرة واحدة). المصافحة أدناه تعكس الحالة الفعلية على المضيف.",
            f"{node.wg_mgmt_ip}/32",
        )
    if apply.get("applied") and pub in set(apply.get("applied_pubkeys") or []):
        return StageOutcome("done", "أُضيف نظير wg-mgmt للعقدة على مضيف اللوحة.", f"{node.wg_mgmt_ip}/32")
    if apply.get("applied"):
        # Sync ran but this node's key wasn't in the readback — real mismatch.
        return StageOutcome("failed",
                            "طُبِّقت المزامنة على اللوحة لكن مفتاح هذه العقدة لم يظهر بين النظراء — راجع سجل الأداة.")
    return StageOutcome("failed",
                        f"تعذّر تطبيق نظير wg-mgmt على مضيف اللوحة: {apply.get('message') or 'سبب غير معروف'}")


# ── stage 3: proxy peer ──────────────────────────────────────────────────────
def stage_proxy_peer(node, ctx) -> StageOutcome:
    if not _eligible(node):
        return StageOutcome("warn", "العقدة مُعطّلة/مُستنزَفة — مستبعدة عمداً من نظراء البروكسي.")
    if not (node.wg_data_pubkey or "").strip():
        return StageOutcome("failed",
                            "لا يوجد مفتاح wg-data للعقدة — لا يمكن نشر نظير للبروكسي. أعد الإضافة.")
    if node.name in ctx.get("desired_proxy_names", set()):
        data_ip = _derive_wg_data_ip(node.wg_mgmt_ip)
        return StageOutcome("done",
                            "مفتاح wg-data منشور للوكيل عبر /api/proxy/wg-peers (يطبّقه عميل البروكسي).",
                            f"{data_ip}/32")
    return StageOutcome("failed",
                        "تعذّر اشتقاق عنوان wg-data (10.98.0.x) — تحقّق من أن wg-mgmt داخل 10.99.0.0/24.")


# ── stage 4: script ──────────────────────────────────────────────────────────
def stage_script(node, ctx) -> StageOutcome:
    current_pubkey = ctx.get("panel_pubkey") or ""
    if not current_pubkey:
        return StageOutcome("failed",
                            "لم يُولَّد مفتاح اللوحة العام بعد — ولّده من «إعدادات بنية الأسطول» أولاً.")
    # Try the real render path via the node's onboarding job (carries vault key
    # refs). If the bindings are incomplete we surface the exact Arabic «بانتظار».
    try:
        from fleet.registry.models_onboarding import OnboardingJob
        from fleet.registry.onboarding_service import OnboardingService, OnboardingError
        from fleet.registry.script_bindings_check import check_bindings, summary_ar

        job = (
            OnboardingJob.query
            .filter_by(chr_id=node.id)
            .order_by(OnboardingJob.id.desc())
            .first()
        )
        if job is not None and job.wg_keypair_ref:
            bindings = OnboardingService()._build_bindings(job)
            missing = check_bindings(bindings)
            if missing:
                return StageOutcome("failed", summary_ar(missing))
            if str(bindings.get("PANEL_WG_PUBKEY") or "") != current_pubkey:
                return StageOutcome("failed",
                                    "السكربت المُعاد توليده لا يحمل مفتاح اللوحة الحالي — خلل في الإعدادات.")
            # Bindings complete + carry the CURRENT panel pubkey.
            if node.needs_reimport:
                return StageOutcome("warn",
                                    "أُعيد توليد السكربت بمفتاح اللوحة الحالي — يلزم إعادة استيراده على العقدة "
                                    "(«عرض السكربت»). ستتأكد المصافحة أدناه من التطبيق.")
            return StageOutcome("done", "السكربت قابل للتوليد بالمفتاح الحالي وبيانات كاملة.")
    except OnboardingError as exc:
        return StageOutcome("failed", str(exc))
    except Exception:  # noqa: BLE001 — fall through to the settings-readiness check
        pass

    # Fallback (no recoverable job): at least confirm the fleet infra settings
    # are complete so a fresh script COULD be produced.
    try:
        from fleet.registry.infra_settings import is_fleet_ready, missing_required
        if is_fleet_ready():
            if node.needs_reimport:
                return StageOutcome("warn",
                                    "الإعدادات مكتملة لكن العقدة بحاجة لإعادة استيراد السكربت بالمفتاح الحالي.")
            return StageOutcome("done", "إعدادات بنية الأسطول مكتملة — السكربت قابل للتوليد.")
        miss = "، ".join(missing_required())
        return StageOutcome("failed", f"بانتظار إعداد بنية الأسطول: {miss}")
    except Exception:  # noqa: BLE001
        return StageOutcome("warn", "تعذّر التحقّق من جاهزية السكربت — تابع المصافحة أدناه.")


# ── stage 5: wg-mgmt handshake (also clears needs_reimport on success) ────────
def stage_wg_mgmt(node, ctx) -> StageOutcome:
    try:
        from fleet.health.wg_verify import verify_node_wg_identity
        r = verify_node_wg_identity(node)
    except Exception as exc:  # noqa: BLE001
        return StageOutcome("warn", f"تعذّر تشغيل فحص مفاتيح wg-mgmt: {exc}")

    if r.code == "ok":
        # Real proof the CHR trusts the CURRENT panel key → the script landed.
        from fleet.sync.keys import clear_node_reimport
        clear_node_reimport(node)
        return StageOutcome("done", r.message_ar, _hs_value(r.last_handshake))
    if r.code in ("panel_key_unset",):
        return StageOutcome("failed", r.message_ar)
    if r.code in ("panel_key_mismatch", "chr_key_mismatch", "peer_missing"):
        return StageOutcome("failed", r.message_ar)
    # no_credentials | rest_failed | verify_unavailable → can't confirm, non-blocking.
    return StageOutcome("warn", r.message_ar, r.code)


# ── stage 6: wg-data handshake ───────────────────────────────────────────────
def stage_wg_data(node, ctx) -> StageOutcome:
    try:
        from fleet.sync.wg_data_check import verify_node_wg_data
        r = verify_node_wg_data(node)
    except Exception as exc:  # noqa: BLE001
        return StageOutcome("warn", f"تعذّر تشغيل فحص مصافحة wg-data: {exc}")
    if r.ok is True:
        return StageOutcome("done", r.message_ar, _hs_value(r.last_handshake))
    if r.ok is False:
        return StageOutcome("failed", r.message_ar)
    return StageOutcome("warn", r.message_ar, r.code)


# ── stage 7: routing-table publication (DB-only) ─────────────────────────────
def stage_routing(node, ctx) -> StageOutcome:
    data_ip = _derive_wg_data_ip(node.wg_mgmt_ip)
    if not data_ip.startswith("10.98."):
        return StageOutcome("failed", "عنوان wg-data غير مشتق — راجع مرحلة نظير البروكسي.")
    if _eligible(node):
        return StageOutcome("done",
                            "العقدة منشورة في /api/proxy/routing-table (الوكيل يقبل RADIUS منها).",
                            data_ip)
    return StageOutcome("warn",
                        "العقدة مُعطّلة/مُستنزَفة — غير منشورة في جدول التوجيه (سلوك مقصود).")


# ── stage 8: RADIUS reachability hint (DB/config-only) ───────────────────────
def stage_radius(node, ctx) -> StageOutcome:
    data_ip = _derive_wg_data_ip(node.wg_mgmt_ip)
    data_ok = data_ip.startswith("10.98.")
    if not data_ok:
        return StageOutcome("warn", "العنوان غير مشتق — أصلح المراحل أعلاه أولاً.")
    if not _eligible(node):
        return StageOutcome("warn", "العقدة غير منشورة — لن يستقبل الوكيل RADIUS منها.")
    # PPP reserved-subnet collision (the live 2026-06 root cause) — config-only.
    try:
        from flask import current_app
        from app.services.reserved_subnets import is_reserved_address, is_reserved_range
        cfg = current_app.config
        local_addr = (cfg.get("CHR_PPP_LOCAL_ADDRESS") or "").strip()
        pool_range = (cfg.get("CHR_PPP_POOL_RANGES") or "").strip()
        coll = (bool(local_addr) and is_reserved_address(local_addr)) or \
               (bool(pool_range) and is_reserved_range(pool_range))
    except Exception:  # noqa: BLE001
        coll = False
    if coll:
        return StageOutcome("warn",
                            "تصادم عناوين PPP مع 10.98/10.99 — قد يُسقط الوكيل الحزمة. غيّر نطاق PPP.")
    return StageOutcome("done",
                        "السلوك المتوقّع: الوكيل يستقبل RADIUS من العقدة (عميل غير معروف → Reject لا timeout).")


_STAGE_FNS = {
    "keys": stage_keys,
    "panel_peer": stage_panel_peer,
    "proxy_peer": stage_proxy_peer,
    "script": stage_script,
    "wg_mgmt": stage_wg_mgmt,
    "wg_data": stage_wg_data,
    "routing": stage_routing,
    "radius": stage_radius,
}


def run_stage(stage_key: str, node, ctx) -> StageOutcome:
    """Run one stage's REAL check. Unknown key → warn (never crash the runner)."""
    fn = _STAGE_FNS.get(stage_key)
    if fn is None:
        return StageOutcome("warn", f"مرحلة غير معروفة: {stage_key}")
    try:
        return fn(node, ctx)
    except Exception as exc:  # noqa: BLE001 — a stage must never crash the job
        return StageOutcome("warn", f"تعذّر تنفيذ المرحلة: {exc}")


def _hs_value(handshake: str) -> str:
    return f"آخر مصافحة: {handshake}" if handshake else ""


__all__ = ["StageOutcome", "STAGES", "HARD_STAGES", "run_stage"]
