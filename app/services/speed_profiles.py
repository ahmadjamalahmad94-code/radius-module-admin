"""بروفايلات السرعة المركزية + تطبيق ``rate-limit`` على CHR.

التحكّم بالسرعة جوهر المنتج: لكل نفق/اتصال سرعةٌ صريحة (تنزيل/رفع) تُطبَّق فعلًا على
CHR لا مجرّد البروفايل الافتراضي. تُترجَم السرعة إلى ``rate-limit`` على ``/ppp/profile``
على RouterOS، ثم يُسنَد ذلك البروفايل إلى ``/ppp/secret`` الخاص بالاتصال.

اتجاه ``rate-limit`` على RouterOS من منظور الراوتر: ``rx/tx`` حيث ``rx`` = ما يستقبله
الراوتر من العميل (= **رفع** العميل) و``tx`` = ما يرسله للعميل (= **تنزيل** العميل).
لذا السلسلة المُطبَّقة = ``<upload>M/<download>M``.

**العقد المركزي (Per-Direction Symmetric)**
كل قيمة سرعة في هذه اللوحة (Mbps) تعني سرعة **لكل اتجاه على حدة** — ليست مجموعًا.
أي ``850 Mbps`` تعني ``850↓ تنزيل + 850↑ رفع`` متزامنين، وتُترجَم إلى
``rate-limit = 850M/850M`` على CHR. لا تُضمَّن الاتجاهان أبدًا في رقم واحد مجمَّع.
حين يختار المالك «سرعة متماثلة» (الافتراضي) تُعبَّأ ``download_mbps`` و
``upload_mbps`` بالقيمة نفسها؛ النمط غير المتماثل متاح للحالات النادرة فقط.

هذه إعدادات مركزية للمالك ولا تُرسَل أبدًا لأي لوحة عميل (تُعرَض السرعة فقط في رد
الجسر كمعلومة، لا أي وصول إلى CHR).
"""
from __future__ import annotations

import re

from ..extensions import db
from ..models import ChrSpeedProfile, CustomerVpnTunnel


class SpeedProfileError(ValueError):
    """خطأ تحقّق يُعرض على واجهة المدير (رسالة عربية)."""


_CODE_RE = re.compile(r"[^a-z0-9_-]+")


def clean_code(value: str) -> str:
    code = _CODE_RE.sub("-", (value or "").strip().lower()).strip("-")
    return code[:80]


def rate_limit_string(download_mbps, upload_mbps) -> str:
    """يبني سلسلة ``rate-limit`` لـ RouterOS من سرعتي التنزيل/الرفع (Mbps).

    الصيغة ``<upload>M/<download>M`` (rx=رفع، tx=تنزيل). فارغة إن لم تكتمل السرعة.

    **سيناريو متماثل (هو الافتراضي):** ``rate_limit_string(850, 850) == "850M/850M"``
    — 850 لكل اتجاه على حدة، ليس 850 إجمالاً. نفس الرقم على الجانبين هو سلوك
    المنتج المعتمد (انظر :func:`symmetric_rate_limit`).
    """
    try:
        down = int(download_mbps or 0)
        up = int(upload_mbps or 0)
    except (TypeError, ValueError):
        return ""
    if down <= 0 or up <= 0:
        return ""
    return f"{up}M/{down}M"


def symmetric_rate_limit(value) -> str:
    """يبني ``rate-limit`` متماثل: نفس القيمة (Mbps) لكل اتجاه.

    العقد المعتمد للمالك: قيمة واحدة تعني نفس السرعة تنزيلاً ورفعًا — أي
    ``symmetric_rate_limit(850) == "850M/850M"`` (rx=850M، tx=850M). فارغة إن
    لم تكن القيمة عددًا موجبًا. هذه هي الواجهة المختصرة التي تستعملها
    المسارات/المودالات الجديدة بدل تكرار التنزيل والرفع.
    """
    try:
        v = int(value or 0)
    except (TypeError, ValueError):
        return ""
    if v <= 0:
        return ""
    return f"{v}M/{v}M"


def per_direction_label(download_mbps, upload_mbps, *, suffix: str = "ميجابت") -> str:
    """نص عربي موحَّد للعرض: ``«850↓ / 850↑ ميجابت»`` (لكل اتجاه على حدة).

    يُستعمل في القوالب والـAPI كي لا يقرأ المالك «850» على أنها إجمالي مجموع
    اتجاهين. يعيد ``"—"`` إن لم تكتمل القيمتان.
    """
    try:
        down = int(download_mbps or 0)
        up = int(upload_mbps or 0)
    except (TypeError, ValueError):
        return "—"
    if down <= 0 and up <= 0:
        return "—"
    if down == up:
        return f"{down}↓ / {up}↑ {suffix}"
    # غير متماثل (نادر) — نعرضه صريحًا كي لا يلتبس بمتماثل.
    return f"{down}↓ / {up}↑ {suffix} (غير متماثل)"


def custom_profile_name(download_mbps, upload_mbps) -> str:
    """اسم ``/ppp/profile`` لسرعة مخصّصة (غير مرتبطة ببروفايل محفوظ)."""
    return f"hob-{int(download_mbps)}d-{int(upload_mbps)}u"


# ───────────────────────── reads ─────────────────────────

def list_profiles(*, active_only: bool = False) -> list[ChrSpeedProfile]:
    query = ChrSpeedProfile.query
    if active_only:
        query = query.filter_by(active=True)
    return query.order_by(ChrSpeedProfile.download_mbps.asc(), ChrSpeedProfile.id.asc()).all()


def get(profile_id) -> ChrSpeedProfile | None:
    try:
        return db.session.get(ChrSpeedProfile, int(profile_id))
    except (TypeError, ValueError):
        return None


# ───────────────────────── validation + CRUD ─────────────────────────

def _parse_speed(form, field: str, label: str) -> int:
    raw = (form.get(field) or "").strip()
    if not raw.isdigit():
        raise SpeedProfileError(f"الحقل «{label}» يجب أن يكون رقمًا صحيحًا (Mbps).")
    value = int(raw)
    if not (1 <= value <= 100000):
        raise SpeedProfileError(f"الحقل «{label}» خارج النطاق المسموح (1–100000 Mbps).")
    return value


def _parse_optional_int(form, field: str, label: str) -> int | None:
    raw = (form.get(field) or "").strip()
    if not raw:
        return None
    if not raw.isdigit() or int(raw) < 1:
        raise SpeedProfileError(f"الحقل «{label}» يجب أن يكون رقمًا موجبًا أو فارغًا.")
    return int(raw)


def _resolve_symmetric_fields(form) -> tuple[str, str]:
    """يطبّق سياسة «السرعة المتماثلة»: إن مُرِّر حقل ``speed_mbps`` (الافتراضي
    الجديد) فإن قيمته تُنسَخ إلى ``download_mbps`` و``upload_mbps`` معًا، تجاهلاً
    لأي قيم منفصلة قد تكون فارغة. النموذج غير المتماثل (نادر) يرسل القيمتين
    مباشرة ويترك ``speed_mbps`` فارغًا.

    يعيد القيم الجاهزة كنصوص (mutable form يُحدَّث ولكن نُعيد القيم لقراءة لاحقة).
    """
    raw_sym = (form.get("speed_mbps") or "").strip()
    if raw_sym:
        # سياسة المالك: قيمة واحدة ⇒ نفس السرعة لكل اتجاه. نُملِئ الحقلين معًا
        # ونتجاهل أي قيم منفصلة كي لا تتسلَّل قيمة مختلفة بالخطأ.
        try:
            form.setlist("download_mbps", [raw_sym]) if hasattr(form, "setlist") else None
            form.setlist("upload_mbps", [raw_sym]) if hasattr(form, "setlist") else None
        except Exception:  # noqa: BLE001 — form may be a plain dict (tests)
            pass
        # Fall through: _parse_speed reads form.get("download_mbps") / ("upload_mbps").
        # If form.setlist isn't available (plain dict), patch via __setitem__:
        try:
            form["download_mbps"] = raw_sym
            form["upload_mbps"] = raw_sym
        except Exception:
            pass
    return (form.get("download_mbps") or "", form.get("upload_mbps") or "")


def create_profile(form) -> ChrSpeedProfile:
    name = (form.get("name") or "").strip()[:140]
    if not name:
        raise SpeedProfileError("اسم البروفايل مطلوب.")
    code = clean_code(form.get("code") or name)
    if not code:
        raise SpeedProfileError("رمز البروفايل (code) غير صالح.")
    if ChrSpeedProfile.query.filter_by(code=code).first():
        raise SpeedProfileError(f"الرمز «{code}» مستخدم سلفًا — اختر رمزًا آخر.")
    _resolve_symmetric_fields(form)
    download = _parse_speed(form, "download_mbps", "سرعة التنزيل")
    upload = _parse_speed(form, "upload_mbps", "سرعة الرفع")
    max_sessions = _parse_optional_int(form, "max_sessions", "حدّ الجلسات")
    profile = ChrSpeedProfile(
        name=name,
        code=code,
        download_mbps=download,
        upload_mbps=upload,
        max_sessions=max_sessions,
        chr_profile_name=(form.get("chr_profile_name") or "").strip()[:80],
        active=bool(form.get("active", "1")),
        notes=(form.get("notes") or "").strip()[:255],
    )
    db.session.add(profile)
    db.session.flush()
    return profile


def update_profile(profile: ChrSpeedProfile, form) -> ChrSpeedProfile:
    name = (form.get("name") or "").strip()[:140]
    if not name:
        raise SpeedProfileError("اسم البروفايل مطلوب.")
    profile.name = name
    _resolve_symmetric_fields(form)
    profile.download_mbps = _parse_speed(form, "download_mbps", "سرعة التنزيل")
    profile.upload_mbps = _parse_speed(form, "upload_mbps", "سرعة الرفع")
    profile.max_sessions = _parse_optional_int(form, "max_sessions", "حدّ الجلسات")
    profile.chr_profile_name = (form.get("chr_profile_name") or "").strip()[:80]
    profile.active = bool(form.get("active"))
    profile.notes = (form.get("notes") or "").strip()[:255]
    db.session.add(profile)
    return profile


def delete_profile(profile: ChrSpeedProfile) -> None:
    """يحذف البروفايل إن لم يكن مستخدمًا في أي نفق؛ وإلا يكتفي بتعطيله."""
    in_use = CustomerVpnTunnel.query.filter_by(speed_profile_id=profile.id).first()
    if in_use:
        profile.active = False
        db.session.add(profile)
        raise SpeedProfileError(
            "البروفايل مستخدم في أنفاق قائمة — عُطِّل بدل الحذف (لن يظهر للاختيار الجديد)."
        )
    db.session.delete(profile)


# ───────────────────────── CHR application ─────────────────────────

def ensure_on_chr(profile: ChrSpeedProfile) -> dict:
    """Fan-out: idempotently install ``/ppp/profile`` for ``profile`` on every
    eligible fleet CHR (enabled + not drain + not disabled). The unified
    profile name lets every node carry the same rate-limit policy so any
    tunnel placed by the brain finds its profile already in place.

    Returns ``{"total", "ok", "skipped", "errors", "per_node": [...]}`` so the
    «اختبار/مزامنة» button in the admin UI can show one card per node.
    A single-node failure is reported in the result — it never breaks the
    rest of the fan-out. The pre-zero-central behaviour (raise on any
    failure) was a chr_settings-singleton assumption that doesn't fit a
    multi-node deployment.

    pool **مشترك واحد** لكل البروفايلات (لا pool لكل سرعة) — البروفايلات تختلف فقط
    بالـrate-limit. بدون local/remote-address لا يأخذ العميل IPv4.
    """
    from flask import current_app
    from . import fleet_node_router
    from .fleet_node_router import FleetNodeUnavailable
    from .reserved_subnets import (
        ReservedSubnetError,
        assert_address_not_reserved,
        assert_pool_range_not_reserved,
    )
    from .routeros_client import RouterOSError
    cfg = current_app.config
    pool_name = (cfg.get("CHR_PPP_ADDRESS_POOL") or "ppp-vpn-pool").strip() or "ppp-vpn-pool"
    local_addr = (cfg.get("CHR_PPP_LOCAL_ADDRESS") or "10.10.0.1").strip() or "10.10.0.1"
    pool_ranges = (cfg.get("CHR_PPP_POOL_RANGES") or "10.10.0.10-10.10.0.250").strip()
    use_enc = bool(cfg.get("CHR_PPP_USE_ENCRYPTION", True))
    # The PPP gateway address + the client pool MUST NOT overlap the wg-mgmt
    # / wg-data /24s. Otherwise the CHR routes RADIUS toward a PPP client
    # instead of the wg-data peer (the chr-vpn-1 collision of 2026-06).
    # Validate ONCE up-front — same config is pushed to every node so a
    # reserved-subnet collision applies fleet-wide.
    try:
        assert_address_not_reserved(local_addr, field_label="CHR_PPP_LOCAL_ADDRESS")
        assert_pool_range_not_reserved(pool_ranges, field_label="CHR_PPP_POOL_RANGES")
    except ReservedSubnetError as exc:
        raise SpeedProfileError(str(exc)) from exc

    nodes = fleet_node_router.available_nodes()
    result = {
        "total": len(nodes),
        "ok": 0,
        "skipped": 0,
        "errors": 0,
        "per_node": [],
    }
    if not nodes:
        # No fleet at all — nothing to sync to. Caller sees ok=0/total=0 and
        # surfaces the «أضف عقدة CHR أولًا» message.
        return result

    for node in nodes:
        per = {"node_id": node.id, "node_name": node.name, "ok": False, "message": ""}
        try:
            client = fleet_node_router.build_client_for(node)
        except FleetNodeUnavailable as exc:
            per["message"] = exc.message
            result["skipped"] += 1
            result["per_node"].append(per)
            continue
        try:
            client.ensure_ip_pool(name=pool_name, ranges=pool_ranges)
            client.ensure_ppp_profile(
                name=profile.effective_chr_profile_name,
                rate_limit=rate_limit_string(profile.download_mbps, profile.upload_mbps),
                local_address=local_addr,
                remote_address=pool_name,
                use_encryption=use_enc,
            )
        except RouterOSError as exc:
            per["message"] = exc.message or "RouterOS error"
            result["errors"] += 1
            result["per_node"].append(per)
            continue
        per["ok"] = True
        per["message"] = "تم الدفع للعقدة."
        result["ok"] += 1
        result["per_node"].append(per)
    return result


def serialize(profile: ChrSpeedProfile) -> dict:
    return {
        "id": profile.id,
        "name": profile.name,
        "code": profile.code,
        "download_mbps": profile.download_mbps,
        "upload_mbps": profile.upload_mbps,
        "max_sessions": profile.max_sessions,
        "chr_profile_name": profile.effective_chr_profile_name,
        "rate_limit": rate_limit_string(profile.download_mbps, profile.upload_mbps),
        "active": profile.active,
    }
