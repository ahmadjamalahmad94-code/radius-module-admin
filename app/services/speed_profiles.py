"""بروفايلات السرعة المركزية + تطبيق ``rate-limit`` على CHR.

التحكّم بالسرعة جوهر المنتج: لكل نفق/اتصال سرعةٌ صريحة (تنزيل/رفع) تُطبَّق فعلًا على
CHR لا مجرّد البروفايل الافتراضي. تُترجَم السرعة إلى ``rate-limit`` على ``/ppp/profile``
على RouterOS، ثم يُسنَد ذلك البروفايل إلى ``/ppp/secret`` الخاص بالاتصال.

اتجاه ``rate-limit`` على RouterOS من منظور الراوتر: ``rx/tx`` حيث ``rx`` = ما يستقبله
الراوتر من العميل (= **رفع** العميل) و``tx`` = ما يرسله للعميل (= **تنزيل** العميل).
لذا السلسلة المُطبَّقة = ``<upload>M/<download>M``.

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

    الصيغة ``<upload>M/<download>M`` (rx=رفع، tx=تنزيل). فارغة إن لم تكتمل السرعة."""
    try:
        down = int(download_mbps or 0)
        up = int(upload_mbps or 0)
    except (TypeError, ValueError):
        return ""
    if down <= 0 or up <= 0:
        return ""
    return f"{up}M/{down}M"


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


def create_profile(form) -> ChrSpeedProfile:
    name = (form.get("name") or "").strip()[:140]
    if not name:
        raise SpeedProfileError("اسم البروفايل مطلوب.")
    code = clean_code(form.get("code") or name)
    if not code:
        raise SpeedProfileError("رمز البروفايل (code) غير صالح.")
    if ChrSpeedProfile.query.filter_by(code=code).first():
        raise SpeedProfileError(f"الرمز «{code}» مستخدم سلفًا — اختر رمزًا آخر.")
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

def ensure_on_chr(profile: ChrSpeedProfile):
    """يهيّئ ``/ppp/profile`` المقابل على CHR بسرعته **والعنونة** (idempotent). يرفع
    للمستدعي عند فشل CHR/الإعداد. للاستخدام من واجهة «اختبار/مزامنة البروفايل».

    pool **مشترك واحد** لكل البروفايلات (لا pool لكل سرعة) — البروفايلات تختلف فقط
    بالـrate-limit. بدون local/remote-address لا يأخذ العميل IPv4."""
    from flask import current_app
    from . import chr_settings
    from .reserved_subnets import (
        ReservedSubnetError,
        assert_address_not_reserved,
        assert_pool_range_not_reserved,
    )
    cfg = current_app.config
    pool_name = (cfg.get("CHR_PPP_ADDRESS_POOL") or "ppp-vpn-pool").strip() or "ppp-vpn-pool"
    local_addr = (cfg.get("CHR_PPP_LOCAL_ADDRESS") or "10.10.0.1").strip() or "10.10.0.1"
    pool_ranges = (cfg.get("CHR_PPP_POOL_RANGES") or "10.10.0.10-10.10.0.250").strip()
    use_enc = bool(cfg.get("CHR_PPP_USE_ENCRYPTION", True))
    # The PPP gateway address + the client pool MUST NOT overlap the wg-mgmt
    # / wg-data /24s. Otherwise the CHR routes RADIUS toward a PPP client
    # instead of the wg-data peer (the chr-vpn-1 collision of 2026-06).
    try:
        assert_address_not_reserved(local_addr, field_label="CHR_PPP_LOCAL_ADDRESS")
        assert_pool_range_not_reserved(pool_ranges, field_label="CHR_PPP_POOL_RANGES")
    except ReservedSubnetError as exc:
        raise SpeedProfileError(str(exc)) from exc
    client = chr_settings.build_client()
    client.ensure_ip_pool(name=pool_name, ranges=pool_ranges)
    client.ensure_ppp_profile(
        name=profile.effective_chr_profile_name,
        rate_limit=rate_limit_string(profile.download_mbps, profile.upload_mbps),
        local_address=local_addr,
        remote_address=pool_name,
        use_encryption=use_enc,
    )


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
