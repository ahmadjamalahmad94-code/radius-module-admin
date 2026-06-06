"""كوتة المرور الشهرية لأنفاق CHR مع **تخفيض السرعة عند النفاد** (لا فصل).

أنفاق تغيير الـIP تمرّر باندويث عاليًا، فالمالك يحدّد سقفًا شهريًا بالـGB. عند بلوغ
السقف يُنقل النفق إلى بروفايل سرعة منخفضة (throttle) على CHR بدل فصله، ومع بداية كل
شهر يُصفَّر العدّاد وتُستعاد السرعة الكاملة.

القياس best-effort بالاستطلاع: نقرأ ``bytes-in/out`` لجلسة PPP الحيّة دوريًا ونراكم
الفروقات (عدّاد الجلسة يُصفَّر عند إعادة الاتصال، لذا نجمع الدلتا لا القيمة المطلقة).
للنفق الدائم الاتصال هذا دقيق عمليًا؛ المحاسبة البايت-المثالية تتطلب RADIUS لاحقًا.

التصميم منفصل: :func:`decide` دالّة **خالصة** (بلا DB/شبكة) تحوي كل منطق القرار
فيمكن اختبارها وحدها؛ و:func:`sync_tunnel`/:func:`run_once` تغلّفانها بـDB وCHR.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone


def current_period(now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    return now.strftime("%Y-%m")


def gb_to_bytes(gb: int | float | None) -> int:
    try:
        return int(float(gb or 0) * 1_000_000_000)  # GB عشري (1e9)، متّسق مع العرض
    except (TypeError, ValueError):
        return 0


@dataclass
class QuotaDecision:
    period: str          # الشهر المخزَّن بعد المعالجة (YYYY-MM)
    bytes_used: int      # إجمالي الاستهلاك المُراكَم لهذا الشهر
    sample_bytes: int    # أساس عيّنة الجلسة الحالية (لمنع العدّ المزدوج)
    should_throttle: bool  # طبّق بروفايل التخفيض الآن
    should_restore: bool   # استعد السرعة الكاملة الآن (تدوير الشهر)
    exhausted: bool        # الكوتة مستنفدة لهذا الشهر


def decide(
    *,
    stored_period: str,
    bytes_used: int,
    sample_bytes: int,
    live_session_bytes: int,
    quota_bytes: int,
    is_throttled: bool,
    now_period: str,
) -> QuotaDecision:
    """منطق القرار الخالص (بلا آثار جانبية).

    - ``live_session_bytes`` = bytes-in+out للجلسة الحيّة الآن (0 إن غير متصل).
    - ``quota_bytes`` = الكوتة بالبايت (0 ⇒ بلا حد، لا تخفيض إطلاقًا).
    يعالج: تدوير الشهر (تصفير + استعادة)، تراكم الدلتا (مع تصفير عيّنة عند إعادة
    الاتصال)، وقرار التخفيض/الاستعادة دون ارتداد.
    """
    # ── تدوير الشهر: تصفير العدّاد واستعادة السرعة ──
    if stored_period != now_period:
        return QuotaDecision(
            period=now_period, bytes_used=0, sample_bytes=live_session_bytes,
            should_throttle=False, should_restore=bool(is_throttled),
            exhausted=False,
        )
    # ── تراكم الدلتا داخل نفس الشهر ──
    if live_session_bytes >= sample_bytes:
        delta = live_session_bytes - sample_bytes      # نفس الجلسة مستمرة
    else:
        delta = live_session_bytes                     # أُعيد الاتصال (عُدّاد صُفِّر)
    new_used = bytes_used + max(0, delta)
    new_sample = live_session_bytes

    if quota_bytes <= 0:  # بلا حد
        return QuotaDecision(
            period=now_period, bytes_used=new_used, sample_bytes=new_sample,
            should_throttle=False, should_restore=bool(is_throttled),
            exhausted=False,
        )
    exhausted = new_used >= quota_bytes
    return QuotaDecision(
        period=now_period, bytes_used=new_used, sample_bytes=new_sample,
        should_throttle=exhausted and not is_throttled,
        should_restore=(not exhausted) and is_throttled,
        exhausted=exhausted,
    )


# ── أسماء بروفايلات CHR للسرعة الكاملة/المخفّضة لنفقٍ معيّن ──

def full_profile_name(tunnel) -> str:
    """بروفايل السرعة الكاملة المعتاد للنفق (بروفايل السرعة أو الافتراضي)."""
    name = (getattr(tunnel, "profile", "") or "").strip()
    return name or "default"


def throttle_profile_name(tunnel) -> str:
    """اسم بروفايل التخفيض الخاص بهذا النفق على CHR."""
    return f"hob-throttle-{int(getattr(tunnel, 'id', 0) or 0)}"


def sync_tunnel(tunnel, client, *, now: datetime | None = None) -> dict:
    """يزامن كوتة نفقٍ واحد مقابل CHR ويطبّق التخفيض/الاستعادة عند اللزوم.

    يحدّث حقول ``tunnel`` في مكانها (المستدعي يحفظ الجلسة). يعيد ملخّصًا.
    لا يرفع: أي خطأ CHR يُبلَّغ في الملخّص فلا يكسر بقية الأنفاق في العامل."""
    from .speed_profiles import rate_limit_string  # محلي لتفادي دوران الاستيراد
    now = now or datetime.now(timezone.utc)
    nowp = current_period(now)
    quota_bytes = gb_to_bytes(getattr(tunnel, "monthly_quota_gb", None))

    # اقرأ جلسة PPP الحيّة (إن وُجدت) لاستخراج بايتات الجلسة الحالية.
    live = 0
    try:
        active = client.find_ppp_active(tunnel.username)
        if active:
            bi = int(active.get("bytes-in") or 0)
            bo = int(active.get("bytes-out") or 0)
            live = bi + bo
    except Exception as exc:  # noqa: BLE001 — خطأ نفقٍ لا يكسر العامل
        return {"username": tunnel.username, "ok": False, "error": str(exc)}

    d = decide(
        stored_period=tunnel.quota_period or "",
        bytes_used=int(tunnel.quota_bytes_used or 0),
        sample_bytes=int(tunnel.quota_sample_bytes or 0),
        live_session_bytes=live,
        quota_bytes=quota_bytes,
        is_throttled=bool(tunnel.is_throttled),
        now_period=nowp,
    )
    tunnel.quota_period = d.period
    tunnel.quota_bytes_used = d.bytes_used
    tunnel.quota_sample_bytes = d.sample_bytes

    action = "none"
    try:
        if d.should_throttle:
            tname = throttle_profile_name(tunnel)
            tdown = int(getattr(tunnel, "throttle_down_mbps", 0) or 1)
            tup = int(getattr(tunnel, "throttle_up_mbps", 0) or 1)
            client.ensure_ppp_profile(
                name=tname,
                rate_limit=rate_limit_string(tdown, tup),
            )
            client.set_secret_profile(tunnel.chr_secret_id, tname)
            _bounce(client, tunnel.username)
            tunnel.is_throttled = True
            action = "throttled"
        elif d.should_restore:
            client.set_secret_profile(tunnel.chr_secret_id, full_profile_name(tunnel))
            _bounce(client, tunnel.username)
            tunnel.is_throttled = False
            action = "restored"
    except Exception as exc:  # noqa: BLE001
        return {"username": tunnel.username, "ok": False, "error": str(exc),
                "used": d.bytes_used, "exhausted": d.exhausted}

    return {"username": tunnel.username, "ok": True, "action": action,
            "used": d.bytes_used, "quota": quota_bytes, "exhausted": d.exhausted}


def _bounce(client, username: str) -> None:
    """يفصل الجلسة الحيّة (إن وُجدت) كي تُعاد بالبروفايل المُحدَّث فورًا."""
    try:
        active = client.find_ppp_active(username)
        if active:
            client.remove_ppp_active(str(active.get(".id") or active.get("id") or ""))
    except Exception:  # noqa: BLE001 — الفصل تحسين لا شرط
        pass


def run_once(now: datetime | None = None) -> dict:
    """يزامن كوتة كل الأنفاق الفعّالة المُنشأة على CHR التي لها كوتة شهرية.

    يُستدعى من مؤقّت systemd (مثل whatsapp-drain) كل بضع دقائق — اللوحة بلا عامل
    مقيم. يبني عميل CHR مرّة واحدة، يمرّ على الأنفاق، يحفظ، ويعيد ملخّصًا. لا يرفع:
    خطأ نفقٍ لا يكسر البقية."""
    from ..extensions import db
    from ..models import CustomerVpnTunnel
    from . import chr_settings

    summary = {"checked": 0, "throttled": 0, "restored": 0, "errors": 0}
    now = now or datetime.now(timezone.utc)
    try:
        client = chr_settings.build_client()
    except Exception as exc:  # noqa: BLE001 — CHR غير مهيّأ ⇒ لا شيء نفعله
        return {**summary, "fatal": f"CHR client unavailable: {exc}"}

    tunnels = (
        CustomerVpnTunnel.query
        .filter(CustomerVpnTunnel.status == "active")
        .filter(CustomerVpnTunnel.chr_provisioned.is_(True))
        .filter(CustomerVpnTunnel.monthly_quota_gb.isnot(None))
        .filter(CustomerVpnTunnel.monthly_quota_gb > 0)
        .all()
    )
    for tunnel in tunnels:
        summary["checked"] += 1
        res = sync_tunnel(tunnel, client, now=now)
        if not res.get("ok"):
            summary["errors"] += 1
        elif res.get("action") == "throttled":
            summary["throttled"] += 1
        elif res.get("action") == "restored":
            summary["restored"] += 1
    db.session.commit()
    return summary
