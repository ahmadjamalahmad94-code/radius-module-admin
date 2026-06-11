"""اختبارات «السرعة لكل اتجاه على حدة» (per-direction symmetric bandwidth).

السياسة:
    قيمة سرعة واحدة (مثلاً ``850``) تعني ``850↓ تنزيل + 850↑ رفع`` متزامنين،
    وتُترجَم على CHR إلى ``rate-limit = 850M/850M`` (rx=رفع، tx=تنزيل). لا
    تُجمَع أبدًا كقيمة كلية واحدة.

تغطّي هذه الحالات:
    1. صيغة rate-limit الفعلية المرسَلة لـ CHR.
    2. الواجهة المختصرة ``symmetric_rate_limit(850)``.
    3. عرض الواجهة (label عربي).
    4. تطبيع نماذج الإدخال: ``speed_mbps`` يُملِئ التنزيل والرفع معًا.
    5. حسابات السعة المحجوزة لا تحسب الاتجاهين كقيمتين مزدوجَتين.
    6. القيم غير المتماثلة (نادر) تُعرَض صراحةً كي لا تلتبس.
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from app.extensions import db
from app.models import (
    ChrSpeedProfile,
    Customer,
    License,
    Plan,
    ServiceAllocation,
    utcnow,
)
from app.services import speed_profiles as sp


# ───────────────────────── (1) rate-limit format ─────────────────────────


def test_rate_limit_symmetric_emits_value_M_value_M():
    """العقد المركزي: ``rate_limit_string(850, 850)`` ⇒ ``"850M/850M"``."""
    assert sp.rate_limit_string(850, 850) == "850M/850M"
    assert sp.rate_limit_string(10, 10) == "10M/10M"
    assert sp.rate_limit_string(100, 100) == "100M/100M"
    assert sp.rate_limit_string(1000, 1000) == "1000M/1000M"


def test_rate_limit_string_zero_or_missing_is_blank():
    """قيم غير مكتملة ⇒ سلسلة فارغة (لا تشكيل، يستعمل البروفايل الافتراضي)."""
    assert sp.rate_limit_string(0, 0) == ""
    assert sp.rate_limit_string(None, None) == ""
    assert sp.rate_limit_string(850, 0) == ""
    assert sp.rate_limit_string(0, 850) == ""
    assert sp.rate_limit_string("not-a-number", 850) == ""


def test_rate_limit_string_asymmetric_keeps_both_values():
    """حين تختلف القيمتان (نادر) نُبقي كلًّا منهما لا نسوّيهما تلقائيًا."""
    # rx = upload (perspective of router), tx = download
    assert sp.rate_limit_string(100, 50) == "50M/100M"
    assert sp.rate_limit_string(20, 1000) == "1000M/20M"


# ─────────────────── (2) symmetric_rate_limit one-arg API ───────────────────


def test_symmetric_rate_limit_emits_value_M_value_M():
    """قيمة واحدة ⇒ ``"<value>M/<value>M"`` بلا التباس."""
    assert sp.symmetric_rate_limit(850) == "850M/850M"
    assert sp.symmetric_rate_limit("850") == "850M/850M"
    assert sp.symmetric_rate_limit(1) == "1M/1M"


def test_symmetric_rate_limit_blank_on_invalid():
    assert sp.symmetric_rate_limit(0) == ""
    assert sp.symmetric_rate_limit(None) == ""
    assert sp.symmetric_rate_limit("not-a-number") == ""
    assert sp.symmetric_rate_limit(-50) == ""


# ───────────────────────── (3) display label ─────────────────────────


def test_per_direction_label_symmetric():
    """العرض للمتماثل: «850↓ / 850↑ ميجابت» — لا يستعمل كلمة «إجمالي»."""
    text = sp.per_direction_label(850, 850)
    assert "850↓" in text
    assert "850↑" in text
    assert "ميجابت" in text
    assert "غير متماثل" not in text


def test_per_direction_label_asymmetric_marks_it():
    text = sp.per_direction_label(100, 50)
    assert "100↓" in text
    assert "50↑" in text
    assert "غير متماثل" in text


def test_per_direction_label_blank_on_missing():
    assert sp.per_direction_label(0, 0) == "—"
    assert sp.per_direction_label(None, None) == "—"


# ───────────────────────── (4) form normalisation ─────────────────────────


def test_create_profile_with_speed_mbps_fills_both_directions(app):
    """نموذج جديد يرسل ``speed_mbps=850`` فقط ⇒ تنزيل + رفع = 850 تلقائيًا."""
    form = {
        "name": "باقة 850 ميجابت",
        "code": "850m-sym",
        "speed_mbps": "850",
        "active": "1",
    }
    with app.app_context():
        # نمسح أي بروفايل سابق بنفس الرمز كي لا يتعارض seed مع الاختبار.
        ChrSpeedProfile.query.filter_by(code="850m-sym").delete()
        db.session.commit()
        profile = sp.create_profile(form)
        db.session.commit()
        db.session.refresh(profile)
        assert profile.download_mbps == 850
        assert profile.upload_mbps == 850
        assert sp.rate_limit_string(profile.download_mbps, profile.upload_mbps) == "850M/850M"


def test_create_profile_legacy_separate_fields_still_works(app):
    """النموذج المتقدّم (قيمتان منفصلتان) يجب أن يبقى مدعومًا للحالات النادرة."""
    form = {
        "name": "غير متماثل اختبار",
        "code": "asym-test",
        "download_mbps": "1000",
        "upload_mbps": "100",
        "active": "1",
    }
    with app.app_context():
        ChrSpeedProfile.query.filter_by(code="asym-test").delete()
        db.session.commit()
        profile = sp.create_profile(form)
        db.session.commit()
        db.session.refresh(profile)
        assert profile.download_mbps == 1000
        assert profile.upload_mbps == 100
        # rate-limit يحفظ القيمتين منفصلتين (RouterOS rx/tx).
        assert sp.rate_limit_string(profile.download_mbps, profile.upload_mbps) == "100M/1000M"


def test_speed_mbps_wins_over_separate_fields_if_both_sent(app):
    """إن وصلت كلتاهما (تسرّب أو UI قديم) فإن ``speed_mbps`` تفوز كي لا
    تتسرَّب قيمة غير متماثلة بالخطأ."""
    form = {
        "name": "حسم المتماثل",
        "code": "sym-wins",
        "speed_mbps": "200",
        "download_mbps": "999",  # ينبغي تجاهلها لصالح speed_mbps
        "upload_mbps": "1",      # نفس الشيء
        "active": "1",
    }
    with app.app_context():
        ChrSpeedProfile.query.filter_by(code="sym-wins").delete()
        db.session.commit()
        profile = sp.create_profile(form)
        db.session.commit()
        db.session.refresh(profile)
        assert profile.download_mbps == 200
        assert profile.upload_mbps == 200


# ─────────────────── (5) capacity math is per-direction ───────────────────


def test_reserved_capacity_sums_speed_limit_mbps_once_not_doubled(app):
    """``_fleet_reserved_mbps`` يجمع ``speed_limit_mbps`` بنفس القيمة لكل
    تخصيص — لا يجمع التنزيل + الرفع لينتج ضِعفًا.

    سيناريو: تخصيصان كل واحد بـ850 ⇒ المحجوز = 1700 (= 850 + 850)، لا
    3400 (= 850×2 لاتجاهين × تخصيصَين). نسبق ذلك بإنشاء عميل وتجهيز
    fleet node حقيقي.
    """
    from app.admin.infra_routes import _fleet_reserved_mbps
    from fleet.registry.models_chr import FleetChrNode, FleetProvider

    with app.app_context():
        provider = FleetProvider(name="acme-bw-test", cost_model="open")
        db.session.add(provider)
        db.session.flush()
        node = FleetChrNode(
            provider_id=provider.id, name="bw-test-node-1",
            public_ip="203.0.113.31", wg_mgmt_ip="10.99.0.31",
            wg_mgmt_pubkey="x" * 44,
            routeros_api_port=8729, coa_port=3799,
            max_sessions=500, link_speed_mbps=10000,
            weight=1.0, enabled=True, drain=False, status="up",
        )
        db.session.add(node)
        db.session.flush()

        plan = Plan.query.filter_by(slug="pro").first()
        cust = Customer(company_name="BW Test ISP", status="active")
        db.session.add(cust)
        db.session.flush()
        lic = License(
            customer_id=cust.id, plan_id=plan.id,
            license_key="HBR-BW-TEST-0001", status="active",
            starts_at=utcnow(), expires_at=utcnow() + timedelta(days=30),
            max_fingerprints=3,
        )
        db.session.add(lic)
        db.session.flush()

        # تخصيصان نشطان كل واحد بسرعة 850 (لكل اتجاه على حدة).
        for i in range(2):
            db.session.add(ServiceAllocation(
                customer_id=cust.id,
                service_type="sstp",
                status="active",
                fleet_chr_node_id=node.id,
                speed_limit_mbps=850,
                max_accounts=10,
                max_peers=0,
            ))
        db.session.commit()

        reserved = _fleet_reserved_mbps(node)
        # المتوقَّع: 850 + 850 = 1700 (لكل اتجاه على حدة). لا 3400.
        assert reserved == 1700, (
            f"المحجوز لكل اتجاه يجب أن يكون 1700 (850×2)؛ تحصَّلنا على {reserved}. "
            "لو نتج 3400 معناه أن الحساب يضاعف الاتجاهين بالخطأ."
        )
        # السعة المتاحة (per-direction) = link_speed_mbps - reserved.
        assert (node.link_speed_mbps - reserved) == 8300


# ─────────────────── (6) UI renders per-direction labels ───────────────────


def test_speed_profiles_page_renders_per_direction_label(app, client):
    """صفحة بروفايلات السرعة تعرض ``X↓ / Y↑`` لا قيمة منفردة مبهمة."""
    # نُنشئ بروفايلًا حتى يظهر في الجدول.
    with app.app_context():
        if not ChrSpeedProfile.query.filter_by(code="200m-ui").first():
            db.session.add(ChrSpeedProfile(
                name="باقة 200", code="200m-ui",
                download_mbps=200, upload_mbps=200, active=True,
            ))
            db.session.commit()
    _login_admin(client)
    rv = client.get("/admin/chr/speed-profiles")
    assert rv.status_code == 200, rv.data[:200]
    body = rv.data.decode("utf-8")
    # علامات per-direction موجودة في الصفحة.
    assert "↓" in body
    assert "↑" in body
    # rate-limit المعروض في الجدول يطابق العقد.
    assert "200M/200M" in body
    # شرح «لكل اتجاه» يظهر فوق نموذج الإدخال.
    assert "لكل اتجاه" in body


# ───────────────────────── helpers ─────────────────────────


def _login_admin(client):
    """يُسجّل دخول المسؤول الافتراضي (CSRF متضمَّن في صفحة الدخول)."""
    client.get("/login")
    with client.session_transaction() as sess:
        token = sess.get("_csrf_token")
    return client.post(
        "/login",
        data={"username": "admin", "password": "admin12345", "_csrf_token": token or ""},
        follow_redirects=False,
    )
