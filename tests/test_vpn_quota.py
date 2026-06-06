"""اختبارات وحدة لدالّة القرار الخالصة :func:`decide` في كوتة أنفاق CHR.

``decide`` بلا DB/شبكة، لذا تُختبر مباشرةً: تراكم الدلتا، إعادة الاتصال، عبور
الكوتة (تخفيض)، عدم تكرار التخفيض، تدوير الشهر (تصفير + استعادة)، وكوتة 0 (بلا حد).
"""
from app.services.vpn_quota import decide, gb_to_bytes


def test_same_session_delta_accumulates_under_quota():
    """نفس الجلسة مستمرة (live>=sample): الدلتا تُضاف، تحت الكوتة فلا تخفيض."""
    d = decide(
        stored_period="2026-06",
        bytes_used=1_000,
        sample_bytes=500,
        live_session_bytes=800,
        quota_bytes=gb_to_bytes(100),
        is_throttled=False,
        now_period="2026-06",
    )
    assert d.period == "2026-06"
    assert d.bytes_used == 1_300          # 1000 + (800 - 500)
    assert d.sample_bytes == 800
    assert d.should_throttle is False
    assert d.should_restore is False
    assert d.exhausted is False


def test_reconnect_counts_live_as_delta():
    """أُعيد الاتصال (live<sample ⇒ عدّاد الجلسة صُفِّر): تُحتسب live كاملةً كدلتا."""
    d = decide(
        stored_period="2026-06",
        bytes_used=5_000,
        sample_bytes=1_000,
        live_session_bytes=200,
        quota_bytes=gb_to_bytes(100),
        is_throttled=False,
        now_period="2026-06",
    )
    assert d.bytes_used == 5_200          # 5000 + 200 (لا 5000 + (200-1000))
    assert d.sample_bytes == 200
    assert d.should_throttle is False
    assert d.exhausted is False


def test_crossing_quota_throttles_and_exhausts():
    """بلوغ الكوتة لأول مرّة: تخفيض + استنفاد."""
    quota = 1_000
    d = decide(
        stored_period="2026-06",
        bytes_used=900,
        sample_bytes=0,
        live_session_bytes=200,
        quota_bytes=quota,
        is_throttled=False,
        now_period="2026-06",
    )
    assert d.bytes_used == 1_100          # >= 1000
    assert d.exhausted is True
    assert d.should_throttle is True
    assert d.should_restore is False


def test_already_throttled_and_over_does_not_repeat():
    """مخفّض أصلًا وما زال فوق الكوتة: لا تخفيض مكرّر ولا استعادة."""
    quota = 1_000
    d = decide(
        stored_period="2026-06",
        bytes_used=2_000,
        sample_bytes=2_000,
        live_session_bytes=2_500,
        quota_bytes=quota,
        is_throttled=True,
        now_period="2026-06",
    )
    assert d.exhausted is True
    assert d.should_throttle is False     # لا تكرار
    assert d.should_restore is False


def test_month_rollover_resets_and_restores():
    """تدوير الشهر: تصفير العدّاد، تحديث الفترة، واستعادة السرعة إن كان مخفّضًا."""
    d = decide(
        stored_period="2026-05",
        bytes_used=9_999,
        sample_bytes=4_000,
        live_session_bytes=4_500,
        quota_bytes=gb_to_bytes(50),
        is_throttled=True,
        now_period="2026-06",
    )
    assert d.bytes_used == 0
    assert d.period == "2026-06"
    assert d.sample_bytes == 4_500        # أساس العيّنة = الجلسة الحيّة الحالية
    assert d.should_restore is True
    assert d.should_throttle is False
    assert d.exhausted is False


def test_zero_quota_never_throttles_but_restores_if_throttled():
    """كوتة 0 ⇒ بلا حد: لا تخفيض إطلاقًا، لكن استعِد السرعة إن كان مخفّضًا سابقًا."""
    # مخفّض سابقًا ثم أُزيلت الكوتة ⇒ يجب استعادته.
    d = decide(
        stored_period="2026-06",
        bytes_used=10_000,
        sample_bytes=0,
        live_session_bytes=5_000,
        quota_bytes=0,
        is_throttled=True,
        now_period="2026-06",
    )
    assert d.should_throttle is False
    assert d.should_restore is True
    assert d.exhausted is False

    # غير مخفّض وبلا كوتة ⇒ لا فعل.
    d2 = decide(
        stored_period="2026-06",
        bytes_used=10_000,
        sample_bytes=0,
        live_session_bytes=5_000,
        quota_bytes=0,
        is_throttled=False,
        now_period="2026-06",
    )
    assert d2.should_throttle is False
    assert d2.should_restore is False
    assert d2.exhausted is False
