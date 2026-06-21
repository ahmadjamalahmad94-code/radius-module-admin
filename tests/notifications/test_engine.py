"""Countdown / depletion engine: fires at 7/3/1 + 100/50, once each."""
from __future__ import annotations

from datetime import timedelta

from app.notifications.engine import scan_once
from app.notifications.models import Notification

from .conftest import (
    BASE_NOW,
    seed_customer,
    seed_ip_change,
    seed_license,
    seed_whatsapp,
    set_usage,
)


def _keys(prefix: str) -> set[str]:
    return {n.dedupe_key for n in Notification.query.all()
            if n.dedupe_key and n.dedupe_key.startswith(prefix)}


def test_license_expiry_fires_at_7_3_1_and_expired_once_each(app):
    cust = seed_customer()
    deadline = BASE_NOW + timedelta(days=30)
    lic = seed_license(cust, expires_at=deadline)
    pfx = f"license_expiry:{lic.id}"

    # 7 days out → only the 7d threshold.
    scan_once(now=deadline - timedelta(days=7))
    assert _keys(pfx) == {f"{pfx}:7d"}

    # 3 days out → 3d added (7d already there, not duplicated).
    scan_once(now=deadline - timedelta(days=3))
    assert _keys(pfx) == {f"{pfx}:7d", f"{pfx}:3d"}

    # 1 day out → 1d added.
    scan_once(now=deadline - timedelta(days=1))
    assert _keys(pfx) == {f"{pfx}:7d", f"{pfx}:3d", f"{pfx}:1d"}

    # On expiry → terminal "expired".
    scan_once(now=deadline)
    assert _keys(pfx) == {f"{pfx}:7d", f"{pfx}:3d", f"{pfx}:1d", f"{pfx}:expired"}

    # Idempotent: re-running changes nothing.
    before = Notification.query.count()
    scan_once(now=deadline)
    assert Notification.query.count() == before


def test_license_threshold_each_fires_exactly_once(app):
    cust = seed_customer()
    deadline = BASE_NOW + timedelta(days=10)
    lic = seed_license(cust, expires_at=deadline)
    pfx = f"license_expiry:{lic.id}"
    # Scan the SAME 7-day point twice — second is a no-op.
    scan_once(now=deadline - timedelta(days=7))
    scan_once(now=deadline - timedelta(days=7))
    assert Notification.query.filter_by(dedupe_key=f"{pfx}:7d").count() == 1


def test_ip_change_expiry_fires_at_thresholds(app):
    cust = seed_customer()
    deadline = BASE_NOW + timedelta(days=30)
    alloc = seed_ip_change(cust, expires_at=deadline)
    pfx = f"ip_change_expiry:{alloc.id}"
    scan_once(now=deadline - timedelta(days=7))
    scan_once(now=deadline - timedelta(days=3))
    scan_once(now=deadline - timedelta(days=1))
    assert _keys(pfx) == {f"{pfx}:7d", f"{pfx}:3d", f"{pfx}:1d"}


def test_message_package_fires_at_100_50_empty_once_each(app):
    cust = seed_customer()
    counter = seed_whatsapp(cust, limit=500, sent=0, period_key="2026-06")
    pfx = f"message_package:{cust.id}:2026-06"

    # remaining 100 → :100
    set_usage(counter, 400)
    scan_once(now=BASE_NOW)
    assert _keys(pfx) == {f"{pfx}:100"}

    # remaining 50 → :50 added
    set_usage(counter, 450)
    scan_once(now=BASE_NOW)
    assert _keys(pfx) == {f"{pfx}:100", f"{pfx}:50"}

    # remaining 0 → :empty added
    set_usage(counter, 500)
    scan_once(now=BASE_NOW)
    assert _keys(pfx) == {f"{pfx}:100", f"{pfx}:50", f"{pfx}:empty"}

    # Idempotent.
    before = Notification.query.count()
    scan_once(now=BASE_NOW)
    assert Notification.query.count() == before


def test_message_package_period_resets_dedupe(app):
    cust = seed_customer()
    counter = seed_whatsapp(cust, limit=500, sent=450, period_key="2026-07")
    # Counter is for July; scan in July → July-keyed dedupe (distinct from June).
    from datetime import datetime
    scan_once(now=datetime(2026, 7, 15, 12, 0, 0))
    assert Notification.query.filter_by(
        dedupe_key=f"message_package:{cust.id}:2026-07:50").count() == 1


def test_trial_source_is_noop_without_trial_field(app):
    """FLAGGED: no trial model exists; the trial source must emit nothing."""
    cust = seed_customer()
    seed_license(cust, expires_at=BASE_NOW + timedelta(days=2))
    scan_once(now=BASE_NOW)
    assert Notification.query.filter_by(type="trial_expiry").count() == 0
