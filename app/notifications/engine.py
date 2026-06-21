"""Scheduled countdown / depletion alert engine.

One idempotent pass (:func:`scan_once`) emits notifications at thresholds:

* License / subscription expiry — 7/3/1 days before + on expiry.
* IP-change service expiry (``ServiceAllocation`` service_type='ip_change')
  — same 7/3/1 + on expiry.
* Trial-period expiry — FLAGGED: there is no trial model today (no
  ``trial_ends_at`` / ``Plan.is_trial``). The source is wired but a no-op
  until a trial field exists; see :func:`_trial_deadline`.
* Message-package depletion — when remaining hits 100 / 50 / empty
  (``WhatsAppServiceSettings.monthly_message_limit`` − usage).
* Billing overdue — pending payment requests past their ``expires_at``.

Each threshold fires exactly once via a stable ``dedupe_key``. ``<=`` crossing
semantics make it robust to a missed scan (a threshold still fires the first
time the value drops at-or-below it).

Run it via the ``notifications-scan`` CLI command (cron/systemd timer) or the
opt-in background worker. Safe to run as often as you like.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from app.extensions import db
from app.models import (
    Customer,
    License,
    LicensePaymentRequest,
    ServiceAllocation,
    WhatsAppServiceSettings,
    WhatsAppUsageCounter,
    utcnow,
)

from . import billing, service
from .thresholds import expiry_thresholds, package_thresholds

logger = logging.getLogger(__name__)


@dataclass
class ScanSummary:
    checked: dict[str, int] = field(default_factory=dict)
    emitted: int = 0
    notification_ids: list[int] = field(default_factory=list)

    def _bump(self, source: str) -> None:
        self.checked[source] = self.checked.get(source, 0) + 1

    def to_dict(self) -> dict:
        return {"checked": self.checked, "emitted": self.emitted}


def _days_left(deadline: datetime, now: datetime) -> int:
    """Whole days until ``deadline`` (negative once past). Tests pass exact
    timedeltas so a +7d deadline yields 7."""
    return (deadline - now).days


def _emit_countdown(
    summary: ScanSummary,
    *,
    source: str,
    type: str,
    deadline: datetime,
    now: datetime,
    key_prefix: str,
    title_for,
    body_for,
    customer_id: Optional[int],
    license_id: Optional[int] = None,
    link: str = "",
) -> None:
    """Shared 7/3/1 + on-expiry emitter for any dated source."""
    days = _days_left(deadline, now)
    # On/after expiry → one terminal notification.
    if days <= 0:
        note = service.create(
            type=type, severity="critical",
            title=title_for(0), body=body_for(0),
            customer_id=customer_id, license_id=license_id, link=link,
            dedupe_key=f"{key_prefix}:expired",
        )
        if note.id not in summary.notification_ids:
            summary.emitted += 1
            summary.notification_ids.append(note.id)
        return
    # Pre-expiry thresholds: fire each level the value has dropped at/below.
    for t in expiry_thresholds():
        if days <= t:
            sev = "critical" if t <= 1 else "warning"
            note = service.create(
                type=type, severity=sev,
                title=title_for(days), body=body_for(days),
                customer_id=customer_id, license_id=license_id, link=link,
                dedupe_key=f"{key_prefix}:{t}d",
            )
            if note.id not in summary.notification_ids:
                summary.emitted += 1
                summary.notification_ids.append(note.id)


# ── individual sources ───────────────────────────────────────────────────
def _scan_licenses(summary: ScanSummary, now: datetime) -> None:
    rows = (License.query
            .filter(License.status == "active")
            .filter(License.expires_at.isnot(None))
            .all())
    for lic in rows:
        summary._bump("license")
        name = _customer_name(lic.customer_id)
        _emit_countdown(
            summary, source="license", type="license_expiry",
            deadline=lic.expires_at, now=now,
            key_prefix=f"license_expiry:{lic.id}",
            title_for=lambda d: ("انتهى الاشتراك" if d <= 0
                                 else f"الاشتراك ينتهي خلال {d} يوم"),
            body_for=lambda d, n=name, k=lic.license_key: (
                f"اشتراك العميل «{n}» (ترخيص {k}) "
                + ("قد انتهى." if d <= 0 else f"ينتهي خلال {d} يوم. جدِّد قبل الانقطاع.")),
            customer_id=lic.customer_id, license_id=lic.id,
        )


def _scan_ip_change(summary: ScanSummary, now: datetime) -> None:
    rows = (ServiceAllocation.query
            .filter(ServiceAllocation.service_type == "ip_change")
            .filter(ServiceAllocation.status == "active")
            .filter(ServiceAllocation.expires_at.isnot(None))
            .all())
    for alloc in rows:
        summary._bump("ip_change")
        name = _customer_name(alloc.customer_id)
        _emit_countdown(
            summary, source="ip_change", type="ip_change_expiry",
            deadline=alloc.expires_at, now=now,
            key_prefix=f"ip_change_expiry:{alloc.id}",
            title_for=lambda d: ("انتهت خدمة تغيير IP" if d <= 0
                                 else f"خدمة تغيير IP تنتهي خلال {d} يوم"),
            body_for=lambda d, n=name: (
                f"خدمة تغيير IP للعميل «{n}» "
                + ("قد انتهت." if d <= 0 else f"تنتهي خلال {d} يوم.")),
            customer_id=alloc.customer_id,
        )


def _trial_deadline(lic: License):
    """Trial expiry deadline for a license, or None.

    FLAGGED: the schema has no trial concept yet (no ``trial_ends_at`` /
    ``Plan.is_trial``). We read an optional ``trial_ends_at`` attribute if a
    future migration adds it, so this source activates with zero code change.
    Until then it returns None and the trial source emits nothing.
    """
    return getattr(lic, "trial_ends_at", None)


def _scan_trials(summary: ScanSummary, now: datetime) -> None:
    rows = License.query.filter(License.status == "active").all()
    for lic in rows:
        deadline = _trial_deadline(lic)
        if deadline is None:
            continue  # no trial data — flagged no-op
        summary._bump("trial")
        name = _customer_name(lic.customer_id)
        _emit_countdown(
            summary, source="trial", type="trial_expiry",
            deadline=deadline, now=now,
            key_prefix=f"trial_expiry:{lic.id}",
            title_for=lambda d: ("انتهت الفترة التجريبية" if d <= 0
                                 else f"الفترة التجريبية تنتهي خلال {d} يوم"),
            body_for=lambda d, n=name: (
                f"الفترة التجريبية للعميل «{n}» "
                + ("انتهت." if d <= 0 else f"تنتهي خلال {d} يوم.")),
            customer_id=lic.customer_id, license_id=lic.id,
        )


def _scan_message_packages(summary: ScanSummary, now: datetime) -> None:
    """Remaining = monthly_message_limit − sent_count (current month).

    Interpretation FLAGGED in the report: there is no purchased-balance
    column; "remaining" is the monthly allowance minus usage this period.
    The period is in the dedupe key so it resets each month.
    """
    period_key = now.strftime("%Y-%m")
    rows = WhatsAppServiceSettings.query.filter_by(enabled=True).all()
    for cfg in rows:
        limit = int(cfg.monthly_message_limit or 0)
        if limit <= 0:
            continue
        summary._bump("message_package")
        counter = (WhatsAppUsageCounter.query
                   .filter_by(customer_id=cfg.customer_id,
                              period_type="monthly", period_key=period_key)
                   .first())
        sent = int(counter.sent_count or 0) if counter else 0
        remaining = limit - sent
        name = _customer_name(cfg.customer_id)
        if remaining <= 0:
            note = service.create(
                type="message_package_empty", severity="critical",
                title="نفدت رسائل الباقة",
                body=f"باقة رسائل العميل «{name}» نفدت لهذا الشهر ({sent}/{limit}).",
                customer_id=cfg.customer_id,
                dedupe_key=f"message_package:{cfg.customer_id}:{period_key}:empty",
            )
            if note.id not in summary.notification_ids:
                summary.emitted += 1
                summary.notification_ids.append(note.id)
            continue
        for t in package_thresholds():
            if remaining <= t:
                sev = "critical" if t <= 50 else "warning"
                note = service.create(
                    type="message_package_low", severity=sev,
                    title=f"باقة الرسائل: متبقٍّ {remaining}",
                    body=(f"باقة رسائل العميل «{name}» اقتربت من النفاد — "
                          f"متبقٍّ {remaining} من {limit} هذا الشهر."),
                    customer_id=cfg.customer_id,
                    dedupe_key=f"message_package:{cfg.customer_id}:{period_key}:{t}",
                )
                if note.id not in summary.notification_ids:
                    summary.emitted += 1
                    summary.notification_ids.append(note.id)


def _scan_overdue_invoices(summary: ScanSummary, now: datetime) -> None:
    rows = (LicensePaymentRequest.query
            .filter(LicensePaymentRequest.status == "pending")
            .filter(LicensePaymentRequest.expires_at.isnot(None))
            .filter(LicensePaymentRequest.expires_at < now)
            .all())
    for req in rows:
        summary._bump("overdue")
        note = billing.notify_payment_overdue(req)
        if note is not None and note.id not in summary.notification_ids:
            summary.emitted += 1
            summary.notification_ids.append(note.id)


def _customer_name(customer_id: Optional[int]) -> str:
    if not customer_id:
        return "—"
    c = db.session.get(Customer, customer_id)
    return (c.company_name if c else "—") or "—"


# ── public entrypoint ────────────────────────────────────────────────────
def scan_once(now: Optional[datetime] = None, *, commit: bool = True) -> ScanSummary:
    """One idempotent pass over every source. Returns a :class:`ScanSummary`.

    ``now`` is injectable for tests. ``commit=False`` lets a caller batch.
    """
    now = now or utcnow()
    summary = ScanSummary()
    for fn in (_scan_licenses, _scan_ip_change, _scan_trials,
               _scan_message_packages, _scan_overdue_invoices):
        try:
            fn(summary, now)
        except Exception:  # noqa: BLE001 — one bad source never kills the pass
            logger.exception("notify-engine: source %s failed", fn.__name__)
    if commit:
        db.session.commit()
    return summary
