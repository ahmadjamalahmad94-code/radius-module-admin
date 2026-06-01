"""WhatsApp send-policy gate.

:func:`can_send` is the single decision point the gateway calls before queuing
or sending a WhatsApp message for a customer. It runs an ordered series of
checks (service enabled, account connected, event allowed, template approved,
subscriber opt-in, quiet hours, then per-minute/daily/monthly rate limits) and
returns the FIRST failing reason as a :class:`PolicyDecision`. Critical events
(OTP, password reset/changed) bypass opt-in and quiet-hours.

All Arabic operator/subscriber-facing messages live in :data:`REASONS`.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from ...models import utcnow
from . import settings as wa_settings
from .phone import WhatsAppPhoneError, normalize_phone_for_whatsapp


@dataclass
class PolicyDecision:
    allowed: bool
    reason: str = ""
    message_ar: str = ""
    normalized_phone: str = ""
    template_id: int | None = None


# Reason code -> Arabic message shown to the operator / subscriber.
REASONS: dict[str, str] = {
    "service_disabled": "خدمة واتساب غير مفعلة لهذا العميل.",
    "whatsapp_not_connected": "لم يتم ربط رقم واتساب بعد.",
    "event_type_not_allowed": "نوع الإشعار غير مسموح في الإعدادات الحالية.",
    "missing_template": "لا يوجد قالب واتساب مربوط لهذا النوع.",
    "template_not_approved": "قالب واتساب غير معتمد أو غير مربوط.",
    "subscriber_not_opted_in": "المشترك لم يوافق على استقبال إشعارات واتساب.",
    "quiet_hours_active": "خارج ساعات الإرسال المسموحة.",
    "per_minute_limit_reached": "تم تجاوز حد الإرسال في الدقيقة.",
    "daily_limit_reached": "تم الوصول إلى الحد اليومي للرسائل.",
    "monthly_limit_reached": "تم الوصول إلى الحد الشهري للرسائل.",
    "invalid_phone": "رقم الهاتف غير صالح للإرسال عبر واتساب.",
    "invalid_payload": "بيانات الطلب غير صالحة.",
}

# Events that bypass opt-in AND quiet-hours (always reach the subscriber).
CRITICAL_EVENTS = {"otp", "password_reset", "password_changed"}

# Event type -> the WhatsAppServiceSettings boolean attr that gates it.
# ``test_message`` is special-cased in can_send (allowed whenever connected).
EVENT_ALLOW_FLAG: dict[str, str] = {
    "otp": "allow_otp",
    "expiry_notice": "allow_expiry_notice",
    "subscription_expiry": "allow_expiry_notice",
    "subscription_expiry_soon": "allow_expiry_notice",
    "quota_warning": "allow_quota_notice",
    "maintenance_notice": "allow_maintenance_notice",
    "password_reset": "allow_password_reset",
    "password_changed": "allow_password_reset",
    "bulk_utility": "allow_bulk_utility",
    "marketing": "allow_marketing",
}


def _block(code: str, *, normalized_phone: str = "") -> PolicyDecision:
    return PolicyDecision(
        allowed=False,
        reason=code,
        message_ar=REASONS[code],
        normalized_phone=normalized_phone,
    )


def _parse_hhmm(value: str | None) -> tuple[int, int] | None:
    """Parse a ``HH:MM`` string into (hour, minute), or None if unusable."""
    if not value:
        return None
    parts = str(value).split(":")
    if len(parts) != 2:
        return None
    try:
        hour, minute = int(parts[0]), int(parts[1])
    except (TypeError, ValueError):
        return None
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        return None
    return hour, minute


def _local_now(now: datetime, timezone: str | None) -> datetime:
    """Return ``now`` in the settings timezone.

    Falls back to the naive ``now`` if the tz is missing/invalid. ``now`` is
    treated as naive UTC (matching :func:`app.models.utcnow`).
    """
    if not timezone:
        return now
    try:
        tz = ZoneInfo(timezone)
    except (ZoneInfoNotFoundError, ValueError, KeyError):
        return now
    base = now.replace(tzinfo=ZoneInfo("UTC")) if now.tzinfo is None else now
    return base.astimezone(tz)


def _within_quiet_hours(local_now: datetime, start: tuple[int, int], end: tuple[int, int]) -> bool:
    """True if ``local_now``'s time is within [start, end), handling midnight wrap."""
    minutes = local_now.hour * 60 + local_now.minute
    start_m = start[0] * 60 + start[1]
    end_m = end[0] * 60 + end[1]
    if start_m == end_m:
        # Zero-length window: never active.
        return False
    if start_m < end_m:
        return start_m <= minutes < end_m
    # Wraps past midnight (e.g. 22:00 -> 06:00).
    return minutes >= start_m or minutes < end_m


def can_send(
    customer_id: int,
    *,
    event_type: str,
    recipient_phone: str,
    template_key: str | None = None,
    subscriber_id=None,
    idempotency_key: str | None = None,
    now: datetime | None = None,
) -> PolicyDecision:
    """Decide whether a WhatsApp message may be queued/sent.

    Runs checks in a fixed order and returns the FIRST failing reason. On
    success returns ``PolicyDecision(allowed=True, ...)`` carrying the
    normalized phone and (if a template was resolved) its id.
    """
    if now is None:
        now = utcnow()

    is_test = event_type == "test_message"

    # 1. Idempotency key is mandatory.
    if not idempotency_key:
        return _block("invalid_payload")

    # 2. Phone must normalize.
    try:
        normalized_phone = normalize_phone_for_whatsapp(recipient_phone)
    except WhatsAppPhoneError:
        return _block("invalid_phone")

    # 3. Service must be enabled.
    settings = wa_settings.get_settings(customer_id)
    if not settings.enabled:
        return _block("service_disabled", normalized_phone=normalized_phone)

    # 4. Account must be connected.
    account = wa_settings.get_account(customer_id)
    if account is None or account.connection_status != "connected":
        return _block("whatsapp_not_connected", normalized_phone=normalized_phone)

    # 5. Event allow flag (test_message is always allowed once connected).
    if not is_test:
        flag_attr = EVENT_ALLOW_FLAG.get(event_type)
        if flag_attr is not None and not bool(getattr(settings, flag_attr, False)):
            return _block("event_type_not_allowed", normalized_phone=normalized_phone)

    # 6. Template approval (skipped for test_message; only when a key is given).
    template_id: int | None = None
    if not is_test and template_key:
        template = wa_settings.get_template(customer_id, template_key, "ar")
        if template is None:
            return _block("missing_template", normalized_phone=normalized_phone)
        if template.status != "approved":
            return _block("template_not_approved", normalized_phone=normalized_phone)
        template_id = template.id

    # 7. Subscriber opt-in (skipped for critical events or when no subscriber).
    if event_type not in CRITICAL_EVENTS and subscriber_id is not None:
        if settings.require_subscriber_opt_in:
            pref = wa_settings.get_subscriber_pref(customer_id, subscriber_id)
            if pref is None or not pref.whatsapp_opt_in or pref.blocked:
                return _block("subscriber_not_opted_in", normalized_phone=normalized_phone)

    # 8. Quiet hours (skipped for critical events).
    if event_type not in CRITICAL_EVENTS and settings.quiet_hours_enabled:
        start = _parse_hhmm(settings.quiet_hours_start)
        end = _parse_hhmm(settings.quiet_hours_end)
        if start is not None and end is not None:
            local_now = _local_now(now, settings.timezone)
            if _within_quiet_hours(local_now, start, end):
                return _block("quiet_hours_active", normalized_phone=normalized_phone)

    # 9. Per-minute rate limit.
    per_minute_limit = settings.per_minute_limit
    if per_minute_limit is not None:
        recent = wa_settings.count_messages_since(customer_id, now - timedelta(seconds=60))
        if recent >= per_minute_limit:
            return _block("per_minute_limit_reached", normalized_phone=normalized_phone)

    # 10. Daily limit.
    if settings.daily_message_limit is not None:
        if wa_settings.count_today(customer_id, now) >= settings.daily_message_limit:
            return _block("daily_limit_reached", normalized_phone=normalized_phone)

    # 11. Monthly limit.
    if settings.monthly_message_limit is not None:
        if wa_settings.count_month(customer_id, now) >= settings.monthly_message_limit:
            return _block("monthly_limit_reached", normalized_phone=normalized_phone)

    return PolicyDecision(
        allowed=True,
        normalized_phone=normalized_phone,
        template_id=template_id,
    )
