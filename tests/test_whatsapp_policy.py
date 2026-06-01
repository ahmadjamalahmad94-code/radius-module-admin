from __future__ import annotations

from datetime import datetime, timedelta

from app.extensions import db
from app.models import Customer, WhatsAppMessageQueue
from app.services.whatsapp import settings as wa
from app.services.whatsapp.policy import can_send


GOOD_PHONE = "0599123456"          # normalizes to +970599123456
SUBSCRIBER_ID = "sub-1"


def make_customer(name: str = "WA Policy ISP") -> Customer:
    customer = Customer(company_name=name, contact_name="Admin", email="wap@example.test")
    db.session.add(customer)
    db.session.commit()
    return customer


def build_allowed_baseline() -> Customer:
    """Customer fully provisioned so can_send(...) returns allowed=True."""
    customer = make_customer()
    # Connected account.
    wa.upsert_account(customer.id, phone_number_id="123", access_token="tok-value")
    wa.set_connection_status(customer.id, "connected")
    # Enabled settings, generous limits, no quiet hours.
    wa.update_settings(
        customer.id,
        enabled=True,
        allow_otp=True,
        allow_expiry_notice=True,
        require_subscriber_opt_in=True,
        quiet_hours_enabled=False,
        per_minute_limit=10,
        daily_message_limit=100,
        monthly_message_limit=500,
    )
    # Approved template for the expiry_notice path.
    wa.upsert_template(customer.id, local_key="expiry_ar", status="approved")
    # Opted-in subscriber.
    wa.upsert_subscriber_prefs(customer.id, [
        {"subscriber_id": SUBSCRIBER_ID, "phone": GOOD_PHONE, "whatsapp_opt_in": True},
    ])
    return customer


def _decide(customer, **overrides):
    kwargs = dict(
        event_type="expiry_notice",
        recipient_phone=GOOD_PHONE,
        template_key="expiry_ar",
        subscriber_id=SUBSCRIBER_ID,
        idempotency_key="idem-1",
    )
    kwargs.update(overrides)
    return can_send(customer.id, **kwargs)


def _seed_queue_rows(customer_id: int, created_at: datetime, count: int, *, prefix: str) -> None:
    for i in range(count):
        row = WhatsAppMessageQueue(
            customer_id=customer_id,
            source_system="radius_module",
            source_event_type="expiry_notice",
            recipient_phone="+970599000001",
            normalized_recipient_phone="+970599000001",
            idempotency_key=f"{prefix}-{i}",
            status="queued",
        )
        db.session.add(row)
        db.session.flush()
        row.created_at = created_at
    db.session.commit()


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------
def test_baseline_is_allowed(app):
    customer = build_allowed_baseline()
    decision = _decide(customer)
    assert decision.allowed is True
    assert decision.reason == ""
    assert decision.normalized_phone == "+970599123456"
    assert decision.template_id is not None


# ---------------------------------------------------------------------------
# One flipped condition each -> exact reason
# ---------------------------------------------------------------------------
def test_missing_idempotency_key(app):
    customer = build_allowed_baseline()
    decision = _decide(customer, idempotency_key=None)
    assert decision.allowed is False
    assert decision.reason == "invalid_payload"


def test_invalid_phone(app):
    customer = build_allowed_baseline()
    decision = _decide(customer, recipient_phone="not-a-number")
    assert decision.allowed is False
    assert decision.reason == "invalid_phone"


def test_service_disabled(app):
    customer = build_allowed_baseline()
    wa.update_settings(customer.id, enabled=False)
    decision = _decide(customer)
    assert decision.allowed is False
    assert decision.reason == "service_disabled"
    # Phone was normalized before the gate tripped.
    assert decision.normalized_phone == "+970599123456"


def test_not_connected(app):
    customer = build_allowed_baseline()
    wa.set_connection_status(customer.id, "disconnected")
    decision = _decide(customer)
    assert decision.allowed is False
    assert decision.reason == "whatsapp_not_connected"


def test_event_allow_flag_off(app):
    customer = build_allowed_baseline()
    wa.update_settings(customer.id, allow_expiry_notice=False)
    decision = _decide(customer)
    assert decision.allowed is False
    assert decision.reason == "event_type_not_allowed"


def test_missing_template(app):
    customer = build_allowed_baseline()
    decision = _decide(customer, template_key="does_not_exist")
    assert decision.allowed is False
    assert decision.reason == "missing_template"


def test_template_not_approved(app):
    customer = build_allowed_baseline()
    wa.set_template_status(customer.id, "expiry_ar", "ar", "draft")
    decision = _decide(customer)
    assert decision.allowed is False
    assert decision.reason == "template_not_approved"


def test_subscriber_not_opted_in(app):
    customer = build_allowed_baseline()
    wa.upsert_subscriber_prefs(customer.id, [
        {"subscriber_id": SUBSCRIBER_ID, "whatsapp_opt_in": False},
    ])
    decision = _decide(customer)
    assert decision.allowed is False
    assert decision.reason == "subscriber_not_opted_in"


def test_otp_allowed_even_with_no_opt_in(app):
    customer = build_allowed_baseline()
    # OTP needs an approved template too; create one and opt the sub OUT.
    wa.upsert_template(customer.id, local_key="otp_ar", status="approved")
    wa.upsert_subscriber_prefs(customer.id, [
        {"subscriber_id": SUBSCRIBER_ID, "whatsapp_opt_in": False},
    ])
    decision = _decide(customer, event_type="otp", template_key="otp_ar")
    # CRITICAL_EVENTS bypass opt-in entirely.
    assert decision.allowed is True
    assert decision.reason == ""


def test_otp_allowed_with_no_subscriber_pref_row(app):
    customer = build_allowed_baseline()
    wa.upsert_template(customer.id, local_key="otp_ar", status="approved")
    decision = _decide(customer, event_type="otp", template_key="otp_ar", subscriber_id="ghost")
    assert decision.allowed is True


# ---------------------------------------------------------------------------
# Quiet hours (inject now); OTP bypasses
# ---------------------------------------------------------------------------
def test_quiet_hours_active_blocks_non_critical(app):
    customer = build_allowed_baseline()
    # Window 22:00 -> 06:00 local; pick a UTC 'now' that lands inside it.
    wa.update_settings(
        customer.id,
        quiet_hours_enabled=True,
        quiet_hours_start="22:00",
        quiet_hours_end="06:00",
        timezone="UTC",
    )
    now_inside = datetime(2026, 6, 15, 23, 0, 0)  # 23:00 UTC -> within window
    decision = _decide(customer, now=now_inside)
    assert decision.allowed is False
    assert decision.reason == "quiet_hours_active"


def test_quiet_hours_bypassed_by_otp(app):
    customer = build_allowed_baseline()
    wa.upsert_template(customer.id, local_key="otp_ar", status="approved")
    wa.update_settings(
        customer.id,
        quiet_hours_enabled=True,
        quiet_hours_start="22:00",
        quiet_hours_end="06:00",
        timezone="UTC",
    )
    now_inside = datetime(2026, 6, 15, 23, 0, 0)
    decision = _decide(customer, event_type="otp", template_key="otp_ar", now=now_inside)
    assert decision.allowed is True


def test_quiet_hours_outside_window_allowed(app):
    customer = build_allowed_baseline()
    wa.update_settings(
        customer.id,
        quiet_hours_enabled=True,
        quiet_hours_start="22:00",
        quiet_hours_end="06:00",
        timezone="UTC",
    )
    now_outside = datetime(2026, 6, 15, 12, 0, 0)  # midday: outside window
    decision = _decide(customer, now=now_outside)
    assert decision.allowed is True


# ---------------------------------------------------------------------------
# Rate limits (seed queue rows + inject now)
# ---------------------------------------------------------------------------
def test_per_minute_limit_reached(app):
    customer = build_allowed_baseline()
    wa.update_settings(customer.id, per_minute_limit=3)
    now = datetime(2026, 6, 15, 12, 0, 0)
    # 3 messages in the last 60s == limit reached.
    _seed_queue_rows(customer.id, now - timedelta(seconds=10), 3, prefix="pm")
    decision = _decide(customer, now=now)
    assert decision.allowed is False
    assert decision.reason == "per_minute_limit_reached"


def test_daily_limit_reached(app):
    customer = build_allowed_baseline()
    wa.update_settings(customer.id, per_minute_limit=1000, daily_message_limit=5)
    now = datetime(2026, 6, 15, 12, 0, 0)
    # 5 rows earlier today (older than 60s so per-minute does not trip first).
    _seed_queue_rows(customer.id, now - timedelta(hours=3), 5, prefix="day")
    decision = _decide(customer, now=now)
    assert decision.allowed is False
    assert decision.reason == "daily_limit_reached"


def test_monthly_limit_reached(app):
    customer = build_allowed_baseline()
    wa.update_settings(
        customer.id,
        per_minute_limit=1000,
        daily_message_limit=1000,
        monthly_message_limit=4,
    )
    now = datetime(2026, 6, 15, 12, 0, 0)
    # 4 rows earlier this month, before today, so only monthly trips.
    _seed_queue_rows(customer.id, datetime(2026, 6, 3, 9, 0, 0), 4, prefix="mon")
    decision = _decide(customer, now=now)
    assert decision.allowed is False
    assert decision.reason == "monthly_limit_reached"
