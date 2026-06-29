from __future__ import annotations

from datetime import datetime, timedelta

from app.extensions import db
from app.models import (
    Customer,
    WhatsAppMessageQueue,
    WhatsAppServiceSettings,
    WhatsAppUsageCounter,
    utcnow,
)
from app.services.whatsapp import settings as wa
from app.services.whatsapp.crypto import decrypt_secret


def make_customer(name: str = "WA ISP") -> Customer:
    customer = Customer(company_name=name, contact_name="Admin", email="wa@example.test")
    db.session.add(customer)
    db.session.commit()
    return customer


def _seed_queue(customer_id: int, created_at: datetime, *, status: str = "queued", idem: str) -> WhatsAppMessageQueue:
    row = WhatsAppMessageQueue(
        customer_id=customer_id,
        source_system="radius_module",
        source_event_type="otp",
        recipient_phone="+970599000001",
        normalized_recipient_phone="+970599000001",
        idempotency_key=idem,
        status=status,
    )
    db.session.add(row)
    db.session.flush()
    # created_at has a server-side default; override explicitly for the test.
    row.created_at = created_at
    db.session.commit()
    return row


# ---------------------------------------------------------------------------
# Account credentials: encryption + masking + partial save
# ---------------------------------------------------------------------------
def test_upsert_account_encrypts_token(app):
    customer = make_customer()
    token = "EAABsbCS1iHgBO9xQ_super_secret_meta_token"
    account = wa.upsert_account(
        customer.id,
        phone_number_id="123456789",
        display_phone_number="+970599000000",
        business_display_name="Acme",
        access_token=token,
        app_secret="app-secret-value",
        webhook_verify_token="verify-token-123",
    )
    # Stored ciphertext is not the plaintext, and round-trips back.
    assert account.access_token_encrypted
    assert account.access_token_encrypted != token
    assert decrypt_secret(account.access_token_encrypted) == token
    # App secret stored encrypted too; verify token stored only as a hash.
    assert account.webhook_secret_encrypted
    assert account.webhook_secret_encrypted != "app-secret-value"
    assert account.webhook_verify_token_hash
    assert account.webhook_verify_token_hash != "verify-token-123"


def test_account_public_dict_has_no_secrets_but_masked_preview(app):
    customer = make_customer()
    token = "EAABsbCS1iHgBO9xQ_super_secret_meta_token"
    account = wa.upsert_account(
        customer.id,
        phone_number_id="123456789",
        access_token=token,
        app_secret="app-secret-value",
        webhook_verify_token="verify-token-123",
    )
    public = wa.account_public_dict(account)

    # No secret material of any kind leaks into the public dict.
    blob = repr(public)
    assert token not in blob
    assert account.access_token_encrypted not in blob
    assert "app-secret-value" not in blob
    assert "verify-token-123" not in blob
    assert "access_token_encrypted" not in public
    assert "webhook_secret_encrypted" not in public
    assert "webhook_verify_token_hash" not in public

    # But a masked preview is present.
    masked = public["access_token_masked"]
    assert masked not in ("", "—")
    assert token not in masked
    assert "…" in masked
    assert masked.startswith("EAAB")


def test_account_public_dict_masked_dash_when_no_token(app):
    customer = make_customer()
    account = wa.upsert_account(customer.id, phone_number_id="999")
    public = wa.account_public_dict(account)
    assert public["access_token_masked"] == "—"


def test_saving_other_fields_without_token_keeps_token(app):
    customer = make_customer()
    token = "EAABsbCS1iHgBO9xQ_super_secret_meta_token"
    wa.upsert_account(customer.id, phone_number_id="123", access_token=token)

    # Re-save WITHOUT passing access_token (e.g. operator edits display name).
    account = wa.upsert_account(
        customer.id,
        phone_number_id="123",
        business_display_name="Renamed Co",
    )
    assert account.business_display_name == "Renamed Co"
    # The previously stored token must be preserved.
    assert account.access_token_encrypted
    assert decrypt_secret(account.access_token_encrypted) == token

    # Passing empty string must also NOT clear it.
    account2 = wa.upsert_account(customer.id, phone_number_id="123", access_token="")
    assert decrypt_secret(account2.access_token_encrypted) == token


def test_set_connection_status(app):
    customer = make_customer()
    wa.upsert_account(customer.id, phone_number_id="123")
    account = wa.set_connection_status(customer.id, "connected")
    assert account.connection_status == "connected"
    assert account.connected_at is not None

    account = wa.set_connection_status(
        customer.id, "error", error_code="190", error_message="token expired"
    )
    assert account.connection_status == "error"
    assert account.last_error_code == "190"
    assert account.last_error_message == "token expired"


def test_normalized_integration_status_folds_to_three_states():
    """The rich connection states collapse to Connected / Needs action /
    Disconnected for the spec's 3-state badge."""
    assert wa.normalized_integration_status("connected") == "connected"
    for s in ("error", "suspended", "pending"):
        assert wa.normalized_integration_status(s) == "needs_action"
    for s in ("disconnected", "not_configured", "", None, "weird"):
        assert wa.normalized_integration_status(s) == "disconnected"


def test_account_public_dict_exposes_integration_status(app):
    customer = make_customer()
    # No account row yet → disconnected, with no None-check needed by callers.
    assert wa.account_public_dict(None) == {"integration_status": "disconnected"}

    wa.upsert_account(customer.id, phone_number_id="123")
    wa.set_connection_status(customer.id, "connected")
    public = wa.account_public_dict(wa.get_account(customer.id))
    assert public["integration_status"] == "connected"
    # And it never leaks a token.
    assert "access_token" not in public and "access_token_encrypted" not in public


# ---------------------------------------------------------------------------
# Settings: default creation + allow-list updates
# ---------------------------------------------------------------------------
def test_get_settings_creates_default_row(app):
    customer = make_customer()
    assert WhatsAppServiceSettings.query.filter_by(customer_id=customer.id).first() is None
    settings = wa.get_settings(customer.id)
    assert settings.id is not None
    assert settings.customer_id == customer.id
    # Idempotent: a second call returns the same row.
    again = wa.get_settings(customer.id)
    assert again.id == settings.id


def test_update_settings_allow_list(app):
    customer = make_customer()
    settings = wa.update_settings(
        customer.id,
        enabled=True,
        daily_message_limit=42,
        allow_marketing=True,
        # Not in the allow-list -> must be ignored, not set.
        id=999999,
        bogus_field="nope",
    )
    assert settings.enabled is True
    assert settings.daily_message_limit == 42
    assert settings.allow_marketing is True
    # Disallowed keys did not mutate protected columns / add attributes.
    assert settings.id != 999999
    assert settings.customer_id == customer.id
    assert getattr(settings, "bogus_field", None) is None


# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------
def test_template_upsert_get_status(app):
    customer = make_customer()
    t = wa.upsert_template(
        customer.id,
        local_key="otp",
        provider_template_name="otp_ar",
        category="AUTHENTICATION",
        body_preview="رمزك هو {{1}}",
    )
    assert t.id is not None
    assert t.status == "draft"
    assert wa.get_template(customer.id, "otp", "ar").id == t.id

    # Upsert again updates in place (no duplicate row).
    t2 = wa.upsert_template(customer.id, local_key="otp", body_preview="updated")
    assert t2.id == t.id
    assert len(wa.list_templates(customer.id)) == 1

    updated = wa.set_template_status(customer.id, "otp", "ar", "approved")
    assert updated.status == "approved"


# ---------------------------------------------------------------------------
# Usage counters + queue counting
# ---------------------------------------------------------------------------
def test_bump_usage_increments_daily_and_monthly(app):
    customer = make_customer()
    now = datetime(2026, 6, 15, 10, 30, 0)

    usage = wa.bump_usage(customer.id, now, queued=2, sent=1)
    assert usage["daily"]["queued"] == 2
    assert usage["daily"]["sent"] == 1
    assert usage["monthly"]["queued"] == 2
    assert usage["monthly"]["sent"] == 1

    # A second bump on the same day accumulates on both rows.
    usage = wa.bump_usage(customer.id, now, queued=3, delivered=4, failed=1)
    assert usage["daily"]["queued"] == 5
    assert usage["daily"]["delivered"] == 4
    assert usage["daily"]["failed"] == 1
    assert usage["monthly"]["queued"] == 5

    # Exactly one daily + one monthly counter exists for this period.
    assert WhatsAppUsageCounter.query.filter_by(
        customer_id=customer.id, period_type="daily", period_key="2026-06-15"
    ).count() == 1
    assert WhatsAppUsageCounter.query.filter_by(
        customer_id=customer.id, period_type="monthly", period_key="2026-06"
    ).count() == 1


def test_bump_usage_next_day_is_separate_daily_same_monthly(app):
    customer = make_customer()
    day1 = datetime(2026, 6, 15, 10, 0, 0)
    day2 = datetime(2026, 6, 16, 9, 0, 0)
    wa.bump_usage(customer.id, day1, queued=2)
    wa.bump_usage(customer.id, day2, queued=5)

    # day2's daily counter holds only day2's delta.
    assert wa.get_usage(customer.id, day2)["daily"]["queued"] == 5
    assert wa.get_usage(customer.id, day1)["daily"]["queued"] == 2
    # Monthly aggregates both days.
    assert wa.get_usage(customer.id, day2)["monthly"]["queued"] == 7


def test_count_today_month_and_since(app):
    customer = make_customer()
    now = datetime(2026, 6, 15, 12, 0, 0)

    # Two rows today (this month), one earlier this month, one last month.
    _seed_queue(customer.id, now - timedelta(seconds=30), idem="k-30s")
    _seed_queue(customer.id, now - timedelta(hours=2), idem="k-2h")
    _seed_queue(customer.id, datetime(2026, 6, 2, 8, 0, 0), idem="k-earlier-month")
    _seed_queue(customer.id, datetime(2026, 5, 20, 8, 0, 0), idem="k-last-month")
    # A failed + a canceled row must NOT be counted.
    _seed_queue(customer.id, now - timedelta(seconds=10), status="failed", idem="k-failed")
    _seed_queue(customer.id, now - timedelta(seconds=10), status="canceled", idem="k-canceled")

    # Last 60s: only the -30s row (failed/canceled excluded).
    assert wa.count_messages_since(customer.id, now - timedelta(seconds=60)) == 1
    # Today (since midnight 2026-06-15): -30s and -2h rows = 2.
    assert wa.count_today(customer.id, now) == 2
    # This month (since 2026-06-01): the 3 valid June rows = 3.
    assert wa.count_month(customer.id, now) == 3


# ---------------------------------------------------------------------------
# Subscriber preferences
# ---------------------------------------------------------------------------
def test_upsert_subscriber_prefs_opt_in_transitions_and_phone(app):
    customer = make_customer()
    rows = wa.upsert_subscriber_prefs(customer.id, [
        {"subscriber_id": "sub-1", "phone": "0599123456", "whatsapp_opt_in": True},
        {"subscriber_id": "sub-2", "phone": "garbage!!", "whatsapp_opt_in": False},
        {"subscriber_id": "", "whatsapp_opt_in": True},  # skipped (no id)
    ])
    assert len(rows) == 2

    p1 = wa.get_subscriber_pref(customer.id, "sub-1")
    assert p1.whatsapp_opt_in is True
    assert p1.opted_in_at is not None
    # Best-effort normalization of a PS local number.
    assert p1.normalized_phone == "+970599123456"

    p2 = wa.get_subscriber_pref(customer.id, "sub-2")
    assert p2.whatsapp_opt_in is False
    # Unparseable phone keeps raw, empty normalized.
    assert p2.phone == "garbage!!"
    assert p2.normalized_phone is None

    # Transition opt-out: stamps opted_out_at, upserts in place (no new row).
    wa.upsert_subscriber_prefs(customer.id, [
        {"subscriber_id": "sub-1", "whatsapp_opt_in": False},
    ])
    p1b = wa.get_subscriber_pref(customer.id, "sub-1")
    assert p1b.id == p1.id
    assert p1b.whatsapp_opt_in is False
    assert p1b.opted_out_at is not None


def test_upsert_subscriber_prefs_caps_batch_at_500(app):
    customer = make_customer()
    items = [{"subscriber_id": f"s-{i}", "whatsapp_opt_in": True} for i in range(600)]
    rows = wa.upsert_subscriber_prefs(customer.id, items)
    assert len(rows) == 500
