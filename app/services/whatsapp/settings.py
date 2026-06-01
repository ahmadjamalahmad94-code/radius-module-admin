"""Per-customer WhatsApp account / settings / templates / usage service.

Module-level functions, all scoped by ``customer_id``, mirroring the style of
``app/services/license_service.py`` (module functions + direct ``db.session``
+ an ``AuditLog`` helper). Secrets (access token, app secret) are stored
ENCRYPTED via :mod:`app.services.whatsapp.crypto`; the webhook verify token is
stored only as a Werkzeug password hash. Nothing here ever returns a plaintext
or encrypted secret to a caller — only masked previews via
:func:`account_public_dict`.
"""
from __future__ import annotations

from datetime import datetime

from werkzeug.security import generate_password_hash

from ...extensions import db
from ...models import (
    AuditLog,
    WhatsAppMessageQueue,
    WhatsAppServiceSettings,
    WhatsAppSubscriberPreference,
    WhatsAppTemplate,
    WhatsAppTenantAccount,
    WhatsAppUsageCounter,
    utcnow,
)
from .crypto import decrypt_secret, encrypt_secret, mask_secret
from .phone import WhatsAppPhoneError, normalize_phone_for_whatsapp


# Message-queue statuses that should NOT count towards usage/limits.
_UNCOUNTED_QUEUE_STATUSES = ("canceled", "failed")

# Columns the operator may set via update_settings (allow-list).
_SETTINGS_ALLOWED_FIELDS = frozenset({
    "enabled",
    "plan_code",
    "monthly_message_limit",
    "daily_message_limit",
    "per_minute_limit",
    "allow_otp",
    "allow_expiry_notice",
    "allow_quota_notice",
    "allow_maintenance_notice",
    "allow_password_reset",
    "allow_bulk_utility",
    "allow_marketing",
    "require_subscriber_opt_in",
    "quiet_hours_enabled",
    "quiet_hours_start",
    "quiet_hours_end",
    "timezone",
})

# Max subscriber-preference rows accepted in a single batch upsert.
_MAX_PREF_BATCH = 500


def _audit(action: str, entity_type: str, entity_id, summary: str, metadata=None) -> None:
    """Append an AuditLog row (no actor: these are system/service actions)."""
    row = AuditLog(
        actor_admin_id=None,
        action=action,
        entity_type=entity_type,
        entity_id=str(entity_id),
        summary=summary,
    )
    row.meta = metadata or {}
    db.session.add(row)


# ---------------------------------------------------------------------------
# Account (credentials + connection state)
# ---------------------------------------------------------------------------
def get_account(customer_id: int) -> WhatsAppTenantAccount | None:
    return WhatsAppTenantAccount.query.filter_by(customer_id=int(customer_id)).first()


def upsert_account(
    customer_id: int,
    *,
    license_id: int | None = None,
    meta_business_id: str = "",
    whatsapp_business_account_id: str = "",
    phone_number_id: str = "",
    display_phone_number: str = "",
    business_display_name: str = "",
    access_token: str | None = None,
    webhook_verify_token: str | None = None,
    app_secret: str | None = None,
) -> WhatsAppTenantAccount:
    """Create or update the customer's WhatsApp account.

    Secrets are only overwritten when a non-empty new value is passed, so the
    UI can save other fields without clearing a previously stored token.
    Commits and writes a ``whatsapp_credentials_saved`` audit row.
    """
    account = get_account(customer_id)
    if account is None:
        account = WhatsAppTenantAccount(customer_id=int(customer_id))
        db.session.add(account)

    if license_id is not None:
        account.license_id = license_id

    # Non-secret descriptive fields are always set from the provided values.
    account.meta_business_id = meta_business_id or ""
    account.whatsapp_business_account_id = whatsapp_business_account_id or ""
    account.phone_number_id = phone_number_id or ""
    account.display_phone_number = display_phone_number or ""
    account.business_display_name = business_display_name or ""

    # Secrets: only overwrite when a non-empty new value is supplied.
    if access_token:
        account.access_token_encrypted = encrypt_secret(access_token)
    if app_secret:
        account.webhook_secret_encrypted = encrypt_secret(app_secret)
    if webhook_verify_token:
        account.webhook_verify_token_hash = generate_password_hash(webhook_verify_token)

    db.session.commit()
    _audit(
        "whatsapp_credentials_saved",
        "whatsapp_account",
        account.id,
        "WhatsApp credentials saved",
        {
            "customer_id": int(customer_id),
            "phone_number_id": account.phone_number_id or "",
            "waba_id": account.whatsapp_business_account_id or "",
        },
    )
    db.session.commit()
    return account


def set_connection_status(
    customer_id: int,
    status: str,
    *,
    error_code: str = "",
    error_message: str = "",
) -> WhatsAppTenantAccount | None:
    """Set the account connection status (+ optional last error). Commits."""
    account = get_account(customer_id)
    if account is None:
        return None
    now = utcnow()
    account.connection_status = status
    account.last_error_code = error_code or None
    account.last_error_message = error_message or None
    if status == "connected":
        account.connected_at = now
    elif status == "disconnected":
        account.disconnected_at = now
    db.session.commit()
    return account


def account_public_dict(account: WhatsAppTenantAccount | None) -> dict:
    """Public, secret-free view of an account.

    NEVER includes the encrypted or plaintext access token / app secret /
    verify token. Provides ``access_token_masked`` (a short preview) so the UI
    can show that a token exists without revealing it.
    """
    if account is None:
        return {}

    masked = "—"
    try:
        plaintext = decrypt_secret(account.access_token_encrypted or "")
        if plaintext:
            masked = mask_secret(plaintext)
    except Exception:  # noqa: BLE001 — never leak / raise from a display helper
        masked = "—"

    return {
        "status": account.connection_status,
        "connection_status": account.connection_status,
        "provider": account.provider,
        "meta_business_id": account.meta_business_id or "",
        "whatsapp_business_account_id": account.whatsapp_business_account_id or "",
        "waba_id": account.whatsapp_business_account_id or "",
        "phone_number_id": account.phone_number_id or "",
        "display_phone_number": account.display_phone_number or "",
        "business_display_name": account.business_display_name or "",
        "quality_rating": account.quality_rating or "",
        "messaging_limit_tier": account.messaging_limit_tier or "",
        "connected_at": account.connected_at,
        "disconnected_at": account.disconnected_at,
        "last_error": {
            "code": account.last_error_code or "",
            "message": account.last_error_message or "",
        },
        "access_token_masked": masked,
    }


# ---------------------------------------------------------------------------
# Service settings (plan + policy switches)
# ---------------------------------------------------------------------------
def get_settings(customer_id: int) -> WhatsAppServiceSettings:
    """Return the customer's settings row, creating a default one if missing."""
    settings = WhatsAppServiceSettings.query.filter_by(customer_id=int(customer_id)).first()
    if settings is None:
        settings = WhatsAppServiceSettings(customer_id=int(customer_id))
        db.session.add(settings)
        db.session.commit()
    return settings


def update_settings(customer_id: int, **fields) -> WhatsAppServiceSettings:
    """Update settings using an allow-list of columns. Commits + audits."""
    settings = get_settings(customer_id)
    changed: dict[str, object] = {}
    for key, value in fields.items():
        if key in _SETTINGS_ALLOWED_FIELDS:
            setattr(settings, key, value)
            changed[key] = value
    db.session.commit()
    _audit(
        "whatsapp_settings_changed",
        "whatsapp_settings",
        settings.id,
        "WhatsApp settings changed",
        {"customer_id": int(customer_id), "fields": sorted(changed.keys())},
    )
    db.session.commit()
    return settings


# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------
def list_templates(customer_id: int) -> list[WhatsAppTemplate]:
    return (
        WhatsAppTemplate.query.filter_by(customer_id=int(customer_id))
        .order_by(WhatsAppTemplate.local_key.asc(), WhatsAppTemplate.language.asc())
        .all()
    )


def get_template(customer_id: int, local_key: str, language: str = "ar") -> WhatsAppTemplate | None:
    return WhatsAppTemplate.query.filter_by(
        customer_id=int(customer_id),
        local_key=local_key,
        language=language,
    ).first()


def upsert_template(
    customer_id: int,
    *,
    local_key: str,
    provider_template_name: str = "",
    language: str = "ar",
    category: str = "UTILITY",
    body_preview: str = "",
    status: str | None = None,
) -> WhatsAppTemplate:
    """Create or update a template by (customer, local_key, language). Commits."""
    template = get_template(customer_id, local_key, language)
    if template is None:
        template = WhatsAppTemplate(
            customer_id=int(customer_id),
            local_key=local_key,
            language=language,
        )
        db.session.add(template)
    template.provider_template_name = provider_template_name or None
    template.category = category or "UTILITY"
    template.body_preview = body_preview or None
    if status is not None:
        template.status = status
    db.session.commit()
    return template


def set_template_status(
    customer_id: int,
    local_key: str,
    language: str,
    status: str,
) -> WhatsAppTemplate | None:
    """Set a template's status (e.g. draft -> approved). Commits."""
    template = get_template(customer_id, local_key, language)
    if template is None:
        return None
    template.status = status
    db.session.commit()
    return template


# ---------------------------------------------------------------------------
# Usage / limits
# ---------------------------------------------------------------------------
def count_messages_since(customer_id: int, since_dt: datetime) -> int:
    """Count queued messages created at/after ``since_dt`` that still count.

    Excludes canceled/failed rows (they don't consume a sending slot).
    """
    return (
        WhatsAppMessageQueue.query.filter(
            WhatsAppMessageQueue.customer_id == int(customer_id),
            WhatsAppMessageQueue.created_at >= since_dt,
            WhatsAppMessageQueue.status.notin_(_UNCOUNTED_QUEUE_STATUSES),
        ).count()
    )


def count_today(customer_id: int, now: datetime) -> int:
    midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
    return count_messages_since(customer_id, midnight)


def count_month(customer_id: int, now: datetime) -> int:
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    return count_messages_since(customer_id, month_start)


def _get_or_create_counter(customer_id: int, period_type: str, period_key: str) -> WhatsAppUsageCounter:
    counter = WhatsAppUsageCounter.query.filter_by(
        customer_id=int(customer_id),
        period_type=period_type,
        period_key=period_key,
    ).first()
    if counter is None:
        counter = WhatsAppUsageCounter(
            customer_id=int(customer_id),
            period_type=period_type,
            period_key=period_key,
            queued_count=0,
            sent_count=0,
            delivered_count=0,
            failed_count=0,
        )
        db.session.add(counter)
    return counter


def _apply_counter_delta(
    counter: WhatsAppUsageCounter,
    *,
    queued: int,
    sent: int,
    delivered: int,
    failed: int,
) -> None:
    counter.queued_count = int(counter.queued_count or 0) + int(queued)
    counter.sent_count = int(counter.sent_count or 0) + int(sent)
    counter.delivered_count = int(counter.delivered_count or 0) + int(delivered)
    counter.failed_count = int(counter.failed_count or 0) + int(failed)


def bump_usage(
    customer_id: int,
    now: datetime,
    *,
    queued: int = 0,
    sent: int = 0,
    delivered: int = 0,
    failed: int = 0,
) -> dict:
    """Increment both the daily and monthly usage counters for ``now``.

    Upserts the daily (period_key ``YYYY-MM-DD``) and monthly (``YYYY-MM``)
    rows, adding the supplied deltas. Commits. Returns the post-increment usage.
    """
    daily = _get_or_create_counter(customer_id, "daily", now.strftime("%Y-%m-%d"))
    monthly = _get_or_create_counter(customer_id, "monthly", now.strftime("%Y-%m"))
    for counter in (daily, monthly):
        _apply_counter_delta(
            counter,
            queued=queued,
            sent=sent,
            delivered=delivered,
            failed=failed,
        )
    db.session.commit()
    return get_usage(customer_id, now)


def _counter_dict(counter: WhatsAppUsageCounter | None) -> dict:
    if counter is None:
        return {"queued": 0, "sent": 0, "delivered": 0, "failed": 0}
    return {
        "queued": int(counter.queued_count or 0),
        "sent": int(counter.sent_count or 0),
        "delivered": int(counter.delivered_count or 0),
        "failed": int(counter.failed_count or 0),
    }


def get_usage(customer_id: int, now: datetime) -> dict:
    daily = WhatsAppUsageCounter.query.filter_by(
        customer_id=int(customer_id),
        period_type="daily",
        period_key=now.strftime("%Y-%m-%d"),
    ).first()
    monthly = WhatsAppUsageCounter.query.filter_by(
        customer_id=int(customer_id),
        period_type="monthly",
        period_key=now.strftime("%Y-%m"),
    ).first()
    return {"daily": _counter_dict(daily), "monthly": _counter_dict(monthly)}


# ---------------------------------------------------------------------------
# Subscriber preferences
# ---------------------------------------------------------------------------
def get_subscriber_pref(customer_id: int, subscriber_id) -> WhatsAppSubscriberPreference | None:
    return WhatsAppSubscriberPreference.query.filter_by(
        customer_id=int(customer_id),
        subscriber_id=str(subscriber_id),
    ).first()


def _normalize_phone_best_effort(phone: str | None) -> tuple[str, str]:
    """Return (raw, normalized). Normalization is best-effort: an unparseable
    number keeps its raw value and an empty normalized form."""
    raw = str(phone or "").strip()
    if not raw:
        return "", ""
    try:
        return raw, normalize_phone_for_whatsapp(raw)
    except WhatsAppPhoneError:
        return raw, ""


def upsert_subscriber_prefs(customer_id: int, items: list[dict]) -> list[WhatsAppSubscriberPreference]:
    """Batch upsert subscriber preferences (capped at 500 rows).

    Upserts by (customer_id, subscriber_id). Phone is normalized best-effort.
    ``opted_in_at`` / ``opted_out_at`` are stamped on opt-in transitions.
    Commits once at the end. Returns the affected rows.
    """
    customer_id = int(customer_id)
    now = utcnow()
    affected: list[WhatsAppSubscriberPreference] = []

    for item in (items or [])[:_MAX_PREF_BATCH]:
        subscriber_id = str(item.get("subscriber_id") or "").strip()
        if not subscriber_id:
            continue

        pref = get_subscriber_pref(customer_id, subscriber_id)
        is_new = pref is None
        if is_new:
            pref = WhatsAppSubscriberPreference(
                customer_id=customer_id,
                subscriber_id=subscriber_id,
            )
            db.session.add(pref)

        if "phone" in item:
            raw, normalized = _normalize_phone_best_effort(item.get("phone"))
            pref.phone = raw or None
            pref.normalized_phone = normalized or None

        # Per-category prefs + blocked flag: set when explicitly provided.
        for attr in ("allow_otp", "allow_service_notices", "allow_maintenance", "allow_marketing", "blocked"):
            if attr in item:
                setattr(pref, attr, bool(item[attr]))
        if "source" in item:
            pref.source = str(item.get("source") or "") or None

        # Opt-in transition handling.
        if "whatsapp_opt_in" in item:
            new_opt_in = bool(item["whatsapp_opt_in"])
            prev_opt_in = bool(pref.whatsapp_opt_in) if not is_new else False
            pref.whatsapp_opt_in = new_opt_in
            if new_opt_in and (is_new or not prev_opt_in):
                pref.opted_in_at = now
            elif not new_opt_in and (is_new or prev_opt_in):
                pref.opted_out_at = now

        affected.append(pref)

    db.session.commit()
    return affected
