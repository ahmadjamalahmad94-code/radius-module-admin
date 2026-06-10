r"""Outbound WhatsApp message queue service.

This module owns the lifecycle of :class:`WhatsAppMessageQueue` rows: enqueueing
(idempotent), the status state-machine transitions, and the *atomic claim* that
guarantees only one drainer can take a queued row for sending. It deliberately
contains no provider/network code — see :mod:`app.services.whatsapp.worker`,
which calls into here. Every mutating helper commits.

Status machine::

    queued -> sending -> sent -> delivered -> read
                      \-> failed (terminal unless re-queued via schedule_retry)
    queued/failed -> canceled

Idempotency: ``idempotency_key`` is ``UNIQUE`` on the table. :func:`enqueue`
never creates a duplicate — a repeated key returns the existing row with
``created=False``. The DB constraint is the source of truth, so a concurrent
double-enqueue is caught and resolved to the existing row.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from flask import current_app
from sqlalchemy.exc import IntegrityError

from ...extensions import db
from ...models import WhatsAppMessageQueue, utcnow
from . import settings


# Statuses from which an operator/system may still cancel a message.
_CANCELABLE_STATUSES = ("queued", "failed")


def _max_attempts_default() -> int:
    """Default max attempts — UI-editable via /admin/settings/platform.

    Resolver chain (Setting row -> app.config -> built-in default 3) lives
    in :mod:`app.services.platform_settings`. Falls back gracefully if the
    settings module can't be reached (test bootstrap, etc.).
    """
    try:
        from ..platform_settings import get_int
        return get_int("WHATSAPP_MAX_ATTEMPTS", 3)
    except Exception:  # noqa: BLE001
        try:
            return int(current_app.config.get("WHATSAPP_MAX_ATTEMPTS") or 3)
        except (TypeError, ValueError):
            return 3


# ---------------------------------------------------------------------------
# Lookups
# ---------------------------------------------------------------------------
def get_by_idempotency_key(idempotency_key: str) -> WhatsAppMessageQueue | None:
    return WhatsAppMessageQueue.query.filter_by(
        idempotency_key=str(idempotency_key)
    ).first()


def get_message(message_id: int) -> WhatsAppMessageQueue | None:
    return db.session.get(WhatsAppMessageQueue, int(message_id))


# ---------------------------------------------------------------------------
# Enqueue (idempotent)
# ---------------------------------------------------------------------------
def enqueue(
    customer_id: int,
    *,
    source_system: str,
    source_event_type: str,
    recipient_phone: str,
    normalized_recipient_phone: str,
    idempotency_key: str,
    template_key: str | None = None,
    template_name: str | None = None,
    language: str = "ar",
    variables=None,
    raw_body: str | None = None,
    priority: int = 5,
    subscriber_id=None,
    license_id: int | None = None,
) -> tuple[WhatsAppMessageQueue, bool]:
    """Idempotently enqueue an outbound WhatsApp message.

    Returns ``(row, created)``. If a row with ``idempotency_key`` already exists
    it is returned with ``created=False`` and NOTHING is created or mutated. A
    freshly created row is ``status="queued"``, ``attempts=0``,
    ``max_attempts`` from ``WHATSAPP_MAX_ATTEMPTS``, with ``variables`` stored
    via the JSON property; the daily/monthly ``queued`` usage counter is bumped.
    """
    customer_id = int(customer_id)
    idempotency_key = str(idempotency_key)

    existing = get_by_idempotency_key(idempotency_key)
    if existing is not None:
        return existing, False

    row = WhatsAppMessageQueue(
        customer_id=customer_id,
        license_id=license_id,
        source_system=source_system,
        source_event_type=source_event_type,
        subscriber_id=str(subscriber_id) if subscriber_id is not None else None,
        recipient_phone=recipient_phone,
        normalized_recipient_phone=normalized_recipient_phone,
        template_key=template_key or None,
        template_name=template_name or None,
        language=language or "ar",
        raw_body=raw_body or None,
        priority=int(priority) if priority is not None else 5,
        status="queued",
        idempotency_key=idempotency_key,
        attempts=0,
        max_attempts=_max_attempts_default(),
    )
    # Store variables through the JSON property (serializes to variables_json).
    row.variables = variables or {}
    db.session.add(row)

    try:
        db.session.commit()
    except IntegrityError:
        # A concurrent enqueue won the UNIQUE(idempotency_key) race. Resolve to
        # the row that landed first — never surface a duplicate or an error.
        db.session.rollback()
        winner = get_by_idempotency_key(idempotency_key)
        if winner is not None:
            return winner, False
        raise

    # Count this as a queued message for usage/limits.
    settings.bump_usage(customer_id, utcnow(), queued=1)
    return row, True


# ---------------------------------------------------------------------------
# Status-machine transitions (each commits)
# ---------------------------------------------------------------------------
def mark_sent(row: WhatsAppMessageQueue, provider_message_id: str | None) -> WhatsAppMessageQueue:
    row.status = "sent"
    row.provider_message_id = provider_message_id or None
    row.sent_at = utcnow()
    row.error_code = None
    row.error_message = None
    row.next_attempt_at = None
    db.session.commit()
    return row


def mark_delivered(row: WhatsAppMessageQueue) -> WhatsAppMessageQueue:
    row.status = "delivered"
    row.delivered_at = utcnow()
    db.session.commit()
    return row


def mark_read(row: WhatsAppMessageQueue) -> WhatsAppMessageQueue:
    row.status = "read"
    row.read_at = utcnow()
    db.session.commit()
    return row


def mark_failed(
    row: WhatsAppMessageQueue,
    code: str | None,
    message: str | None,
) -> WhatsAppMessageQueue:
    row.status = "failed"
    row.error_code = code or None
    row.error_message = message or None
    row.failed_at = utcnow()
    row.next_attempt_at = None
    db.session.commit()
    return row


def cancel_message(row: WhatsAppMessageQueue) -> bool:
    """Cancel a message. Allowed only from ``queued`` or ``failed``.

    Returns ``True`` if it was canceled, ``False`` if its current status does
    not permit cancellation (e.g. already sent/delivered/sending).
    """
    if row.status not in _CANCELABLE_STATUSES:
        return False
    row.status = "canceled"
    row.next_attempt_at = None
    db.session.commit()
    return True


def schedule_retry(
    row: WhatsAppMessageQueue,
    delay_seconds: int,
    now: datetime | None = None,
) -> WhatsAppMessageQueue:
    """Re-queue a row for a later retry.

    Sets status back to ``queued`` and ``next_attempt_at = now + delay`` so the
    drainer skips it until the backoff window elapses.
    """
    now = now or utcnow()
    row.status = "queued"
    row.next_attempt_at = now + timedelta(seconds=int(delay_seconds))
    db.session.commit()
    return row


# ---------------------------------------------------------------------------
# Atomic claim (double-send guard)
# ---------------------------------------------------------------------------
def _claim(row: WhatsAppMessageQueue, now: datetime) -> bool:
    """Atomically move a row from ``queued`` to ``sending``.

    Uses a single conditional UPDATE filtered on ``status="queued"`` so that
    exactly one drainer can win the row even if several run concurrently. The
    ``rowcount`` of the UPDATE tells us whether *we* claimed it: 1 means we own
    it, 0 means another worker already took it (or it is no longer queued).
    Returns ``True`` iff this caller claimed the row.
    """
    updated = (
        db.session.query(WhatsAppMessageQueue)
        .filter_by(id=row.id, status="queued")
        .update({"status": "sending", "updated_at": now}, synchronize_session=False)
    )
    db.session.commit()
    if updated == 1:
        # Reflect the claimed state on the in-memory instance the caller holds.
        db.session.refresh(row)
        return True
    return False
