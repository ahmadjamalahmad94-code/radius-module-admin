"""WhatsApp queue drain worker.

This module turns ``queued`` :class:`WhatsAppMessageQueue` rows into actual
provider sends. It has NO resident loop: the panel runs a single gunicorn
worker, so draining is invoked on demand by the ``whatsapp-drain`` Flask CLI
command (wired to a systemd timer in production).

Responsibilities:

* :func:`drain_once` — claim a batch of due rows and send each, tallying a
  summary. One bad row never aborts the batch.
* :func:`_send_one` — send a single (already-claimed) row through the provider
  and apply the resulting status transition, including retry backoff.
* The retry policy: a *retryable* provider error re-queues the row with an
  increasing delay (1/5/15 min) until ``attempts`` reaches ``max_attempts``;
  after that, or on a non-retryable error, the row fails permanently.

Network isolation: the only thing that talks to Meta is the provider returned
by :func:`get_provider`. Tests monkeypatch the provider's ``send_*`` methods so
no request ever leaves the process.
"""
from __future__ import annotations

from datetime import datetime

from flask import current_app

from ...extensions import db
from ...models import WhatsAppMessageQueue, utcnow
from . import queue, settings
from .providers import MetaCloudWhatsAppProvider, WhatsAppProviderError


# Retry backoff (seconds) keyed by the attempt number that just failed.
# attempt 1 -> wait 1 min, attempt 2 -> 5 min, attempt 3 -> 15 min.
BACKOFF: dict[int, int] = {1: 60, 2: 300, 3: 900}

# Fallback delay when the attempt number is beyond the explicit BACKOFF map.
_DEFAULT_BACKOFF_SECONDS = 900


def get_provider(account) -> MetaCloudWhatsAppProvider:
    """Return the provider used to send messages for ``account``.

    A tiny indirection on purpose: tests monkeypatch
    ``MetaCloudWhatsAppProvider.send_template_message`` /
    ``send_text_message`` and this returns a fresh instance of that class, so
    the patched methods are exercised and no network call is made.
    """
    return MetaCloudWhatsAppProvider()


def _batch_size_default() -> int:
    """Batch size — UI-editable via /admin/settings/platform."""
    try:
        from ..platform_settings import get_int
        return get_int("WHATSAPP_DRAIN_BATCH_SIZE", 50)
    except Exception:  # noqa: BLE001
        try:
            return int(current_app.config.get("WHATSAPP_DRAIN_BATCH_SIZE") or 50)
        except (TypeError, ValueError):
            return 50


def _resolve_template_name(account_customer_id: int, row: WhatsAppMessageQueue) -> str | None:
    """Resolve the provider-side template name for a row.

    Prefers an explicit ``row.template_name``. Otherwise looks up the customer's
    template by ``row.template_key`` + ``row.language`` and returns its
    ``provider_template_name`` (which itself may be ``None`` if not yet mapped).
    """
    if row.template_name:
        return row.template_name
    if not row.template_key:
        return None
    template = settings.get_template(account_customer_id, row.template_key, row.language or "ar")
    if template is None:
        return None
    return template.provider_template_name


def _send_one(row: WhatsAppMessageQueue, now: datetime) -> str:
    """Send a single claimed row and apply its resulting status transition.

    Returns one of ``"sent"``, ``"retried"``, ``"failed"``. Assumes ``row`` is
    already claimed (status ``sending``). All provider errors are caught here;
    unexpected exceptions are handled by the caller (:func:`drain_once`).
    """
    account = settings.get_account(row.customer_id)
    if account is None or account.connection_status != "connected":
        queue.mark_failed(row, "whatsapp_not_connected", "لم يتم ربط رقم واتساب.")
        return "failed"

    provider = get_provider(account)

    try:
        if row.template_key or row.template_name:
            template_name = _resolve_template_name(row.customer_id, row)
            result = provider.send_template_message(
                account,
                recipient=row.normalized_recipient_phone,
                template_name=template_name,
                language=row.language or "ar",
                variables=row.variables,
            )
        elif row.raw_body:
            result = provider.send_text_message(
                account,
                recipient=row.normalized_recipient_phone,
                body=row.raw_body,
            )
        else:
            # Nothing to send (no template, no body) — permanent misconfig.
            queue.mark_failed(row, "empty_message", "لا يوجد محتوى للإرسال.")
            return "failed"
    except WhatsAppProviderError as exc:
        row.attempts = int(row.attempts or 0) + 1
        row.error_code = exc.code
        row.error_message = exc.message
        if exc.retryable and row.attempts < int(row.max_attempts or 0):
            delay = BACKOFF.get(row.attempts, _DEFAULT_BACKOFF_SECONDS)
            queue.schedule_retry(row, delay, now)
            return "retried"
        # Non-retryable, or out of attempts: fail permanently.
        queue.mark_failed(row, exc.code, exc.message)
        settings.bump_usage(row.customer_id, now, failed=1)
        return "failed"

    queue.mark_sent(row, (result or {}).get("provider_message_id"))
    settings.bump_usage(row.customer_id, now, sent=1)
    return "sent"


def drain_once(batch_size: int | None = None, now: datetime | None = None) -> dict:
    """Claim and send one batch of due messages.

    Selects ``queued`` rows whose ``next_attempt_at`` is null or already due,
    ordered by ``priority`` then ``id`` (FIFO within a priority), capped at
    ``batch_size`` (config default). Each row is atomically claimed before
    sending so two concurrent drainers can never double-send. A row that fails
    to claim (already taken) is counted as ``skipped``. Any unexpected error
    while sending a row is contained: the row is failed with ``internal_error``
    so it cannot loop forever, and the batch continues.

    Returns a summary ``{"claimed", "sent", "retried", "failed", "skipped"}``.
    """
    now = now or utcnow()
    batch_size = batch_size if batch_size is not None else _batch_size_default()

    summary = {"claimed": 0, "sent": 0, "retried": 0, "failed": 0, "skipped": 0}

    due = (
        WhatsAppMessageQueue.query.filter(
            WhatsAppMessageQueue.status == "queued",
            db.or_(
                WhatsAppMessageQueue.next_attempt_at.is_(None),
                WhatsAppMessageQueue.next_attempt_at <= now,
            ),
        )
        .order_by(WhatsAppMessageQueue.priority.asc(), WhatsAppMessageQueue.id.asc())
        .limit(int(batch_size))
        .all()
    )

    for row in due:
        if not queue._claim(row, now):
            # Another drainer grabbed it (or it is no longer queued).
            summary["skipped"] += 1
            continue
        summary["claimed"] += 1

        try:
            result = _send_one(row, now)
        except Exception:  # noqa: BLE001 — one bad row must not abort the batch.
            # Unexpected (non-provider) failure. Fail it permanently with a
            # generic code so it does not get re-claimed forever, then move on.
            db.session.rollback()
            try:
                queue.mark_failed(row, "internal_error", "خطأ داخلي")
            except Exception:  # noqa: BLE001 — never let cleanup abort the loop.
                db.session.rollback()
            summary["failed"] += 1
            continue

        if result in summary:
            summary[result] += 1

    return summary
