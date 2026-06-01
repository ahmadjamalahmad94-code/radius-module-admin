"""Tests for the WhatsApp message queue + drain worker.

The provider is ALWAYS mocked here (``MetaCloudWhatsAppProvider.send_*`` are
monkeypatched), so no test ever touches Meta / the network. We exercise:

* enqueue idempotency (UNIQUE idempotency_key — never a duplicate),
* the drain happy path (queued -> sent + usage),
* retryable failure backoff + the "skip until next_attempt_at" behaviour,
* max-attempts exhaustion (retryable but out of tries -> failed),
* non-retryable failure (immediate failed + usage),
* the double-send guard (a claimed/sending row is never re-sent; ``_claim``
  returns False for an already-claimed row).
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from app.extensions import db
from app.models import Customer, WhatsAppMessageQueue, utcnow
from app.services.whatsapp import queue, settings, worker
from app.services.whatsapp.providers import (
    MetaCloudWhatsAppProvider,
    WhatsAppProviderError,
)


# Normalized phone reused across most tests.
PHONE = "970599000000"


def _provision_connected_customer(app):
    """Create a customer with a connected account, enabled settings, and an
    approved template ``otp`` -> provider name ``otp_ar``. Returns customer id."""
    with app.app_context():
        customer = Customer(company_name="Acme ISP")
        db.session.add(customer)
        db.session.commit()
        cid = customer.id

        # Account with a (dummy) token, then mark it connected.
        settings.upsert_account(
            cid,
            phone_number_id="123456789012345",
            access_token="EAABdummyTOKEN",
        )
        settings.set_connection_status(cid, "connected")

        # Enable the service and approve a template.
        settings.update_settings(cid, enabled=True)
        settings.upsert_template(
            cid,
            local_key="otp",
            provider_template_name="otp_ar",
            language="ar",
            status="approved",
        )
    return cid


def _enqueue_template(app, cid, *, idempotency_key, recipient=PHONE, priority=5):
    with app.app_context():
        row, created = queue.enqueue(
            cid,
            source_system="tests",
            source_event_type="otp",
            recipient_phone=recipient,
            normalized_recipient_phone=recipient,
            idempotency_key=idempotency_key,
            template_key="otp",
            language="ar",
            variables=["123456"],
            priority=priority,
        )
        # Detach-safe: return primitives the caller can re-query by.
        return row.id, created


# --------------------------------------------------------------------------- idempotency


def test_enqueue_is_idempotent(app):
    cid = _provision_connected_customer(app)

    first_id, first_created = _enqueue_template(app, cid, idempotency_key="evt-1")
    second_id, second_created = _enqueue_template(app, cid, idempotency_key="evt-1")

    assert first_created is True
    assert second_created is False
    # Same row, never a duplicate.
    assert first_id == second_id
    with app.app_context():
        assert WhatsAppMessageQueue.query.count() == 1


# --------------------------------------------------------------------------- happy path


def test_drain_happy_path_sends_and_counts(app, monkeypatch):
    cid = _provision_connected_customer(app)
    row_id, _ = _enqueue_template(app, cid, idempotency_key="evt-send")

    calls = {}

    def fake_send_template(self, account, *, recipient, template_name, language, variables):
        calls["recipient"] = recipient
        calls["template_name"] = template_name
        calls["language"] = language
        calls["variables"] = variables
        return {"provider_message_id": "wamid.OK"}

    monkeypatch.setattr(MetaCloudWhatsAppProvider, "send_template_message", fake_send_template)

    with app.app_context():
        summary = worker.drain_once()
        row = db.session.get(WhatsAppMessageQueue, row_id)

        assert summary["claimed"] == 1
        assert summary["sent"] == 1
        assert row.status == "sent"
        assert row.provider_message_id == "wamid.OK"
        assert row.sent_at is not None

        # The resolved provider template name (otp -> otp_ar) was used.
        assert calls["template_name"] == "otp_ar"
        assert calls["recipient"] == PHONE

        # Usage 'sent' counter for today was incremented.
        usage = settings.get_usage(cid, utcnow())
        assert usage["daily"]["sent"] == 1


# --------------------------------------------------------------------------- retryable


def test_retryable_failure_backs_off_then_skips(app, monkeypatch):
    cid = _provision_connected_customer(app)
    row_id, _ = _enqueue_template(app, cid, idempotency_key="evt-retry")

    send_calls = {"n": 0}

    def fake_send_template(self, account, **kwargs):
        send_calls["n"] += 1
        raise WhatsAppProviderError(
            "rate_limited", "slow down", retryable=True, http_status=429
        )

    monkeypatch.setattr(MetaCloudWhatsAppProvider, "send_template_message", fake_send_template)

    now = utcnow()
    with app.app_context():
        summary = worker.drain_once(now=now)
        row = db.session.get(WhatsAppMessageQueue, row_id)

        assert summary["retried"] == 1
        assert summary["sent"] == 0
        assert row.status == "queued"
        assert row.attempts == 1
        assert row.error_code == "rate_limited"
        # Backoff for attempt 1 == 60s.
        assert row.next_attempt_at is not None
        delta = (row.next_attempt_at - now).total_seconds()
        assert 59 <= delta <= 61

    # A second drain at the SAME 'now' must skip it (next_attempt_at in future):
    # it is not even selected, so the provider is not called again.
    with app.app_context():
        summary2 = worker.drain_once(now=now)
        row = db.session.get(WhatsAppMessageQueue, row_id)
        assert summary2["claimed"] == 0
        assert summary2["sent"] == 0
        assert row.status == "queued"
        assert row.attempts == 1

    assert send_calls["n"] == 1  # provider invoked exactly once total

    # Once the backoff window elapses, it becomes due again and is retried.
    later = now + timedelta(seconds=61)
    with app.app_context():
        summary3 = worker.drain_once(now=later)
        assert summary3["claimed"] == 1
        assert summary3["retried"] == 1
    assert send_calls["n"] == 2


# --------------------------------------------------------------------------- max attempts


def test_retryable_failure_at_max_attempts_fails(app, monkeypatch):
    cid = _provision_connected_customer(app)
    row_id, _ = _enqueue_template(app, cid, idempotency_key="evt-max")

    # Simulate a row that has already burned 2 of its 3 attempts.
    with app.app_context():
        row = db.session.get(WhatsAppMessageQueue, row_id)
        row.attempts = 2
        row.max_attempts = 3
        db.session.commit()

    def fake_send_template(self, account, **kwargs):
        raise WhatsAppProviderError("rate_limited", "slow down", retryable=True)

    monkeypatch.setattr(MetaCloudWhatsAppProvider, "send_template_message", fake_send_template)

    with app.app_context():
        summary = worker.drain_once()
        row = db.session.get(WhatsAppMessageQueue, row_id)
        # attempts -> 3, which is == max_attempts, so NO further retry.
        assert row.attempts == 3
        assert row.status == "failed"
        assert summary["failed"] == 1
        assert summary["retried"] == 0


# --------------------------------------------------------------------------- non-retryable


def test_non_retryable_failure_fails_immediately(app, monkeypatch):
    cid = _provision_connected_customer(app)
    row_id, _ = _enqueue_template(app, cid, idempotency_key="evt-nonretry")

    def fake_send_template(self, account, **kwargs):
        raise WhatsAppProviderError(
            "meta_request_invalid", "bad template", retryable=False, http_status=400
        )

    monkeypatch.setattr(MetaCloudWhatsAppProvider, "send_template_message", fake_send_template)

    with app.app_context():
        summary = worker.drain_once()
        row = db.session.get(WhatsAppMessageQueue, row_id)

        assert row.status == "failed"
        assert row.error_code == "meta_request_invalid"
        assert row.attempts == 1
        assert summary["failed"] == 1

        usage = settings.get_usage(cid, utcnow())
        assert usage["daily"]["failed"] == 1


# --------------------------------------------------------------------------- double-send guard


def test_drain_does_not_resend_already_sending_row(app, monkeypatch):
    """A row already in 'sending' (claimed by another drainer) must not be
    handed to the provider again."""
    cid = _provision_connected_customer(app)
    sending_phone = "970599111111"
    row_id, _ = _enqueue_template(
        app, cid, idempotency_key="evt-sending", recipient=sending_phone
    )

    sent_recipients = []

    def fake_send_template(self, account, *, recipient, **kwargs):
        sent_recipients.append(recipient)
        return {"provider_message_id": "wamid.SHOULD_NOT_HAPPEN"}

    monkeypatch.setattr(MetaCloudWhatsAppProvider, "send_template_message", fake_send_template)

    # Mark the row as already 'sending' (i.e. claimed elsewhere).
    with app.app_context():
        row = db.session.get(WhatsAppMessageQueue, row_id)
        row.status = "sending"
        db.session.commit()

        summary = worker.drain_once()
        row = db.session.get(WhatsAppMessageQueue, row_id)

        # It was never selected (status != queued) -> provider not called for it,
        # and it stays in 'sending'.
        assert row.status == "sending"

    assert sending_phone not in sent_recipients
    assert sent_recipients == []


def test_claim_returns_false_for_already_sending_row(app):
    """Direct _claim test: claiming a row that is already 'sending' yields False
    (its rowcount is 0 because the status filter no longer matches)."""
    cid = _provision_connected_customer(app)
    row_id, _ = _enqueue_template(app, cid, idempotency_key="evt-claim")

    now = utcnow()
    with app.app_context():
        row = db.session.get(WhatsAppMessageQueue, row_id)

        # First claim on a queued row succeeds.
        assert queue._claim(row, now) is True
        assert row.status == "sending"

        # A second claim on the same (now 'sending') row must fail.
        assert queue._claim(row, now) is False
