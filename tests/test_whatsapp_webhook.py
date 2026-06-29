"""Tests for the Meta WhatsApp Cloud webhook (app/services/whatsapp/webhook.py
+ the ``GET/POST /api/whatsapp/webhook`` route in app/api/routes.py).

Unlike the signed integration endpoints, Meta reaches this route with NO HMAC
triad, NO CSRF token, and NO login. It is CSRF-exempt because ``/api/`` paths
are skipped by ``_install_csrf``. Meta authenticates instead through:

* GET — the ``hub.verify_token`` handshake (matched against a tenant account's
  stored Werkzeug hash), and
* POST — the optional ``X-Hub-Signature-256`` app-secret signature.

No Meta network is touched: ``parse_webhook`` is pure and ``process_event``
only mutates local queue rows.

Coverage:
* GET challenge: correct verify_token -> 200 body == challenge; wrong -> 403.
* POST status delivered/read/failed -> the matching queue row advances and a
  processed WhatsAppWebhookEvent is stored (failed also stores error code/msg).
* idempotency: the SAME status delivered twice -> one event, second reports
  ``skipped_duplicates == 1`` and does not double-update / crash.
* unmatched phone_number_id -> event stored with
  ``processing_error == "webhook_unmatched_phone_number"``, HTTP 200, no crash.
* malformed/garbage POST body -> HTTP 200, no crash (stored as ``unknown``).
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import json as _json
from datetime import timedelta

import pytest

from app import create_app, seed_defaults
from app.config import TestingConfig
from app.extensions import db
from app.models import (
    Customer,
    WhatsAppMessageQueue,
    WhatsAppWebhookEvent,
    utcnow,
)
from app.services.whatsapp import settings as wa_settings


PHONE_NUMBER_ID = "123456789012345"
VERIFY_TOKEN = "verify-tok-abc123"
APP_SECRET = "app-secret-xyz789"
WAMID = "wamid.HBgMTEST"

# Matches TestingConfig.META_APP_SECRET — the app-level secret Meta uses to sign
# webhooks for accounts that have no per-tenant ``webhook_secret_encrypted``.
META_APP_SECRET = "test-app-secret"


# --------------------------------------------------------------------------- app

@pytest.fixture()
def app():
    app = create_app(TestingConfig)
    with app.app_context():
        db.create_all()
        seed_defaults(app)
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


# --------------------------------------------------------------------------- helpers

def _make_customer(company_name: str = "Webhook Co") -> int:
    customer = Customer(company_name=company_name, contact_name="Owner")
    db.session.add(customer)
    db.session.commit()
    return customer.id


def _provision_account(customer_id: int, *, with_secret: bool = False) -> None:
    """Give the customer a WhatsApp account with a known verify token (+phone
    number id), optionally storing an app secret too (encrypted)."""
    wa_settings.upsert_account(
        customer_id,
        phone_number_id=PHONE_NUMBER_ID,
        display_phone_number="+970599000000",
        business_display_name="Acme ISP",
        webhook_verify_token=VERIFY_TOKEN,
        app_secret=APP_SECRET if with_secret else None,
    )


def _queue_row(customer_id: int, *, provider_message_id: str = WAMID, status: str = "sent") -> int:
    """Pre-create a queued/sent message row whose status the webhook updates."""
    row = WhatsAppMessageQueue(
        customer_id=customer_id,
        source_system="radius_module",
        source_event_type="otp",
        recipient_phone="+970599000000",
        normalized_recipient_phone="+970599000000",
        template_key="otp",
        status=status,
        provider_message_id=provider_message_id,
        idempotency_key=f"c{customer_id}:wh-{provider_message_id}",
        sent_at=utcnow() - timedelta(minutes=1),
    )
    db.session.add(row)
    db.session.commit()
    return row.id


def _status_payload(status: str, *, message_id: str = WAMID, errors=None) -> dict:
    """A realistic Meta status webhook payload with metadata.phone_number_id."""
    status_obj = {
        "id": message_id,
        "status": status,
        "timestamp": "1717200000",
        "recipient_id": "970599000000",
    }
    if errors is not None:
        status_obj["errors"] = errors
    return {
        "object": "whatsapp_business_account",
        "entry": [
            {
                "id": "WABA_ID",
                "changes": [
                    {
                        "field": "messages",
                        "value": {
                            "messaging_product": "whatsapp",
                            "metadata": {
                                "display_phone_number": "970599000000",
                                "phone_number_id": PHONE_NUMBER_ID,
                            },
                            "statuses": [status_obj],
                        },
                    }
                ],
            }
        ],
    }


def _sign(raw: bytes, secret: str) -> str:
    """Meta's ``X-Hub-Signature-256`` over the EXACT raw body bytes."""
    return "sha256=" + _hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).hexdigest()


def _post(client, payload, *, secret: str = META_APP_SECRET, sign: bool = True):
    """POST a webhook with a VALID signature by default (strict policy).

    Serializes ``payload`` ourselves so the signed bytes are exactly the bytes
    Flask receives. Pass ``sign=False`` to omit the header (to assert a 401).
    """
    raw = _json.dumps(payload).encode("utf-8")
    headers = {}
    if sign:
        headers["X-Hub-Signature-256"] = _sign(raw, secret)
    return client.post(
        "/api/whatsapp/webhook",
        data=raw,
        content_type="application/json",
        headers=headers,
    )


# --------------------------------------------------------------------------- GET handshake

def test_get_challenge_correct_token_returns_challenge(client, app):
    customer_id = _make_customer("Verify Co")
    _provision_account(customer_id)

    res = client.get(
        "/api/whatsapp/webhook",
        query_string={
            "hub.mode": "subscribe",
            "hub.verify_token": VERIFY_TOKEN,
            "hub.challenge": "1158201444",
        },
    )
    assert res.status_code == 200
    assert res.get_data(as_text=True) == "1158201444"
    assert res.mimetype == "text/plain"


def test_get_challenge_wrong_token_is_forbidden(client, app):
    customer_id = _make_customer("Verify Co")
    _provision_account(customer_id)

    res = client.get(
        "/api/whatsapp/webhook",
        query_string={
            "hub.mode": "subscribe",
            "hub.verify_token": "WRONG-TOKEN",
            "hub.challenge": "1158201444",
        },
    )
    assert res.status_code == 403


def test_get_challenge_wrong_mode_is_forbidden(client, app):
    customer_id = _make_customer("Verify Co")
    _provision_account(customer_id)

    res = client.get(
        "/api/whatsapp/webhook",
        query_string={
            "hub.mode": "unsubscribe",
            "hub.verify_token": VERIFY_TOKEN,
            "hub.challenge": "x",
        },
    )
    assert res.status_code == 403


# --------------------------------------------------------------------------- POST status

def test_post_status_delivered_updates_row_and_stores_event(client, app):
    customer_id = _make_customer("Delivered Co")
    _provision_account(customer_id)
    row_id = _queue_row(customer_id, status="sent")

    res = _post(client, _status_payload("delivered"))
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is True
    assert body["stored"] == 1
    assert body["processed"] == 1
    assert body["skipped_duplicates"] == 0

    with app.app_context():
        row = db.session.get(WhatsAppMessageQueue, row_id)
        assert row.status == "delivered"
        assert row.delivered_at is not None
        event = WhatsAppWebhookEvent.query.filter_by(provider_message_id=WAMID).one()
        assert event.event_type == "message_status"
        assert event.processed is True
        assert event.processed_at is not None
        assert event.customer_id == customer_id
        assert event.phone_number_id == PHONE_NUMBER_ID
        assert event.processing_error is None


def test_post_status_read_updates_row(client, app):
    customer_id = _make_customer("Read Co")
    _provision_account(customer_id)
    row_id = _queue_row(customer_id, status="delivered")

    res = _post(client, _status_payload("read"))
    assert res.status_code == 200
    assert res.get_json()["processed"] == 1

    with app.app_context():
        row = db.session.get(WhatsAppMessageQueue, row_id)
        assert row.status == "read"
        assert row.read_at is not None


def test_post_status_failed_stores_error(client, app):
    customer_id = _make_customer("Failed Co")
    _provision_account(customer_id)
    row_id = _queue_row(customer_id, status="sent")

    errors = [
        {
            "code": 131026,
            "title": "Message undeliverable",
            "error_data": {"details": "Recipient is not on WhatsApp."},
        }
    ]
    res = _post(client, _status_payload("failed", errors=errors))
    assert res.status_code == 200
    assert res.get_json()["processed"] == 1

    with app.app_context():
        row = db.session.get(WhatsAppMessageQueue, row_id)
        assert row.status == "failed"
        assert row.failed_at is not None
        assert row.error_code == "131026"
        assert row.error_message == "Message undeliverable"


# --------------------------------------------------------------------------- idempotency

def test_post_same_status_twice_is_idempotent(client, app):
    customer_id = _make_customer("Idemp Co")
    _provision_account(customer_id)
    row_id = _queue_row(customer_id, status="sent")

    payload = _status_payload("delivered")

    first = _post(client, payload)
    assert first.status_code == 200
    assert first.get_json()["stored"] == 1
    assert first.get_json()["skipped_duplicates"] == 0

    with app.app_context():
        row = db.session.get(WhatsAppMessageQueue, row_id)
        first_delivered_at = row.delivered_at
        assert first_delivered_at is not None

    # Same delivery again -> no new event, reported as a skipped duplicate.
    second = _post(client, payload)
    assert second.status_code == 200
    body2 = second.get_json()
    assert body2["stored"] == 0
    assert body2["processed"] == 0
    assert body2["skipped_duplicates"] == 1

    with app.app_context():
        assert WhatsAppWebhookEvent.query.filter_by(provider_message_id=WAMID).count() == 1
        # The row was not re-stamped on the duplicate.
        row = db.session.get(WhatsAppMessageQueue, row_id)
        assert row.delivered_at == first_delivered_at


def test_post_distinct_statuses_for_same_message_each_stored(client, app):
    """sent -> delivered -> read for one wamid are THREE distinct events."""
    customer_id = _make_customer("Lifecycle Co")
    _provision_account(customer_id)
    row_id = _queue_row(customer_id, status="sent")

    for status in ("sent", "delivered", "read"):
        res = _post(client, _status_payload(status))
        assert res.status_code == 200
        assert res.get_json()["stored"] == 1

    with app.app_context():
        assert WhatsAppWebhookEvent.query.filter_by(provider_message_id=WAMID).count() == 3
        row = db.session.get(WhatsAppMessageQueue, row_id)
        assert row.status == "read"
        assert row.read_at is not None
        assert row.delivered_at is not None


# --------------------------------------------------------------------------- unmatched + garbage

def test_post_unmatched_phone_number_stores_error_200(client, app):
    """A payload whose phone_number_id matches no account is stored unprocessed."""
    customer_id = _make_customer("Unmatched Co")
    _provision_account(customer_id)  # account uses PHONE_NUMBER_ID

    payload = _status_payload("delivered")
    # Point the payload at a DIFFERENT phone_number_id.
    payload["entry"][0]["changes"][0]["value"]["metadata"]["phone_number_id"] = "999999999999999"

    # No per-account secret matches this unknown phone id, so Meta signs with the
    # app-level secret — a valid signature still passes; the event is stored but
    # unmatched (no account to apply against).
    res = _post(client, payload)
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is True
    assert body["stored"] == 1
    assert body["processed"] == 0

    with app.app_context():
        event = WhatsAppWebhookEvent.query.filter_by(provider_message_id=WAMID).one()
        assert event.processing_error == "webhook_unmatched_phone_number"
        assert event.processed is False
        assert event.customer_id is None


def test_post_garbage_body_returns_200_no_crash(client, app):
    customer_id = _make_customer("Garbage Co")
    _provision_account(customer_id)

    raw = b"this is not json {{{"
    res = client.post(
        "/api/whatsapp/webhook",
        data=raw,
        content_type="application/json",
        headers={"X-Hub-Signature-256": _sign(raw, META_APP_SECRET)},
    )
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is True
    # An empty/garbage payload yields one stored "unknown" event (unmatched).
    assert body["stored"] == 1
    assert body["processed"] == 0

    with app.app_context():
        event = WhatsAppWebhookEvent.query.first()
        assert event is not None
        assert event.event_type == "unknown"


def test_post_empty_json_object_returns_200(client, app):
    _make_customer("Empty Co")
    res = _post(client, {})
    assert res.status_code == 200
    assert res.get_json()["ok"] is True


# --------------------------------------------------------------------------- signature

def test_post_with_valid_signature_processes(client, app):
    """Account WITH a stored per-tenant app secret + a correct signature -> processed."""
    customer_id = _make_customer("Signed Co")
    _provision_account(customer_id, with_secret=True)
    row_id = _queue_row(customer_id, status="sent")

    # The per-account secret (APP_SECRET) takes precedence over META_APP_SECRET.
    res = _post(client, _status_payload("delivered"), secret=APP_SECRET)
    assert res.status_code == 200
    assert res.get_json()["processed"] == 1

    with app.app_context():
        row = db.session.get(WhatsAppMessageQueue, row_id)
        assert row.status == "delivered"


def test_post_with_tampered_signature_is_rejected_401(client, app):
    """Secret configured + a NON-MATCHING signature -> 401, nothing stored/applied.

    This is the core hardening: a tampered signature must NOT pass with a 200.
    """
    customer_id = _make_customer("BadSig Co")
    _provision_account(customer_id, with_secret=True)
    row_id = _queue_row(customer_id, status="sent")

    res = client.post(
        "/api/whatsapp/webhook",
        json=_status_payload("delivered"),
        headers={"X-Hub-Signature-256": "sha256=deadbeef"},
    )
    assert res.status_code == 401

    with app.app_context():
        # Rejected BEFORE storage: no event row, queue row untouched.
        assert WhatsAppWebhookEvent.query.count() == 0
        row = db.session.get(WhatsAppMessageQueue, row_id)
        assert row.status == "sent"
        assert row.delivered_at is None


def test_post_with_signature_over_wrong_body_is_rejected_401(client, app):
    """A signature valid for a DIFFERENT body (replay/tamper) -> 401."""
    customer_id = _make_customer("WrongBody Co")
    _provision_account(customer_id, with_secret=True)

    payload = _status_payload("delivered")
    raw = _json.dumps(payload).encode("utf-8")
    # Sign some OTHER bytes, then send `raw` — the HMAC won't match.
    bogus_sig = _sign(b'{"entry":[]}', APP_SECRET)

    res = client.post(
        "/api/whatsapp/webhook",
        data=raw,
        content_type="application/json",
        headers={"X-Hub-Signature-256": bogus_sig},
    )
    assert res.status_code == 401
    with app.app_context():
        assert WhatsAppWebhookEvent.query.count() == 0


def test_post_missing_signature_with_secret_configured_is_rejected_401(client, app):
    """Secret configured + NO signature header at all -> 401, nothing stored."""
    customer_id = _make_customer("NoSig Co")
    _provision_account(customer_id, with_secret=True)
    row_id = _queue_row(customer_id, status="sent")

    res = _post(client, _status_payload("delivered"), sign=False)
    assert res.status_code == 401

    with app.app_context():
        assert WhatsAppWebhookEvent.query.count() == 0
        row = db.session.get(WhatsAppMessageQueue, row_id)
        assert row.status == "sent"


def test_post_no_secret_tenant_stored_unverified_not_processed_200(client, app, monkeypatch):
    """No app secret configured anywhere (Phase-1 onboarding) -> the event is
    stored but flagged unverified and NOT applied, and the request still 200s
    (does not 500). A warning is logged."""
    # Clear the app-level secret so NEITHER per-account nor app-level resolves.
    monkeypatch.setitem(app.config, "META_APP_SECRET", "")

    customer_id = _make_customer("Onboarding Co")
    _provision_account(customer_id, with_secret=False)  # no per-account secret
    row_id = _queue_row(customer_id, status="sent")

    # Unsigned delivery: with no secret we cannot verify, so we accept-but-flag.
    res = _post(client, _status_payload("delivered"), sign=False)
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is True
    assert body["stored"] == 1
    assert body["processed"] == 0

    with app.app_context():
        event = WhatsAppWebhookEvent.query.filter_by(provider_message_id=WAMID).one()
        assert event.processing_error == "unverified_no_app_secret"
        assert event.processed is False
        # The queue row was NOT advanced — unverified events never apply state.
        row = db.session.get(WhatsAppMessageQueue, row_id)
        assert row.status == "sent"
        assert row.delivered_at is None
