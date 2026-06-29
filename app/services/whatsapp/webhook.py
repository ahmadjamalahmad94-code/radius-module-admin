"""Meta WhatsApp Cloud webhook ingestion + processing.

Meta talks to us in two ways and neither uses our HMAC integration triad
(that triad is for the radius_module runtime, not Meta):

* GET verification handshake — Meta presents ``hub.mode=subscribe`` +
  ``hub.verify_token`` + ``hub.challenge``. We echo the challenge back as
  plain text iff the presented token matches SOME tenant account's stored
  Werkzeug hash (``webhook_verify_token_hash``).
* POST event delivery — status callbacks (sent/delivered/read/failed) and
  inbound messages. Meta authenticates the POST with an ``X-Hub-Signature-256``
  header: ``"sha256=" + HMAC_SHA256(app_secret, raw_body)``.

Design rules the route + tests rely on:

* :func:`ingest` is defensive end-to-end. ``parse_webhook`` never raises, and
  every downstream step is guarded so a malformed/garbage payload still results
  in a stored ``unknown`` event and a clean summary — never a 5xx.
* Events are idempotent: a stable ``event_id`` (status id + status, or message
  id, else a content hash) is used to skip a duplicate delivery. Meta retries
  aggressively, so a re-POST of the same status must not double-apply the queue
  update.
* App-secret signature policy (:func:`verify_signature`):
    - STRICT once a secret exists. When an app secret resolves for the targeted
      account — the per-tenant ``webhook_secret_encrypted`` (manual path) OR the
      app-level ``META_APP_SECRET`` (Embedded Signup path) — the POST MUST carry a
      well-formed ``X-Hub-Signature-256: sha256=<hex>`` header equal to
      ``HMAC_SHA256(secret, raw_body)`` compared in constant time. A MISSING,
      malformed, or NON-MATCHING signature is a hard failure: the route rejects
      the delivery with HTTP 401 and NOTHING is stored or applied. This is the
      core fix for the prior lenient behavior that accepted tampered/absent
      signatures with a 200.
    - PHASE-1 LENIENT only while NO secret is configured yet (a tenant still
      mid-onboarding). We cannot verify, so we do not hard-break inbound: the
      route logs a clear warning, the events are stored, but they are flagged
      ``processing_error="unverified_no_app_secret"`` and NOT applied — i.e.
      explicitly unverified, never silently trusted. The moment a secret exists,
      the strict path above is the default.
  Signatures and secrets are NEVER logged.
"""
from __future__ import annotations

import hashlib
import hmac
import json

from flask import current_app
from werkzeug.security import check_password_hash

from ...extensions import db
from ...models import (
    WhatsAppMessageQueue,
    WhatsAppTenantAccount,
    WhatsAppWebhookEvent,
    utcnow,
)
from .crypto import decrypt_secret
from .providers import MetaCloudWhatsAppProvider

_PROVIDER = "meta_cloud"


# ---------------------------------------------------------------------------
# GET verification handshake
# ---------------------------------------------------------------------------
def verify_challenge(args) -> str | None:
    """Return the ``hub.challenge`` string iff the handshake is valid, else None.

    Meta sends ``hub.mode``/``hub.verify_token``/``hub.challenge`` as query
    args. We accept the handshake when ``mode == "subscribe"`` and the presented
    token matches the stored verify-token hash of SOME tenant account (each is a
    Werkzeug password hash). We iterate every account that has a hash so the
    check does not short-circuit on the first row (constant-ish over accounts).
    """
    try:
        mode = args.get("hub.mode")
        token = args.get("hub.verify_token")
        challenge = args.get("hub.challenge")
    except Exception:  # noqa: BLE001 — a hostile args object must never crash us
        return None

    if mode != "subscribe" or not token:
        return None

    matched = False
    accounts = (
        WhatsAppTenantAccount.query.filter(
            WhatsAppTenantAccount.webhook_verify_token_hash.isnot(None)
        ).all()
    )
    for account in accounts:
        token_hash = account.webhook_verify_token_hash
        if not token_hash:
            continue
        try:
            if check_password_hash(token_hash, token):
                matched = True
        except Exception:  # noqa: BLE001 — a malformed stored hash must not raise
            continue

    if not matched:
        return None
    # ``challenge`` may legitimately be absent in a malformed probe; echo "" then.
    return challenge if challenge is not None else ""


# ---------------------------------------------------------------------------
# POST event ingestion
# ---------------------------------------------------------------------------
def _phone_number_id_from_payload(payload) -> str | None:
    """Defensively pull entry[].changes[].value.metadata.phone_number_id."""
    try:
        entries = payload.get("entry") if isinstance(payload, dict) else None
        if not isinstance(entries, list):
            return None
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            changes = entry.get("changes")
            if not isinstance(changes, list):
                continue
            for change in changes:
                if not isinstance(change, dict):
                    continue
                value = change.get("value")
                if not isinstance(value, dict):
                    continue
                metadata = value.get("metadata")
                if not isinstance(metadata, dict):
                    continue
                pnid = metadata.get("phone_number_id")
                if pnid:
                    return str(pnid)
    except Exception:  # noqa: BLE001 — purely best-effort extraction
        return None
    return None


def _event_id_for(event: dict) -> str:
    """Derive a stable, idempotent event id for a normalized event.

    A WhatsApp message id (``wamid...``) walks sent -> delivered -> read, so the
    id ALONE is not unique across a message's lifecycle. We therefore key a
    status event on ``"<provider_message_id>:<status>"`` and an inbound message
    on ``"<provider_message_id>"``. When no id is present we fall back to a
    SHA-256 of the JSON-serialized event so two identical deliveries still
    collide (and dedup) while distinct ones don't.
    """
    event_type = event.get("event_type")
    pmid = event.get("provider_message_id")

    if event_type == "message_status" and pmid:
        return f"meta:{pmid}:{event.get('status') or ''}"
    if event_type == "inbound_message" and pmid:
        return f"meta:in:{pmid}"

    try:
        blob = json.dumps(event, sort_keys=True, default=str)
    except (TypeError, ValueError):
        blob = repr(event)
    digest = hashlib.sha256(blob.encode("utf-8", "replace")).hexdigest()
    return f"meta:hash:{digest}"


# Signature verdicts returned by :func:`verify_signature`.
SIG_VERIFIED = "verified"               # secret resolved AND header matches -> process
SIG_FAILED = "failed"                   # secret resolved but header missing/bad -> 401
SIG_UNVERIFIED_NO_SECRET = "unverified_no_secret"  # no secret yet -> store, flag, 200


def _resolve_app_secret(account) -> str:
    """Resolve the app secret used to verify Meta's signature, or "" if none.

    Resolution order:
      1. the account's per-account ``webhook_secret_encrypted`` (manual path), else
      2. the app-level ``META_APP_SECRET`` — Embedded Signup connections don't
         store a per-account secret; their webhooks are signed with the Meta app
         secret, so we verify against it.
    A corrupt stored secret or a missing app context degrades to "" (no secret).
    """
    secret = ""
    encrypted = getattr(account, "webhook_secret_encrypted", None) if account is not None else None
    if encrypted:
        try:
            secret = decrypt_secret(encrypted)
        except Exception:  # noqa: BLE001 — a corrupt stored secret must not 5xx
            secret = ""
    if not secret:
        try:
            secret = (current_app.config.get("META_APP_SECRET") or "").strip()
        except Exception:  # noqa: BLE001 — outside app context, etc.
            secret = ""
    return secret


def _hmac_matches(secret, signature_header, raw_body) -> bool:
    """Constant-time check that ``signature_header`` is Meta's valid signature.

    Returns False on no secret, no/empty header, or any mismatch. The HMAC is
    computed over the EXACT raw request bytes (never a re-serialized body).
    """
    if not secret or not signature_header:
        return False
    body = raw_body if isinstance(raw_body, (bytes, bytearray)) else str(raw_body or "").encode("utf-8")
    expected = "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    try:
        return hmac.compare_digest(expected, signature_header)
    except Exception:  # noqa: BLE001 — exotic header types must not crash us
        return False


def _signature_ok(account, signature_header, raw_body) -> bool:
    """Low-level: True iff a secret resolves for ``account`` AND the presented
    ``X-Hub-Signature-256`` header matches it (constant-time). False on no
    secret / no header / mismatch. The verdict POLICY (401 vs. Phase-1 lenient)
    lives in :func:`verify_signature`; this is the raw cryptographic check.
    """
    return _hmac_matches(_resolve_app_secret(account), signature_header, raw_body)


def _account_for_payload(payload):
    """Resolve (phone_number_id, account) for a webhook payload, or (id|None, None)."""
    phone_number_id = _phone_number_id_from_payload(payload)
    account = None
    if phone_number_id:
        account = WhatsAppTenantAccount.query.filter_by(
            phone_number_id=phone_number_id
        ).first()
    return phone_number_id, account


def verify_signature(payload, signature_header, raw_body) -> str:
    """Classify Meta's POST signature into a verdict (see module docstring).

    Returns one of:
      * ``SIG_VERIFIED``            — a secret resolves and the header matches it.
      * ``SIG_FAILED``             — a secret resolves but the header is missing,
                                     malformed, or non-matching. The route MUST
                                     reject this with HTTP 401 and store nothing.
      * ``SIG_UNVERIFIED_NO_SECRET`` — no secret configured yet (Phase-1): the
                                     route accepts but flags events unverified.

    The HMAC is taken over the raw request bytes; the secret is never logged.
    """
    _phone_number_id, account = _account_for_payload(payload)
    secret = _resolve_app_secret(account)
    if not secret:
        return SIG_UNVERIFIED_NO_SECRET
    return SIG_VERIFIED if _hmac_matches(secret, signature_header, raw_body) else SIG_FAILED


def ingest(payload, *, signature_status=SIG_VERIFIED) -> dict:
    """Ingest a Meta webhook POST. Store + (optionally) process each event.

    ``signature_status`` is the verdict from :func:`verify_signature`. A
    ``SIG_FAILED`` delivery is rejected upstream with HTTP 401 and never reaches
    here, so this only sees ``SIG_VERIFIED`` (process normally) or
    ``SIG_UNVERIFIED_NO_SECRET`` (store but flag unverified, do not apply).

    Returns ``{"stored": n, "processed": m, "skipped_duplicates": d}``. Never
    raises: the caller wraps this and always returns HTTP 200 so Meta does not
    enter a retry storm.
    """
    summary = {"stored": 0, "processed": 0, "skipped_duplicates": 0}

    events = MetaCloudWhatsAppProvider().parse_webhook(payload)
    phone_number_id, account = _account_for_payload(payload)
    customer_id = account.customer_id if account is not None else None

    for event in events:
        if not isinstance(event, dict):
            continue
        event_id = _event_id_for(event)

        # Idempotent: a duplicate delivery of the same event is skipped.
        existing = WhatsAppWebhookEvent.query.filter_by(event_id=event_id).first()
        if existing is not None:
            summary["skipped_duplicates"] += 1
            continue

        row = WhatsAppWebhookEvent(
            provider=_PROVIDER,
            event_type=str(event.get("event_type") or "unknown"),
            phone_number_id=phone_number_id,
            provider_message_id=event.get("provider_message_id"),
            customer_id=customer_id,
            event_id=event_id,
            processed=False,
            received_at=utcnow(),
        )
        row.payload = payload
        db.session.add(row)
        summary["stored"] += 1

        if account is None:
            row.processing_error = "webhook_unmatched_phone_number"
            continue
        if signature_status == SIG_UNVERIFIED_NO_SECRET:
            # No app secret configured yet (tenant mid-onboarding). Store the
            # event but do NOT apply state changes — it is explicitly unverified,
            # never silently trusted. The route has already logged a warning.
            row.processing_error = "unverified_no_app_secret"
            continue

        try:
            process_event(row, event)
            row.processed = True
            row.processed_at = utcnow()
            summary["processed"] += 1
        except Exception as exc:  # noqa: BLE001 — processing must never 5xx
            row.processing_error = f"process_error: {exc}"[:500]

    db.session.commit()
    return summary


# ---------------------------------------------------------------------------
# Event processing
# ---------------------------------------------------------------------------
# Meta delivery status -> our queue status + the timestamp column it stamps.
_STATUS_MAP = {
    "sent": ("sent", "sent_at"),
    "delivered": ("delivered", "delivered_at"),
    "read": ("read", "read_at"),
    "failed": ("failed", "failed_at"),
}


def process_event(event_row, event: dict) -> None:
    """Apply a normalized event's side effects. Never raises on bad data.

    Only ``message_status`` mutates state: it correlates the Meta delivery
    receipt to a :class:`WhatsAppMessageQueue` row (by ``provider_message_id``
    AND the matched customer) and advances its lifecycle. ``inbound_message`` /
    ``template_status`` / ``unknown`` are store-only here (no-op).

    Does NOT commit; :func:`ingest` owns the single commit per request.
    """
    event_type = event.get("event_type")
    if event_type != "message_status":
        return

    provider_message_id = event.get("provider_message_id")
    if not provider_message_id:
        return

    mapped = _STATUS_MAP.get(str(event.get("status") or ""))
    if mapped is None:
        return
    new_status, timestamp_attr = mapped

    query = WhatsAppMessageQueue.query.filter_by(
        provider_message_id=provider_message_id
    )
    # Scope strictly to the matched customer so one tenant's webhook can never
    # mutate another tenant's message row.
    if event_row.customer_id is not None:
        query = query.filter_by(customer_id=event_row.customer_id)
    row = query.first()
    if row is None:
        return

    now = utcnow()
    row.status = new_status
    # Stamp the lifecycle timestamp only if not already set (idempotent).
    if getattr(row, timestamp_attr, None) is None:
        setattr(row, timestamp_attr, now)

    if new_status == "failed":
        errors = event.get("errors")
        code, message = _first_error(errors)
        if code is not None:
            row.error_code = str(code)[:60]
        if message is not None:
            row.error_message = str(message)


def _first_error(errors) -> tuple[object | None, object | None]:
    """Extract (code, message/title) from a Meta status ``errors`` list."""
    if not isinstance(errors, list) or not errors:
        return None, None
    first = errors[0]
    if not isinstance(first, dict):
        return None, None
    code = first.get("code")
    # Meta uses ``title``; older payloads carry ``message``. Prefer title.
    message = first.get("title")
    if message is None:
        message = first.get("message")
    if message is None:
        details = first.get("error_data")
        if isinstance(details, dict):
            message = details.get("details")
    return code, message
