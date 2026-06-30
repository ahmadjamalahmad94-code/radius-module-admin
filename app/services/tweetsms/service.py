"""High-level OWNER→customer SMS service.

Bridges :mod:`settings` (resolved creds) and :mod:`adapter` (the wire), adds
phone normalization, the 60-char segment rule, per-recipient result mapping, and
DB logging. The api_key is NEVER logged — only ``settings.resolved()`` reads it,
and only to hand it straight to the adapter URL builder.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

from flask import current_app, has_request_context, session

from ...extensions import db
from ...models import SmsLog
from ..whatsapp.phone import WhatsAppPhoneError, normalize_phone_for_whatsapp
from . import adapter, settings

#: Per-message character budget. Each SMS segment costs money, so the compose UI
#: guides the owner at this length and warns beyond it.
SEGMENT_LIMIT = 60


@dataclass
class SegmentInfo:
    length: int
    limit: int
    segments: int
    over_limit: bool


def segment_info(text: str) -> SegmentInfo:
    """Unicode-aware character + segment count for ``text``.

    Counts Unicode code points (so a 4-byte emoji is ONE character, matching the
    JS ``[...text].length`` counter). Segments are ceil(len / 60), min 1.
    """
    length = len(text or "")
    segments = max(1, math.ceil(length / SEGMENT_LIMIT)) if length else 0
    return SegmentInfo(
        length=length,
        limit=SEGMENT_LIMIT,
        segments=segments,
        over_limit=length > SEGMENT_LIMIT,
    )


def _dial_to_msisdn(phone: str, default_country: str = "PS") -> str:
    """Normalize ``phone`` to an international MSISDN with NO leading '+'
    (TweetSMS wants e.g. ``970599123456``). Raises on invalid input."""
    e164 = normalize_phone_for_whatsapp(phone, default_country=default_country)
    return e164.lstrip("+")


@dataclass
class RecipientResult:
    label: str
    phone: str          # as entered / displayed
    msisdn: str         # normalized international (no '+'), "" when invalid
    ok: bool
    status: str         # sent | failed | invalid
    message: str        # Arabic outcome reason
    sms_id: str = ""
    customer_id: int | None = None


def _current_admin_id() -> int | None:
    """The acting admin id, or None outside a request (e.g. service unit tests)."""
    if not has_request_context():
        return None
    return session.get("admin_id")


def _log_row(r: RecipientResult, *, sender: str, seg: int, body_preview: str) -> None:
    code = "" if r.ok else (r.status if r.status == "invalid" else "")
    db.session.add(SmsLog(
        actor_admin_id=_current_admin_id(),
        customer_id=r.customer_id,
        to_phone=r.msisdn or r.phone[:40],
        sender=sender[:40],
        body_preview=body_preview,
        segments=seg,
        status=r.status,
        provider_sms_id=(r.sms_id or "")[:64],
        error_code=(code or "")[:16],
        error_message=("" if r.ok else r.message)[:255],
    ))


def send_to_recipients(recipients, message: str, *, http_get=None) -> dict:
    """Send ``message`` to each recipient and return a structured result.

    ``recipients`` is an iterable of dicts ``{phone, label?, customer_id?}`` (or
    bare phone strings). Each recipient is sent INDIVIDUALLY so the per-recipient
    outcome maps cleanly to the UI. Invalid phones are reported without a send.
    Every attempt is logged to ``sms_logs``. Returns
    ``{ok, sent, failed, sender, segments, results: [...]}``.
    """
    message = message or ""
    if not message.strip():
        return {"ok": False, "error": "نص الرسالة فارغ.", "sent": 0, "failed": 0,
                "results": [], "sender": "", "segments": 0}
    if not settings.configured():
        return {"ok": False, "error": "لم تُضبَط بيانات TweetSMS بعد (المفتاح/المُرسِل).",
                "sent": 0, "failed": 0, "results": [], "sender": "", "segments": 0}

    creds = settings.resolved()
    sender = creds["sender"]
    timeout = float(current_app.config.get("TWEETSMS_TIMEOUT", 15.0))
    seg = segment_info(message).segments
    body_preview = message[:200]
    default_country = str(current_app.config.get("TWEETSMS_DEFAULT_COUNTRY", "PS"))

    results: list[RecipientResult] = []
    for item in recipients:
        if isinstance(item, str):
            phone, label, cid = item, item, None
        else:
            phone = (item.get("phone") or "").strip()
            label = (item.get("label") or phone or "—").strip()
            cid = item.get("customer_id")

        if not phone:
            r = RecipientResult(label=label, phone=phone, msisdn="", ok=False,
                                status="invalid", message="لا يوجد رقم هاتف.", customer_id=cid)
            results.append(r)
            _log_row(r, sender=sender, seg=seg, body_preview=body_preview)
            continue

        try:
            msisdn = _dial_to_msisdn(phone, default_country)
        except WhatsAppPhoneError:
            r = RecipientResult(label=label, phone=phone, msisdn="", ok=False,
                                status="invalid", message="رقم غير صالح.", customer_id=cid)
            results.append(r)
            _log_row(r, sender=sender, seg=seg, body_preview=body_preview)
            continue

        outcome = adapter.send_sms(creds, msisdn, message, sender,
                                   timeout=timeout, http_get=http_get)
        first = outcome.first
        if outcome.ok and first and first.ok:
            r = RecipientResult(label=label, phone=phone, msisdn=msisdn, ok=True,
                                status="sent", message=first.message,
                                sms_id=first.sms_id, customer_id=cid)
        else:
            reason = (outcome.error or (first.message if first else "")
                      or adapter.UNKNOWN_MESSAGE)
            r = RecipientResult(label=label, phone=phone, msisdn=msisdn, ok=False,
                                status="failed", message=reason, customer_id=cid)
        results.append(r)
        _log_row(r, sender=sender, seg=seg, body_preview=body_preview)

    sent = sum(1 for r in results if r.ok)
    failed = len(results) - sent
    return {
        "ok": sent > 0,
        "sent": sent,
        "failed": failed,
        "sender": sender,
        "segments": seg,
        "results": [
            {"label": r.label, "phone": r.phone, "msisdn": r.msisdn, "ok": r.ok,
             "status": r.status, "message": r.message, "sms_id": r.sms_id}
            for r in results
        ],
    }
