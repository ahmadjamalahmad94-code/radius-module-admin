"""Omni-channel delivery abstraction.

A notification's canonical home is the in-panel **center** (the row itself =
the ``web`` channel). Beyond that, each requested channel is a pluggable
handler. We REUSE existing infra rather than reinventing transports:

* ``panel``    → the panel-messaging **bridge** (``panel_messaging.send_to_customer``);
                 this is how a customer-targeted notification reaches the
                 customer's radius/panel on its next poll. (Requirement 4.)
* ``telegram`` → the existing messaging **router** + owner Telegram chat id.
* ``whatsapp`` / ``sms`` → the existing messaging router, to the customer's
                 stored phone (``dial_code + phone``) when targeted.
* ``email`` / ``push`` → STUBS behind the same interface — registered, return
                 ``not_configured`` — so they light up by swapping the handler.

Every handler is wrapped so a delivery failure never breaks notification
creation; the per-channel outcome is recorded in ``Notification.delivery``.
"""
from __future__ import annotations

import logging
from typing import Any, Callable

from app.extensions import db
from app.models import Customer

logger = logging.getLogger(__name__)

#: Severity → bridge importance (the bridge speaks info|warning|critical too).
_IMPORTANCE = {"info": "info", "warning": "warning", "critical": "critical"}

# Channels we treat as "the row itself" — always satisfied by storage.
WEB_CHANNELS = ("web", "in_app")


def _result(ok: bool, code: str, message: str = "", **extra: Any) -> dict[str, Any]:
    out = {"ok": ok, "code": code, "message": message}
    out.update(extra)
    return out


# ── individual channel handlers ──────────────────────────────────────────
def _deliver_panel(note) -> dict[str, Any]:
    """Customer-targeted → queue on the bridge for the customer's panel."""
    if not note.customer_id:
        return _result(False, "no_target", "إشعار غير موجّه لعميل — لا يُرسَل عبر الجسر.")
    customer = db.session.get(Customer, note.customer_id)
    if customer is None:
        return _result(False, "no_customer", "العميل غير موجود.")
    try:
        from app.services import panel_messaging

        msg = panel_messaging.send_to_customer(
            customer,
            body=note.body or note.title,
            subject=note.title,
            channel="notice",
            importance=_IMPORTANCE.get(note.severity, "info"),
            sender_admin_id=None,
            sender_label="مركز الإشعارات",
            metadata={
                "notification_id": note.id,
                "type": note.type,
                "dedupe_key": note.dedupe_key,
                "link": note.link,
            },
        )
        return _result(True, "queued", "أُدرج في طابور لوحة العميل.", panel_message_id=msg.id)
    except Exception as exc:  # noqa: BLE001 — bridge errors never break creation
        logger.exception("notify: bridge enqueue failed for note=%s", note.id)
        return _result(False, "bridge_error", str(exc))


def _deliver_via_router(channel: str, note) -> dict[str, Any]:
    """Telegram/WhatsApp/SMS via the existing messaging router."""
    recipient = _resolve_recipient(channel, note)
    if not recipient:
        return _result(False, "no_recipient", "لا يوجد مستلِم مهيّأ لهذه القناة.")
    try:
        from app.services.messaging import router

        text = f"{note.title}\n\n{note.body}".strip() if note.title else (note.body or "")
        res = router.send(channel, recipient, text)
        return _result(bool(res.ok), res.code or ("ok" if res.ok else "failed"),
                       res.message, provider_message_id=res.provider_message_id)
    except Exception as exc:  # noqa: BLE001
        logger.exception("notify: router send failed channel=%s note=%s", channel, note.id)
        return _result(False, "router_error", str(exc))


def _deliver_stub(channel: str, note) -> dict[str, Any]:
    """Email/Push — not wired yet. Same interface; swap this for a real
    handler when the adapter lands. Logged, never raised."""
    logger.info("notify: channel %s not wired yet (note=%s) — stub no-op", channel, note.id)
    return _result(False, "not_configured", f"قناة {channel} غير مفعّلة بعد.")


def _resolve_recipient(channel: str, note) -> str:
    """Best-effort recipient for a router channel.

    * Customer-targeted whatsapp/sms → the customer's E.164 phone.
    * Telegram → the owner's configured chat id (owner-facing channel).

    Recipient resolution is intentionally conservative: when we can't resolve
    one we return "" and the channel reports ``no_recipient`` rather than
    guessing. This is a clean extension point.
    """
    if channel == "telegram":
        try:
            from app.services.messaging.settings_store import get_owner_prefs

            return str((get_owner_prefs() or {}).get("owner_telegram_chat_id") or "").strip()
        except Exception:  # noqa: BLE001
            return ""
    if channel in ("whatsapp", "sms") and note.customer_id:
        customer = db.session.get(Customer, note.customer_id)
        if customer is None:
            return ""
        dial = str(getattr(customer, "dial_code", "") or "").strip()
        phone = str(getattr(customer, "phone", "") or "").strip()
        if not phone:
            return ""
        return (dial + phone).replace(" ", "") if dial and not phone.startswith("+") else phone
    return ""


#: Pluggable channel registry. Swap a stub for a real handler to wire a
#: channel — nothing else changes.
CHANNEL_HANDLERS: dict[str, Callable[[Any], dict[str, Any]]] = {
    "panel": _deliver_panel,
    "telegram": lambda note: _deliver_via_router("telegram", note),
    "whatsapp": lambda note: _deliver_via_router("whatsapp", note),
    "sms": lambda note: _deliver_via_router("sms", note),
    "email": lambda note: _deliver_stub("email", note),
    "push": lambda note: _deliver_stub("push", note),
}


def dispatch(note) -> dict[str, Any]:
    """Fan a notification out to its requested channels; record each result.

    ``web``/``in_app`` are satisfied by the row's existence. Unknown channels
    are recorded as ``unknown_channel`` rather than raising. Returns the
    delivery map (also persisted onto ``note.delivery``).
    """
    results: dict[str, Any] = {}
    for channel in note.channels:
        if channel in WEB_CHANNELS:
            results[channel] = _result(True, "stored", "ظاهر في مركز الإشعارات.")
            continue
        handler = CHANNEL_HANDLERS.get(channel)
        if handler is None:
            results[channel] = _result(False, "unknown_channel", f"قناة غير معروفة: {channel}")
            continue
        results[channel] = handler(note)
    note.delivery = results
    return results
