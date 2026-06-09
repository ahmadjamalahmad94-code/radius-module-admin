"""High-level facades on top of the channel router.

Two facades, both designed so callers never have to reason about which
channels are wired or where credentials live:

* :func:`notify_owner` — Layer 1, owner-side broadcast. Skipped silently when
  the event isn't in the owner's preferences (so adding hooks is cheap and
  safe — events that aren't enabled just become no-ops).
* :func:`message_customer` — Layer 2, customer-side push. Routes to WhatsApp
  + SMS by default using the customer's stored ``dial_code`` + ``phone``.
"""
from __future__ import annotations

import logging
from typing import Any, Iterable

from .channels import CHANNELS, OWNER_EVENT_LABELS
from .router import SendResult, send
from .settings_store import get_owner_prefs

_log = logging.getLogger(__name__)


# ── Layer 1: owner notifications ─────────────────────────────────────────

def notify_owner(event: str, detail: str = "", *, extra: dict[str, Any] | None = None) -> list[SendResult]:
    """Fan out a panel/customer event to the OWNER's enabled channels.

    Silently a no-op when the event isn't enabled in owner prefs — that lets
    new event hooks be added freely without breaking existing flows. Returns
    one :class:`SendResult` per channel attempted (empty list = nothing sent).

    Failures are LOGGED but never raised: the caller is in the middle of a
    business action (creating a customer, recording a payment, …) and must not
    be blocked by a messaging glitch.
    """
    prefs = get_owner_prefs()
    if event not in prefs.get("events", []):
        return []
    text = _format_owner_message(event, detail, extra or {})
    results: list[SendResult] = []
    for channel in prefs.get("channels", []):
        if channel not in CHANNELS:
            continue
        to = _owner_recipient(channel, prefs)
        if not to:
            results.append(SendResult(False, channel=channel, code="no_recipient",
                                      message=f"لا يوجد عنوان مستلم للمالك على {channel}."))
            continue
        try:
            result = send(channel, to, text)
        except Exception as exc:  # adapter bug; do NOT propagate
            _log.exception("notify_owner: send via %s crashed", channel)
            results.append(SendResult(False, channel=channel, code="crash",
                                      message=str(exc)))
            continue
        if not result.ok:
            _log.warning("notify_owner: %s send returned %s", channel, result.code)
        results.append(result)
    return results


def _owner_recipient(channel: str, prefs: dict[str, Any]) -> str:
    if channel == "telegram":
        return (prefs.get("owner_telegram_chat_id") or "").strip()
    # sms + whatsapp share the owner's phone number
    return (prefs.get("owner_phone") or "").strip()


def _format_owner_message(event: str, detail: str, extra: dict[str, Any]) -> str:
    label = OWNER_EVENT_LABELS.get(event, event)
    parts = [f"[{label}]"]
    if detail:
        parts.append(detail)
    if extra:
        # Keep extra payload compact and ASCII-safe for SMS budgets.
        kv = " ".join(f"{k}={v}" for k, v in extra.items() if v is not None)
        if kv:
            parts.append(kv)
    return " ".join(parts)


# ── Layer 2: customer messaging ──────────────────────────────────────────

def message_customer(
    customer: Any,
    text: str,
    *,
    channels: Iterable[str] = ("whatsapp", "sms"),
) -> list[SendResult]:
    """Send ``text`` to a customer over the requested ``channels`` (default:
    WhatsApp + SMS). Returns one result per channel attempted.

    ``customer`` is duck-typed so this works with the ORM ``Customer`` model
    or a plain object with ``dial_code`` + ``phone``. When the customer has no
    phone on file, every channel result is ``no_recipient`` — the caller can
    surface that as a UI hint to update the contact details.
    """
    to = _customer_phone(customer)
    results: list[SendResult] = []
    for channel in channels:
        if channel not in CHANNELS:
            results.append(SendResult(False, channel=channel, code="unknown_channel",
                                      message=f"قناة غير معروفة: {channel}"))
            continue
        if not to:
            results.append(SendResult(False, channel=channel, code="no_recipient",
                                      message="لا يوجد رقم هاتف مسجَّل للعميل."))
            continue
        try:
            results.append(send(channel, to, text))
        except Exception as exc:  # adapter bug; do NOT propagate
            _log.exception("message_customer: send via %s crashed", channel)
            results.append(SendResult(False, channel=channel, code="crash", message=str(exc)))
    return results


def _customer_phone(customer: Any) -> str:
    phone = (getattr(customer, "phone", "") or "").strip()
    if not phone:
        return ""
    dial = (getattr(customer, "dial_code", "") or "").strip()
    # Phone is stored as the local part; prefix the dial code (E.164-ish).
    # If the operator already typed a leading +, trust it as-is.
    if phone.startswith("+"):
        return phone.lstrip("+")
    if dial:
        return f"{dial.lstrip('+')}{phone.lstrip('0')}"
    return phone


__all__ = ["notify_owner", "message_customer"]
