"""The support-LINE messaging service — «رسائل لوحة التراخيص» + poll-based chat.

A thin, well-tested layer over the :class:`PanelMessage` model that powers the
bidirectional support line between the provider licensing panel and a customer's
radius panel:

  * provider → customer : ``send_to_customer`` (a notice or a chat reply); the
    radius PULLS these via :func:`poll_undelivered` (marks delivered) and ACKs
    them via :func:`ack_seen`.
  * customer → provider : ``record_from_customer`` (the radius POSTs a chat /
    support message that lands in the provider inbox).

Channels: ``notice`` (announcement/alert) and ``chat`` (support conversation).
Both directions share one table so a customer's thread reads as one timeline.
"""
from __future__ import annotations

from typing import Any, Optional

from ..extensions import db
from ..models import Customer, License, PanelMessage, utcnow

CHANNELS = ("notice", "chat")
IMPORTANCES = ("info", "warning", "critical")


class PanelMessagingError(ValueError):
    """Raised on invalid panel-message input."""


def _clean_channel(value: str) -> str:
    v = str(value or "notice").strip().lower()
    return v if v in CHANNELS else "notice"


def _clean_importance(value: str) -> str:
    v = str(value or "info").strip().lower()
    return v if v in IMPORTANCES else "info"


def send_to_customer(
    customer: Customer,
    *,
    body: str,
    subject: str = "",
    channel: str = "notice",
    importance: str = "info",
    sender_admin_id: Optional[int] = None,
    sender_label: str = "",
    license: License | None = None,
    metadata: dict[str, Any] | None = None,
) -> PanelMessage:
    """Provider → customer: queue a message the radius will pull on its next poll."""
    text = str(body or "").strip()
    if not text:
        raise PanelMessagingError("نص الرسالة مطلوب.")
    msg = PanelMessage(
        customer_id=customer.id,
        license_id=license.id if license is not None else None,
        direction="to_customer",
        channel=_clean_channel(channel),
        importance=_clean_importance(importance),
        subject=str(subject or "").strip()[:180],
        body=text[:4000],
        sender_admin_id=sender_admin_id,
        sender_label=str(sender_label or "لوحة التراخيص").strip()[:120],
    )
    msg.message_metadata = metadata or {}
    db.session.add(msg)
    db.session.flush()
    return msg


def record_from_customer(
    customer: Customer,
    *,
    body: str,
    subject: str = "",
    channel: str = "chat",
    license: License | None = None,
    sender_label: str = "",
    metadata: dict[str, Any] | None = None,
) -> PanelMessage:
    """Customer (radius) → provider: store an inbound chat / support message.

    Inbound messages are 'delivered' the moment we persist them (they're already
    on the provider side); the provider reads them from the customer thread/inbox.
    """
    text = str(body or "").strip()
    if not text:
        raise PanelMessagingError("نص الرسالة مطلوب.")
    msg = PanelMessage(
        customer_id=customer.id,
        license_id=license.id if license is not None else None,
        direction="from_customer",
        channel=_clean_channel(channel),
        importance="info",
        subject=str(subject or "").strip()[:180],
        body=text[:4000],
        sender_label=str(sender_label or "لوحة الزبون").strip()[:120],
        delivered_at=utcnow(),
    )
    msg.message_metadata = metadata or {}
    db.session.add(msg)
    db.session.flush()
    return msg


def poll_undelivered(customer: Customer, *, mark_delivered: bool = True, limit: int = 100) -> list[PanelMessage]:
    """The radius pulls provider→customer messages it hasn't received yet.

    Returns the oldest-first batch of ``to_customer`` rows with no ``delivered_at``
    and stamps them delivered (so the next poll won't re-send them)."""
    rows = (PanelMessage.query
            .filter_by(customer_id=customer.id, direction="to_customer")
            .filter(PanelMessage.delivered_at.is_(None))
            .order_by(PanelMessage.created_at.asc())
            .limit(max(1, min(int(limit or 100), 500)))
            .all())
    if mark_delivered and rows:
        now = utcnow()
        for r in rows:
            r.delivered_at = now
    return rows


def ack_seen(customer: Customer, message_ids: list[int]) -> int:
    """The radius confirms the customer saw these provider messages."""
    ids = [int(m) for m in (message_ids or []) if str(m).strip().lstrip("-").isdigit()]
    if not ids:
        return 0
    rows = (PanelMessage.query
            .filter(PanelMessage.customer_id == customer.id,
                    PanelMessage.direction == "to_customer",
                    PanelMessage.id.in_(ids),
                    PanelMessage.seen_at.is_(None))
            .all())
    now = utcnow()
    for r in rows:
        r.seen_at = now
    return len(rows)


def thread_for_customer(customer: Customer, *, limit: int = 200) -> list[PanelMessage]:
    """The full panel-message timeline (both directions) for the admin view."""
    return (PanelMessage.query
            .filter_by(customer_id=customer.id)
            .order_by(PanelMessage.created_at.asc())
            .limit(max(1, min(int(limit or 200), 1000)))
            .all())


def unread_from_customer_count(customer: Customer) -> int:
    """How many inbound customer messages the provider hasn't 'seen' (seen_at is
    repurposed for inbound as a provider-read marker via mark_inbound_seen)."""
    return (PanelMessage.query
            .filter_by(customer_id=customer.id, direction="from_customer")
            .filter(PanelMessage.seen_at.is_(None))
            .count())


def mark_inbound_seen(customer: Customer) -> int:
    """Provider opened the thread → clear the inbound-unread marker."""
    rows = (PanelMessage.query
            .filter_by(customer_id=customer.id, direction="from_customer")
            .filter(PanelMessage.seen_at.is_(None))
            .all())
    now = utcnow()
    for r in rows:
        r.seen_at = now
    return len(rows)


def to_bridge_dict(msg: PanelMessage) -> dict[str, Any]:
    """Serialize a message for the bridge response the radius consumes."""
    return {
        "id": msg.id,
        "direction": msg.direction,
        "channel": msg.channel,
        "importance": msg.importance,
        "subject": msg.subject,
        "body": msg.body,
        "sender_label": msg.sender_label,
        "created_at": (msg.created_at.replace(microsecond=0).isoformat() + "Z") if msg.created_at else None,
    }


__all__ = [
    "PanelMessagingError", "CHANNELS", "IMPORTANCES",
    "send_to_customer", "record_from_customer", "poll_undelivered", "ack_seen",
    "thread_for_customer", "unread_from_customer_count", "mark_inbound_seen", "to_bridge_dict",
]
