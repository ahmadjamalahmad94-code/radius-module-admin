"""The single unified Notification model.

Every alert in the system — countdown thresholds, billing events, future
producers — writes ONE row here. The admin notification-center reads from
this table; customer-targeted rows are additionally fanned out to the
customer over the existing panel-messaging bridge (see ``channels.py``).
"""
from __future__ import annotations

import json
from typing import Any

from app.extensions import db
from app.models import utcnow

#: Severity vocabulary — mirrors the bridge's ``importance`` so a
#: customer-targeted row maps 1:1 onto a PanelMessage.
SEVERITIES = ("info", "warning", "critical")


class Notification(db.Model):
    """A single notification.

    ``customer_id`` NULL  → owner/admin-only (shows in the center only).
    ``customer_id`` set   → customer-targeted (center + queued to that
                            customer's panel via the bridge).

    ``dedupe_key`` is the idempotency anchor: a producer that may run many
    times (the scheduled engine) passes a stable key so the same threshold
    never fires twice. It is UNIQUE; NULL is allowed (multiple NULLs are
    distinct under SQLite/Postgres unique semantics) for ad-hoc rows.
    """

    __tablename__ = "notifications"
    __table_args__ = (
        db.Index("ix_notifications_customer_created", "customer_id", "created_at"),
        db.Index("ix_notifications_unread", "read_at"),
        db.UniqueConstraint("dedupe_key", name="uq_notifications_dedupe_key"),
    )

    id = db.Column(db.Integer, primary_key=True)
    # Producer/event type, e.g. "license_expiry", "payment_received",
    # "message_package_low". Free-form so new producers need no migration.
    type = db.Column(db.String(60), nullable=False, index=True)
    severity = db.Column(db.String(16), default="info", nullable=False, index=True)
    title = db.Column(db.String(200), default="", nullable=False)
    body = db.Column(db.Text, default="", nullable=False)

    # Target customer (NULL = owner/admin-only).
    customer_id = db.Column(
        db.Integer, db.ForeignKey("customers.id"), nullable=True, index=True
    )
    license_id = db.Column(
        db.Integer, db.ForeignKey("licenses.id"), nullable=True
    )

    # Requested delivery channels (JSON list) + per-channel result (JSON dict).
    channels_json = db.Column(db.Text, default="[]", nullable=False)
    delivery_json = db.Column(db.Text, default="{}", nullable=False)

    # Deep-link the center / customer panel can open (receipt, detail page…).
    link = db.Column(db.String(500), default="", nullable=False)

    # Idempotency anchor (UNIQUE). NULL for ad-hoc rows.
    dedupe_key = db.Column(db.String(160), nullable=True)

    # Read/unread: NULL == unread.
    read_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)

    customer = db.relationship("Customer")

    # ── JSON convenience accessors ───────────────────────────────────────
    @property
    def channels(self) -> list[str]:
        try:
            value = json.loads(self.channels_json or "[]")
            return [str(c) for c in value] if isinstance(value, list) else []
        except (ValueError, TypeError):
            return []

    @channels.setter
    def channels(self, value: list[str]) -> None:
        self.channels_json = json.dumps(list(value or []), ensure_ascii=False)

    @property
    def delivery(self) -> dict[str, Any]:
        try:
            value = json.loads(self.delivery_json or "{}")
            return value if isinstance(value, dict) else {}
        except (ValueError, TypeError):
            return {}

    @delivery.setter
    def delivery(self, value: dict[str, Any]) -> None:
        self.delivery_json = json.dumps(dict(value or {}), ensure_ascii=False)

    @property
    def is_read(self) -> bool:
        return self.read_at is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "severity": self.severity,
            "title": self.title,
            "body": self.body,
            "customer_id": self.customer_id,
            "license_id": self.license_id,
            "channels": self.channels,
            "delivery": self.delivery,
            "link": self.link,
            "dedupe_key": self.dedupe_key,
            "is_read": self.is_read,
            "read_at": self.read_at.isoformat() + "Z" if self.read_at else None,
            "created_at": self.created_at.isoformat() + "Z" if self.created_at else None,
        }
