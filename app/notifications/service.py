"""Notification service — the one seam every producer calls.

``create()`` is idempotent on ``dedupe_key``: the scheduled engine can run
every few minutes and a given threshold fires exactly once. After persisting
the row it fans out to the requested channels (bridge + messaging adapters).
"""
from __future__ import annotations

import logging
from typing import Any, Iterable, Optional

from app.extensions import db
from app.models import utcnow

from .channels import dispatch
from .models import Notification

logger = logging.getLogger(__name__)

#: Default channels when a producer doesn't specify. ``web`` is always there
#: (the center); customer-targeted rows also ride the ``panel`` bridge.
_DEFAULT_OWNER_CHANNELS = ("web",)
_DEFAULT_CUSTOMER_CHANNELS = ("web", "panel")


def create(
    *,
    type: str,
    title: str,
    body: str = "",
    severity: str = "info",
    customer_id: Optional[int] = None,
    license_id: Optional[int] = None,
    channels: Optional[Iterable[str]] = None,
    link: str = "",
    dedupe_key: Optional[str] = None,
    emit: bool = True,
) -> Notification:
    """Create (or return the existing, on dedupe) notification + fan out.

    Idempotent: if ``dedupe_key`` is given and a row already exists, that row
    is returned unchanged and NO re-delivery happens. The caller is expected
    to ``db.session.commit()`` (mirrors the rest of the codebase).
    """
    if dedupe_key:
        existing = Notification.query.filter_by(dedupe_key=dedupe_key).first()
        if existing is not None:
            return existing

    if channels is None:
        channels = _DEFAULT_CUSTOMER_CHANNELS if customer_id else _DEFAULT_OWNER_CHANNELS

    note = Notification(
        type=str(type)[:60],
        severity=severity if severity in ("info", "warning", "critical") else "info",
        title=str(title or "")[:200],
        body=str(body or ""),
        customer_id=customer_id,
        license_id=license_id,
        link=str(link or "")[:500],
        dedupe_key=(str(dedupe_key)[:160] if dedupe_key else None),
    )
    note.channels = list(channels)
    db.session.add(note)
    db.session.flush()  # assign id before channel fan-out (used in metadata)

    if emit:
        try:
            dispatch(note)
        except Exception:  # noqa: BLE001 — delivery never breaks creation
            logger.exception("notify: dispatch failed for note=%s", note.id)
    return note


# ── read-state + queries (center / bell) ─────────────────────────────────
def mark_read(notification_id: int) -> bool:
    note = db.session.get(Notification, notification_id)
    if note is None:
        return False
    if note.read_at is None:
        note.read_at = utcnow()
    return True


def mark_all_read(*, customer_id: Optional[int] = None) -> int:
    q = Notification.query.filter(Notification.read_at.is_(None))
    if customer_id is not None:
        q = q.filter(Notification.customer_id == customer_id)
    now = utcnow()
    rows = q.all()
    for r in rows:
        r.read_at = now
    return len(rows)


def unread_count() -> int:
    return Notification.query.filter(Notification.read_at.is_(None)).count()


def recent(
    *,
    limit: int = 50,
    unread_only: bool = False,
    type: Optional[str] = None,
    severity: Optional[str] = None,
    customer_id: Optional[int] = None,
) -> list[Notification]:
    q = Notification.query
    if unread_only:
        q = q.filter(Notification.read_at.is_(None))
    if type:
        q = q.filter(Notification.type == type)
    if severity:
        q = q.filter(Notification.severity == severity)
    if customer_id is not None:
        q = q.filter(Notification.customer_id == customer_id)
    return q.order_by(Notification.created_at.desc()).limit(max(1, min(int(limit), 500))).all()
