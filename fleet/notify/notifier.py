"""fleet.notify.notifier — turn ``fleet_events`` rows into owner alerts.

Public surface is intentionally tiny:

* :func:`dispatch_event(event)` — call this AFTER you've added an
  :class:`fleet.notify.models_alert.Event` row and committed (or right
  before the commit if the producer prefers a single transaction). The
  notifier:

  1. asks the rule matrix for a :class:`AlertSpec`,
  2. checks the owner has the kind enabled,
  3. enforces the dedupe slot via the ``Alert`` partial-unique index,
  4. creates one :class:`Alert` row per configured channel,
  5. fires :func:`app.services.messaging.send` per row — recording
     the outcome on the same Alert row.

The dispatcher NEVER raises for messaging-side problems: producers are
typically inside a request handler or a worker tick and shouldn't be
blocked by a misconfigured SMS gateway. All transport errors land on
``Alert.status`` (``failed`` / ``suppressed``).

The transport layer is the channel router from the messaging foundation
(:func:`app.services.messaging.send`). We DELIBERATELY do not go through
``messaging.notify_owner`` because that helper's per-event gate is bound
to the customer-side OWNER_EVENTS catalog — fleet events have their own
catalog, dedupe rules, and Alert ledger.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models import utcnow
from app.services.messaging import send as channel_send
from app.services.messaging.settings_store import get_owner_prefs

from .models_alert import ALERT_ACTIVE_STATUSES, Alert, Event
from .rules import AlertSpec, spec_for
from .settings_store import get_channels, is_kind_enabled

_log = logging.getLogger(__name__)


def dispatch_event(event: Event) -> list[Alert]:
    """Run the rule matrix against ``event`` and queue/send Alert rows.

    Returns the list of Alert rows touched (newly inserted OR a single
    row found by the dedupe lookup). Empty list means a no-op (kind
    disabled or no channels configured) — explicitly NOT an error.
    """
    if event is None:
        return []
    if not is_kind_enabled(event.kind):
        return []
    spec = spec_for(event)
    channels = get_channels()
    if not channels:
        # No channels configured — record nothing rather than litter Alert
        # rows the operator can't action.
        _log.info("fleet.notify: no channels configured; skipping %s", event.kind)
        return []

    prefs = get_owner_prefs()
    out: list[Alert] = []
    for channel in channels:
        recipient = _recipient_for(channel, prefs)
        if not recipient:
            # Don't write a row that's guaranteed to fail — record one
            # "no_recipient" suppressed Alert so the owner can see WHY in
            # the alerts view, then move on.
            out.append(_write_suppressed(event, spec, channel, ""))
            continue

        existing = _existing_active(spec.dedupe_key, channel) if spec.dedupe_key else None
        if existing is not None:
            out.append(existing)
            continue

        alert = Alert(
            event_id=event.id,
            created_at=utcnow(),
            channel=channel,
            recipient=recipient,
            body=spec.body,
            status="queued",
            dedupe_key=spec.dedupe_key,
        )
        db.session.add(alert)
        try:
            db.session.flush()
        except IntegrityError:
            # A racing producer just claimed the dedupe slot — fall back
            # to the existing row.
            db.session.rollback()
            existing = _existing_active(spec.dedupe_key, channel)
            if existing is not None:
                out.append(existing)
                continue
            # Shouldn't happen — drop the row and move on quietly.
            continue

        _deliver(alert, spec)
        out.append(alert)
    return out


# ── helpers ───────────────────────────────────────────────────────────────

def _recipient_for(channel: str, prefs: dict[str, Any]) -> str:
    if channel == "telegram":
        return (prefs.get("owner_telegram_chat_id") or "").strip()
    # sms + whatsapp share the owner's phone (E.164 without "+")
    return (prefs.get("owner_phone") or "").strip()


def _existing_active(dedupe_key: str | None, channel: str) -> Alert | None:
    if not dedupe_key:
        return None
    return (
        Alert.query
        .filter(Alert.dedupe_key == dedupe_key)
        .filter(Alert.channel == channel)
        .filter(Alert.status.in_(tuple(ALERT_ACTIVE_STATUSES)))
        .first()
    )


def _write_suppressed(event: Event, spec: AlertSpec, channel: str,
                      recipient: str) -> Alert:
    """Persist an Alert row that records 'we wanted to send but couldn't'."""
    alert = Alert(
        event_id=event.id,
        created_at=utcnow(),
        channel=channel,
        recipient=recipient or "—",
        body=spec.body,
        status="suppressed",
        # Suppressed rows opt out of the dedupe slot so the next real
        # event can still create an active alert once a recipient lands.
        dedupe_key=None,
    )
    db.session.add(alert)
    try:
        db.session.flush()
    except IntegrityError:
        db.session.rollback()
    return alert


def _deliver(alert: Alert, spec: AlertSpec) -> None:
    """Hand the alert body to the channel router and update status."""
    try:
        result = channel_send(alert.channel, alert.recipient, alert.body)
    except Exception as exc:  # adapter bug — never propagate
        _log.exception("fleet.notify: send via %s crashed", alert.channel)
        alert.status = "failed"
        alert.retries = (alert.retries or 0) + 1
        return
    if result.ok:
        alert.status = "sent"
        alert.sent_at = utcnow()
    else:
        # Distinguish "channel not configured" (the owner expects to see
        # this) from a real transport failure.
        alert.status = "suppressed" if result.code in ("disabled", "not_configured", "no_recipient") else "failed"
        alert.retries = (alert.retries or 0) + 1
        _log.info("fleet.notify: %s -> %s (%s)", alert.channel, alert.status, result.code)


__all__ = ["dispatch_event"]
