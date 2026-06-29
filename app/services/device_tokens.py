"""Central device-token registry — the customer→FCM-token store.

The ONE global mobile app registers its FCM token centrally with licensing
(forwarded over the signed bridge by the radius instance it is connected to,
which authenticates with its ``license_key`` bearer). Licensing keys each token
to the resolved customer and reads them back to dispatch FCM when any radius
instance forwards a push for that customer.

Every function is fail-safe at the caller layer; this layer only reads/writes.
"""
from __future__ import annotations

from typing import Iterable

from ..extensions import db
from ..models import DeviceToken, utcnow

# Platforms the app may report (empty allowed — older clients).
ALLOWED_PLATFORMS = {"android", "ios", "web", ""}


def register(customer_id: int, token: str, *, platform: str = "",
             app_version: str = "", external_user_id: str = "") -> DeviceToken | None:
    """Upsert a device token. Idempotent on ``token`` — re-registering the same
    token refreshes its customer/platform/last_seen rather than duplicating.

    Re-keying a token to a different customer (e.g. the app logged into a
    different instance) moves it — the token is globally unique."""
    tok = (token or "").strip()
    if not tok:
        return None
    row = DeviceToken.query.filter_by(token=tok).first()
    if row is None:
        row = DeviceToken(token=tok)
    row.customer_id = int(customer_id)
    row.platform = (platform or "").strip().lower()[:16]
    row.app_version = (app_version or "").strip()[:40]
    row.external_user_id = (external_user_id or "").strip()[:120]
    row.last_seen_at = utcnow()
    db.session.add(row)
    db.session.commit()
    return row


def unregister(token: str) -> int:
    """Delete a device token (app logout). Returns rows removed (0/1)."""
    tok = (token or "").strip()
    if not tok:
        return 0
    n = DeviceToken.query.filter_by(token=tok).delete(synchronize_session=False)
    db.session.commit()
    return int(n or 0)


def tokens_for_customer(customer_id: int) -> list[str]:
    """All registered FCM tokens for a customer (for multicast)."""
    rows = (DeviceToken.query
            .filter_by(customer_id=int(customer_id))
            .order_by(DeviceToken.id.asc())
            .all())
    return [r.token for r in rows if r.token]


def prune(tokens: Iterable[str]) -> int:
    """Delete tokens FCM reported invalid/unregistered (global by token)."""
    toks = [str(t).strip() for t in (tokens or []) if str(t).strip()]
    if not toks:
        return 0
    n = (DeviceToken.query
         .filter(DeviceToken.token.in_(toks))
         .delete(synchronize_session=False))
    db.session.commit()
    return int(n or 0)


def count_for_customer(customer_id: int) -> int:
    return int(DeviceToken.query.filter_by(customer_id=int(customer_id)).count())
