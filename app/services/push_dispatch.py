"""Central push dispatch — resolve a customer's device tokens and send FCM.

This is the single point where the licensing panel turns a forwarded push
request (from a customer radius instance over the signed bridge) into an actual
FCM multicast to that customer's registered devices. It ties together the
device-token registry (``device_tokens``) and the FCM sender (``firebase_fcm``)
and prunes tokens FCM reports as dead.

``dispatch_to_customer`` is synchronous + fail-safe (used by tests and the
test-push path); ``spawn_dispatch`` runs it off the request thread, mirroring
``customer_backups._spawn_drive_upload``.
"""
from __future__ import annotations

import logging
from typing import Any, Mapping, Optional

from flask import Flask, current_app

from . import device_tokens, firebase_fcm

_LOG = logging.getLogger(__name__)


def dispatch_to_customer(customer_id: int, *, title: str, body: str,
                         data: Optional[Mapping[str, Any]] = None) -> dict:
    """Send a push to every device registered for ``customer_id``. Synchronous
    and fully fail-safe. Returns the sender diagnostic dict, augmented with
    ``customer_id`` and ``pruned``.

    reason values: ``no_tokens`` (none registered) · ``fcm_disabled`` (no
    credential / library on the server) · ``sent`` (dispatched)."""
    try:
        tokens = device_tokens.tokens_for_customer(int(customer_id))
    except Exception:  # noqa: BLE001
        _LOG.debug("token lookup failed", exc_info=True)
        return {"ok": False, "reason": "lookup_error", "sent": 0, "failed": 0,
                "customer_id": int(customer_id), "pruned": 0}
    if not tokens:
        return {"ok": False, "reason": "no_tokens", "sent": 0, "failed": 0,
                "customer_id": int(customer_id), "pruned": 0}

    res = firebase_fcm.send_to_tokens(tokens, title, body, data or {})
    pruned = 0
    invalid = res.get("invalid_tokens") or []
    if invalid:
        try:
            pruned = device_tokens.prune(invalid)
        except Exception:  # noqa: BLE001
            _LOG.debug("prune invalid tokens failed", exc_info=True)
    out = dict(res)
    out["customer_id"] = int(customer_id)
    out["pruned"] = pruned
    return out


def spawn_dispatch(app: Flask, customer_id: int, *, title: str, body: str,
                   data: Optional[Mapping[str, Any]] = None) -> None:
    """Dispatch a push off the request thread (best-effort, never raises)."""
    import threading

    payload = dict(data or {})

    def _worker() -> None:
        with app.app_context():
            try:
                dispatch_to_customer(customer_id, title=title, body=body, data=payload)
            except Exception:  # noqa: BLE001 — background, best-effort
                _LOG.debug("push dispatch worker failed", exc_info=True)

    try:
        threading.Thread(target=_worker, name="fcm-dispatch", daemon=True).start()
    except Exception:  # noqa: BLE001
        _LOG.debug("push dispatch spawn failed", exc_info=True)
