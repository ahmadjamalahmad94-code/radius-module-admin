"""Owner-toggleable debug logging for the panel's `/api/proxy/*` surface.

When the live proxy stops landing telemetry / heartbeats / placement calls,
the operator needs a way to see at a glance:

  * who hit the endpoint,
  * what the panel computed and returned,
  * why a record was rejected.

Production logs are intentionally quiet (one line per heartbeat is fine; a
debug dump on every routing-table refresh is not). This flag flips the
panel into a verbose mode for as long as the owner needs.

Resolution order
----------------
1. ``Setting[fleet.proxy_api.debug_logging]`` = ``"1"`` / ``"0"``  ← UI toggle.
2. ``app.config["FLEET_PROXY_API_DEBUG"]`` (env fallback for cron/CI).
3. Default OFF (no spam).

The flag is read fresh on every endpoint call so the operator does NOT have
to restart the panel to flip it. Read failures collapse to OFF — the panel
must never crash a proxy request because the debug flag couldn't be loaded.
"""
from __future__ import annotations

import logging
from typing import Any

from flask import current_app

logger = logging.getLogger("fleet.proxy_api")

SETTING_KEY = "fleet.proxy_api.debug_logging"


def is_debug_enabled() -> bool:
    """True iff the owner has explicitly turned proxy-API debug logging ON.

    Default-OFF: any missing row, any malformed value, any DB error in
    the read path collapses to ``False`` — the proxy keeps running.
    """
    try:
        # Local import so the helper module stays cheap to import.
        from app.extensions import db
        from app.models import Setting
        row = db.session.get(Setting, SETTING_KEY)
        if row is not None and (row.value or "").strip() == "1":
            return True
    except Exception:  # noqa: BLE001 — read path must never crash
        pass
    try:
        return bool(current_app.config.get("FLEET_PROXY_API_DEBUG", False))
    except Exception:  # noqa: BLE001
        return False


def set_debug_enabled(value: bool) -> None:
    """UI / CLI seam — persist a new value into the Setting row."""
    from app.extensions import db
    from app.models import Setting
    row = db.session.get(Setting, SETTING_KEY)
    desired = "1" if bool(value) else "0"
    if row is None:
        row = Setting(key=SETTING_KEY, value=desired)
    else:
        row.value = desired
    db.session.add(row)
    db.session.commit()


def dlog(endpoint: str, **fields: Any) -> None:
    """Emit ONE structured INFO line per call when debug is enabled.

    The format is deliberately a single line of ``key=value`` pairs so a
    ``journalctl | grep fleet.proxy_api`` is enough to reconstruct what
    the panel told the proxy. Values are stringified to keep the log line
    safe even when a counter comes through as ``None``.
    """
    if not is_debug_enabled():
        return
    parts = " ".join(f"{k}={v!r}" for k, v in fields.items())
    logger.info("fleet.proxy_api %s %s", endpoint, parts)


__all__ = ["SETTING_KEY", "is_debug_enabled", "set_debug_enabled", "dlog"]
