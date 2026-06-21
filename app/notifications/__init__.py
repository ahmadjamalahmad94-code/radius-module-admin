"""Unified notification backbone (licensing side).

ONE notification model + center that every producer writes to, an
omni-channel delivery abstraction (reusing the existing messaging adapters
+ the panel-messaging bridge), a scheduled countdown/depletion engine, and
billing notifications.

Public surface:

* :class:`app.notifications.models.Notification` — the single table.
* :func:`app.notifications.service.create` — idempotent create + fan-out.
* :func:`app.notifications.engine.scan_once` — the scheduled engine pass.
* :func:`app.notifications.billing` — invoice/payment notifications.

Nothing here duplicates existing infra: customer delivery rides
``app.services.panel_messaging`` (the bridge); Telegram/SMS/WhatsApp ride
``app.services.messaging`` (the adapter router); secrets reuse the Fernet
wrapper. See the module docstrings for the exact reuse seams.
"""
from __future__ import annotations
