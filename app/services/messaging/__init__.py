"""Unified messaging service — pluggable channel adapters + facades.

The package gives the panel ONE place to send outbound text via SMS, WhatsApp,
or Telegram, plus two facades on top of the raw channel router:

* :func:`notify_owner` — Layer 1: routes panel/customer events to the OWNER's
  configured channels (enable/disable + per-event preferences live in DB-backed
  settings).
* :func:`message_customer` — Layer 2: routes a free-form message to a CUSTOMER
  via WhatsApp + SMS, using their stored ``dial_code`` + ``phone``.

The raw send() router lives in :mod:`.router`. Per-channel HTTP clients live in
``adapters/`` and share the :class:`.adapters.base.ChannelAdapter` contract so a
real provider can be wired up later by editing a single HTTP call site (look
for the ``# TODO(messaging):`` markers).

Credentials are persisted in the existing key-value ``settings`` table; secrets
are encrypted at rest with the same Fernet key the WhatsApp module uses
(:mod:`app.services.whatsapp.crypto`). Never store a plaintext token.
"""
from __future__ import annotations

from .channels import CHANNELS, CHANNEL_LABELS, OWNER_EVENTS, OWNER_EVENT_LABELS
from .layers import (
    dispatch_lifecycle,
    message_customer,
    notify_owner,
    send_credentials,
)
from .lifecycle import (
    LIFECYCLE_EVENTS,
    all_event_states,
    build_credentials_text,
    get_event_state,
    is_enabled as lifecycle_is_enabled,
    render as lifecycle_render,
    save_event as save_lifecycle_event,
)
from .router import SendResult, send
from .settings_store import (
    ChannelSettingsError,
    get_channel_state,
    get_owner_prefs,
    save_channel,
    save_owner_prefs,
    test_send,
)

__all__ = [
    "CHANNELS",
    "CHANNEL_LABELS",
    "OWNER_EVENTS",
    "OWNER_EVENT_LABELS",
    "LIFECYCLE_EVENTS",
    "ChannelSettingsError",
    "SendResult",
    "all_event_states",
    "build_credentials_text",
    "dispatch_lifecycle",
    "get_channel_state",
    "get_event_state",
    "get_owner_prefs",
    "lifecycle_is_enabled",
    "lifecycle_render",
    "message_customer",
    "notify_owner",
    "save_channel",
    "save_lifecycle_event",
    "save_owner_prefs",
    "send",
    "send_credentials",
    "test_send",
]
