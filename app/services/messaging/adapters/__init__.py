"""Channel adapter implementations — one module per provider family.

A channel adapter is responsible for ONE thing: given an already-resolved set
of credentials + a recipient + a body, perform the outbound HTTP call. It must
never read settings on its own — the router (or the test-send route) hands it
a plain dict of plaintext credentials. That keeps the encryption boundary in a
single place (``settings_store.resolved_credentials``).

Each adapter exposes a class implementing :class:`base.ChannelAdapter`:
``configured(creds) -> bool`` and ``send(creds, to, text, **opts) -> dict``.
"""
from __future__ import annotations

from .base import (
    AdapterResult,
    ChannelAdapter,
    NotConfiguredError,
    SendFailedError,
)
from .sms import SmsAdapter
from .telegram import TelegramAdapter
from .whatsapp import WhatsAppAdapter

#: Adapter registry — keyed by channel id (see :data:`messaging.CHANNELS`).
ADAPTERS: dict[str, ChannelAdapter] = {
    "sms": SmsAdapter(),
    "whatsapp": WhatsAppAdapter(),
    "telegram": TelegramAdapter(),
}

__all__ = [
    "ADAPTERS",
    "AdapterResult",
    "ChannelAdapter",
    "NotConfiguredError",
    "SendFailedError",
    "SmsAdapter",
    "TelegramAdapter",
    "WhatsAppAdapter",
]
