"""OWNER→customer SMS via the TweetSMS (tweetsms.ps) legacy HTTP API.

* :mod:`adapter`  — pure URL build + GET + plain-text parse (no Flask/DB).
* :mod:`settings` — the owner's single encrypted credential set (masked UI).
* :mod:`service`  — phone normalization, 60-char segments, per-recipient send +
  DB logging.

The provider api_key/password are the OWNER's (he bought the credit) and are
stored encrypted at rest; they are never logged.
"""
from __future__ import annotations

from . import adapter, service, settings
from .service import SEGMENT_LIMIT, segment_info, send_to_recipients

__all__ = [
    "adapter",
    "service",
    "settings",
    "SEGMENT_LIMIT",
    "segment_info",
    "send_to_recipients",
]
