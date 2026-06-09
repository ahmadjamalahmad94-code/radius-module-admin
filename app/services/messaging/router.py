"""Channel router — the single entry point used by all callers.

``send(channel, to, text)`` resolves credentials, checks the enable flag,
delegates to the matching adapter, and returns a uniform :class:`SendResult`.
The router NEVER raises for not-configured / disabled / provider failures —
that would force every caller to wrap try/except. Programming errors (unknown
channel) propagate.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .adapters import ADAPTERS, NotConfiguredError
from .channels import CHANNELS
from .settings_store import channel_enabled, resolved_credentials


@dataclass
class SendResult:
    """Stable result type returned by :func:`send`, :func:`notify_owner`, and
    :func:`message_customer`. The shape is dict-friendly for JSON responses.
    """

    ok: bool
    channel: str
    code: str = ""  # machine code: ok | not_configured | disabled | failed | unknown_channel
    message: str = ""  # Arabic, UI-safe
    provider_message_id: str = ""
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "channel": self.channel,
            "code": self.code,
            "message": self.message,
            "provider_message_id": self.provider_message_id,
            "meta": dict(self.meta),
        }


def send(channel: str, to: str, text: str, **opts: Any) -> SendResult:
    """Dispatch one message via ``channel``.

    Returns a clean ``SendResult`` for every outcome — the caller renders a
    toast / records a row. Never raises for configuration / transport issues.
    """
    if channel not in CHANNELS:
        return SendResult(False, channel=channel, code="unknown_channel",
                          message=f"قناة غير معروفة: {channel}")
    if not channel_enabled(channel):
        return SendResult(False, channel=channel, code="disabled",
                          message=f"قناة {channel} غير مفعّلة.")
    adapter = ADAPTERS[channel]
    creds = resolved_credentials(channel)
    if not adapter.configured(creds):
        return SendResult(False, channel=channel, code="not_configured",
                          message=f"اعتمادات قناة {channel} غير مكتملة.")
    try:
        result = adapter.send(creds, to, text, **opts)
    except NotConfiguredError:
        return SendResult(False, channel=channel, code="not_configured",
                          message=f"اعتمادات قناة {channel} غير مكتملة.")
    if not result.ok:
        return SendResult(False, channel=channel, code="failed",
                          message=result.message or "تعذّر الإرسال.",
                          meta=result.meta)
    return SendResult(
        True, channel=channel, code="ok",
        message="تم الإرسال بنجاح.",
        provider_message_id=result.provider_message_id,
        meta=result.meta,
    )
