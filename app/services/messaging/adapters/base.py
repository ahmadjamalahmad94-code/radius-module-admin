"""Shared adapter contract + error types."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass
class AdapterResult:
    """What an adapter returns on a successful send.

    The adapter NEVER raises on transport errors — it returns
    ``ok=False`` with an Arabic ``message`` so the caller can render a toast.
    Only programming errors propagate.
    """

    ok: bool
    message: str = ""
    provider_message_id: str = ""
    meta: dict[str, Any] = field(default_factory=dict)


class NotConfiguredError(Exception):
    """Raised when a caller tries to send via a channel with missing creds.

    The router catches this and converts it to a clean ``SendResult`` so the
    UI shows a toast instead of crashing.
    """


class SendFailedError(Exception):
    """Programming-level adapter misuse (bad recipient, etc.). NOT for HTTP
    failures — those are returned as ``AdapterResult(ok=False, ...)``."""


class ChannelAdapter(Protocol):
    """Every adapter must satisfy this contract."""

    name: str

    def configured(self, creds: dict[str, str]) -> bool:  # pragma: no cover
        ...

    def send(self, creds: dict[str, str], to: str, text: str, **opts: Any) -> AdapterResult:  # pragma: no cover
        ...
