"""Compatibility shim around the existing Meta Cloud WhatsApp provider.

The messaging package keeps its own contract (``send_text`` returns a plain
dict, never raises) so adapters remain transport-agnostic. This shim is the
only place that knows about ``WhatsAppProviderError`` and the in-memory
account stand-in.
"""
from __future__ import annotations

from typing import Any

from ..whatsapp.cloud_settings import _AccountShim
from ..whatsapp.providers import MetaCloudWhatsAppProvider, WhatsAppProviderError


def send_text(*, token: str, phone_number_id: str, to: str, text: str) -> dict[str, Any]:
    """Send a free-text WhatsApp message and return ``{ok, message, ...}``.

    Never raises for provider/HTTP errors. The caller (an adapter) turns the
    dict into an :class:`AdapterResult`.
    """
    if not token or not phone_number_id:
        return {"ok": False, "code": "not_configured",
                "message": "اعتمادات واتساب غير مكتملة."}
    provider = MetaCloudWhatsAppProvider()
    account = _AccountShim(token, phone_number_id)
    try:
        result = provider.send_text_message(account, recipient=to, body=text)
    except WhatsAppProviderError as exc:
        return {"ok": False, "code": exc.code, "message": exc.message}
    return {"ok": True, "provider_message_id": result.get("provider_message_id", "")}
