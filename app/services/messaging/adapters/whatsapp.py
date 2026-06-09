"""WhatsApp adapter — reuses the existing Meta Cloud client.

This adapter is a thin shim over ``app.services.whatsapp.providers``: the panel
already has a battle-tested Meta Cloud provider with error mapping, token
masking, and a single audited HTTP call site. The messaging layer just routes
through it so credentials and rate-limit handling stay in one place.

Two credential modes are supported:

1. **Reuse panel-managed credentials** (``mode == "panel"``) — most installs:
   the admin already configured Meta Cloud API on the WhatsApp settings page.
   The adapter resolves the panel's house credentials at send time and uses
   them. No duplicate token entry is required.

2. **Direct creds** (``mode == "direct"``) — fallback when the panel-managed
   WhatsApp module isn't enabled. The messaging settings page lets the admin
   paste a ``phone_number_id`` + ``access_token`` directly.

In both cases, sends are SHORT free-text via the Meta ``messages`` endpoint —
fine when the recipient has an open customer-service window. Outside the
24-hour window, a template message is required; the adapter surfaces that as a
clean error so the caller can pick a template flow.
"""
from __future__ import annotations

from typing import Any

from flask import current_app

from .base import AdapterResult, NotConfiguredError


class WhatsAppAdapter:
    name = "whatsapp"

    #: ``mode`` switches between "panel" (reuse existing Meta Cloud config) and
    #: "direct" (use phone_number_id + access_token from messaging settings).
    cred_keys: tuple[str, ...] = ("mode", "phone_number_id", "access_token")

    def configured(self, creds: dict[str, str]) -> bool:
        mode = (creds.get("mode") or "panel").strip()
        if mode == "panel":
            return self._panel_configured()
        return bool((creds.get("phone_number_id") or "").strip()
                    and (creds.get("access_token") or "").strip())

    def send(self, creds: dict[str, str], to: str, text: str, **opts: Any) -> AdapterResult:
        to = (to or "").strip()
        text = (text or "").strip()
        if not to or not text:
            return AdapterResult(False, message="رقم المستلم أو نص الرسالة فارغ.")
        if not self.configured(creds):
            raise NotConfiguredError("whatsapp not configured")

        token, phone_number_id = self._resolve_creds(creds)
        from .._compat_whatsapp import send_text  # local import: avoid cycles

        try:
            # TODO(messaging): this single call site is where outbound WhatsApp
            # text is dispatched. The compat shim wraps the Meta Cloud provider
            # and returns a structured dict so adapter contracts stay stable.
            result = send_text(token=token, phone_number_id=phone_number_id, to=to, text=text)
        except Exception as exc:  # provider raised — return as failure
            return AdapterResult(False, message=f"تعذّر إرسال واتساب: {exc}")

        if not result.get("ok"):
            return AdapterResult(
                False,
                message=result.get("message") or "تعذّر إرسال واتساب.",
                meta={"code": result.get("code", "")},
            )
        return AdapterResult(
            True,
            provider_message_id=result.get("provider_message_id", ""),
            meta={"code": "ok"},
        )

    # ── credential resolution ────────────────────────────────────────────

    def _panel_configured(self) -> bool:
        try:
            from ...whatsapp import cloud_settings as wac  # local import: avoid cycles
        except Exception:
            return False
        try:
            creds = wac.resolved()
        except Exception:
            return False
        return bool(creds.get("access_token") and creds.get("phone_number_id"))

    def _resolve_creds(self, creds: dict[str, str]) -> tuple[str, str]:
        mode = (creds.get("mode") or "panel").strip()
        if mode == "panel":
            from ...whatsapp import cloud_settings as wac  # local import: avoid cycles
            resolved = wac.resolved()
            return resolved.get("access_token", ""), resolved.get("phone_number_id", "")
        return (creds.get("access_token") or "").strip(), (creds.get("phone_number_id") or "").strip()
