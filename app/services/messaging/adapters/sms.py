"""Generic HTTP SMS adapter.

Designed for the broad family of HTTP SMS gateways that take a POST body with
``to`` + ``message`` + ``from`` and a bearer/api-key header. The exact contract
varies per provider (Twilio, MessageBird, Vonage, regional ones …), so this
adapter intentionally keeps the wire payload tiny and easy to swap.

Wiring a specific provider later is a small edit at ``_build_request`` — change
the URL/payload shape, keep the credential schema if possible.
"""
from __future__ import annotations

from typing import Any

from . import _http
from .base import AdapterResult, NotConfiguredError


class SmsAdapter:
    name = "sms"

    #: Credentials the adapter expects in ``creds``. Keys are the same names
    #: persisted in the ``settings`` table by ``settings_store``.
    cred_keys: tuple[str, ...] = ("base_url", "api_key", "sender_id")

    def configured(self, creds: dict[str, str]) -> bool:
        return bool((creds.get("base_url") or "").strip()
                    and (creds.get("api_key") or "").strip())

    def send(self, creds: dict[str, str], to: str, text: str, **opts: Any) -> AdapterResult:
        to = (to or "").strip()
        text = (text or "").strip()
        if not to or not text:
            return AdapterResult(False, message="رقم المستلم أو نص الرسالة فارغ.")
        if not self.configured(creds):
            raise NotConfiguredError("sms not configured")

        url, payload, headers = self._build_request(creds, to, text)
        # TODO(messaging): adjust ``_build_request`` to match the concrete SMS
        # provider once chosen (Twilio / regional aggregator / …). This single
        # POST is the only network call site for SMS.
        result = _http.post_json(url, payload=payload, headers=headers, timeout=15.0)
        if result.error:
            return AdapterResult(False, message=f"تعذّر الاتصال بمزود الرسائل: {result.error}")
        if not result.ok:
            snippet = _short_body(result.body)
            return AdapterResult(
                False,
                message=f"رفض المزود الإرسال (HTTP {result.status}). {snippet}",
                meta={"status": result.status},
            )
        provider_id = _provider_id(result.body)
        return AdapterResult(True, provider_message_id=provider_id, meta={"status": result.status})

    # ── building blocks ──────────────────────────────────────────────────

    def _build_request(self, creds: dict[str, str], to: str, text: str) -> tuple[str, dict, dict]:
        """Return ``(url, json_payload, headers)``.

        Generic shape: bearer-style API key + JSON body. Override the body keys
        per concrete provider — that's the single line that varies the most.
        """
        base_url = creds["base_url"].rstrip("/")
        api_key = creds["api_key"]
        sender = (creds.get("sender_id") or "").strip()
        payload = {"to": to, "message": text}
        if sender:
            payload["from"] = sender
        headers = {
            "Authorization": f"Bearer {api_key}",
        }
        return base_url, payload, headers


def _provider_id(body: Any) -> str:
    if isinstance(body, dict):
        for key in ("message_id", "id", "sid", "messageId", "uuid"):
            v = body.get(key)
            if isinstance(v, str) and v:
                return v
    return ""


def _short_body(body: Any) -> str:
    if isinstance(body, dict):
        msg = body.get("message") or body.get("error") or body.get("detail")
        if isinstance(msg, str) and msg:
            return msg[:200]
    if isinstance(body, str):
        return body[:200]
    return ""
