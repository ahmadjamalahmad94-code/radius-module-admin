"""Telegram bot adapter — official Bot API.

Talks to ``https://api.telegram.org/bot<TOKEN>/sendMessage``. The ``chat_id``
is configurable per send (owner-notify defaults to the saved ``default_chat_id``;
customer messaging passes the customer's chat id explicitly when known).
"""
from __future__ import annotations

from typing import Any

from . import _http
from .base import AdapterResult, NotConfiguredError


class TelegramAdapter:
    name = "telegram"

    cred_keys: tuple[str, ...] = ("bot_token", "default_chat_id")

    def configured(self, creds: dict[str, str]) -> bool:
        return bool((creds.get("bot_token") or "").strip())

    def send(self, creds: dict[str, str], to: str, text: str, **opts: Any) -> AdapterResult:
        text = (text or "").strip()
        chat_id = (to or "").strip() or (creds.get("default_chat_id") or "").strip()
        if not chat_id or not text:
            return AdapterResult(False, message="معرّف الدردشة أو نص الرسالة فارغ.")
        if not self.configured(creds):
            raise NotConfiguredError("telegram not configured")

        bot_token = creds["bot_token"].strip()
        # TODO(messaging): swap the parse_mode default below if your team
        # standardises on MarkdownV2 / HTML; the Bot API endpoint itself is
        # stable.
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {"chat_id": chat_id, "text": text}
        result = _http.post_json(url, payload=payload, timeout=15.0)
        if result.error:
            return AdapterResult(False, message=f"تعذّر الاتصال بتيليجرام: {result.error}")
        body = result.body if isinstance(result.body, dict) else {}
        if not result.ok or not body.get("ok"):
            desc = body.get("description") if isinstance(body, dict) else ""
            return AdapterResult(
                False,
                message=f"رفض تيليجرام الإرسال (HTTP {result.status}). {desc or ''}".strip(),
                meta={"status": result.status},
            )
        msg_id = ""
        bdata = body.get("result") if isinstance(body, dict) else None
        if isinstance(bdata, dict):
            mid = bdata.get("message_id")
            if mid is not None:
                msg_id = str(mid)
        return AdapterResult(True, provider_message_id=msg_id, meta={"status": result.status})
