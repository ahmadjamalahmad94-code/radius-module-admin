"""WhatsApp message-sending provider abstraction.

This module defines the provider contract the gateway uses to talk to a
WhatsApp Business backend, plus the concrete Meta Cloud API implementation.

Design rules that callers and tests rely on:

* The ONLY place that touches the network is
  :meth:`MetaCloudWhatsAppProvider._request`. It is intentionally tiny so
  tests can monkeypatch it and never hit Meta. Every higher-level method
  (send/validate/health) goes through it.
* Access tokens are secrets. They are decrypted lazily inside ``_token`` and
  passed only as an ``Authorization: Bearer`` header. They are NEVER placed in
  exception messages, ``str(exc)``, or logs (no token/body logging at INFO).
* Errors raised to the gateway are :class:`WhatsAppProviderError` with a
  machine ``code``, a non-admin-safe Arabic ``message``, and a ``retryable``
  flag so the queue/worker can decide whether to back off and retry.

``requests`` is not a dependency of this project (see requirements.txt), so the
HTTP call is built on the standard-library ``urllib`` — the same approach used
by ``app/services/google_drive.py``.
"""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from flask import current_app

from .crypto import decrypt_secret


class WhatsAppProviderError(Exception):
    """A provider-level failure surfaced to the gateway.

    Carries a stable machine ``code``, a user/non-admin-safe ``message``
    (Arabic), whether the operation is worth retrying, and the originating
    HTTP status (when the error came from an HTTP response).

    Security: the string form of this exception must NEVER contain an access
    token or a raw provider response body. Only ``code`` and the curated
    ``message`` are exposed.
    """

    def __init__(
        self,
        code: str,
        message: str,
        *,
        retryable: bool = False,
        http_status: int | None = None,
        meta_code: int | None = None,
        meta_subcode: int | None = None,
        meta_detail: str = "",
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = bool(retryable)
        self.http_status = http_status
        # Raw Meta error facts (code/subcode/message). Kept as attributes for
        # admin-facing diagnostics; NEVER folded into ``message``/``str`` (which
        # stay curated and token-free).
        self.meta_code = meta_code
        self.meta_subcode = meta_subcode
        self.meta_detail = meta_detail or ""

    def __str__(self) -> str:
        # Deliberately limited to code + curated message. Never include tokens,
        # headers, or response bodies here.
        return f"[{self.code}] {self.message}"

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return (
            f"WhatsAppProviderError(code={self.code!r}, "
            f"retryable={self.retryable!r}, http_status={self.http_status!r})"
        )


class BaseWhatsAppProvider:
    """Abstract contract every WhatsApp provider implementation must satisfy.

    Subclasses implement the actual transport. Methods here raise
    ``NotImplementedError`` so an incomplete provider fails loudly rather than
    silently dropping messages.
    """

    def validate_credentials(self, account: Any) -> dict:
        """Probe the account credentials. Return a normalized status dict."""
        raise NotImplementedError

    def send_template_message(
        self,
        account: Any,
        *,
        recipient: str,
        template_name: str,
        language: str,
        variables: Any,
    ) -> dict:
        """Send an approved template message. Return ``{"provider_message_id": ...}``."""
        raise NotImplementedError

    def send_text_message(self, account: Any, *, recipient: str, body: str) -> dict:
        """Send a free-form text message (only valid inside an open session)."""
        raise NotImplementedError

    def health_check(self, account: Any) -> dict:
        """Lightweight liveness probe. Return ``{"ok": bool, "status": ...}``."""
        raise NotImplementedError

    def parse_webhook(self, payload: Any) -> list[dict]:
        """Normalize an inbound webhook payload into a list of event dicts."""
        raise NotImplementedError

    def normalize_error(self, http_status: int | None, body: Any) -> WhatsAppProviderError:
        """Classify a provider error response into a ``WhatsAppProviderError``."""
        raise NotImplementedError


# Meta error codes that are permanent for the given message/recipient/template
# and must NOT be retried (retrying just burns quota and re-fails).
_META_NON_RETRYABLE_CODES = {
    100,  # invalid parameter (bad recipient, malformed request)
    131008,  # required parameter missing
    131009,  # parameter value not valid
    131026,  # message undeliverable (e.g. recipient not on WhatsApp)
    131047,  # re-engagement message outside allowed window (needs template)
    131051,  # unsupported message type
    132000,  # template param count mismatch
    132001,  # template does not exist / not approved
    132005,  # template hydrated text too long
    132007,  # template format/policy violation
    132012,  # template parameter format mismatch
    132015,  # template paused
    132016,  # template disabled
    133010,  # phone number not registered
}

# Meta error codes that are transient (rate limit / throttling) — safe to retry
# with backoff even though the HTTP status may look like a generic error.
_META_RETRYABLE_CODES = {
    4,  # application request limit reached
    80007,  # rate limit issues
    130429,  # rate limit hit
    131048,  # spam rate limit hit (transient backoff)
    131056,  # (Business + recipient) pair rate limit hit
    133016,  # too many requests / temporary
}


class MetaCloudWhatsAppProvider(BaseWhatsAppProvider):
    """WhatsApp Business Cloud API provider (graph.facebook.com).

    Reads its base URL / API version / timeout from ``current_app.config`` at
    call time (lazy), so it can be instantiated without an app context and used
    later inside a request/worker context.
    """

    def __init__(self) -> None:
        # Nothing eager here: config is read lazily in ``_config`` so the
        # provider can be constructed outside an app context.
        pass

    # ----------------------------------------------------------------- config
    def _config(self) -> tuple[str, str, int]:
        cfg = current_app.config
        base = (cfg.get("WHATSAPP_GRAPH_BASE") or "https://graph.facebook.com").rstrip("/")
        version = (cfg.get("WHATSAPP_GRAPH_API_VERSION") or "v21.0").strip("/")
        try:
            timeout = int(cfg.get("WHATSAPP_HTTP_TIMEOUT_SECONDS") or 15)
        except (TypeError, ValueError):
            timeout = 15
        return base, version, timeout

    def _token(self, account: Any) -> str:
        """Decrypt the account access token. Raise if absent.

        The decrypted token is returned to the caller only to be used as an
        Authorization header inside ``_request``; it must never be logged.
        """
        encrypted = getattr(account, "access_token_encrypted", None)
        token = decrypt_secret(encrypted) if encrypted else ""
        if not token:
            raise WhatsAppProviderError("missing_token", "Access Token غير موجود.")
        return token

    def _phone_number_id(self, account: Any) -> str:
        pnid = (getattr(account, "phone_number_id", None) or "").strip()
        if not pnid:
            raise WhatsAppProviderError(
                "missing_phone_number_id", "معرّف رقم الهاتف غير مهيأ."
            )
        return pnid

    # ---------------------------------------------------------------- network
    def _request(
        self,
        method: str,
        path: str,
        token: str,
        *,
        json_body: dict | None = None,
        params: dict | None = None,
    ) -> tuple[int, dict]:
        """Perform a single Graph API call. THE only network access point.

        Returns ``(status_code, parsed_json)`` for 2xx responses. For non-2xx
        responses the Meta error JSON is parsed and handed to
        :meth:`normalize_error`, which raises. Connection/timeout problems raise
        a retryable ``meta_unreachable`` error.

        Kept intentionally small so tests monkeypatch this single method and
        never touch the network. NEVER logs the token, headers, or body.
        """
        base, version, timeout = self._config()
        url = f"{base}/{version}/{path.lstrip('/')}"
        if params:
            url = f"{url}?{urllib.parse.urlencode(params)}"

        data: bytes | None = None
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }
        if json_body is not None:
            data = json.dumps(json_body).encode("utf-8")
            headers["Content-Type"] = "application/json"

        req = urllib.request.Request(url, data=data, headers=headers, method=method.upper())

        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = int(getattr(resp, "status", None) or resp.getcode() or 0)
                raw = resp.read()
                parsed = self._parse_json(raw)
                if 200 <= status < 300:
                    return status, parsed
                # Defensive: urlopen normally raises HTTPError for non-2xx, but
                # handle the unusual success-object-with-error-status case too.
                raise self.normalize_error(status, parsed)
        except urllib.error.HTTPError as exc:
            # Meta returns its error payload in the HTTPError body.
            try:
                raw = exc.read()
            except Exception:  # pragma: no cover - body already consumed
                raw = b""
            parsed = self._parse_json(raw)
            raise self.normalize_error(exc.code, parsed) from None
        except (urllib.error.URLError, socket.timeout, TimeoutError, OSError):
            # DNS failure, refused connection, timeout, TLS error, etc.
            # Do NOT attach the underlying exception text: it can echo the URL
            # but, more importantly, we keep the surfaced message generic.
            raise WhatsAppProviderError(
                "meta_unreachable",
                "تعذّر الاتصال بخدمة Meta.",
                retryable=True,
            ) from None

    @staticmethod
    def _parse_json(raw: bytes | str | None) -> dict:
        if not raw:
            return {}
        if isinstance(raw, bytes):
            try:
                raw = raw.decode("utf-8")
            except UnicodeDecodeError:
                return {}
        try:
            value = json.loads(raw)
        except (ValueError, TypeError):
            return {}
        return value if isinstance(value, dict) else {"data": value}

    # --------------------------------------------------------------- send ops
    def send_template_message(
        self,
        account: Any,
        *,
        recipient: str,
        template_name: str,
        language: str,
        variables: Any = None,
    ) -> dict:
        token = self._token(account)
        phone_number_id = self._phone_number_id(account)

        template: dict[str, Any] = {
            "name": template_name,
            "language": {"code": language},
        }
        components = self._build_components(variables)
        if components:
            template["components"] = components

        body = {
            "messaging_product": "whatsapp",
            "to": recipient,
            "type": "template",
            "template": template,
        }
        _status, resp = self._request(
            "POST", f"{phone_number_id}/messages", token, json_body=body
        )
        return {"provider_message_id": self._extract_message_id(resp)}

    def send_text_message(self, account: Any, *, recipient: str, body: str) -> dict:
        token = self._token(account)
        phone_number_id = self._phone_number_id(account)

        payload = {
            "messaging_product": "whatsapp",
            "to": recipient,
            "type": "text",
            "text": {"body": body},
        }
        _status, resp = self._request(
            "POST", f"{phone_number_id}/messages", token, json_body=payload
        )
        return {"provider_message_id": self._extract_message_id(resp)}

    @staticmethod
    def _build_components(variables: Any) -> list[dict]:
        """Turn template variables into a Meta ``components`` list.

        Accepts either a positional ``list``/``tuple`` of values, or a ``dict``
        (values taken in insertion order). Produces a single body component
        whose parameters are ``{"type": "text", "text": "<value>"}``. Empty /
        ``None`` input yields no components (template has no variables).
        """
        if not variables:
            return []

        if isinstance(variables, dict):
            values = list(variables.values())
        elif isinstance(variables, (list, tuple)):
            values = list(variables)
        else:
            # A single scalar variable.
            values = [variables]

        parameters = [{"type": "text", "text": str(value)} for value in values]
        if not parameters:
            return []
        return [{"type": "body", "parameters": parameters}]

    @staticmethod
    def _extract_message_id(resp: dict) -> str | None:
        messages = resp.get("messages") if isinstance(resp, dict) else None
        if isinstance(messages, list) and messages:
            first = messages[0]
            if isinstance(first, dict):
                return first.get("id")
        return None

    # ---------------------------------------------------------- validate/health
    def validate_credentials(self, account: Any) -> dict:
        token = self._token(account)
        phone_number_id = self._phone_number_id(account)

        _status, resp = self._request(
            "GET",
            phone_number_id,
            token,
            params={
                "fields": "display_phone_number,verified_name,quality_rating,messaging_limit_tier"
            },
        )
        return {
            "ok": True,
            "display_phone_number": resp.get("display_phone_number"),
            "business_display_name": resp.get("verified_name"),
            "quality_rating": resp.get("quality_rating"),
            "messaging_limit_tier": resp.get("messaging_limit_tier"),
        }

    def health_check(self, account: Any) -> dict:
        """Lightweight liveness probe against the phone-number node.

        Returns ``{"ok": True, "status": "connected"}`` when reachable. On a
        provider error it returns ``{"ok": False, ...}`` rather than raising, so
        a health poller can record state without exception handling. The token
        is never included in the returned dict.
        """
        try:
            token = self._token(account)
            phone_number_id = self._phone_number_id(account)
        except Exception as exc:  # noqa: BLE001 — a liveness probe must never raise
            # Includes WhatsAppCryptoError when the stored token ciphertext is
            # corrupt/tampered; report misconfigured instead of propagating.
            return {"ok": False, "status": "misconfigured", "code": getattr(exc, "code", "config_error")}

        try:
            _status, resp = self._request(
                "GET", phone_number_id, token, params={"fields": "id"}
            )
        except WhatsAppProviderError as exc:
            return {
                "ok": False,
                "status": "unreachable" if exc.retryable else "error",
                "code": exc.code,
                "retryable": exc.retryable,
            }
        return {"ok": True, "status": "connected", "id": resp.get("id")}

    # -------------------------------------------------------------- webhooks
    def parse_webhook(self, payload: Any) -> list[dict]:
        """Normalize a Meta webhook payload into a flat list of events.

        Emits ``message_status`` events for delivery receipts and
        ``inbound_message`` events for incoming user messages. Tolerates any
        missing key and never raises: a payload it does not recognize yields
        ``[{"event_type": "unknown"}]``.
        """
        events: list[dict] = []
        try:
            entries = payload.get("entry") if isinstance(payload, dict) else None
            if not isinstance(entries, list):
                return [{"event_type": "unknown"}]

            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                changes = entry.get("changes")
                if not isinstance(changes, list):
                    continue
                for change in changes:
                    if not isinstance(change, dict):
                        continue
                    value = change.get("value")
                    if not isinstance(value, dict):
                        continue
                    events.extend(self._statuses_from_value(value))
                    events.extend(self._messages_from_value(value))
        except Exception:
            # Absolutely never raise on a malformed/unexpected payload.
            return [{"event_type": "unknown"}]

        if not events:
            return [{"event_type": "unknown"}]
        return events

    @staticmethod
    def _statuses_from_value(value: dict) -> list[dict]:
        out: list[dict] = []
        statuses = value.get("statuses")
        if not isinstance(statuses, list):
            return out
        for status in statuses:
            if not isinstance(status, dict):
                continue
            out.append(
                {
                    "event_type": "message_status",
                    "provider_message_id": status.get("id"),
                    "status": status.get("status"),
                    "recipient": status.get("recipient_id"),
                    "errors": status.get("errors"),
                }
            )
        return out

    @staticmethod
    def _messages_from_value(value: dict) -> list[dict]:
        out: list[dict] = []
        messages = value.get("messages")
        if not isinstance(messages, list):
            return out
        for message in messages:
            if not isinstance(message, dict):
                continue
            text_obj = message.get("text")
            text = text_obj.get("body") if isinstance(text_obj, dict) else None
            out.append(
                {
                    "event_type": "inbound_message",
                    "from": message.get("from"),
                    "provider_message_id": message.get("id"),
                    "type": message.get("type"),
                    "text": text,
                }
            )
        return out

    # ---------------------------------------------------------- error mapping
    def normalize_error(self, http_status: int | None, body: Any) -> WhatsAppProviderError:
        """Map an HTTP status + Meta error body to a classified error.

        Retryable: HTTP 429, any 5xx, or a Meta error code in the known
        transient set. Non-retryable: 400/401/403 and known permanent
        template/recipient errors. The surfaced ``message`` stays generic and
        Arabic-safe for non-admins; it never contains a token or the raw body.
        """
        status = http_status if isinstance(http_status, int) else None

        meta_code = None
        meta_subcode = None
        meta_detail = ""
        if isinstance(body, dict):
            error = body.get("error")
            if isinstance(error, dict):
                meta_code = error.get("code")
                meta_subcode = error.get("error_subcode")
                meta_detail = str(error.get("message") or "")

        # Normalize Meta code to int when possible for set membership.
        code_int = meta_code if isinstance(meta_code, int) else None
        if code_int is None and isinstance(meta_code, str) and meta_code.isdigit():
            code_int = int(meta_code)

        sub_int = meta_subcode if isinstance(meta_subcode, int) else None

        def _err(code: str, message: str, *, retryable: bool = False) -> WhatsAppProviderError:
            # Attach the raw Meta facts for admin diagnostics without leaking them
            # into the curated message/str.
            return WhatsAppProviderError(
                code, message, retryable=retryable, http_status=status,
                meta_code=code_int, meta_subcode=sub_int, meta_detail=meta_detail,
            )

        # 1) Explicit transient Meta codes win (rate limits) regardless of status.
        if code_int in _META_RETRYABLE_CODES:
            return _err("meta_rate_limited", "تم تجاوز حد الإرسال مؤقتًا، أعد المحاولة لاحقًا.", retryable=True)

        # 2) Explicit permanent Meta codes (bad template / recipient / params).
        if code_int in _META_NON_RETRYABLE_CODES:
            return _err("meta_request_invalid", "تعذّر إرسال الرسالة: الطلب أو القالب غير صالح.")

        # 3) Fall back to HTTP-status classification.
        if status == 429:
            return _err("meta_rate_limited", "تم تجاوز حد الإرسال مؤقتًا، أعد المحاولة لاحقًا.", retryable=True)
        if status is not None and 500 <= status < 600:
            return _err("meta_server_error", "خطأ مؤقت في خدمة Meta، أعد المحاولة لاحقًا.", retryable=True)
        if status in (401, 403):
            return _err("meta_auth_failed", "فشل التحقق من بيانات الاعتماد لدى Meta.")
        if status == 400:
            return _err("meta_request_invalid", "تعذّر إرسال الرسالة: الطلب غير صالح.")

        # 4) Anything else: treat 4xx as permanent, unknown/none as non-retryable.
        if status is not None and 400 <= status < 500:
            return _err("meta_request_invalid", "تعذّر إرسال الرسالة عبر Meta.")
        return _err("meta_error", "حدث خطأ أثناء الاتصال بخدمة Meta.")
