"""Tiny HTTP helper used only by the payment-gateway adapters.

Mirrors ``app/services/messaging/adapters/_http.py`` (project convention) so
that each adapter has a single, well-bounded network seam and every test can
stub one function (``post_json`` / ``get_json``) to fake the provider.

NEVER log full request bodies — they may carry HMAC signatures derived from
the api_secret. We log only the URL host/path and the HTTP status code.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

log = logging.getLogger("payment_gateways._http")


@dataclass(frozen=True)
class HttpResult:
    ok: bool = False
    status: int = 0
    body: Any = None
    error: str = ""
    meta: dict[str, Any] = field(default_factory=dict)


def _log_url(url: str, status: int, kind: str) -> None:
    try:
        u = urlparse(url)
        log.info("payment_gateway %s %s://%s%s -> %s", kind, u.scheme, u.netloc, u.path, status)
    except Exception:  # noqa: BLE001
        log.info("payment_gateway %s ? -> %s", kind, status)


def post_json(url: str, *, payload: dict[str, Any], headers: dict[str, str] | None = None,
              timeout: float = 15.0) -> HttpResult:
    """POST a JSON payload, return a uniform :class:`HttpResult`.

    Adapters call this once. To unit-test an adapter without network access,
    monkeypatch ``payment_gateways._http.post_json``.
    """
    try:
        data = json.dumps(payload).encode("utf-8")
        req = Request(url, data=data, headers={**(headers or {}), "Content-Type": "application/json"},
                      method="POST")
        with urlopen(req, timeout=timeout) as resp:  # noqa: S310 — adapter-owned URLs
            status = int(resp.status)
            raw = resp.read()
            body: Any
            try:
                body = json.loads(raw.decode("utf-8") or "{}")
            except json.JSONDecodeError:
                body = {"_raw": raw.decode("utf-8", errors="replace")}
            _log_url(url, status, "POST")
            return HttpResult(ok=200 <= status < 300, status=status, body=body)
    except HTTPError as e:
        _log_url(url, int(e.code or 0), "POST")
        return HttpResult(ok=False, status=int(e.code or 0), error=str(e.reason))
    except URLError as e:
        _log_url(url, 0, "POST")
        return HttpResult(ok=False, status=0, error=str(e.reason))
    except Exception as e:  # noqa: BLE001
        _log_url(url, 0, "POST")
        return HttpResult(ok=False, status=0, error=type(e).__name__)


def get_json(url: str, *, headers: dict[str, str] | None = None,
             timeout: float = 15.0) -> HttpResult:
    try:
        req = Request(url, headers={**(headers or {})}, method="GET")
        with urlopen(req, timeout=timeout) as resp:  # noqa: S310
            status = int(resp.status)
            raw = resp.read()
            try:
                body = json.loads(raw.decode("utf-8") or "{}")
            except json.JSONDecodeError:
                body = {"_raw": raw.decode("utf-8", errors="replace")}
            _log_url(url, status, "GET")
            return HttpResult(ok=200 <= status < 300, status=status, body=body)
    except HTTPError as e:
        _log_url(url, int(e.code or 0), "GET")
        return HttpResult(ok=False, status=int(e.code or 0), error=str(e.reason))
    except URLError as e:
        _log_url(url, 0, "GET")
        return HttpResult(ok=False, status=0, error=str(e.reason))
    except Exception as e:  # noqa: BLE001
        _log_url(url, 0, "GET")
        return HttpResult(ok=False, status=0, error=type(e).__name__)


__all__ = ["HttpResult", "post_json", "get_json"]
