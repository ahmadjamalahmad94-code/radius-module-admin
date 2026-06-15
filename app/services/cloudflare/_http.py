"""Tiny HTTP seam for the Cloudflare DNS client.

Mirrors ``app/services/payment_gateways/_http.py`` (project convention) so the
Cloudflare client has a single, well-bounded network seam. Every test stubs one
of these four functions to fake the Cloudflare API — no real network in CI.

Cloudflare's v4 API uses Bearer-token auth and wraps every response in a
``{"success": bool, "errors": [...], "result": ...}`` envelope; parsing that
envelope is the client's job (``client.py``), not this module's. Here we only
move bytes and return a uniform :class:`HttpResult`.

NEVER log request bodies or the Authorization header — the token is a secret.
We log only the method, host + path, and the HTTP status code.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

log = logging.getLogger("cloudflare._http")


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
        log.info("cloudflare %s %s://%s%s -> %s", kind, u.scheme, u.netloc, u.path, status)
    except Exception:  # noqa: BLE001
        log.info("cloudflare %s ? -> %s", kind, status)


def _request(method: str, url: str, *, payload: dict[str, Any] | None,
             headers: dict[str, str] | None, timeout: float) -> HttpResult:
    """Shared request core for all verbs — keeps error handling in one place."""
    try:
        data = None
        merged = {**(headers or {})}
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            merged["Content-Type"] = "application/json"
        req = Request(url, data=data, headers=merged, method=method)
        with urlopen(req, timeout=timeout) as resp:  # noqa: S310 — client-owned URLs
            status = int(resp.status)
            raw = resp.read()
            try:
                body = json.loads(raw.decode("utf-8") or "{}")
            except json.JSONDecodeError:
                body = {"_raw": raw.decode("utf-8", errors="replace")}
            _log_url(url, status, method)
            return HttpResult(ok=200 <= status < 300, status=status, body=body)
    except HTTPError as e:
        # Cloudflare returns a JSON envelope even on 4xx — surface it so the
        # client can read the error code (e.g. token scope problems).
        body: Any = None
        try:
            body = json.loads((e.read() or b"").decode("utf-8") or "{}")
        except Exception:  # noqa: BLE001
            body = None
        _log_url(url, int(e.code or 0), method)
        return HttpResult(ok=False, status=int(e.code or 0), body=body, error=str(e.reason))
    except URLError as e:
        _log_url(url, 0, method)
        return HttpResult(ok=False, status=0, error=str(e.reason))
    except Exception as e:  # noqa: BLE001
        _log_url(url, 0, method)
        return HttpResult(ok=False, status=0, error=type(e).__name__)


def get_json(url: str, *, headers: dict[str, str] | None = None,
             timeout: float = 15.0) -> HttpResult:
    return _request("GET", url, payload=None, headers=headers, timeout=timeout)


def post_json(url: str, *, payload: dict[str, Any], headers: dict[str, str] | None = None,
              timeout: float = 15.0) -> HttpResult:
    return _request("POST", url, payload=payload, headers=headers, timeout=timeout)


def put_json(url: str, *, payload: dict[str, Any], headers: dict[str, str] | None = None,
             timeout: float = 15.0) -> HttpResult:
    return _request("PUT", url, payload=payload, headers=headers, timeout=timeout)


def delete_json(url: str, *, headers: dict[str, str] | None = None,
                timeout: float = 15.0) -> HttpResult:
    return _request("DELETE", url, payload=None, headers=headers, timeout=timeout)


__all__ = ["HttpResult", "get_json", "post_json", "put_json", "delete_json"]
