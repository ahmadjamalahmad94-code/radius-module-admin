"""Tiny stdlib-urllib helper shared by the messaging adapters.

The project deliberately avoids ``requests`` (see whatsapp/providers.py for the
same rationale). Adapters use this thin wrapper instead of hitting urllib
directly so tests can monkeypatch a single function — see
``tests/unit/messaging/test_adapters.py``.

This is the ONLY place adapters touch the network. If you wire a real provider
later, do it by editing the adapter's prepared request payload and calling
:func:`post_json` — the wire format stays simple HTTP-JSON.
"""
from __future__ import annotations

import json
import socket
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


class HttpResult:
    __slots__ = ("status", "body", "error")

    def __init__(self, status: int, body: Any, error: str = "") -> None:
        self.status = status
        self.body = body
        self.error = error

    @property
    def ok(self) -> bool:
        return not self.error and 200 <= self.status < 300


def post_json(
    url: str,
    payload: dict | None = None,
    *,
    form: dict | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 15.0,
) -> HttpResult:
    """POST to ``url`` and return a structured result.

    Pass exactly one of ``payload`` (JSON body) or ``form`` (urlencoded body).
    Never raises on a network / non-2xx response — the caller sees ``error``
    populated or ``status >= 400``. Body is parsed as JSON when the response
    declares it (else returned as ``str``).
    """
    headers = dict(headers or {})
    if form is not None and payload is not None:
        raise ValueError("post_json: pass either payload or form, not both")
    if form is not None:
        data = urllib.parse.urlencode(form).encode("utf-8")
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    else:
        data = json.dumps(payload or {}).encode("utf-8")
        headers.setdefault("Content-Type", "application/json")
    headers.setdefault("Accept", "application/json")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            status = resp.getcode()
            ctype = (resp.headers.get("Content-Type") or "").lower()
    except urllib.error.HTTPError as exc:
        raw = exc.read() if hasattr(exc, "read") else b""
        status = exc.code
        ctype = (exc.headers.get("Content-Type") or "").lower() if exc.headers else ""
    except (urllib.error.URLError, socket.timeout, ConnectionError) as exc:
        return HttpResult(0, None, error=str(exc) or exc.__class__.__name__)

    body: Any
    text = raw.decode("utf-8", "replace") if raw else ""
    if "json" in ctype and text:
        try:
            body = json.loads(text)
        except ValueError:
            body = text
    else:
        body = text
    return HttpResult(status, body)


def get_json(
    url: str,
    *,
    params: dict | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 15.0,
) -> HttpResult:
    """GET helper used by lightweight liveness probes."""
    if params:
        sep = "&" if "?" in url else "?"
        url = url + sep + urllib.parse.urlencode(params)
    headers = dict(headers or {})
    headers.setdefault("Accept", "application/json")
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            status = resp.getcode()
            ctype = (resp.headers.get("Content-Type") or "").lower()
    except urllib.error.HTTPError as exc:
        raw = exc.read() if hasattr(exc, "read") else b""
        status = exc.code
        ctype = (exc.headers.get("Content-Type") or "").lower() if exc.headers else ""
    except (urllib.error.URLError, socket.timeout, ConnectionError) as exc:
        return HttpResult(0, None, error=str(exc) or exc.__class__.__name__)

    body: Any
    text = raw.decode("utf-8", "replace") if raw else ""
    if "json" in ctype and text:
        try:
            body = json.loads(text)
        except ValueError:
            body = text
    else:
        body = text
    return HttpResult(status, body)
