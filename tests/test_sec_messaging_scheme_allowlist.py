"""SEC M4 — the shared messaging HTTP helper only speaks http(s).

The SMS adapter forwards an admin-configured ``base_url`` straight into
``_http.post_json``. urllib's default opener also handles file://, ftp://,
gopher:// … so without a scheme allowlist that config field is an arbitrary
local-file read / internal-request primitive. The guard must reject any
non-http(s) URL BEFORE touching the network or filesystem.
"""
from __future__ import annotations

import pytest

from app.services.messaging.adapters import _http


# file:// would be an arbitrary local-file read; the others are SSRF-amplifiers.
BLOCKED = [
    "file:///etc/passwd",
    "file://localhost/etc/hostname",
    "ftp://internal-host/secret",
    "gopher://169.254.169.254/",
    "//no-scheme-host/path",
    "",
]


def _explode(*a, **k):  # pragma: no cover - must never be reached
    raise AssertionError("urlopen must not be called for a blocked scheme")


@pytest.mark.parametrize("url", BLOCKED)
def test_post_json_blocks_non_http_scheme(url, monkeypatch):
    # If the guard fails open, this stub turns the leak into a loud failure.
    monkeypatch.setattr(_http.urllib.request, "urlopen", _explode)
    res = _http.post_json(url, payload={"x": 1})
    assert res.ok is False
    assert res.status == 0
    assert "scheme" in res.error


@pytest.mark.parametrize("url", BLOCKED)
def test_get_json_blocks_non_http_scheme(url, monkeypatch):
    monkeypatch.setattr(_http.urllib.request, "urlopen", _explode)
    res = _http.get_json(url)
    assert res.ok is False
    assert res.status == 0
    assert "scheme" in res.error


def test_http_and_https_still_reach_the_opener(monkeypatch):
    """A legitimate https gateway URL passes the guard and dials the opener."""
    seen = {}

    class _Resp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return b'{"ok": true}'
        def getcode(self): return 200
        headers = {"Content-Type": "application/json"}

    def _fake_urlopen(req, timeout=None):
        seen["url"] = req.full_url if hasattr(req, "full_url") else req
        return _Resp()

    monkeypatch.setattr(_http.urllib.request, "urlopen", _fake_urlopen)
    res = _http.post_json("https://sms.example.com/send", payload={"m": "hi"})
    assert res.ok is True
    assert seen["url"].startswith("https://sms.example.com")
