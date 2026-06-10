"""Phase 10 — security sweep: every /api/proxy/* fleet endpoint MUST
require X-Proxy-Token, and no secret may ever appear in plaintext in any
panel-side response or recorded state.

The canonical endpoint list is :func:`fleet.hardening.fleet_proxy_endpoints` —
adding an endpoint there is the only way to participate in the sweep. This
test then enforces, for every row:

* No ``X-Proxy-Token`` header → response status ∈ {401, 403, 404}. The
  4xx codes are accepted because the panel may choose ``404`` for an
  unknown sub-resource before the auth gate runs (as long as the endpoint
  never leaks data), and ``403`` is a legitimate auth-rejection code. The
  positive invariant is "no 2xx body without auth".
* Body never contains the words ``"ok": true`` (sanity-check that no
  fleet content was leaked).

Secret-redaction checks:

* Cloudflare API token loaded into a :class:`_RedactedToken` never
  appears in its repr / str.
* :func:`fleet.dns.cloudflare.apply_desired_state` output — even when
  errors fire — never contains the plaintext token.
* The proxy shared secret (`RADIUS_PROXY_SHARED_SECRET`) never appears
  in the routing-table response (it's a server-side secret for auth,
  not for transmission).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import time

import pytest

from app.extensions import db

from fleet.hardening import FleetEndpoint, fleet_proxy_endpoints


# ════════════════════════════════════════════════════════════════════════
# 1. Auth sweep
# ════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize("endpoint", fleet_proxy_endpoints(),
                         ids=lambda e: f"{e.method}_{e.path}")
def test_endpoint_rejects_request_without_proxy_token(app, client, endpoint):
    """No header → MUST NOT return 2xx or expose fleet data."""
    fn = client.get if endpoint.method == "GET" else client.post
    # Send a syntactically valid JSON body for POSTs so a 400 (validation)
    # never masks an auth bypass.
    kwargs = {}
    if endpoint.method == "POST":
        kwargs = {"data": json.dumps({}), "content_type": "application/json"}
    r = fn(endpoint.path, **kwargs)
    assert r.status_code in (401, 403), (
        f"{endpoint.method} {endpoint.path} returned {r.status_code} "
        f"without X-Proxy-Token (must be 401/403)"
    )
    # And the body must not carry fleet content.
    body = (r.get_data(as_text=True) or "").lower()
    assert '"ok": true' not in body
    assert '"ok":true' not in body


@pytest.mark.parametrize("endpoint", fleet_proxy_endpoints(),
                         ids=lambda e: f"{e.method}_{e.path}")
def test_endpoint_rejects_tampered_token(app, client, endpoint):
    """A token with valid SHAPE but wrong HMAC also gets 401."""
    fake = f"{int(time.time())}:nonce-bad-mac:{'0'*64}"
    fn = client.get if endpoint.method == "GET" else client.post
    kwargs = {"headers": {"X-Proxy-Token": fake}}
    if endpoint.method == "POST":
        kwargs.update(data=json.dumps({}), content_type="application/json")
    r = fn(endpoint.path, **kwargs)
    assert r.status_code in (401, 403), (
        f"{endpoint.method} {endpoint.path} accepted a bad HMAC (got "
        f"{r.status_code})"
    )


# ════════════════════════════════════════════════════════════════════════
# 2. Secret redaction
# ════════════════════════════════════════════════════════════════════════


_TOKEN_SENTINEL = "cf_p10_TOKEN_must_not_leak_xyz123"


def test_cloudflare_redacted_token_repr_safe():
    from fleet.dns.cloudflare import _RedactedToken
    t = _RedactedToken(_TOKEN_SENTINEL)
    assert _TOKEN_SENTINEL not in repr(t)
    assert _TOKEN_SENTINEL not in str(t)
    # `.reveal()` is the only path back to plaintext.
    assert t.reveal() == _TOKEN_SENTINEL
    assert bool(_RedactedToken("")) is False
    assert bool(t) is True


def test_routing_table_response_does_not_leak_proxy_shared_secret(app, client):
    """The proxy_shared_secret is used to *verify* the X-Proxy-Token. It
    must NEVER appear in any /api/proxy/routing-table response field."""
    app.config["RADIUS_PROXY_SHARED_SECRET"] = "proxy-shared-secret-sentinel-12345"
    token = _valid_token(app)
    r = client.get("/api/proxy/routing-table",
                   headers={"X-Proxy-Token": token})
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "proxy-shared-secret-sentinel-12345" not in body


def test_apply_desired_state_dry_run_does_not_contain_token(app):
    """Even on the dry-run path, the cloudflare driver must not surface
    the token in any IntendedCall body / ApplyResult.snapshot / errors."""
    from fleet.dns.cloudflare import (
        DesiredOrigin, MODE_FREE, apply_desired_state, _RedactedToken,
    )
    import fleet.dns.cloudflare as cf_mod

    # Stub the token loader so the test runs without the vault.
    orig = cf_mod._load_token
    cf_mod._load_token = lambda _cfg: _RedactedToken(_TOKEN_SENTINEL)
    try:
        result = apply_desired_state(
            [DesiredOrigin(node="chr-A", ip="203.0.113.10", weight=1.0, included=True)],
            mode=MODE_FREE,
            dry_run=True,
        )
    finally:
        cf_mod._load_token = orig

    rendered = " ".join([
        repr(result.calls_planned), repr(result.calls_executed),
        repr(result.errors), repr(result.snapshot),
    ])
    assert _TOKEN_SENTINEL not in rendered


# ════════════════════════════════════════════════════════════════════════
# Helpers
# ════════════════════════════════════════════════════════════════════════


def _valid_token(app) -> str:
    secret = app.config["RADIUS_PROXY_SHARED_SECRET"]
    ts = int(time.time())
    nonce = f"p10-secret-{ts}-{id(app)}"
    msg = f"{ts}:{nonce}"
    mac = hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()
    return f"{ts}:{nonce}:{mac}"
