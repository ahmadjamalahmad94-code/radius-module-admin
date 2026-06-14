"""fix/chr-rest-500-and-api-auth — actionable REST error envelope.

Live blocker (resolved here): the panel's wg-mgmt verify call on
chr-vpn-2 surfaced ::

    rest_failed: تعذّر القراءة عبر REST -- خطأ داخلي في CHR --
    Internal Server Error

The operator could not tell WHICH endpoint failed, with WHAT status,
nor what RouterOS actually said in the body. Two-pronged fix:

1. ``RouterOSClient._request`` + ``_http_error`` thread the HTTP method
   + REST path through into ``RouterOSError`` (new fields
   ``request_method`` / ``request_path`` / ``response_excerpt``).
2. ``wg_verify.verify_node_wg_identity`` assembles a precise verdict
   that names the endpoint, the HTTP status, the underlying code, and a
   truncated CHR-side body excerpt.

Plus a robustness fix to the two calls wg_verify itself makes:
``find_wireguard_interface`` and ``list_wireguard_peers`` now fetch the
bare list + filter client-side, because at least some RouterOS v7
builds return HTTP 500 on the ``?name=X`` / ``?interface=X`` server-
side filter (which was the actual on-device cause of the live 500).

These tests pin both:
  * the RouterOSError carries the path + status + body excerpt;
  * the wg_verify Arabic verdict names the endpoint + status + excerpt;
  * find_wireguard_interface + list_wireguard_peers fetch-all-then-
    filter (no server-side ?filter query string).
"""
from __future__ import annotations

import io
import json
import urllib.error

import pytest

from app.services.routeros_client import RouterOSClient, RouterOSError
from fleet.health.wg_verify import verify_node_wg_identity
from fleet.registry.models_chr import FleetChrNode


# ════════════════════════════════════════════════════════════════════════
# Helpers
# ════════════════════════════════════════════════════════════════════════


def _node(**over) -> FleetChrNode:
    n = FleetChrNode()
    n.name = over.get("name", "chr-rest-500")
    n.wg_mgmt_ip = over.get("wg_mgmt_ip", "10.99.0.99")
    n.wg_mgmt_pubkey = over.get("wg_mgmt_pubkey", "CHRKEY=")
    n.routeros_api_user = over.get("user", "")
    n.routeros_api_password_enc = over.get("password_enc", "")
    n.routeros_api_port = over.get("port", 8443)
    return n


@pytest.fixture()
def _wg_env(app, monkeypatch):
    """Same env shape as the existing wg_verify tests."""
    with app.app_context():
        monkeypatch.setattr(
            "fleet.registry.infra_settings.panel_pubkey_for_display",
            lambda: "PANELKEY=",
        )
        monkeypatch.setattr(
            "fleet.health.wg_verify.credentials_for",
            lambda node: {
                "host": node.wg_mgmt_ip, "port": 8443,
                "user": "hobe-panel", "password": "pw",
            },
        )
        yield


# ════════════════════════════════════════════════════════════════════════
# (1) RouterOSError carries the endpoint label + status + body excerpt
# ════════════════════════════════════════════════════════════════════════
class TestRouterOSErrorCarriesContext:

    def test_endpoint_label_compact(self):
        e = RouterOSError(
            "chr_server_error", "خطأ داخلي في CHR.",
            http_status=500,
            request_method="GET", request_path="interface/wireguard?name=wg-mgmt",
        )
        assert e.endpoint_label() == "GET /rest/interface/wireguard?name=wg-mgmt"

    def test_endpoint_label_empty_when_unset(self):
        e = RouterOSError("connect_failed", "تعذّر الاتصال.")
        assert e.endpoint_label() == ""

    def test_response_excerpt_capped_at_160_chars(self):
        e = RouterOSError(
            "chr_server_error", "خطأ داخلي.",
            response_excerpt="X" * 500,
        )
        assert len(e.response_excerpt) == 160
        assert e.response_excerpt == "X" * 160


# ════════════════════════════════════════════════════════════════════════
# (2) _http_error builds an error with method+path+excerpt populated
# ════════════════════════════════════════════════════════════════════════
class TestHttpErrorWrapsContext:

    def _http_500_with_body(self, body_text: str) -> urllib.error.HTTPError:
        """Build a real urllib HTTPError carrying a JSON body."""
        return urllib.error.HTTPError(
            url="https://10.99.0.99:8443/rest/interface/wireguard?name=wg-mgmt",
            code=500, msg="Internal Server Error",
            hdrs={},  # type: ignore[arg-type]
            fp=io.BytesIO(body_text.encode("utf-8")),
        )

    def test_500_carries_endpoint_and_excerpt(self):
        c = RouterOSClient(host="10.99.0.99", username="u", password="p")
        body = json.dumps({"detail": "Internal Server Error"})
        err = c._http_error(
            self._http_500_with_body(body),
            method="GET",
            path="interface/wireguard?name=wg-mgmt",
        )
        assert err.code == "chr_server_error"
        assert err.http_status == 500
        assert err.request_method == "GET"
        assert err.request_path == "interface/wireguard?name=wg-mgmt"
        # The truncated body excerpt is preserved so the operator
        # sees what RouterOS actually said.
        assert "Internal Server Error" in err.response_excerpt
        # The Arabic message names the endpoint compactly.
        assert "GET /rest/interface/wireguard" in err.message

    def test_401_carries_endpoint(self):
        c = RouterOSClient(host="10.99.0.99", username="u", password="p")
        err = c._http_error(
            urllib.error.HTTPError(
                url="https://h/rest/system/resource", code=401,
                msg="Unauthorized", hdrs={}, fp=io.BytesIO(b"unauth"),
            ),
            method="GET", path="system/resource",
        )
        assert err.code == "auth_failed"
        assert err.http_status == 401
        assert err.endpoint_label() == "GET /rest/system/resource"


# ════════════════════════════════════════════════════════════════════════
# (3) wg_verify surfaces endpoint + status in the Arabic verdict
# ════════════════════════════════════════════════════════════════════════
class TestWgVerifyMessageIsActionable:

    def test_500_with_endpoint_is_named(self, app, _wg_env):
        """The exact live failure shape — RouterOS REST 500 from one of
        the two wg_verify calls. The verdict must point at the endpoint
        + status + body excerpt, not just say «Internal Server Error»."""

        class _FailingClient:
            def list_wireguard_peers(self, *, interface=None, proplist=None):
                raise RouterOSError(
                    "chr_server_error",
                    "خطأ داخلي في CHR — Internal Server Error — "
                    "GET /rest/interface/wireguard/peers?interface=wg-mgmt.",
                    http_status=500,
                    request_method="GET",
                    request_path="interface/wireguard/peers?interface=wg-mgmt",
                    response_excerpt='{"detail":"Internal Server Error"}',
                )

            def find_wireguard_interface(self, name, *, proplist=None):
                return {"name": name, "public-key": "X"}

        r = verify_node_wg_identity(
            _node(), client_factory=lambda **kw: _FailingClient(),
        )
        assert not r.ok
        assert r.code == "rest_failed"
        # Endpoint named.
        assert "/rest/interface/wireguard/peers" in r.message_ar, (
            f"endpoint missing from verdict: {r.message_ar!r}"
        )
        # HTTP status named.
        assert "HTTP 500" in r.message_ar, (
            f"status missing from verdict: {r.message_ar!r}"
        )
        # Body excerpt named (the operator can see what RouterOS said).
        assert "Internal Server Error" in r.message_ar
        # Underlying code surfaced for log / grep.
        assert "chr_server_error" in r.message_ar


# ════════════════════════════════════════════════════════════════════════
# (4) find_wireguard_interface + list_wireguard_peers no longer rely on
#     RouterOS server-side ?filter — they fetch all + filter client-side
# ════════════════════════════════════════════════════════════════════════
class TestNoServerSideFilter:

    def test_find_wireguard_interface_uses_bare_list_endpoint(self, monkeypatch):
        """Pre-fix this called `GET interface/wireguard?name=X` which
        500s on at least some RouterOS v7 builds (the live CHR was one).
        The new shape calls the bare endpoint and filters client-side."""
        calls = []
        def fake_request(self, method, path, *, params=None, body=None):
            calls.append((method, path, params))
            return [
                {"name": "wg-users", "public-key": "U"},
                {"name": "wg-mgmt", "public-key": "M"},
            ]
        monkeypatch.setattr(RouterOSClient, "_request", fake_request)
        c = RouterOSClient(host="h", username="u", password="p")
        r = c.find_wireguard_interface("wg-mgmt")
        assert r == {"name": "wg-mgmt", "public-key": "M"}
        # The single REST call had NO `?name=` filter.
        assert calls == [("GET", "interface/wireguard", None)], calls

    def test_list_wireguard_peers_filters_client_side(self, monkeypatch):
        """Same treatment for the peers endpoint."""
        calls = []
        def fake_request(self, method, path, *, params=None, body=None):
            calls.append((method, path, params))
            return [
                {"interface": "wg-mgmt", "public-key": "A"},
                {"interface": "wg-users", "public-key": "B"},
                {"interface": "wg-mgmt", "public-key": "C"},
            ]
        monkeypatch.setattr(RouterOSClient, "_request", fake_request)
        c = RouterOSClient(host="h", username="u", password="p")
        peers = c.list_wireguard_peers(interface="wg-mgmt")
        assert [p["public-key"] for p in peers] == ["A", "C"]
        # The single REST call had NO `?interface=` filter.
        assert calls == [("GET", "interface/wireguard/peers", None)], calls

    def test_find_returns_none_when_no_match(self, monkeypatch):
        def fake_request(self, method, path, *, params=None, body=None):
            return [{"name": "wg-users"}]
        monkeypatch.setattr(RouterOSClient, "_request", fake_request)
        c = RouterOSClient(host="h", username="u", password="p")
        assert c.find_wireguard_interface("wg-mgmt") is None
