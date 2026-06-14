"""fix/chr-rest-wireguard-permission — REST read of wireguard peers.

LIVE blocker (after password auth converged): the panel's REST probe
`GET /rest/interface/wireguard/peers` returned HTTP 500
`{"detail":"std failure: not allowed (9)"}` — a RouterOS PERMISSION
denial (authenticated but unauthorized). The hobe-panel group
(`read,write,sensitive,reboot,rest-api`) lacked the `api` policy that
REST shares for reading the secret-bearing wireguard menu.

Two coordinated fixes:
  (a) GENERATOR §11 — grant the group the `api` policy. Safe: the binary
      api/api-ssl SERVICES stay disabled at /ip service, so the bit only
      governs the already-authenticated REST session.
  (b) PANEL — wg_verify requests only a non-secret `.proplist`
      (public-key/endpoint/handshake/rx/tx) so private/preshared keys
      never traverse REST (defense-in-depth), plus a single bounded
      retry on a transient post-import auth_failed (cert-swap race).
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from fleet.registry.script_render import (
    ChrKeyMaterial,
    RouterosTemplateConfig,
    render_chr_script,
)


# ════════════════════════════════════════════════════════════════════════
# Render helper
# ════════════════════════════════════════════════════════════════════════


@pytest.fixture()
def script() -> str:
    cfg = RouterosTemplateConfig(
        panel_wg_pubkey="P==", panel_wg_endpoint="panel.t", panel_wg_addr="10.99.0.1",
        proxy_wg_pubkey="X=", proxy_wg_endpoint="proxy.t", proxy_wg_addr="10.98.0.1",
        chr_shared_secret="s", sstp_cert_name="c", ike_cert_name="i",
        client_supernet="10.0.0.0/8", dns_push="1.1.1.1", gw_local_addr="10.0.0.1",
        api_user="hobe-panel", api_password="pw",
    )
    keys = ChrKeyMaterial(
        mgmt_privkey="M", mgmt_addr="10.99.0.12/24",
        data_privkey="D", data_addr="10.98.0.12/24", wan_iface="ether1",
    )
    return render_chr_script(
        SimpleNamespace(name="chr-vpn-2", public_ip="203.0.113.12"), keys, cfg,
    )


# ════════════════════════════════════════════════════════════════════════
# (a) Generator grants `api` policy; api/api-ssl SERVICES stay disabled
# ════════════════════════════════════════════════════════════════════════
class TestGroupPolicyGrantsApi:

    def test_both_branches_grant_api(self, script):
        # Both /user group add and set carry the api policy.
        assert script.count("policy=read,write,sensitive,reboot,rest-api,api") >= 2, (
            "group policy must grant `api` (REST shares the API permission "
            "layer; reading /interface/wireguard/peers over REST needs it)"
        )

    def test_binary_api_services_stay_disabled(self, script):
        """The safety guarantee is SERVICE-level: granting the api POLICY
        does not re-open the binary api/api-ssl ports."""
        assert ("set api     disabled=yes" in script
                or "set api disabled=yes" in script)
        assert "set api-ssl disabled=yes" in script


# ════════════════════════════════════════════════════════════════════════
# (b) Panel wireguard reads request a non-secret .proplist
# ════════════════════════════════════════════════════════════════════════
class TestProplistOnWireguardReads:

    def _client(self):
        from app.services.routeros_client import RouterOSClient
        return RouterOSClient(
            host="10.99.0.12", port=8443,
            username="hobe-panel", password="pw",
        )

    def test_list_peers_sends_proplist(self):
        c = self._client()
        captured = {}
        def _fake(method, path, *, params=None, body=None):
            captured["method"] = method
            captured["path"] = path
            captured["params"] = params
            return []
        c._request = _fake  # type: ignore[assignment]
        c.list_wireguard_peers(
            interface="wg-mgmt",
            proplist=["public-key", "last-handshake", "rx", "tx"],
        )
        pl = (captured["params"] or {}).get(".proplist", "")
        assert "public-key" in pl
        # Secret fields are NEVER requested.
        assert "private-key" not in pl
        assert "preshared-key" not in pl
        # interface kept so the client-side filter still works.
        assert "interface" in pl

    def test_find_interface_sends_proplist(self):
        c = self._client()
        captured = {}
        def _fake(method, path, *, params=None, body=None):
            captured["params"] = params
            return [{"name": "wg-mgmt", "public-key": "K="}]
        c._request = _fake  # type: ignore[assignment]
        c.find_wireguard_interface("wg-mgmt", proplist=["name", "public-key"])
        pl = (captured["params"] or {}).get(".proplist", "")
        assert "public-key" in pl
        assert "private-key" not in pl

    def test_no_proplist_keeps_bare_get(self):
        """Back-compat: omitting proplist sends no params (provisioning
        callers are unaffected)."""
        c = self._client()
        captured = {}
        def _fake(method, path, *, params=None, body=None):
            captured["params"] = params
            return []
        c._request = _fake  # type: ignore[assignment]
        c.list_wireguard_peers(interface="wg-mgmt")
        assert captured["params"] is None


# ════════════════════════════════════════════════════════════════════════
# (c) wg_verify requests non-secret fields + retries once on auth_failed
# ════════════════════════════════════════════════════════════════════════
class TestWgVerifyProplistAndRetry:

    def _node(self):
        return SimpleNamespace(
            id=1, name="chr-vpn-2", wg_mgmt_ip="10.99.0.12",
            wg_mgmt_pubkey="K" * 44, routeros_api_port=8443,
        )

    def test_verify_requests_non_secret_proplist(self, app, monkeypatch):
        """wg_verify must pass a proplist that excludes private/preshared
        keys to both wireguard reads."""
        with app.app_context():
            from fleet.health import wg_verify as wv
            monkeypatch.setattr(
                wv, "credentials_for",
                lambda node: {"host": "10.99.0.12", "port": 8443,
                              "user": "hobe-panel", "password": "pw"},
            )
            from fleet.registry import infra_settings
            monkeypatch.setattr(
                infra_settings, "panel_pubkey_for_display", lambda: "K" * 44,
            )
            seen = {"peers_proplist": None, "iface_proplist": None}

            class _FakeClient:
                def list_wireguard_peers(self, *, interface=None, proplist=None):
                    seen["peers_proplist"] = proplist
                    return [{"comment": "hobe-fleet-mgmt", "public-key": "K" * 44,
                             "last-handshake": "1s"}]
                def find_wireguard_interface(self, name, *, proplist=None):
                    seen["iface_proplist"] = proplist
                    return {"name": name, "public-key": "K" * 44}

            res = wv.verify_node_wg_identity(
                self._node(), client_factory=lambda **kw: _FakeClient(),
            )
            assert res.code == "ok", res.message_ar
            for pl in (seen["peers_proplist"], seen["iface_proplist"]):
                assert pl is not None
                assert "private-key" not in pl
                assert "preshared-key" not in pl
            assert "public-key" in seen["peers_proplist"]

    def test_verify_retries_once_on_auth_failed(self, app, monkeypatch):
        """A transient post-import auth_failed (cert-swap race) is retried
        once and then succeeds — no false-negative on the troubleshoot."""
        with app.app_context():
            from fleet.health import wg_verify as wv
            from app.services.routeros_client import RouterOSError
            monkeypatch.setattr(
                wv, "credentials_for",
                lambda node: {"host": "10.99.0.12", "port": 8443,
                              "user": "hobe-panel", "password": "pw"},
            )
            from fleet.registry import infra_settings
            monkeypatch.setattr(
                infra_settings, "panel_pubkey_for_display", lambda: "K" * 44,
            )
            monkeypatch.setattr(wv, "_default_factory", None, raising=False)
            # Avoid a real 1.2s sleep in the test.
            import time as _t
            monkeypatch.setattr(_t, "sleep", lambda *a, **k: None)

            calls = {"n": 0}

            class _FlakyClient:
                def list_wireguard_peers(self, *, interface=None, proplist=None):
                    calls["n"] += 1
                    if calls["n"] == 1:
                        raise RouterOSError("auth_failed", "auth", http_status=401)
                    return [{"comment": "hobe-fleet-mgmt", "public-key": "K" * 44,
                             "last-handshake": "1s"}]
                def find_wireguard_interface(self, name, *, proplist=None):
                    return {"name": name, "public-key": "K" * 44}

            res = wv.verify_node_wg_identity(
                self._node(), client_factory=lambda **kw: _FlakyClient(),
            )
            assert res.code == "ok", res.message_ar
            assert calls["n"] == 2, "must retry the read exactly once"

    def test_verify_does_not_retry_non_auth_errors(self, app, monkeypatch):
        """A permission error (the real live blocker) is NOT retried — it
        surfaces immediately so the operator sees the precise reason."""
        with app.app_context():
            from fleet.health import wg_verify as wv
            from app.services.routeros_client import RouterOSError
            monkeypatch.setattr(
                wv, "credentials_for",
                lambda node: {"host": "10.99.0.12", "port": 8443,
                              "user": "hobe-panel", "password": "pw"},
            )
            from fleet.registry import infra_settings
            monkeypatch.setattr(
                infra_settings, "panel_pubkey_for_display", lambda: "K" * 44,
            )
            calls = {"n": 0}

            class _DeniedClient:
                def list_wireguard_peers(self, *, interface=None, proplist=None):
                    calls["n"] += 1
                    raise RouterOSError(
                        "chr_server_error", "not allowed (9)",
                        http_status=500,
                        request_method="GET",
                        request_path="interface/wireguard/peers",
                        response_excerpt='{"detail":"std failure: not allowed (9)"}',
                    )
                def find_wireguard_interface(self, name, *, proplist=None):
                    return {}

            res = wv.verify_node_wg_identity(
                self._node(), client_factory=lambda **kw: _DeniedClient(),
            )
            assert res.code == "rest_failed"
            assert calls["n"] == 1, "permission errors must NOT be retried"
            assert "not allowed (9)" in res.message_ar
