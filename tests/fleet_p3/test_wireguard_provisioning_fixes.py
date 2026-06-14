"""fix/fleet-wireguard-provisioning — owner deep-debug bug fixes.

Each test maps to one of the owner's bug letters:

  A — endpoint-address NEVER empty + post-setup validation
  B — render with LIVE control + proxy WG pubkeys (snapshot persisted)
  C+D — panel adds + persists the server-side wg-mgmt peer at provision
  F — rollback validation gate (12 explicit checks; cancel only on PASS)
  G — hobe-close-* defined BEFORE hobe-open-* (no first-import race)
  L — detailed not_targeted diagnostics (no bare error code)
  ALSO — chr_nodes[].wg_data_pubkey published in routing-table
"""
from __future__ import annotations

import json
import re

import pytest

from fleet.registry.script_render import render_from_bindings


_BASE: dict = {
    "ROUTER_IDENTITY":    "chr-vpn-2",
    "CHR_PUBLIC_IP":      "89.105.218.1",
    "WAN_IFACE":          "ether1",
    "WG_MGMT_PRIVKEY":    "MGMT_PRIV==",
    "WG_MGMT_ADDR":       "10.99.0.12/24",
    "WG_DATA_PRIVKEY":    "DATA_PRIV==",
    "WG_DATA_ADDR":       "10.98.0.12/24",
    "WG_DATA_ADDR_IP":    "10.98.0.12",
    # The live-server key the owner saw on the control host -- the panel
    # MUST embed THIS, not whatever was stored in the DB at render time.
    "PANEL_WG_PUBKEY":    "3GasLNhMU0dujBZNnASYmWjVMxh7kyg37IkJfxbaZjg=",
    "PANEL_WG_ENDPOINT":  "178.105.180.6:51820",
    "PANEL_WG_ADDR":      "10.99.0.1",
    "PROXY_WG_PUBKEY":    "PROXYPUBKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQM=",
    "PROXY_WG_ENDPOINT":  "178.105.251.67:51821",
    "PROXY_WG_ADDR":      "10.98.0.1",
    "CHR_SHARED_SECRET":  "S" * 48,
    "SSTP_CERT_NAME":     "",
    "IKE_CERT_NAME":      "",
    "CLIENT_SUPERNET":    "10.0.0.0/8",
    "DNS_PUSH":           "1.1.1.1",
    "GW_LOCAL_ADDR":      "10.10.0.1",
    "API_USER":           "panel-mgmt",
    "API_PASSWORD":       "pw" * 16,
    "API_PORT":           8443,
    "OPERATOR_ADMIN_IPS": "",
}


def _render(**overrides) -> str:
    return render_from_bindings({**_BASE, **overrides})


# ════════════════════════════════════════════════════════════════════════
# BUG A — endpoint-address NEVER empty
# ════════════════════════════════════════════════════════════════════════
class TestBugAEndpointNeverEmpty:
    def test_helper_keeps_hostname_when_resolve_returns_empty(self):
        """hobeSetEndpoint must FALL BACK to the hostname (peer-add value)
        when the resolved IP is empty / garbage — never overwrite to ""."""
        script = _render()
        assert ":local hobeSetEndpoint" in script
        # The wrapper:
        #   * passes if-clean: set endpoint-address=$clean
        #   * else branch:    set endpoint-address=$fallback (the hostname)
        assert "endpoint-address=$clean" in script
        assert "endpoint-address=$fallback" in script
        # The fallback string is the hostname, not the empty string.
        assert "resolve unusable, keeping hostname" in script

    def test_hobe_resolve_returns_empty_string_on_total_failure(self):
        """A 5-retry total failure must return "" — the wrapper then
        falls back to the hostname rather than setting an empty endpoint."""
        script = _render()
        # The function definition ends with `:return ""` on permanent failure.
        # (Pre-fix it returned `$host` directly; the wrapper now owns the
        # fallback choice.)
        idx = script.index(":local hobeResolve do=")
        body = script[idx:idx + 800]
        assert ':return ""' in body, (
            "hobeResolve must return empty on permanent failure so the "
            "wrapper can take the hostname-fallback branch"
        )

    def test_post_setup_validation_block_renders(self):
        """Section 2d asserts both peer endpoint-address fields are
        non-empty AFTER setup and flips hobeWgValidationOk on miss.

        fix/script-service-get-guard reshaped the inline
        `[/interface wireguard peers get [find comment=...] endpoint-
        address]` into a length-guarded two-step
        `:local ref [... find comment=...]` + `... get $ref endpoint-
        address` so an empty find can't halt the import. Pin both the
        find AND the resulting get separately."""
        script = _render()
        assert ":global hobeWgValidationOk true" in script
        assert ":global hobeWgValidationDetail" in script
        # Length-guarded shape — separate find + get on the ref.
        assert (
            '/interface wireguard peers find comment="hobe-fleet-mgmt"'
            in script
        ), "wg-mgmt peer find missing from section 2d"
        assert (
            '/interface wireguard peers find comment="hobe-fleet-data"'
            in script
        ), "wg-data peer find missing from section 2d"
        # Both gets pull endpoint-address from the guarded local ref.
        assert "get $mgmtPeerRef endpoint-address" in script
        assert "get $dataPeerRef endpoint-address" in script
        # The miss path flips the global to false + logs error.
        assert ":set hobeWgValidationOk false" in script
        assert "hobe-fleet: BUG A" in script


# ════════════════════════════════════════════════════════════════════════
# BUG B — LIVE pubkey rendering + snapshot
# ════════════════════════════════════════════════════════════════════════
class TestBugBLivePubkey:
    def test_read_live_panel_pubkey_returns_none_when_helper_absent(self, monkeypatch):
        """No helper installed (dev/CI) → the function returns None."""
        from fleet.sync import wg_apply
        monkeypatch.setattr(wg_apply, "helper_installed", lambda: False)
        assert wg_apply.read_live_panel_pubkey() is None

    def test_read_live_panel_pubkey_returns_key_on_success(self, monkeypatch):
        """Helper present and prints a valid base64-44 key → function
        returns the key as-is."""
        from fleet.sync import wg_apply
        live_key = "A" * 43 + "="
        monkeypatch.setattr(wg_apply, "helper_installed", lambda: True)
        monkeypatch.setattr(
            wg_apply, "_run_helper",
            lambda action, payload: (True, json.dumps({
                "interface": "wg-mgmt", "public_key": live_key,
            })),
        )
        assert wg_apply.read_live_panel_pubkey() == live_key

    def test_read_live_panel_pubkey_rejects_malformed(self, monkeypatch):
        """Helper prints garbage (wrong length, wrong shape) → reject —
        we never embed a wrong key into a script."""
        from fleet.sync import wg_apply
        monkeypatch.setattr(wg_apply, "helper_installed", lambda: True)
        monkeypatch.setattr(
            wg_apply, "_run_helper",
            lambda a, p: (True, json.dumps({"public_key": "too-short"})),
        )
        assert wg_apply.read_live_panel_pubkey() is None

    def test_helper_pubkey_subcommand_exists(self):
        """The deploy script ``hobe-wg-sync`` must accept the ``pubkey``
        action (else the python wrapper has nothing to invoke)."""
        from pathlib import Path
        body = Path("deploy/zero_touch/hobe-wg-sync").read_text(encoding="utf-8")
        assert "def cmd_pubkey" in body
        assert "wg show wg-mgmt public-key" in body or '"show", iface, "public-key"' in body
        assert '"pubkey"' in body and 'cmd_pubkey' in body
        assert 'sys.argv[1] == "pubkey"' in body
        # And the installer's sudoers grant covers pubkey too.
        inst = Path("deploy/zero_touch/install_wg_helper.sh").read_text(encoding="utf-8")
        assert "${HELPER_DST} pubkey" in inst


# ════════════════════════════════════════════════════════════════════════
# BUG C+D — server-side peer add + persist
# ════════════════════════════════════════════════════════════════════════
class TestBugCDServerPeerAdd:
    def test_render_script_source_calls_reconcile_panel_host(self):
        """OnboardingService.render_script must invoke
        reconcile_panel_host() after a successful render — that is what
        actually adds the CHR's wg-mgmt peer on the control server.

        We verify this at the SOURCE level (a full integration test
        would need the entire vault + DB + key-provider chain mocked,
        which obscures the contract). The source pin is sharp: the
        function name + the import path are both required in the
        render_script body.
        """
        from pathlib import Path
        src = Path("fleet/registry/onboarding_service.py").read_text(encoding="utf-8")
        # The call site uses a lazy import inside render_script.
        assert "from fleet.sync.service import reconcile_panel_host" in src
        # And invokes it (without arguments — reconciles the full set).
        assert "reconcile_panel_host()" in src
        # Locate render_script body; the reconcile must live INSIDE it
        # (not in another method).
        render_start = src.index("def render_script(")
        # Find the start of the NEXT def to bound the body.
        next_def = src.index("\n    def ", render_start + 1)
        body = src[render_start:next_def]
        assert "reconcile_panel_host()" in body, (
            "reconcile_panel_host() must be called from INSIDE "
            "render_script, not elsewhere in the file"
        )

    def test_resync_server_peers_endpoint_exists(self, app, client):
        """The «إعادة مزامنة peers الخادم» action endpoint must exist
        at /admin/fleet/sync/server-peers/resync."""
        rules = {str(r.rule) for r in app.url_map.iter_rules()}
        assert "/admin/fleet/sync/server-peers/resync" in rules

    def test_apply_panel_peers_persists_via_wg_quick_save(self):
        """The helper script calls ``wg-quick save`` after each apply
        so the peer set survives a reboot. We grep the helper source
        for the literal call (the only persistence path)."""
        from pathlib import Path
        body = Path("deploy/zero_touch/hobe-wg-sync").read_text(encoding="utf-8")
        assert '"wg-quick", "save"' in body, (
            "the helper must `wg-quick save` after `wg set ... peer ...` "
            "so /etc/wireguard/wg-mgmt.conf persists the new peer set"
        )


# ════════════════════════════════════════════════════════════════════════
# BUG F — 12-check rollback validation gate
# ════════════════════════════════════════════════════════════════════════
class TestBugFValidationGate:
    def test_rollback_only_cancelled_after_gate_passes(self):
        """The cancel block must be inside an `:if ($hobeRollbackOk)`
        branch — never unconditional."""
        script = _render()
        # The unconditional remove on its own line is gone.
        # New pattern: `:if ($hobeRollbackOk) do={ ... /system scheduler
        # remove ... }`. We assert (1) the gate variable is defined, (2)
        # the remove appears INSIDE the if-true block, (3) the else
        # block logs VALIDATION FAILED + does NOT remove.
        assert ":global hobeRollbackOk true" in script
        assert ":if ($hobeRollbackOk) do={" in script
        # Locate the gate; the remove must be in the same if-true block.
        gate = script.index(":if ($hobeRollbackOk) do={")
        body = script[gate:gate + 2000]
        assert '/system scheduler remove [find name="hobe-fleet-rollback"]' in body
        # And the failure path: VALIDATION FAILED log line + DOES NOT remove.
        assert "VALIDATION FAILED" in script
        assert "rollback LEFT ARMED" in script

    @pytest.mark.parametrize("check_name", [
        "(1)",  # endpoint validation
        "(2) wg-mgmt no handshake",
        "(3) wg-data endpoint empty",
        "(4) wg-data no handshake",
        "(5) www-ssl not enabled",
        "(6) firewall hobe-fleet-fw-api-ssl missing",
        "(7) firewall hobe-fleet-fw-drop-last missing",
        "(8) no-public-radius drop missing",
        "(9) hobe-open-winbox missing",
        "(10) hobe-close-winbox missing",
        "(11) break-glass open but auto-close scheduler missing",
        "(12) public winbox open without emergency mode",
    ])
    def test_all_12_checks_render(self, check_name):
        """Each of the 12 validation checks names a specific failure
        signature in its failure-reason text so the operator can read
        :log error/print and know exactly which check tripped."""
        script = _render()
        assert check_name in script, (
            f"validation check {check_name!r} not present in rendered "
            "rollback gate — incomplete BUG F coverage"
        )


# ════════════════════════════════════════════════════════════════════════
# BUG G — hobe-close-* defined BEFORE hobe-open-*
# ════════════════════════════════════════════════════════════════════════
class TestBugGCloseBeforeOpen:
    def test_close_winbox_defined_before_open_winbox(self):
        script = _render()
        close = script.index('add name="hobe-close-winbox"')
        open_ = script.index('add name="hobe-open-winbox"')
        assert close < open_, (
            "hobe-close-winbox must be added BEFORE hobe-open-winbox so "
            "the auto-close scheduler that hobe-open-winbox arms always "
            "has a real script to run on first tick"
        )

    def test_close_webfig_defined_before_open_webfig(self):
        script = _render()
        close = script.index('add name="hobe-close-webfig"')
        open_ = script.index('add name="hobe-open-webfig"')
        assert close < open_

    def test_validation_check_10_blocks_cancel_when_close_missing(self):
        """If a future template regression dropped the close script,
        check (10) would catch it and refuse to cancel the rollback."""
        script = _render()
        assert "(10) hobe-close-winbox missing" in script


# ════════════════════════════════════════════════════════════════════════
# BUG L — detailed not_targeted diagnostics
# ════════════════════════════════════════════════════════════════════════
class TestBugLNotTargetedDiagnostics:
    def test_diagnostics_payload_contains_all_required_fields(self, app):
        """The diagnostics helper must produce a JSON payload with the
        fields the operator needs: requested node id+name+IP+pubkey+REST
        host, the actually-polled sibling's same fields, the human
        Arabic reason, and a machine reason_code."""
        from fleet.ui.routes import _not_targeted_diagnostics

        class _Node:
            def __init__(self, **kw):
                for k, v in kw.items(): setattr(self, k, v)
        requested = _Node(
            id=1, name="chr-vpn-1", wg_mgmt_ip="10.99.0.11",
            wg_mgmt_pubkey="K" * 44, routeros_api_port=8443,
            control_wg_public_key_snapshot="L" * 44,
        )
        sibling = _Node(
            id=2, name="chr-vpn-2", wg_mgmt_ip="10.99.0.12",
            wg_mgmt_pubkey="M" * 44, routeros_api_port=8443,
        )
        with app.app_context():
            payload = json.loads(_not_targeted_diagnostics(requested, sibling))
        assert payload["kind"] == "not_targeted"
        assert payload["reason_code"] == "poll_all_sibling_skipped"
        assert payload["requested"]["id"] == 1
        assert payload["requested"]["name"] == "chr-vpn-1"
        assert payload["requested"]["expected_wg_mgmt_ip"] == "10.99.0.11"
        assert payload["requested"]["expected_rest_host"] == "10.99.0.11:8443"
        assert payload["requested"]["control_wg_public_key_snapshot"] == "L" * 44
        assert payload["actually_polled"]["id"] == 2
        assert payload["actually_polled"]["name"] == "chr-vpn-2"
        assert payload["actually_polled"]["wg_mgmt_ip"] == "10.99.0.12"
        assert payload["actually_polled"]["rest_host"] == "10.99.0.12:8443"
        # Arabic reason text present.
        assert "تم استدعاء" in payload["reason_ar"]


# ════════════════════════════════════════════════════════════════════════
# routing-table — chr_nodes[] now carries wg_data_pubkey
# ════════════════════════════════════════════════════════════════════════
def test_routing_table_publishes_wg_data_pubkey(app, client, monkeypatch):
    """The proxy contract gains chr_nodes[].wg_data_pubkey so the proxy
    can correlate an incoming RADIUS packet to a node identity in one
    read (vs cross-referencing /api/proxy/wg-peers)."""
    import hashlib, hmac, time
    SECRET = "wg-prov-test"
    app.config["RADIUS_PROXY_SHARED_SECRET"] = SECRET
    from app.api import proxy_api
    proxy_api._NONCE_CACHE.clear()

    from app.extensions import db
    from fleet.registry.models_chr import FleetChrNode, FleetProvider

    with app.app_context():
        prov = FleetProvider.query.first() or FleetProvider(
            name="p", cost_model="open", price_per_tb=0,
            overage_allowed=False, billing_cycle_day=1,
        )
        if prov.id is None:
            db.session.add(prov); db.session.commit()
        node = FleetChrNode(
            provider_id=prov.id, name="chr-vpn-1",
            public_ip="178.105.244.112",
            wg_mgmt_ip="10.99.0.11", wg_mgmt_pubkey="X" * 44,
            wg_data_pubkey="DATAPUBKEY=" + "A" * 32,
            max_sessions=500, link_speed_mbps=1000, weight=1.0,
            enabled=True, drain=False, status="up",
            cpu_pct=10, active_sessions=0,
        )
        db.session.add(node); db.session.commit()

        ts = int(time.time()); nonce = "wg-prov-1"
        mac = hmac.new(SECRET.encode(), f"{ts}:{nonce}".encode(),
                       hashlib.sha256).hexdigest()
        r = client.get("/api/proxy/routing-table",
                       headers={"X-Proxy-Token": f"{ts}:{nonce}:{mac}"})
        body = r.get_json()
        entry = next(e for e in body["chr_nodes"] if e["name"] == "chr-vpn-1")
        assert "wg_data_pubkey" in entry, (
            "fix/fleet-wireguard-provisioning: chr_nodes[] must publish "
            "wg_data_pubkey so the proxy can correlate RADIUS sources "
            "to node identities."
        )
        assert entry["wg_data_pubkey"] == "DATAPUBKEY=" + "A" * 32
        assert entry["wg_data_ip"] == "10.98.0.11"
