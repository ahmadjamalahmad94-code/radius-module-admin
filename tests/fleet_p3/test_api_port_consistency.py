"""fix/api-service-port-consistency — single source of truth for the
REST-over-www-ssl transport port.

Owner's follow-up after the policy-fix: «وإذا بيحتاج اتصال api، ادمج
تفعيل بالسكربت مع ظبط البورت» — wire the transport WITH the port, not
just the granted policy. This file is the guard test.

The granted policy is ``rest-api`` (the login channel for HTTPS REST
over www-ssl). The unified script must:

  (a) ENABLE www-ssl on a specific port (one binding),
  (b) ASSIGN the cert (otherwise www-ssl can't bind),
  (c) ADD a firewall accept on the SAME port (scoped wg-mgmt + PANEL/32),
  (d) ALL three references — service ``set www-ssl port=``, firewall
      ``dst-port=``, and the panel's ``credentials_for(node)["port"]`` —
      must equal ONE value. No two-literals-that-drift.

  (e) Binary ``api`` and ``api-ssl`` (8728/8729) MUST stay DISABLED —
      the panel doesn't use them; granting ``api`` policy on the user
      would imply a binary login channel that's surface area we don't
      need. The granted policy ``rest-api`` aligns with the enabled
      www-ssl transport.

Pinned here:

* the service-set + firewall accept + node-row dial port are all
  ``8443`` (the single source of truth);
* the binding name ``API_PORT`` is used in BOTH the ``set www-ssl
  port=`` line AND the ``hobe-fleet-fw-api-ssl`` rule — text-grep
  asserts the Jinja substitution actually rendered to the same value;
* ``set api disabled=yes`` and ``set api-ssl disabled=yes`` are
  unconditional in the rendered script;
* the monitor's ``_resolve_target`` falls back to 8443 (NOT 8729 —
  the previous literal was vestigial drift, now fixed in the same
  commit).
"""
from __future__ import annotations

import re

import pytest

from app.extensions import db
from fleet.health.routeros_creds import credentials_for, set_credentials
from fleet.registry.models_chr import FleetChrNode, FleetProvider
from fleet.registry.onboarding_service import OnboardingService


#: The single value every port reference must equal.
EXPECTED_PORT = 8443


_BASE_CFG = {
    "PANEL_WG_PUBKEY": "PANEL_PUBKEY_BASE64_xxxxxxxxxxxxxxxxxxxxxxxx=",
    "PANEL_WG_ENDPOINT": "panel.example.com:51820",
    "PROXY_WG_PUBKEY": "PROXY_PUBKEY_BASE64_xxxxxxxxxxxxxxxxxxxxxxxx=",
    "PROXY_WG_ENDPOINT": "proxy.example.com:51821",
    "CHR_SHARED_SECRET": "central-shared-secret-from-panel-xxxxxxxx",
}


def _form(name: str = "chr-vpn-3") -> dict:
    return dict(
        name=name, provider="contabo-de", cost_model="open",
        public_ip="1.1.1.3", max_sessions=500, link_speed_mbps=1000,
        router_username="admin", router_password="admin12345",
    )


@pytest.fixture()
def provider_app(app):
    p = FleetProvider(name="contabo-de", cost_model="open", price_per_tb=0)
    db.session.add(p); db.session.commit()
    return app


def _render() -> tuple[str, FleetChrNode]:
    svc = OnboardingService(config=dict(_BASE_CFG))
    job = svc.create_draft(_form(), auto_advance=False)
    svc.generate_keys(job)
    _, script = svc.render_script(job)
    node = db.session.get(FleetChrNode, job.chr_id)
    return script, node


# ════════════════════════════════════════════════════════════════════════
# (a) — www-ssl ENABLED with the expected port + cert
# ════════════════════════════════════════════════════════════════════════
class TestWwwSslEnabled:

    def test_set_www_ssl_disabled_no(self, provider_app):
        script, _ = _render()
        flat = script.replace(" \\\n    ", " ")
        www_line = next(
            ln for ln in flat.splitlines()
            if ln.lstrip().startswith("set www-ssl disabled=no")
        )
        assert f"port={EXPECTED_PORT}" in www_line, www_line
        assert "certificate=hobe-fleet-api-cert" in www_line, www_line

    def test_cert_assigned_after_poll_wait(self, provider_app):
        """Defence in depth — the cert poll-wait from the chr-vpn-3
        unstick fix must still precede the set line, otherwise www-ssl
        can be set with an unsigned cert and silently fail to bind."""
        script, _ = _render()
        poll_idx = script.index(":local certReady false")
        www_idx = script.index("set www-ssl disabled=no")
        assert poll_idx < www_idx


# ════════════════════════════════════════════════════════════════════════
# (b/c) — firewall accept on the SAME port, scoped wg-mgmt + PANEL/32
# ════════════════════════════════════════════════════════════════════════
class TestFirewallAccept:

    def test_api_ssl_accept_uses_same_port(self, provider_app):
        script, _ = _render()
        flat = script.replace(" \\\n    ", " ")
        api_rule = next(
            ln for ln in flat.splitlines()
            if 'comment="hobe-fleet-fw-api-ssl"' in ln and ln.lstrip().startswith("add ")
        )
        assert f"dst-port={EXPECTED_PORT}" in api_rule, api_rule
        assert "in-interface=wg-mgmt" in api_rule, api_rule
        assert "protocol=tcp" in api_rule, api_rule
        # ACL: only the panel's wg-mgmt IP.
        assert "src-address=10.99.0.1/32" in api_rule, api_rule

    def test_api_ssl_accept_precedes_drop_last(self, provider_app):
        """place-before semantics — the rule must anchor against the
        catch-all drop, not land after it."""
        script, _ = _render()
        flat = script.replace(" \\\n    ", " ")
        api_rule = next(
            ln for ln in flat.splitlines()
            if 'comment="hobe-fleet-fw-api-ssl"' in ln and ln.lstrip().startswith("add ")
        )
        assert 'place-before=[find comment="hobe-fleet-fw-drop-last"]' in api_rule


# ════════════════════════════════════════════════════════════════════════
# (d) — single port: script == firewall == panel client
# ════════════════════════════════════════════════════════════════════════
class TestSinglePortSourceOfTruth:

    def test_script_set_port_equals_firewall_port(self, provider_app):
        """The two references inside the SAME script must agree."""
        script, _ = _render()
        # Extract `port=` from `set www-ssl ... port=N ...`
        set_match = re.search(r"set www-ssl disabled=no\s+port=(\d+)", script.replace(" \\\n    ", " "))
        assert set_match, "set www-ssl line missing port= value"
        set_port = int(set_match.group(1))
        # Extract `dst-port=` from `hobe-fleet-fw-api-ssl` rule
        fw_match = re.search(
            r'add chain=input[^\n]*?dst-port=(\d+)[^\n]*?comment="hobe-fleet-fw-api-ssl"',
            script.replace(" \\\n    ", " "),
        )
        assert fw_match, "api-ssl firewall rule missing dst-port"
        fw_port = int(fw_match.group(1))
        assert set_port == fw_port == EXPECTED_PORT

    def test_panel_client_dials_same_port(self, provider_app):
        """``credentials_for(node)`` is what the live-metrics poller +
        wg_verify use to build the REST client. The port it returns
        MUST equal the port the script just opened."""
        _, node = _render()
        creds = credentials_for(node)
        assert creds is not None
        assert creds["port"] == EXPECTED_PORT, (
            f"panel dials :{creds['port']} but script enables :{EXPECTED_PORT} "
            "— DRIFT will break REST."
        )

    def test_node_row_default_port_is_rest_not_binary(self, provider_app):
        """The model column default + the _build_bindings stamp must
        write 8443 (REST/www-ssl), NEVER 8728/8729 (binary api/api-ssl)."""
        _, node = _render()
        assert node.routeros_api_port == EXPECTED_PORT
        assert node.routeros_api_port not in (8728, 8729)


# ════════════════════════════════════════════════════════════════════════
# (e) — binary api/api-ssl explicitly DISABLED + rest-api policy matches
# ════════════════════════════════════════════════════════════════════════
class TestBinaryApiDisabled:

    def test_set_api_disabled_yes(self, provider_app):
        script, _ = _render()
        assert "set api     disabled=yes" in script or "set api disabled=yes" in script

    def test_set_api_ssl_disabled_yes(self, provider_app):
        script, _ = _render()
        assert "set api-ssl disabled=yes" in script

    def test_granted_policy_includes_rest_api_not_api(self, provider_app):
        """The granted policy must align with the ENABLED transport:
        ``rest-api`` (REST over www-ssl, what the panel dials), NOT
        ``api`` (the binary protocol we explicitly disable).

        feat/chr-group-idempotent-no-remove wraps the group provision
        in a find-len guard so both `/user group add` and
        `/user group set` carry the policy — we check both."""
        script, _ = _render()
        # Tolerant continuation join + strip comments so a doc comment
        # like `/user group add policy=` doesn't false-match.
        flat = re.sub(r" \\\n\s*", " ", script)
        text = "\n".join(
            ln for ln in flat.splitlines()
            if not ln.lstrip().startswith("#")
        )
        policies = re.findall(
            r"/user group (?:add|set) [^\n]*?policy=(\S+)", text,
        )
        assert policies, "no /user group add/set policy= line found"
        for policy_value in policies:
            granted = set(policy_value.split(","))
            assert "rest-api" in granted, granted
            assert "api" not in granted, granted


# ════════════════════════════════════════════════════════════════════════
# (f) — monitor fallback port is 8443 (NOT 8729) — drift guard
# ════════════════════════════════════════════════════════════════════════
class TestMonitorFallbackPort:
    """fix/api-service-port-consistency: ``fleet/health/monitor.py``
    used to fall back to 8729 (binary api-ssl) when ``node
    .routeros_api_port`` was None. The model column has a NOT NULL
    default of 8443 so the fallback never fires in practice, but the
    misleading 8729 literal invited drift. This test pins the new
    fallback at 8443.

    We exercise the fallback directly by calling _resolve_target with
    a node whose port we've forced to None (bypassing the column
    default)."""

    def test_resolve_target_fallback_is_rest_port(self, provider_app):
        from fleet.health.monitor import _resolve_target
        # Synthesise a node-like with port=None to force the fallback.
        class _FakeNode:
            id = 1
            name = "chr-x"
            wg_mgmt_ip = "10.99.0.99"
            public_ip = "1.2.3.4"
            routeros_api_port = None
        t = _resolve_target(_FakeNode())
        assert t.port == EXPECTED_PORT, (
            f"monitor fallback port must be {EXPECTED_PORT} (REST/www-ssl), "
            f"got {t.port} (a non-REST fallback is the drift this test guards "
            "against — see fix/api-service-port-consistency commit body)."
        )
