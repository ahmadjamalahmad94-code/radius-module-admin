"""feat/chr-sstp-enduser (M1) — role-gated SSTP server + dedicated cert.

SSTP was the one end-user VPN gap: the block was gated on a cert NAME the
script never created, so in production (SSTP_CERT_NAME empty) SSTP never
rendered. M1 makes vpn_sstp self-sufficient:

  * vpn_sstp ON, no custom cert → AUTO-CREATE a dedicated self-signed
    `hobe-sstp-cert` (CN = CHR public IP), poll-wait, enable the SSTP
    server with it, open the firewall port. The cert is SEPARATE from
    hobe-fleet-api-cert (which is bound to www-ssl/wg-mgmt and scoped to
    PANEL/32 — never reuse it for a public listener).
  * vpn_sstp ON, SSTP_CERT_NAME set → use that cert verbatim, skip the
    auto-create (operator brought a real cert).
  * vpn_sstp OFF → server disabled, no cert, no firewall port.

RADIUS service=ppp already covers SSTP logins (asserted by the existing
RADIUS block); SSTP end-users authenticate through the proxy.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from fleet.registry.script_render import (
    ChrKeyMaterial,
    RouterosTemplateConfig,
    build_bindings,
    render_from_bindings,
)

_ALL = ["radius_transport", "vpn_sstp", "vpn_pptp", "vpn_ipsec", "vpn_wireguard"]


def _cfg(sstp_cert_name: str = "") -> RouterosTemplateConfig:
    return RouterosTemplateConfig(
        panel_wg_pubkey="P==", panel_wg_endpoint="p.t", panel_wg_addr="10.99.0.1",
        proxy_wg_pubkey="X=", proxy_wg_endpoint="x.t", proxy_wg_addr="10.98.0.1",
        chr_shared_secret="s", sstp_cert_name=sstp_cert_name, ike_cert_name="",
        client_supernet="10.0.0.0/8", dns_push="1.1.1.1", gw_local_addr="10.0.0.1",
        api_user="hobe-panel", api_password="pw",
    )


def _render(roles, *, sstp_cert_name: str = "") -> str:
    cfg = _cfg(sstp_cert_name)
    keys = ChrKeyMaterial(
        mgmt_privkey="M", mgmt_addr="10.99.0.12/24",
        data_privkey="D", data_addr="10.98.0.12/24", wan_iface="ether1",
    )
    node = SimpleNamespace(name="chr-vpn-2", public_ip="178.105.180.6")
    b = build_bindings(node, keys, cfg)
    b["NODE_ROLES_SET"] = frozenset(roles)
    return render_from_bindings(b)


# ════════════════════════════════════════════════════════════════════════
# (1) vpn_sstp ON, default (auto self-signed cert)
# ════════════════════════════════════════════════════════════════════════
class TestSstpAutoCert:

    def test_block_renders_with_dedicated_cert(self):
        s = _render(_ALL)
        # Dedicated cert created (NOT hobe-fleet-api-cert).
        assert "add name=hobe-sstp-cert" in s
        assert 'common-name="178.105.180.6"' in s
        assert "key-usage=digital-signature,key-encipherment,tls-server" in s
        # Self-signed: `sign hobe-sstp-cert` with NO ca=.
        assert "sign hobe-sstp-cert\n" in s
        assert "sign hobe-sstp-cert ca=" not in s
        # Poll-wait guard present.
        assert "sstpCertReady" in s
        # Server enabled with that cert.
        assert "/interface sstp-server server" in s
        assert "set enabled=yes port=443 authentication=mschap2" in s
        assert "certificate=hobe-sstp-cert" in s
        assert "tls-version=only-1.2" in s
        assert "default-profile=" in s

    def test_does_not_reuse_www_ssl_cert_for_sstp(self):
        s = _render(_ALL)
        # The sstp-server block must reference hobe-sstp-cert, never the
        # www-ssl/wg-mgmt cert. Flatten line-continuations first (the
        # `set` line wraps across `\`-newlines).
        import re
        flat = re.sub(r" \\\n\s*", " ", s)
        m = re.search(r"/interface sstp-server server\nset [^\n]*", flat)
        assert m, "sstp-server set line not found"
        assert "certificate=hobe-sstp-cert" in m.group(0)
        assert "certificate=hobe-fleet-api-cert" not in m.group(0)

    def test_firewall_opens_sstp_port(self):
        s = _render(_ALL)
        assert "hobe-fleet-fw-sstp" in s
        assert "protocol=tcp dst-port=443" in s

    def test_ascii_only(self):
        s = _render(_ALL)
        assert sum(1 for c in s if ord(c) > 127) == 0


# ════════════════════════════════════════════════════════════════════════
# (2) vpn_sstp ON, operator-supplied cert → use it, skip auto-create
# ════════════════════════════════════════════════════════════════════════
class TestSstpCustomCert:

    def test_uses_custom_cert_and_skips_autocreate(self):
        s = _render(_ALL, sstp_cert_name="my-letsencrypt-cert")
        assert "certificate=my-letsencrypt-cert" in s
        # No auto-create when a custom cert is configured.
        assert "add name=hobe-sstp-cert" not in s
        assert "sstpCertReady" not in s
        # Server still enabled + firewall still open.
        assert "set enabled=yes port=443" in s
        assert "hobe-fleet-fw-sstp" in s


# ════════════════════════════════════════════════════════════════════════
# (3) vpn_sstp OFF → disabled, no cert, no firewall port
# ════════════════════════════════════════════════════════════════════════
class TestSstpDisabled:

    def test_role_off_disables_server_and_omits_cert(self):
        s = _render([r for r in _ALL if r != "vpn_sstp"])
        assert "/interface sstp-server server\nset enabled=no" in s
        assert "add name=hobe-sstp-cert" not in s
        assert "sstpCertReady" not in s
        # Firewall SSTP accept omitted.
        assert "hobe-fleet-fw-sstp" not in s

    def test_radius_still_covers_ppp(self):
        """SSTP logins authenticate via RADIUS service=ppp — confirm the
        RADIUS client + ppp aaa are still emitted (unchanged by M1)."""
        s = _render(_ALL)
        assert "add service=ppp address=10.98.0.1" in s
        assert "set use-radius=yes" in s
