"""feat/data-connection-panel (2b) — version-aware client-script generator.

Pins the customer-MikroTik .rsc for SSTP + PPTP × RouterOS v6 + v7:
  * server target = the VPS subdomain (NEVER a CHR/panel IP);
  * SSTP carries verify-server-certificate=yes (real LE cert ⇒ no CA
    import) on both versions;
  * NO CHR/proxy references in the output;
  * ASCII-clean; the connection name lands as the interface name + comment.
"""
from __future__ import annotations

import pytest

from app.services.data_connection_script import (
    DataConnectionScriptError,
    render_client_rsc,
)

_KW = dict(server="client5.hoberadius.com", username="sub_ahmad",
           password="s3cr3t-pw", name="ahmad-data")


def _render(**over):
    return render_client_rsc(**{**_KW, **over})


# ════════════════════════════════════════════════════════════════════════
# Matrix: SSTP/PPTP × v6/v7
# ════════════════════════════════════════════════════════════════════════
@pytest.mark.parametrize("protocol", ["sstp", "pptp"])
@pytest.mark.parametrize("ver", ["6", "7"])
class TestMatrix:

    def test_ascii_clean(self, protocol, ver):
        s = _render(protocol=protocol, ros_version=ver)
        assert sum(1 for c in s if ord(c) > 127) == 0

    def test_targets_vps_subdomain_not_chr_or_panel(self, protocol, ver):
        s = _render(protocol=protocol, ros_version=ver)
        assert "connect-to=client5.hoberadius.com" in s
        # No CHR/proxy/fleet IPs or hostnames leak into the client script.
        for bad in ("10.99.", "10.98.", "10.51.", "proxy", "chr-", "wg-mgmt", "wg-data"):
            assert bad not in s, f"{bad!r} must not appear in a direct-to-VPS script"

    def test_credentials_and_name(self, protocol, ver):
        s = _render(protocol=protocol, ros_version=ver)
        assert 'user="sub_ahmad"' in s
        assert 'password="s3cr3t-pw"' in s
        # name as interface name AND comment (the «name as comment» need).
        assert 'name="ahmad-data"' in s
        assert 'comment="ahmad-data"' in s

    def test_right_interface_menu(self, protocol, ver):
        s = _render(protocol=protocol, ros_version=ver)
        assert f"/interface {protocol}-client" in s


# ════════════════════════════════════════════════════════════════════════
# SSTP specifics
# ════════════════════════════════════════════════════════════════════════
class TestSstp:

    def test_verify_cert_on_both_versions(self):
        for ver in ("6", "7"):
            s = _render(protocol="sstp", ros_version=ver)
            assert "verify-server-certificate=yes" in s, ver

    def test_v7_has_tls_version_v6_does_not(self):
        assert "tls-version=only-1.2" in _render(protocol="sstp", ros_version="7")
        assert "tls-version" not in _render(protocol="sstp", ros_version="6")

    def test_custom_port(self):
        s = _render(protocol="sstp", ros_version="7", sstp_port=8443)
        assert "port=8443" in s

    def test_default_port_443(self):
        assert "port=443" in _render(protocol="sstp", ros_version="6")


# ════════════════════════════════════════════════════════════════════════
# PPTP specifics
# ════════════════════════════════════════════════════════════════════════
class TestPptp:

    def test_profile_default_encryption_both_versions(self):
        for ver in ("6", "7"):
            assert "profile=default-encryption" in _render(protocol="pptp", ros_version=ver)

    def test_no_tls_or_cert_in_pptp(self):
        s = _render(protocol="pptp", ros_version="7")
        assert "verify-server-certificate" not in s
        assert "tls-version" not in s


# ════════════════════════════════════════════════════════════════════════
# Validation + hygiene
# ════════════════════════════════════════════════════════════════════════
class TestValidation:

    def test_bad_protocol(self):
        with pytest.raises(DataConnectionScriptError):
            _render(protocol="l2tp", ros_version="6")

    def test_bad_version(self):
        with pytest.raises(DataConnectionScriptError):
            _render(protocol="sstp", ros_version="5")

    def test_rejects_quote_injection_in_creds(self):
        with pytest.raises(DataConnectionScriptError):
            _render(protocol="sstp", ros_version="7", password='a" bad')

    def test_name_sanitized(self):
        s = _render(protocol="sstp", ros_version="7", name="ahmad data!@#")
        assert 'name="ahmad-data"' in s and "!" not in s

    def test_add_default_route_toggle(self):
        on = _render(protocol="sstp", ros_version="7", add_default_route=True)
        off = _render(protocol="sstp", ros_version="7", add_default_route=False)
        assert "add-default-route=yes" in on
        assert "add-default-route=no" in off
