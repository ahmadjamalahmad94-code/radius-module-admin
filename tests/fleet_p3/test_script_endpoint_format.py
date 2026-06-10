"""fix/fleet-endpoint-and-idempotency — assert the rendered RouterOS script
emits WireGuard peer endpoints in the only shape MikroTik accepts:
host-only ``endpoint-address=<host>`` with a separate ``endpoint-port=<n>``.

The bug we're fixing: with ``endpoint-address=control.hoberadius.com:51820
endpoint-port=51820``, MikroTik silently rejects the colon-port inside
``endpoint-address``. The peer lands with ``current-endpoint-address=""``
and no handshake ever fires. Confirmed on the real router — fixing it to
``endpoint-address=control.hoberadius.com endpoint-port=51820`` brought
wg-data up instantly. This file locks in the correct shape so it can't
regress on a template edit.
"""
from __future__ import annotations

import re

import pytest

from fleet.registry.script_render import (
    _DEFAULT_ENDPOINT_PORTS,
    _split_endpoint,
    render_from_bindings,
)


_BASE = {
    "ROUTER_IDENTITY":    "chr-vpn-1",
    "CHR_PUBLIC_IP":      "178.105.244.112",
    "WAN_IFACE":          "ether1",
    "WG_MGMT_PRIVKEY":    "MGMT_PRIVKEY_BASE64==",
    "WG_MGMT_ADDR":       "10.99.0.11/32",
    "WG_DATA_PRIVKEY":    "DATA_PRIVKEY_BASE64==",
    "WG_DATA_ADDR":       "10.98.0.11/32",
    "WG_DATA_ADDR_IP":    "10.98.0.11",
    "PANEL_WG_PUBKEY":    "PANELPUBKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "PANEL_WG_ENDPOINT":  "control.hoberadius.com:51820",
    "PANEL_WG_ADDR":      "10.99.0.1",
    "PROXY_WG_PUBKEY":    "PROXYPUBKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQM=",
    "PROXY_WG_ENDPOINT":  "proxy.hoberadius.com:51821",
    "PROXY_WG_ADDR":      "10.98.0.1",
    "CHR_SHARED_SECRET":  "kla0FAzDKNJGoGIXdpDaCKB4Q2ytm-txZZZ_strongsecret",
    "SSTP_CERT_NAME":     "vpn-cert",
    "IKE_CERT_NAME":      "ike-cert",
    "CLIENT_SUPERNET":    "10.0.0.0/8",
    "DNS_PUSH":           "1.1.1.1",
    "GW_LOCAL_ADDR":      "10.10.0.1",
}


def _render(**overrides):
    return render_from_bindings({**_BASE, **overrides})


# ─── _split_endpoint — the single canonical parser ──────────────────────────

@pytest.mark.parametrize(
    "raw, default_port, expected_host, expected_port",
    [
        # combined host:port — the canonical Setting shape
        ("control.hoberadius.com:51820", 51820, "control.hoberadius.com", 51820),
        ("proxy.hoberadius.com:51821",   51821, "proxy.hoberadius.com",   51821),
        # operator typed a custom port — honored
        ("control.hoberadius.com:5555",  51820, "control.hoberadius.com", 5555),
        # host alone — falls back to per-plane default
        ("control.hoberadius.com",       51820, "control.hoberadius.com", 51820),
        ("proxy.hoberadius.com",         51821, "proxy.hoberadius.com",   51821),
        # bare IPv4
        ("178.105.180.6:51820",          51820, "178.105.180.6",          51820),
        ("178.105.180.6",                51820, "178.105.180.6",          51820),
        # bracketed IPv6 with port
        ("[2001:db8::1]:51820",          51820, "[2001:db8::1]",          51820),
        # bracketed IPv6 alone — port defaults
        ("[2001:db8::1]",                51820, "[2001:db8::1]",          51820),
    ],
)
def test_split_endpoint_canonical_cases(raw, default_port, expected_host, expected_port):
    host, port = _split_endpoint(raw, default_port=default_port)
    assert host == expected_host
    assert port == expected_port


# ─── the rendered .rsc must NEVER have a colon-port in endpoint-address ─────

def test_wg_mgmt_endpoint_address_has_no_colon_port():
    """The exact bug: ``endpoint-address=host:port`` is silently rejected."""
    script = _render(PANEL_WG_ENDPOINT="control.hoberadius.com:51820")
    flat = script.replace(" \\\n", " ")
    # Find the wg-mgmt peer line.
    line = next(l for l in flat.splitlines() if "add interface=wg-mgmt" in l)
    m = re.search(r"endpoint-address=(\S+)", line)
    assert m, f"no endpoint-address on wg-mgmt peer: {line!r}"
    addr = m.group(1)
    assert ":" not in addr, (
        f"endpoint-address contains a colon-port — MikroTik rejects this and "
        f"the handshake never fires: {addr!r}"
    )
    assert addr == "control.hoberadius.com"
    # And a separate endpoint-port carries the right value.
    m = re.search(r"endpoint-port=(\d+)", line)
    assert m and m.group(1) == "51820", line


def test_wg_data_endpoint_address_has_no_colon_port():
    script = _render(PROXY_WG_ENDPOINT="proxy.hoberadius.com:51821")
    flat = script.replace(" \\\n", " ")
    line = next(l for l in flat.splitlines() if "add interface=wg-data" in l)
    m = re.search(r"endpoint-address=(\S+)", line)
    assert m, f"no endpoint-address on wg-data peer: {line!r}"
    addr = m.group(1)
    assert ":" not in addr, f"colon-port leaked into endpoint-address: {addr!r}"
    assert addr == "proxy.hoberadius.com"
    m = re.search(r"endpoint-port=(\d+)", line)
    assert m and m.group(1) == "51821", line


def test_endpoint_address_no_colon_anywhere_in_rendered_script():
    """Belt-and-braces: across the WHOLE rendered .rsc, NO endpoint-address
    line may ever contain a colon. Catches a future template edit that
    accidentally re-introduces the combined form, regardless of which peer."""
    script = _render()
    flat = script.replace(" \\\n", " ")
    for lineno, line in enumerate(flat.splitlines(), start=1):
        for m in re.finditer(r"endpoint-address=(\S+)", line):
            addr = m.group(1)
            assert ":" not in addr, (
                f"L{lineno}: endpoint-address contains colon-port — "
                f"MikroTik will silently reject: {addr!r} (line: {line!r})"
            )


# ─── operator can type just a host — port defaults per plane ───────────────

def test_host_only_endpoint_uses_per_plane_default_port():
    """The infra-settings validator now accepts a bare ``host``; the renderer
    must back-fill the correct port per plane (51820 / 51821)."""
    script = _render(
        PANEL_WG_ENDPOINT="control.hoberadius.com",
        PROXY_WG_ENDPOINT="proxy.hoberadius.com",
    )
    flat = script.replace(" \\\n", " ")
    mgmt = next(l for l in flat.splitlines() if "add interface=wg-mgmt" in l)
    data = next(l for l in flat.splitlines() if "add interface=wg-data" in l)
    assert "endpoint-port=51820" in mgmt, mgmt
    assert "endpoint-port=51821" in data, data
    # And neither host carries a colon-port (re-asserted explicitly).
    assert "endpoint-address=control.hoberadius.com " in mgmt + " "
    assert "endpoint-address=proxy.hoberadius.com " in data + " "


def test_operator_custom_port_is_honored():
    """If the operator typed ``control.example.com:9999`` we use 9999, not the default."""
    script = _render(
        PANEL_WG_ENDPOINT="control.example.com:9999",
        PROXY_WG_ENDPOINT="proxy.example.com:8888",
    )
    flat = script.replace(" \\\n", " ")
    mgmt = next(l for l in flat.splitlines() if "add interface=wg-mgmt" in l)
    data = next(l for l in flat.splitlines() if "add interface=wg-data" in l)
    assert "endpoint-port=9999" in mgmt, mgmt
    assert "endpoint-port=8888" in data, data


# ─── per-plane default port constants stay in sync with template defaults ──

def test_default_endpoint_ports_match_template_listen_ports():
    """The renderer's per-plane default ports MUST equal the template's
    ``listen-port`` values. If the template ever bumps wg-mgmt to a new
    port, this constant has to move in lockstep — otherwise a host-only
    operator endpoint would land on the wrong port."""
    assert _DEFAULT_ENDPOINT_PORTS["PANEL_WG_ENDPOINT"] == 51820
    assert _DEFAULT_ENDPOINT_PORTS["PROXY_WG_ENDPOINT"] == 51821
    # Cross-check against the template itself.
    script = _render()
    assert "listen-port=51820" in script
    assert "listen-port=51821" in script
