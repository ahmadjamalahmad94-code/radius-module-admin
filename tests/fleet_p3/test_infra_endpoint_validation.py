"""fix/fleet-endpoint-and-idempotency — assert the infra-settings endpoint
validator (the UI input that produces PANEL_WG_ENDPOINT / PROXY_WG_ENDPOINT)
accepts ``host`` or ``host:port`` and REJECTS anything that would later let
a ``:port`` leak into ``endpoint-address`` on the rendered .rsc.
"""
from __future__ import annotations

import pytest

from fleet.registry.infra_settings import InfraSettingsError, split_endpoint


# ─── happy path: host:port — the canonical Setting shape ────────────────────

@pytest.mark.parametrize(
    "raw, expected_host, expected_port",
    [
        ("control.hoberadius.com:51820", "control.hoberadius.com", 51820),
        ("proxy.hoberadius.com:51821",   "proxy.hoberadius.com",   51821),
        ("178.105.180.6:51820",          "178.105.180.6",          51820),
        # bracketed IPv6 with port
        ("[2001:db8::1]:51820",          "[2001:db8::1]",          51820),
        # operator-chosen high port
        ("control.example.com:65535",    "control.example.com",    65535),
    ],
)
def test_split_endpoint_accepts_host_colon_port(raw, expected_host, expected_port):
    host, port = split_endpoint(raw, default_port=51820)
    assert host == expected_host
    assert port == expected_port


# ─── host alone — falls back to the per-plane default port ─────────────────

@pytest.mark.parametrize(
    "raw, default_port, expected_host, expected_port",
    [
        ("control.hoberadius.com", 51820, "control.hoberadius.com", 51820),
        ("proxy.hoberadius.com",   51821, "proxy.hoberadius.com",   51821),
        ("178.105.180.6",          51820, "178.105.180.6",          51820),
        ("[2001:db8::1]",          51820, "[2001:db8::1]",          51820),
    ],
)
def test_split_endpoint_accepts_host_alone(raw, default_port, expected_host, expected_port):
    host, port = split_endpoint(raw, default_port=default_port)
    assert host == expected_host
    assert port == expected_port


# ─── rejections: anything that would later corrupt endpoint-address ────────

@pytest.mark.parametrize(
    "raw",
    [
        # multi-colon junk (non-IPv6)
        "control.hoberadius.com:51820:extra",
        "host:port:extra",
        # port out of range
        "control.hoberadius.com:0",
        "control.hoberadius.com:65536",
        "control.hoberadius.com:99999",
        # non-numeric port
        "control.hoberadius.com:abc",
        "control.hoberadius.com:51820x",
        # empty host
        ":51820",
        # leading/trailing dot
        ".bad.host:51820",
        # whitespace inside
        "host with space:51820",
        # bracket-less IPv6 (ambiguous — must be bracketed)
        "2001:db8::1:51820",
        # malformed brackets
        "[2001:db8::1:51820",
        "[2001:db8::1]bad",
    ],
)
def test_split_endpoint_rejects_garbage(raw):
    with pytest.raises(InfraSettingsError):
        split_endpoint(raw, default_port=51820)


def test_split_endpoint_rejects_empty():
    with pytest.raises(InfraSettingsError):
        split_endpoint("", default_port=51820)
    with pytest.raises(InfraSettingsError):
        split_endpoint("   ", default_port=51820)
