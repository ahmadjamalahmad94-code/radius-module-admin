"""Reserved-subnet guard — PPP/VPN pools MUST stay out of 10.98/24 and 10.99/24.

Live root cause of the 2026-06 ``unknown CHR IP 10.98.0.11 — dropped``
incident: the panel's default ``CHR_PPP_LOCAL_ADDRESS`` was ``10.98.0.1``
and ``CHR_PPP_POOL_RANGES`` was ``10.98.0.10-10.98.0.250`` — both inside
the wg-data /24 the proxy uses. A PPP client that took ``10.98.0.5`` would
hijack the RADIUS path back to the proxy.

The reserved-subnet helper (``app/services/reserved_subnets.py``) is now
the single source of truth for "is this value safe?". Every PPP-pool /
local-address write path calls one of its assertions. These tests pin
the rejection contract.
"""
from __future__ import annotations

import pytest

from app.services.reserved_subnets import (
    ReservedSubnetError,
    assert_address_not_reserved,
    assert_network_not_reserved,
    assert_pool_range_not_reserved,
    is_reserved_address,
    is_reserved_network,
    is_reserved_range,
)


# ════════════════════════════════════════════════════════════════════════
# 1. The headline detector cases — exact live-deploy values
# ════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize("addr,reserved", [
    # The live-deploy default — both must be rejected.
    ("10.98.0.1", True),
    ("10.99.0.1", True),
    # A node-allocated address in each pool.
    ("10.98.0.11", True),
    ("10.99.0.11", True),
    # Edge of /24 — broadcast / first host.
    ("10.98.0.0", True),
    ("10.98.0.255", True),
    # Outside the pools — must pass.
    ("10.0.0.1", False),
    ("10.10.0.1", False),
    ("10.100.0.1", False),
    ("172.16.0.1", False),
    ("192.168.1.1", False),
    # The 10.99/24 boundary case — adjacent /24 is safe.
    ("10.99.1.1", False),
    # A non-IP string never matches.
    ("not-an-ip", False),
    ("", False),
])
def test_is_reserved_address(addr, reserved):
    assert is_reserved_address(addr) is reserved


@pytest.mark.parametrize("ranges,reserved", [
    # The live-deploy default — pool entirely inside wg-data /24.
    ("10.98.0.10-10.98.0.250", True),
    # Pool that STRADDLES the boundary — partial overlap must still reject.
    ("10.97.0.250-10.98.0.10", True),
    # Multi-token range with one bad token must reject.
    ("10.10.0.1-10.10.0.250,10.99.0.5", True),
    # All-safe multi-token must pass.
    ("10.10.0.10-10.10.0.250,10.20.0.10-10.20.0.250", False),
    # Single-host token inside the pool — reject.
    ("10.99.0.5", True),
    # Bare safe IP — pass.
    ("10.10.0.5", False),
    ("", False),
])
def test_is_reserved_range(ranges, reserved):
    assert is_reserved_range(ranges) is reserved


@pytest.mark.parametrize("cidr,reserved", [
    ("10.98.0.0/24", True),
    ("10.99.0.0/24", True),
    # Smaller subnet fully inside the reserved /24.
    ("10.98.0.0/28", True),
    # Bigger subnet that overlaps reserved.
    ("10.98.0.0/16", True),
    # Adjacent /24 — safe.
    ("10.97.0.0/24", False),
    ("10.100.0.0/24", False),
    # The template default — passes.
    ("10.0.0.0/8", True),    # 10.0.0.0/8 ENCLOSES both reserved /24s
    ("10.10.0.0/16", False),
    ("", False),
])
def test_is_reserved_network(cidr, reserved):
    assert is_reserved_network(cidr) is reserved


# ════════════════════════════════════════════════════════════════════════
# 2. assertion helpers raise on bad input, return clean on good input
# ════════════════════════════════════════════════════════════════════════


def test_assert_address_rejects_wg_data_addr():
    with pytest.raises(ReservedSubnetError) as exc:
        assert_address_not_reserved("10.98.0.1", field_label="CHR_PPP_LOCAL_ADDRESS")
    msg = str(exc.value)
    assert "10.98.0.1" in msg
    assert "محجوزة" in msg
    assert "CHR_PPP_LOCAL_ADDRESS" in msg


def test_assert_address_accepts_safe_addr():
    assert assert_address_not_reserved("10.10.0.1") == "10.10.0.1"
    assert assert_address_not_reserved("  10.10.0.1  ") == "10.10.0.1"
    # Empty is a no-op (the caller is responsible for its own required-check).
    assert assert_address_not_reserved("") == ""


def test_assert_pool_range_rejects_live_deploy_default():
    with pytest.raises(ReservedSubnetError):
        assert_pool_range_not_reserved("10.98.0.10-10.98.0.250")


def test_assert_pool_range_accepts_safe_range():
    assert assert_pool_range_not_reserved("10.10.0.10-10.10.0.250") \
        == "10.10.0.10-10.10.0.250"


def test_assert_network_rejects_reserved_cidr():
    with pytest.raises(ReservedSubnetError):
        assert_network_not_reserved("10.98.0.0/24", field_label="CLIENT_SUPERNET")


def test_assert_network_accepts_default_supernet_when_not_reserved():
    # The /16 supernet of an adjacent block is safe.
    assert assert_network_not_reserved("10.10.0.0/16") == "10.10.0.0/16"


# ════════════════════════════════════════════════════════════════════════
# 3. The script renderer refuses to emit a collision
# ════════════════════════════════════════════════════════════════════════


def _bindings(**over):
    """Bare-minimum binding dict that the unified template would accept.
    Only the two values we care about for this test are exposed; the
    renderer's collision guard runs BEFORE Jinja, so the template never
    needs to be evaluated."""
    from fleet.registry.script_render import _DEFAULT_ENDPOINT_PORTS  # noqa: F401
    base = {
        "ROUTER_IDENTITY": "chr-test",
        "CHR_PUBLIC_IP": "203.0.113.1",
        "WG_MGMT_PRIVKEY": "z" * 44,
        "WG_MGMT_ADDR": "10.99.0.11/24",
        "WG_DATA_PRIVKEY": "z" * 44,
        "WG_DATA_ADDR": "10.98.0.11/24",
        "WG_DATA_ADDR_IP": "10.98.0.11",
        "PANEL_WG_PUBKEY": "p" * 44,
        "PANEL_WG_ENDPOINT": "panel.example.com:51820",
        "PANEL_WG_ADDR": "10.99.0.1",
        "PROXY_WG_PUBKEY": "p" * 44,
        "PROXY_WG_ENDPOINT": "proxy.example.com:51821",
        "PROXY_WG_ADDR": "10.98.0.1",
        "CHR_SHARED_SECRET": "s" * 32,
        "SSTP_CERT_NAME": "",
        "IKE_CERT_NAME": "",
        "CLIENT_SUPERNET": "10.0.0.0/8",
        "DNS_PUSH": "1.1.1.1",
        "GW_LOCAL_ADDR": "10.255.255.1",
        "WAN_IFACE": "ether1",
        "API_USER": "",
        "API_PASSWORD": "",
        "API_PORT": 8443,
    }
    base.update(over)
    return base


def test_render_refuses_gw_local_in_reserved_subnet():
    """A panel-side template that smuggles ``GW_LOCAL_ADDR=10.98.0.1``
    must fail render rather than ship a colliding CHR script."""
    from fleet.registry.script_render import render_from_bindings
    with pytest.raises(ValueError) as exc:
        render_from_bindings(_bindings(GW_LOCAL_ADDR="10.98.0.1"))
    assert "GW_LOCAL_ADDR" in str(exc.value)
    assert "10.98.0.1" in str(exc.value)


def test_render_accepts_safe_gw_local():
    """The default safe value renders cleanly — we haven't broken the
    legitimate path."""
    from fleet.registry.script_render import render_from_bindings
    out = render_from_bindings(_bindings())
    # Sanity: the template did run and the safe GW address landed in the
    # output (proves the guard didn't false-positive on default config).
    assert "10.255.255.1" in out


# ════════════════════════════════════════════════════════════════════════
# 4. The config defaults are now safe
# ════════════════════════════════════════════════════════════════════════


def test_config_defaults_outside_reserved_subnets(app):
    """A clean app boot must NOT default the PPP pool into a reserved net."""
    cfg = app.config
    assert not is_reserved_address(cfg["CHR_PPP_LOCAL_ADDRESS"]), (
        f"CHR_PPP_LOCAL_ADDRESS default {cfg['CHR_PPP_LOCAL_ADDRESS']} is in "
        "a reserved fleet subnet"
    )
    assert not is_reserved_range(cfg["CHR_PPP_POOL_RANGES"]), (
        f"CHR_PPP_POOL_RANGES default {cfg['CHR_PPP_POOL_RANGES']} overlaps "
        "a reserved fleet subnet"
    )
