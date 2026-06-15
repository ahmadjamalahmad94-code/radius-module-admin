"""Tests for the on-VPS agent skeleton (deploy/accel-ppp/agent/vps_agent.py).

The agent lives under deploy/ (it may move to radius-module later), so we add
its directory to sys.path and import it directly. All OS calls go through the
FakeExecutor — nothing here touches wg/tc/accel-cmd/certbot.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

AGENT_DIR = Path(__file__).resolve().parents[1] / "deploy" / "accel-ppp" / "agent"
if str(AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(AGENT_DIR))

import vps_agent as va  # noqa: E402


# ── pure: argv builders ───────────────────────────────────────────────────────
def test_cidr_for_ipv4_ipv6_and_explicit():
    assert va._cidr_for("10.20.0.5") == "10.20.0.5/32"
    assert va._cidr_for("fd00::5") == "fd00::5/128"
    assert va._cidr_for("10.20.0.0/24") == "10.20.0.0/24"


def test_build_wireguard_peer_argv_basic():
    spec = va.WireguardPeerSpec(public_key="PUBKEY=", allowed_ip="10.20.0.5", interface="wg-data")
    cmds = va.build_wireguard_peer_argv(spec)
    assert cmds == [["wg", "set", "wg-data", "peer", "PUBKEY=",
                     "allowed-ips", "10.20.0.5/32"]]


def test_build_wireguard_peer_argv_with_psk_writes_file_first():
    spec = va.WireguardPeerSpec(public_key="ABCDEFGH123", allowed_ip="10.20.0.5",
                                preshared_key="secretpsk")
    cmds = va.build_wireguard_peer_argv(spec)
    # PSK file must be written BEFORE the wg set, and referenced by path.
    assert cmds[0][0] == "sh"
    assert cmds[-1][0] == "wg" and "preshared-key" in cmds[-1]


def test_mbit_to_kbit():
    assert va.mbit_to_kbit(5) == 5000
    assert va.mbit_to_kbit(10) == 10000
    assert va.mbit_to_kbit(0) == 1000  # floored to 1 Mbit, never 0


def test_build_shaper_argv_rate_and_structure():
    spec = va.WireguardPeerSpec(public_key="K", allowed_ip="10.20.0.7", rate_mbit=5)
    cmds = va.build_shaper_argv(spec)
    verbs = [(c[0], c[1]) for c in cmds]
    assert ("tc", "qdisc") in verbs and ("tc", "class") in verbs and ("tc", "filter") in verbs
    flat = " ".join(" ".join(c) for c in cmds)
    assert "5000kbit" in flat            # 5 Mbit cap applied
    assert "10.20.0.7/32" in flat        # filtered to the peer /32
    assert "1:7" in flat                 # classid derived from last octet


def test_build_shaper_argv_uses_default_rate():
    spec = va.WireguardPeerSpec(public_key="K", allowed_ip="10.20.0.7")
    assert spec.rate_mbit == va.DEFAULT_RATE_MBIT == 5
    flat = " ".join(" ".join(c) for c in va.build_shaper_argv(spec))
    assert "5000kbit" in flat


# ── pure: session parsing ─────────────────────────────────────────────────────
def test_parse_sessions_with_header():
    raw = (
        "ifname   | username | ip          | type | rx-bytes | tx-bytes\n"
        "ppp0     | alice    | 10.20.0.5   | sstp | 1048576  | 2097152\n"
        "ppp1     | bob      | 10.20.0.6   | pptp | 0        | 0\n"
    )
    sessions = va.parse_sessions(raw)
    assert len(sessions) == 2
    assert sessions[0].username == "alice" and sessions[0].ip == "10.20.0.5"
    assert sessions[0].type == "sstp" and sessions[0].rx_bytes == 1048576
    assert sessions[1].username == "bob"


def test_parse_sessions_no_header_whitespace():
    raw = "ppp0 alice 10.20.0.5 sstp\nppp1 bob 10.20.0.6 l2tp\n"
    sessions = va.parse_sessions(raw)
    assert [s.username for s in sessions] == ["alice", "bob"]
    assert sessions[0].iface == "ppp0" and sessions[0].type == "sstp"


def test_parse_sessions_empty_and_garbage():
    assert va.parse_sessions("") == []
    assert va.parse_sessions("\n  \n") == []


# ── agent + FakeExecutor ──────────────────────────────────────────────────────
def test_apply_wireguard_peer_runs_wg_then_tc():
    fake = va.FakeExecutor()
    agent = va.VpsAgent(fake)
    spec = va.WireguardPeerSpec(public_key="K", allowed_ip="10.20.0.5", rate_mbit=5)
    res = agent.apply_wireguard_peer(spec)
    assert res.ok
    verbs = [c[0] for c in fake.calls]
    assert verbs[0] == "wg"             # peer first
    assert "tc" in verbs                # then shaper
    assert res.commands[0][0] == "wg"


def test_apply_wireguard_peer_stops_on_failure():
    # wg set fails → shaper must NOT run.
    fake = va.FakeExecutor({"wg set": va.CommandResult(1, "", "permission denied")})
    agent = va.VpsAgent(fake)
    spec = va.WireguardPeerSpec(public_key="K", allowed_ip="10.20.0.5")
    res = agent.apply_wireguard_peer(spec)
    assert not res.ok and "permission denied" in res.detail
    assert all(c[0] != "tc" for c in fake.calls)  # shaper never reached


def test_list_active_sessions_parses_executor_output():
    out = "ifname | username | ip\nppp0 | carol | 10.20.0.9\n"
    fake = va.FakeExecutor({"accel-cmd show": va.CommandResult(0, out, "")})
    agent = va.VpsAgent(fake)
    sessions = agent.list_active_sessions()
    assert len(sessions) == 1 and sessions[0].username == "carol"


def test_list_active_sessions_empty_on_failure():
    fake = va.FakeExecutor({"accel-cmd show": va.CommandResult(1, "", "no socket")})
    agent = va.VpsAgent(fake)
    assert agent.list_active_sessions() == []


def test_renew_cert_invokes_certbot():
    fake = va.FakeExecutor()
    agent = va.VpsAgent(fake)
    res = agent.renew_cert()
    assert res.ok
    assert fake.calls == [["certbot", "renew", "--quiet"]]


def test_cli_dry_run_serve_is_clean_stub(capsys):
    rc = va.main(["--serve", "--dry-run"])
    assert rc == 0
    assert "skeleton" in capsys.readouterr().out.lower()
