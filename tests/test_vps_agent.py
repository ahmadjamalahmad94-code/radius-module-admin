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


# ── cert automation: DNS-wait + certbot + reload ─────────────────────────────
class _Clock:
    """Injectable monotonic+sleep so wait_for_dns runs instantly in tests."""
    def __init__(self):
        self.t = 0.0
    def monotonic(self):
        return self.t
    def sleep(self, s):
        self.t += s


def test_build_certbot_argv_default_standalone():
    argv = va.build_certbot_argv("client5.hoberadius.com", "a@b.com")
    assert argv[:2] == ["certbot", "certonly"]
    assert "--standalone" in argv and "--keep-until-expiring" in argv
    assert "-d" in argv and "client5.hoberadius.com" in argv
    assert "a@b.com" in argv and "--staging" not in argv


def test_build_certbot_argv_staging_and_webroot():
    argv = va.build_certbot_argv("c.x", "a@b.com", staging=True, webroot="/var/www")
    assert "--staging" in argv
    assert "--webroot" in argv and "/var/www" in argv and "--standalone" not in argv


def test_wait_for_dns_succeeds_after_propagation():
    clk = _Clock()
    res = va.wait_for_dns(
        "client5.hoberadius.com", "1.2.3.4",
        resolver=va.FakeResolver([["9.9.9.9"], ["1.2.3.4"]]),  # propagates on 2nd poll
        timeout_s=300, interval_s=10, sleep=clk.sleep, monotonic=clk.monotonic)
    assert res.ok and res.attempts == 2 and "1.2.3.4" in res.resolved


def test_wait_for_dns_times_out_nonfatal():
    clk = _Clock()
    res = va.wait_for_dns(
        "client5.hoberadius.com", "1.2.3.4",
        resolver=va.FakeResolver([["9.9.9.9"]]),   # never the expected IP
        timeout_s=30, interval_s=10, sleep=clk.sleep, monotonic=clk.monotonic)
    assert not res.ok and res.attempts >= 2
    assert "did not resolve" in res.detail and "Cloudflare" in res.detail


def test_wait_for_dns_ipv6():
    clk = _Clock()
    res = va.wait_for_dns(
        "client9.hoberadius.com", "2001:db8::1",
        resolver=va.FakeResolver([["2001:db8::1"]]),
        timeout_s=30, interval_s=10, sleep=clk.sleep, monotonic=clk.monotonic)
    assert res.ok and res.attempts == 1


def test_ensure_cert_waits_then_issues():
    clk = _Clock()
    fake = va.FakeExecutor()
    agent = va.VpsAgent(fake, resolver=va.FakeResolver([["9.9.9.9"], ["1.2.3.4"]]))
    res = agent.ensure_cert("client5.hoberadius.com", "1.2.3.4", "a@b.com",
                            timeout_s=300, interval_s=10, sleep=clk.sleep, monotonic=clk.monotonic)
    assert res.ok and "issued" in res.detail
    certbot_calls = [c for c in fake.calls if c[0] == "certbot"]
    assert len(certbot_calls) == 1 and "--standalone" in certbot_calls[0]


def test_ensure_cert_dns_timeout_skips_certbot():
    clk = _Clock()
    fake = va.FakeExecutor()
    agent = va.VpsAgent(fake, resolver=va.FakeResolver([["9.9.9.9"]]))  # never resolves
    res = agent.ensure_cert("client5.hoberadius.com", "1.2.3.4", "a@b.com",
                            timeout_s=30, interval_s=10, sleep=clk.sleep, monotonic=clk.monotonic)
    assert not res.ok and "DNS wait failed" in res.detail
    assert all(c[0] != "certbot" for c in fake.calls)  # certbot never invoked


def test_ensure_cert_certbot_failure_is_nonfatal():
    clk = _Clock()
    fake = va.FakeExecutor({"certbot certonly": va.CommandResult(1, "", "challenge failed")})
    agent = va.VpsAgent(fake, resolver=va.FakeResolver([["1.2.3.4"]]))
    res = agent.ensure_cert("client5.hoberadius.com", "1.2.3.4", "a@b.com",
                            timeout_s=30, interval_s=10, sleep=clk.sleep, monotonic=clk.monotonic)
    assert not res.ok and "certbot failed" in res.detail and "challenge failed" in res.detail


def test_reload_accel_ppp_prefers_graceful():
    fake = va.FakeExecutor()  # everything succeeds
    res = va.VpsAgent(fake).reload_accel_ppp()
    assert res.ok
    assert fake.calls == [["accel-cmd", "reload"]]  # stops at first success


def test_reload_accel_ppp_falls_back_to_restart():
    fake = va.FakeExecutor({
        "accel-cmd reload": va.CommandResult(1, "", "no socket"),
        "systemctl reload": va.CommandResult(1, "", "not loaded"),
    })
    res = va.VpsAgent(fake).reload_accel_ppp()
    assert res.ok
    assert [c[0] for c in fake.calls] == ["accel-cmd", "systemctl", "systemctl"]
    assert fake.calls[-1] == ["systemctl", "restart", "accel-ppp"]


def test_reload_accel_ppp_all_fail():
    fake = va.FakeExecutor({
        "accel-cmd reload": va.CommandResult(1),
        "systemctl reload": va.CommandResult(1),
        "systemctl restart": va.CommandResult(1),
    })
    res = va.VpsAgent(fake).reload_accel_ppp()
    assert not res.ok and "failed" in res.detail


def test_cli_ensure_cert_requires_args():
    # Missing --subdomain/--vps-ip/--email returns 2 BEFORE any network/OS call.
    assert va.main(["--ensure-cert"]) == 2
