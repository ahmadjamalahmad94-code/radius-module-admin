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


def test_build_peer_shaper_argv_rate_and_structure():
    spec = va.WireguardPeerSpec(public_key="K", allowed_ip="10.20.0.7", rate_mbit=5)
    cmds = va.build_peer_shaper_argv(spec, 0x1a)   # minor from the allocator
    verbs = [(c[0], c[1]) for c in cmds]
    assert ("tc", "class") in verbs and ("tc", "filter") in verbs
    assert ("tc", "qdisc") in verbs                # leaf qdisc (NOT the root)
    flat = " ".join(" ".join(c) for c in cmds)
    assert "5000kbit" in flat            # 5 Mbit cap applied
    assert "10.20.0.7/32" in flat        # filtered to the peer /32
    assert "1:1a" in flat                # classid minor is HEX
    assert "prio 26" in flat             # filter prio == minor (decimal) → deletable
    # build_peer_shaper_argv MUST NOT emit the root qdisc (that's ensure_root_qdisc).
    assert not any(c[:4] == ["tc", "qdisc", "replace", "dev"] and "root" in c for c in cmds)


def test_build_peer_shaper_argv_ipv6_uses_ip6_match():
    spec = va.WireguardPeerSpec(public_key="K", allowed_ip="fd00::7", rate_mbit=5)
    flat = " ".join(" ".join(c) for c in va.build_peer_shaper_argv(spec, 5))
    assert "protocol ipv6" in flat and "match ip6 dst" in flat
    assert "fd00::7/128" in flat


def test_build_peer_shaper_argv_uses_default_rate():
    spec = va.WireguardPeerSpec(public_key="K", allowed_ip="10.20.0.7")
    assert spec.rate_mbit == va.DEFAULT_RATE_MBIT == 5
    flat = " ".join(" ".join(c) for c in va.build_peer_shaper_argv(spec, 3))
    assert "5000kbit" in flat


# ── collision-free classid allocator ─────────────────────────────────────────
def test_classid_allocator_no_collision_stable_and_reuse():
    a = va.ClassidAllocator()
    m1, m2 = a.allocate("PKA"), a.allocate("PKB")
    assert m1 != m2                       # two peers never collide
    assert a.allocate("PKA") == m1        # stable per key
    assert a.minor_for("PKB") == m2
    a.release("PKA")
    assert a.allocate("PKC") == m1        # freed minor is reused
    assert "PKA" not in a


def test_classid_allocator_skips_reserved_default():
    a = va.ClassidAllocator()
    assert va.HTB_DEFAULT_MINOR not in set(a.allocate(f"k{i}") for i in range(50))


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


def test_cli_serve_requires_peer_source(capsys):
    # --serve now runs the real reconcile loop; without a peer source it
    # refuses (rc 2) rather than spinning a daemon with nothing to fetch.
    rc = va.main(["--serve", "--dry-run"])
    assert rc == 2
    assert "peer-source-url" in capsys.readouterr().out.lower()


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
                            challenge="http01",
                            timeout_s=300, interval_s=10, sleep=clk.sleep, monotonic=clk.monotonic)
    assert res.ok and "issued" in res.detail
    certbot_calls = [c for c in fake.calls if c[0] == "certbot"]
    assert len(certbot_calls) == 1 and "--standalone" in certbot_calls[0]


def test_ensure_cert_dns_timeout_skips_certbot():
    clk = _Clock()
    fake = va.FakeExecutor()
    agent = va.VpsAgent(fake, resolver=va.FakeResolver([["9.9.9.9"]]))  # never resolves
    res = agent.ensure_cert("client5.hoberadius.com", "1.2.3.4", "a@b.com",
                            challenge="http01",
                            timeout_s=30, interval_s=10, sleep=clk.sleep, monotonic=clk.monotonic)
    assert not res.ok and "DNS wait failed" in res.detail
    assert all(c[0] != "certbot" for c in fake.calls)  # certbot never invoked


def test_ensure_cert_certbot_failure_is_nonfatal():
    clk = _Clock()
    fake = va.FakeExecutor({"certbot certonly": va.CommandResult(1, "", "challenge failed")})
    agent = va.VpsAgent(fake, resolver=va.FakeResolver([["1.2.3.4"]]))
    res = agent.ensure_cert("client5.hoberadius.com", "1.2.3.4", "a@b.com",
                            challenge="http01",
                            timeout_s=30, interval_s=10, sleep=clk.sleep, monotonic=clk.monotonic)
    assert not res.ok and "certbot (http01) failed" in res.detail and "challenge failed" in res.detail


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


# ── cert challenge selection (HTTP-01 / DNS-01 fallback) ─────────────────────
def test_build_certbot_argv_dns01_uses_cloudflare_plugin():
    argv = va.build_certbot_argv("c.x", "a@b.com", challenge=va.CHALLENGE_DNS01,
                                 cf_credentials_path="/etc/letsencrypt/cf.ini")
    assert "--dns-cloudflare" in argv
    assert "--dns-cloudflare-credentials" in argv and "/etc/letsencrypt/cf.ini" in argv
    assert "--standalone" not in argv


def test_select_challenge_logic():
    assert va.select_challenge("auto", port80_open=True) == "http01"
    assert va.select_challenge("auto", port80_open=False) == "dns01"
    assert va.select_challenge("http01", port80_open=False) == "http01"  # override
    assert va.select_challenge("dns01", port80_open=True) == "dns01"     # override


def test_ensure_cert_auto_port80_open_uses_http01():
    clk = _Clock()
    fake = va.FakeExecutor()
    agent = va.VpsAgent(fake, resolver=va.FakeResolver([["1.2.3.4"]]),
                        prober=va.FakePort80Prober(True))
    res = agent.ensure_cert("c.hoberadius.com", "1.2.3.4", "a@b.com",
                            challenge="auto", timeout_s=30, interval_s=10,
                            sleep=clk.sleep, monotonic=clk.monotonic)
    assert res.ok and "via http01" in res.detail
    certbot = next(c for c in fake.calls if c[0] == "certbot")
    assert "--standalone" in certbot


def test_ensure_cert_auto_port80_blocked_falls_back_to_dns01():
    fake = va.FakeExecutor()
    agent = va.VpsAgent(fake, prober=va.FakePort80Prober(False))
    res = agent.ensure_cert("c.hoberadius.com", "1.2.3.4", "a@b.com",
                            challenge="auto", cf_credentials_path="/etc/le/cf.ini")
    assert res.ok and "via dns01" in res.detail
    certbot = next(c for c in fake.calls if c[0] == "certbot")
    assert "--dns-cloudflare" in certbot
    # DNS-01 doesn't need the A record to point here → no DNS wait was needed.


def test_ensure_cert_dns01_without_credentials_is_actionable():
    fake = va.FakeExecutor()
    agent = va.VpsAgent(fake, prober=va.FakePort80Prober(False))
    res = agent.ensure_cert("c.hoberadius.com", "1.2.3.4", "a@b.com", challenge="auto")
    assert not res.ok and "Cloudflare credentials" in res.detail
    assert all(c[0] != "certbot" for c in fake.calls)  # never invoked


# ── reconcile daemon ─────────────────────────────────────────────────────────
class _ReconcileExec:
    """Fake executor that models wg peer presence + tc qdisc state for the loop."""
    def __init__(self, present=None, root_present=True):
        self.calls = []
        self.present = list(present or [])     # pubkeys `wg show … peers` reports
        self.root_present = root_present
        self.fail_keys = set()                 # pubkeys whose `wg set` fails

    def run(self, argv):
        self.calls.append(argv)
        if argv[0] == "wg" and "peers" in argv:
            return va.CommandResult(0, "\n".join(self.present), "")
        if argv[:3] == ["tc", "qdisc", "show"]:
            return va.CommandResult(0, "qdisc htb 1: root" if self.root_present else "", "")
        if argv[0] == "wg" and "set" in argv and len(argv) > 4 and argv[4] in self.fail_keys:
            return va.CommandResult(1, "", "wg failed")
        return va.CommandResult(0, "", "")


def _peer(k, ip): return va.DesiredPeer(public_key=k, allowed_ip=ip)


def test_reconcile_adds_missing_peers():
    fx = _ReconcileExec(present=[])
    agent = va.VpsAgent(fx)
    r = agent.reconcile_once(va.StaticPeerSource([_peer("PK1", "10.20.0.5")]), "wg-data")
    assert r.ok and r.added == ["PK1"] and not r.removed and not r.in_sync
    assert any(c[0] == "wg" and "set" in c for c in fx.calls)
    assert any(c[0] == "tc" for c in fx.calls)


def test_reconcile_in_sync_is_noop():
    src = va.StaticPeerSource([_peer("PK1", "10.20.0.5"), _peer("PK2", "10.20.1.5")])
    fx = _ReconcileExec(present=[])
    agent = va.VpsAgent(fx)
    agent.reconcile_once(src, "wg-data")        # tick 1 applies
    fx.present = ["PK1", "PK2"]                  # now present on the iface
    n = len(fx.calls)
    r2 = agent.reconcile_once(src, "wg-data")    # tick 2 — already in sync
    assert r2.in_sync and not r2.added and not r2.removed
    mutating = [c for c in fx.calls[n:] if c[0] in ("wg", "tc") and "show" not in c]
    assert mutating == []                        # zero mutating commands


def test_reconcile_removes_only_managed_peers():
    src1 = va.StaticPeerSource([_peer("PK1", "10.20.0.5")])
    fx = _ReconcileExec(present=[])
    agent = va.VpsAgent(fx)
    agent.reconcile_once(src1, "wg-data")        # we add+manage PK1
    # Now PK1 is gone from desired, and an OPERATOR-added peer OP exists.
    fx.present = ["PK1", "OP"]
    r = agent.reconcile_once(va.StaticPeerSource([]), "wg-data")
    assert r.removed == ["PK1"]                  # only the peer WE manage
    remove_cmds = [c for c in fx.calls if c[0] == "wg" and c[-1] == "remove"]
    assert all("OP" not in c for c in remove_cmds)  # operator peer untouched


def test_reconcile_fetch_error_is_nonfatal():
    class Boom:
        def fetch_desired(self): raise RuntimeError("net down")
    r = va.VpsAgent(_ReconcileExec()).reconcile_once(Boom(), "wg-data")
    assert not r.ok and "fetch failed" in r.detail   # no exception escaped


def test_reconcile_peer_apply_error_is_recorded_not_raised():
    fx = _ReconcileExec(present=[]); fx.fail_keys = {"PKBAD"}
    agent = va.VpsAgent(fx)
    r = agent.reconcile_once(va.StaticPeerSource([_peer("PKBAD", "10.20.0.9")]), "wg-data")
    assert not r.ok and r.errors == ["PKBAD"] and r.added == []


def test_ensure_root_qdisc_idempotent():
    present = _ReconcileExec(root_present=True)
    va.VpsAgent(present).ensure_root_qdisc("wg-data")
    assert not any(c[:3] == ["tc", "qdisc", "add"] for c in present.calls)  # already there
    absent = _ReconcileExec(root_present=False)
    va.VpsAgent(absent).ensure_root_qdisc("wg-data")
    assert any(c[:3] == ["tc", "qdisc", "add"] for c in absent.calls)       # created


def test_serve_runs_bounded_ticks():
    fx = _ReconcileExec(present=["PK1"])
    agent = va.VpsAgent(fx)
    results = agent.serve(va.StaticPeerSource([_peer("PK1", "10.20.0.5")]),
                          iface="wg-data", interval_s=5, max_ticks=3,
                          sleep=lambda s: None)
    assert len(results) == 3 and all(isinstance(r, va.ReconcileResult) for r in results)


# ── desired-peer contract parsing ─────────────────────────────────────────────
def test_parse_desired_peers_contract_shape():
    payload = {"peers": [
        {"name": "c5", "public_key": "PK1", "allowed_ips": ["10.20.0.5/32"], "endpoint": None},
        {"name": "c6", "public_key": "PK2", "allowed_ips": ["10.20.0.6/32"], "rate_mbit": 10},
    ]}
    peers = va.parse_desired_peers(payload)
    assert [p.public_key for p in peers] == ["PK1", "PK2"]
    assert peers[0].allowed_ip == "10.20.0.5/32" and peers[0].rate_mbit == 5  # default
    assert peers[1].rate_mbit == 10                                           # override


def test_parse_desired_peers_skips_invalid():
    payload = {"peers": [
        {"public_key": "", "allowed_ips": ["10.0.0.1/32"]},   # no key
        {"public_key": "PK", "allowed_ips": []},               # no allowed_ips
        {"public_key": "OK", "allowed_ips": ["10.0.0.2/32"]},
    ]}
    peers = va.parse_desired_peers(payload)
    assert [p.public_key for p in peers] == ["OK"]


def test_http_peer_source_parses_mocked_fetch():
    payload = {"peers": [{"public_key": "PK1", "allowed_ips": ["10.20.0.5/32"]}]}
    src = va.HttpPeerSource("https://panel/api/proxy/wg-peers", lambda u: payload)
    peers = src.fetch_desired()
    assert len(peers) == 1 and peers[0].public_key == "PK1"


# ── WG data-port clash check ──────────────────────────────────────────────────
def test_parse_listening_udp_ports():
    ss = ("State  Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
          "UNCONN 0      0      0.0.0.0:51820      0.0.0.0:*\n"
          "UNCONN 0      0      [::]:53            [::]:*\n")
    assert va.parse_listening_udp_ports(ss) == {51820, 53}


def test_pick_free_port():
    assert va.pick_free_port(51820, {51820, 51821}) == 51822
    assert va.pick_free_port(51820, set()) == 51820
    assert va.pick_free_port(65535, {65535}, max_tries=1) is None  # nothing in range


def test_check_wg_port_free_and_clash():
    busy = va.FakeExecutor({"ss -lun": va.CommandResult(
        0, "State Local Address:Port\nUNCONN 0.0.0.0:51820 0.0.0.0:*\n", "")})
    free, port, _ = va.VpsAgent(busy).check_wg_port(51821)
    assert free and port == 51821
    clash_free, clash_port, detail = va.VpsAgent(busy).check_wg_port(51820)
    assert not clash_free and clash_port is None and "in use" in detail
    # auto-pick the next free port
    _, picked, _ = va.VpsAgent(busy).check_wg_port(51820, pick_next=True)
    assert picked == 51821
