"""Regressions for the live-deployment debug fixes.

Covers the three monitor invariants this branch changed
(``fleet/health/monitor.py``):

1. ``_resolve_target`` PREFERS ``wg_mgmt_ip`` over ``public_ip``. The
   live deployment was probing RouterOS api-ssl on the public IP, which
   the operator's firewall correctly blocked — every CHR read down.

2. The default pinger is ICMP (:class:`IcmpPinger`). The TCP-connect
   pinger remains importable as a back-compat override.

3. A node that has NEVER been verified ``up`` cannot be flipped to
   ``down`` by a failing probe streak. Provisioning nodes get to stay in
   ``unknown`` until they actually answer once. This breaks the catch-22
   where the routing-table excluded ``down`` nodes and the monitor
   marked a fresh CHR ``down`` before its wg-mgmt tunnel ever came up.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.extensions import db
from fleet.config import HealthConfig
from fleet.health.models_health import FleetChrHealth
from fleet.health.monitor import (
    IcmpPinger,
    PingResult,
    PingTarget,
    TcpConnectPinger,
    _default_pinger,
    _resolve_target,
    evaluate_transition,
    run_once,
)
from fleet.registry.models_chr import FleetChrNode, FleetProvider


def _t(seconds: int) -> datetime:
    return datetime(2026, 6, 10, 0, 0, 0, tzinfo=timezone.utc).replace(tzinfo=None) + timedelta(seconds=seconds)


def _cfg() -> HealthConfig:
    return HealthConfig()


def _provider() -> FleetProvider:
    p = FleetProvider(name="acme-gaps", cost_model="open")
    db.session.add(p)
    db.session.commit()
    return p


def _make_node(name: str, *, public_ip: str = "203.0.113.50",
               wg_mgmt_ip: str = "10.99.0.50", status: str = "provisioning") -> FleetChrNode:
    provider = FleetProvider.query.first() or _provider()
    n = FleetChrNode(
        provider_id=provider.id, name=name,
        public_ip=public_ip, wg_mgmt_ip=wg_mgmt_ip,
        wg_mgmt_pubkey="x" * 44,
        routeros_api_port=8729, coa_port=3799,
        max_sessions=500, link_speed_mbps=1000,
        weight=1.0, enabled=True, status=status,
    )
    db.session.add(n); db.session.commit()
    return n


# ════════════════════════════════════════════════════════════════════════
# 1. _resolve_target picks wg_mgmt_ip first
# ════════════════════════════════════════════════════════════════════════
class TestResolveTarget:
    def test_prefers_wg_mgmt_over_public_ip(self, app):
        node = _make_node("chr-prefer-wg", public_ip="203.0.113.11", wg_mgmt_ip="10.99.0.11")
        target = _resolve_target(node)
        # Control plane wins — public_ip is firewall-blocked on the WAN.
        assert target.host == "10.99.0.11"
        assert target.host != "203.0.113.11"

    def test_falls_back_to_public_ip_when_wg_missing(self, app):
        node = _make_node("chr-public-fallback",
                          public_ip="198.51.100.55", wg_mgmt_ip="10.99.0.99")
        # Simulate a bad row where wg_mgmt_ip somehow ended up blank.
        node.wg_mgmt_ip = ""
        db.session.commit()
        target = _resolve_target(node)
        assert target.host == "198.51.100.55"


# ════════════════════════════════════════════════════════════════════════
# 2. ICMP pinger is the default
# ════════════════════════════════════════════════════════════════════════
class TestDefaultPinger:
    def test_default_is_icmp(self):
        p = _default_pinger()
        assert isinstance(p, IcmpPinger)

    def test_tcp_pinger_still_importable(self):
        # Back-compat: callers that want a specific TCP port may still
        # construct it explicitly. The default just stopped being TCP.
        assert TcpConnectPinger().ping is not None


# ════════════════════════════════════════════════════════════════════════
# 3. Provisioning / unknown nodes do not flip to down
# ════════════════════════════════════════════════════════════════════════
class TestUnknownNeverDown:
    def test_single_fail_from_unknown_stays_unknown(self):
        h = FleetChrHealth(chr_id=1, state="unknown", state_since=_t(0),
                           consecutive_fail=0, consecutive_ok=0, flap_count_1h=0)
        tr = evaluate_transition(h, ping_ok=False, now=_t(60),
                                 last_fail_ts=None, cfg=_cfg())
        assert tr is None
        assert h.state == "unknown"

    def test_long_fail_streak_from_unknown_still_not_down(self):
        """The headline regression. Before this fix, a 5-minute fail
        streak from unknown would flip to down — exactly what was
        happening to chr-vpn-1 while its wg-mgmt was still being set up."""
        h = FleetChrHealth(chr_id=1, state="unknown", state_since=_t(0),
                           consecutive_fail=0, consecutive_ok=0, flap_count_1h=0)
        # Replay 5 minutes of continuous fails.
        evaluate_transition(h, ping_ok=False, now=_t(60),
                            last_fail_ts=None, cfg=_cfg())
        tr = evaluate_transition(h, ping_ok=False, now=_t(60 + 600),
                                 last_fail_ts=_t(60), cfg=_cfg())
        assert tr is None, "unknown must NOT escalate to down"
        assert h.state == "unknown"
        # Fail counters still tick (so once the node is verified up, a
        # future outage will fire correctly).
        assert h.consecutive_fail >= 2

    def test_first_ok_from_unknown_seeds_up(self):
        """Once verified, the node is officially ``up`` — and from then
        on the normal up→down hysteresis applies. This is what allows
        chr-vpn-1 to flip up the moment wg-mgmt comes online."""
        h = FleetChrHealth(chr_id=1, state="unknown", state_since=_t(0),
                           consecutive_fail=0, consecutive_ok=0, flap_count_1h=0)
        tr = evaluate_transition(h, ping_ok=True, now=_t(0),
                                 last_fail_ts=None, cfg=_cfg())
        assert tr is not None and tr.to_state == "up"

    def test_up_to_down_still_works_after_verification(self):
        """The protective rule applies ONLY to unknown nodes. Once a node
        has been seen ``up``, a 5-minute fail streak must still take it
        to ``down`` — otherwise we'd lose real outage detection."""
        h = FleetChrHealth(chr_id=1, state="up", state_since=_t(0),
                           consecutive_fail=0, consecutive_ok=5, flap_count_1h=0)
        evaluate_transition(h, ping_ok=False, now=_t(60),
                            last_fail_ts=None, cfg=_cfg())
        tr = evaluate_transition(h, ping_ok=False, now=_t(60 + 300),
                                 last_fail_ts=_t(60 + 299), cfg=_cfg())
        assert tr is not None and tr.to_state == "down"


# ════════════════════════════════════════════════════════════════════════
# 4. End-to-end via run_once — a provisioning node that never answers
# stays in unknown, with no health_down event written.
# ════════════════════════════════════════════════════════════════════════
class _AlwaysFailPinger:
    def __init__(self):
        self.calls: list[PingTarget] = []

    def ping(self, target):  # noqa: D401
        self.calls.append(target)
        return PingResult(ok=False, error="timeout")


class TestRunOnceProvisioning:
    def test_provisioning_node_with_no_reach_never_flips_down(self, app):
        node = _make_node("chr-prov-never-up", status="provisioning")
        fake = _AlwaysFailPinger()
        # Simulate 30 minutes of continuous fails from a brand-new node
        # whose wg-mgmt tunnel hasn't come up yet — the operator scenario.
        for i in range(6):
            run_once(pinger=fake, now=_t(60 + i * 300))
        health = db.session.get(FleetChrHealth, node.id)
        assert health.state == "unknown", (
            "a provisioning node that never answered must stay unknown — "
            "marking it down would block the routing-table from publishing it."
        )
        # And the registry node's status is left alone (still provisioning).
        db.session.refresh(node)
        assert node.status == "provisioning"
        # The probe targeted wg_mgmt_ip — the headline routing fix.
        assert all(call.host.startswith("10.99.") for call in fake.calls)

    def test_provisioning_node_flips_up_on_first_reach(self, app):
        """When wg-mgmt finally comes up, a single OK probe seeds the
        node to ``up`` and the routing-table starts publishing it."""

        class _OneShotOkPinger:
            def __init__(self):
                self.calls = 0

            def ping(self, target):
                self.calls += 1
                return PingResult(ok=True, latency_ms=2.3)

        node = _make_node("chr-prov-then-up", status="provisioning")
        run_once(pinger=_OneShotOkPinger(), now=_t(0))
        health = db.session.get(FleetChrHealth, node.id)
        assert health.state == "up"
