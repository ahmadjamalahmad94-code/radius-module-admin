"""Auto-promote ``provisioning → up`` on health-up.

Live regression: an operator's CHR finished wg-mgmt setup, ICMP started
replying, the health monitor flipped ``FleetChrHealth.state`` to
``up``, BUT the registry row ``fleet_chr_nodes.status`` stayed
``provisioning``. The dashboard kept saying «provisioning»; the
routing-table publisher / brain ranking saw the stale value. Two
paths cause this in production:

  A. Fresh node — first OK probe takes ``health.state`` ``unknown → up``
     and the existing ``_denormalize_node_status`` mirror sets
     ``node.status = "up"``. This already worked before the fix.
  B. Pre-fix state — ``health.state`` was already ``up`` from an older
     monitor pass but the registry row was never reconciled. No new
     transition fires, so the old mirror never runs.

The new ``_reconcile_node_status`` step runs on EVERY probe and
guarantees the registry row matches the health row. The reconciler
respects operator intent: ``disabled`` is never overwritten by the
monitor.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.extensions import db
from fleet.health import monitor as _mon
from fleet.health.models_health import FleetChrHealth
from fleet.health.monitor import PingResult, PingTarget, run_once
from fleet.registry.models_chr import FleetChrNode, FleetProvider


def _t(seconds: int) -> datetime:
    return datetime(2026, 6, 10, 0, 0, 0, tzinfo=timezone.utc).replace(tzinfo=None) + timedelta(seconds=seconds)


def _provider() -> FleetProvider:
    p = FleetProvider(name="acme-promote", cost_model="open")
    db.session.add(p); db.session.commit()
    return p


def _node(*, name: str = "chr-vpn-1", status: str = "provisioning",
          enabled: bool = True, drain: bool = False) -> FleetChrNode:
    provider = FleetProvider.query.first() or _provider()
    n = FleetChrNode(
        provider_id=provider.id, name=name,
        public_ip="203.0.113.11", wg_mgmt_ip="10.99.0.11",
        wg_mgmt_pubkey="x" * 44,
        routeros_api_port=8729, coa_port=3799,
        max_sessions=500, link_speed_mbps=1000,
        weight=1.0, enabled=enabled, drain=drain, status=status,
    )
    db.session.add(n); db.session.commit()
    return n


class _OkPinger:
    def ping(self, target: PingTarget) -> PingResult:
        return PingResult(ok=True, latency_ms=10.0)


class _FailPinger:
    def ping(self, target: PingTarget) -> PingResult:
        return PingResult(ok=False, error="timeout")


# ════════════════════════════════════════════════════════════════════════
# Path A — fresh node: first OK probe flips status to "up"
# ════════════════════════════════════════════════════════════════════════
def test_first_ok_probe_promotes_provisioning_to_up(app):
    node = _node(status="provisioning")
    run_once(pinger=_OkPinger(), now=_t(0))

    db.session.refresh(node)
    assert node.status == "up", (
        f"provisioning + first OK probe must promote to up; got status={node.status!r}"
    )
    assert node.last_ping_ok_at == _t(0)

    h = db.session.get(FleetChrHealth, node.id)
    assert h.state == "up"


# ════════════════════════════════════════════════════════════════════════
# Path B — stale health row already up, registry still provisioning →
#          reconcile on the NEXT probe (no new transition needed)
# ════════════════════════════════════════════════════════════════════════
def test_stale_provisioning_with_up_health_reconciles_on_next_probe(app):
    """Simulate the live regression: health says up already, but the
    registry got stuck at provisioning because the older mirror only
    fired on transitions."""
    node = _node(status="provisioning")
    # Pretend an older monitor pass set health.state="up" but the
    # registry never got reconciled.
    h = FleetChrHealth(
        chr_id=node.id, state="up", state_since=_t(-3600),
        consecutive_fail=0, consecutive_ok=5, flap_count_1h=0,
    )
    db.session.add(h); db.session.commit()
    db.session.refresh(node)
    assert node.status == "provisioning", "test setup precondition"

    # New probe (still OK) — no new transition, but reconcile fires.
    run_once(pinger=_OkPinger(), now=_t(0))
    db.session.refresh(node)
    assert node.status == "up", (
        "stale provisioning + up health must reconcile on the next probe"
    )
    assert node.last_ping_ok_at == _t(0)


# ════════════════════════════════════════════════════════════════════════
# Operator-disabled nodes are NEVER turned back on by a probe
# ════════════════════════════════════════════════════════════════════════
def test_disabled_node_stays_disabled_even_when_health_says_up(app):
    """The operator explicitly turned the node off — a successful probe
    must not silently re-enable it."""
    node = _node(status="disabled", enabled=False)
    h = FleetChrHealth(
        chr_id=node.id, state="up", state_since=_t(-3600),
        consecutive_fail=0, consecutive_ok=5, flap_count_1h=0,
    )
    db.session.add(h); db.session.commit()

    # Use check_now (run_once skips disabled nodes by virtue of
    # enabled=False, but check_now probes regardless to let an operator
    # smoke-test a disabled node before re-enabling).
    _mon.check_now(node.id, pinger=_OkPinger(), now=_t(0))
    db.session.refresh(node)
    assert node.status == "disabled", (
        f"disabled status must never be overwritten by a probe; got {node.status!r}"
    )
    # last_ping_ok_at still bumps so the dashboard shows liveness while disabled.
    assert node.last_ping_ok_at == _t(0)


def test_drain_flag_is_independent_of_status_promotion(app):
    """``drain`` is a separate boolean; promoting status to ``up`` must
    not flip the drain flag (operator-controlled)."""
    node = _node(status="provisioning", drain=True)
    run_once(pinger=_OkPinger(), now=_t(0))
    db.session.refresh(node)
    assert node.status == "up"
    assert node.drain is True, "drain flag must not be touched by the monitor"


# ════════════════════════════════════════════════════════════════════════
# Provisioning + failing probe stays provisioning (not down)
# — companion to the earlier «unknown-never-down» fix
# ════════════════════════════════════════════════════════════════════════
def test_provisioning_with_failing_probe_stays_provisioning(app):
    """Failing probes do not promote OR demote a node that's still in
    health.state=unknown. The reconciler leaves it alone — the
    «unknown-never-down» rule already keeps health at unknown."""
    node = _node(status="provisioning")
    run_once(pinger=_FailPinger(), now=_t(0))
    db.session.refresh(node)
    assert node.status == "provisioning"
    h = db.session.get(FleetChrHealth, node.id)
    assert h.state == "unknown"


# ════════════════════════════════════════════════════════════════════════
# After promotion, a real outage still flips status to down via the
# existing transition path
# ════════════════════════════════════════════════════════════════════════
def test_promoted_node_can_still_go_down_on_real_outage(app):
    node = _node(status="provisioning")
    # First OK promotes to up.
    run_once(pinger=_OkPinger(), now=_t(0))
    db.session.refresh(node)
    assert node.status == "up"

    # 5-minute fail streak — should flip both health and node row to down.
    run_once(pinger=_FailPinger(), now=_t(60))
    run_once(pinger=_FailPinger(), now=_t(60 + 100))
    run_once(pinger=_FailPinger(), now=_t(60 + 200))
    run_once(pinger=_FailPinger(), now=_t(60 + 300))

    db.session.refresh(node)
    assert node.status == "down"
    h = db.session.get(FleetChrHealth, node.id)
    assert h.state == "down"
