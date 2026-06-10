"""Panel gate 3 — fleet.health.monitor._notify_hook fans a transition out to BOTH
the Phase-8 rebalance orchestrator AND the Phase-9 notifier (union, not either/or).

A regression guard: a future edit that drops one branch (so only notifications OR
only auto-failover fire) must fail here.
"""
from __future__ import annotations

from app.extensions import db
from fleet.brain.models_session import PlacementDecision, Session
from fleet.health.models_health import FleetChrHealth
from fleet.notify.models_alert import Event
from fleet.registry.models_chr import FleetChrNode, FleetProvider


def _seed_down_scenario():
    prov = FleetProvider(name="C", cost_model="open", price_per_tb=0)
    db.session.add(prov)
    db.session.flush()
    src = FleetChrNode(provider_id=prov.id, name="src", public_ip="1.1.1.1",
                       wg_mgmt_ip="10.99.0.1", wg_mgmt_pubkey="k", max_sessions=100,
                       link_speed_mbps=100, status="down", enabled=True, active_sessions=3)
    dst = FleetChrNode(provider_id=prov.id, name="dst", public_ip="1.1.1.2",
                       wg_mgmt_ip="10.99.0.2", wg_mgmt_pubkey="k", max_sessions=100,
                       link_speed_mbps=100, status="up", enabled=True, active_sessions=0)
    db.session.add_all([src, dst])
    db.session.flush()
    db.session.add_all([
        FleetChrHealth(chr_id=src.id, state="down"),
        FleetChrHealth(chr_id=dst.id, state="up"),
        Session(username="u@c", realm="c", chr_id=src.id, framed_ip="10.0.0.1",
                acct_session_id="s1", state="active"),
    ])
    db.session.commit()
    return src


def test_notify_hook_fires_both_rebalance_and_notify(app, monkeypatch):
    src = _seed_down_scenario()

    # Spy on both downstream consumers. _notify_hook imports them locally at call
    # time, so patching the module attribute is honoured.
    fired = {"notify": False, "rebalance": False}
    import fleet.brain.rebalance as reb
    import fleet.notify.notifier as notif

    orig_disp, orig_onmon = notif.dispatch_event, reb.on_monitor_event
    monkeypatch.setattr(notif, "dispatch_event", lambda ev: (fired.__setitem__("notify", True), orig_disp(ev))[1])
    monkeypatch.setattr(reb, "on_monitor_event", lambda ev: (fired.__setitem__("rebalance", True), orig_onmon(ev))[1])

    from fleet.health import monitor
    ev = Event(kind="health_down", severity="crit", chr_id=src.id)
    db.session.add(ev)
    db.session.flush()

    monitor._notify_hook(ev)

    # BOTH downstreams were invoked.
    assert fired["notify"] is True
    assert fired["rebalance"] is True
    # And the rebalance branch actually recorded a forced-evacuation decision.
    assert PlacementDecision.query.count() >= 1


def test_notify_hook_survives_a_failing_consumer(app, monkeypatch):
    """Each consumer is wrapped in its own try/except — one raising must not stop
    the other or break the probe loop."""
    src = _seed_down_scenario()
    import fleet.notify.notifier as notif

    def _boom(_ev):
        raise RuntimeError("notify exploded")

    monkeypatch.setattr(notif, "dispatch_event", _boom)

    from fleet.health import monitor
    ev = Event(kind="health_down", severity="crit", chr_id=src.id)
    db.session.add(ev)
    db.session.flush()

    # Must NOT raise despite the notifier blowing up, and the rebalance branch
    # still runs (decision recorded).
    monitor._notify_hook(ev)
    assert PlacementDecision.query.count() >= 1
