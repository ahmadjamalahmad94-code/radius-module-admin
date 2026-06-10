"""CHR Fleet Phase 8 — orchestrator verification.

Covers:

* **Forced evacuation** — DOWN source: ALL active users move regardless
  of their ``movable`` flag (even immovable users are placed), and the
  ``should_move`` hysteresis is bypassed.
* **Pressure rebalance** — UP-but-stressed source: only ``movable=True``
  users are added to the plan; immovable users land in
  ``skipped_movable``; users still under cooldown land in
  ``skipped_hysteresis``.
* **Headroom / per-target cap** — even if the brain says "send them
  all to the best target", the planner spreads them across the
  ``max_moves_per_target_per_plan`` window.
* **Insufficient capacity** — when the fleet's spare seats are below
  ``insufficient_capacity_pct`` of the source's active sessions, the
  plan is truncated and ``capacity_warning=True``; ``execute_rebalance``
  emits a ``cap_warn`` event.
* **execute_rebalance** records ``failover_start`` /
  ``failover_done`` events, one PlacementDecision per intended move,
  and calls a reconcile-fn hook.
* **Auto-trigger** — :func:`on_monitor_event` does its work only on
  ``health_down`` and only when ``auto_failover_on_down`` is True.
* **Sensor safety** — the monitor's ``_notify_hook`` swallows
  orchestrator exceptions so a buggy plan never breaks the sensor loop.
"""
from __future__ import annotations

import dataclasses
from datetime import datetime, timedelta
from unittest.mock import patch

import pytest

from app.extensions import db

from fleet.brain.models_session import (
    PlacementDecision,
    Session,
    UserFleet,
)
from fleet.brain.rebalance import (
    ExecuteResult,
    FailoverTrigger,
    IntendedMove,
    PressureTrigger,
    RebalancePlan,
    execute_rebalance,
    on_monitor_event,
    plan_rebalance,
)
from fleet.config import FLEET, FleetConfig, OrchestratorConfig
from fleet.health.models_health import FleetChrHealth
from fleet.notify.models_alert import Event
from fleet.registry.models_chr import FleetChrNode, FleetProvider


# ════════════════════════════════════════════════════════════════════════
# Fixtures
# ════════════════════════════════════════════════════════════════════════


_NODE_SEQ: list[int] = [0]


def _provider() -> FleetProvider:
    p = FleetProvider.query.first()
    if p is not None:
        return p
    p = FleetProvider(
        name="acme-p8", cost_model="open", price_per_tb=0,
        overage_allowed=False, billing_cycle_day=1,
    )
    db.session.add(p); db.session.commit()
    return p


def _node(name: str, *, max_sessions: int = 1000, cpu: float = 20.0,
          status: str = "up", health_state: str = "up",
          active: int = 0) -> FleetChrNode:
    _NODE_SEQ[0] += 1
    h = _NODE_SEQ[0]
    n = FleetChrNode(
        provider_id=_provider().id, name=name,
        public_ip=f"203.0.113.{h}", wg_mgmt_ip=f"10.99.0.{h}",
        wg_mgmt_pubkey="x" * 44,
        max_sessions=max_sessions, link_speed_mbps=1000,
        weight=1.0, enabled=True, status=status,
        cpu_pct=cpu, active_sessions=active,
    )
    db.session.add(n); db.session.commit()
    # Health row so rank() can read state.
    hr = FleetChrHealth(
        chr_id=n.id, state=health_state,
        state_since=datetime(2026, 6, 10),
    )
    db.session.add(hr); db.session.commit()
    return n


def _user(username: str, *, movable: bool, customer_id: int = 1) -> UserFleet:
    u = UserFleet(
        customer_id=customer_id,
        realm=username.split("@", 1)[1] if "@" in username else "x",
        username=username, movable=movable,
    )
    db.session.add(u); db.session.commit()
    return u


def _session(*, username: str, chr_id: int,
             framed_ip: str, acct: str | None = None,
             started_at: datetime | None = None) -> Session:
    s = Session(
        username=username,
        realm=username.split("@", 1)[1] if "@" in username else "x",
        chr_id=chr_id, framed_ip=framed_ip,
        acct_session_id=(acct or f"acct-{username}-{chr_id}"),
        state="active",
        started_at=(started_at or datetime(2026, 6, 10, 12, 0, 0)),
    )
    db.session.add(s); db.session.commit()
    return s


# ════════════════════════════════════════════════════════════════════════
# 1. Forced evacuation — ignores movable + hysteresis
# ════════════════════════════════════════════════════════════════════════


def test_forced_evac_moves_all_users_regardless_of_movable(app):
    src = _node("chr-down", status="down", health_state="down")
    dst = _node("chr-up", active=20)

    # Mix of movable and immovable users on the dying source.
    _user("alice@c", movable=True)
    _user("bob@c", movable=False)
    _user("carol@c", movable=False)
    _session(username="alice@c", chr_id=src.id, framed_ip="10.0.0.1")
    _session(username="bob@c",   chr_id=src.id, framed_ip="10.0.0.2")
    _session(username="carol@c", chr_id=src.id, framed_ip="10.0.0.3")

    plan = plan_rebalance(FailoverTrigger(
        source_chr_id=src.id, source_name=src.name, reason="node_down",
    ))

    # All three users are in the plan even though two are immovable.
    assert {m.username for m in plan.moves} == {"alice@c", "bob@c", "carol@c"}
    # None landed in skipped_movable for a failover trigger.
    assert plan.skipped_movable == ()
    assert plan.skipped_hysteresis == ()
    # All moves are flagged movable_required=False (audit trail).
    assert all(m.movable_required is False for m in plan.moves)
    # Every move targets the surviving healthy node.
    assert {m.to_chr_id for m in plan.moves} == {dst.id}


def test_forced_evac_bypasses_should_move_cooldown(app):
    """A user moved 1 second ago is still relocated when the source dies."""
    src = _node("chr-fail", status="down", health_state="down")
    dst = _node("chr-target", active=5)
    _user("alice@c", movable=True)
    _session(username="alice@c", chr_id=src.id, framed_ip="10.0.0.1")
    # A very recent previous move — would block a pressure rebalance.
    db.session.add(PlacementDecision(
        username="alice@c", decided_at=datetime(2026, 6, 10, 11, 59, 50),
        kind="rebalance", outcome="applied",
    ))
    db.session.commit()

    plan = plan_rebalance(
        FailoverTrigger(source_chr_id=src.id, source_name=src.name),
        now=datetime(2026, 6, 10, 12, 0, 0),
    )
    assert [m.username for m in plan.moves] == ["alice@c"]


# ════════════════════════════════════════════════════════════════════════
# 2. Pressure rebalance — movable-only + hysteresis
# ════════════════════════════════════════════════════════════════════════


def test_pressure_rebalance_moves_only_movable_users(app):
    """Stressed-but-still-up source: immovable users stay put."""
    src = _node("chr-hot", cpu=85.0, active=10)  # over shed
    dst = _node("chr-cool", cpu=20.0, active=5)

    _user("alice@c", movable=True)
    _user("bob@c",   movable=False)
    _session(username="alice@c", chr_id=src.id, framed_ip="10.0.0.1")
    _session(username="bob@c",   chr_id=src.id, framed_ip="10.0.0.2")

    plan = plan_rebalance(PressureTrigger(
        source_chr_id=src.id, source_name=src.name, reason="cpu_shed",
    ))
    assert [m.username for m in plan.moves] == ["alice@c"]
    assert plan.skipped_movable == ("bob@c",)
    # Pressure path flags every queued move as movable_required=True.
    assert all(m.movable_required is True for m in plan.moves)


def test_pressure_rebalance_respects_cooldown_hysteresis(app):
    """A movable user inside the cooldown window is skipped."""
    src = _node("chr-hot", cpu=85.0, active=10)
    _node("chr-cool", cpu=20.0, active=5)
    _user("alice@c", movable=True)
    _session(username="alice@c", chr_id=src.id, framed_ip="10.0.0.1")
    # Just moved 10 seconds ago — well inside the 600-s cooldown.
    db.session.add(PlacementDecision(
        username="alice@c", decided_at=datetime(2026, 6, 10, 12, 0, 0),
        kind="rebalance", outcome="applied",
    ))
    db.session.commit()

    plan = plan_rebalance(
        PressureTrigger(source_chr_id=src.id, source_name=src.name),
        now=datetime(2026, 6, 10, 12, 0, 10),
    )
    assert plan.moves == ()
    assert plan.skipped_hysteresis == ("alice@c",)


# ════════════════════════════════════════════════════════════════════════
# 3. Headroom / thundering-herd
# ════════════════════════════════════════════════════════════════════════


def test_per_target_cap_staggers_assignments_across_targets(app):
    """Even with one obvious 'best' target, the planner spreads moves
    across multiple targets up to ``max_moves_per_target_per_plan``."""
    src = _node("chr-failing", status="down", health_state="down")
    # Two healthy targets — the first is "best" by score, but the
    # planner must spread once the per-target cap is reached.
    dst1 = _node("chr-target-1", active=0)
    dst2 = _node("chr-target-2", active=0)

    # Override the per-target cap to a tiny value so the test reaches
    # the boundary without having to seed 11 sessions.
    cfg = FleetConfig(
        orchestrator=dataclasses.replace(
            FLEET.orchestrator,
            max_moves_per_target_per_plan=2,
        )
    )
    for i in range(5):
        _user(f"u{i}@c", movable=False)
        _session(username=f"u{i}@c", chr_id=src.id,
                 framed_ip=f"10.0.0.{i}",
                 acct=f"a{i}")

    plan = plan_rebalance(FailoverTrigger(
        source_chr_id=src.id, source_name=src.name,
    ), cfg=cfg)
    # 5 users, 2 targets, cap=2/target → 4 moves planned + 1 skipped.
    moves_per_target: dict[int, int] = {}
    for m in plan.moves:
        moves_per_target[m.to_chr_id] = moves_per_target.get(m.to_chr_id, 0) + 1
    assert all(v <= 2 for v in moves_per_target.values())
    assert len(plan.moves) == 4
    assert len(plan.skipped_capacity) == 1
    assert plan.capacity_warning is True


def test_target_min_free_pct_blocks_over_packing(app):
    """A target near its own capacity stops receiving once the
    post-plan free percentage would dip below the threshold."""
    src = _node("chr-down", status="down", health_state="down")
    # Target with max=10 and 8 already active → 2 free seats. With
    # min-free=10% the target accepts 1 more (post=9 active → 10% free).
    dst = _node("chr-tiny", max_sessions=10, active=8)

    # Seed actual session rows so spare math reflects reality.
    for i in range(8):
        # Sessions on OTHER nodes are not relevant; create on src that we will be moving.
        pass
    for i in range(3):
        _user(f"v{i}@c", movable=False)
        _session(username=f"v{i}@c", chr_id=src.id,
                 framed_ip=f"10.0.1.{i}")
    # Seed live active load on the target.
    for i in range(8):
        u = _user(f"existing{i}@c", movable=False)
        _session(username=f"existing{i}@c", chr_id=dst.id,
                 framed_ip=f"10.99.{i}.1", acct=f"t-{i}")

    cfg = FleetConfig(orchestrator=dataclasses.replace(
        FLEET.orchestrator, target_min_free_pct=10.0,
    ))
    plan = plan_rebalance(FailoverTrigger(
        source_chr_id=src.id, source_name=src.name,
    ), cfg=cfg)
    # Only one of the three source users fits before min-free is hit.
    assert len(plan.moves) == 1
    assert len(plan.skipped_capacity) == 2
    assert plan.capacity_warning is True


# ════════════════════════════════════════════════════════════════════════
# 4. Insufficient capacity warning
# ════════════════════════════════════════════════════════════════════════


def test_insufficient_capacity_truncates_and_warns(app):
    """When the spare capacity is well below the source's active count,
    the planner truncates and ``capacity_warning`` fires."""
    src = _node("chr-dying", status="down", health_state="down")
    # Single target with only 2 free seats (max 10, 8 active already).
    dst = _node("chr-narrow", max_sessions=10, active=8)
    for i in range(8):
        u = _user(f"e{i}@c", movable=False)
        _session(username=f"e{i}@c", chr_id=dst.id,
                 framed_ip=f"10.50.{i}.1", acct=f"e-{i}")
    # 10 source users — fleet spare (2) is FAR below 50% of 10 = 5.
    for i in range(10):
        _user(f"x{i}@c", movable=False)
        _session(username=f"x{i}@c", chr_id=src.id,
                 framed_ip=f"10.7.0.{i}", acct=f"s-{i}")

    plan = plan_rebalance(FailoverTrigger(
        source_chr_id=src.id, source_name=src.name,
    ))
    # Plan is truncated to whatever fits; spare was 2, so at most 1 fit
    # before min-free=10% blocks more.
    assert len(plan.moves) <= 2
    assert plan.capacity_warning is True
    assert plan.skipped_capacity, "expected some users to land in skipped_capacity"


# ════════════════════════════════════════════════════════════════════════
# 5. execute_rebalance — events + decisions + reconcile hook
# ════════════════════════════════════════════════════════════════════════


def test_execute_records_decisions_events_and_calls_reconcile(app):
    src = _node("chr-evac", status="down", health_state="down")
    dst = _node("chr-survivor", active=10)
    _user("alice@c", movable=False)
    _user("bob@c", movable=False)
    _session(username="alice@c", chr_id=src.id, framed_ip="10.0.0.1")
    _session(username="bob@c",   chr_id=src.id, framed_ip="10.0.0.2")

    plan = plan_rebalance(FailoverTrigger(
        source_chr_id=src.id, source_name=src.name, reason="node_down",
    ))
    assert len(plan.moves) == 2

    reconcile_calls = []
    def fake_reconcile():
        reconcile_calls.append(1)
        return {"ok": True}

    result = execute_rebalance(plan, reconcile_fn=fake_reconcile)

    # One PlacementDecision per intended move.
    assert len(result.decision_ids) == 2
    fresh = (
        PlacementDecision.query
        .filter(PlacementDecision.id.in_(result.decision_ids)).all()
    )
    assert {pd.kind for pd in fresh} == {"forced_failover"}
    assert {pd.outcome for pd in fresh} == {"pending"}
    assert all(pd.from_chr_id == src.id for pd in fresh)
    assert all(pd.to_chr_id == dst.id for pd in fresh)

    # failover_start + failover_done events on the source chr_id.
    kinds = {ev.kind for ev in Event.query.filter(
        Event.id.in_(result.event_ids)).all()}
    assert "failover_start" in kinds and "failover_done" in kinds

    # Reconcile was called exactly once.
    assert result.reconcile_called is True
    assert reconcile_calls == [1]


def test_execute_emits_cap_warn_when_plan_truncates(app):
    src = _node("chr-dead", status="down", health_state="down")
    dst = _node("chr-tiny", max_sessions=2, active=2)
    for i in range(2):
        u = _user(f"pre{i}@c", movable=False)
        _session(username=f"pre{i}@c", chr_id=dst.id,
                 framed_ip=f"10.10.{i}.1", acct=f"p-{i}")
    for i in range(3):
        _user(f"src{i}@c", movable=False)
        _session(username=f"src{i}@c", chr_id=src.id,
                 framed_ip=f"10.20.{i}.1", acct=f"src-{i}")

    plan = plan_rebalance(FailoverTrigger(
        source_chr_id=src.id, source_name=src.name,
    ))
    assert plan.capacity_warning is True

    result = execute_rebalance(plan, reconcile_fn=lambda: None)
    warn_events = Event.query.filter(Event.kind == "cap_warn").all()
    assert warn_events, "expected at least one cap_warn event"


def test_execute_overwrites_pending_decision_for_same_user(app):
    """Re-running the same trigger replaces the pending decision rather
    than creating a duplicate row."""
    src = _node("chr-rep", status="down", health_state="down")
    dst = _node("chr-fresh", active=0)
    _user("alice@c", movable=False)
    _session(username="alice@c", chr_id=src.id, framed_ip="10.0.0.1")

    plan = plan_rebalance(FailoverTrigger(
        source_chr_id=src.id, source_name=src.name,
    ))
    r1 = execute_rebalance(plan, reconcile_fn=lambda: None)
    r2 = execute_rebalance(plan, reconcile_fn=lambda: None)
    pending_rows = PlacementDecision.query.filter_by(
        username="alice@c", outcome="pending").all()
    assert len(pending_rows) == 1


def test_execute_survives_reconcile_failure(app):
    src = _node("chr-x", status="down", health_state="down")
    dst = _node("chr-y", active=5)
    _user("alice@c", movable=False)
    _session(username="alice@c", chr_id=src.id, framed_ip="10.0.0.1")

    plan = plan_rebalance(FailoverTrigger(
        source_chr_id=src.id, source_name=src.name,
    ))
    def broken():
        raise RuntimeError("DNS provider down")
    result = execute_rebalance(plan, reconcile_fn=broken)
    assert result.reconcile_called is False
    assert result.reconcile_error == "RuntimeError"
    # Decisions still persisted.
    assert PlacementDecision.query.filter_by(username="alice@c").count() == 1


# ════════════════════════════════════════════════════════════════════════
# 6. Auto-trigger from the monitor
# ════════════════════════════════════════════════════════════════════════


def test_on_monitor_event_runs_only_on_health_down(app):
    """``health_up`` events do nothing; ``health_down`` produces a plan."""
    src = _node("chr-mon-x", status="down", health_state="down")
    dst = _node("chr-mon-y", active=5)
    _user("alice@c", movable=False)
    _session(username="alice@c", chr_id=src.id, framed_ip="10.0.0.1")

    up_ev = Event(chr_id=src.id, kind="health_up", severity="info")
    up_ev.detail = {}
    db.session.add(up_ev); db.session.commit()
    assert on_monitor_event(up_ev) is None

    # ``health_down`` triggers the orchestrator.
    down_ev = Event(chr_id=src.id, kind="health_down", severity="crit")
    down_ev.detail = {"from_state": "up", "to_state": "down"}
    db.session.add(down_ev); db.session.commit()
    result = on_monitor_event(down_ev)
    assert isinstance(result, ExecuteResult)
    assert len(result.decision_ids) == 1


def test_monitor_hook_swallows_orchestrator_exceptions(app):
    """``_notify_hook`` must keep the sensor loop alive even when the
    orchestrator raises (P8 instability cannot stop P4 metric writes)."""
    from fleet.health import monitor as mon

    with patch.object(mon, "_notify_hook", wraps=mon._notify_hook) as spy:
        # Build a synthetic event that would normally invoke the
        # orchestrator. Monkeypatch the orchestrator to raise.
        with patch(
            "fleet.brain.rebalance.on_monitor_event",
            side_effect=RuntimeError("orchestrator bug"),
        ):
            ev = Event(chr_id=1, kind="health_down", severity="crit")
            ev.detail = {}
            # This must NOT raise out of _notify_hook.
            mon._notify_hook(ev)
        assert spy.called


def test_auto_failover_disabled_short_circuits(app):
    """When ``OrchestratorConfig.auto_failover_on_down`` is False the
    monitor hook is a no-op."""
    # Monkeypatch FLEET to a config with the flag off.
    from fleet.brain import rebalance as r

    src = _node("chr-flag-off", status="down", health_state="down")
    _user("alice@c", movable=False)
    _session(username="alice@c", chr_id=src.id, framed_ip="10.0.0.1")
    ev = Event(chr_id=src.id, kind="health_down", severity="crit")
    ev.detail = {}
    db.session.add(ev); db.session.commit()

    disabled = FleetConfig(orchestrator=dataclasses.replace(
        FLEET.orchestrator, auto_failover_on_down=False,
    ))
    with patch.object(r, "FLEET", disabled):
        assert on_monitor_event(ev) is None
    # No decisions were created.
    assert PlacementDecision.query.filter_by(username="alice@c").count() == 0


# ════════════════════════════════════════════════════════════════════════
# 7. Smoke
# ════════════════════════════════════════════════════════════════════════


def test_create_app_boots(app):
    from sqlalchemy import inspect
    tables = set(inspect(db.engine).get_table_names())
    assert {"fleet_chr_nodes", "fleet_users", "fleet_sessions",
            "fleet_placement_decisions", "fleet_events",
            "fleet_chr_health"}.issubset(tables)
