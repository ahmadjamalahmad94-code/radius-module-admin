"""Phase-8 gate — the REAL engine drives the dashboard via the string-trigger
convenience layer (ORCHESTRATOR_BACKEND == "real").

The UI adapter calls plan_rebalance("manual") with a STRING trigger and expects a
plan whose moves carry node NAMES. The gate bridge maps that to the frozen engine
(object trigger) and enriches the plan; execute stamps plan_id/trigger/source_node
into fleet_placement_decisions.reason_json.
"""
from __future__ import annotations

from app.extensions import db
from fleet.brain import orchestrator_adapter as ad
from fleet.brain.models_session import PlacementDecision, Session, UserFleet
from fleet.health.models_health import FleetChrHealth
from fleet.registry.models_chr import FleetChrNode, FleetProvider


def _seed_pressure_scenario() -> None:
    prov = FleetProvider(name="Contabo", cost_model="open", price_per_tb=0)
    db.session.add(prov)
    db.session.flush()
    src = FleetChrNode(provider_id=prov.id, name="chr-src", public_ip="203.0.113.1",
                       wg_mgmt_ip="10.99.0.1", wg_mgmt_pubkey="k", max_sessions=1000,
                       link_speed_mbps=1000, status="up", enabled=True, active_sessions=5)
    dst = FleetChrNode(provider_id=prov.id, name="chr-dst", public_ip="203.0.113.2",
                       wg_mgmt_ip="10.99.0.2", wg_mgmt_pubkey="k", max_sessions=1000,
                       link_speed_mbps=1000, status="up", enabled=True, active_sessions=0)
    db.session.add_all([src, dst])
    db.session.flush()
    db.session.add_all([
        FleetChrHealth(chr_id=src.id, state="up"),
        FleetChrHealth(chr_id=dst.id, state="up"),
        UserFleet(customer_id=1, realm="c5", username="bob@c5", movable=True),
        Session(username="bob@c5", realm="c5", chr_id=src.id, framed_ip="10.0.0.9",
                acct_session_id="s1", state="active"),
    ])
    db.session.commit()


def test_string_trigger_manual_plan_drives_real_engine(app):
    _seed_pressure_scenario()

    plan = ad.plan_rebalance("manual")

    # The real engine — not the stub — produced this plan.
    assert ad.ORCHESTRATOR_BACKEND == "real"
    assert ad.is_available() is True
    assert plan.kind == "rebalance"
    assert plan.source_node == "chr-src"
    assert plan.estimate_summary  # non-empty human description
    # A movable user on the busy source is moved to the idle target — node NAMES.
    assert len(plan.moves) == 1
    mv = plan.moves[0]
    assert mv.username == "bob@c5"
    assert mv.realm == "c5"
    assert mv.from_node == "chr-src"
    assert mv.to_node == "chr-dst"


def test_execute_records_decisions_and_stamps_reason(app):
    _seed_pressure_scenario()
    plan = ad.plan_rebalance("manual")

    result = ad.execute_rebalance(plan)

    assert result.plan_id == plan.plan_id
    assert result.applied is True
    assert result.moves_attempted == 1
    assert result.moves_applied == 1
    # The audit row carries plan_id / trigger / source_node so the «آخر الخطط»
    # dashboard aggregation can group by plan.
    pd = PlacementDecision.query.filter_by(username="bob@c5").first()
    assert pd is not None
    assert pd.reason["plan_id"] == plan.plan_id
    assert pd.reason["trigger"] == "manual"
    assert pd.reason["source_node"] == "chr-src"


def test_forced_failover_string_trigger(app):
    _seed_pressure_scenario()
    # Evacuate the source node by name — forced failover ignores the movable flag.
    plan = ad.plan_forced_failover("chr-src")
    assert ad.ORCHESTRATOR_BACKEND == "real"
    assert plan.kind == "forced_failover"
    assert plan.source_node == "chr-src"
    assert len(plan.moves) == 1 and plan.moves[0].to_node == "chr-dst"
