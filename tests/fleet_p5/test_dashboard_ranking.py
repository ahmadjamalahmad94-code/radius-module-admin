"""Phase-5 gate — task C: the dashboard ranking binds to the REAL brain.

After the gate wires ``fleet.brain.__init__`` to re-export ``rank``, the
dashboard's ``ranked_view_for`` must report ``ranking_source == "real"`` (the
ordering came from ``fleet.brain.rank``), not the local ``"fallback"`` stub.
"""
from __future__ import annotations

from app.extensions import db
from fleet.registry.models_chr import FleetChrNode, FleetProvider
from fleet.ui.brain_view import brain_available, ranked_view_for
from fleet.ui.dashboard_data import build_node_views


def _seed_node(name: str = "chr-rank-1", ip: str = "203.0.113.5", mgmt: str = "10.99.0.5") -> FleetChrNode:
    prov = FleetProvider.query.filter_by(name="Contabo").one_or_none()
    if prov is None:
        prov = FleetProvider(name="Contabo", cost_model="open", price_per_tb=0)
        db.session.add(prov)
        db.session.flush()
    node = FleetChrNode(
        provider_id=prov.id, name=name, public_ip=ip,
        wg_mgmt_ip=mgmt, wg_mgmt_pubkey="k",
        max_sessions=1000, link_speed_mbps=1000,
        status="up", enabled=True, drain=False,
    )
    db.session.add(node)
    db.session.commit()
    return node


def test_brain_rank_is_importable_at_package_root(app):
    # The gate re-export (fleet/brain/__init__.py) is what makes this True.
    assert brain_available() is True


def test_dashboard_ranking_source_is_real(app):
    _seed_node()
    views = build_node_views(FleetChrNode.query.all())
    ranking, source = ranked_view_for(views)
    assert source == "real"  # came from fleet.brain.rank, not the local fallback
    assert ranking, "expected at least one ranked node"
    assert ranking[0].source == "real"
