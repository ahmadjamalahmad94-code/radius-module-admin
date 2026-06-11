"""Auto peer registration is correct + idempotent, and eligibility exactly
mirrors the routing-table (drain/disabled excluded)."""
from __future__ import annotations

from app.extensions import db

from tests.fleet_zero_touch.conftest import _pk, make_node, make_provider


def test_desired_sets_are_idempotent(zt):
    prov = make_provider()
    make_node(prov, "chr-a", octet=11)
    make_node(prov, "chr-b", octet=12)
    db.session.commit()

    from fleet.sync.peers import desired_panel_peers, desired_proxy_peers
    a1 = [p.to_dict() for p in desired_panel_peers()]
    a2 = [p.to_dict() for p in desired_panel_peers()]
    b1 = [p.to_dict() for p in desired_proxy_peers()]
    b2 = [p.to_dict() for p in desired_proxy_peers()]
    assert a1 == a2 and b1 == b2
    assert [p["address"] for p in a1] == ["10.99.0.11", "10.99.0.12"]
    assert [p["address"] for p in b1] == ["10.98.0.11", "10.98.0.12"]
    assert a1[0]["allowed_ips"] == ["10.99.0.11/32"]
    assert b1[0]["allowed_ips"] == ["10.98.0.11/32"]


def test_drain_and_disabled_excluded(zt):
    prov = make_provider()
    make_node(prov, "ok", octet=11)
    make_node(prov, "drained", octet=12, drain=True)
    make_node(prov, "disabled", octet=13, status="disabled")
    make_node(prov, "off", octet=14, enabled=False)
    db.session.commit()

    from fleet.sync.peers import desired_panel_peers, desired_proxy_peers
    assert [p.name for p in desired_panel_peers()] == ["ok"]
    assert [p.name for p in desired_proxy_peers()] == ["ok"]


def test_proxy_peer_requires_data_pubkey(zt):
    prov = make_provider()
    make_node(prov, "has-data", octet=11)
    make_node(prov, "no-data", octet=12, data_pub="")  # missing wg-data pubkey
    db.session.commit()

    from fleet.sync.peers import desired_proxy_peers, desired_panel_peers
    # proxy peer omitted when data pubkey missing; panel peer still present.
    assert [p.name for p in desired_proxy_peers()] == ["has-data"]
    assert {p.name for p in desired_panel_peers()} == {"has-data", "no-data"}


def test_apply_panel_peers_safe_without_helper(zt):
    """No scoped helper installed → reported no-op, never raises, never shells."""
    prov = make_provider()
    make_node(prov, "ok", octet=11)
    db.session.commit()

    from fleet.sync.peers import desired_panel_peers
    from fleet.sync.wg_apply import apply_panel_peers
    res = apply_panel_peers(desired_panel_peers())
    assert res.available is False
    assert res.applied is False
    assert res.desired_count == 1
