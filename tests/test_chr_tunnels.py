"""Zero-central tunnel provisioning — VPN tunnels target a FleetChrNode.

The pre-zero-central tests in this file pinned the singleton
``chr_settings`` lifecycle (validate_and_save / lock / unlock / reveal /
test_connection). All of that is gone now: there's no singleton, and
every tunnel is provisioned on a specific fleet node either chosen by
the operator or auto-picked by the fleet brain.

What this suite pins:
  * provision_tunnel() picks the brain's best-eligible node when no
    explicit choice is given;
  * provision_tunnel() uses the operator's explicit choice when given;
  * the resulting CustomerVpnTunnel stamps the fleet_chr_node_id FK;
  * no node available → a clean Arabic error (no_fleet_node) bubbles up;
  * serialize_tunnel() returns the picked node's public_host + service
    port (not a global singleton).
"""
from __future__ import annotations

import pytest

from app.extensions import db
from app.models import Customer, License, Plan, utcnow
from app.services import vpn_tunnels as vt
from fleet.registry.models_chr import FleetChrNode, FleetProvider


# ─────────────────────────────────────────────────────────────────────────
# Test helpers
# ─────────────────────────────────────────────────────────────────────────
def _customer():
    c = Customer(
        company_name="ACME", contact_name="O", email="o@acme",
        status="active",
    )
    db.session.add(c); db.session.commit()
    return c


def _provider():
    p = FleetProvider(name="prov-test", cost_model="open", price_per_tb=0)
    db.session.add(p); db.session.flush()
    return p


def _fleet_node(prov, *, name="chr-1", public_ip="1.2.3.4", wg="10.99.0.11",
                status="up", enabled=True, drain=False, sessions=0):
    n = FleetChrNode(
        provider_id=prov.id, name=name, public_ip=public_ip,
        wg_mgmt_ip=wg, wg_mgmt_pubkey="pubkey",
        routeros_api_port=8443, routeros_api_user="hobe-panel",
        routeros_api_password_enc="",
        coa_port=3799, max_sessions=1000, link_speed_mbps=1000,
        status=status, enabled=enabled, drain=drain,
        active_sessions=sessions,
    )
    db.session.add(n); db.session.commit()
    return n


def _license(customer):
    from datetime import timedelta
    plan = Plan.query.first()
    if not plan:
        plan = Plan(name="basic", slug="basic")
        db.session.add(plan); db.session.flush()
    now = utcnow()
    lic = License(
        customer_id=customer.id, plan_id=plan.id,
        license_key=f"LIC-{customer.id}", status="active",
        starts_at=now, expires_at=now + timedelta(days=30),
        grace_until=now + timedelta(days=37),
    )
    db.session.add(lic); db.session.commit()
    return lic


class _StubClient:
    last_host: str = ""

    def __init__(self, **kw):
        type(self).last_host = kw.get("host", "")

    def ensure_ip_pool(self, **kw): return {}
    def ensure_ppp_profile(self, **kw): return {}
    def create_ppp_secret(self, **kw): return {".id": "*A1"}
    def remove_ppp_secret(self, _id): return None
    def ensure_ipsec_mode_config(self, **kw): return {}
    def ensure_ipsec_peer(self, **kw): return {}
    def ensure_ipsec_identity(self, **kw): return {}
    def find_ipsec_user(self, name): return None
    def create_ipsec_user(self, **kw): return {".id": "*B1"}
    def remove_ipsec_user(self, _id): return None


@pytest.fixture(autouse=True)
def _stub_node_client(monkeypatch):
    from app.services import fleet_node_router
    _StubClient.last_host = ""

    def _build(node):
        return _StubClient(host=(node.public_ip or node.wg_mgmt_ip))
    monkeypatch.setattr(fleet_node_router, "build_client_for", _build)


# ─────────────────────────────────────────────────────────────────────────
# Brain auto-pick chooses the best-eligible node
# ─────────────────────────────────────────────────────────────────────────
def test_provision_picks_brain_best_node_when_no_explicit_choice(app):
    cust = _customer()
    lic = _license(cust)
    prov = _provider()
    busy = _fleet_node(prov, name="chr-busy", public_ip="10.0.0.1",
                       wg="10.99.0.1", sessions=900)
    best = _fleet_node(prov, name="chr-best", public_ip="10.0.0.2",
                       wg="10.99.0.2", sessions=10)

    tunnel = vt.provision_tunnel(
        cust, lic, tunnel_type="sstp", max_connections=1,
        source="admin_manual", enforce_allowance=False,
    )
    db.session.commit()

    assert tunnel.fleet_chr_node_id == best.id, (
        f"expected best=chr-best (id={best.id}) but tunnel stamped {tunnel.fleet_chr_node_id}"
    )
    assert _StubClient.last_host == best.public_ip


def test_provision_honours_explicit_fleet_chr_node_id(app):
    cust = _customer()
    lic = _license(cust)
    prov = _provider()
    a = _fleet_node(prov, name="chr-a", public_ip="10.0.0.1", wg="10.99.0.1")
    b = _fleet_node(prov, name="chr-b", public_ip="10.0.0.2", wg="10.99.0.2")
    tunnel = vt.provision_tunnel(
        cust, lic, tunnel_type="sstp", max_connections=1,
        source="admin_manual", enforce_allowance=False,
        fleet_chr_node_id=b.id,
    )
    db.session.commit()
    assert tunnel.fleet_chr_node_id == b.id
    assert _StubClient.last_host == b.public_ip


def test_provision_fails_cleanly_when_no_fleet_node(app):
    cust = _customer()
    lic = _license(cust)
    with pytest.raises(vt.VpnTunnelError) as ei:
        vt.provision_tunnel(
            cust, lic, tunnel_type="sstp", max_connections=1,
            source="admin_manual", enforce_allowance=False,
        )
    assert ei.value.code == "no_fleet_node"
    assert "الأسطول" in str(ei.value)


def test_disabled_node_is_skipped_by_brain(app):
    cust = _customer()
    lic = _license(cust)
    prov = _provider()
    _fleet_node(prov, name="chr-disabled", public_ip="10.0.0.1",
                wg="10.99.0.1", enabled=False)
    good = _fleet_node(prov, name="chr-good", public_ip="10.0.0.2",
                       wg="10.99.0.2")
    tunnel = vt.provision_tunnel(
        cust, lic, tunnel_type="sstp", max_connections=1,
        source="admin_manual", enforce_allowance=False,
    )
    db.session.commit()
    assert tunnel.fleet_chr_node_id == good.id


# ─────────────────────────────────────────────────────────────────────────
# Serialisation reflects the per-node endpoint
# ─────────────────────────────────────────────────────────────────────────
def test_serialize_uses_node_public_ip(app):
    cust = _customer()
    lic = _license(cust)
    prov = _provider()
    node = _fleet_node(prov, name="chr-srv", public_ip="203.0.113.99",
                       wg="10.99.0.99")
    tunnel = vt.provision_tunnel(
        cust, lic, tunnel_type="sstp", max_connections=1,
        source="admin_manual", enforce_allowance=False,
    )
    db.session.commit()
    data = vt.serialize_tunnel(tunnel, include_password=False)
    assert data["chr_host"] == "203.0.113.99"
    assert data["chr_public_host"] == "203.0.113.99"
    assert data["service_port"] == 443
    assert data["chr_node_name"] == "chr-srv"
