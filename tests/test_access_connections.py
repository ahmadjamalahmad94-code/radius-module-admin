"""Zero-central «اتصالات الوصول» — node-picker UX.

The page is the headline UX of the zero-central work: every provisioning
modal now exposes «على أي عقدة؟», defaulting to the brain's best pick.
This suite pins:

  * the page renders the picker for PPP, IPsec, and WireGuard;
  * the page passes ``fleet_chr_node_id`` to the create endpoints;
  * the chosen node is honoured (the resulting tunnel/peer carries
    ``fleet_chr_node_id``);
  * when no node is picked, the brain auto-picks the best one;
  * the readiness flag (``chr_enabled``) tracks fleet availability —
    not the legacy singleton.
"""
from __future__ import annotations

import pytest

from app.extensions import db
from app.models import Customer, CustomerVpnTunnel, License, Plan, WireguardPeer, utcnow
from app.services import fleet_node_router
from fleet.registry.models_chr import FleetChrNode, FleetProvider


# ─────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────
def _login(client):
    return client.post("/login", data={"username": "admin", "password": "admin12345"})


def _customer(name="ACME"):
    c = Customer(company_name=name, contact_name="O", email=f"o@{name.lower()}",
                 status="active")
    db.session.add(c); db.session.commit()
    return c


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


def _provider():
    p = FleetProvider(name="prov", cost_model="open", price_per_tb=0)
    db.session.add(p); db.session.flush()
    return p


def _fleet_node(prov, *, name, ip, wg, **kw):
    n = FleetChrNode(
        provider_id=prov.id, name=name, public_ip=ip,
        wg_mgmt_ip=wg, wg_mgmt_pubkey="x",
        routeros_api_port=8443, routeros_api_user="hobe-panel",
        routeros_api_password_enc="",
        coa_port=3799, max_sessions=1000, link_speed_mbps=1000,
        status=kw.pop("status", "up"),
        enabled=kw.pop("enabled", True),
        drain=kw.pop("drain", False),
        active_sessions=kw.pop("sessions", 0),
    )
    db.session.add(n); db.session.commit()
    return n


class _StubClient:
    last_host: str = ""
    def __init__(self, host): type(self).last_host = host
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
    def create_wireguard_peer(self, **kw): return {".id": "*W1"}
    def remove_wireguard_peer(self, _id): return None
    # WG infra — return shape the service expects (name + public-key string)
    def ensure_wireguard_interface(self, **kw):
        return {".id": "*WI1", "name": kw.get("name"), "public-key": "SERVER-PUB"}
    def list_wireguard_interfaces(self): return []
    def list_ip_addresses(self): return []
    def add_ip_address(self, **kw): return {}


@pytest.fixture(autouse=True)
def _stub_node_client(monkeypatch):
    _StubClient.last_host = ""
    monkeypatch.setattr(
        fleet_node_router, "build_client_for",
        lambda node: _StubClient(host=(node.public_ip or node.wg_mgmt_ip)),
    )


# ─────────────────────────────────────────────────────────────────────────
# Page render — picker present in every modal
# ─────────────────────────────────────────────────────────────────────────
def test_access_connections_page_renders_node_picker(client, app):
    _login(client)
    prov = _provider()
    _fleet_node(prov, name="chr-mtl", ip="1.2.3.4", wg="10.99.0.4")
    _fleet_node(prov, name="chr-nyc", ip="5.6.7.8", wg="10.99.0.8")
    body = client.get("/admin/access-connections").get_data(as_text=True)

    # Picker text + select are present.
    assert "على أي عقدة؟" in body
    assert 'name="fleet_chr_node_id"' in body
    # Both fleet nodes are listed.
    assert "chr-mtl" in body
    assert "chr-nyc" in body


def test_picker_disabled_when_no_fleet(client, app):
    _login(client)
    body = client.get("/admin/access-connections").get_data(as_text=True)
    assert "لا توجد عقد في الأسطول" in body


# ─────────────────────────────────────────────────────────────────────────
# Form submission — the chosen node is honoured
# ─────────────────────────────────────────────────────────────────────────
def test_ppp_create_targets_explicit_node(client, app):
    _login(client)
    cust = _customer()
    _license(cust)
    prov = _provider()
    a = _fleet_node(prov, name="chr-a", ip="10.0.0.1", wg="10.99.0.1")
    b = _fleet_node(prov, name="chr-b", ip="10.0.0.2", wg="10.99.0.2")

    rv = client.post("/admin/access-connections/ppp", data={
        "customer_id": cust.id,
        "tunnel_type": "sstp",
        "max_connections": "1",
        "fleet_chr_node_id": b.id,
    }, follow_redirects=False)
    assert rv.status_code in (302, 303)

    tunnel = CustomerVpnTunnel.query.order_by(CustomerVpnTunnel.id.desc()).first()
    assert tunnel is not None
    assert tunnel.fleet_chr_node_id == b.id
    assert _StubClient.last_host == b.public_ip


def test_ppp_create_falls_back_to_brain_when_no_pick(client, app):
    _login(client)
    cust = _customer()
    _license(cust)
    prov = _provider()
    busy = _fleet_node(prov, name="chr-busy", ip="10.0.0.1", wg="10.99.0.1",
                       sessions=900)
    best = _fleet_node(prov, name="chr-best", ip="10.0.0.2", wg="10.99.0.2",
                       sessions=10)

    rv = client.post("/admin/access-connections/ppp", data={
        "customer_id": cust.id,
        "tunnel_type": "sstp",
        "max_connections": "1",
        # no fleet_chr_node_id → brain pick
    }, follow_redirects=False)
    assert rv.status_code in (302, 303)
    tunnel = CustomerVpnTunnel.query.order_by(CustomerVpnTunnel.id.desc()).first()
    assert tunnel is not None
    assert tunnel.fleet_chr_node_id == best.id


def test_wireguard_create_stamps_picked_node(client, app):
    _login(client)
    cust = _customer()
    _license(cust)
    prov = _provider()
    a = _fleet_node(prov, name="chr-a", ip="10.0.0.1", wg="10.99.0.1")
    b = _fleet_node(prov, name="chr-b", ip="10.0.0.2", wg="10.99.0.2")

    rv = client.post("/admin/access-connections/wireguard", data={
        "customer_id": cust.id,
        "label": "my-phone",
        "use_preshared": "on",
        "fleet_chr_node_id": b.id,
    }, follow_redirects=False)
    assert rv.status_code in (302, 303)
    peer = WireguardPeer.query.order_by(WireguardPeer.id.desc()).first()
    assert peer is not None
    assert peer.fleet_chr_node_id == b.id


# ─────────────────────────────────────────────────────────────────────────
# Aggregate readiness — replaces the legacy chr_settings.enabled flag
# ─────────────────────────────────────────────────────────────────────────
def test_stats_chr_configured_tracks_fleet_availability(app):
    from app.services import access_connections as ac
    # No nodes → not configured.
    assert ac.stats()["chr_configured"] is False
    prov = _provider()
    _fleet_node(prov, name="chr-1", ip="10.0.0.1", wg="10.99.0.1")
    assert ac.stats()["chr_configured"] is True
