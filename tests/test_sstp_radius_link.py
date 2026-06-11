"""SSTP = RADIUS-transport link — architectural intent guard.

The SSTP tunnel created via /admin/access-connections is NOT a generic
customer VPN: it is the transport that carries RADIUS auth/acct/CoA
traffic between the subscriber's MikroTik and the customer's RADIUS VPS.

This suite pins:

  * the SSTP protocol descriptor names the role explicitly («رابط RADIUS»);
  * the SSTP modal title + subtitle describe the RADIUS-transport role
    (so operators don't mistake it for a plain VPN);
  * radius_link_preview() audits the whole chain:
      customer → CustomerRadiusInstance → ProxyRealmRoute → fleet
      node in allow-list, and returns Arabic operator-facing messages;
  * the create endpoint flashes a warning (does NOT block) when the
    chain is incomplete, so the operator can stage things in any order;
  * serialize_tunnel() emits a ``radius_link`` block on SSTP rows with
    the realm + RADIUS target + a subscriber-MikroTik usage hint;
  * NON-SSTP tunnel types do NOT get the ``radius_link`` block (it's
    specific to the RADIUS-transport role).
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from app.extensions import db
from app.models import (
    Customer, CustomerRadiusInstance, License, Plan, ProxyRealmRoute, utcnow,
)
from app.services import access_connections as ac
from app.services import fleet_node_router, vpn_tunnels as vt
from fleet.registry.models_chr import FleetChrNode, FleetProvider


# ─────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────
def _login_admin(client):
    return client.post("/login", data={"username": "admin", "password": "admin12345"})


def _customer(name="ClientFive"):
    c = Customer(company_name=name, contact_name="O", email=f"o@{name.lower()}",
                 status="active")
    db.session.add(c); db.session.commit()
    return c


def _license(customer):
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


def _radius_instance(customer, realm="client5", auth_ip="10.250.0.5"):
    inst = CustomerRadiusInstance(
        customer_id=customer.id, instance_name=f"{realm}-radius",
        mgmt_wg_ip=auth_ip, radius_auth_ip=auth_ip,
        radius_auth_port=1812, radius_acct_port=1813,
        realm=realm, secret_vault_ref="", status="online",
    )
    db.session.add(inst); db.session.commit()
    return inst


def _proxy_route(customer, instance, fleet_node_ids, status="active"):
    r = ProxyRealmRoute(
        realm=instance.realm, customer_id=customer.id,
        radius_instance_id=instance.id, target_radius_ip=instance.radius_auth_ip,
        target_auth_port=instance.radius_auth_port,
        target_acct_port=instance.radius_acct_port,
        status=status, secret_vault_ref="",
    )
    r.allowed_fleet_chr_node_ids = list(fleet_node_ids)
    db.session.add(r); db.session.commit()
    return r


def _provider():
    p = FleetProvider(name="prov", cost_model="open", price_per_tb=0)
    db.session.add(p); db.session.flush()
    return p


def _fleet_node(prov, *, name="chr-1", ip="1.2.3.4", wg="10.99.0.11"):
    n = FleetChrNode(
        provider_id=prov.id, name=name, public_ip=ip,
        wg_mgmt_ip=wg, wg_mgmt_pubkey="x",
        routeros_api_port=8443, routeros_api_user="hobe-panel",
        routeros_api_password_enc="",
        coa_port=3799, max_sessions=1000, link_speed_mbps=1000,
        status="up", enabled=True, drain=False,
    )
    db.session.add(n); db.session.commit()
    return n


class _StubClient:
    def __init__(self, **kw): pass
    def ensure_ip_pool(self, **kw): return {}
    def ensure_ppp_profile(self, **kw): return {}
    def create_ppp_secret(self, **kw): return {".id": "*A1"}
    def remove_ppp_secret(self, _id): return None


@pytest.fixture(autouse=True)
def _stub_node_client(monkeypatch):
    monkeypatch.setattr(
        fleet_node_router, "build_client_for",
        lambda node: _StubClient(host=(node.public_ip or node.wg_mgmt_ip)),
    )


# ─────────────────────────────────────────────────────────────────────────
# Descriptor + modal copy
# ─────────────────────────────────────────────────────────────────────────
def test_sstp_descriptor_names_the_radius_transport_role():
    assert "رابط RADIUS" in ac.PROTOCOLS["sstp"].name, (
        "SSTP card must call out the RADIUS-transport role in its name "
        "so the operator doesn't reach for it as a generic VPN."
    )
    assert "RADIUS" in ac.PROTOCOLS["sstp"].short
    # Other protocols stay neutral.
    assert "RADIUS" not in ac.PROTOCOLS["pptp"].name


def test_access_connections_page_renders_radius_chrome_for_sstp(client, app):
    _login_admin(client)
    prov = _provider()
    _fleet_node(prov)
    body = client.get("/admin/access-connections").get_data(as_text=True)
    assert "إنشاء رابط RADIUS عبر SSTP" in body
    assert "auth/acct/CoA" in body
    # The inline preview block + its API URL are present.
    assert "سلسلة RADIUS" in body
    assert "/admin/access-connections/api/radius-link-preview" in body
    # PPTP modal stays generic — the relabel is SSTP-specific.
    assert "إضافة اتصال PPTP" in body


# ─────────────────────────────────────────────────────────────────────────
# Chain preview helper
# ─────────────────────────────────────────────────────────────────────────
def test_preview_full_chain_ok(app):
    cust = _customer()
    inst = _radius_instance(cust)
    prov = _provider()
    node = _fleet_node(prov)
    _proxy_route(cust, inst, [node.id])

    p = ac.radius_link_preview(cust.id, node.id)
    assert p["ok"] is True
    assert p["realm"] == "client5"
    assert p["radius_target"] == "10.250.0.5:1812"
    assert p["has_radius_instance"] is True
    assert p["has_proxy_route"] is True
    assert p["node_in_allowlist"] is True


def test_preview_warns_when_no_radius_instance(app):
    cust = _customer()  # no CustomerRadiusInstance
    prov = _provider()
    node = _fleet_node(prov)

    p = ac.radius_link_preview(cust.id, node.id)
    assert p["ok"] is False
    assert p["has_radius_instance"] is False
    assert "نسخة RADIUS" in p["message"]


def test_preview_warns_when_no_proxy_route(app):
    cust = _customer()
    _radius_instance(cust)
    prov = _provider()
    node = _fleet_node(prov)
    # no ProxyRealmRoute

    p = ac.radius_link_preview(cust.id, node.id)
    assert p["ok"] is False
    assert p["has_radius_instance"] is True
    assert p["has_proxy_route"] is False
    assert "وكيل RADIUS" in p["message"]
    # Realm + target still visible so the operator sees what's wired.
    assert p["realm"] == "client5"
    assert p["radius_target"] == "10.250.0.5:1812"


def test_preview_warns_when_node_not_in_allowlist(app):
    cust = _customer()
    inst = _radius_instance(cust)
    prov = _provider()
    a = _fleet_node(prov, name="chr-a", ip="10.0.0.1", wg="10.99.0.1")
    b = _fleet_node(prov, name="chr-b", ip="10.0.0.2", wg="10.99.0.2")
    _proxy_route(cust, inst, [a.id])  # only A is allowed

    p = ac.radius_link_preview(cust.id, b.id)
    assert p["ok"] is False
    assert p["node_in_allowlist"] is False
    assert "العقد المسموحة" in p["message"]


def test_preview_warns_when_route_not_active(app):
    cust = _customer()
    inst = _radius_instance(cust)
    prov = _provider()
    node = _fleet_node(prov)
    _proxy_route(cust, inst, [node.id], status="draft")

    p = ac.radius_link_preview(cust.id, node.id)
    assert p["ok"] is False
    assert "active" in p["message"]


def test_preview_empty_allowlist_accepts_any_node(app):
    """An empty allowed_fleet_chr_node_ids list means «all nodes ok»."""
    cust = _customer()
    inst = _radius_instance(cust)
    prov = _provider()
    node = _fleet_node(prov)
    _proxy_route(cust, inst, [])  # empty list

    p = ac.radius_link_preview(cust.id, node.id)
    assert p["ok"] is True
    assert p["node_in_allowlist"] is True


# ─────────────────────────────────────────────────────────────────────────
# Preview API endpoint
# ─────────────────────────────────────────────────────────────────────────
def test_preview_api_returns_chain_state(client, app):
    _login_admin(client)
    cust = _customer()
    inst = _radius_instance(cust)
    prov = _provider()
    node = _fleet_node(prov)
    _proxy_route(cust, inst, [node.id])

    rv = client.get(
        f"/admin/access-connections/api/radius-link-preview"
        f"?customer_id={cust.id}&fleet_chr_node_id={node.id}"
    )
    assert rv.status_code == 200
    payload = rv.get_json()
    assert payload["ok"] is True
    assert payload["realm"] == "client5"
    assert payload["radius_target"] == "10.250.0.5:1812"


# ─────────────────────────────────────────────────────────────────────────
# Create endpoint flashes a warning when the chain is incomplete
# ─────────────────────────────────────────────────────────────────────────
def test_sstp_create_warns_when_no_radius_instance_but_still_creates(client, app):
    """The operator may stage things out of order — we WARN, not BLOCK."""
    _login_admin(client)
    cust = _customer()
    _license(cust)
    # NO CustomerRadiusInstance, NO ProxyRealmRoute
    prov = _provider()
    node = _fleet_node(prov)

    rv = client.post("/admin/access-connections/ppp", data={
        "customer_id": cust.id,
        "tunnel_type": "sstp",
        "max_connections": "1",
        "fleet_chr_node_id": node.id,
    }, follow_redirects=False)
    assert rv.status_code in (302, 303)

    # Tunnel was still created (warn-not-block policy).
    from app.models import CustomerVpnTunnel
    tunnel = CustomerVpnTunnel.query.first()
    assert tunnel is not None
    assert tunnel.tunnel_type == "sstp"
    assert tunnel.fleet_chr_node_id == node.id

    # The warning landed in the session flashes.
    with client.session_transaction() as sess:
        flashes = sess.get("_flashes") or []
    categories = [c for (c, _msg) in flashes]
    msgs = " ".join(m for (_, m) in flashes)
    assert "warning" in categories, f"expected a warning flash, got {categories}"
    assert "RADIUS" in msgs


def test_sstp_create_success_toast_names_the_radius_role(client, app):
    """When the chain is complete, the success toast explicitly names
    SSTP as the RADIUS link so the operator's next move is clear."""
    _login_admin(client)
    cust = _customer()
    _license(cust)
    inst = _radius_instance(cust)
    prov = _provider()
    node = _fleet_node(prov)
    _proxy_route(cust, inst, [node.id])

    rv = client.post("/admin/access-connections/ppp", data={
        "customer_id": cust.id,
        "tunnel_type": "sstp",
        "max_connections": "1",
        "fleet_chr_node_id": node.id,
    }, follow_redirects=False)
    assert rv.status_code in (302, 303)

    with client.session_transaction() as sess:
        flashes = sess.get("_flashes") or []
    msgs = " ".join(m for (_, m) in flashes)
    assert "رابط RADIUS عبر SSTP" in msgs
    assert "SSTP-Client" in msgs or "ميكروتيك" in msgs


# ─────────────────────────────────────────────────────────────────────────
# Bridge serialization carries the realm + RADIUS target for SSTP only
# ─────────────────────────────────────────────────────────────────────────
def test_serialize_sstp_emits_radius_link_block(app):
    cust = _customer()
    lic = _license(cust)
    inst = _radius_instance(cust)
    prov = _provider()
    node = _fleet_node(prov, name="chr-mtl", ip="203.0.113.50", wg="10.99.0.50")
    _proxy_route(cust, inst, [node.id])

    tunnel = vt.provision_tunnel(
        cust, lic, tunnel_type="sstp", max_connections=1,
        source="admin_manual", enforce_allowance=False,
        fleet_chr_node_id=node.id,
    )
    db.session.commit()

    data = vt.serialize_tunnel(tunnel, include_password=False)
    assert "radius_link" in data, "SSTP must carry the RADIUS-transport binding"
    link = data["radius_link"]
    assert link["role"] == "radius_transport"
    assert link["realm"] == "client5"
    assert link["radius_auth_ip"] == "10.250.0.5"
    assert link["radius_auth_port"] == 1812
    # The usage hint includes the node's public host + the realm so the
    # customer panel can render the subscriber-MikroTik snippet.
    assert "203.0.113.50" in link["usage_ar"]
    assert "client5" in link["usage_ar"]


def test_serialize_sstp_without_instance_carries_placeholder(app):
    """When the customer has no RADIUS instance yet, the SSTP row
    still gets a placeholder ``radius_link`` so the customer panel
    can render «اضبط نسخة RADIUS أولًا» instead of a missing field."""
    cust = _customer()
    lic = _license(cust)
    prov = _provider()
    node = _fleet_node(prov)

    tunnel = vt.provision_tunnel(
        cust, lic, tunnel_type="sstp", max_connections=1,
        source="admin_manual", enforce_allowance=False,
        fleet_chr_node_id=node.id,
    )
    db.session.commit()

    data = vt.serialize_tunnel(tunnel, include_password=False)
    assert "radius_link" in data
    link = data["radius_link"]
    assert link["role"] == "radius_transport"
    assert link["realm"] == ""
    assert "نسخة RADIUS" in link["usage_ar"]


def test_non_sstp_tunnels_do_not_carry_radius_link(app):
    cust = _customer()
    lic = _license(cust)
    _radius_instance(cust)
    prov = _provider()
    node = _fleet_node(prov)

    tunnel = vt.provision_tunnel(
        cust, lic, tunnel_type="pptp", max_connections=1,
        source="admin_manual", enforce_allowance=False,
        fleet_chr_node_id=node.id,
    )
    db.session.commit()

    data = vt.serialize_tunnel(tunnel, include_password=False)
    assert "radius_link" not in data, (
        "Only SSTP carries the RADIUS-transport binding — the role is "
        "specific to the access-connections SSTP flow."
    )
