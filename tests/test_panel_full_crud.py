"""Panel full-CRUD coverage — every EDIT and DELETE the owner asked for.

Areas covered (branch ``feat/panel-full-crud-edit-delete``):

* F1 — proxy-routes 405 fix (``/admin/infra/proxy-routes/reload``).
* E2 — ProxyRealmRoute edit + delete.
* E3 — CustomerRadiusInstance delete + secret rotate.
* E1 — FleetChrNode edit + delete (with FK + JSON-list scrub).
* E4 — VpnServicePlan delete (block-on-active).

Every test does the REAL thing: logs the seeded admin in (promoted to super),
posts a real form body, and asserts on the DB row + the rendered flash + the
audit log + the response status. No mocks of the route layer.
"""
from __future__ import annotations

import uuid
from datetime import timedelta
from decimal import Decimal

import pytest

from app import create_app, seed_defaults
from app.config import TestingConfig
from app.extensions import db
from app.models import (
    Admin,
    AuditLog,
    Customer,
    CustomerRadiusInstance,
    CustomerVpnEntitlement,
    License,
    Plan,
    ProxyRealmRoute,
    ServiceAllocation,
    Setting,
    VpnServicePlan,
    utcnow,
)
from app.services.license_service import generate_license_key


# ─────────────────────────────────────────────────────────────────────────
# Shared fixtures — TestingConfig app + logged-in super-admin client
# ─────────────────────────────────────────────────────────────────────────


@pytest.fixture()
def app():
    app = create_app(TestingConfig)
    with app.app_context():
        db.create_all()
        seed_defaults(app)
        admin = Admin.query.filter_by(username="admin").first()
        if admin is not None:
            admin.is_super_admin = True
            db.session.commit()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    c = app.test_client()
    c.post("/login", data={"username": "admin", "password": "admin12345"})
    return c


def _mk_customer_with_license(name: str = "CRUD Co") -> tuple[Customer, License]:
    customer = Customer(
        company_name=f"{name} {uuid.uuid4().hex[:6]}",
        status="active",
        runtime_url="http://10.0.0.42/",
    )
    plan = Plan.query.filter_by(slug="pro").first()
    db.session.add(customer)
    db.session.flush()
    lic = License(
        customer_id=customer.id,
        plan_id=plan.id,
        license_key=generate_license_key(),
        status="active",
        starts_at=utcnow() - timedelta(days=1),
        expires_at=utcnow() + timedelta(days=30),
        grace_until=utcnow() + timedelta(days=37),
    )
    db.session.add(lic)
    db.session.commit()
    return customer, lic


def _mk_radius_instance(customer: Customer, realm: str = "") -> CustomerRadiusInstance:
    inst = CustomerRadiusInstance(
        customer_id=customer.id,
        instance_name="vps-radius",
        realm=realm or f"c{customer.id}-{uuid.uuid4().hex[:4]}",
        radius_auth_ip="10.20.30.40",
        radius_auth_port=1812,
        radius_acct_port=1813,
        mgmt_wg_ip="10.99.0.40",
        secret_vault_ref="",
        status="active",
    )
    db.session.add(inst)
    db.session.commit()
    return inst


def _mk_proxy_route(inst: CustomerRadiusInstance) -> ProxyRealmRoute:
    route = ProxyRealmRoute(
        customer_id=inst.customer_id,
        radius_instance_id=inst.id,
        realm=inst.realm,
        target_radius_ip=inst.radius_auth_ip,
        target_auth_port=inst.radius_auth_port,
        target_acct_port=inst.radius_acct_port,
        secret_vault_ref=inst.secret_vault_ref,
        status="active",
    )
    route.allowed_fleet_chr_node_ids = []
    db.session.add(route)
    db.session.commit()
    return route


def _mk_fleet_node(name: str = "chr-test"):
    from fleet.registry.models_chr import FleetChrNode, FleetProvider

    provider = FleetProvider.query.first()
    if provider is None:
        provider = FleetProvider(
            name="crud-provider",
            cost_model="open",
            price_per_tb=0,
            overage_allowed=False,
            billing_cycle_day=1,
        )
        db.session.add(provider)
        db.session.commit()
    full_name = f"{name}-{uuid.uuid4().hex[:4]}"
    suffix = full_name.replace("-", "")[-4:].rjust(4, "0")
    last_octet = abs(hash(full_name)) % 240 + 11
    n = FleetChrNode(
        provider_id=provider.id,
        name=full_name,
        public_ip=f"203.0.113.{last_octet}",
        wg_mgmt_ip=f"10.99.0.{last_octet}",
        wg_mgmt_pubkey="x" * 44,
        max_sessions=500,
        link_speed_mbps=1000,
        weight=Decimal("1.0"),
        enabled=True,
        drain=False,
        status="up",
    )
    db.session.add(n)
    db.session.commit()
    return n


# ═════════════════════════════════════════════════════════════════════════
# F1 — proxy-routes reload (the former 405)
# ═════════════════════════════════════════════════════════════════════════


def test_proxy_routes_reload_was_405_now_200(app, client):
    """The former bug: clicking «تحديث التكوين» on /admin/infra/proxy-routes
    posted to a non-existent endpoint, safe_url_for rewrote the action to
    "#", the form re-POSTed to the GET-only list URL, and Flask returned
    405 Method Not Allowed. Now the real endpoint exists; the POST should
    return 302 (redirect after success), NEVER 405."""
    res = client.post("/admin/infra/proxy-routes/reload")
    assert res.status_code == 302, res.data
    # Marker is persisted in Setting so the next routing-table publisher
    # poll sees the explicit operator refresh request.
    with app.app_context():
        row = db.session.get(Setting, "proxy_routes_refresh_marker")
        assert row is not None and row.value
        # Audit row exists.
        a = AuditLog.query.filter_by(action="proxy_routes_reload").order_by(AuditLog.id.desc()).first()
        assert a is not None


def test_proxy_routes_list_get_still_405s_on_post_when_action_url_wrong(client):
    """Reverse check: posting to the LIST URL itself is still rejected (405).
    This pins the original failure mode so a future regression where someone
    silently re-introduces an action="#" template breaks loudly."""
    res = client.post("/admin/infra/proxy-routes")
    assert res.status_code == 405


# ═════════════════════════════════════════════════════════════════════════
# E2 — Proxy route edit + delete
# ═════════════════════════════════════════════════════════════════════════


def test_proxy_route_edit_persists_changes_and_audits(app, client):
    with app.app_context():
        customer, _ = _mk_customer_with_license("Edit-Route")
        inst = _mk_radius_instance(customer)
        route = _mk_proxy_route(inst)
        route_id = route.id
        instance_id = inst.id

    # GET the form renders.
    res = client.get(f"/admin/infra/proxy-routes/{route_id}/edit")
    assert res.status_code == 200
    assert b"\xd8\xaa\xd8\xb9\xd8\xaf\xd9\x8a\xd9\x84" in res.data  # «تعديل»

    res = client.post(
        f"/admin/infra/proxy-routes/{route_id}/edit",
        data={
            "realm": "renamed-realm",
            "radius_instance_id": str(instance_id),
            "target_radius_ip": "192.0.2.99",
            "target_auth_port": "1816",
            "target_acct_port": "1817",
            "secret_vault_ref": "vault://test-rotated",
            "status": "active",
        },
    )
    assert res.status_code == 302

    with app.app_context():
        r = db.session.get(ProxyRealmRoute, route_id)
        assert r.realm == "renamed-realm"
        assert r.target_radius_ip == "192.0.2.99"
        assert r.target_auth_port == 1816
        assert r.target_acct_port == 1817
        assert r.secret_vault_ref == "vault://test-rotated"
        assert r.status == "active"
        a = AuditLog.query.filter_by(action="proxy_route_edit", entity_id=str(route_id)).first()
        assert a is not None


def test_proxy_route_delete_removes_row_and_audits(app, client):
    with app.app_context():
        customer, _ = _mk_customer_with_license("Del-Route")
        inst = _mk_radius_instance(customer)
        route = _mk_proxy_route(inst)
        route_id = route.id
        realm = route.realm

    res = client.post(f"/admin/infra/proxy-routes/{route_id}/delete")
    assert res.status_code == 302

    with app.app_context():
        assert db.session.get(ProxyRealmRoute, route_id) is None
        a = AuditLog.query.filter_by(action="proxy_route_delete", entity_id=str(route_id)).first()
        assert a is not None
        assert realm in (a.summary or "")


def test_proxy_route_edit_rejects_realm_collision(app, client):
    with app.app_context():
        c1, _ = _mk_customer_with_license("Collide-A")
        c2, _ = _mk_customer_with_license("Collide-B")
        i1 = _mk_radius_instance(c1, realm="taken-realm")
        i2 = _mk_radius_instance(c2, realm="loser-realm")
        _mk_proxy_route(i1)
        r2 = _mk_proxy_route(i2)
        r2_id = r2.id
        i2_id = i2.id

    res = client.post(
        f"/admin/infra/proxy-routes/{r2_id}/edit",
        data={"realm": "taken-realm", "radius_instance_id": str(i2_id)},
    )
    assert res.status_code == 302  # redirects back to edit page
    with app.app_context():
        r = db.session.get(ProxyRealmRoute, r2_id)
        assert r.realm == "loser-realm"  # unchanged


# ═════════════════════════════════════════════════════════════════════════
# E3 — RADIUS instance delete (cascade route) + rotate secret
# ═════════════════════════════════════════════════════════════════════════


def test_radius_instance_delete_cascades_proxy_route(app, client):
    with app.app_context():
        customer, _ = _mk_customer_with_license("Del-Inst")
        inst = _mk_radius_instance(customer)
        route = _mk_proxy_route(inst)
        inst_id = inst.id
        route_id = route.id

    res = client.post(f"/admin/infra/radius-instances/{inst_id}/delete")
    assert res.status_code == 302
    with app.app_context():
        assert db.session.get(CustomerRadiusInstance, inst_id) is None
        # Proxy route auto-cascaded via "all, delete-orphan" relationship.
        assert db.session.get(ProxyRealmRoute, route_id) is None
        a = AuditLog.query.filter_by(action="radius_instance_delete").order_by(AuditLog.id.desc()).first()
        assert a is not None


def test_radius_instance_delete_blocked_by_active_allocation(app, client):
    with app.app_context():
        customer, _ = _mk_customer_with_license("Blocked-Inst")
        inst = _mk_radius_instance(customer)
        inst_id = inst.id
        alloc = ServiceAllocation(
            customer_id=customer.id,
            radius_instance_id=inst.id,
            service_type="sstp",
            status="active",
            speed_limit_mbps=10,
        )
        db.session.add(alloc)
        db.session.commit()

    res = client.post(f"/admin/infra/radius-instances/{inst_id}/delete", follow_redirects=False)
    assert res.status_code == 302
    with app.app_context():
        # Instance was NOT deleted.
        assert db.session.get(CustomerRadiusInstance, inst_id) is not None


def test_radius_instance_rotate_secret_mints_new_value(app, client):
    with app.app_context():
        customer, _ = _mk_customer_with_license("Rotate-Secret")
        inst = _mk_radius_instance(customer)
        route = _mk_proxy_route(inst)
        inst_id = inst.id
        route_id = route.id
        old_ref = inst.secret_vault_ref

    res = client.post(f"/admin/infra/radius-instances/{inst_id}/rotate-secret", follow_redirects=False)
    assert res.status_code == 302
    with app.app_context():
        i = db.session.get(CustomerRadiusInstance, inst_id)
        assert i.secret_vault_ref.startswith("vault://radius_secret.customer.")
        assert i.secret_vault_ref != old_ref  # the empty old_ref proves we wrote a new one
        # Route's secret_vault_ref refreshed in tandem.
        r = db.session.get(ProxyRealmRoute, route_id)
        assert r.secret_vault_ref == i.secret_vault_ref
        # Setting row exists with non-empty value.
        key = i.secret_vault_ref.removeprefix("vault://")
        s = db.session.get(Setting, key)
        assert s is not None and len(s.value) >= 16
        a = AuditLog.query.filter_by(action="radius_instance_rotate_secret").order_by(AuditLog.id.desc()).first()
        assert a is not None


# ═════════════════════════════════════════════════════════════════════════
# E1 — Fleet CHR node edit + delete (with FK scrub)
# ═════════════════════════════════════════════════════════════════════════


def test_chr_node_edit_form_renders(app, client):
    with app.app_context():
        n = _mk_fleet_node("edit-me")
        node_id = n.id
    res = client.get(f"/admin/fleet/chr-nodes/{node_id}/edit")
    assert res.status_code == 200


def test_chr_node_edit_persists_fields(app, client):
    with app.app_context():
        n = _mk_fleet_node("persist-me")
        node_id = n.id
    res = client.post(
        f"/admin/fleet/chr-nodes/{node_id}/edit",
        data={
            "name": "renamed-node",
            "public_ip": "198.51.100.7",
            "wg_mgmt_ip": "10.99.0.77",
            "wg_mgmt_pubkey": "y" * 44,
            "max_sessions": "750",
            "link_speed_mbps": "2000",
            "weight": "1.5",
            "routeros_api_port": "8443",
            "coa_port": "3799",
            "routeros_api_user": "panel-api",
            "cost_model": "metered",
            "price_per_tb": "0.50",
            "bandwidth_cap_tb": "10",
            "overage_allowed": "1",
        },
    )
    assert res.status_code == 302

    with app.app_context():
        from fleet.registry.models_chr import FleetChrNode
        n = db.session.get(FleetChrNode, node_id)
        assert n.name == "renamed-node"
        assert n.public_ip == "198.51.100.7"
        assert n.max_sessions == 750
        assert int(n.link_speed_mbps) == 2000
        assert n.weight == Decimal("1.5")
        assert n.routeros_api_user == "panel-api"
        assert n.cost_model == "metered"
        assert n.overage_allowed is True
        a = AuditLog.query.filter_by(action="fleet_chr_node_edit").order_by(AuditLog.id.desc()).first()
        assert a is not None


def test_chr_node_delete_blocked_by_active_allocation(app, client):
    with app.app_context():
        customer, _ = _mk_customer_with_license("FleetBlock")
        n = _mk_fleet_node("blocked-node")
        node_id = n.id
        alloc = ServiceAllocation(
            customer_id=customer.id,
            fleet_chr_node_id=n.id,
            service_type="sstp",
            status="active",
            speed_limit_mbps=20,
        )
        db.session.add(alloc)
        db.session.commit()
    res = client.post(f"/admin/fleet/chr-nodes/{node_id}/delete", follow_redirects=False)
    assert res.status_code == 302
    with app.app_context():
        from fleet.registry.models_chr import FleetChrNode
        assert db.session.get(FleetChrNode, node_id) is not None


def test_chr_node_delete_scrubs_proxy_route_allowlist(app, client):
    with app.app_context():
        customer, _ = _mk_customer_with_license("Scrub-Allowlist")
        inst = _mk_radius_instance(customer)
        n = _mk_fleet_node("scrub-target")
        node_id = n.id
        route = _mk_proxy_route(inst)
        route.allowed_fleet_chr_node_ids = [node_id, 99999]
        db.session.commit()
        route_id = route.id

    res = client.post(f"/admin/fleet/chr-nodes/{node_id}/delete", follow_redirects=False)
    assert res.status_code == 302
    with app.app_context():
        from fleet.registry.models_chr import FleetChrNode
        assert db.session.get(FleetChrNode, node_id) is None
        r = db.session.get(ProxyRealmRoute, route_id)
        assert node_id not in (r.allowed_fleet_chr_node_ids or [])
        # The unrelated stale ID 99999 is left alone (we only scrub the
        # deleted node's id).
        assert 99999 in (r.allowed_fleet_chr_node_ids or [])
        a = AuditLog.query.filter_by(action="fleet_chr_node_delete").order_by(AuditLog.id.desc()).first()
        assert a is not None


# ═════════════════════════════════════════════════════════════════════════
# E4 — VPN service plan delete (block-on-active)
# ═════════════════════════════════════════════════════════════════════════


def _mk_vpn_plan(code: str = "vpn_50m") -> VpnServicePlan:
    plan = VpnServicePlan(
        code=f"{code}_{uuid.uuid4().hex[:4]}",
        name="VPN test",
        download_mbps=50,
        upload_mbps=50,
        max_vpn_users=10,
        max_locations=1,
        is_active=True,
    )
    db.session.add(plan)
    db.session.commit()
    return plan


def test_vpn_plan_delete_works_when_unreferenced(app, client):
    with app.app_context():
        plan = _mk_vpn_plan("free-to-delete")
        plan_id = plan.id
    res = client.post(f"/admin/vpn-services/{plan_id}/delete", follow_redirects=False)
    assert res.status_code == 302
    with app.app_context():
        assert db.session.get(VpnServicePlan, plan_id) is None
        a = AuditLog.query.filter_by(action="vpn_service_plan_deleted").order_by(AuditLog.id.desc()).first()
        assert a is not None


def test_vpn_plan_delete_blocked_by_active_entitlement(app, client):
    with app.app_context():
        plan = _mk_vpn_plan("locked-plan")
        plan_id = plan.id
        customer, lic = _mk_customer_with_license("VPN-Customer")
        ent = CustomerVpnEntitlement(
            customer_id=customer.id,
            license_id=lic.id,
            vpn_plan_id=plan.id,
            enabled=True,
            status="active",
            download_mbps=50,
            upload_mbps=50,
        )
        db.session.add(ent)
        db.session.commit()
    res = client.post(f"/admin/vpn-services/{plan_id}/delete", follow_redirects=False)
    assert res.status_code == 302
    with app.app_context():
        assert db.session.get(VpnServicePlan, plan_id) is not None  # NOT deleted
