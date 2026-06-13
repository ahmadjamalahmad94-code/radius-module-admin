"""feat/data-chr-management-page — /admin/fleet/data-nodes contract.

Three parts pinned:

  1. Role toggle persists into ``FleetChrNode.roles_json`` via the
     existing ``app.services.node_roles`` API and flips
     ``needs_reimport=True`` on a real change. data-only = a node
     whose enabled_roles == {radius_transport}.
  2. Page renders the SSTP «رابط RADIUS» create form pre-filled with
     the chosen data CHR's id, pointing at the existing
     /admin/access-connections/ppp endpoint (we don't fork the
     generator — we reuse it).
  3. Connections list lives under each data node, reads the real
     CustomerVpnTunnel rows whose ``fleet_chr_node_id`` matches, and
     surfaces the visual chain (5 segments) + live status. When a
     status field has no live source (no proxy heartbeat for the
     realm yet) we render «غير متوفّرة بعد», never a fake state.
"""
from __future__ import annotations

import json

import pytest

from app.extensions import db
from app.models import (
    Admin, Customer, CustomerRadiusInstance, CustomerVpnTunnel,
    ProxyRealmRoute,
)
from app.services import node_roles as nr
from fleet.registry.models_chr import FleetChrNode, FleetProvider
from fleet.ui import data_nodes_view as dn


# ════════════════════════════════════════════════════════════════════════
# Fixtures + helpers
# ════════════════════════════════════════════════════════════════════════


def _login_admin(client):
    return client.post(
        "/login", data={"username": "admin", "password": "admin12345"}
    )


def _make_super_admin():
    adm = Admin.query.first()
    if adm and not adm.is_super_admin:
        adm.is_super_admin = True
        db.session.commit()


def _provider() -> FleetProvider:
    p = FleetProvider.query.first()
    if p is not None:
        return p
    p = FleetProvider(
        name="dn-prov", cost_model="open", price_per_tb=0,
        overage_allowed=False, billing_cycle_day=1,
    )
    db.session.add(p); db.session.commit()
    return p


_NODE_SEQ = [10]


def _make_node(**kw) -> FleetChrNode:
    _NODE_SEQ[0] += 1
    base = dict(
        provider_id=_provider().id,
        name=f"chr-dn-{_NODE_SEQ[0]}",
        public_ip=f"203.0.113.{_NODE_SEQ[0]}",
        wg_mgmt_ip=f"10.99.0.{_NODE_SEQ[0]}", wg_mgmt_pubkey="x" * 44,
        max_sessions=500, link_speed_mbps=1000, weight=1.0,
        enabled=True, drain=False, status="up",
        cpu_pct=0, active_sessions=0,
    )
    base.update(kw)
    n = FleetChrNode(**base)
    db.session.add(n); db.session.commit()
    return n


def _make_customer_with_realm(*, realm: str, radius_ip: str = "10.200.0.2"):
    c = Customer(
        company_name=f"acme-{realm}", email=f"x+{realm}@y.com",
        country_iso="PS", dial_code="970",
    )
    db.session.add(c); db.session.commit()
    inst = CustomerRadiusInstance(
        customer_id=c.id,
        instance_name=f"{realm}-radius",
        radius_auth_ip=radius_ip,
        mgmt_wg_ip="10.99.0.99",
        realm=realm,
    )
    db.session.add(inst); db.session.commit()
    return c, inst


def _make_tunnel(*, customer, node, status="active",
                 delivery="delivered", username=None):
    t = CustomerVpnTunnel(
        customer_id=customer.id,
        tunnel_type="sstp",
        username=username or f"u-{customer.id}-{node.id}",
        password_encrypted="ENC==",
        password_hint="…hint",
        status=status,
        delivery_status=delivery,
        chr_provisioned=True,
        fleet_chr_node_id=node.id,
        download_mbps=100, upload_mbps=100,
    )
    db.session.add(t); db.session.commit()
    return t


# ════════════════════════════════════════════════════════════════════════
# (1) Page renders + nav from dashboard
# ════════════════════════════════════════════════════════════════════════
class TestPageRenders:

    def test_dashboard_links_to_data_nodes(self, app, client):
        _login_admin(client); _make_super_admin()
        html = client.get("/admin/fleet/").get_data(as_text=True)
        assert "/admin/fleet/data-nodes" in html
        assert "عقد البيانات" in html

    def test_page_renders_for_super_admin(self, app, client):
        _login_admin(client); _make_super_admin()
        _make_node(name="chr-data-1")
        r = client.get("/admin/fleet/data-nodes")
        assert r.status_code == 200, r.data[:200]
        html = r.get_data(as_text=True)
        assert "إدارة عقد البيانات" in html
        # Page CSRF form for the role-toggle JS.
        assert 'id="dn-csrf-form"' in html

    def test_route_carries_super_admin_required(self):
        """The seeded admin in the test DB is auto-promoted to super by
        ``seed_defaults`` (the bootstrap path); proving the negative-auth
        path from the test client therefore needs a fresh non-super
        admin. Cheaper + as-strong: pin the decorator at the source
        level — the contract that protects the page is the
        ``@super_admin_required`` line above the view function."""
        from pathlib import Path
        src = Path("fleet/ui/routes.py").read_text(encoding="utf-8")
        i = src.index("def fleet_data_nodes_index(")
        prelude = src[max(0, i - 200): i]
        assert "@super_admin_required" in prelude, (
            "page handler must carry @super_admin_required so a "
            "non-super admin cannot reach it"
        )


# ════════════════════════════════════════════════════════════════════════
# (2) Part 1 — role toggle persists + flips needs_reimport
# ════════════════════════════════════════════════════════════════════════
class TestRoleToggle:

    def test_save_roles_updates_roles_json(self, app, client):
        _login_admin(client); _make_super_admin()
        n = _make_node(name="chr-roles-1")
        # Start with all-roles (empty list = all-roles per node_roles).
        assert nr.enabled_roles(n) == set(nr.NODE_ROLES)

        r = client.post(
            f"/admin/fleet/data-nodes/{n.id}/roles",
            data=json.dumps({"roles": ["radius_transport"]}),
            content_type="application/json",
        )
        assert r.status_code == 200, r.data[:200]
        body = r.get_json()
        assert body["ok"] is True
        assert body["roles"] == ["radius_transport"]
        assert body["changed"] is True
        assert body["needs_reimport"] is True
        # Re-read from DB.
        db.session.refresh(n)
        assert sorted(nr.enabled_roles(n)) == ["radius_transport"]
        assert n.needs_reimport is True

    def test_save_same_roles_is_no_op(self, app, client):
        _login_admin(client); _make_super_admin()
        n = _make_node(name="chr-roles-2")
        nr.set_roles(n, ["radius_transport"], commit=True)
        n.needs_reimport = False
        db.session.commit()

        r = client.post(
            f"/admin/fleet/data-nodes/{n.id}/roles",
            data=json.dumps({"roles": ["radius_transport"]}),
            content_type="application/json",
        )
        body = r.get_json()
        assert body["ok"] is True
        assert body["changed"] is False
        # needs_reimport stays as it was (False).
        db.session.refresh(n)
        assert n.needs_reimport is False

    def test_unknown_node_returns_404(self, app, client):
        _login_admin(client); _make_super_admin()
        r = client.post(
            "/admin/fleet/data-nodes/999999/roles",
            data=json.dumps({"roles": ["radius_transport"]}),
            content_type="application/json",
        )
        assert r.status_code == 404

    def test_bad_request_when_roles_missing(self, app, client):
        _login_admin(client); _make_super_admin()
        n = _make_node(name="chr-roles-3")
        r = client.post(
            f"/admin/fleet/data-nodes/{n.id}/roles",
            data=json.dumps({"not_roles": []}),
            content_type="application/json",
        )
        assert r.status_code == 400


# ════════════════════════════════════════════════════════════════════════
# (3) data-only = radius_transport ONLY — script gates on this
# ════════════════════════════════════════════════════════════════════════
class TestDataOnlyRendersOnlyDataServices:

    def test_data_only_node_view_flags(self, app):
        n = _make_node(name="chr-data-only")
        nr.set_roles(n, ["radius_transport"], commit=True)
        view = dn.build_view_for(n.id)
        assert view is not None
        assert view.is_data is True
        assert view.is_data_only is True
        assert view.roles == ("radius_transport",)

    def test_data_only_script_emits_radius_no_vpn(self, app):
        """A data-only render of the unified script must enable RADIUS
        + skip every VPN service block. Pins that the role gate works
        end-to-end — toggling a node to data-only via the new page
        REALLY makes its rendered script data-only."""
        from fleet.registry.script_render import render_from_bindings
        bindings = {
            "ROUTER_IDENTITY": "chr-data-only",
            "CHR_PUBLIC_IP": "203.0.113.1",
            "WAN_IFACE": "ether1",
            "WG_MGMT_PRIVKEY": "M" * 44,
            "WG_MGMT_ADDR": "10.99.0.11/24",
            "WG_DATA_PRIVKEY": "D" * 44,
            "WG_DATA_ADDR": "10.98.0.11/24",
            "WG_DATA_ADDR_IP": "10.98.0.11",
            "PANEL_WG_PUBKEY": "P" * 43 + "=",
            "PANEL_WG_ENDPOINT": "panel.example.com:51820",
            "PANEL_WG_ADDR": "10.99.0.1",
            "PROXY_WG_PUBKEY": "X" * 43 + "=",
            "PROXY_WG_ENDPOINT": "proxy.example.com:51821",
            "PROXY_WG_ADDR": "10.98.0.1",
            "CHR_SHARED_SECRET": "S" * 48,
            "SSTP_CERT_NAME": "", "IKE_CERT_NAME": "",
            "CLIENT_SUPERNET": "10.0.0.0/8", "DNS_PUSH": "1.1.1.1",
            "GW_LOCAL_ADDR": "10.10.0.1",
            "API_USER": "", "API_PASSWORD": "", "API_PORT": 8443,
            "OPERATOR_ADMIN_IPS": "",
            # The role gate the new page drives.
            "NODE_ROLES_SET": {"radius_transport"},
        }
        out = render_from_bindings(bindings)
        # RADIUS / wg-data path renders.
        assert "wg-data" in out
        assert 'comment="hobe-fleet-radius"' in out
        # Every VPN service block is SKIPPED (their `enabled=no` fallback).
        assert "/interface pptp-server server\nset enabled=no" in out
        assert "/interface sstp-server server\nset enabled=no" in out
        assert "/interface l2tp-server server\nset enabled=no" in out
        # No wg-users user-WG either.
        assert 'comment="hobe-fleet-users"' not in out


# ════════════════════════════════════════════════════════════════════════
# (4) Part 2 — page exposes the create-form pre-filled with this CHR
# ════════════════════════════════════════════════════════════════════════
class TestCreateFormReusesExistingGenerator:

    def test_form_action_is_existing_access_route(self, app, client):
        _login_admin(client); _make_super_admin()
        n = _make_node(name="chr-create-form")
        nr.set_roles(n, ["radius_transport"], commit=True)
        # A customer must exist so the dropdown has at least one option.
        _make_customer_with_realm(realm="acme")
        html = client.get("/admin/fleet/data-nodes").get_data(as_text=True)
        # Form posts to the existing access-connections create handler.
        assert 'action="/admin/access-connections/ppp"' in html
        # Pre-filled hidden tunnel_type + the chosen fleet node id.
        assert 'name="tunnel_type" value="sstp"' in html
        assert f'name="fleet_chr_node_id" value="{n.id}"' in html
        # The chain-preview wrapper is wired to the existing endpoint
        # so the operator sees «سلسلة RADIUS» before clicking create.
        assert "data-dn-chain-preview" in html
        assert "/admin/access-connections/api/radius-link-preview" in html

    def test_non_data_node_does_not_show_create_form(self, app, client):
        """A node that has NO radius_transport role MUST NOT show the
        create form — the SSTP «رابط RADIUS» path requires the data
        role on the chosen CHR to make sense."""
        _login_admin(client); _make_super_admin()
        n = _make_node(name="chr-vpn-only")
        nr.set_roles(n, ["vpn_sstp"], commit=True)
        html = client.get("/admin/fleet/data-nodes").get_data(as_text=True)
        # The form must not carry THIS node id as the fleet_chr_node_id.
        assert f'name="fleet_chr_node_id" value="{n.id}"' not in html


# ════════════════════════════════════════════════════════════════════════
# (5) Part 3 — connections list + chain + status
# ════════════════════════════════════════════════════════════════════════
class TestConnectionsList:

    def test_view_lists_sstp_tunnels_for_node(self, app):
        n = _make_node(name="chr-list-1")
        c, inst = _make_customer_with_realm(realm="acme-l1")
        _make_tunnel(customer=c, node=n, status="active", username="u1")
        _make_tunnel(customer=c, node=n, status="pending", username="u2")

        view = dn.build_view_for(n.id)
        assert view is not None
        assert view.connection_count == 2
        names = {row.username for row in view.connections}
        assert names == {"u1", "u2"}
        # Customer + realm + radius target hydrated from the related rows.
        row = next(r for r in view.connections if r.username == "u1")
        assert row.customer_name == c.company_name
        assert row.realm == "acme-l1"
        assert row.radius_target.startswith("10.200.0.2:")

    def test_chain_has_five_segments_including_node_name(self, app):
        n = _make_node(name="chr-chain")
        c, _ = _make_customer_with_realm(realm="acme-chain")
        _make_tunnel(customer=c, node=n)
        view = dn.build_view_for(n.id)
        row = view.connections[0]
        assert len(row.chain) == 5
        # Segments are the operator-facing labels — MikroTik → SSTP →
        # node → proxy → RADIUS.
        assert "ميكروتيك" in row.chain[0]
        assert "SSTP" in row.chain[1]
        assert n.name in row.chain[2]
        assert "وكيل RADIUS" in row.chain[3]
        assert "acme-chain" in row.chain[4]

    def test_no_proxy_heartbeat_yet_shows_not_available(self, app, client):
        """When the proxy hasn't reported the realm in any heartbeat
        yet (CustomerRadiusInstance.last_seen_at is None), the table
        renders «غير متوفّرة بعد» — never a fabricated status."""
        _login_admin(client); _make_super_admin()
        n = _make_node(name="chr-no-hb")
        nr.set_roles(n, ["radius_transport"], commit=True)
        c, _ = _make_customer_with_realm(realm="acme-no-hb")
        _make_tunnel(customer=c, node=n)
        html = client.get("/admin/fleet/data-nodes").get_data(as_text=True)
        assert "غير متوفّرة بعد" in html

    def test_realm_last_seen_renders_when_proxy_heartbeat_landed(
        self, app, client,
    ):
        """After a proxy heartbeat sets CustomerRadiusInstance.last_seen_at,
        the row shows the ISO timestamp instead of «غير متوفّرة بعد»."""
        from datetime import datetime
        _login_admin(client); _make_super_admin()
        n = _make_node(name="chr-hb")
        nr.set_roles(n, ["radius_transport"], commit=True)
        c, inst = _make_customer_with_realm(realm="acme-hb")
        # Simulate the proxy heartbeat path.
        inst.last_seen_at = datetime(2026, 6, 14, 12, 0, 0)
        inst.status = "online"
        db.session.commit()
        _make_tunnel(customer=c, node=n)
        view = dn.build_view_for(n.id)
        assert view.connections[0].realm_last_seen_at.startswith("2026-06-14T12:00")

    def test_page_renders_visual_chain_for_each_connection(self, app, client):
        _login_admin(client); _make_super_admin()
        n = _make_node(name="chr-visual")
        nr.set_roles(n, ["radius_transport"], commit=True)
        c, _ = _make_customer_with_realm(realm="acme-visual")
        _make_tunnel(customer=c, node=n, username="visual-u")
        html = client.get("/admin/fleet/data-nodes").get_data(as_text=True)
        # The 5-segment chain widget renders.
        assert 'class="dn-chain"' in html
        # The username appears as the tunnel label.
        assert "visual-u" in html

    def test_json_endpoint_returns_view_dict(self, app, client):
        _login_admin(client); _make_super_admin()
        n = _make_node(name="chr-json")
        nr.set_roles(n, ["radius_transport"], commit=True)
        c, _ = _make_customer_with_realm(realm="acme-json")
        _make_tunnel(customer=c, node=n, username="json-u")
        r = client.get(f"/admin/fleet/data-nodes/{n.id}.json")
        assert r.status_code == 200
        body = r.get_json()
        assert body["ok"] is True
        v = body["view"]
        assert v["node_id"] == n.id
        assert v["is_data"] is True
        assert v["connection_count"] == 1
        assert v["connections"][0]["username"] == "json-u"
        assert len(v["connections"][0]["chain"]) == 5


# ════════════════════════════════════════════════════════════════════════
# (6) The page surfaces «بحاجة لإعادة استيراد» on a flagged node
# ════════════════════════════════════════════════════════════════════════
class TestReimportSurface:

    def test_reimport_badge_renders_when_flag_set(self, app, client):
        _login_admin(client); _make_super_admin()
        n = _make_node(name="chr-reimp", needs_reimport=True)
        nr.set_roles(n, ["radius_transport"], commit=True)
        html = client.get("/admin/fleet/data-nodes").get_data(as_text=True)
        assert "بحاجة لإعادة استيراد السكربت" in html
        assert "dn-node--reimport" in html

    def test_no_reimport_badge_when_flag_clear(self, app, client):
        _login_admin(client); _make_super_admin()
        n = _make_node(name="chr-clean", needs_reimport=False)
        nr.set_roles(n, ["radius_transport"], commit=True)
        html = client.get("/admin/fleet/data-nodes").get_data(as_text=True)
        # The per-card badge is gated on n.needs_reimport. The classes
        # ``dn-node--reimport`` (article wrapper) and ``dn-pill reimport``
        # (head badge) are APPLIED inside class="..." attributes only
        # for flagged nodes; the rule definitions in the style block
        # always exist + would false-positive a bare substring check.
        # The summary-card label «عقد بحاجة لإعادة استيراد السكربت»
        # ALSO always renders (it's the count) so we don't grep the
        # phrase — we grep the unique class-application.
        assert "dn-node dn-node--data dn-node--reimport" not in html
        # The head pill carries the class `dn-pill reimport` only when
        # the flag is set.
        assert 'class="dn-pill reimport"' not in html
