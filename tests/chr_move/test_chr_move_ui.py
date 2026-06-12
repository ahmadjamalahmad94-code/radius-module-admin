"""feat/panel-chr-move-public-ip — UI render integration test.

The service-layer tests (``test_chr_move.py``) verify the data + behaviour
contract. This file verifies the customer-detail page renders the move
control end-to-end:

  * The «نقل الـCHR / تغيير الـIP العام» card appears in tab-network.
  * The form posts to ``admin.move_customer_chr``.
  * Every eligible CHR appears in the target ``<select>`` with its
    ``public_ip`` exposed via ``data-public-ip``.
  * The current-egress IP line shows the customer's current public IP(s).
  * The button uses the design-system ``data-confirm-form`` modal
    (never a native ``alert/confirm``).

A passing render also writes a snapshot to repo root —
``_chr_move_ui_snapshot.html`` — for the owner to eyeball offline.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.extensions import db
from app.models import (
    Admin,
    Customer,
    CustomerRadiusInstance,
    ProxyRealmRoute,
)
from fleet.registry.models_chr import FleetChrNode, FleetProvider


def _login_admin(client):
    return client.post("/login", data={"username": "admin", "password": "admin12345"})


def _make_super_admin():
    adm = Admin.query.first()
    if adm and not adm.is_super_admin:
        adm.is_super_admin = True
        db.session.commit()


def _seed_provider():
    p = FleetProvider(name="ui-tests", cost_model="open", price_per_tb=0)
    db.session.add(p); db.session.flush()
    return p


def _seed_node(prov, *, name, public_ip, wg_octet, **overrides):
    defaults = dict(
        provider_id=prov.id,
        name=name,
        public_ip=public_ip,
        wg_mgmt_ip=f"10.99.0.{wg_octet}",
        wg_mgmt_pubkey="x" * 44,
        routeros_api_port=8729,
        coa_port=3799,
        max_sessions=500,
        link_speed_mbps=1000,
        enabled=True, drain=False, status="up",
        roles_json=json.dumps(["radius_transport", "vpn_sstp", "vpn_pptp",
                                "vpn_ipsec", "vpn_wireguard"]),
    )
    defaults.update(overrides)
    n = FleetChrNode(**defaults)
    db.session.add(n); db.session.flush()
    return n


def _seed_customer(*, name="Test SaaS Inc"):
    c = Customer(company_name=name, email="ops@testsaas.example", phone="")
    db.session.add(c); db.session.flush()
    inst = CustomerRadiusInstance(
        customer_id=c.id,
        instance_name=f"client{c.id}-radius",
        realm=f"client{c.id}",
        radius_auth_ip=f"10.200.{c.id}.2",
        status="online",
    )
    db.session.add(inst); db.session.flush()
    route = ProxyRealmRoute(
        realm=inst.realm, customer_id=c.id, radius_instance_id=inst.id,
        target_radius_ip=inst.radius_auth_ip, status="active",
    )
    db.session.add(route); db.session.commit()
    return c, inst, route


def test_move_card_renders_with_current_ip_and_eligible_targets(app, client):
    """End-to-end: seed customer + 2 eligible CHRs + 1 ineligible CHR,
    log in as super-admin, GET /admin/customers/<id>, assert the move
    card's invariants render correctly. Also writes
    ``_chr_move_ui_snapshot.html`` to the repo root for visual review."""
    prov = _seed_provider()
    node_a = _seed_node(prov, name="chr-old-de01", public_ip="203.0.113.10", wg_octet=11)
    node_b = _seed_node(prov, name="chr-new-fi02", public_ip="203.0.113.20", wg_octet=12)
    # Ineligible — drain — must NOT appear in the target list.
    _seed_node(prov, name="chr-drain-us03", public_ip="203.0.113.30",
               wg_octet=13, drain=True)
    cust, _, route = _seed_customer()
    route.allowed_fleet_chr_node_ids = [node_a.id]
    db.session.add(route); db.session.commit()

    _login_admin(client); _make_super_admin()
    resp = client.get(f"/admin/customers/{cust.id}")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)

    # The card header is present.
    assert "نقل الـCHR / تغيير الـIP العام" in body
    # The form posts to the move handler.
    assert f"/admin/customers/{cust.id}/move-chr" in body
    # The current egress IP is surfaced (we pinned the customer to node_a).
    assert "203.0.113.10" in body
    # Every eligible CHR is in the <select> with its public_ip
    # exposed via data-public-ip so the JS preview can pick it up.
    assert 'data-public-ip="203.0.113.10"' in body
    assert 'data-public-ip="203.0.113.20"' in body
    # The drain CHR is NOT offered as a target.
    assert "chr-drain-us03" not in body
    assert "203.0.113.30" not in body
    # The button uses the design-system confirm modal, NOT a native alert.
    assert 'data-confirm-form="cd-chrmove-form"' in body
    assert "alert(" not in body  # belt-and-braces
    # The page copy + the JS confirm-msg both reference the ≤60s queue
    # cycle so the operator knows the reconnect is async, not instant.
    assert "≤60 ثانية" in body
    assert "قائمة الانتظار" in body

    # Snapshot for the owner — write the rendered page so the
    # «بدي صورة» request has an artefact to open offline.
    out = Path(__file__).resolve().parents[2] / "_chr_move_ui_snapshot.html"
    out.write_text(body, encoding="utf-8")


def test_move_card_hidden_when_customer_has_no_radius_instance(app, client):
    """Defence: the card should not render for a customer with no
    realm — there's nothing to move."""
    cust = Customer(company_name="No Realm", email="x@x.x", phone="")
    db.session.add(cust); db.session.commit()
    _login_admin(client); _make_super_admin()
    resp = client.get(f"/admin/customers/{cust.id}")
    assert resp.status_code == 200
    assert "نقل الـCHR / تغيير الـIP العام" not in resp.get_data(as_text=True)


def test_move_card_shows_empty_state_when_no_eligible_nodes(app, client):
    """If every CHR is ineligible the card renders an explanatory
    empty-state — never an actionable form on top of an empty fleet."""
    prov = _seed_provider()
    _seed_node(prov, name="chr-drain", public_ip="1.1.1.1", wg_octet=11, drain=True)
    _seed_customer()
    _login_admin(client); _make_super_admin()
    cust = Customer.query.first()
    resp = client.get(f"/admin/customers/{cust.id}")
    body = resp.get_data(as_text=True)
    # The card section appears (the customer has a realm) but the form
    # is replaced by the empty-state copy.
    assert "نقل الـCHR / تغيير الـIP العام" in body
    assert "لا توجد عقد CHR مؤهَّلة" in body
    assert 'name="target_node_id"' not in body
