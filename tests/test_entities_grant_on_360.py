"""Grant «الجهات» (multi_tenant) directly from the Customer 360 page.

The provider activates the entities service for a specific customer from
/admin/customers/<id> (Customer 360): set entity_count + per-entity limits →
the service flows from fully-`hidden` to `granted` in the capacity contract.
Reversible: un-grant returns it to `hidden`.
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from app.extensions import db
from app.models import Admin, Customer, License, Plan, utcnow
from app.services.customer_control import build_runtime_contract_for_license


@pytest.fixture()
def cust_lic(app):
    plan = Plan.query.filter_by(slug="pro").one()
    c = Customer(company_name="Entities Co", email="ent360@example.com", status="active")
    db.session.add(c)
    db.session.flush()
    lic = License(customer_id=c.id, plan_id=plan.id, license_key="LIC-ENT360",
                  status="active", starts_at=utcnow() - timedelta(days=1),
                  expires_at=utcnow() + timedelta(days=365),
                  grace_until=utcnow() + timedelta(days=372))
    db.session.add(lic)
    db.session.commit()
    return c, lic


def _admin(client):
    a = Admin.query.first()
    with client.session_transaction() as s:
        s["admin_id"] = a.id


def _mt(lic):
    return build_runtime_contract_for_license(
        lic, license_active=True, status="active")["services"]["multi_tenant"]


# ── the control is on the 360 page ───────────────────────────────────────────
def test_360_page_shows_entities_grant_control(app, client, cust_lic):
    c, _lic = cust_lic
    _admin(client)
    body = client.get(f"/admin/customers/{c.id}").get_data(as_text=True)
    assert "تفعيل خدمة الجهات" in body
    assert 'name="entity_count"' in body
    assert 'name="entity_max_subscribers"' in body   # a per-entity limit field
    assert 'name="return_to"' in body                # returns to 360 on submit


# ── grant from 360 → granted in the contract with entity_count + per-entity ──
def test_grant_from_360_emits_into_contract(app, client, cust_lic):
    c, lic = cust_lic
    _admin(client)
    # hidden before
    assert _mt(lic)["visibility"] == "hidden"
    r = client.post(f"/admin/customers/{c.id}/grant-entities", data={
        "action": "grant", "return_to": "detail",
        "entity_count": "4",
        "entity_max_subscribers": "150",
        "entity_max_cards": "300",
        "entity_max_nas": "3",
    }, follow_redirects=False)
    assert r.status_code in (301, 302)
    assert f"/admin/customers/{c.id}" in r.headers["Location"]   # back to 360
    db.session.expire_all()
    mt = _mt(lic)
    assert mt["visibility"] == "granted"
    assert mt["enabled"] is True
    assert mt["entity_count"] == 4
    assert mt["per_entity_limits"] == {
        "max_subscribers": 150, "max_cards": 300, "max_nas": 3,
    }


# ── un-grant from 360 → hidden again ─────────────────────────────────────────
def test_ungrant_from_360_returns_to_hidden(app, client, cust_lic):
    c, lic = cust_lic
    _admin(client)
    client.post(f"/admin/customers/{c.id}/grant-entities", data={
        "action": "grant", "return_to": "detail", "entity_count": "2",
        "entity_max_subscribers": "100",
    }, follow_redirects=False)
    db.session.expire_all()
    assert _mt(lic)["visibility"] == "granted"
    # revoke
    r = client.post(f"/admin/customers/{c.id}/grant-entities", data={
        "action": "revoke", "return_to": "detail",
    }, follow_redirects=False)
    assert f"/admin/customers/{c.id}" in r.headers["Location"]
    db.session.expire_all()
    mt = _mt(lic)
    assert mt["visibility"] == "hidden"
    assert mt["enabled"] is False
    assert "entity_count" not in mt


# ── stays hidden until granted (no grant → hidden, not an upsell) ────────────
def test_hidden_until_granted_default(app, client, cust_lic):
    _c, lic = cust_lic
    mt = _mt(lic)
    assert mt["visibility"] == "hidden"
    assert mt["status"] == "hidden"
    assert mt["upgradable"] is False
