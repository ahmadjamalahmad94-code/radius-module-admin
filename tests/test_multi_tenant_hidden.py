"""«الجهات» / multi_tenant — the FULLY-HIDDEN-until-granted service.

A state distinct from locked_upgrade: the customer doesn't see it AT ALL — no
sidebar entry, no «طلب تفعيل» upsell — until the provider explicitly grants it.
On grant the provider sets entity_count + a per-entity limit set; both ride in
entitlement.config and flow into the capacity contract under
``services.multi_tenant.visibility`` ("hidden" | "granted"). Revoke hides it
again. The radius reads ``visibility`` directly; build_provider_grants drops a
hidden entry entirely (it never bucketed into the settings section as an upsell).
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from app.extensions import db
from app.models import Admin, Customer, License, Plan, utcnow
from app.services.customer_control import (
    build_runtime_contract_for_license,
    get_or_create_service_entitlement,
)


@pytest.fixture()
def cust_lic(app):
    plan = Plan.query.filter_by(slug="pro").one()
    c = Customer(company_name="Tenant Co", email="tenant@example.com", status="active")
    db.session.add(c)
    db.session.flush()
    lic = License(customer_id=c.id, plan_id=plan.id, license_key="LIC-MT-TEST",
                  status="active", starts_at=utcnow() - timedelta(days=1),
                  expires_at=utcnow() + timedelta(days=365),
                  grace_until=utcnow() + timedelta(days=372))
    db.session.add(lic)
    db.session.commit()
    return c, lic


def _admin_client(app, client):
    admin = Admin.query.first()
    with client.session_transaction() as s:
        s["admin_id"] = admin.id
    return client


def _mt(lic):
    return build_runtime_contract_for_license(
        lic, license_active=True, status="active")["services"]["multi_tenant"]


# ── default: fully hidden (NOT locked_upgrade) ─────────────────────────────────
def test_hidden_by_default(cust_lic):
    _c, lic = cust_lic
    mt = _mt(lic)
    assert mt["visibility"] == "hidden"
    assert mt["status"] == "hidden"          # distinct from "locked_upgrade"
    assert mt["enabled"] is False
    assert mt["upgradable"] is False         # NOT even an upsell
    assert mt["hidden"] is True
    assert "limits" not in mt                # no caps leak while hidden


def test_hidden_entry_absent_from_provider_grants(cust_lic):
    """A hidden-until-granted service contributes NOTHING to its section gate —
    multi_tenant maps to `settings`, but while hidden it must not appear in the
    settings grant's services list (it's invisible, not an upsell)."""
    _c, lic = cust_lic
    grants = build_runtime_contract_for_license(
        lic, license_active=True, status="active")["provider_grants"]
    # settings stays present (integration_bridge etc.), but without multi_tenant
    assert "multi_tenant" not in grants.get("settings", {}).get("services", [])


# ── grant via the provider route → visible + carries entity_count + limits ─────
def test_grant_sets_entity_count_and_per_entity_limits(app, client, cust_lic):
    c, lic = cust_lic
    _admin_client(app, client)
    r = client.post(f"/admin/customers/{c.id}/grant-entities", data={
        "action": "grant",
        "entity_count": "3",
        "entity_max_subscribers": "200",
        "entity_max_cards": "500",
        "entity_max_nas": "5",
    }, follow_redirects=False)
    assert r.status_code in (301, 302)
    db.session.expire_all()
    mt = _mt(lic)
    assert mt["visibility"] == "granted"
    assert mt["enabled"] is True
    assert mt["entity_count"] == 3
    assert mt["per_entity_limits"] == {
        "max_subscribers": 200, "max_cards": 500, "max_nas": 5,
    }


def test_granted_then_revoked_hides_again(app, client, cust_lic):
    c, lic = cust_lic
    _admin_client(app, client)
    client.post(f"/admin/customers/{c.id}/grant-entities", data={
        "action": "grant", "entity_count": "2", "entity_max_subscribers": "100",
    }, follow_redirects=False)
    db.session.expire_all()
    assert _mt(lic)["visibility"] == "granted"
    # revoke → fully hidden again (no upsell residue)
    client.post(f"/admin/customers/{c.id}/grant-entities", data={
        "action": "revoke",
    }, follow_redirects=False)
    db.session.expire_all()
    mt = _mt(lic)
    assert mt["visibility"] == "hidden"
    assert mt["enabled"] is False
    assert "entity_count" not in mt
    ent = get_or_create_service_entitlement(c, "multi_tenant")
    assert "visibility" not in (ent.config or {})


# ── stays hidden in the free trial (NOT part of the trial offer) ──────────────
def test_hidden_even_in_trial(app, cust_lic):
    c, _lic = cust_lic
    from app.services.trial_plan import apply_trial_to_customer
    trial_lic = apply_trial_to_customer(c)["license"]
    mt = _mt(trial_lic)
    assert mt["visibility"] == "hidden"
    assert mt["enabled"] is False
