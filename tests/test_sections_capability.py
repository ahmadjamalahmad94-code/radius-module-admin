"""«إدارة أقسام الواجهة» / sections — the provider-side grant for the customer
radius's /admin/radius/sections capability.

The customer radius treats the capability key ``sections`` as GRANTED when the
provider contract has ``services.sections`` enabled+active (or
``features.sections == "enabled"``); otherwise the page is hidden + the route is
gated. This module proves the PROVIDER side:

  • DEFAULT is OFF — services.sections is hidden (enabled False, status "hidden")
    for every customer, since the feature is still under development.
  • The provider grant route writes the entitlement in the exact shape the
    customer reads as GRANTED: enabled=True, status="active",
    config["visibility"]="granted" → services.sections enabled+active.
  • Revoke clears it back to hidden (default OFF), leaving no residue.
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
    c = Customer(company_name="Sections Co", email="sections@example.com", status="active")
    db.session.add(c)
    db.session.flush()
    lic = License(customer_id=c.id, plan_id=plan.id, license_key="LIC-SECTIONS-TEST",
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


def _sections(lic):
    return build_runtime_contract_for_license(
        lic, license_active=True, status="active")["services"]["sections"]


# ── default: fully hidden / OFF (NOT granted) ─────────────────────────────────
def test_sections_hidden_by_default(cust_lic):
    _c, lic = cust_lic
    sec = _sections(lic)
    # The customer reads "enabled+active" as GRANTED — default must NOT satisfy it.
    assert sec["enabled"] is False
    assert sec["status"] == "hidden"          # distinct from active/locked_upgrade
    assert sec["visibility"] == "hidden"
    assert sec["hidden"] is True
    # plain on/off capability — no «الجهات» entity fields leak in
    assert "entity_count" not in sec
    assert "per_entity_limits" not in sec


def test_sections_absent_from_provider_grants_by_default(cust_lic):
    """A hidden capability must not surface in any aggregated section gate."""
    _c, lic = cust_lic
    grants = build_runtime_contract_for_license(
        lic, license_active=True, status="active")["provider_grants"]
    for gate in grants.values():
        assert "sections" not in gate.get("services", [])


# ── grant via the provider route → enabled+active (the shape the customer reads) ─
def test_grant_makes_sections_enabled_and_active(app, client, cust_lic):
    c, lic = cust_lic
    _admin_client(app, client)
    r = client.post(f"/admin/customers/{c.id}/grant-sections", data={
        "action": "grant",
    }, follow_redirects=False)
    assert r.status_code in (301, 302)
    db.session.expire_all()
    sec = _sections(lic)
    # Exactly what the customer side gates /admin/radius/sections on:
    assert sec["enabled"] is True
    assert sec["status"] == "active"
    assert sec["visibility"] == "granted"
    # Persisted contract shape on the entitlement itself.
    ent = get_or_create_service_entitlement(c, "sections")
    assert ent.enabled is True
    assert ent.status == "active"
    assert (ent.config or {}).get("visibility") == "granted"


def test_granted_then_revoked_hides_again(app, client, cust_lic):
    c, lic = cust_lic
    _admin_client(app, client)
    client.post(f"/admin/customers/{c.id}/grant-sections", data={"action": "grant"},
                follow_redirects=False)
    db.session.expire_all()
    assert _sections(lic)["visibility"] == "granted"
    # revoke → fully hidden again (back to default OFF, no residue)
    client.post(f"/admin/customers/{c.id}/grant-sections", data={"action": "revoke"},
                follow_redirects=False)
    db.session.expire_all()
    sec = _sections(lic)
    assert sec["enabled"] is False
    assert sec["status"] == "hidden"
    assert sec["visibility"] == "hidden"
    ent = get_or_create_service_entitlement(c, "sections")
    assert "visibility" not in (ent.config or {})


# ── stays OFF in the free trial (NOT part of the trial offer) ─────────────────
def test_sections_hidden_even_in_trial(app, cust_lic):
    c, _lic = cust_lic
    from app.services.trial_plan import apply_trial_to_customer
    trial_lic = apply_trial_to_customer(c)["license"]
    sec = _sections(trial_lic)
    assert sec["enabled"] is False
    assert sec["visibility"] == "hidden"
