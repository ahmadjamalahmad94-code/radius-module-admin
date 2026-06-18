"""Provider→radius service-gate emission in the capacity contract.

Verifies that a provider service the owner disabled / hid / limited reaches the
radius gate under one of its 14 section keys (`provider_grants`), that the
aggregation semantics hold, that the map covers the whole catalog, and that the
contract fingerprint changes when the operator saves a tariff (propagation).
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from app.extensions import db
from app.models import (
    Customer, License, Plan, ServiceCatalogItem, utcnow,
)
from app.services.customer_control import (
    SERVICE_TIER_FREE_LIMITED,
    build_runtime_contract_for_license,
    get_or_create_service_entitlement,
    set_catalog_policy,
    set_service_hidden,
)
from app.services.provider_service_gate import (
    PROVIDER_TO_GATE, RADIUS_GATE_KEYS, build_provider_grants,
)

HTTPS = {"base_url": "https://license-panel.test"}


@pytest.fixture()
def cust_lic(app):
    plan = Plan.query.filter_by(slug="pro").one()
    c = Customer(company_name="Gate Co", email="gate@example.com", status="active")
    db.session.add(c)
    db.session.flush()
    lic = License(customer_id=c.id, plan_id=plan.id, license_key="LIC-GATE-TEST",
                  status="active", starts_at=utcnow() - timedelta(days=1),
                  expires_at=utcnow() + timedelta(days=365),
                  grace_until=utcnow() + timedelta(days=372))
    db.session.add(lic)
    db.session.commit()
    return c, lic


def _contract(lic):
    return build_runtime_contract_for_license(lic, license_active=True, status="active")


def _grants(lic):
    return _contract(lic)["provider_grants"]


# ── shape ─────────────────────────────────────────────────────────────────--
def test_contract_carries_provider_grants_and_fingerprint(cust_lic):
    _c, lic = cust_lic
    ct = _contract(lic)
    assert "provider_grants" in ct and isinstance(ct["provider_grants"], dict)
    assert ct.get("fingerprint")
    # every emitted gate key is one of the 14 (anti_mac_clone may be absent)
    assert set(ct["provider_grants"]).issubset(set(RADIUS_GATE_KEYS))


def test_anti_mac_clone_omitted_no_provider_service(cust_lic):
    _c, lic = cust_lic
    assert "anti_mac_clone" not in _grants(lic)   # radius default-enables it


# ── disable / hide / limit reach the gate key ───────────────────────────────
def test_suspended_provider_service_gates_its_section(cust_lic):
    # `reports` is a single-service gate → suspending it gates `reports`.
    c, lic = cust_lic
    ent = get_or_create_service_entitlement(c, "reports")
    ent.status = "suspended"
    ent.enabled = False
    db.session.commit()
    g = _grants(lic)["reports"]
    assert g["enabled"] is False and g["status"] == "suspended"


def test_hidden_provider_service_marks_gate_hidden(cust_lic):
    c, lic = cust_lic
    ent = get_or_create_service_entitlement(c, "reports")
    ent.status = "active"
    ent.enabled = True
    set_service_hidden(ent, True)
    db.session.commit()
    g = _grants(lic)["reports"]
    assert g["hidden"] is True


def test_limit_emitted_into_gate(cust_lic):
    c, lic = cust_lic
    item = ServiceCatalogItem.query.filter_by(service_key="subscribers").one()
    set_catalog_policy(item, SERVICE_TIER_FREE_LIMITED)
    ent = get_or_create_service_entitlement(c, "subscribers")
    ent.limits = {"max_total": 500}
    db.session.commit()
    g = _grants(lic)["subscribers"]
    assert g.get("limits", {}).get("max_total") == 500
    # And the top-level limits map still carries the dotted path.
    assert _contract(lic)["limits"]["subscribers"]["max_total"] >= 0


# ── aggregation semantics ────────────────────────────────────────────────────
def test_any_enabled_keeps_multi_service_section_available(cust_lic):
    """Suspending ONE service of a multi-service gate does NOT gate the section
    (subscribers gate = subscribers + subscriber_groups + sessions)."""
    c, lic = cust_lic
    ent = get_or_create_service_entitlement(c, "subscribers")
    ent.status = "suspended"
    ent.enabled = False
    db.session.commit()
    ct = _contract(lic)
    assert ct["services"]["subscribers"]["enabled"] is False   # the service itself
    assert ct["provider_grants"]["subscribers"]["enabled"] is True  # section stays (sessions/groups)


def test_disabling_all_mapped_services_gates_the_section(cust_lic):
    """Suspend every service feeding `communications` → the gate disables."""
    c, lic = cust_lic
    for key in ("communications", "whatsapp_gateway"):
        ent = get_or_create_service_entitlement(c, key)
        ent.status = "suspended"
        ent.enabled = False
    db.session.commit()
    g = _grants(lic)["communications"]
    assert g["enabled"] is False and g["status"] == "suspended"


def test_build_provider_grants_unit_semantics():
    services = {
        "communications": {"enabled": False, "status": "disabled", "hidden": True},
        "whatsapp_gateway": {"enabled": False, "status": "suspended", "hidden": True},
        "reports": {"enabled": True, "status": "active", "hidden": False,
                    "limits": {"max_reports": 5}},
        "integration_bridge": {"enabled": True, "status": "active"},  # → settings
    }
    g = build_provider_grants(services)
    assert g["communications"] == {
        "enabled": False, "status": "suspended", "hidden": True,
        "services": ["communications", "whatsapp_gateway"],
    }
    assert g["reports"]["enabled"] is True and g["reports"]["limits"] == {"max_reports": 5}
    assert "settings" in g  # integration_bridge mapped to settings


# ── mapping completeness (guardrail) ─────────────────────────────────────────
def test_mapping_values_are_valid_gate_keys():
    assert set(PROVIDER_TO_GATE.values()).issubset(set(RADIUS_GATE_KEYS))


def test_mapping_covers_full_catalog(app):
    """Every provider catalog service must map to a gate key (or be explicitly
    listed below as intentionally provider-only) — so nothing silently bypasses
    the gate when the catalog grows."""
    intentionally_unmapped: set[str] = set()  # none today
    catalog_keys = {i.service_key for i in ServiceCatalogItem.query.all()}
    unmapped = catalog_keys - set(PROVIDER_TO_GATE) - intentionally_unmapped
    assert unmapped == set(), f"unmapped provider services: {sorted(unmapped)}"


# ── propagation: fingerprint changes on tariff save ──────────────────────────
def test_fingerprint_changes_when_tariff_saved(app, client, cust_lic):
    c, lic = cust_lic
    before = _contract(lic)["fingerprint"]
    client.post("/login", data={"username": "admin", "password": "admin12345"})
    res = client.post(f"/admin/customers/{c.id}/service-tiers", data={
        "tier_reports": "free_unlimited",
        "suspended_reports": "on",
    }, follow_redirects=True)
    assert res.status_code == 200
    db.session.expire_all()
    after = _contract(lic)["fingerprint"]
    assert after != before


# ── bridge endpoint surfaces it (bearer/HTTPS) ───────────────────────────────
def test_bridge_endpoint_returns_provider_grants(app, client, cust_lic):
    _c, lic = cust_lic
    res = client.post("/api/integration/hoberadius/capacity-contract",
                      json={"license_key": lic.license_key}, **HTTPS)
    assert res.status_code == 200
    data = res.get_json()
    assert data["ok"] is True
    assert "provider_grants" in data and "fingerprint" in data
    assert set(data["provider_grants"]).issubset(set(RADIUS_GATE_KEYS))
    # also inside the nested contract
    assert "provider_grants" in data["contract"]


def test_heartbeat_returns_capacity_fingerprint(app, client, cust_lic):
    _c, lic = cust_lic
    res = client.post("/api/integration/hoberadius/instance-ops/heartbeat",
                      json={"license_key": lic.license_key}, **HTTPS)
    # 200 with the fingerprint hint (provision may be a no-op; that's fine).
    assert res.status_code == 200
    body = res.get_json()
    assert body.get("ok") is True
    assert body.get("capacity_fingerprint")
