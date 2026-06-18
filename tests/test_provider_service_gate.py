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
    # `reports` is a single-service gate → an explicit «موقوفة» suspend is the
    # ONLY thing that maps to a hard `disabled` (radius hides+403).
    c, lic = cust_lic
    ent = get_or_create_service_entitlement(c, "reports")
    ent.status = "suspended"
    ent.enabled = False
    db.session.commit()
    g = _grants(lic)["reports"]
    assert g["enabled"] is False and g["status"] == "disabled"
    assert g["requires_activation"] is False


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


def test_suspending_all_mapped_services_hard_disables_the_section(cust_lic):
    """Suspend every service feeding `communications` → hard `disabled`
    (nothing left sellable, all explicitly «موقوفة»)."""
    c, lic = cust_lic
    # communications gate now = communications + whatsapp_gateway + sms_gateway;
    # suspend ALL so nothing is left sellable → hard disabled.
    for key in ("communications", "whatsapp_gateway", "sms_gateway"):
        ent = get_or_create_service_entitlement(c, key)
        ent.status = "suspended"
        ent.enabled = False
    db.session.commit()
    g = _grants(lic)["communications"]
    assert g["enabled"] is False and g["status"] == "disabled"
    assert g["requires_activation"] is False


def test_build_provider_grants_unit_semantics():
    services = {
        # both off + explicitly suspended, nothing sellable → hard disabled
        "communications": {"enabled": False, "status": "suspended", "tier": "paid", "hidden": True},
        "whatsapp_gateway": {"enabled": False, "status": "suspended", "tier": "paid", "hidden": True},
        # paid + off + NOT suspended → locked_upgrade (visible upsell)
        "card_marketplace": {"enabled": False, "status": "disabled", "tier": "paid"},  # → store
        "reports": {"enabled": True, "status": "active", "hidden": False,
                    "limits": {"max_reports": 5}},
        "integration_bridge": {"enabled": True, "status": "active"},  # → settings
    }
    g = build_provider_grants(services)
    # all-suspended section → hard disabled (radius hides+403)
    assert g["communications"]["status"] == "disabled"
    assert g["communications"]["enabled"] is False and g["communications"]["hidden"] is True
    assert g["communications"]["requires_activation"] is False
    # paid-not-purchased → locked_upgrade (radius shows locked + upgrade CTA)
    assert g["store"]["status"] == "locked_upgrade"
    assert g["store"]["requires_activation"] is True and g["store"]["enabled"] is False
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


# ── FIX 1: license block unlocks the radius lifecycle gate ───────────────────
def test_contract_carries_license_block(cust_lic):
    _c, lic = cust_lic
    blk = _contract(lic)["license"]
    # The fields the radius lifecycle gate reads — redundant aliases so it
    # unlocks however it keys on them.
    assert blk["active"] is True and blk["activated"] is True
    assert blk["status"] == "active" and blk["state"] == "active"
    assert blk["expires_at"]  # ISO timestamp present


def test_bridge_endpoint_mirrors_license_at_top_level(app, client, cust_lic):
    """The CRITICAL unlock: license must be a TOP-LEVEL sibling of
    provider_grants (the gate read the response root and found none → locked)."""
    _c, lic = cust_lic
    data = client.post("/api/integration/hoberadius/capacity-contract",
                       json={"license_key": lic.license_key}, **HTTPS).get_json()
    assert "license" in data, "top-level license block missing → radius would lock"
    assert data["license"]["active"] is True
    assert data["license"]["activated"] is True
    assert data["license"]["status"] == "active"
    assert data["license"]["expires_at"]
    # license sits next to provider_grants at the root
    assert "provider_grants" in data


# ── FIX 2: paid-not-purchased is locked_upgrade, not disabled ────────────────
def test_paid_default_service_is_locked_upgrade_not_disabled(cust_lic):
    """Under the owner's model only the five infrastructure services are paid;
    each emits at the SERVICE level as locked_upgrade (visible «طلب تفعيل»),
    NEVER disabled — and nothing is hard-`disabled` in a fresh customer."""
    _c, lic = cust_lic
    ct = _contract(lic)
    services = ct["services"]
    # a default-paid service is a VISIBLE upsell at the service level
    ip = services["ip_change_vpn"]
    assert ip["tier"] == "paid"
    assert ip["status"] == "locked_upgrade"
    assert ip["requires_activation"] is True
    assert ip["enabled"] is False
    # NOTHING is hard-disabled purely from paid defaults (nothing suspended) —
    # not a single service, not a single gate.
    assert all(s.get("status") != "disabled" for s in services.values())
    assert all(g["status"] != "disabled" for g in ct["provider_grants"].values())
    # free software is open: the `store` section (card_marketplace …) is active
    assert ct["provider_grants"]["store"]["status"] == "active"


def test_only_explicit_suspend_hard_disables(cust_lic):
    """The ONLY thing that maps to a hard `disabled` is an explicit «موقوفة»
    suspend. customer_support is the sole service feeding `service_requests`
    (a clean single-service gate); free by default → active; suspended → disabled."""
    c, lic = cust_lic
    # default (free software) → the section is OPEN
    assert _grants(lic)["service_requests"]["status"] == "active"
    # explicit «موقوفة» → hard disabled (radius hide + 403)
    ent = get_or_create_service_entitlement(c, "customer_support")
    ent.status = "suspended"
    ent.enabled = False
    db.session.commit()
    assert _grants(lic)["service_requests"]["status"] == "disabled"
