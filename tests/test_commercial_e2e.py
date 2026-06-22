"""COMMERCIAL END-TO-END suite — the pre-launch verification on the provider side.

This is the capstone over the commercial model (trial, packages, pricing,
discounts, service gate states, activations, support line, hide/declutter,
«الجهات»). Where it adds value it drives the REAL bridge surface the customer
radius pulls (`/api/integration/hoberadius/...`) so we prove the emitted
contract — not just the internal helpers — is correct end to end.

Scenario groups:
  A. License lifecycle (never-activated → active → expired → grace; suspended).
  B. Trial 14-day → 100 concurrent-online.
  C. Packages → concurrent-online cap (all six).
  D. Duration discounts compute + are editable.
  E. The five service-gate states each map to the right contract fields.
  F. Activations: «طلب تفعيل» → provider queue → approve → contract.
  G. «الجهات» grant emits entity_count + per_entity_limits.
  H. Support line: ticket + chat + notice round-trips over the bridge.
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from app.extensions import db
from app.models import (
    Admin, Customer, CustomerServiceRequest, License, Plan, ServiceCatalogItem, utcnow,
)
from app.services import subscription_pricing as sp
from app.services.customer_control import (
    SERVICE_TIER_FREE_UNLIMITED,
    build_runtime_contract_for_license,
    get_or_create_service_entitlement,
    set_catalog_policy,
    set_service_hidden,
)

HTTPS = {"base_url": "https://license-panel.test"}


def _admin(client):
    a = Admin.query.first()
    with client.session_transaction() as s:
        s["admin_id"] = a.id


def _customer(name="E2E Co", email="e2e@example.com", status="active"):
    c = Customer(company_name=name, email=email, status=status)
    db.session.add(c)
    db.session.flush()
    return c


def _license(customer, plan, *, key, expires_days=365, grace_days=7, status="active"):
    now = utcnow()
    lic = License(customer_id=customer.id, plan_id=plan.id, license_key=key, status=status,
                  starts_at=now - timedelta(days=1),
                  expires_at=now + timedelta(days=expires_days),
                  grace_until=now + timedelta(days=expires_days + grace_days))
    db.session.add(lic)
    db.session.commit()
    return lic


def _capacity(client, license_key):
    return client.post("/api/integration/hoberadius/capacity-contract",
                       json={"license_key": license_key}, **HTTPS)


# ── A. LICENSE LIFECYCLE (through the bridge) ─────────────────────────────────
def test_lifecycle_never_activated(app, client):
    """No valid license → radius stays locked. An unknown key can't even
    authenticate the bridge (401), and at the contract level a null license
    reports not-activated."""
    # bridge: unknown key is rejected at the bearer layer
    assert _capacity(client, "HBR-DOES-NOT-EXIST").status_code == 401
    # contract semantics: a null license is activated=False / active=False
    with app.app_context():
        block = build_runtime_contract_for_license(None, license_active=False, status="not_found")["license"]
        assert block["activated"] is False and block["active"] is False


def test_lifecycle_pending_customer_blocked(app, client):
    """A license whose customer is still «pending» (not yet activated by the
    admin) is blocked at the bridge with a machine-readable reason."""
    with app.app_context():
        plan = Plan.query.filter_by(slug="pro").one()
        c = _customer(email="pending@x.com", status="pending")
        _license(c, plan, key="HBR-E2E-PENDING")
    r = _capacity(client, "HBR-E2E-PENDING")
    assert r.status_code == 403
    assert r.get_json()["reason"] == "customer_pending"


def test_lifecycle_active(app, client):
    with app.app_context():
        plan = Plan.query.filter_by(slug="pro").one()
        lic = _license(_customer(email="active@x.com"), plan, key="HBR-E2E-ACTIVE")
    data = _capacity(client, "HBR-E2E-ACTIVE").get_json()
    assert data["license"]["active"] is True
    assert data["license"]["activated"] is True
    assert data["license"]["status"] == "active"


def test_lifecycle_expired_past_grace(app, client):
    with app.app_context():
        plan = Plan.query.filter_by(slug="pro").one()
        # expired 10 days ago, grace ended 3 days ago
        _license(_customer(email="exp@x.com"), plan, key="HBR-E2E-EXP",
                 expires_days=-10, grace_days=7)
    data = _capacity(client, "HBR-E2E-EXP").get_json()
    assert data["license"]["active"] is False
    assert data["license"]["status"] == "expired"


def test_lifecycle_in_grace(app, client):
    with app.app_context():
        plan = Plan.query.filter_by(slug="pro").one()
        # expired 2 days ago, but grace still has 5 days left
        _license(_customer(email="grace@x.com"), plan, key="HBR-E2E-GRACE",
                 expires_days=-2, grace_days=7)
    data = _capacity(client, "HBR-E2E-GRACE").get_json()
    assert data["license"]["active"] is True            # grace still operates
    assert data["license"]["status"] == "grace"


def test_lifecycle_suspended_denied(app, client):
    with app.app_context():
        plan = Plan.query.filter_by(slug="pro").one()
        _license(_customer(email="susp@x.com"), plan, key="HBR-E2E-SUSP", status="suspended")
    data = _capacity(client, "HBR-E2E-SUSP").get_json()
    assert data["license"]["active"] is False


# ── B. TRIAL → 100 concurrent-online ─────────────────────────────────────────
def test_trial_emits_100_concurrent_and_14_days(app, client):
    with app.app_context():
        from app.services.trial_plan import apply_trial_to_customer
        c = _customer(email="trial@x.com")
        res = apply_trial_to_customer(c)
        lic_key = res["license"].license_key
        assert res["days"] == 14
    data = _capacity(client, lic_key).get_json()
    assert data["limits"]["active_online"]["max"] == 100
    assert data["license"]["active"] is True


# ── C. PACKAGES → concurrent-online cap (all six) ────────────────────────────
@pytest.mark.parametrize("slug,cap", [
    ("pkg_cafes", 50), ("pkg_starter", 100), ("pkg_networks", 250),
    ("pkg_large", 500), ("pkg_companies", 1000), ("pkg_unlimited", 0),
])
def test_each_package_emits_its_concurrency_cap(app, client, slug, cap):
    with app.app_context():
        plan = Plan.query.filter_by(slug=slug).one()
        lic = _license(_customer(email=f"{slug}@x.com"), plan, key=f"HBR-{slug.upper()}")
    data = _capacity(client, f"HBR-{slug.upper()}").get_json()
    assert data["limits"]["active_online"]["max"] == cap
    assert data["limits"]["active_online"]["scope"] == "instance"
    assert data["limits"]["active_online"]["counts"] == "all_session_types"


# ── D. DISCOUNTS compute + editable ──────────────────────────────────────────
def test_discounts_compute_default_and_editable(app):
    with app.app_context():
        # default: 12 months × $50 → 20% off → $480
        q = sp.quote(50, 12)
        assert q.percent == 20 and q.total == 480 and q.savings == 120
        # edit a tier → recompute
        sp.set_discount_tiers([{"months": 12, "percent": 25, "enabled": True}])
        db.session.commit()
        assert sp.quote(50, 12).total == 450        # 600 × 0.75
        assert sp.discount_percent_for(3) == 0       # removed tier


# ── E. THE FIVE GATE STATES → contract fields ────────────────────────────────
@pytest.fixture()
def gate_cust(app):
    plan = Plan.query.filter_by(slug="pro").one()
    c = _customer(email="gate@x.com")
    lic = _license(c, plan, key="HBR-E2E-GATE")
    return c, lic


def _svc(lic, key):
    return build_runtime_contract_for_license(lic, license_active=True, status="active")["services"][key]


def _grant(lic, gate):
    return build_runtime_contract_for_license(lic, license_active=True, status="active")["provider_grants"].get(gate)


def test_gate_state_free_enabled(gate_cust):
    c, lic = gate_cust
    item = ServiceCatalogItem.query.filter_by(service_key="reports").one()
    set_catalog_policy(item, SERVICE_TIER_FREE_UNLIMITED)
    db.session.commit()
    assert _svc(lic, "reports")["enabled"] is True
    assert _grant(lic, "reports")["status"] == "active"


def test_gate_state_locked_upgrade(gate_cust):
    _c, lic = gate_cust
    # Only the five infrastructure services are paid; each is a VISIBLE upsell at
    # the SERVICE level (locked_upgrade + «طلب تفعيل»), never a hard block.
    ip = _svc(lic, "ip_change_vpn")
    assert ip["tier"] == "paid"
    assert ip["status"] == "locked_upgrade" and ip["requires_activation"] is True and ip["enabled"] is False


def test_gate_state_disabled_commercial_block(gate_cust):
    c, lic = gate_cust
    ent = get_or_create_service_entitlement(c, "reports")
    ent.status = "suspended"; ent.enabled = False
    db.session.commit()
    assert _grant(lic, "reports")["status"] == "disabled"


def test_gate_state_hidden_declutter(gate_cust):
    c, lic = gate_cust
    ent = get_or_create_service_entitlement(c, "reports")
    ent.status = "active"; ent.enabled = True
    set_service_hidden(ent, True)
    db.session.commit()
    g = _grant(lic, "reports")
    assert g["hidden"] is True and g["enabled"] is True and g["status"] == "active"  # no 403


def test_gate_state_hidden_until_granted(gate_cust):
    _c, lic = gate_cust
    mt = _svc(lic, "multi_tenant")
    assert mt["visibility"] == "hidden" and mt["status"] == "hidden" and mt["upgradable"] is False


# ── E′. The «شركتي» live scenario: free software open, paid locked, none blocked
def test_fresh_customer_correct_commercial_state(gate_cust):
    """The exact state the owner wants on the live radius for «شركتي»: a fresh
    active customer has all SOFTWARE accessible, only the infrastructure
    services as «طلب تفعيل», and NOTHING hard-disabled (no «موقوفة»)."""
    _c, lic = gate_cust
    ct = build_runtime_contract_for_license(lic, license_active=True, status="active")
    services, grants = ct["services"], ct["provider_grants"]

    # «تغيير عنوان الإنترنت» is now ONE merged paid card (ip_change_vpn); the
    # retired public_ip_change is no longer a separate catalog service.
    PAID = {"ip_change_vpn", "remote_support", "remote_health_fix", "multi_tenant"}
    assert "public_ip_change" not in services  # no orphan second card

    # finance-center (the live symptom) is now OPEN — free + enabled, gate active.
    fc = services["finance_center"]
    assert fc["enabled"] is True and fc["status"] == "active"
    assert grants["finance"]["status"] == "active"

    # representative free software is enabled
    for k in ("accounting", "invoices", "communications", "reports", "cards",
              "subscribers", "routers", "whatsapp_gateway", "sms_gateway", "backups"):
        assert services[k]["enabled"] is True, f"{k} should be free+enabled"
        assert services[k]["status"] == "active"

    # the NON-hidden paid services are visible upsells (locked_upgrade)
    for k in ("ip_change_vpn", "remote_support", "remote_health_fix"):
        assert services[k]["enabled"] is False
        assert services[k]["status"] == "locked_upgrade", f"{k} must be locked_upgrade"
        assert services[k]["requires_activation"] is True
    # multi_tenant is the fully-hidden paid service
    assert services["multi_tenant"]["visibility"] == "hidden"

    # NOTHING is hard-disabled (nothing explicitly «موقوفة») — service or gate
    assert all(s.get("status") != "disabled" for s in services.values())
    assert all(g["status"] != "disabled" for g in grants.values())

    # and only these are paid; everything else is free
    paid_services = {k for k, s in services.items() if s.get("tier") == "paid"}
    assert paid_services == PAID


# ── F. ACTIVATIONS over the bridge: request → approve → contract ─────────────
def test_activation_loop_through_bridge(app, client):
    with app.app_context():
        plan = Plan.query.filter_by(slug="pro").one()
        c = _customer(email="act@x.com")
        lic = _license(c, plan, key="HBR-E2E-ACT")
    # radius requests SMS package activation
    r = client.post("/api/integration/hoberadius/service-requests",
                    json={"license_key": "HBR-E2E-ACT", "service_key": "sms_gateway",
                          "request_type": "activation", "desired_limits": {"package_messages": 2500}}, **HTTPS)
    assert r.status_code == 201
    ref = r.get_json()["service_request"]["reference"]
    sr = CustomerServiceRequest.query.filter_by(public_reference=ref).one()
    _admin(client)
    client.post(f"/admin/service-requests/{sr.id}/approve", data={}, follow_redirects=False)
    # grant is live in the contract the radius pulls
    data = _capacity(client, "HBR-E2E-ACT").get_json()
    sms = data["services"]["sms_gateway"]
    assert sms["enabled"] is True and sms["limits"]["sms_package_credits"] == 2500


# ── G. «الجهات» grant emits entity_count + per_entity_limits ─────────────────
def test_entities_grant_emits_into_contract(app, client):
    with app.app_context():
        plan = Plan.query.filter_by(slug="pro").one()
        c = _customer(email="ent@x.com")
        lic = _license(c, plan, key="HBR-E2E-ENT")
        cid = c.id
    _admin(client)
    client.post(f"/admin/customers/{cid}/grant-entities", data={
        "action": "grant", "entity_count": "4",
        "entity_max_subscribers": "150", "entity_max_cards": "300", "entity_max_nas": "3",
    }, follow_redirects=False)
    mt = _capacity(client, "HBR-E2E-ENT").get_json()["services"]["multi_tenant"]
    assert mt["visibility"] == "granted" and mt["entity_count"] == 4
    assert mt["per_entity_limits"] == {"max_subscribers": 150, "max_cards": 300, "max_nas": 3}


# ── H. SUPPORT LINE round-trips over the bridge ──────────────────────────────
def test_support_line_ticket_chat_notice(app, client):
    with app.app_context():
        from app.services import panel_messaging
        plan = Plan.query.filter_by(slug="pro").one()
        c = _customer(email="line@x.com")
        lic = _license(c, plan, key="HBR-E2E-LINE")
        cid = c.id
    key = {"license_key": "HBR-E2E-LINE"}
    # ticket create + reply pull
    ref = client.post("/api/integration/hoberadius/service-requests",
                      json={**key, "service_key": "customer_support", "request_type": "support",
                            "notes": "مساعدة"}, **HTTPS).get_json()["service_request"]["reference"]
    sr = CustomerServiceRequest.query.filter_by(public_reference=ref).one()
    _admin(client)
    client.post(f"/admin/service-requests/{sr.id}/reply", data={"message": "أهلًا بك"}, follow_redirects=True)
    thread = client.post("/api/integration/hoberadius/service-requests/messages",
                         json={**key, "reference": ref}, **HTTPS).get_json()["messages"]
    assert any("أهلًا" in m["body"] for m in thread)
    # provider notice → poll
    client.post(f"/admin/customers/{cid}/messages",
                data={"channel": "notice", "importance": "info", "body": "إشعار تجريبي"}, follow_redirects=True)
    polled = client.post("/api/integration/hoberadius/messages/poll", json=key, **HTTPS).get_json()
    assert polled["count"] == 1 and "إشعار" in polled["messages"][0]["body"]
    # customer chat → inbox
    sent = client.post("/api/integration/hoberadius/messages/send",
                       json={**key, "channel": "chat", "body": "استفسار"}, **HTTPS)
    assert sent.status_code == 201
