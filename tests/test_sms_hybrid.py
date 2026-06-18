"""SMS gateway — the HYBRID service: free BYO-API + paid «طلب حزمة رسائل».

Two modes, one service (sms_gateway):
  1. BYO API — the customer plugs in their OWN SMS gateway and pays the provider
     directly. FREE on our side (like whatsapp_gateway) — available in the trial
     as free_limited with BYO caps (max_messages_monthly / max_messages_daily).
  2. Buy a package — an optional PAID «طلب حزمة رسائل» (quantity). On approval the
     purchased count is CREDITED onto sms_package_credits (additive, never clobbers
     the running balance), and flows into the capacity contract.
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from app.extensions import db
from app.models import (
    Admin, Customer, CustomerServiceRequest, License, Plan, ServiceCatalogItem, utcnow,
)
from app.services.customer_control import (
    SERVICE_REQUEST_EXTRA_FIELDS,
    SERVICE_TIER_FREE_LIMITED,
    build_runtime_contract_for_license,
    create_customer_service_request,
    get_or_create_service_entitlement,
    service_spec_fields,
)
from app.services.trial_plan import apply_trial_to_customer, trial_tier_for, TRIAL_PAID_SERVICES


@pytest.fixture()
def cust_lic(app):
    plan = Plan.query.filter_by(slug="pro").one()
    c = Customer(company_name="SMS Co", email="sms@example.com", status="active")
    db.session.add(c)
    db.session.flush()
    lic = License(customer_id=c.id, plan_id=plan.id, license_key="LIC-SMS-TEST",
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


# ── catalog ──────────────────────────────────────────────────────────────────
def test_sms_gateway_in_catalog(app):
    item = ServiceCatalogItem.query.filter_by(service_key="sms_gateway").first()
    assert item is not None
    assert item.category == "communications"


# ── mode 2: the buy-package request field exists ───────────────────────────────
def test_sms_has_buy_package_request_field():
    extra = {f["key"] for f in SERVICE_REQUEST_EXTRA_FIELDS.get("sms_gateway", [])}
    assert "package_messages" in extra  # «طلب حزمة رسائل» quantity
    # and the BYO caps are ordinary limit fields
    spec = {f["key"] for f in service_spec_fields("sms_gateway")}
    assert {"max_messages_monthly", "max_messages_daily", "sms_package_credits"} <= spec


# ── mode 1: SMS is FREE (BYO) in the trial, not paid ───────────────────────────
def test_sms_is_free_in_trial_not_paid():
    assert "sms_gateway" not in TRIAL_PAID_SERVICES
    # has limit fields → free_limited (BYO caps respected), not free_unlimited
    assert trial_tier_for("sms_gateway") == SERVICE_TIER_FREE_LIMITED


def test_trial_customer_gets_sms_free_with_byo_caps(app, cust_lic):
    c, _lic = cust_lic
    trial_lic = apply_trial_to_customer(c)["license"]
    sms = build_runtime_contract_for_license(
        trial_lic, license_active=True, status="active")["services"]["sms_gateway"]
    assert sms["enabled"] is True                       # free → on
    assert sms["tier"] == SERVICE_TIER_FREE_LIMITED
    # BYO caps come from the spec defaults; no package credit bought yet
    assert sms["limits"]["max_messages_monthly"] == 1000
    assert sms["limits"]["max_messages_daily"] == 200
    assert sms["limits"].get("sms_package_credits", 0) == 0


# ── mode 2: approving a package CREDITS the balance (additive) → contract ──────
def test_approve_package_credits_sms_balance(app, client, cust_lic):
    c, lic = cust_lic
    req = create_customer_service_request(
        customer=c, service_key="sms_gateway", request_type="activation",
        desired_limits={"package_messages": 5000})
    db.session.commit()
    rid = req.id
    _admin_client(app, client)
    r = client.post(f"/admin/service-requests/{rid}/approve", data={}, follow_redirects=False)
    assert r.status_code in (301, 302)
    db.session.expire_all()
    ent = get_or_create_service_entitlement(c, "sms_gateway")
    assert int((ent.limits or {}).get("sms_package_credits") or 0) == 5000
    sms = build_runtime_contract_for_license(
        lic, license_active=True, status="active")["services"]["sms_gateway"]
    assert sms["enabled"] is True
    assert sms["limits"]["sms_package_credits"] == 5000


def test_second_package_is_additive_not_clobbered(app, client, cust_lic):
    c, lic = cust_lic
    _admin_client(app, client)
    for qty in (2000, 3000):
        req = create_customer_service_request(
            customer=c, service_key="sms_gateway", request_type="activation",
            desired_limits={"package_messages": qty})
        db.session.commit()
        rid = req.id
        client.post(f"/admin/service-requests/{rid}/approve", data={}, follow_redirects=False)
        db.session.expire_all()
    ent = get_or_create_service_entitlement(c, "sms_gateway")
    assert int((ent.limits or {}).get("sms_package_credits") or 0) == 5000  # 2000 + 3000


def test_admin_form_package_qty_overrides_desired(app, client, cust_lic):
    c, lic = cust_lic
    req = create_customer_service_request(
        customer=c, service_key="sms_gateway", request_type="activation",
        desired_limits={"package_messages": 1000})
    db.session.commit()
    rid = req.id
    _admin_client(app, client)
    # admin credits a different package size at approval time
    client.post(f"/admin/service-requests/{rid}/approve",
                data={"package_messages": "8000"}, follow_redirects=False)
    db.session.expire_all()
    ent = get_or_create_service_entitlement(c, "sms_gateway")
    assert int((ent.limits or {}).get("sms_package_credits") or 0) == 8000
