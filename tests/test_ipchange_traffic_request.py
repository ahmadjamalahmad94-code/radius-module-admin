"""IP-change «طلب تفعيل»-with-traffic flow.

The customer requests the IP-change service AND specifies a traffic amount
(quota_gb); the request lands in the «طلبات الخدمات» queue; on approval the VPN
entitlement is activated with that traffic quota, which flows into the capacity
contract as the IP-change grant's traffic_quota_gb.
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from app.extensions import db
from app.models import (
    Admin, Customer, CustomerServiceRequest, CustomerVpnEntitlement, License, Plan, utcnow,
)
from app.services.customer_control import (
    build_runtime_contract_for_license, create_customer_service_request, service_spec_fields,
)


@pytest.fixture()
def cust_lic(app):
    plan = Plan.query.filter_by(slug="pro").one()
    c = Customer(company_name="IP Co", email="ip@example.com", status="active")
    db.session.add(c)
    db.session.flush()
    lic = License(customer_id=c.id, plan_id=plan.id, license_key="LIC-IPTRAFFIC",
                  status="active", starts_at=utcnow() - timedelta(days=1),
                  expires_at=utcnow() + timedelta(days=30), grace_until=utcnow() + timedelta(days=37))
    db.session.add(lic)
    db.session.commit()
    return c, lic


def _admin_client(app, client):
    admin = Admin.query.first()
    with client.session_transaction() as s:
        s["admin_id"] = admin.id
    return client


# ── the request form carries a traffic-amount field ─────────────────────────
def test_ipchange_spec_has_traffic_field():
    keys = {f["key"] for f in service_spec_fields("ip_change_vpn")}
    assert "quota_gb" in keys  # the traffic-amount field
    quota = next(f for f in service_spec_fields("ip_change_vpn") if f["key"] == "quota_gb")
    assert quota["unit"].startswith("GB")


def test_portal_request_captures_traffic_amount(app, client, cust_lic):
    c, _lic = cust_lic
    # log in as a customer user
    from app.models import CustomerUser
    u = CustomerUser(customer_id=c.id, username="ipowner", email=c.email,
                     full_name="IP Owner", role_key="owner", active=True)
    u.set_password("ownerpass12345", increment_version=False)
    u.password_version = 1
    db.session.add(u)
    db.session.commit()
    with client.session_transaction() as s:
        s["customer_user_id"] = u.id
        s["customer_id"] = c.id
        s["customer_name"] = u.username
    res = client.post("/portal/services/ip_change_vpn/request", data={
        "request_type": "activation",
        "spec_download_mbps": "50", "spec_upload_mbps": "50",
        "spec_max_vpn_users": "5", "spec_quota_gb": "750",
        "notes": "نحتاج تغيير IP بحصة 750 جيجا",
    }, follow_redirects=True)
    assert res.status_code == 200
    req = (CustomerServiceRequest.query
           .filter_by(customer_id=c.id, service_key="ip_change_vpn")
           .order_by(CustomerServiceRequest.id.desc()).first())
    assert req is not None and (req.desired_limits or {}).get("quota_gb") == 750


# ── approval activates with the requested quota → contract ───────────────────
def test_approve_with_requested_quota_flows_to_contract(app, client, cust_lic):
    c, lic = cust_lic
    req = create_customer_service_request(
        customer=c, service_key="ip_change_vpn", request_type="activation",
        desired_limits={"download_mbps": 50, "upload_mbps": 50, "max_vpn_users": 5, "quota_gb": 500})
    db.session.commit()
    rid = req.id
    _admin_client(app, client)
    r = client.post(f"/admin/service-requests/{rid}/approve", data={}, follow_redirects=False)
    assert r.status_code in (301, 302)
    db.session.expire_all()
    ent = CustomerVpnEntitlement.query.filter_by(customer_id=c.id).first()
    assert ent.enabled is True and ent.status == "active"
    assert ent.traffic_quota_gb == 500
    vpn = build_runtime_contract_for_license(lic, license_active=True, status="active")["services"]["ip_change_vpn"]
    assert vpn["enabled"] is True and vpn["traffic_quota_gb"] == 500


def test_trial_customer_can_request_and_activate_ipchange(app, client, cust_lic):
    """A trial customer has ip_change_vpn locked (generic entitlement disabled);
    requesting + approving it with a traffic amount must flip it ON in the
    contract (the approve path enables both the generic + VPN entitlements)."""
    c, lic = cust_lic
    from app.services.trial_plan import apply_trial_to_customer
    trial_lic = apply_trial_to_customer(c)["license"]
    # locked before request
    before = build_runtime_contract_for_license(trial_lic, license_active=True, status="active")
    assert before["services"]["ip_change_vpn"]["enabled"] is False
    # request with traffic + approve
    req = create_customer_service_request(
        customer=c, service_key="ip_change_vpn", request_type="activation",
        desired_limits={"download_mbps": 25, "upload_mbps": 25, "max_vpn_users": 3, "quota_gb": 300})
    db.session.commit()
    rid = req.id
    _admin_client(app, client)
    client.post(f"/admin/service-requests/{rid}/approve", data={}, follow_redirects=False)
    db.session.expire_all()
    after = build_runtime_contract_for_license(trial_lic, license_active=True, status="active")
    vpn = after["services"]["ip_change_vpn"]
    assert vpn["enabled"] is True and vpn["traffic_quota_gb"] == 300


def test_admin_override_quota_wins_over_requested(app, client, cust_lic):
    c, lic = cust_lic
    req = create_customer_service_request(
        customer=c, service_key="ip_change_vpn", request_type="activation",
        desired_limits={"download_mbps": 50, "upload_mbps": 50, "max_vpn_users": 5, "quota_gb": 500})
    db.session.commit()
    rid = req.id
    _admin_client(app, client)
    # admin grants a different quota than requested
    client.post(f"/admin/service-requests/{rid}/approve",
                data={"traffic_quota_gb": "1000"}, follow_redirects=False)
    db.session.expire_all()
    ent = CustomerVpnEntitlement.query.filter_by(customer_id=c.id).first()
    assert ent.traffic_quota_gb == 1000


def test_entitlement_quota_overrides_plan_quota(cust_lic):
    """build_effective_vpn_entitlement: the per-customer approved quota wins
    over the linked plan's traffic_quota_gb."""
    from app.models import VpnServicePlan
    from app.services.vpn_entitlements import (
        build_effective_vpn_entitlement, get_or_create_customer_vpn_entitlement,
    )
    c, lic = cust_lic
    vplan = VpnServicePlan.query.first()
    if vplan is not None:
        vplan.traffic_quota_gb = 999  # plan says 999…
    ent = get_or_create_customer_vpn_entitlement(c)
    ent.enabled = True
    ent.status = "active"
    ent.download_mbps = 50
    ent.upload_mbps = 50
    ent.max_vpn_users = 5
    ent.max_locations = 1
    ent.vpn_plan_id = vplan.id if vplan else None
    ent.traffic_quota_gb = 250  # …but the customer's approved quota is 250
    ent.license_id = lic.id
    db.session.add(ent)   # the helper returns a transient row; caller persists
    db.session.commit()
    eff = build_effective_vpn_entitlement(lic, license_allows_services=True)
    assert eff.enabled is True and eff.traffic_quota_gb == 250  # entitlement wins
