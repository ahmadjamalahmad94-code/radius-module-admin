from __future__ import annotations

from datetime import timedelta

import pytest

from app.extensions import db
from app.models import AuditLog, Customer, CustomerVpnEntitlement, License, Plan, VpnServicePlan, utcnow
from app.services.license_service import generate_license_key


def _login(client):
    return client.post("/login", data={"username": "admin", "password": "admin12345"})


def _customer_with_license(*, status: str = "active", expires_delta=timedelta(days=30)) -> tuple[Customer, License]:
    customer = Customer(company_name="VPN Customer", contact_name="Owner")
    plan = VpnServicePlan.query.filter_by(code="vpn_50m").first()
    license_plan = Plan.query.filter_by(slug="pro").one()
    now = utcnow()
    db.session.add(customer)
    db.session.flush()
    lic = License(
        customer_id=customer.id,
        plan_id=license_plan.id,
        license_key=generate_license_key(),
        status=status,
        starts_at=now - timedelta(days=1),
        expires_at=now + expires_delta,
        grace_until=now + expires_delta + timedelta(days=7),
        max_fingerprints=10,
    )
    db.session.add(lic)
    db.session.flush()
    if plan:
        db.session.add(CustomerVpnEntitlement(
            customer_id=customer.id,
            license_id=lic.id,
            vpn_plan_id=plan.id,
            enabled=True,
            status="active",
            download_mbps=plan.download_mbps,
            upload_mbps=plan.upload_mbps,
            max_vpn_users=plan.max_vpn_users,
            max_locations=plan.max_locations,
        ))
    db.session.commit()
    return customer, lic


def _license_check(client, lic: License, fingerprint: str = "fp-vpn"):
    return client.post("/api/license/check", json={
        "license_key": lic.license_key,
        "server_fingerprint": fingerprint,
        "hostname": "customer-radius",
    })


def test_vpn_service_plan_can_be_created_edited_and_disabled(client):
    _login(client)

    created = client.post("/admin/vpn-services/new", data={
        "name": "VPN 25 Mbps",
        "code": "vpn_25m",
        "description": "خدمة تغيير IP / VPN",
        "download_mbps": "25",
        "upload_mbps": "25",
        "max_vpn_users": "40",
        "max_locations": "1",
        "traffic_quota_gb": "",
        "price_monthly": "19.99",
        "is_active": "1",
    }, follow_redirects=True)

    assert created.status_code == 200
    plan = VpnServicePlan.query.filter_by(code="vpn_25m").one()
    assert plan.download_mbps == 25
    assert plan.is_active is True

    edited = client.post(f"/admin/vpn-services/{plan.id}/edit", data={
        "name": "VPN 30 Mbps",
        "code": "vpn_30m",
        "description": "updated",
        "download_mbps": "30",
        "upload_mbps": "30",
        "max_vpn_users": "50",
        "max_locations": "2",
        "traffic_quota_gb": "500",
        "price_monthly": "29.00",
        "is_active": "1",
    }, follow_redirects=True)
    assert edited.status_code == 200
    assert db.session.get(VpnServicePlan, plan.id).code == "vpn_30m"

    disabled = client.post(f"/admin/vpn-services/{plan.id}/disable", follow_redirects=True)
    assert disabled.status_code == 200
    assert db.session.get(VpnServicePlan, plan.id).is_active is False
    assert AuditLog.query.filter_by(action="vpn_service_plan_disabled").count() == 1


@pytest.mark.parametrize(
    ("plan_code", "download", "upload", "users"),
    [
        ("vpn_10m", 10, 10, 25),
        ("vpn_50m", 50, 50, 100),
        ("vpn_100m", 100, 100, 250),
        (None, 75, 75, 150),
    ],
)
def test_customer_vpn_entitlement_can_activate_standard_and_custom_speeds(client, plan_code, download, upload, users):
    _login(client)
    customer, lic = _customer_with_license()
    CustomerVpnEntitlement.query.filter_by(customer_id=customer.id).delete()
    db.session.commit()
    vpn_plan = VpnServicePlan.query.filter_by(code=plan_code).first() if plan_code else None

    data = {
        "vpn_plan_id": str(vpn_plan.id) if vpn_plan else "",
        "license_id": str(lic.id),
        "status": "active",
        "enabled": "1",
        "download_mbps": "" if vpn_plan else str(download),
        "upload_mbps": "" if vpn_plan else str(upload),
        "max_vpn_users": "" if vpn_plan else str(users),
        "max_locations": "1",
        "expires_at": "",
        "notes": "commercial activation",
        "action": "activate",
    }
    if vpn_plan:
        data["apply_plan_defaults"] = "1"

    response = client.post(f"/admin/customers/{customer.id}/vpn-service", data=data, follow_redirects=True)

    assert response.status_code == 200
    entitlement = CustomerVpnEntitlement.query.filter_by(customer_id=customer.id).one()
    assert entitlement.enabled is True
    assert entitlement.download_mbps == download
    assert entitlement.upload_mbps == upload
    assert entitlement.max_vpn_users == users

    body = _license_check(client, lic, fingerprint=f"fp-{download}").get_json()
    vpn = body["services"]["ip_change_vpn"]
    assert vpn["enabled"] is True
    assert vpn["status"] == "active"
    assert vpn["download_mbps"] == download
    assert vpn["upload_mbps"] == upload
    assert vpn["max_vpn_users"] == users
    assert vpn["enforcement_mode"] == "customer_runtime"


def test_invalid_vpn_speed_values_are_rejected(client):
    _login(client)
    customer, lic = _customer_with_license()

    response = client.post(f"/admin/customers/{customer.id}/vpn-service", data={
        "license_id": str(lic.id),
        "status": "active",
        "enabled": "1",
        "download_mbps": "0",
        "upload_mbps": "50",
        "max_vpn_users": "100",
        "max_locations": "1",
        "action": "activate",
    })

    assert response.status_code == 400
    assert db.session.get(CustomerVpnEntitlement, customer.vpn_entitlement.id).download_mbps == 50


@pytest.mark.parametrize(
    ("license_status", "expires_delta"),
    [
        ("suspended", timedelta(days=30)),
        ("active", timedelta(days=-10)),
    ],
)
def test_suspended_or_expired_license_does_not_receive_active_vpn_entitlement(client, license_status, expires_delta):
    _customer, lic = _customer_with_license(status=license_status, expires_delta=expires_delta)
    if expires_delta.days < 0:
        lic.grace_until = utcnow() - timedelta(days=1)
        db.session.commit()

    body = _license_check(client, lic, fingerprint=f"fp-{license_status}-{expires_delta.days}").get_json()

    assert body["active"] is False
    assert body["services"]["ip_change_vpn"]["enabled"] is False


def test_contract_returns_disabled_and_expired_when_vpn_is_not_active(client):
    customer, lic = _customer_with_license()
    entitlement = CustomerVpnEntitlement.query.filter_by(customer_id=customer.id).one()
    entitlement.enabled = False
    entitlement.status = "disabled"
    db.session.commit()

    disabled = _license_check(client, lic, fingerprint="fp-disabled").get_json()["services"]["ip_change_vpn"]
    assert disabled == {"enabled": False, "status": "disabled"}

    entitlement.enabled = False
    entitlement.status = "suspended"
    db.session.commit()

    suspended = _license_check(client, lic, fingerprint="fp-service-suspended").get_json()["services"]["ip_change_vpn"]
    assert suspended["enabled"] is False
    assert suspended["status"] == "suspended"

    entitlement.enabled = True
    entitlement.status = "active"
    entitlement.expires_at = utcnow() - timedelta(days=1)
    db.session.commit()

    expired = _license_check(client, lic, fingerprint="fp-expired").get_json()["services"]["ip_change_vpn"]
    assert expired["enabled"] is False
    assert expired["status"] == "expired"


def test_existing_license_check_fields_remain_backward_compatible(client):
    customer, lic = _customer_with_license()
    CustomerVpnEntitlement.query.filter_by(customer_id=customer.id).delete()
    db.session.commit()

    body = _license_check(client, lic, fingerprint="fp-compat").get_json()

    assert body["active"] is True
    assert body["status"] == "active"
    assert body["mode"] == "active"
    assert {"expires_at", "grace_until", "plan", "features"}.issubset(body.keys())
    assert body["services"]["ip_change_vpn"] == {"enabled": False, "status": "disabled"}


def test_vpn_admin_pages_render(client):
    _login(client)
    customer, _lic = _customer_with_license()

    plans = client.get("/admin/vpn-services")
    customer_page = client.get(f"/admin/customers/{customer.id}/vpn-service")

    assert plans.status_code == 200
    assert "خدمات VPN / تغيير IP" in plans.get_data(as_text=True)
    assert customer_page.status_code == 200
    assert "ما سيصل للريدياس" in customer_page.get_data(as_text=True)


def test_customer_vpn_entitlement_update_creates_audit_record(client):
    _login(client)
    customer, lic = _customer_with_license()

    response = client.post(f"/admin/customers/{customer.id}/vpn-service", data={
        "license_id": str(lic.id),
        "status": "active",
        "enabled": "1",
        "download_mbps": "100",
        "upload_mbps": "100",
        "max_vpn_users": "250",
        "max_locations": "1",
        "action": "activate",
    }, follow_redirects=True)

    assert response.status_code == 200
    assert AuditLog.query.filter_by(action="customer_vpn_entitlement_updated").count() == 1
