"""HIDE ↔ SUSPEND matrix + smart spec-requests (feat/services-catalog-policy).

The owner's experiment, made deterministic:

* HIDDEN  («مخفي»)   = VIEW state — the service vanishes from THAT customer's
  portal entirely (even free/basic) but KEEPS WORKING.
* SUSPEND («موقوفة») = FUNCTION state — the service stops until resumed.
* The two are ORTHOGONAL: hiding never suspends; suspending never hides.

Plus: the smart per-type activate/upgrade spec schema + server-side clamping
(docs/SERVICE_SPEC_REQUEST_CONTRACT.md).
"""
from __future__ import annotations

import pytest

from app.extensions import db
from app.models import (
    AuditLog,
    Customer,
    CustomerServiceRequest,
    CustomerUser,
    License,
    Plan,
    ServiceCatalogItem,
    utcnow,
)
from app.services.customer_control import (
    SERVICE_TIER_FREE_UNLIMITED,
    build_runtime_contract_for_license,
    get_or_create_service_entitlement,
    service_is_hidden,
    service_spec_fields,
    set_catalog_policy,
    set_service_hidden,
)


@pytest.fixture()
def customer_with_license(app):
    plan = Plan.query.filter_by(slug="pro").one()
    customer = Customer(company_name="Matrix Customer", contact_name="Owner",
                        email="matrix@example.com", status="active")
    db.session.add(customer)
    db.session.flush()
    lic = License(
        customer_id=customer.id,
        plan_id=plan.id,
        license_key="LIC-MATRIX-TEST",
        status="active",
        starts_at=utcnow(),
        expires_at=utcnow().replace(year=utcnow().year + 1),
        grace_until=utcnow().replace(year=utcnow().year + 1),
    )
    db.session.add(lic)
    db.session.commit()
    return customer, lic


def _login_admin(client):
    return client.post("/login", data={"username": "admin", "password": "admin12345"})


def _login_as_customer(app, client, customer: Customer) -> CustomerUser:
    user = CustomerUser(
        customer_id=customer.id, username="matrix-owner", email=customer.email,
        full_name="Matrix Owner", role_key="owner", active=True,
    )
    user.set_password("ownerpass12345", increment_version=False)
    user.password_version = 1
    db.session.add(user)
    customer.status = "active"
    db.session.commit()
    with client.session_transaction() as s:
        s["customer_user_id"] = user.id
        s["customer_id"] = customer.id
        s["customer_name"] = user.username
    return user


def _pick_service() -> ServiceCatalogItem:
    for item in ServiceCatalogItem.query.all():
        if not item.default_enabled and item.service_key != "ip_change_vpn":
            return item
    raise AssertionError("no suitable catalog service found")


# ─────────────────────────────────────────────────────────────────────────
# The matrix
# ─────────────────────────────────────────────────────────────────────────

def test_hidden_service_stays_enabled_but_vanishes_from_portal(app, client, customer_with_license):
    """ANSWER to the owner's experiment: hiding does NOT suspend."""
    customer, lic = customer_with_license
    item = _pick_service()
    set_catalog_policy(item, SERVICE_TIER_FREE_UNLIMITED)
    ent = get_or_create_service_entitlement(customer, item.service_key)
    set_service_hidden(ent, True)
    db.session.commit()

    contract = build_runtime_contract_for_license(lic, license_active=True, status="active")
    svc = contract["services"][item.service_key]
    assert svc["enabled"] is True            # STILL WORKS — hide is view-only
    assert svc["status"] == "active"
    assert svc["hidden"] is True             # the radius client mirrors this

    _login_as_customer(app, client, customer)
    body = client.get("/portal").get_data(as_text=True)
    # Every rendered card carries data-name="<label> <service_key>" — for the
    # hidden service no such marker exists anywhere on the page.
    assert (item.service_key + '"') not in body


def test_hidden_for_x_still_visible_for_y(app, customer_with_license):
    """Per-customer isolation: hide for X — Y still gets the service."""
    customer_x, _lic_x = customer_with_license
    item = _pick_service()
    set_catalog_policy(item, SERVICE_TIER_FREE_UNLIMITED)
    ent = get_or_create_service_entitlement(customer_x, item.service_key)
    set_service_hidden(ent, True)

    plan = Plan.query.filter_by(slug="pro").one()
    customer_y = Customer(company_name="Visible Co", email="y@example.com", status="active")
    db.session.add(customer_y)
    db.session.flush()
    lic_y = License(
        customer_id=customer_y.id, plan_id=plan.id, license_key="LIC-MATRIX-Y",
        status="active", starts_at=utcnow(),
        expires_at=utcnow().replace(year=utcnow().year + 1),
    )
    db.session.add(lic_y)
    db.session.commit()

    svc_y = build_runtime_contract_for_license(lic_y, license_active=True, status="active")["services"][item.service_key]
    assert svc_y["hidden"] is False
    assert svc_y["enabled"] is True


def test_suspend_stops_service_even_when_tier_is_free(customer_with_license):
    """SUSPEND beats the free tier — free must never resurrect a suspension."""
    customer, lic = customer_with_license
    item = _pick_service()
    set_catalog_policy(item, SERVICE_TIER_FREE_UNLIMITED)
    ent = get_or_create_service_entitlement(customer, item.service_key)
    ent.status = "suspended"
    ent.enabled = False
    db.session.commit()

    svc = build_runtime_contract_for_license(lic, license_active=True, status="active")["services"][item.service_key]
    assert svc["enabled"] is False           # STOPPED
    assert svc["status"] == "suspended"
    assert svc["hidden"] is False            # suspend does NOT hide


def test_hide_and_suspend_are_orthogonal_and_compose(customer_with_license):
    customer, lic = customer_with_license
    item = _pick_service()
    set_catalog_policy(item, SERVICE_TIER_FREE_UNLIMITED)
    ent = get_or_create_service_entitlement(customer, item.service_key)

    def _svc():
        return build_runtime_contract_for_license(
            lic, license_active=True, status="active")["services"][item.service_key]

    # Both ON: invisible AND stopped.
    set_service_hidden(ent, True)
    ent.status = "suspended"
    ent.enabled = False
    db.session.commit()
    svc = _svc()
    assert svc["hidden"] is True and svc["enabled"] is False and svc["status"] == "suspended"

    # Un-hide only → visible again but STILL suspended (resume is explicit).
    set_service_hidden(ent, False)
    db.session.commit()
    svc = _svc()
    assert svc["hidden"] is False and svc["enabled"] is False and svc["status"] == "suspended"

    # Resume + hide again → works (free override) but stays out of view.
    set_service_hidden(ent, True)
    ent.status = "active"
    db.session.commit()
    svc = _svc()
    assert svc["hidden"] is True and svc["enabled"] is True and svc["status"] == "active"


def test_tiers_page_saves_hide_and_suspend_toggles(app, client, customer_with_license):
    """The Customer-360 control surface round-trips both toggles + audits."""
    customer, _lic = customer_with_license
    item = _pick_service()
    _login_admin(client)

    res = client.post(f"/admin/customers/{customer.id}/service-tiers", data={
        f"tier_{item.service_key}": "free_unlimited",
        f"hidden_{item.service_key}": "on",
        f"suspended_{item.service_key}": "on",
    }, follow_redirects=True)
    assert res.status_code == 200
    db.session.expire_all()
    ent = get_or_create_service_entitlement(customer, item.service_key)
    assert service_is_hidden(ent) is True
    assert ent.status == "suspended"
    assert ent.enabled is False

    # Both OFF → visible + resumed (free tier re-enables).
    res = client.post(f"/admin/customers/{customer.id}/service-tiers", data={
        f"tier_{item.service_key}": "free_unlimited",
    }, follow_redirects=True)
    assert res.status_code == 200
    db.session.expire_all()
    ent = get_or_create_service_entitlement(customer, item.service_key)
    assert service_is_hidden(ent) is False
    assert ent.status == "active"
    assert ent.enabled is True

    row = (AuditLog.query
           .filter_by(action="customer_service_entitlement_updated")
           .order_by(AuditLog.id.desc()).first())
    assert row is not None


# ─────────────────────────────────────────────────────────────────────────
# Smart spec schema + request clamping
# ─────────────────────────────────────────────────────────────────────────

def test_service_spec_fields_enriched_schema(app):
    by_key = {f["key"]: f for f in service_spec_fields("whatsapp_gateway")}
    assert by_key["max_messages_daily"]["default"] == 100
    assert by_key["max_messages_daily"]["max"] == 10000
    assert by_key["max_messages_daily"]["unit"]
    # Bandwidth-type extras: per-direction speed + users + quota.
    vpn = {f["key"]: f for f in service_spec_fields("ip_change_vpn")}
    assert "download_mbps" in vpn and "upload_mbps" in vpn
    assert vpn["download_mbps"]["unit"].endswith("↓")
    assert vpn["upload_mbps"]["unit"].endswith("↑")
    assert "max_vpn_users" in vpn
    # Unknown service → empty schema (modal shows the no-specs notice).
    assert service_spec_fields("definitely-not-a-service") == []


def test_portal_request_carries_clamped_desired_limits(app, client, customer_with_license):
    customer, _lic = customer_with_license
    _login_as_customer(app, client, customer)
    f_max = next(f for f in service_spec_fields("subscribers") if f["key"] == "max_total")["max"]

    res = client.post("/portal/services/subscribers/request", data={
        "request_type": "upgrade",
        "spec_max_total": str(int(f_max) + 999999),   # absurd → clamped to max
        "notes": "نريد ترقية",
    }, follow_redirects=True)
    assert res.status_code == 200

    req = (CustomerServiceRequest.query
           .filter_by(customer_id=customer.id, service_key="subscribers")
           .order_by(CustomerServiceRequest.id.desc()).first())
    assert req is not None
    assert req.request_type == "upgrade"
    assert (req.desired_limits or {}).get("max_total") == int(f_max)
    # The Arabic spec summary (with the unit) is prepended to the notes.
    assert "المواصفات المطلوبة" in (req.notes or "")
    assert "مشترك" in (req.notes or "")
