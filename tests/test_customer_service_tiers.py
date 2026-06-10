"""Tests for the per-subscriber service tier model.

The tier (free_unlimited / free_limited / paid) is admin-controlled per
customer and per service. Free tiers auto-enable in the runtime contract and
render as "ready" in the customer panel; paid tiers stay gated and expose
activation / upgrade requests.
"""
from __future__ import annotations

import json

import pytest

from app.extensions import db
from app.models import (
    Customer,
    CustomerServiceEntitlement,
    CustomerUser,
    License,
    Plan,
    ServiceCatalogItem,
    utcnow,
)
from app.services.customer_control import (
    SERVICE_TIER_DEFAULT,
    SERVICE_TIER_FREE_LIMITED,
    SERVICE_TIER_FREE_UNLIMITED,
    SERVICE_TIER_PAID,
    SERVICE_TIER_VALUES,
    build_runtime_contract_for_license,
    clean_service_tier,
    get_or_create_service_entitlement,
    service_tier_for_entitlement,
    set_service_tier_on_entitlement,
)


# ─────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────
@pytest.fixture()
def customer_with_license(app):
    plan = Plan.query.filter_by(slug="pro").one()
    customer = Customer(company_name="Tier Customer", contact_name="Owner", email="tier@example.com")
    db.session.add(customer)
    db.session.flush()
    lic = License(
        customer_id=customer.id,
        plan_id=plan.id,
        license_key="LIC-TIER-TEST",
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


def _login_as_customer(app, customer: Customer) -> CustomerUser:
    user = CustomerUser(
        customer_id=customer.id,
        username="tier-owner",
        email=customer.email,
        full_name="Tier Owner",
        role_key="owner",
        active=True,
    )
    user.set_password("ownerpass12345", increment_version=False)
    user.password_version = 1
    db.session.add(user)
    customer.status = "active"
    db.session.commit()
    return user


# ─────────────────────────────────────────────────────────────────────────
# Unit-level tier helpers
# ─────────────────────────────────────────────────────────────────────────
def test_clean_service_tier_normalizes_known_values_and_defaults_unknown():
    assert clean_service_tier("paid") == "paid"
    assert clean_service_tier("free_unlimited") == "free_unlimited"
    assert clean_service_tier("FREE_LIMITED") == "free_limited"
    assert clean_service_tier("  paid  ") == "paid"
    # bogus / empty → safe default
    assert clean_service_tier("") == SERVICE_TIER_DEFAULT == "paid"
    assert clean_service_tier(None) == SERVICE_TIER_DEFAULT
    assert clean_service_tier("free_dream") == SERVICE_TIER_DEFAULT


def test_tier_constants_cover_three_canonical_values():
    assert set(SERVICE_TIER_VALUES) == {SERVICE_TIER_PAID, SERVICE_TIER_FREE_UNLIMITED, SERVICE_TIER_FREE_LIMITED}


def test_service_tier_for_entitlement_defaults_to_paid_when_unset(customer_with_license):
    customer, _lic = customer_with_license
    item = ServiceCatalogItem.query.first()
    ent = get_or_create_service_entitlement(customer, item.service_key)
    assert service_tier_for_entitlement(ent) == "paid"
    # also tolerates None
    assert service_tier_for_entitlement(None) == "paid"


def test_set_service_tier_roundtrips_through_config_json(customer_with_license):
    customer, _lic = customer_with_license
    item = ServiceCatalogItem.query.first()
    ent = get_or_create_service_entitlement(customer, item.service_key)
    set_service_tier_on_entitlement(ent, "free_unlimited")
    db.session.commit()
    refreshed = (
        CustomerServiceEntitlement.query
        .filter_by(customer_id=customer.id, service_key=item.service_key)
        .one()
    )
    assert service_tier_for_entitlement(refreshed) == "free_unlimited"
    assert refreshed.config.get("tier") == "free_unlimited"


def test_set_service_tier_preserves_unrelated_config_keys(customer_with_license):
    customer, _lic = customer_with_license
    item = ServiceCatalogItem.query.first()
    ent = get_or_create_service_entitlement(customer, item.service_key)
    ent.config = {"already": "here", "tier": "paid"}
    db.session.flush()
    set_service_tier_on_entitlement(ent, "free_limited")
    db.session.commit()
    assert ent.config == {"already": "here", "tier": "free_limited"}


def test_default_tier_is_not_persisted_to_config(customer_with_license):
    """Storing the default value of 'paid' should keep config clean — no clutter."""
    customer, _lic = customer_with_license
    item = ServiceCatalogItem.query.first()
    ent = get_or_create_service_entitlement(customer, item.service_key)
    ent.config = {"tier": "free_unlimited"}
    db.session.flush()
    set_service_tier_on_entitlement(ent, "paid")
    assert "tier" not in (ent.config or {})


# ─────────────────────────────────────────────────────────────────────────
# Runtime contract — free tier auto-enables the service
# ─────────────────────────────────────────────────────────────────────────
def test_free_unlimited_tier_auto_enables_service_in_contract(customer_with_license):
    customer, lic = customer_with_license
    # Pick a service that is NOT default_enabled (otherwise the test is trivial).
    item = next(
        (it for it in ServiceCatalogItem.query.all()
         if not it.default_enabled and it.service_key != "ip_change_vpn"),
        None,
    )
    assert item is not None, "expected at least one non-default service in the catalog"
    ent = get_or_create_service_entitlement(customer, item.service_key)
    set_service_tier_on_entitlement(ent, "free_unlimited")
    ent.enabled = False
    ent.status = "disabled"
    db.session.commit()

    contract = build_runtime_contract_for_license(lic, license_active=True, status="active")
    svc = contract["services"].get(item.service_key, {})
    assert svc.get("enabled") is True
    assert svc.get("status") == "active"
    assert svc.get("tier") == "free_unlimited"
    assert svc.get("tier_label")
    assert svc.get("tier_tone") == "green"


def test_free_limited_tier_auto_enables_and_carries_tier_payload(customer_with_license):
    customer, lic = customer_with_license
    item = ServiceCatalogItem.query.filter_by(service_key="subscribers").first() or ServiceCatalogItem.query.first()
    ent = get_or_create_service_entitlement(customer, item.service_key)
    set_service_tier_on_entitlement(ent, "free_limited")
    ent.limits = {"max_total": 50}
    ent.enabled = False
    db.session.commit()

    contract = build_runtime_contract_for_license(lic, license_active=True, status="active")
    svc = contract["services"].get(item.service_key, {})
    assert svc.get("enabled") is True
    assert svc.get("tier") == "free_limited"
    assert svc.get("tier_tone") == "teal"
    assert svc.get("limits", {}).get("max_total") == 50


def test_paid_tier_stays_gated_when_entitlement_disabled(customer_with_license):
    customer, lic = customer_with_license
    item = next(
        (it for it in ServiceCatalogItem.query.all()
         if not it.default_enabled and it.service_key != "ip_change_vpn"),
        None,
    )
    ent = get_or_create_service_entitlement(customer, item.service_key)
    # explicit paid + disabled — the default path
    set_service_tier_on_entitlement(ent, "paid")
    ent.enabled = False
    ent.status = "disabled"
    db.session.commit()

    contract = build_runtime_contract_for_license(lic, license_active=True, status="active")
    svc = contract["services"].get(item.service_key, {})
    assert svc.get("enabled") is False
    assert svc.get("tier") == "paid"
    assert svc.get("tier_tone") == "violet"


def test_free_tier_does_not_override_inactive_license(customer_with_license):
    """Even with a free tier set, an inactive license must still hide the service."""
    customer, lic = customer_with_license
    item = next(
        (it for it in ServiceCatalogItem.query.all()
         if not it.default_enabled and it.service_key != "ip_change_vpn"),
        None,
    )
    ent = get_or_create_service_entitlement(customer, item.service_key)
    set_service_tier_on_entitlement(ent, "free_unlimited")
    db.session.commit()

    contract = build_runtime_contract_for_license(lic, license_active=False, status="suspended")
    svc = contract["services"].get(item.service_key, {})
    assert svc.get("enabled") is False


# ─────────────────────────────────────────────────────────────────────────
# Admin tier-control page
# ─────────────────────────────────────────────────────────────────────────
def test_admin_tier_page_renders_for_customer(client, customer_with_license):
    customer, _lic = customer_with_license
    _login_admin(client)
    res = client.get(f"/admin/customers/{customer.id}/service-tiers")
    assert res.status_code == 200
    body = res.get_data(as_text=True)
    # The page lists each catalog service + 3 radio choices.
    assert "تعرفة" in body
    assert "مجانية مطلقة" in body
    assert "مدفوعة" in body


def test_admin_tier_save_persists_choices(client, customer_with_license):
    customer, _lic = customer_with_license
    _login_admin(client)
    # pick a service and flip it to free_unlimited via the bulk form
    item = next(
        (it for it in ServiceCatalogItem.query.all()
         if not it.default_enabled and it.service_key != "ip_change_vpn"),
        None,
    )
    res = client.post(
        f"/admin/customers/{customer.id}/service-tiers",
        data={f"tier_{item.service_key}": "free_unlimited"},
        follow_redirects=False,
    )
    assert res.status_code in (302, 303)
    ent = (
        CustomerServiceEntitlement.query
        .filter_by(customer_id=customer.id, service_key=item.service_key)
        .one()
    )
    assert service_tier_for_entitlement(ent) == "free_unlimited"
    assert ent.enabled is True
    assert ent.status == "active"


def test_admin_tier_save_with_free_limited_captures_limit_value(client, customer_with_license):
    customer, _lic = customer_with_license
    _login_admin(client)
    # "subscribers" has a max_total limit field in SERVICE_LIMIT_FIELDS.
    res = client.post(
        f"/admin/customers/{customer.id}/service-tiers",
        data={
            "tier_subscribers": "free_limited",
            "limit_subscribers_max_total": "120",
        },
        follow_redirects=False,
    )
    assert res.status_code in (302, 303)
    ent = (
        CustomerServiceEntitlement.query
        .filter_by(customer_id=customer.id, service_key="subscribers")
        .one()
    )
    assert service_tier_for_entitlement(ent) == "free_limited"
    assert ent.limits.get("max_total") == 120


def test_admin_tier_save_rejects_negative_limit(client, customer_with_license):
    customer, _lic = customer_with_license
    _login_admin(client)
    res = client.post(
        f"/admin/customers/{customer.id}/service-tiers",
        data={
            "tier_subscribers": "free_limited",
            "limit_subscribers_max_total": "-5",
        },
        follow_redirects=False,
    )
    # Validation error should redirect back without persisting the negative limit.
    assert res.status_code in (302, 303)
    ent = CustomerServiceEntitlement.query.filter_by(
        customer_id=customer.id, service_key="subscribers"
    ).first()
    # Either no entitlement created OR limits never picked up the bad value.
    if ent is not None:
        assert ent.limits.get("max_total", 0) >= 0


def test_admin_route_form_does_not_silently_skip_unknown_tier(client, customer_with_license):
    """An unknown tier string falls back to paid (the safe default)."""
    customer, _lic = customer_with_license
    _login_admin(client)
    res = client.post(
        f"/admin/customers/{customer.id}/service-tiers",
        data={"tier_subscribers": "gold_premium_super"},
        follow_redirects=False,
    )
    assert res.status_code in (302, 303)
    ent = (
        CustomerServiceEntitlement.query
        .filter_by(customer_id=customer.id, service_key="subscribers")
        .one()
    )
    assert service_tier_for_entitlement(ent) == "paid"


# ─────────────────────────────────────────────────────────────────────────
# Customer dashboard rendering — tier badges + activation flow
# ─────────────────────────────────────────────────────────────────────────
def test_customer_dashboard_renders_tier_badges_and_modals(app, client, customer_with_license):
    customer, _lic = customer_with_license
    user = _login_as_customer(app, customer)
    # Pre-mark one service free so we can spot the green badge.
    item = next(
        (it for it in ServiceCatalogItem.query.all()
         if not it.default_enabled and it.service_key != "ip_change_vpn"),
        None,
    )
    ent = get_or_create_service_entitlement(customer, item.service_key)
    set_service_tier_on_entitlement(ent, "free_unlimited")
    ent.enabled = True
    ent.status = "active"
    db.session.commit()

    with client.session_transaction() as s:
        s["customer_user_id"] = user.id
        s["customer_id"] = customer.id
        s["customer_name"] = user.username

    res = client.get("/portal")
    assert res.status_code == 200
    body = res.get_data(as_text=True)
    # The redesigned services pane is on the page.
    assert "خدماتي" in body
    # Tier filter chips were rendered.
    assert 'data-tier="free_unlimited"' in body
    assert 'data-tier="paid"' in body
    # The activation modal markup is present (so paid services have somewhere to land).
    assert "pp-activate-modal" in body
    assert "pp-upgrade-modal" in body
    # And the redesigned card carries tier metadata.
    assert "pp-tier-badge" in body


def test_customer_activation_request_persists_spec_fields(app, client, customer_with_license):
    """POSTing spec_<field> fields builds desired_limits + summary on the request."""
    from app.models import CustomerServiceRequest

    customer, _lic = customer_with_license
    user = _login_as_customer(app, customer)
    with client.session_transaction() as s:
        s["customer_user_id"] = user.id
        s["customer_id"] = customer.id
        s["customer_name"] = user.username

    # File an activation request for "subscribers" with a max_total spec.
    res = client.post(
        "/portal/services/subscribers/request",
        data={
            "request_type": "activation",
            "spec_max_total": "250",
            "notes": "نحتاج مساحة لمشتركي الموزّع الجديد",
        },
        follow_redirects=False,
    )
    assert res.status_code in (302, 303)
    req = (
        CustomerServiceRequest.query
        .filter_by(customer_id=customer.id, service_key="subscribers")
        .order_by(CustomerServiceRequest.id.desc())
        .first()
    )
    assert req is not None
    assert req.desired_limits.get("max_total") == 250
    # The human-readable summary was prepended to the notes for the admin inbox.
    assert "المواصفات المطلوبة" in (req.notes or "")
    assert "250" in (req.notes or "")


def test_customer_upgrade_request_records_upgrade_target(app, client, customer_with_license):
    from app.models import CustomerServiceRequest

    customer, _lic = customer_with_license
    user = _login_as_customer(app, customer)
    with client.session_transaction() as s:
        s["customer_user_id"] = user.id
        s["customer_id"] = customer.id
        s["customer_name"] = user.username

    res = client.post(
        "/portal/services/subscribers/request",
        data={
            "request_type": "upgrade",
            "spec_max_total": "1000",
            "upgrade_target": "more_capacity",
            "notes": "ترقية الباقة بعد توسعة الفرع",
        },
        follow_redirects=False,
    )
    assert res.status_code in (302, 303)
    req = (
        CustomerServiceRequest.query
        .filter_by(customer_id=customer.id, service_key="subscribers")
        .order_by(CustomerServiceRequest.id.desc())
        .first()
    )
    assert req is not None
    assert req.request_type == "upgrade"
    assert req.desired_limits.get("max_total") == 1000
