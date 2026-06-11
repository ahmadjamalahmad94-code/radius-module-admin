"""Catalog-level default service policy (feat/services-catalog-policy).

The owner sets a GLOBAL default tier per service on the dedicated «الخدمات»
page (/admin/services): free_unlimited / free_limited (+ basic quantities) /
paid. Stored in ``ServiceCatalogItem.metadata_json`` (no schema change). The
per-subscriber tier (/admin/customers/<id>/service-tiers) remains an explicit
OVERRIDE that always wins. The effective tier gates the runtime contract AND
the customer portal end-to-end.
"""
from __future__ import annotations

import pytest

from app.extensions import db
from app.models import (
    AuditLog,
    Customer,
    CustomerUser,
    License,
    Plan,
    ServiceCatalogItem,
    utcnow,
)
from app.services.customer_control import (
    SERVICE_TIER_FREE_LIMITED,
    SERVICE_TIER_FREE_UNLIMITED,
    SERVICE_TIER_PAID,
    build_runtime_contract_for_license,
    catalog_default_limits,
    catalog_default_tier,
    effective_service_tier,
    entitlement_has_explicit_tier,
    get_or_create_service_entitlement,
    service_limit_fields,
    set_catalog_policy,
    set_service_tier_on_entitlement,
)


# ─────────────────────────────────────────────────────────────────────────
# Fixtures (mirror tests/test_customer_service_tiers.py)
# ─────────────────────────────────────────────────────────────────────────
@pytest.fixture()
def customer_with_license(app):
    plan = Plan.query.filter_by(slug="pro").one()
    customer = Customer(company_name="Catalog Customer", contact_name="Owner",
                        email="catalog@example.com", status="active")
    db.session.add(customer)
    db.session.flush()
    lic = License(
        customer_id=customer.id,
        plan_id=plan.id,
        license_key="LIC-CATALOG-TEST",
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


def _pick_service(*, with_limit_fields: bool = False) -> ServiceCatalogItem:
    """A non-default-enabled catalog service (so gating is actually exercised)."""
    for item in ServiceCatalogItem.query.all():
        if item.default_enabled or item.service_key == "ip_change_vpn":
            continue
        if with_limit_fields and not service_limit_fields(item.service_key):
            continue
        return item
    raise AssertionError("no suitable catalog service found")


# ─────────────────────────────────────────────────────────────────────────
# Policy model round-trips
# ─────────────────────────────────────────────────────────────────────────
def test_catalog_policy_roundtrip(app):
    item = _pick_service(with_limit_fields=True)
    field_key = service_limit_fields(item.service_key)[0][0]

    set_catalog_policy(item, SERVICE_TIER_FREE_LIMITED, {field_key: 5})
    db.session.commit()
    assert catalog_default_tier(item) == SERVICE_TIER_FREE_LIMITED
    assert catalog_default_limits(item) == {field_key: 5}

    set_catalog_policy(item, SERVICE_TIER_FREE_UNLIMITED)
    db.session.commit()
    assert catalog_default_tier(item) == SERVICE_TIER_FREE_UNLIMITED
    assert catalog_default_limits(item) == {}  # limits cleared with the tier

    # Paid (the implicit default) clears both metadata keys entirely.
    set_catalog_policy(item, SERVICE_TIER_PAID)
    db.session.commit()
    assert catalog_default_tier(item) == SERVICE_TIER_PAID
    assert "default_tier" not in item.catalog_metadata
    assert "default_limits" not in item.catalog_metadata


def test_catalog_policy_ignores_garbage(app):
    item = _pick_service()
    set_catalog_policy(item, "nonsense-tier")
    assert catalog_default_tier(item) == SERVICE_TIER_PAID  # cleaned to default
    item.catalog_metadata = {"default_tier": "free_limited", "default_limits": "not-a-dict"}
    assert catalog_default_limits(item) == {}


def test_effective_tier_override_beats_catalog(app, customer_with_license):
    customer, _lic = customer_with_license
    item = _pick_service()
    set_catalog_policy(item, SERVICE_TIER_FREE_UNLIMITED)
    db.session.commit()

    # No entitlement → catalog default applies.
    tier, source = effective_service_tier(None, item)
    assert (tier, source) == (SERVICE_TIER_FREE_UNLIMITED, "catalog")

    # Entitlement WITHOUT explicit tier → still catalog.
    ent = get_or_create_service_entitlement(customer, item.service_key)
    db.session.commit()
    assert not entitlement_has_explicit_tier(ent)
    tier, source = effective_service_tier(ent, item)
    assert (tier, source) == (SERVICE_TIER_FREE_UNLIMITED, "catalog")

    # Explicit per-subscriber PAID beats the free catalog default.
    set_service_tier_on_entitlement(ent, SERVICE_TIER_PAID)
    # paid is stored implicitly (config key removed) — emulate the tiers page
    # which posts paid explicitly: config must mark the override.
    config = dict(ent.config or {})
    config["tier"] = SERVICE_TIER_PAID
    ent.config = config
    db.session.commit()
    tier, source = effective_service_tier(ent, item)
    assert (tier, source) == (SERVICE_TIER_PAID, "override")


# ─────────────────────────────────────────────────────────────────────────
# Contract gating end-to-end (the policy actually gates, not display-only)
# ─────────────────────────────────────────────────────────────────────────
def test_contract_catalog_free_unlimited_opens_service(customer_with_license):
    _customer, lic = customer_with_license
    item = _pick_service()
    set_catalog_policy(item, SERVICE_TIER_FREE_UNLIMITED)
    db.session.commit()

    contract = build_runtime_contract_for_license(lic, license_active=True, status="active")
    svc = contract["services"][item.service_key]
    assert svc["enabled"] is True
    assert svc["status"] == "active"
    assert svc["tier"] == SERVICE_TIER_FREE_UNLIMITED
    assert svc["tier_source"] == "catalog"
    assert svc["upgradable"] is False
    assert "limits" not in svc  # unlimited — no caps travel


def test_contract_catalog_free_limited_opens_with_caps_and_upgradable(customer_with_license):
    _customer, lic = customer_with_license
    item = _pick_service(with_limit_fields=True)
    field_key = service_limit_fields(item.service_key)[0][0]
    set_catalog_policy(item, SERVICE_TIER_FREE_LIMITED, {field_key: 7})
    db.session.commit()

    contract = build_runtime_contract_for_license(lic, license_active=True, status="active")
    svc = contract["services"][item.service_key]
    assert svc["enabled"] is True
    assert svc["status"] == "active"
    assert svc["tier"] == SERVICE_TIER_FREE_LIMITED
    assert svc["tier_source"] == "catalog"
    assert svc["upgradable"] is True            # «قابلة للتطوير»
    assert svc["limits"] == {field_key: 7}      # the basic quantity travels

    # …and the ENFORCED limits contract carries the cap for the radius side.
    assert contract["limits"][item.service_key][field_key] == 7


def test_contract_catalog_paid_stays_gated(customer_with_license):
    _customer, lic = customer_with_license
    item = _pick_service()
    set_catalog_policy(item, SERVICE_TIER_PAID)
    db.session.commit()

    contract = build_runtime_contract_for_license(lic, license_active=True, status="active")
    svc = contract["services"][item.service_key]
    assert svc["enabled"] is False
    assert svc["tier"] == SERVICE_TIER_PAID
    assert svc["upgradable"] is False


def test_contract_subscriber_override_beats_catalog(customer_with_license):
    customer, lic = customer_with_license
    item = _pick_service()
    set_catalog_policy(item, SERVICE_TIER_FREE_UNLIMITED)
    ent = get_or_create_service_entitlement(customer, item.service_key)
    config = dict(ent.config or {})
    config["tier"] = SERVICE_TIER_PAID          # explicit per-subscriber paid
    ent.config = config
    ent.enabled = False
    ent.status = "disabled"
    db.session.commit()

    contract = build_runtime_contract_for_license(lic, license_active=True, status="active")
    svc = contract["services"][item.service_key]
    assert svc["enabled"] is False              # override wins over free catalog
    assert svc["tier"] == SERVICE_TIER_PAID
    assert svc["tier_source"] == "override"


def test_contract_subscriber_limits_beat_catalog_limits(customer_with_license):
    customer, lic = customer_with_license
    item = _pick_service(with_limit_fields=True)
    field_key = service_limit_fields(item.service_key)[0][0]
    set_catalog_policy(item, SERVICE_TIER_FREE_LIMITED, {field_key: 7})
    ent = get_or_create_service_entitlement(customer, item.service_key)
    ent.limits = {field_key: 20}                # per-subscriber raise (upgrade)
    db.session.commit()

    contract = build_runtime_contract_for_license(lic, license_active=True, status="active")
    svc = contract["services"][item.service_key]
    assert svc["limits"] == {field_key: 20}
    assert contract["limits"][item.service_key][field_key] == 20


def test_contract_inactive_license_still_gates_free_catalog(customer_with_license):
    _customer, lic = customer_with_license
    item = _pick_service()
    set_catalog_policy(item, SERVICE_TIER_FREE_UNLIMITED)
    db.session.commit()

    contract = build_runtime_contract_for_license(lic, license_active=False, status="expired")
    svc = contract["services"][item.service_key]
    assert svc["enabled"] is False              # license gate beats free tier


# ─────────────────────────────────────────────────────────────────────────
# The admin «الخدمات» page
# ─────────────────────────────────────────────────────────────────────────
def test_services_page_renders_catalog_with_tier_radios(app, client):
    _login_admin(client)
    res = client.get("/admin/services")
    assert res.status_code == 200
    body = res.get_data(as_text=True)
    assert "السياسة الافتراضية" in body
    assert "مجانية مطلقة" in body
    assert "مجانية محدودة" in body
    assert "مدفوعة غير مفعّلة" in body
    # Every catalog service has a radio group.
    for item in ServiceCatalogItem.query.all():
        assert f'name="tier_{item.service_key}"' in body


def test_services_page_save_persists_policy_and_audits(app, client):
    _login_admin(client)
    item = _pick_service(with_limit_fields=True)
    field_key = service_limit_fields(item.service_key)[0][0]

    form = {}
    for it in ServiceCatalogItem.query.all():
        form[f"tier_{it.service_key}"] = "paid"
    form[f"tier_{item.service_key}"] = "free_limited"
    form[f"limit_{item.service_key}_{field_key}"] = "9"

    res = client.post("/admin/services/policy", data=form, follow_redirects=True)
    assert res.status_code == 200

    db.session.expire_all()
    fresh = ServiceCatalogItem.query.filter_by(service_key=item.service_key).one()
    assert catalog_default_tier(fresh) == SERVICE_TIER_FREE_LIMITED
    assert catalog_default_limits(fresh) == {field_key: 9}

    row = (
        AuditLog.query
        .filter_by(action="service_catalog_policy_updated")
        .order_by(AuditLog.id.desc())
        .first()
    )
    assert row is not None

    # Reload shows the saved state (selected radio + the quantity).
    res2 = client.get("/admin/services")
    body = res2.get_data(as_text=True)
    assert f'name="limit_{item.service_key}_{field_key}"' in body
    assert 'value="9"' in body


def test_services_page_save_rejects_negative_quantity(app, client):
    _login_admin(client)
    item = _pick_service(with_limit_fields=True)
    field_key = service_limit_fields(item.service_key)[0][0]
    res = client.post("/admin/services/policy", data={
        f"tier_{item.service_key}": "free_limited",
        f"limit_{item.service_key}_{field_key}": "-3",
    }, follow_redirects=True)
    assert res.status_code == 200
    assert "لا يمكن أن تكون سالبة" in res.get_data(as_text=True)
    db.session.expire_all()
    fresh = ServiceCatalogItem.query.filter_by(service_key=item.service_key).one()
    assert catalog_default_tier(fresh) == SERVICE_TIER_PAID  # nothing persisted


# ─────────────────────────────────────────────────────────────────────────
# Portal end-to-end (the policy gates what the customer actually sees)
# ─────────────────────────────────────────────────────────────────────────
def _login_as_customer(app, client, customer: Customer) -> CustomerUser:
    user = CustomerUser(
        customer_id=customer.id,
        username="catalog-owner",
        email=customer.email,
        full_name="Catalog Owner",
        role_key="owner",
        active=True,
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


def test_portal_free_limited_catalog_service_shows_upgrade_cta(app, client, customer_with_license):
    customer, _lic = customer_with_license
    item = _pick_service(with_limit_fields=True)
    field_key = service_limit_fields(item.service_key)[0][0]
    set_catalog_policy(item, SERVICE_TIER_FREE_LIMITED, {field_key: 4})
    db.session.commit()
    _login_as_customer(app, client, customer)

    res = client.get("/portal")
    assert res.status_code == 200
    body = res.get_data(as_text=True)
    # The card is rendered free_limited (teal tier) AND offers ترقية.
    assert 'data-tier="free_limited"' in body
    assert "ضمن خطتك" in body
    assert "ترقية" in body


def test_portal_catalog_paid_service_keeps_activation_cta(app, client, customer_with_license):
    customer, _lic = customer_with_license
    item = _pick_service()
    set_catalog_policy(item, SERVICE_TIER_PAID)
    db.session.commit()
    _login_as_customer(app, client, customer)

    res = client.get("/portal")
    assert res.status_code == 200
    body = res.get_data(as_text=True)
    assert "طلب تفعيل" in body
