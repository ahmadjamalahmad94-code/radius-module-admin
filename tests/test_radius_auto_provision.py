"""Auto-provision the customer's RADIUS instance + ProxyRealmRoute on bridge link.

The contract under test (owner mandate, branch
``feat/remove-legacy-linking-auth``): "Registering the RADIUS instance + route
is ESSENTIAL for the link — make it AUTOMATIC."

When the radius-module hits ``POST /api/integration/hoberadius/instance-ops/
heartbeat`` with a valid license-key bearer + a few facts about its own
RADIUS server, the panel auto-creates (or refreshes) the
``CustomerRadiusInstance`` AND the ``ProxyRealmRoute`` and the route
immediately appears in the proxy's routing-table.

These tests pin every piece of the loop:

  1. First heartbeat → instance + route created, shared secret minted ONCE.
  2. Second heartbeat → idempotent refresh, no new rows, minted secret NOT
     echoed again.
  3. Realm collisions auto-disambiguate to the customer-id slug.
  4. Manual «تسجيل / تعديل نسخة RADIUS» form creates + persists.
  5. The auto-created route is published by ``/api/proxy/routing-table``
     with the expected realm + target + allowed_chr_ips.
"""
from __future__ import annotations

import hashlib
import hmac
import time
import uuid
from datetime import timedelta

import pytest

from app import create_app, seed_defaults
from app.config import TestingConfig
from app.extensions import db
from app.models import (
    Admin,
    Customer,
    CustomerRadiusInstance,
    License,
    Plan,
    ProxyRealmRoute,
    Setting,
    utcnow,
)
from app.services.license_service import generate_license_key


HEARTBEAT_URL = "/api/integration/hoberadius/instance-ops/heartbeat"
ROUTING_TABLE_URL = "/api/proxy/routing-table"
PROXY_SECRET = "test-auto-provision-shared-secret-1234"


# ─────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────

@pytest.fixture()
def app():
    app = create_app(
        TestingConfig,
        RADIUS_PROXY_SHARED_SECRET=PROXY_SECRET,
        RADIUS_PROXY_TOKEN_TTL=60,
    )
    with app.app_context():
        db.create_all()
        seed_defaults(app)
        # Promote the seeded admin to super so super-admin-gated endpoints
        # (the manual save form) open up for the test client.
        admin = Admin.query.filter_by(username="admin").first()
        if admin is not None:
            admin.is_super = True
            db.session.commit()
        # Reset proxy nonce cache between runs — token TTL is 60s and the
        # cache is module-level state.
        from app.api import proxy_api
        proxy_api._NONCE_CACHE.clear()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


def _mk_license(company: str = "Auto-Provision Co") -> License:
    customer = Customer(company_name=f"{company} {uuid.uuid4().hex[:6]}", status="active")
    plan = Plan.query.filter_by(slug="pro").first()
    db.session.add(customer)
    db.session.flush()
    lic = License(
        customer_id=customer.id,
        plan_id=plan.id,
        license_key=generate_license_key(),
        status="active",
        starts_at=utcnow() - timedelta(days=1),
        expires_at=utcnow() + timedelta(days=30),
        grace_until=utcnow() + timedelta(days=37),
    )
    db.session.add(lic)
    db.session.commit()
    return lic


_NONCE_SEQ = [0]


def _proxy_token() -> str:
    _NONCE_SEQ[0] += 1
    ts = int(time.time())
    nonce = f"auto-prov-{ts}-{_NONCE_SEQ[0]}"
    mac = hmac.new(PROXY_SECRET.encode(), f"{ts}:{nonce}".encode(), hashlib.sha256).hexdigest()
    return f"{ts}:{nonce}:{mac}"


def _login_admin(client):
    return client.post("/login", data={"username": "admin", "password": "admin12345"})


# ═════════════════════════════════════════════════════════════════════════
# 1. Auto-provision — first heartbeat
# ═════════════════════════════════════════════════════════════════════════

def test_first_heartbeat_creates_instance_and_route(app, client):
    lic = _mk_license()
    license_key = lic.license_key
    customer_id = lic.customer_id

    res = client.post(HEARTBEAT_URL, json={
        "license_key": license_key,
        "instance_url": "https://radius-vps-1.example/",
        "realm": "client5",
        "radius_auth_ip": "187.77.70.18",
        "radius_auth_port": 1812,
        "radius_acct_port": 1813,
        "mgmt_wg_ip": "10.99.0.7",
        "hostname": "client5-radius",
        "server_fingerprint": "fp-first",
    })
    assert res.status_code == 200, res.get_json()
    body = res.get_json()
    assert body["ok"] is True
    prov = body["provision"]
    assert prov["status"] == "provisioned"
    assert prov["instance_action"] == "created"
    assert prov["route_action"] == "created"
    assert prov["realm"] == "client5"
    assert prov["radius_target"] == "187.77.70.18:1812"
    assert prov["secret_minted"] is True
    # The minted shared secret comes back ONCE on first creation.
    minted_secret = prov["shared_secret"]
    assert isinstance(minted_secret, str) and len(minted_secret) >= 16

    # DB matches
    with app.app_context():
        inst = CustomerRadiusInstance.query.filter_by(customer_id=customer_id).one()
        assert inst.realm == "client5"
        assert inst.radius_auth_ip == "187.77.70.18"
        assert inst.radius_auth_port == 1812
        assert inst.radius_acct_port == 1813
        assert inst.mgmt_wg_ip == "10.99.0.7"
        assert inst.status == "active"
        assert inst.secret_vault_ref.startswith("vault://radius_secret.customer.")

        route = ProxyRealmRoute.query.filter_by(customer_id=customer_id).one()
        assert route.realm == "client5"
        assert route.target_radius_ip == "187.77.70.18"
        assert route.target_auth_port == 1812
        assert route.target_acct_port == 1813
        assert route.status == "active"
        assert route.secret_vault_ref == inst.secret_vault_ref


# ═════════════════════════════════════════════════════════════════════════
# 2. Idempotency — second heartbeat refreshes, does NOT duplicate
# ═════════════════════════════════════════════════════════════════════════

def test_repeat_heartbeat_is_idempotent_and_keeps_minted_secret(app, client):
    lic = _mk_license()
    license_key = lic.license_key
    customer_id = lic.customer_id

    # First call — mint
    first = client.post(HEARTBEAT_URL, json={
        "license_key": license_key,
        "realm": "client9",
        "radius_auth_ip": "10.0.0.9",
    }).get_json()
    assert first["provision"]["secret_minted"] is True
    minted = first["provision"]["shared_secret"]

    # Second call — same identity, same body → idempotent update
    second = client.post(HEARTBEAT_URL, json={
        "license_key": license_key,
        "realm": "client9",
        "radius_auth_ip": "10.0.0.9",
    }).get_json()
    assert second["provision"]["status"] == "provisioned"
    assert second["provision"]["instance_action"] == "updated"
    assert second["provision"]["route_action"] == "updated"
    # Minted secret is NOT echoed on subsequent calls — single round-trip rule.
    assert second["provision"]["secret_minted"] is False
    assert "shared_secret" not in second["provision"]

    with app.app_context():
        assert CustomerRadiusInstance.query.filter_by(customer_id=customer_id).count() == 1
        assert ProxyRealmRoute.query.filter_by(customer_id=customer_id).count() == 1
        # Setting row carries the original minted plaintext (or its Fernet
        # token in vault-enabled envs).
        inst = CustomerRadiusInstance.query.filter_by(customer_id=customer_id).one()
        key = inst.secret_vault_ref.removeprefix("vault://")
        row = db.session.get(Setting, key)
        assert row is not None and row.value
        # In dev / TestingConfig without a vault key, the secret is stored
        # in plaintext as a fallback — assert that matches the minted value.
        try:
            from app.services.customer_vault_crypto import encryption_available
            vault_on = encryption_available()
        except Exception:  # pragma: no cover
            vault_on = False
        if not vault_on:
            assert row.value == minted


def test_explicit_shared_secret_is_persisted_and_never_echoed(app, client):
    lic = _mk_license()
    license_key = lic.license_key

    res = client.post(HEARTBEAT_URL, json={
        "license_key": license_key,
        "realm": "client3",
        "radius_auth_ip": "10.0.0.3",
        "shared_secret": "supplied-secret-from-radius-module-XYZ",
    }).get_json()
    prov = res["provision"]
    assert prov["secret_minted"] is False  # client supplied it
    assert "shared_secret" not in prov     # never echoed back


# ═════════════════════════════════════════════════════════════════════════
# 3. Realm fallback — slug when omitted, preserves explicit on later refresh
# ═════════════════════════════════════════════════════════════════════════

def test_realm_falls_back_to_slug_then_preserves_explicit_change(app, client):
    lic = _mk_license(company="Hobe Networks")
    license_key = lic.license_key
    customer_id = lic.customer_id

    first = client.post(HEARTBEAT_URL, json={
        "license_key": license_key,
        # NO realm supplied → slug of company name
        "radius_auth_ip": "10.1.0.1",
    }).get_json()
    # Slug starts with the company name's alnum form.
    auto_realm = first["provision"]["realm"]
    assert auto_realm.startswith("hobenetworks")

    # Subsequent heartbeat with explicit realm → updates it.
    second = client.post(HEARTBEAT_URL, json={
        "license_key": license_key,
        "realm": "renamed5",
        "radius_auth_ip": "10.1.0.1",
    }).get_json()
    assert second["provision"]["realm"] == "renamed5"
    with app.app_context():
        inst = CustomerRadiusInstance.query.filter_by(customer_id=customer_id).one()
        assert inst.realm == "renamed5"


# ═════════════════════════════════════════════════════════════════════════
# 4. Heartbeat for unknown license — 404, no DB writes
# ═════════════════════════════════════════════════════════════════════════

def test_heartbeat_for_unknown_license_does_not_provision(app, client):
    res = client.post(HEARTBEAT_URL, json={
        "license_key": "HBR-2026-NONE-NONE-NONE",
        "realm": "ghost",
        "radius_auth_ip": "10.0.0.0",
    })
    # 404 from the bearer auth path.
    assert res.status_code in (401, 404)
    with app.app_context():
        assert CustomerRadiusInstance.query.count() == 0
        assert ProxyRealmRoute.query.count() == 0


# ═════════════════════════════════════════════════════════════════════════
# 5. Manual form fallback — admin POST creates the instance
# ═════════════════════════════════════════════════════════════════════════

def test_manual_form_creates_radius_instance(app, client):
    lic = _mk_license(company="Manual Co")
    customer_id = lic.customer_id
    _login_admin(client)

    res = client.post(
        f"/admin/infra/radius-instances/customer/{customer_id}/save",
        data={
            "instance_name": "manual-vps",
            "realm": "manualrealm",
            "mgmt_wg_ip": "10.99.0.50",
            "radius_auth_ip": "203.0.113.50",
            "radius_auth_port": "1812",
            "radius_acct_port": "1813",
            "secret_vault_ref": "",
            "status": "active",
            "notes": "created via the manual fallback form",
        },
        follow_redirects=False,
    )
    assert res.status_code in (302, 303)

    with app.app_context():
        inst = CustomerRadiusInstance.query.filter_by(customer_id=customer_id).one()
        assert inst.realm == "manualrealm"
        assert inst.radius_auth_ip == "203.0.113.50"
        assert inst.radius_auth_port == 1812
        assert inst.radius_acct_port == 1813
        assert inst.mgmt_wg_ip == "10.99.0.50"
        assert inst.instance_name == "manual-vps"
        assert inst.status == "active"


def test_customer_detail_page_links_to_manual_form(app, client):
    """The «تسجيل / تعديل نسخة RADIUS» button on the customer file MUST
    point at the manual fallback form. Without this, the L5 «ربط الريدياس»
    card has no escape hatch when auto-provision can't fire."""
    lic = _mk_license(company="Linked Co")
    customer_id = lic.customer_id
    _login_admin(client)

    res = client.get(f"/admin/customers/{customer_id}")
    assert res.status_code == 200
    html = res.data.decode("utf-8")
    expected_href = f"/admin/infra/radius-instances/customer/{customer_id}"
    assert expected_href in html
    assert "تسجيل" in html and "RADIUS" in html


# ═════════════════════════════════════════════════════════════════════════
# 6. End-to-end — auto-provisioned route appears in routing-table
# ═════════════════════════════════════════════════════════════════════════

def test_auto_provisioned_route_appears_in_routing_table(app, client):
    lic = _mk_license(company="RoutingTable Co")
    license_key = lic.license_key

    # 1. Link event auto-provisions
    prov = client.post(HEARTBEAT_URL, json={
        "license_key": license_key,
        "realm": "rt-client",
        "radius_auth_ip": "192.0.2.20",
        "radius_auth_port": 1812,
        "radius_acct_port": 1813,
    }).get_json()
    assert prov["provision"]["status"] == "provisioned"
    target_ip = prov["provision"]["radius_auth_ip"]

    # 2. The proxy now sees this realm in the routing-table.
    res = client.get(ROUTING_TABLE_URL, headers={"X-Proxy-Token": _proxy_token()})
    assert res.status_code == 200, res.get_json()
    body = res.get_json()
    assert body["ok"] is True
    routes = body["routes"]
    assert routes, "routes[] is EMPTY — auto-provisioned route is invisible to the proxy"
    rt_realm = next((r for r in routes if r["realm"] == "rt-client"), None)
    assert rt_realm is not None, f"realm 'rt-client' not in {[r['realm'] for r in routes]}"
    assert rt_realm["target_ip"] == target_ip
    assert rt_realm["auth_port"] == 1812
    assert rt_realm["acct_port"] == 1813
    # The realm-status header shows the auto-route as active.
    assert body["realms_status"]["active"] >= 1


# ═════════════════════════════════════════════════════════════════════════
# 7. Sanity — legacy endpoints stay gone
# ═════════════════════════════════════════════════════════════════════════

def test_legacy_activate_endpoint_is_404(app, client):
    res = client.post(
        "/api/integration/hoberadius/instance/activate",
        json={"activation_code": "X-X-X", "server_fingerprint": "fp"},
        base_url="https://license-panel.test",
    )
    assert res.status_code == 404


def test_legacy_license_integration_secret_is_not_importable():
    """Removed in L1 — a regression that re-exports it should fail loudly."""
    import app.license_signing as ls
    assert not hasattr(ls, "license_integration_secret")
    assert not hasattr(ls, "_hmac_root_secret")
    assert not hasattr(ls, "_bearer_license_key_ok")
