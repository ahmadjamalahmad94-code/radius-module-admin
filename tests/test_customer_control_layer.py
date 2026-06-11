from __future__ import annotations

import time
from datetime import timedelta

from sqlalchemy import inspect, text

from app import create_app, init_database, seed_defaults
from app.config import TestingConfig
from app.extensions import db
from app.license_signing import sign_license_payload  # kept as test util only
from app.models import (
    AuditLog,
    Customer,
    CustomerRadiusAdmin,
    CustomerServiceEntitlement,
    CustomerServiceRequest,
    CustomerServiceRequestMessage,
    CustomerUser,
    License,
    LicensePaymentRequest,
    Plan,
    PlatformPaymentSettings,
    ServiceCatalogItem,
    utcnow,
)
from app.services.license_service import generate_license_key

SIGNING_SECRET = "customer-control-secret-at-least-32-bytes"


def _login(client):
    return client.post("/login", data={"username": "admin", "password": "admin12345"})


def _customer_with_license() -> tuple[Customer, License]:
    customer = Customer(company_name="Control Customer", contact_name="Owner", email="owner@example.com")
    plan = Plan.query.filter_by(slug="pro").one()
    now = utcnow()
    db.session.add(customer)
    db.session.flush()
    lic = License(
        customer_id=customer.id,
        plan_id=plan.id,
        license_key=generate_license_key(),
        status="active",
        starts_at=now - timedelta(days=1),
        expires_at=now + timedelta(days=30),
        grace_until=now + timedelta(days=37),
        max_fingerprints=3,
    )
    db.session.add(lic)
    db.session.commit()
    return customer, lic


def _signed_payload(license_key: str, *, nonce: str = "nonce-1", secret: str = SIGNING_SECRET):
    payload = {
        "license_key": license_key,
        "server_fingerprint": f"fp-{nonce}",
        "hostname": "radius-runtime",
        "version": "test",
        "timestamp": int(time.time()),
        "nonce": nonce,
    }
    payload["signature"] = sign_license_payload(payload, secret)
    return payload


def _signed_payload_with(license_key: str, *, nonce: str, extra: dict, secret: str = SIGNING_SECRET):
    payload = _signed_payload(license_key, nonce=nonce, secret=secret)
    payload.pop("signature", None)
    payload.update(extra)
    payload["signature"] = sign_license_payload(payload, secret)
    return payload


def _strict_app():
    # Legacy strict-signature flags retired with bearer-only link contract.
    # Name kept so call sites compile; produces a normal TestingConfig app.
    return create_app(TestingConfig)


def test_init_database_upgrades_old_license_payment_request_schema(tmp_path):
    db_path = tmp_path / "old-license-panel.sqlite3"
    app = create_app(
        TestingConfig,
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{db_path}",
        AUTO_INIT_DB=False,
    )
    with app.app_context():
        db.session.execute(text("""
            CREATE TABLE customers (
                id INTEGER PRIMARY KEY,
                company_name VARCHAR(180) NOT NULL,
                contact_name VARCHAR(160) NOT NULL DEFAULT '',
                email VARCHAR(180) NOT NULL DEFAULT '',
                phone VARCHAR(80) NOT NULL DEFAULT '',
                country VARCHAR(100) NOT NULL DEFAULT '',
                city VARCHAR(100) NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                status VARCHAR(20) NOT NULL DEFAULT 'active',
                created_at DATETIME NOT NULL,
                updated_at DATETIME NOT NULL
            )
        """))
        db.session.execute(text("""
            CREATE TABLE license_payment_requests (
                id INTEGER PRIMARY KEY,
                customer_id INTEGER NOT NULL,
                plan_id INTEGER,
                license_id INTEGER,
                purpose VARCHAR(40) NOT NULL,
                amount NUMERIC(10, 2) NOT NULL,
                currency VARCHAR(12) NOT NULL DEFAULT 'USD',
                provider VARCHAR(40) NOT NULL DEFAULT 'manual_wallet',
                receiver_wallet VARCHAR(120) NOT NULL DEFAULT '',
                reference_code VARCHAR(40) NOT NULL,
                status VARCHAR(30) NOT NULL DEFAULT 'pending',
                expires_at DATETIME,
                created_at DATETIME NOT NULL,
                updated_at DATETIME NOT NULL
            )
        """))
        db.session.execute(text("""
            CREATE TABLE provisioning_orders (
                id INTEGER PRIMARY KEY,
                public_reference VARCHAR(40) NOT NULL DEFAULT '',
                customer_id INTEGER,
                status VARCHAR(40) NOT NULL DEFAULT 'payment_pending',
                notes TEXT NOT NULL DEFAULT '',
                delivered_at DATETIME,
                created_at DATETIME NOT NULL,
                updated_at DATETIME NOT NULL
            )
        """))
        db.session.commit()

        init_database(app)

        columns = {column["name"] for column in inspect(db.engine).get_columns("license_payment_requests")}
        assert {"access_token", "applied_at", "applied_action", "applied_result_json"}.issubset(columns)
        provisioning_columns = {column["name"] for column in inspect(db.engine).get_columns("provisioning_orders")}
        assert {
            "license_payment_request_id",
            "target_plan_id",
            "requested_at",
            "paid_at",
            "provisioning_started_at",
            "ready_at",
            "assigned_operator",
        }.issubset(provisioning_columns)
        customer_columns = {column["name"] for column in inspect(db.engine).get_columns("customers")}
        assert {"runtime_url", "portal_config_json"}.issubset(customer_columns)


def test_customer_user_create_edit_disable_and_portal_login(client):
    _login(client)
    customer, _lic = _customer_with_license()

    created = client.post(f"/admin/customers/{customer.id}/users/new", data={
        "username": "customer-admin",
        "email": "owner@example.com",
        "full_name": "Owner",
        "role_key": "owner",
        "password": "Secret123!",
        "active": "1",
    }, follow_redirects=True)

    assert created.status_code == 200
    user = CustomerUser.query.filter_by(customer_id=customer.id, username="customer-admin").one()
    assert user.password_hash != "Secret123!"
    assert user.password_hash.startswith("scrypt:")
    assert user.password_version == 1

    login = client.post("/portal/login", data={"username": "customer-admin", "password": "Secret123!"}, follow_redirects=True)
    assert login.status_code == 200
    assert "Control Customer" in login.get_data(as_text=True)

    edited = client.post(f"/admin/customers/{customer.id}/users/{user.id}/edit", data={
        "username": "customer-admin",
        "email": "owner@example.com",
        "full_name": "Owner",
        "role_key": "owner",
        "password": "NewSecret123!",
        "active": "1",
    }, follow_redirects=True)
    assert edited.status_code == 200
    db.session.refresh(user)
    assert user.password_version == 2
    assert user.check_password("NewSecret123!")

    client.post(f"/admin/customers/{customer.id}/users/{user.id}/disable", follow_redirects=True)
    db.session.refresh(user)
    assert user.active is False
    assert AuditLog.query.filter_by(action="customer_user_disabled").count() == 1


def test_admin_can_set_customer_user_password_from_customer_360(client):
    _login(client)
    customer, _lic = _customer_with_license()
    user = CustomerUser(customer_id=customer.id, username="reset-admin", email="reset@example.com", full_name="Owner", role_key="owner", active=True)
    user.set_password("Secret123!", increment_version=False)
    user.password_version = 1
    db.session.add(user)
    db.session.commit()

    res = client.post(f"/admin/customers/{customer.id}/users/{user.id}/password", data={
        "password": "ResetSecret123!",
        "password_confirm": "ResetSecret123!",
    }, follow_redirects=True)
    db.session.refresh(user)

    assert res.status_code == 200
    assert user.password_version == 2
    assert user.check_password("ResetSecret123!")
    body = res.get_data(as_text=True)
    assert "تعيين كلمة المرور" in body
    assert AuditLog.query.filter_by(action="customer_user_password_set_by_admin").count() == 1


def test_customer_self_signup_stays_pending_until_admin_approves(client):
    signup = client.post("/portal/signup", data={
        "company_name": "Pending Net",
        "full_name": "Pending Owner",
        "username": "pending-owner",
        "email": "pending@example.com",
        "phone": "0590000000",
        "password": "Secret123!",
        "password_confirm": "Secret123!",
    }, follow_redirects=True)

    assert signup.status_code == 200
    customer = Customer.query.filter_by(company_name="Pending Net").one()
    user = CustomerUser.query.filter_by(customer_id=customer.id, username="pending-owner").one()
    assert customer.status == "pending"
    assert user.active is False
    assert user.password_hash.startswith("scrypt:")
    assert user.password_version == 1

    blocked = client.post("/portal/login", data={"username": "pending-owner", "password": "Secret123!"})
    assert blocked.status_code == 401

    _login(client)
    approved = client.post(f"/admin/customers/{customer.id}/approve", follow_redirects=True)
    assert approved.status_code == 200
    db.session.refresh(customer)
    db.session.refresh(user)
    assert customer.status == "active"
    assert user.active is True
    assert AuditLog.query.filter_by(action="customer_approved").count() == 1

    login = client.post("/portal/login", data={"username": "pending-owner", "password": "Secret123!"}, follow_redirects=True)
    assert login.status_code == 200
    assert "Pending Net" in login.get_data(as_text=True)


def test_admin_rejects_duplicate_customer_email_and_phone(client):
    _login(client)
    existing = Customer(
        company_name="Existing Net",
        contact_name="Owner",
        email="owner@example.com",
        phone="0599043337",
        status="active",
    )
    db.session.add(existing)
    db.session.commit()

    duplicate_email = client.post("/admin/customers/new", data={
        "company_name": "Email Duplicate",
        "contact_name": "Other Owner",
        "email": "OWNER@example.com",
        "phone": "0590001111",
        "status": "active",
    })
    assert duplicate_email.status_code == 400
    assert "البريد الإلكتروني مستخدم" in duplicate_email.get_data(as_text=True)

    duplicate_phone = client.post("/admin/customers/new", data={
        "company_name": "Phone Duplicate",
        "contact_name": "Other Owner",
        "email": "other@example.com",
        "phone": "0599-043337",
        "status": "active",
    })
    assert duplicate_phone.status_code == 400
    assert "رقم الجوال مستخدم" in duplicate_phone.get_data(as_text=True)


def test_customer_signup_rejects_duplicate_email_and_phone(client):
    existing = Customer(
        company_name="Existing Portal Net",
        contact_name="Owner",
        email="portal-owner@example.com",
        phone="0599043337",
        status="active",
    )
    db.session.add(existing)
    db.session.commit()

    duplicate_email = client.post("/portal/signup", data={
        "company_name": "Portal Duplicate Email",
        "full_name": "Owner",
        "username": "portal-duplicate-email",
        "email": "PORTAL-OWNER@example.com",
        "phone": "0590002222",
        "password": "Secret123!",
        "password_confirm": "Secret123!",
    })
    assert duplicate_email.status_code == 400
    assert "البريد الإلكتروني مستخدم" in duplicate_email.get_data(as_text=True)

    duplicate_phone = client.post("/portal/signup", data={
        "company_name": "Portal Duplicate Phone",
        "full_name": "Owner",
        "username": "portal-duplicate-phone",
        "email": "portal-new@example.com",
        "phone": "0599 043 337",
        "password": "Secret123!",
        "password_confirm": "Secret123!",
    })
    assert duplicate_phone.status_code == 400
    assert "رقم الجوال مستخدم" in duplicate_phone.get_data(as_text=True)


def test_license_new_page_renders(client):
    _login(client)

    response = client.get("/admin/licenses/new")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "توليد ترخيص جديد" in body
    assert "حدث خطأ داخلي" not in body


def test_customer_portal_shows_radius_runtime_license_setup(client):
    _login(client)
    customer, lic = _customer_with_license()
    user = CustomerUser(customer_id=customer.id, username="portal-owner", email="portal@example.com", full_name="Owner", role_key="owner", active=True)
    user.set_password("Secret123!", increment_version=False)
    db.session.add(user)
    db.session.commit()

    res = client.post("/portal/login", data={"username": "portal-owner", "password": "Secret123!"}, follow_redirects=True)
    body = res.get_data(as_text=True)

    assert res.status_code == 200
    assert "إعداد ربط الريدياس" in body
    assert "قيم الربط الجاهزة للنسخ" not in body
    assert "HOBERADIUS_ADMIN_BASE_URL" not in body
    assert lic.license_key in body
    # Legacy «سر التوقيع» / HOBERADIUS_ADMIN_SHARED_SECRET retired with the
    # bearer-only link contract — the panel must NOT echo any derived secret.
    assert "HOBERADIUS_ADMIN_SHARED_SECRET" not in body
    assert "سر التوقيع" not in body


def test_customer_portal_password_change_increments_version(client):
    _login(client)
    customer, _lic = _customer_with_license()
    user = CustomerUser(customer_id=customer.id, username="portal-pass", email="pass@example.com", full_name="Owner", role_key="owner", active=True)
    user.set_password("Secret123!", increment_version=False)
    db.session.add(user)
    db.session.commit()

    client.post("/portal/login", data={"username": "portal-pass", "password": "Secret123!"})
    changed = client.post("/portal/account/password", data={
        "current_password": "Secret123!",
        "new_password": "NewSecret123!",
        "confirm_password": "NewSecret123!",
    }, follow_redirects=True)
    db.session.refresh(user)

    assert changed.status_code == 200
    assert user.password_version == 2
    assert user.check_password("NewSecret123!")
    assert AuditLog.query.filter_by(action="customer_user_password_changed_from_portal").count() == 1


def test_customer_360_renders_services_users_payments_and_contract(client):
    _login(client)
    customer, _lic = _customer_with_license()

    res = client.get(f"/admin/customers/{customer.id}")
    body = res.get_data(as_text=True)

    assert res.status_code == 200
    assert "ملف العميل 360" in body
    assert "خدمة تغيير العنوان والشبكة الخاصة" in body
    assert "limits JSON" not in body
    assert "config JSON" not in body
    assert "owner أولًا" not in body
    assert "customer_users_version" not in body
    assert "مستخدمو العميل" in body


def test_service_catalog_matches_radius_admin_surfaces(app):
    with app.app_context():
        seed_defaults(app)
        keys = {item.service_key for item in ServiceCatalogItem.query.all()}

    assert {
        "subscribers",
        "cards",
        "card_marketplace",
        "cards_recharge",
        "nas",
        "routers",
        "ip_pools",
        "setup_wizard",
        "finance_center",
        "payment_collection",
        "communications",
        "risk_events",
        "reports",
        "integration_bridge",
        "multi_tenant",
    }.issubset(keys)


def test_service_entitlement_activation_creates_audit_and_contract(client):
    _login(client)
    customer, lic = _customer_with_license()

    res = client.post(f"/admin/customers/{customer.id}/services/cards", data={
        "action": "activate",
        "enabled": "1",
        "status": "active",
        "limit_monthly_generated": "100",
        "notes": "Cards enabled",
    }, follow_redirects=True)

    assert res.status_code == 200
    entitlement = CustomerServiceEntitlement.query.filter_by(customer_id=customer.id, service_key="cards").one()
    assert entitlement.enabled is True
    assert entitlement.limits["monthly_generated"] == 100
    assert AuditLog.query.filter_by(action="customer_service_entitlement_updated").count() == 1

    contract = client.post("/api/license/check", json={
        "license_key": lic.license_key,
        "server_fingerprint": "fp-cards",
    }).get_json()
    assert contract["services"]["cards"]["enabled"] is True
    assert contract["services"]["cards"]["limits"]["monthly_generated"] == 100
    assert contract["limits"]["cards"]["monthly_generated"] == 100


def test_identity_sync_requires_https_in_strict_mode_and_returns_hashes():
    app = _strict_app()
    with app.app_context():
        db.create_all()
        seed_defaults(app)
        customer, lic = _customer_with_license()
        user = CustomerUser(customer_id=customer.id, username="owner", email="owner@example.com", full_name="Owner", role_key="owner", active=True)
        user.set_password("Secret123!", increment_version=False)
        user.password_version = 4
        db.session.add(user)
        db.session.commit()
        client = app.test_client()

        http_res = client.post("/api/integration/hoberadius/identity-sync", json=_signed_payload(lic.license_key, nonce="http"))
        assert http_res.status_code == 426

        https_res = client.post(
            "/api/integration/hoberadius/identity-sync",
            json=_signed_payload(lic.license_key, nonce="https"),
            base_url="https://license-panel.test",
        )
        body = https_res.get_json()

        assert https_res.status_code == 200
        assert body["ok"] is True
        assert body["version"] == 4
        assert body["users"][0]["password_hash"].startswith("scrypt:")
        assert "password" not in body["users"][0]


def test_identity_sync_carries_explicit_is_super_flag():
    """الجسر يدفع is_super صريحاً: للسوبر يوزر الصريح، ولمالك الحساب (توافقاً)،
    ولا يدفعه لمستخدم عادي غير مفعّل عليه العلم."""
    app = _strict_app()
    with app.app_context():
        db.create_all()
        seed_defaults(app)
        customer, lic = _customer_with_license()

        # مستخدم عادي (viewer) مع تفعيل السوبر يوزر الصريح.
        super_user = CustomerUser(
            customer_id=customer.id, username="super-viewer", email="sv@example.com",
            full_name="Super Viewer", role_key="viewer", active=True, is_super=True,
        )
        super_user.set_password("Secret123!", increment_version=False)
        # مالك الحساب: سوبر ضمنياً دون تفعيل العلم.
        owner_user = CustomerUser(
            customer_id=customer.id, username="acct-owner", email="ao@example.com",
            full_name="Owner", role_key="owner", active=True,
        )
        owner_user.set_password("Secret123!", increment_version=False)
        # مستخدم عادي بلا سوبر.
        plain_user = CustomerUser(
            customer_id=customer.id, username="plain-support", email="ps@example.com",
            full_name="Support", role_key="support", active=True,
        )
        plain_user.set_password("Secret123!", increment_version=False)
        db.session.add_all([super_user, owner_user, plain_user])
        db.session.commit()
        client = app.test_client()

        res = client.post(
            "/api/integration/hoberadius/identity-sync",
            json=_signed_payload(lic.license_key, nonce="is-super"),
            base_url="https://license-panel.test",
        )
        body = res.get_json()
        assert res.status_code == 200
        by_username = {u["username"]: u for u in body["users"]}
        assert by_username["super-viewer"]["is_super"] is True
        assert by_username["acct-owner"]["is_super"] is True
        assert by_username["plain-support"]["is_super"] is False


def test_customer_user_form_persists_explicit_is_super(client):
    """نموذج لوحة التراخيص يخزّن العلم الصريح is_super على CustomerUser."""
    _login(client)
    customer, _lic = _customer_with_license()
    created = client.post(f"/admin/customers/{customer.id}/users/new", data={
        "username": "explicit-super",
        "email": "es@example.com",
        "full_name": "Explicit Super",
        "role_key": "admin",
        "is_super": "1",
        "password": "Secret123!",
        "active": "1",
    }, follow_redirects=True)
    assert created.status_code == 200
    user = CustomerUser.query.filter_by(customer_id=customer.id, username="explicit-super").one()
    assert user.is_super is True
    assert user.is_effective_super is True


def test_radius_admins_report_ingests_snapshot_and_does_not_clobber_force_super():
    """بلاغ الراديوس يحدّث اللقطة، وحقل force_super المملوك للّوحة لا يُداس."""
    app = _strict_app()
    with app.app_context():
        db.create_all()
        seed_defaults(app)
        customer, lic = _customer_with_license()
        # صف موجود مسبقاً مفعّل عليه الفرض من اللوحة.
        existing = CustomerRadiusAdmin(
            customer_id=customer.id, radius_admin_id=1, username="admin",
            is_super_admin=False, enabled=True, force_super=True,
        )
        db.session.add(existing)
        db.session.commit()
        client = app.test_client()

        payload = _signed_payload_with(lic.license_key, nonce="admins-report", extra={"admins": [
            {"id": 1, "username": "admin", "is_super_admin": False, "enabled": True,
             "role": "owner", "managed_by_license_admin": False, "external_identity_provider": ""},
            {"id": 2, "username": "helpdesk", "is_super_admin": False, "enabled": True,
             "role": "support", "managed_by_license_admin": True, "external_identity_provider": "license_admin"},
        ]})
        res = client.post(
            "/api/integration/hoberadius/admins/report",
            json=payload,
            base_url="https://license-panel.test",
        )
        body = res.get_json()
        assert res.status_code == 200
        assert body["ok"] is True
        assert body["imported"] == 2

        rows = {r.radius_admin_id: r for r in CustomerRadiusAdmin.query.filter_by(customer_id=customer.id).all()}
        assert rows[1].force_super is True  # لم يُداس بالبلاغ
        assert rows[1].username == "admin"
        assert rows[2].managed_by_license_admin is True


def test_radius_admins_report_marks_primary_and_sorts_it_first():
    """الأدمن الرئيسي (is_primary) يُستورد ويظهر في صدارة قائمة العرض."""
    from app.services.customer_control import import_radius_admins, radius_admins_for_customer

    app = _strict_app()
    with app.app_context():
        db.create_all()
        seed_defaults(app)
        customer, lic = _customer_with_license()
        # يصل الرئيسي بمعرّف أكبر؛ يجب أن يتصدّر القائمة رغم ذلك.
        import_radius_admins(customer, lic, [
            {"id": 5, "username": "helpdesk", "role": "support", "is_primary": False},
            {"id": 9, "username": "admin", "role": "owner", "is_primary": True},
        ])
        db.session.commit()
        rows = radius_admins_for_customer(customer)
        assert [r.username for r in rows] == ["admin", "helpdesk"]
        assert rows[0].is_primary is True
        assert rows[1].is_primary is False


def test_identity_sync_carries_admin_super_overrides():
    """عقد مزامنة الهوية يحمل تعليمات فرض السوبر لأدمن الراديوس المحليين فقط."""
    app = _strict_app()
    with app.app_context():
        db.create_all()
        seed_defaults(app)
        customer, lic = _customer_with_license()
        db.session.add_all([
            CustomerRadiusAdmin(customer_id=customer.id, radius_admin_id=1, username="admin",
                                enabled=True, force_super=True),
            CustomerRadiusAdmin(customer_id=customer.id, radius_admin_id=2, username="helpdesk",
                                enabled=True, force_super=False),
        ])
        db.session.commit()
        client = app.test_client()

        res = client.post(
            "/api/integration/hoberadius/identity-sync",
            json=_signed_payload(lic.license_key, nonce="overrides"),
            base_url="https://license-panel.test",
        )
        body = res.get_json()
        assert res.status_code == 200
        overrides = body["admin_super_overrides"]
        assert len(overrides) == 1
        assert overrides[0] == {"radius_admin_id": 1, "username": "admin", "is_super": True}


def test_admin_can_toggle_radius_admin_force_super(client):
    """زر «اجعله سوبر يوزر» يضبط/يلغي الفرض على صف أدمن الراديوس."""
    _login(client)
    customer, _lic = _customer_with_license()
    row = CustomerRadiusAdmin(
        customer_id=customer.id, radius_admin_id=1, username="admin", enabled=True, force_super=False,
    )
    db.session.add(row)
    db.session.commit()

    enabled = client.post(
        f"/admin/customers/{customer.id}/radius-admins/{row.id}/super",
        data={"action": "enable"}, follow_redirects=True,
    )
    assert enabled.status_code == 200
    db.session.refresh(row)
    assert row.force_super is True

    disabled = client.post(
        f"/admin/customers/{customer.id}/radius-admins/{row.id}/super",
        data={"action": "disable"}, follow_redirects=True,
    )
    assert disabled.status_code == 200
    db.session.refresh(row)
    assert row.force_super is False


def test_runtime_contract_includes_services_limits_and_user_version():
    app = _strict_app()
    with app.app_context():
        db.create_all()
        seed_defaults(app)
        customer, lic = _customer_with_license()
        user = CustomerUser(customer_id=customer.id, username="owner", role_key="owner", active=True)
        user.set_password("Secret123!", increment_version=False)
        user.password_version = 2
        db.session.add(user)
        db.session.commit()
        client = app.test_client()

        res = client.post(
            "/api/integration/hoberadius/runtime-contract",
            json=_signed_payload(lic.license_key, nonce="runtime"),
            base_url="https://license-panel.test",
        )
        body = res.get_json()

        assert res.status_code == 200
        assert body["license"]["active"] is True
        assert body["services"]["ip_change_vpn"]["enabled"] is False
        assert body["limits"]["subscribers"]["max_total"] == lic.plan.max_users
        assert body["customer_users_version"] == 2


# test_runtime_contract_accepts_per_license_portal_secret — retired with the
# derived per-license bind secret (legacy linking auth). Bearer is the only
# credential now and is covered exhaustively in tests/test_simple_link_bearer.py.


def test_runtime_password_change_requires_https_and_updates_version():
    app = _strict_app()
    with app.app_context():
        db.create_all()
        seed_defaults(app)
        customer, lic = _customer_with_license()
        user = CustomerUser(customer_id=customer.id, username="owner", email="owner@example.com", full_name="Owner", role_key="owner", active=True)
        user.set_password("Secret123!", increment_version=False)
        user.password_version = 3
        db.session.add(user)
        db.session.commit()
        client = app.test_client()
        payload = _signed_payload_with(
            lic.license_key,
            nonce="runtime-password",
            extra={"external_user_id": user.id, "username": user.username, "new_password": "RuntimeSecret123!"},
        )

        http_res = client.post("/api/integration/hoberadius/customer-users/password-change", json=payload)
        assert http_res.status_code == 426

        https_res = client.post(
            "/api/integration/hoberadius/customer-users/password-change",
            json=payload,
            base_url="https://license-panel.test",
        )
        body = https_res.get_json()
        db.session.refresh(user)

        assert https_res.status_code == 200
        assert body["status"] == "updated"
        assert body["password_version"] == 4
        assert user.check_password("RuntimeSecret123!")
        assert AuditLog.query.filter_by(action="customer_user_password_changed_from_runtime").count() == 1


def test_service_payment_request_uses_existing_manual_wallet(client):
    _login(client)
    customer, _lic = _customer_with_license()
    db.session.add(PlatformPaymentSettings(
        enabled=True,
        provider="manual_wallet",
        wallet_number="0599999999",
        wallet_owner_name="Hobe",
        currency="USD",
    ))
    db.session.commit()

    res = client.post(f"/admin/customers/{customer.id}/services/cards/payment-request", data={
        "amount": "15",
        "currency": "USD",
    }, follow_redirects=False)

    assert res.status_code == 302
    assert AuditLog.query.filter_by(action="customer_service_payment_request_created").count() == 1


def test_customer_service_request_opens_ticket_and_admin_pages_render(client):
    customer, _lic = _customer_with_license()
    user = CustomerUser(
        customer_id=customer.id,
        username="portal-owner",
        email="portal-owner@example.com",
        full_name="Portal Owner",
        role_key="owner",
        active=True,
    )
    user.set_password("Secret123!", increment_version=False)
    db.session.add(user)
    db.session.commit()

    login = client.post("/portal/login", data={"username": "portal-owner", "password": "Secret123!"})
    assert login.status_code == 302
    created = client.post("/portal/services/cards/request", data={
        "request_type": "activation",
        "notes": "نريد تفعيل خدمة الكروت.",
    })
    assert created.status_code == 302

    ticket = CustomerServiceRequest.query.filter_by(customer_id=customer.id, service_key="cards").one()
    assert ticket.public_reference.startswith("SR-")
    assert ticket.status == "pending"
    assert CustomerServiceRequestMessage.query.filter_by(service_request_id=ticket.id, internal=False).count() == 1

    portal_detail = client.get(f"/portal/service-requests/{ticket.id}")
    assert portal_detail.status_code == 200
    assert ticket.public_reference in portal_detail.get_data(as_text=True)

    _login(client)
    admin_list = client.get("/admin/service-requests")
    assert admin_list.status_code == 200
    assert ticket.public_reference in admin_list.get_data(as_text=True)
    admin_detail = client.get(f"/admin/service-requests/{ticket.id}")
    assert admin_detail.status_code == 200
    assert "اعتماد وتفعيل الخدمة" in admin_detail.get_data(as_text=True)


def test_admin_service_request_payment_confirm_and_approve_updates_contract(client):
    _login(client)
    customer, lic = _customer_with_license()
    db.session.add(PlatformPaymentSettings(
        enabled=True,
        provider="manual_wallet",
        wallet_number="0599999999",
        wallet_owner_name="Hobe",
        currency="USD",
    ))
    request_row = CustomerServiceRequest(
        public_reference="SR-TESTPAY",
        customer_id=customer.id,
        license_id=lic.id,
        service_key="cards",
        title="طلب تفعيل الكروت",
        status="pending",
        payment_status="not_required",
    )
    request_row.request_type = "activation"
    db.session.add(request_row)
    db.session.commit()

    payment = client.post(f"/admin/service-requests/{request_row.id}/payment-request", data={
        "amount": "25",
        "currency": "USD",
    })
    assert payment.status_code == 302
    db.session.refresh(request_row)
    assert request_row.status == "payment_pending"
    assert request_row.payment_request_id is not None

    confirmed = client.post(f"/admin/service-requests/{request_row.id}/confirm-payment", data={
        "review_note": "تم استلام المبلغ نقداً.",
    })
    assert confirmed.status_code == 302
    db.session.refresh(request_row)
    payment_request = db.session.get(LicensePaymentRequest, request_row.payment_request_id)
    assert payment_request.status == "paid"
    assert request_row.payment_status == "paid"

    approved = client.post(f"/admin/service-requests/{request_row.id}/approve", data={
        "license_id": str(lic.id),
        "limit_generate_per_batch": "200",
        "admin_note": "تم التفعيل بعد اعتماد الدفع.",
    })
    assert approved.status_code == 302
    db.session.refresh(request_row)
    entitlement = CustomerServiceEntitlement.query.filter_by(customer_id=customer.id, service_key="cards").one()
    assert request_row.status == "approved"
    assert entitlement.enabled is True
    assert entitlement.status == "active"
    assert entitlement.limits["generate_per_batch"] == 200
    contract = client.post("/api/integration/hoberadius/runtime-contract", json=_signed_payload(lic.license_key), base_url="https://license-panel.test")
    assert contract.status_code == 200
    assert contract.get_json()["services"]["cards"]["enabled"] is True
    assert AuditLog.query.filter_by(action="customer_service_request_approved").count() == 1
