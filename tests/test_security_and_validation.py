from __future__ import annotations

import pytest

from app import create_app, seed_defaults
from app.config import Config, TestingConfig
from app.extensions import db
from app.models import Plan


class UnsafeProductionConfig(Config):
    TESTING = False
    AUTO_INIT_DB = False
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    LICENSE_PANEL_ENV = "production"
    SECRET_KEY = Config.DEFAULT_SECRET_KEY
    ADMIN_PASSWORD = Config.DEFAULT_ADMIN_PASSWORD


class SafeProductionConfig(UnsafeProductionConfig):
    SECRET_KEY = "production-secret-for-tests"
    ADMIN_PASSWORD = "production-admin-password-for-tests"
    SESSION_COOKIE_SECURE = True


def test_production_rejects_default_secret_and_admin_password():
    with pytest.raises(RuntimeError, match="FLASK_SECRET"):
        create_app(UnsafeProductionConfig)


def test_production_accepts_non_default_secret_and_admin_password():
    app = create_app(SafeProductionConfig)
    assert app.config["LICENSE_PANEL_ENV"] == "production"


def test_production_rejects_default_database_uri():
    class UnsafeDatabaseConfig(SafeProductionConfig):
        SQLALCHEMY_DATABASE_URI = Config.DEFAULT_DATABASE_URI

    with pytest.raises(RuntimeError, match="DATABASE_URL"):
        create_app(UnsafeDatabaseConfig)


def test_production_rejects_disabled_rate_limits():
    class UnsafeRateLimitConfig(SafeProductionConfig):
        RATE_LIMITS_ENABLED = False

    with pytest.raises(RuntimeError, match="RATE_LIMITS_ENABLED"):
        create_app(UnsafeRateLimitConfig)


def test_production_rejects_insecure_session_cookie():
    class UnsafeCookieConfig(SafeProductionConfig):
        SESSION_COOKIE_SECURE = False

    with pytest.raises(RuntimeError, match="SESSION_COOKIE_SECURE"):
        create_app(UnsafeCookieConfig)


def test_login_rate_limit_blocks_repeated_attempts():
    app = create_app(
        TestingConfig,
        RATE_LIMITS_ENABLED=True,
        LOGIN_RATE_LIMIT_MAX=2,
        LOGIN_RATE_LIMIT_WINDOW_SECONDS=60,
    )
    with app.app_context():
        db.create_all()
        seed_defaults(app)
        client = app.test_client()

        assert client.post("/login", data={"username": "admin", "password": "wrong"}).status_code == 401
        assert client.post("/login", data={"username": "admin", "password": "wrong"}).status_code == 401
        limited = client.post("/login", data={"username": "admin", "password": "wrong"})

        assert limited.status_code == 429
        assert limited.headers["Retry-After"]


def test_license_check_rate_limit_blocks_repeated_attempts():
    app = create_app(
        TestingConfig,
        RATE_LIMITS_ENABLED=True,
        LICENSE_CHECK_RATE_LIMIT_MAX=2,
        LICENSE_CHECK_RATE_LIMIT_WINDOW_SECONDS=60,
    )
    with app.app_context():
        db.create_all()
        seed_defaults(app)
        client = app.test_client()

        payload = {"license_key": "HBR-2026-NONE-NONE-NONE", "server_fingerprint": "fp-1"}
        assert client.post("/api/license/check", json=payload).status_code == 200
        assert client.post("/api/license/check", json=payload).status_code == 200
        limited = client.post("/api/license/check", json=payload)

        assert limited.status_code == 429
        assert limited.get_json()["status"] == "rate_limited"
        assert limited.headers["Retry-After"]


def test_license_check_rate_limit_uses_license_key_bucket():
    app = create_app(
        TestingConfig,
        RATE_LIMITS_ENABLED=True,
        LICENSE_CHECK_RATE_LIMIT_MAX=100,
        LICENSE_KEY_RATE_LIMIT_MAX=2,
        LICENSE_KEY_RATE_LIMIT_WINDOW_SECONDS=60,
    )
    with app.app_context():
        db.create_all()
        seed_defaults(app)
        client = app.test_client()

        payload = {"license_key": "HBR-2026-SAME-SAME-SAME", "server_fingerprint": "fp-1"}
        assert client.post("/api/license/check", json=payload, environ_base={"REMOTE_ADDR": "10.0.0.1"}).status_code == 200
        assert client.post("/api/license/check", json=payload, environ_base={"REMOTE_ADDR": "10.0.0.2"}).status_code == 200
        limited = client.post("/api/license/check", json=payload, environ_base={"REMOTE_ADDR": "10.0.0.3"})

        assert limited.status_code == 429
        assert limited.get_json()["status"] == "rate_limited"


def test_security_headers_and_secure_cookie_flags_are_set(client):
    response = client.get("/login")

    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "same-origin"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]


def test_secure_cookie_and_hsts_when_enabled():
    app = create_app(TestingConfig, SESSION_COOKIE_SECURE=True)
    with app.app_context():
        db.create_all()
        seed_defaults(app)
        client = app.test_client()
        response = client.post("/login", data={"username": "admin", "password": "admin12345"})

        assert "Secure" in response.headers["Set-Cookie"]
        assert response.headers["Strict-Transport-Security"].startswith("max-age=")


def test_login_rejects_external_next_redirect(client):
    response = client.post(
        "/login?next=https://evil.example/admin",
        data={"username": "admin", "password": "admin12345"},
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert response.headers["Location"] == "/admin/dashboard"


def test_login_allows_internal_next_redirect(client):
    response = client.post(
        "/login?next=/admin/customers",
        data={"username": "admin", "password": "admin12345"},
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert response.headers["Location"] == "/admin/customers"


def test_duplicate_plan_slug_returns_validation_error(client, app):
    client.post("/login", data={"username": "admin", "password": "admin12345"})

    response = client.post("/admin/plans/new", data={
        "name": "Duplicate Starter",
        "slug": "starter",
        "monthly_price": "10",
        "currency": "USD",
        "max_users": "100",
        "max_nas": "1",
        "max_admins": "1",
        "max_devices": "1",
        "status": "active",
    })

    assert response.status_code == 400
    assert Plan.query.filter_by(slug="starter").count() == 1


def test_duplicate_plan_slug_on_update_returns_validation_error(client, app):
    client.post("/login", data={"username": "admin", "password": "admin12345"})
    plan = Plan(
        name="Unique Plan",
        slug="unique-plan",
        monthly_price=10,
        currency="USD",
        max_users=100,
        max_nas=1,
        max_admins=1,
        max_devices=1,
        status="active",
    )
    plan.features = {}
    db.session.add(plan)
    db.session.commit()

    response = client.post(f"/admin/plans/{plan.id}/edit", data={
        "name": "Unique Plan",
        "slug": "starter",
        "monthly_price": "10",
        "currency": "USD",
        "max_users": "100",
        "max_nas": "1",
        "max_admins": "1",
        "max_devices": "1",
        "status": "active",
    })

    assert response.status_code == 400
    db.session.rollback()
    assert db.session.get(Plan, plan.id).slug == "unique-plan"
