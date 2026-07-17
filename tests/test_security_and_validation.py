from __future__ import annotations

import re

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
    # Legacy LICENSE_CHECK_ALLOW_UNSIGNED / SIGNATURE_REQUIRED / HMAC_SECRET
    # were retired with the bearer-only link contract — no longer required by
    # the strict-prod check in app/__init__.py.


class SafeBootstrapConfig(SafeProductionConfig):
    LICENSE_PANEL_ENV = "bootstrap"
    BOOTSTRAP_MODE = True
    SESSION_COOKIE_SECURE = False
    WTF_CSRF_ENABLED = True


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


# test_production_rejects_unsigned_license_checks +
# test_production_rejects_missing_license_hmac_secret — retired with the
# bearer-only link contract. Strict-prod no longer enforces signature flags.


def test_production_rejects_debug_mode(monkeypatch):
    monkeypatch.setenv("FLASK_DEBUG", "1")

    with pytest.raises(RuntimeError, match="FLASK_DEBUG"):
        create_app(SafeProductionConfig)


def test_bootstrap_allows_insecure_session_cookie_for_ip_http():
    app = create_app(SafeBootstrapConfig)

    assert app.config["LICENSE_PANEL_ENV"] == "bootstrap"
    assert app.config["SESSION_COOKIE_SECURE"] is False
    assert app.config["WTF_CSRF_ENABLED"] is True


def test_bootstrap_rejects_default_admin_password():
    class UnsafeBootstrapPasswordConfig(SafeBootstrapConfig):
        ADMIN_PASSWORD = Config.DEFAULT_ADMIN_PASSWORD

    with pytest.raises(RuntimeError, match="LICENSE_ADMIN_PASSWORD"):
        create_app(UnsafeBootstrapPasswordConfig)


def test_bootstrap_rejects_default_flask_secret():
    class UnsafeBootstrapSecretConfig(SafeBootstrapConfig):
        SECRET_KEY = Config.DEFAULT_SECRET_KEY

    with pytest.raises(RuntimeError, match="FLASK_SECRET"):
        create_app(UnsafeBootstrapSecretConfig)


# test_bootstrap_rejects_missing_license_hmac_secret — retired with bearer-only.


def test_bootstrap_rejects_debug_mode(monkeypatch):
    monkeypatch.setenv("FLASK_DEBUG", "1")

    with pytest.raises(RuntimeError, match="FLASK_DEBUG"):
        create_app(SafeBootstrapConfig)


def test_bootstrap_login_page_renders_with_warning_banner():
    app = create_app(SafeBootstrapConfig)
    with app.app_context():
        db.create_all()
        seed_defaults(app)
        client = app.test_client()

        response = client.get("/login", base_url="http://203.0.113.10")

        assert response.status_code == 200
        assert "وضع التهيئة المؤقت مفعل" in response.get_data(as_text=True)
        assert app.config["WTF_CSRF_ENABLED"] is True


def test_bootstrap_csrf_remains_enabled_and_login_works_with_token_over_http():
    app = create_app(SafeBootstrapConfig)
    with app.app_context():
        db.create_all()
        seed_defaults(app)
        client = app.test_client()

        blocked = client.post(
            "/login",
            data={"username": "admin", "password": "production-admin-password-for-tests"},
            base_url="http://203.0.113.10",
        )
        assert blocked.status_code == 400

        page = client.get("/login", base_url="http://203.0.113.10")
        token_match = re.search(r'name="_csrf_token" value="([^"]+)"', page.get_data(as_text=True))
        assert token_match
        response = client.post(
            "/login",
            data={
                "_csrf_token": token_match.group(1),
                "username": "admin",
                "password": "production-admin-password-for-tests",
            },
            base_url="http://203.0.113.10",
            follow_redirects=False,
        )

        assert response.status_code == 302
        assert response.headers["Location"] == "/admin/dashboard"


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
    # SAMEORIGIN (2026-07): يمنع clickjacking الخارجي ويسمح بالتضمين داخل نفس الأصل
    assert response.headers["X-Frame-Options"] == "SAMEORIGIN"
    assert response.headers["Referrer-Policy"] == "same-origin"
    assert "frame-ancestors 'self'" in response.headers["Content-Security-Policy"]


def _csp_directive(policy: str, name: str) -> str:
    """Return the value of a single CSP directive (e.g. ``script-src``)."""
    for part in policy.split(";"):
        part = part.strip()
        if part.startswith(name + " "):
            return part
    return ""


def test_csp_allows_meta_embedded_signup_sdk_exactly(client):
    """The CSP must permit Meta's JS SDK (WhatsApp Embedded Signup) and nothing
    broader, while the rest of the policy stays intact ('self', frame-ancestors
    none). Regression guard for the SDK being blocked by 'self'-only directives."""
    policy = client.get("/login").headers["Content-Security-Policy"]

    # script-src now allows the Facebook SDK origin (kept 'self' + 'unsafe-inline').
    script_src = _csp_directive(policy, "script-src")
    assert "https://connect.facebook.net" in script_src
    assert "'self'" in script_src
    assert "'unsafe-inline'" in script_src

    # connect-src: SDK load + FB.init/FB.login XHR to graph/www.facebook.
    connect_src = _csp_directive(policy, "connect-src")
    assert "'self'" in connect_src
    assert "https://graph.facebook.com" in connect_src
    assert "https://www.facebook.com" in connect_src
    assert "https://connect.facebook.net" in connect_src

    # frame-src: the SDK's hidden facebook.com iframe + the signup dialog.
    frame_src = _csp_directive(policy, "frame-src")
    assert "https://www.facebook.com" in frame_src
    assert "https://web.facebook.com" in frame_src
    assert "https://staticxx.facebook.com" in frame_src
    assert "https://connect.facebook.net" in frame_src

    # img-src keeps data: and adds only the fbcdn images + www.facebook.
    img_src = _csp_directive(policy, "img-src")
    assert "'self'" in img_src
    assert "data:" in img_src
    assert "https://*.fbcdn.net" in img_src

    # Nothing else weakened: base policy + clickjacking protections intact.
    assert "default-src 'self'" in policy
    assert "frame-ancestors 'self'" in policy
    # No broad wildcards crept in (only the scoped fbcdn image wildcard is allowed).
    assert "*.facebook.com" not in policy
    assert " https://*" not in policy.replace("https://*.fbcdn.net", "")


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
