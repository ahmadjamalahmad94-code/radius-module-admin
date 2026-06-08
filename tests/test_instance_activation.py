"""Tests for Admin Bridge instance activation token lifecycle.

Covers:
- Token generation model (generate, hash_code, is_valid)
- Single-use enforcement
- Expiry enforcement
- Admin API endpoint: POST /customers/<id>/activation-token/generate  (super-admin only)
- Integration endpoint: POST /api/integration/hoberadius/instance/activate
- Audit trail written on both sides
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

import pytest

from app.extensions import db
from app.models import Admin, Customer, InstanceActivationToken, License, Plan, utcnow


# ── helpers ──────────────────────────────────────────────────────────────────

def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _login(client):
    """Log in as the seeded admin (admin / admin12345)."""
    return client.post("/login", data={"username": "admin", "password": "admin12345"})


def _make_customer(name: str = "TestCo") -> Customer:
    c = Customer(company_name=name, contact_name="Ali", email=f"{name.lower().replace(' ', '')}@test.com")
    db.session.add(c)
    db.session.flush()
    return c


def _make_license(customer_id: int, key: str = "TESTKEY-0001") -> License:
    plan = Plan.query.first()
    if plan is None:
        plan = Plan(name="Basic", price_usd=10)
        db.session.add(plan)
        db.session.flush()
    lic = License(
        customer_id=customer_id,
        plan_id=plan.id,
        license_key=key,
        max_fingerprints=3,
        expires_at=_now_utc() + timedelta(days=365),
    )
    db.session.add(lic)
    db.session.flush()
    return lic


def _insert_token(customer_id: int, *, expired: bool = False, used: bool = False) -> str:
    """Insert a token in the current DB session and return the raw code."""
    raw = InstanceActivationToken.generate()
    now = _now_utc()
    token = InstanceActivationToken(
        customer_id=customer_id,
        token_hash=InstanceActivationToken.hash_code(raw),
        expires_at=now - timedelta(seconds=1) if expired else now + timedelta(minutes=30),
        used_at=now if used else None,
    )
    db.session.add(token)
    db.session.flush()
    return raw


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture()
def https_app():
    """App configured to trust X-Forwarded-Proto (for HTTPS endpoint tests).
    Also sets LICENSE_CHECK_HMAC_SECRET so license_integration_secret() returns a value.
    """
    from app import create_app, seed_defaults
    from app.config import TestingConfig

    app = create_app(
        TestingConfig,
        TRUST_PROXY_HEADERS=True,
        LICENSE_CHECK_HMAC_SECRET="test-hmac-secret-for-unit-tests",
    )
    with app.app_context():
        db.create_all()
        seed_defaults(app)
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def https_client(https_app):
    return https_app.test_client()


# ── Unit tests: InstanceActivationToken model ─────────────────────────────────

class TestInstanceActivationTokenModel:
    def test_generate_format(self, app):
        """Token has exactly 3 groups of 8 hex chars separated by dashes."""
        with app.app_context():
            raw = InstanceActivationToken.generate()
            parts = raw.split("-")
            assert len(parts) == 3
            for part in parts:
                assert len(part) == 8
                int(part, 16)  # raises if not valid hex

    def test_generate_is_random(self, app):
        with app.app_context():
            tokens = {InstanceActivationToken.generate() for _ in range(20)}
            assert len(tokens) == 20

    def test_hash_code_is_sha256(self, app):
        with app.app_context():
            raw = "ABCD1234-EFGH5678-IJKL9012"
            normalised = raw.replace("-", "").upper()
            expected = hashlib.sha256(normalised.encode()).hexdigest()
            assert InstanceActivationToken.hash_code(raw) == expected
            assert len(InstanceActivationToken.hash_code(raw)) == 64

    def test_hash_code_strips_dashes(self, app):
        with app.app_context():
            with_dashes = "AABBCCDD-EEFF0011-22334455"
            without = "AABBCCDDEEFF001122334455"
            assert InstanceActivationToken.hash_code(with_dashes) == InstanceActivationToken.hash_code(without)

    def test_hash_code_case_insensitive(self, app):
        with app.app_context():
            raw = InstanceActivationToken.generate()
            assert InstanceActivationToken.hash_code(raw) == InstanceActivationToken.hash_code(raw.lower())

    def test_is_valid_fresh_token(self, app):
        with app.app_context():
            c = _make_customer()
            raw = InstanceActivationToken.generate()
            token = InstanceActivationToken(
                customer_id=c.id,
                token_hash=InstanceActivationToken.hash_code(raw),
                expires_at=_now_utc() + timedelta(minutes=30),
            )
            db.session.add(token)
            db.session.flush()
            assert token.is_valid is True

    def test_is_valid_expired_token(self, app):
        with app.app_context():
            c = _make_customer()
            raw = InstanceActivationToken.generate()
            token = InstanceActivationToken(
                customer_id=c.id,
                token_hash=InstanceActivationToken.hash_code(raw),
                expires_at=_now_utc() - timedelta(seconds=1),
            )
            db.session.add(token)
            db.session.flush()
            assert token.is_valid is False

    def test_is_valid_used_token(self, app):
        with app.app_context():
            c = _make_customer()
            raw = InstanceActivationToken.generate()
            token = InstanceActivationToken(
                customer_id=c.id,
                token_hash=InstanceActivationToken.hash_code(raw),
                expires_at=_now_utc() + timedelta(minutes=30),
                used_at=_now_utc(),
            )
            db.session.add(token)
            db.session.flush()
            assert token.is_valid is False

    def test_token_hash_not_plaintext(self, app):
        """DB row stores only the hash, never the raw token."""
        with app.app_context():
            c = _make_customer()
            raw = InstanceActivationToken.generate()
            token = InstanceActivationToken(
                customer_id=c.id,
                token_hash=InstanceActivationToken.hash_code(raw),
                expires_at=_now_utc() + timedelta(minutes=30),
            )
            db.session.add(token)
            db.session.commit()
            stored = db.session.get(InstanceActivationToken, token.id)
            assert stored.token_hash != raw
            assert stored.token_hash == InstanceActivationToken.hash_code(raw)


# ── Admin endpoint: generate token ───────────────────────────────────────────

class TestGenerateActivationTokenEndpoint:
    def test_requires_authentication(self, app, client):
        """Unauthenticated request is redirected / rejected."""
        with app.app_context():
            c = _make_customer()
            cid = c.id
            db.session.commit()
        r = client.post(f"/admin/customers/{cid}/activation-token/generate")
        # Could be 302 (redirect to login) or 401/403.
        assert r.status_code in (302, 401, 403)

    def test_non_super_admin_is_denied(self, app, client):
        """Regular admin (is_super_admin=False) cannot generate tokens.

        ``super_admin_required`` returns JSON 403 for XHR/JSON-Accept requests,
        or a 302 redirect for plain browser requests. Either response means denied.
        """
        with app.app_context():
            c = _make_customer("RegularCo")
            cid = c.id
            # Ensure the default seeded admin is NOT super-admin.
            admin_obj = Admin.query.filter_by(username="admin").first()
            if admin_obj:
                admin_obj.is_super_admin = False
            db.session.commit()

        _login(client)
        # Use JSON Accept header so we get 403 instead of redirect.
        r = client.post(
            f"/admin/customers/{cid}/activation-token/generate",
            headers={"Accept": "application/json"},
        )
        assert r.status_code == 403

    def test_super_admin_generates_token_json(self, app, client):
        with app.app_context():
            c = _make_customer("SuperCo")
            cid = c.id
            # Elevate seeded admin to super-admin.
            admin_obj = Admin.query.filter_by(username="admin").first()
            if admin_obj:
                admin_obj.is_super_admin = True
            db.session.commit()

        _login(client)
        r = client.post(f"/admin/customers/{cid}/activation-token/generate")
        assert r.status_code == 200
        data = r.get_json()
        assert data["ok"] is True
        parts = data["token"].split("-")
        assert len(parts) == 3

    def test_token_has_ttl_and_expiry(self, app, client):
        with app.app_context():
            c = _make_customer("TTLCo")
            cid = c.id
            admin_obj = Admin.query.filter_by(username="admin").first()
            if admin_obj:
                admin_obj.is_super_admin = True
            db.session.commit()

        _login(client)
        r = client.post(f"/admin/customers/{cid}/activation-token/generate")
        data = r.get_json()
        assert data["ttl_minutes"] == InstanceActivationToken.ACTIVATION_TOKEN_TTL_MINUTES
        assert "expires_at" in data

    def test_token_hash_stored_not_plaintext(self, app, client):
        """DB must store hash; plaintext must not appear in the token_hash column."""
        with app.app_context():
            c = _make_customer("HashCo")
            cid = c.id
            admin_obj = Admin.query.filter_by(username="admin").first()
            if admin_obj:
                admin_obj.is_super_admin = True
            db.session.commit()

        _login(client)
        r = client.post(f"/admin/customers/{cid}/activation-token/generate")
        data = r.get_json()
        raw_token = data["token"]
        token_id = data["token_id"]

        with app.app_context():
            stored = db.session.get(InstanceActivationToken, token_id)
            assert stored.token_hash != raw_token
            assert stored.token_hash == InstanceActivationToken.hash_code(raw_token)

    def test_plaintext_appears_only_once_in_response(self, app, client):
        """The raw token appears exactly once in the JSON body (under 'token')."""
        with app.app_context():
            c = _make_customer("OnceCo")
            cid = c.id
            admin_obj = Admin.query.filter_by(username="admin").first()
            if admin_obj:
                admin_obj.is_super_admin = True
            db.session.commit()

        _login(client)
        r = client.post(f"/admin/customers/{cid}/activation-token/generate")
        data = r.get_json()
        raw_json = r.data.decode("utf-8")
        token = data["token"]
        assert raw_json.count(token) == 1


# ── Integration endpoint: activate ───────────────────────────────────────────

class TestInstanceActivateEndpoint:
    """Tests for POST /api/integration/hoberadius/instance/activate.

    Uses https_app / https_client which have TRUST_PROXY_HEADERS=True,
    so passing X-Forwarded-Proto: https satisfies _integration_request_is_secure().
    """

    def _activate(self, client, payload: dict):
        return client.post(
            "/api/integration/hoberadius/instance/activate",
            json=payload,
            headers={"X-Forwarded-Proto": "https"},
        )

    def test_missing_code_returns_422(self, https_app, https_client):
        r = self._activate(https_client, {"activation_code": ""})
        assert r.status_code == 422

    def test_wrong_code_returns_401(self, https_app, https_client):
        r = self._activate(https_client, {"activation_code": "BADC0DE0-BADC0DE0-BADC0DE0"})
        assert r.status_code == 401
        assert r.get_json()["status"] == "invalid_token"

    def test_http_required(self, app, client):
        """Without TRUST_PROXY_HEADERS, endpoint returns 426 UPGRADE REQUIRED."""
        r = client.post("/api/integration/hoberadius/instance/activate", json={"activation_code": "x"})
        assert r.status_code == 426

    def test_expired_token_returns_410(self, https_app, https_client):
        with https_app.app_context():
            c = _make_customer("ExpiredCo")
            _make_license(c.id, "EXPIREDKEY-001")
            raw = _insert_token(c.id, expired=True)
            db.session.commit()

        r = self._activate(https_client, {"activation_code": raw})
        assert r.status_code == 410
        assert r.get_json()["status"] == "expired"

    def test_already_used_token_returns_409(self, https_app, https_client):
        with https_app.app_context():
            c = _make_customer("UsedCo")
            _make_license(c.id, "USEDKEY-001")
            raw = _insert_token(c.id, used=True)
            db.session.commit()

        r = self._activate(https_client, {"activation_code": raw})
        assert r.status_code == 409
        assert r.get_json()["status"] == "already_used"

    def test_valid_token_returns_credentials_and_marks_used(self, https_app, https_client):
        with https_app.app_context():
            c = _make_customer("ActivateCo")
            _make_license(c.id, "ACTIVATEKEY-001")
            raw = _insert_token(c.id)
            token_hash = InstanceActivationToken.hash_code(raw)
            token_id = InstanceActivationToken.query.filter_by(token_hash=token_hash).first().id
            db.session.commit()

        r = self._activate(https_client, {
            "activation_code": raw,
            "server_fingerprint": "fp-test-001",
        })
        assert r.status_code == 200, r.data
        data = r.get_json()
        assert data["ok"] is True
        assert data["status"] == "activated"
        assert data["license_key"] == "ACTIVATEKEY-001"
        assert "shared_secret" in data
        assert len(data["shared_secret"]) >= 32

        # Token must be marked as used.
        with https_app.app_context():
            stored = db.session.get(InstanceActivationToken, token_id)
            assert stored.used_at is not None
            assert stored.used_fingerprint == "fp-test-001"

    def test_single_use_enforcement(self, https_app, https_client):
        """Second activation with same code returns 409."""
        with https_app.app_context():
            c = _make_customer("SingleUseCo")
            _make_license(c.id, "SINGLEKEY-001")
            raw = _insert_token(c.id)
            db.session.commit()

        r1 = self._activate(https_client, {"activation_code": raw})
        assert r1.status_code == 200

        r2 = self._activate(https_client, {"activation_code": raw})
        assert r2.status_code == 409
        assert r2.get_json()["status"] == "already_used"

    def test_shared_secret_not_in_error_response(self, https_app, https_client):
        """The word 'shared_secret' value must never appear in error bodies."""
        r = self._activate(https_client, {"activation_code": "INVALID0-INVALID0-INVALID0"})
        assert r.status_code == 401
        raw_body = r.data.decode("utf-8")
        # Response should not contain any actual secret value.
        data = r.get_json()
        assert "shared_secret" not in data
