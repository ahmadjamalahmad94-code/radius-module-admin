"""Simple-link bearer auth — panel side (docs/SIMPLE_LINK_CONTRACT.md).

Covers the full server contract:
* the license key in the BODY authenticates by itself (bearer) — even in the
  strict signature-required posture;
* old SIGNED requests keep working unchanged;
* the fingerprint is optional (no more 422);
* backups accept the license key as the secret (and no secret at all in
  bearer mode);
* the customer-status 403 carries a machine-readable ``reason``;
* the admin «ربط الريدياس» card renders and regenerate works;
* license keys are masked in audit summaries.
"""
from __future__ import annotations

import time
import uuid
from datetime import timedelta

import pytest

from app import create_app, seed_defaults
from app.config import TestingConfig
from app.extensions import db
from app.license_signing import (
    license_integration_secret,
    mask_license_key,
    sign_license_payload,
)
from app.models import AuditLog, Customer, License, Plan, utcnow
from app.services.license_service import generate_license_key


# ─────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────

def _mk_license(customer_status: str = "active") -> License:
    """Create a customer + active license inside the current app context."""
    customer = Customer(company_name=f"SimpleLink {uuid.uuid4().hex[:6]}", status=customer_status)
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


def _strict_app(**overrides):
    """An app in the production posture: signatures REQUIRED, unsigned refused."""
    app = create_app(
        TestingConfig,
        LICENSE_CHECK_SIGNATURE_REQUIRED=True,
        LICENSE_CHECK_ALLOW_UNSIGNED=False,
        **overrides,
    )
    with app.app_context():
        db.create_all()
        seed_defaults(app)
    return app


HTTPS = {"base_url": "https://license-panel.test"}


# ─────────────────────────────────────────────────────────────────────────
# mask helper
# ─────────────────────────────────────────────────────────────────────────

def test_mask_license_key_shapes():
    assert mask_license_key("HBR-2026-AAAA-BBBB-CCCC") == "HBR-…-CCCC"
    assert mask_license_key("hbr-2026-aaaa-bbbb-cccc") == "HBR-…-CCCC"
    assert mask_license_key("") == ""
    # No dashes → generic masking, never the full value.
    masked = mask_license_key("PLAINSECRETKEY")
    assert "PLAINSECRETKEY" not in masked


# ─────────────────────────────────────────────────────────────────────────
# Bearer mode — strict posture
# ─────────────────────────────────────────────────────────────────────────

def test_bearer_body_key_authenticates_in_strict_mode():
    app = _strict_app()
    with app.app_context():
        lic = _mk_license()
        client = app.test_client()
        res = client.post("/api/license/check", json={"license_key": lic.license_key})
        assert res.status_code == 200
        body = res.get_json()
        assert body["active"] is True
        assert body["status"] == "active"


def test_bearer_unknown_key_is_401_in_strict_mode():
    app = _strict_app()
    with app.app_context():
        client = app.test_client()
        res = client.post("/api/license/check", json={"license_key": "HBR-2026-ZZZZ-ZZZZ-ZZZZ"})
        assert res.status_code == 401


def test_bearer_disabled_flag_restores_old_behaviour():
    app = _strict_app(LICENSE_BEARER_AUTH_ENABLED=False)
    with app.app_context():
        lic = _mk_license()
        client = app.test_client()
        res = client.post("/api/license/check", json={"license_key": lic.license_key})
        assert res.status_code == 401  # valid key alone no longer enough


def test_bearer_exact_client_shape_body_plus_authorization_header():
    """The radius-module client sends BOTH the body license_key AND an
    ``Authorization: Bearer <key>`` header (contract §4). The body is
    authoritative; the header must never break anything — the server accepts
    exactly this shape."""
    app = _strict_app()
    with app.app_context():
        lic = _mk_license()
        client = app.test_client()
        res = client.post(
            "/api/integration/hoberadius/runtime-contract",
            json={"license_key": lic.license_key, "server_fingerprint": "fp-client", "hostname": "radius-vps-1"},
            headers={"Authorization": f"Bearer {lic.license_key}"},
            **HTTPS,
        )
        assert res.status_code == 200
        assert res.get_json()["ok"] is True

        # Header alone (stripped body) does NOT authenticate — the body is
        # authoritative per the header-strip lesson; missing key is 422.
        res_hdr_only = client.post(
            "/api/integration/hoberadius/runtime-contract",
            json={"server_fingerprint": "fp-client"},
            headers={"Authorization": f"Bearer {lic.license_key}"},
            **HTTPS,
        )
        assert res_hdr_only.status_code in (401, 422)


def test_bearer_runtime_contract_over_https():
    app = _strict_app()
    with app.app_context():
        lic = _mk_license()
        client = app.test_client()
        res = client.post(
            "/api/integration/hoberadius/runtime-contract",
            json={"license_key": lic.license_key},
            **HTTPS,
        )
        assert res.status_code == 200
        body = res.get_json()
        assert body["ok"] is True
        assert body["contract"]["license"]["license_key"] == lic.license_key


def test_bearer_runtime_contract_still_426_on_plain_http():
    app = _strict_app()
    with app.app_context():
        lic = _mk_license()
        client = app.test_client()
        res = client.post(
            "/api/integration/hoberadius/runtime-contract",
            json={"license_key": lic.license_key},
        )
        assert res.status_code == 426  # bearer never weakens the HTTPS rule


# ─────────────────────────────────────────────────────────────────────────
# Old signed mode still works (back-compat)
# ─────────────────────────────────────────────────────────────────────────

def test_signed_mode_still_works_in_strict_posture():
    app = _strict_app(LICENSE_CHECK_HMAC_SECRET="root-secret-for-tests")
    with app.app_context():
        lic = _mk_license()
        client = app.test_client()
        body = {
            "license_key": lic.license_key,
            "server_fingerprint": "fp-signed-client",
            "timestamp": int(time.time()),
            "nonce": uuid.uuid4().hex,
        }
        body["signature"] = sign_license_payload(body, "root-secret-for-tests")
        res = client.post("/api/license/check", json=body)
        assert res.status_code == 200
        assert res.get_json()["active"] is True


def test_signed_with_per_license_secret_still_works():
    app = _strict_app(LICENSE_CHECK_HMAC_SECRET="root-secret-for-tests")
    with app.app_context():
        lic = _mk_license()
        per_license = license_integration_secret(app, lic.license_key)
        assert per_license
        client = app.test_client()
        body = {
            "license_key": lic.license_key,
            "server_fingerprint": "fp-derived-client",
            "timestamp": int(time.time()),
            "nonce": uuid.uuid4().hex,
        }
        body["signature"] = sign_license_payload(body, per_license)
        res = client.post("/api/license/check", json=body)
        assert res.status_code == 200
        assert res.get_json()["active"] is True


def test_bad_signature_still_rejected():
    app = _strict_app(LICENSE_CHECK_HMAC_SECRET="root-secret-for-tests")
    with app.app_context():
        lic = _mk_license()
        client = app.test_client()
        body = {
            "license_key": lic.license_key,
            "timestamp": int(time.time()),
            "nonce": uuid.uuid4().hex,
            "signature": "deadbeef" * 8,
        }
        res = client.post("/api/license/check", json=body)
        assert res.status_code == 401


# ─────────────────────────────────────────────────────────────────────────
# Fingerprint is optional
# ─────────────────────────────────────────────────────────────────────────

def test_missing_fingerprint_is_not_422_on_license_check():
    app = _strict_app()
    with app.app_context():
        lic = _mk_license()
        client = app.test_client()
        res = client.post("/api/license/check", json={"license_key": lic.license_key})
        assert res.status_code == 200  # was 422 before simple-link


def test_missing_fingerprint_is_not_422_on_integration():
    app = _strict_app()
    with app.app_context():
        lic = _mk_license()
        client = app.test_client()
        res = client.post(
            "/api/integration/hoberadius/capacity-contract",
            json={"license_key": lic.license_key},
            **HTTPS,
        )
        assert res.status_code == 200
        assert res.get_json()["ok"] is True


def test_fingerprint_still_recorded_when_sent():
    app = _strict_app()
    with app.app_context():
        lic = _mk_license()
        client = app.test_client()
        res = client.post("/api/license/check", json={
            "license_key": lic.license_key,
            "server_fingerprint": "vps-prod-1",
        })
        assert res.status_code == 200
        db.session.refresh(lic)
        assert "vps-prod-1" in lic.fingerprints


# ─────────────────────────────────────────────────────────────────────────
# Customer-status 403 carries the machine-readable reason
# ─────────────────────────────────────────────────────────────────────────

def test_customer_pending_403_has_reason():
    app = _strict_app()
    with app.app_context():
        lic = _mk_license(customer_status="pending")
        client = app.test_client()
        res = client.post(
            "/api/integration/hoberadius/runtime-contract",
            json={"license_key": lic.license_key},
            **HTTPS,
        )
        assert res.status_code == 403
        body = res.get_json()
        assert body["reason"] == "customer_pending"
        assert body["status"] == "customer_pending"
        assert body["customer_status"] == "pending"


def test_customer_blocked_403_has_reason():
    app = _strict_app()
    with app.app_context():
        lic = _mk_license(customer_status="blocked")
        client = app.test_client()
        res = client.post(
            "/api/integration/hoberadius/runtime-contract",
            json={"license_key": lic.license_key},
            **HTTPS,
        )
        assert res.status_code == 403
        assert res.get_json()["reason"] == "customer_blocked"


# ─────────────────────────────────────────────────────────────────────────
# Backups — the license key is the secret
# ─────────────────────────────────────────────────────────────────────────

def _backup_payload(lic: License, **extra) -> dict:
    return {
        "license_key": lic.license_key,
        "backup_reference": f"bk-{uuid.uuid4().hex[:8]}",
        **extra,
    }


def test_backup_accepts_license_key_as_secret():
    app = _strict_app()
    with app.app_context():
        lic = _mk_license()
        client = app.test_client()
        res = client.post(
            "/api/integration/hoberadius/backups/upload",
            json=_backup_payload(lic, admin_secret=lic.license_key),
            **HTTPS,
        )
        assert res.status_code == 201, res.get_json()


def test_backup_accepts_no_secret_in_bearer_mode():
    app = _strict_app()
    with app.app_context():
        lic = _mk_license()
        client = app.test_client()
        res = client.post(
            "/api/integration/hoberadius/backups/upload",
            json=_backup_payload(lic),
            **HTTPS,
        )
        assert res.status_code == 201, res.get_json()


def test_backup_legacy_derived_secret_still_works():
    app = _strict_app(LICENSE_CHECK_HMAC_SECRET="root-secret-for-tests")
    with app.app_context():
        lic = _mk_license()
        secret = license_integration_secret(app, lic.license_key)
        client = app.test_client()
        res = client.post(
            "/api/integration/hoberadius/backups/upload",
            json=_backup_payload(lic, admin_secret=secret),
            **HTTPS,
        )
        assert res.status_code == 201, res.get_json()


def test_backup_rejected_when_bearer_off_and_no_secret():
    app = _strict_app(LICENSE_BEARER_AUTH_ENABLED=False,
                      LICENSE_CHECK_HMAC_SECRET="root-secret-for-tests")
    with app.app_context():
        lic = _mk_license()
        client = app.test_client()
        res = client.post(
            "/api/integration/hoberadius/backups/upload",
            json=_backup_payload(lic),
            **HTTPS,
        )
        assert res.status_code == 401


def test_backup_unknown_key_404s_even_in_bearer_mode():
    app = _strict_app()
    with app.app_context():
        client = app.test_client()
        res = client.post(
            "/api/integration/hoberadius/backups/upload",
            json={"license_key": "HBR-2026-NONE-NONE-NONE", "backup_reference": "bk-x"},
            **HTTPS,
        )
        assert res.status_code == 404


# ─────────────────────────────────────────────────────────────────────────
# Admin card + regenerate
# ─────────────────────────────────────────────────────────────────────────

def _login(client):
    return client.post("/login", data={"username": "admin", "password": "admin12345"})


def test_customer_page_shows_linking_card(app, client):
    with app.app_context():
        lic = _mk_license()
        customer_id = lic.customer_id
        key = lic.license_key
    _login(client)
    res = client.get(f"/admin/customers/{customer_id}")
    assert res.status_code == 200
    html = res.data.decode("utf-8")
    assert "ربط الريدياس" in html
    # Primary admin is super → sees the full key + the regenerate button.
    assert key in html
    assert "إعادة توليد المفتاح" in html
    assert "الأجهزة المرصودة" in html


def test_regenerate_license_key_route(app, client):
    with app.app_context():
        lic = _mk_license()
        customer_id = lic.customer_id
        lic_id = lic.id
        old_key = lic.license_key
    _login(client)
    res = client.post(f"/admin/customers/{customer_id}/license/regenerate-key")
    assert res.status_code == 302
    with app.app_context():
        lic = db.session.get(License, lic_id)
        assert lic.license_key != old_key
        assert lic.license_key.startswith("HBR-")
        row = (
            AuditLog.query
            .filter_by(action="license_key_regenerated", entity_id=str(lic_id))
            .order_by(AuditLog.id.desc())
            .first()
        )
        assert row is not None
        # Masked in audit — never the full old or new key.
        assert old_key not in (row.summary or "")
        assert lic.license_key not in (row.summary or "")


def test_regenerated_key_immediately_authenticates_bearer(app):
    with app.app_context():
        lic = _mk_license()
        lic_id = lic.id
    client = app.test_client()
    _login(client)
    with app.app_context():
        customer_id = db.session.get(License, lic_id).customer_id
    client.post(f"/admin/customers/{customer_id}/license/regenerate-key")
    with app.app_context():
        new_key = db.session.get(License, lic_id).license_key
    res = client.post("/api/license/check", json={"license_key": new_key})
    assert res.status_code == 200
    assert res.get_json()["active"] is True


# ─────────────────────────────────────────────────────────────────────────
# Audit summaries are masked
# ─────────────────────────────────────────────────────────────────────────

def test_license_status_audit_masks_key(app):
    from app.services.license_service import set_license_status
    with app.app_context():
        lic = _mk_license()
        full_key = lic.license_key
        set_license_status(lic, "suspended", actor_admin_id=None)
        row = AuditLog.query.filter_by(action="license_suspended").order_by(AuditLog.id.desc()).first()
        assert row is not None
        assert full_key not in (row.summary or "")
        assert mask_license_key(full_key) in (row.summary or "")
