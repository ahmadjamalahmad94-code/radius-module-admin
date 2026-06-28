"""Simple-link bearer auth — panel side (docs/SIMPLE_LINK_CONTRACT.md).

After the legacy-linking-auth removal (branch
``feat/remove-legacy-linking-auth``), bearer is the ONLY path:

* the license key in the request body authenticates the bridge over HTTPS;
* the fingerprint is purely informational (no 422, no slot-deny);
* backups accept the license key as the secret (and no secret at all);
* the customer-status 403 still carries a machine-readable ``reason``;
* the admin «ربط الريدياس» card renders the live key + regenerate;
* license keys are masked in audit summaries.

Tests for the retired signed-HMAC / activation-code / bridge-token paths
were deleted with the code they covered.
"""
from __future__ import annotations

import uuid
from datetime import timedelta

from app import create_app, seed_defaults
from app.config import TestingConfig
from app.extensions import db
from app.license_signing import mask_license_key
from app.models import AuditLog, Customer, License, Plan, utcnow
from app.services.license_service import generate_license_key


# ─────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────

def _mk_license(customer_status: str = "active") -> License:
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


def _bearer_app(**overrides):
    """Fresh app — bearer-only is the only posture now."""
    app = create_app(TestingConfig, **overrides)
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
    masked = mask_license_key("PLAINSECRETKEY")
    assert "PLAINSECRETKEY" not in masked


# ─────────────────────────────────────────────────────────────────────────
# Bearer mode
# ─────────────────────────────────────────────────────────────────────────

def test_bearer_body_key_authenticates():
    app = _bearer_app()
    with app.app_context():
        lic = _mk_license()
        client = app.test_client()
        res = client.post("/api/license/check", json={"license_key": lic.license_key})
        assert res.status_code == 200
        body = res.get_json()
        assert body["active"] is True
        assert body["status"] == "active"


def test_bearer_unknown_key_is_404_or_401():
    app = _bearer_app()
    with app.app_context():
        client = app.test_client()
        res = client.post("/api/license/check", json={"license_key": "HBR-2026-ZZZZ-ZZZZ-ZZZZ"})
        # not_found result body comes back as 200 with active=False in this
        # endpoint's contract; auth-layer 401 is the integration variant.
        # Either is acceptable — the key never grants access.
        assert res.status_code in (200, 401)
        if res.status_code == 200:
            assert res.get_json()["active"] is False


def test_bearer_exact_client_shape_body_plus_authorization_header():
    """The radius-module client sends BOTH the body license_key AND an
    ``Authorization: Bearer <key>`` header (contract §4). The body is
    authoritative; the header must never break anything."""
    app = _bearer_app()
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


def test_bearer_runtime_contract_over_https():
    app = _bearer_app()
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
    app = _bearer_app()
    with app.app_context():
        lic = _mk_license()
        client = app.test_client()
        res = client.post(
            "/api/integration/hoberadius/runtime-contract",
            json={"license_key": lic.license_key},
        )
        assert res.status_code == 426  # bearer never weakens the HTTPS rule


# ─────────────────────────────────────────────────────────────────────────
# Fingerprint is optional + informational
# ─────────────────────────────────────────────────────────────────────────

def test_missing_fingerprint_is_not_422_on_license_check():
    app = _bearer_app()
    with app.app_context():
        lic = _mk_license()
        client = app.test_client()
        res = client.post("/api/license/check", json={"license_key": lic.license_key})
        assert res.status_code == 200


def test_missing_fingerprint_is_not_422_on_integration():
    app = _bearer_app()
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


def test_fingerprint_recorded_when_sent_never_denies():
    app = _bearer_app()
    with app.app_context():
        lic = _mk_license()
        client = app.test_client()
        for fp in ["vps-prod-1", "vps-prod-2", "vps-prod-3", "vps-prod-4", "vps-prod-5"]:
            res = client.post("/api/license/check", json={
                "license_key": lic.license_key,
                "server_fingerprint": fp,
            })
            assert res.status_code == 200
            assert res.get_json()["active"] is True  # never denies on fp overflow
        db.session.refresh(lic)
        # The newest fingerprint must always be retained — the slot rotation
        # never blocks the latest device.
        assert "vps-prod-5" in lic.fingerprints


# ─────────────────────────────────────────────────────────────────────────
# Customer-status 403 carries the machine-readable reason
# ─────────────────────────────────────────────────────────────────────────

def test_customer_pending_403_has_reason():
    app = _bearer_app()
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
    app = _bearer_app()
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
# Backups — the license key is the only secret
# ─────────────────────────────────────────────────────────────────────────

def _backup_payload(lic: License, **extra) -> dict:
    return {
        "license_key": lic.license_key,
        "backup_reference": f"bk-{uuid.uuid4().hex[:8]}",
        **extra,
    }


def test_backup_accepts_license_key_as_secret():
    app = _bearer_app()
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
    app = _bearer_app()
    with app.app_context():
        lic = _mk_license()
        client = app.test_client()
        res = client.post(
            "/api/integration/hoberadius/backups/upload",
            json=_backup_payload(lic),
            **HTTPS,
        )
        assert res.status_code == 201, res.get_json()


def test_backup_unknown_key_404s():
    app = _bearer_app()
    with app.app_context():
        client = app.test_client()
        res = client.post(
            "/api/integration/hoberadius/backups/upload",
            json={"license_key": "HBR-2026-NONE-NONE-NONE", "backup_reference": "bk-x"},
            **HTTPS,
        )
        assert res.status_code == 404


def _make_sqlite_backup_bytes() -> bytes:
    """A tiny but real SQLite file, like an instance's local backup."""
    import sqlite3
    import tempfile
    import os as _os
    from pathlib import Path as _Path

    path = tempfile.mktemp(suffix=".sqlite3")
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE subscribers(id INTEGER PRIMARY KEY)")
    con.execute("INSERT INTO subscribers VALUES (1)")
    con.commit()
    con.close()
    try:
        return _Path(path).read_bytes()
    finally:
        _os.unlink(path)


def test_backup_stores_uploaded_content_and_downloads_back():
    """The real 'upload a backup file' path: content_base64 is decoded, the
    checksum is verified, the file is stored on disk, and the admin download
    route returns the exact bytes back."""
    import base64
    import hashlib

    app = _bearer_app()
    with app.app_context():
        lic = _mk_license()
        raw = _make_sqlite_backup_bytes()
        checksum = hashlib.sha256(raw).hexdigest()
        client = app.test_client()
        res = client.post(
            "/api/integration/hoberadius/backups/upload",
            json=_backup_payload(
                lic,
                content_base64=base64.b64encode(raw).decode(),
                checksum_sha256=checksum,
                size=len(raw),
                upload_mode="full",
            ),
            **HTTPS,
        )
        assert res.status_code == 201, res.get_json()
        body = res.get_json()
        assert body["stored"] is True
        assert body["status"] == "stored"
        assert body["size"] == len(raw)

        # The stored file round-trips byte-for-byte via the admin download route.
        from app.services.customer_backups import get_artifact_file

        resolved = get_artifact_file(lic.customer_id, body["artifact_id"])
        assert resolved is not None
        path, _name = resolved
        assert path.read_bytes() == raw


def test_backup_rejects_checksum_mismatch():
    """A corrupted upload (checksum ≠ content) is refused with 422 and never
    stored — protects against silently persisting a damaged backup."""
    import base64

    app = _bearer_app()
    with app.app_context():
        lic = _mk_license()
        raw = _make_sqlite_backup_bytes()
        client = app.test_client()
        res = client.post(
            "/api/integration/hoberadius/backups/upload",
            json=_backup_payload(
                lic,
                content_base64=base64.b64encode(raw).decode(),
                checksum_sha256="0" * 64,  # deliberately wrong
                size=len(raw),
                upload_mode="full",
            ),
            **HTTPS,
        )
        assert res.status_code == 422, res.get_json()
        assert res.get_json()["status"] == "checksum_mismatch"


# ─────────────────────────────────────────────────────────────────────────
# Admin card + regenerate (uses shared fixtures from conftest.py)
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
    assert key in html
    assert "إعادة توليد المفتاح" in html
    assert "الأجهزة المرصودة" in html
    # Legacy «سر التوقيع» / activation-token / bridge-token UI must NOT appear.
    assert "سر التوقيع" not in html
    assert "كود التفعيل" not in html
    assert "rotate-bridge" not in html


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


# ─────────────────────────────────────────────────────────────────────────
# Legacy endpoints are gone
# ─────────────────────────────────────────────────────────────────────────

def test_legacy_activate_endpoint_is_404():
    app = _bearer_app()
    with app.app_context():
        client = app.test_client()
        res = client.post(
            "/api/integration/hoberadius/instance/activate",
            json={"activation_code": "X", "server_fingerprint": "fp"},
            **HTTPS,
        )
        assert res.status_code == 404


def test_legacy_activation_token_admin_endpoint_is_404(app, client):
    with app.app_context():
        lic = _mk_license()
        customer_id = lic.customer_id
    _login(client)
    res = client.post(f"/admin/customers/{customer_id}/activation-token/generate")
    assert res.status_code == 404


def test_legacy_bridge_token_admin_endpoint_is_404(app, client):
    with app.app_context():
        lic = _mk_license()
        customer_id = lic.customer_id
    _login(client)
    res = client.post(f"/admin/customers/{customer_id}/bridge-token/rotate")
    assert res.status_code == 404
