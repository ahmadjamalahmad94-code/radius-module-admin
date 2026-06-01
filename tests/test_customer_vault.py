"""Security + behavior tests for the Customer Secure Vault."""
from __future__ import annotations

import pytest
from sqlalchemy import inspect

from app.extensions import db
from app.models import (
    Admin,
    Customer,
    CustomerPrivateRecord,
    CustomerSecret,
    CustomerVaultAuditLog,
)
from app.services import customer_vault as vault
from app.services import customer_vault_crypto as crypto

PLAINTEXT = "S3cr3t-Pa55!-Ωμέγα-اختبار"


def _customer(name="TestCo") -> int:
    c = Customer(company_name=name)
    db.session.add(c)
    db.session.commit()
    return c.id


def _super_admin_id() -> int:
    return Admin.query.filter_by(username="admin").first().id


def _support_admin_id() -> int:
    a = Admin(username="support", full_name="Support", active=True, is_super_admin=False)
    a.set_password("supportpass123")
    db.session.add(a)
    db.session.commit()
    return a.id


def _as(client, admin_id):
    with client.session_transaction() as s:
        s["admin_id"] = admin_id


# ───────── 1. schema ─────────

def test_vault_tables_exist(app):
    with app.app_context():
        names = set(inspect(db.engine).get_table_names())
        assert "customer_private_records" in names
        assert "customer_secret_vault" in names
        assert "customer_vault_audit_logs" in names
        assert "is_super_admin" in {c["name"] for c in inspect(db.engine).get_columns("admins")}


# ───────── 2. encryption ─────────

def test_encrypt_decrypt_roundtrip(app):
    with app.app_context():
        ct = crypto.encrypt_secret(PLAINTEXT)
        assert ct != PLAINTEXT
        assert crypto.decrypt_secret(ct) == PLAINTEXT


def test_encryption_available_and_missing_key(app):
    with app.app_context():
        assert crypto.encryption_available() is True
        original = app.config["CUSTOMER_VAULT_ENCRYPTION_KEY"]
        app.config["CUSTOMER_VAULT_ENCRYPTION_KEY"] = ""
        try:
            assert crypto.encryption_available() is False
            cid = _customer()
            with pytest.raises(vault.VaultError):
                vault.create_secret(cid, {"secret_type": "api_token", "label": "x"}, "abc", actor_id=1)
        finally:
            app.config["CUSTOMER_VAULT_ENCRYPTION_KEY"] = original


def test_mask_secret(app):
    assert crypto.mask_secret("short") and crypto.mask_secret("short") != "short"
    assert "••" in crypto.mask_secret("a-very-long-token-value-1234567890")
    assert crypto.mask_secret("-----BEGIN OPENSSH PRIVATE KEY-----\nabc") == "-----BEGIN…KEY-----"


# ───────── 3. permissions ─────────

def test_unauthenticated_cannot_access_vault(client, app):
    with app.app_context():
        cid = _customer()
    r = client.get(f"/admin/customers/{cid}/vault", follow_redirects=False)
    assert r.status_code in (301, 302)
    assert "/login" in r.headers.get("Location", "")


def test_customer_session_cannot_access_vault(client, app):
    with app.app_context():
        cid = _customer()
    with client.session_transaction() as s:
        s["customer_user_id"] = 999  # a customer, not an admin
    r = client.get(f"/admin/customers/{cid}/vault", follow_redirects=False)
    assert r.status_code in (301, 302)
    assert "/login" in r.headers.get("Location", "")


def test_non_super_admin_cannot_reveal(client, app):
    with app.app_context():
        cid = _customer()
        sec = vault.create_secret(cid, {"secret_type": "api_token", "label": "K"}, PLAINTEXT, actor_id=_super_admin_id())
        sid = sec.id
        support_id = _support_admin_id()
    _as(client, support_id)
    r = client.post(f"/admin/customers/{cid}/vault/secrets/{sid}/reveal",
                    headers={"X-Requested-With": "XMLHttpRequest"}, data={"reason": "x"})
    assert r.status_code == 403
    assert PLAINTEXT not in r.get_data(as_text=True)


def test_super_admin_can_reveal(client, app):
    with app.app_context():
        cid = _customer()
        sec = vault.create_secret(cid, {"secret_type": "api_token", "label": "K"}, PLAINTEXT, actor_id=_super_admin_id())
        sid = sec.id
        admin_id = _super_admin_id()
    _as(client, admin_id)
    r = client.post(f"/admin/customers/{cid}/vault/secrets/{sid}/reveal",
                    headers={"X-Requested-With": "XMLHttpRequest"}, data={"reason": "ops"})
    assert r.status_code == 200
    body = r.get_json()
    assert body["ok"] is True and body["secret"] == PLAINTEXT


# ───────── 4. private records ─────────

def test_private_record_crud(app):
    with app.app_context():
        cid = _customer()
        rec = vault.create_private_record(cid, {"record_type": "vps_url", "title": "VPS", "url": "https://vps.example.com"}, actor_id=1)
        assert rec.id and rec.url == "https://vps.example.com"
        vault.update_private_record(rec.id, cid, {"record_type": "vps_url", "title": "VPS-2"}, actor_id=1)
        assert CustomerPrivateRecord.query.get(rec.id).title == "VPS-2"
        vault.archive_private_record(rec.id, cid, actor_id=1)
        assert vault.list_private_records(cid) == []  # archived hidden
        assert len(vault.list_private_records(cid, include_archived=True)) == 1


# ───────── 5. secrets ─────────

def test_secret_create_encrypts_and_metadata_has_no_plaintext(app):
    with app.app_context():
        cid = _customer()
        sec = vault.create_secret(cid, {"secret_type": "vps_password", "label": "root pw"}, PLAINTEXT, actor_id=1)
        assert sec.encrypted_secret != PLAINTEXT
        meta = vault.list_secret_metadata(cid)
        # metadata objects must not expose plaintext via any string field besides ciphertext
        for m in meta:
            assert m.label != PLAINTEXT
            assert PLAINTEXT not in (m.secret_hint or "")
            assert PLAINTEXT not in (m.notes or "")


def test_reveal_updates_timestamp_and_rotate_changes_ciphertext(app):
    with app.app_context():
        cid = _customer()
        sec = vault.create_secret(cid, {"secret_type": "api_token", "label": "K"}, PLAINTEXT, actor_id=1)
        ct1 = sec.encrypted_secret
        _, plain = vault.reveal_secret(sec.id, cid, actor_id=1)
        assert plain == PLAINTEXT
        assert CustomerSecret.query.get(sec.id).last_revealed_at is not None
        vault.rotate_secret(sec.id, cid, "new-value-456", actor_id=1)
        sec2 = CustomerSecret.query.get(sec.id)
        assert sec2.encrypted_secret != ct1
        assert crypto.decrypt_secret(sec2.encrypted_secret) == "new-value-456"


def test_archive_hides_secret_from_active_list(app):
    with app.app_context():
        cid = _customer()
        sec = vault.create_secret(cid, {"secret_type": "other", "label": "tmp"}, "abc", actor_id=1)
        vault.archive_secret(sec.id, cid, actor_id=1)
        assert vault.list_secret_metadata(cid) == []
        assert len(vault.list_secret_metadata(cid, include_archived=True)) == 1


def test_customer_id_mismatch_is_rejected(app):
    with app.app_context():
        cid_a = _customer("A")
        cid_b = _customer("B")
        sec = vault.create_secret(cid_a, {"secret_type": "other", "label": "x"}, "abc", actor_id=1)
        with pytest.raises(vault.VaultError):
            vault.reveal_secret(sec.id, cid_b, actor_id=1)  # wrong customer
        with pytest.raises(vault.VaultError):
            vault.archive_secret(sec.id, cid_b, actor_id=1)


# ───────── 6. audit ─────────

def test_audit_logged_and_never_contains_plaintext(app):
    with app.app_context():
        cid = _customer()
        sec = vault.create_secret(cid, {"secret_type": "api_token", "label": "K"}, PLAINTEXT, actor_id=1)
        vault.reveal_secret(sec.id, cid, actor_id=1, reason="why")
        vault.rotate_secret(sec.id, cid, "n2", actor_id=1)
        vault.archive_secret(sec.id, cid, actor_id=1)
        actions = {a.action for a in vault.list_vault_audit(cid)}
        assert {"secret_created", "secret_revealed", "secret_rotated", "secret_archived"} <= actions
        for a in CustomerVaultAuditLog.query.all():
            assert PLAINTEXT not in (a.metadata_json or "")
            assert PLAINTEXT not in (a.reason or "")


# ───────── 7. UI route ─────────

def test_vault_page_renders_arabic_and_hides_secret_value(client, app):
    with app.app_context():
        cid = _customer()
        vault.create_secret(cid, {"secret_type": "api_token", "label": "Prod API"}, PLAINTEXT, actor_id=_super_admin_id())
        admin_id = _super_admin_id()
    _as(client, admin_id)
    r = client.get(f"/admin/customers/{cid}/vault")
    html = r.get_data(as_text=True)
    assert r.status_code == 200
    assert "الخزنة الخاصة بالعميل" in html
    assert "الأسرار المحمية" in html
    assert "Prod API" in html            # metadata label shown
    assert PLAINTEXT not in html         # plaintext NEVER in initial HTML


# ───────── 8. security regression ─────────

def test_plaintext_absent_from_create_and_list_responses(client, app):
    with app.app_context():
        cid = _customer()
        admin_id = _super_admin_id()
    _as(client, admin_id)
    # create via the route
    r = client.post(f"/admin/customers/{cid}/vault/secrets",
                    data={"secret_type": "api_token", "label": "Route Secret", "secret_value": PLAINTEXT},
                    follow_redirects=True)
    assert PLAINTEXT not in r.get_data(as_text=True)
    # vault page (list) must not contain plaintext
    r2 = client.get(f"/admin/customers/{cid}/vault")
    assert PLAINTEXT not in r2.get_data(as_text=True)


# ───────── 9. URL validation ─────────

def test_url_validation(app):
    with app.app_context():
        cid = _customer()
        with pytest.raises(vault.VaultError):
            vault.create_private_record(cid, {"record_type": "vps_url", "title": "bad", "url": "javascript:alert(1)"}, actor_id=1)
        ok = vault.create_private_record(cid, {"record_type": "vps_url", "title": "ok", "url": "https://x.example.com"}, actor_id=1)
        assert ok.url == "https://x.example.com"


# ───────── 10. customer-exposure / export safety ─────────

def test_backup_summary_allowlist_excludes_vault_tables():
    from app.services.customer_backups import _SUMMARY_TABLES
    names = {t[0] for t in _SUMMARY_TABLES}
    assert "customer_secret_vault" not in names
    assert "customer_private_records" not in names


def test_public_and_api_modules_do_not_reference_vault_models():
    import pathlib
    root = pathlib.Path(__file__).resolve().parents[1] / "app"
    for sub in ("public", "api"):
        for f in (root / sub).rglob("*.py"):
            text = f.read_text(encoding="utf-8")
            assert "CustomerSecret" not in text
            assert "CustomerPrivateRecord" not in text
            assert "CustomerVaultAuditLog" not in text
