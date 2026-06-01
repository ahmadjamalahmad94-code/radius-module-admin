"""
Customer Secure Vault — service layer (admin-only).

Two data classes per customer:
  • private records (operational notes/links, not secrets)
  • secrets (encrypted at rest via customer_vault_crypto)

Hard rules enforced here:
  - list_secret_metadata NEVER decrypts and NEVER returns plaintext.
  - Only reveal_secret() decrypts, and it updates last_revealed_* + writes an audit row.
  - Every mutation/reveal is audited in customer_vault_audit_logs.
  - Audit metadata never contains plaintext secret values.
  - All lookups are scoped by customer_id (prevents id mismatch / IDOR).
"""
from __future__ import annotations

from urllib.parse import urlparse

from flask import request

from ..extensions import db
from ..models import (
    CustomerPrivateRecord,
    CustomerSecret,
    CustomerVaultAuditLog,
    utcnow,
)
from . import customer_vault_crypto as crypto

# Try to also write to the global audit log (best-effort).
try:
    from ..auth.routes import audit as _global_audit
except Exception:  # pragma: no cover
    _global_audit = None


class VaultError(ValueError):
    """Validation / policy error surfaced to the admin UI."""


RECORD_TYPES = {
    "vps_url", "radius_url", "server_ip", "deployment_note",
    "support_note", "backup_note", "other",
}
SECRET_TYPES = {
    "vps_password", "ssh_password", "ssh_private_key", "database_password",
    "mikrotik_api_password", "google_drive_secret", "whatsapp_token",
    "api_token", "backup_secret", "other",
}
SECRET_STATUSES = {"active", "rotated", "revoked", "archived"}

LIMITS = {"label": 160, "title": 160, "username": 160, "host": 255,
          "url": 500, "notes": 5000, "value": 5000, "hint": 160, "secret": 20000,
          "reason": 255}


# ───────────────────────── validation helpers ─────────────────────────

def _clean(value, max_len: int) -> str:
    s = (value or "").strip()
    if len(s) > max_len:
        raise VaultError(f"القيمة أطول من الحد المسموح ({max_len}).")
    return s


def _valid_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return ""
    if len(url) > LIMITS["url"]:
        raise VaultError("الرابط أطول من الحد المسموح.")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise VaultError("الرابط غير صالح (يجب أن يبدأ بـ http:// أو https://).")
    return url


def _ctx():
    try:
        ip = (request.headers.get("X-Forwarded-For", "") or "").split(",")[0].strip() or (request.remote_addr or "")
        ua = (request.headers.get("User-Agent") or "")[:255]
    except Exception:
        ip, ua = "", ""
    return ip, ua


# ───────────────────────── audit ─────────────────────────

def log_vault_action(customer_id: int, actor_admin_id, action: str, target_type: str,
                     target_id=None, metadata: dict | None = None, reason: str = "") -> None:
    """Write a dedicated vault audit row. NEVER pass plaintext in metadata."""
    ip, ua = _ctx()
    row = CustomerVaultAuditLog(
        customer_id=customer_id, actor_admin_id=actor_admin_id, action=action,
        target_type=target_type, target_id=(int(target_id) if target_id else None),
        ip_address=ip, user_agent=ua, reason=_clean(reason, LIMITS["reason"]),
    )
    row.meta = metadata or {}
    db.session.add(row)
    if _global_audit:
        try:
            _global_audit(f"vault_{action}", f"vault_{target_type}", str(target_id or ""),
                          f"خزنة العميل #{customer_id}: {action}",
                          {"customer_id": customer_id, **(metadata or {})})
        except Exception:
            pass


# ───────────────────────── private records ─────────────────────────

def list_private_records(customer_id: int, include_archived: bool = False):
    q = CustomerPrivateRecord.query.filter_by(customer_id=customer_id)
    if not include_archived:
        q = q.filter_by(is_archived=False)
    return q.order_by(CustomerPrivateRecord.is_pinned.desc(),
                      CustomerPrivateRecord.updated_at.desc()).all()


def _fill_record(rec: CustomerPrivateRecord, data: dict) -> None:
    rtype = (data.get("record_type") or "other").strip()
    if rtype not in RECORD_TYPES:
        raise VaultError("نوع السجل غير مسموح.")
    title = _clean(data.get("title"), LIMITS["title"])
    if not title:
        raise VaultError("العنوان مطلوب.")
    rec.record_type = rtype
    rec.title = title
    rec.value = _clean(data.get("value"), LIMITS["value"])
    rec.url = _valid_url(data.get("url"))
    rec.notes = _clean(data.get("notes"), LIMITS["notes"])
    rec.is_pinned = bool(data.get("is_pinned"))


def create_private_record(customer_id: int, data: dict, actor_id):
    rec = CustomerPrivateRecord(customer_id=customer_id, created_by_admin_id=actor_id,
                                updated_by_admin_id=actor_id)
    _fill_record(rec, data)
    db.session.add(rec)
    db.session.flush()
    log_vault_action(customer_id, actor_id, "private_record_created", "private_record", rec.id,
                     {"record_type": rec.record_type, "title": rec.title})
    db.session.commit()
    return rec


def update_private_record(record_id: int, customer_id: int, data: dict, actor_id):
    rec = CustomerPrivateRecord.query.filter_by(id=record_id, customer_id=customer_id).first()
    if not rec:
        raise VaultError("السجل غير موجود.")
    _fill_record(rec, data)
    rec.updated_by_admin_id = actor_id
    log_vault_action(customer_id, actor_id, "private_record_updated", "private_record", rec.id,
                     {"record_type": rec.record_type})
    db.session.commit()
    return rec


def archive_private_record(record_id: int, customer_id: int, actor_id):
    rec = CustomerPrivateRecord.query.filter_by(id=record_id, customer_id=customer_id).first()
    if not rec:
        raise VaultError("السجل غير موجود.")
    rec.is_archived = True
    rec.updated_by_admin_id = actor_id
    log_vault_action(customer_id, actor_id, "private_record_archived", "private_record", rec.id)
    db.session.commit()
    return rec


# ───────────────────────── secrets ─────────────────────────

def list_secret_metadata(customer_id: int, include_archived: bool = False):
    """Returns secret rows for METADATA display only. Never decrypts.
    Templates must render metadata fields + secret_hint, never encrypted_secret."""
    q = CustomerSecret.query.filter_by(customer_id=customer_id)
    if not include_archived:
        q = q.filter(CustomerSecret.status != "archived")
    return q.order_by(CustomerSecret.updated_at.desc()).all()


def _validate_secret_meta(data: dict) -> dict:
    stype = (data.get("secret_type") or "other").strip()
    if stype not in SECRET_TYPES:
        raise VaultError("نوع السر غير مسموح.")
    label = _clean(data.get("label"), LIMITS["label"])
    if not label:
        raise VaultError("اسم السر (label) مطلوب.")
    return {
        "secret_type": stype,
        "label": label,
        "host": _clean(data.get("host"), LIMITS["host"]),
        "url": _valid_url(data.get("url")),
        "username": _clean(data.get("username"), LIMITS["username"]),
        "secret_hint": _clean(data.get("secret_hint"), LIMITS["hint"]),
        "notes": _clean(data.get("notes"), LIMITS["notes"]),
    }


def _require_crypto():
    if not crypto.encryption_available():
        raise VaultError("مفتاح تشفير الخزنة غير مضبوط. لا يمكن حفظ أو عرض الأسرار.")


def _check_secret_plaintext(plaintext: str) -> str:
    if plaintext is None or plaintext.strip() == "":
        raise VaultError("قيمة السر مطلوبة.")
    if len(plaintext) > LIMITS["secret"]:
        raise VaultError("قيمة السر أكبر من الحد المسموح.")
    return plaintext


def create_secret(customer_id: int, data: dict, plaintext_secret: str, actor_id):
    _require_crypto()
    meta = _validate_secret_meta(data)
    plaintext = _check_secret_plaintext(plaintext_secret)
    sec = CustomerSecret(customer_id=customer_id, created_by_admin_id=actor_id,
                         updated_by_admin_id=actor_id, status="active",
                         encrypted_secret=crypto.encrypt_secret(plaintext), **meta)
    db.session.add(sec)
    db.session.flush()
    log_vault_action(customer_id, actor_id, "secret_created", "secret", sec.id,
                     {"secret_type": sec.secret_type, "label": sec.label})
    db.session.commit()
    return sec


def update_secret_metadata(secret_id: int, customer_id: int, data: dict, actor_id):
    sec = CustomerSecret.query.filter_by(id=secret_id, customer_id=customer_id).first()
    if not sec:
        raise VaultError("السر غير موجود.")
    meta = _validate_secret_meta(data)
    for k, v in meta.items():
        setattr(sec, k, v)
    sec.updated_by_admin_id = actor_id
    log_vault_action(customer_id, actor_id, "secret_updated_metadata", "secret", sec.id,
                     {"secret_type": sec.secret_type})
    db.session.commit()
    return sec


def rotate_secret(secret_id: int, customer_id: int, new_plaintext_secret: str, actor_id):
    _require_crypto()
    sec = CustomerSecret.query.filter_by(id=secret_id, customer_id=customer_id).first()
    if not sec:
        raise VaultError("السر غير موجود.")
    plaintext = _check_secret_plaintext(new_plaintext_secret)
    sec.encrypted_secret = crypto.encrypt_secret(plaintext)
    sec.last_rotated_at = utcnow()
    sec.status = "active"
    sec.updated_by_admin_id = actor_id
    log_vault_action(customer_id, actor_id, "secret_rotated", "secret", sec.id,
                     {"secret_type": sec.secret_type})
    db.session.commit()
    return sec


def reveal_secret(secret_id: int, customer_id: int, actor_id, reason: str = ""):
    """Decrypt and return plaintext. Updates last_revealed_* and writes audit.
    Returns (secret_obj, plaintext). Caller must only expose plaintext via the
    dedicated reveal endpoint response — never render it into a normal page."""
    _require_crypto()
    sec = CustomerSecret.query.filter_by(id=secret_id, customer_id=customer_id).first()
    if not sec:
        raise VaultError("السر غير موجود.")
    plaintext = crypto.decrypt_secret(sec.encrypted_secret)
    sec.last_revealed_at = utcnow()
    sec.last_revealed_by_admin_id = actor_id
    log_vault_action(customer_id, actor_id, "secret_revealed", "secret", sec.id,
                     {"secret_type": sec.secret_type, "label": sec.label}, reason=reason)
    db.session.commit()
    return sec, plaintext


def archive_secret(secret_id: int, customer_id: int, actor_id):
    sec = CustomerSecret.query.filter_by(id=secret_id, customer_id=customer_id).first()
    if not sec:
        raise VaultError("السر غير موجود.")
    sec.status = "archived"
    sec.updated_by_admin_id = actor_id
    log_vault_action(customer_id, actor_id, "secret_archived", "secret", sec.id,
                     {"secret_type": sec.secret_type})
    db.session.commit()
    return sec


def list_vault_audit(customer_id: int, limit: int = 100, action: str = ""):
    q = CustomerVaultAuditLog.query.filter_by(customer_id=customer_id)
    if action:
        q = q.filter_by(action=action)
    return q.order_by(CustomerVaultAuditLog.created_at.desc()).limit(limit).all()
