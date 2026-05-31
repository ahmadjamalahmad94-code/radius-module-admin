"""Receiving side for RADIUS instance database backups.

A customer's RADIUS instance (radius-module) uploads its local SQLite backup
here via the integration bridge. We always record metadata in the customer's
file; the actual file is stored on disk only when the instance sent its
content. Every upload is audited.

Auth is the per-license integration secret (the same secret the panel issues
in the customer portal's "إعداد ربط الريدياس"), supplied by the instance in
the ``X-HobeRadius-Admin-Secret`` header.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
from pathlib import Path
from typing import Any

from flask import Flask, current_app

from ..extensions import db
from ..license_signing import license_integration_secret
from ..models import CustomerBackupArtifact, License, utcnow
from ..services.customer_control import audit_customer_control


MAX_STORED_BYTES = 200 * 1024 * 1024  # 200 MB hard cap on stored content


class BackupUploadError(Exception):
    def __init__(self, code: str, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


def _backups_root() -> Path:
    root = Path(current_app.instance_path) / "customer_backups"
    root.mkdir(parents=True, exist_ok=True)
    return root


def verify_instance_secret(app: Flask, license_key: str, provided_secret: str) -> bool:
    """Validate the X-HobeRadius-Admin-Secret header.

    Accepts EITHER the per-license integration secret OR the root
    LICENSE_CHECK_HMAC_SECRET — mirroring how verify_license_signature()
    accepts both, so the backup upload works regardless of which secret the
    operator configured as HOBERADIUS_ADMIN_SHARED_SECRET on the instance.
    """
    provided = str(provided_secret or "").strip()
    candidates = [
        license_integration_secret(app, license_key),
        str(app.config.get("LICENSE_CHECK_HMAC_SECRET") or "").strip(),
    ]
    if provided:
        for expected in candidates:
            if expected and hmac.compare_digest(provided, expected):
                return True
    # Consistency with the other integration endpoints: if the panel allows
    # unsigned license checks (lenient / non-production posture), accept the
    # upload the same way contract/identity sync are accepted. In production
    # (signature required), only the shared-secret header above is honoured.
    required = bool(app.config.get("LICENSE_CHECK_SIGNATURE_REQUIRED"))
    allow_unsigned = bool(app.config.get("LICENSE_CHECK_ALLOW_UNSIGNED"))
    if not required and allow_unsigned:
        return True
    return False


def _safe_reference(reference: str) -> str:
    """Filesystem-safe slug for a backup reference."""
    cleaned = "".join(ch if (ch.isalnum() or ch in "-_.") else "_" for ch in str(reference or ""))
    return cleaned[:160] or "backup"


def record_backup_upload(
    *,
    license_key: str,
    payload: dict[str, Any],
    provided_secret: str,
) -> dict[str, Any]:
    """Validate + store an uploaded backup. Returns a JSON-able result dict.

    Raises BackupUploadError on auth/validation failures.
    """
    key = str(license_key or "").strip().upper()
    if not key:
        raise BackupUploadError("invalid_request", "license_key مطلوب.", 422)
    if not verify_instance_secret(current_app, key, provided_secret):
        raise BackupUploadError("denied", "فشل التحقق من سر التكامل.", 401)

    lic = License.query.filter_by(license_key=key).first()
    if not lic:
        raise BackupUploadError("not_found", "لا يوجد ترخيص مطابق.", 404)
    customer = lic.customer
    if not customer:
        raise BackupUploadError("not_found", "لا يوجد عميل مرتبط بهذا الترخيص.", 404)

    backup_reference = str(payload.get("backup_reference") or "").strip()
    if not backup_reference:
        raise BackupUploadError("invalid_request", "backup_reference مطلوب.", 422)

    checksum = str(payload.get("checksum_sha256") or "").strip().lower()
    size = _safe_int(payload.get("size"), 0)
    kind = str(payload.get("kind") or "sqlite").strip()[:40]
    module = str(payload.get("module") or "radius-module").strip()[:60]
    instance_id = str(payload.get("instance_id") or "").strip()[:120]
    upload_mode = str(payload.get("upload_mode") or "metadata_only").strip()[:40]
    remote_created_at = str(payload.get("created_at") or "").strip()[:40]
    content_b64 = payload.get("content_base64")

    artifact = CustomerBackupArtifact.query.filter_by(
        customer_id=customer.id, backup_reference=backup_reference
    ).first()
    if not artifact:
        artifact = CustomerBackupArtifact(customer_id=customer.id, backup_reference=backup_reference)
        db.session.add(artifact)

    artifact.license_id = lic.id
    artifact.license_key = key
    artifact.module = module
    artifact.instance_id = instance_id
    artifact.kind = kind
    artifact.size = size
    artifact.checksum_sha256 = checksum
    artifact.upload_mode = upload_mode
    artifact.remote_created_at = remote_created_at

    stored = False
    stored_filename = artifact.stored_filename or ""
    if content_b64:
        try:
            raw = base64.b64decode(str(content_b64), validate=True)
        except (binascii.Error, ValueError) as exc:
            raise BackupUploadError("invalid_request", "محتوى النسخة (base64) غير صالح.", 422) from exc
        if len(raw) > MAX_STORED_BYTES:
            raise BackupUploadError("too_large", "حجم النسخة يتجاوز الحد المسموح للتخزين.", 413)
        if checksum:
            actual = hashlib.sha256(raw).hexdigest()
            if actual != checksum:
                raise BackupUploadError("checksum_mismatch", "بصمة النسخة لا تطابق المحتوى.", 422)
        cust_dir = _backups_root() / str(customer.id)
        cust_dir.mkdir(parents=True, exist_ok=True)
        stored_filename = f"{_safe_reference(backup_reference)}.sqlite3"
        (cust_dir / stored_filename).write_bytes(raw)
        artifact.size = len(raw)
        stored = True

    artifact.content_included = stored
    artifact.stored_filename = stored_filename if stored else ""
    artifact.result_status = "stored" if stored else "metadata_only"
    meta = artifact.artifact_metadata
    meta.update({
        "last_upload_mode": upload_mode,
        "content_omitted_reason": payload.get("content_omitted_reason") or "",
    })
    artifact.artifact_metadata = meta

    audit_customer_control(
        actor_admin_id=None,
        action="customer_backup_uploaded",
        entity_type="customer_backup",
        entity_id=str(backup_reference),
        summary=(
            f"استلام نسخة احتياطية {'بالمحتوى' if stored else '(بيانات وصفية فقط)'} "
            f"من ريدياس العميل {customer.company_name}"
        ),
        metadata={
            "customer_id": customer.id,
            "license_key": key,
            "backup_reference": backup_reference,
            "size": artifact.size,
            "content_included": stored,
        },
    )
    db.session.commit()

    # Best-effort: push to the customer's own Google Drive in a BACKGROUND
    # thread so the HTTP response returns immediately after storing the file.
    # (A synchronous Drive upload made the instance's request time out.)
    drive_queued = False
    if stored:
        try:
            from . import google_drive as gd
            conn = gd.get_connection(customer.id)
            if conn and conn.connected:
                fp = _backups_root() / str(customer.id) / stored_filename
                _spawn_drive_upload(
                    current_app._get_current_object(),
                    customer.id, fp, f"{_safe_reference(backup_reference)}.sqlite3",
                )
                drive_queued = True
        except Exception:  # noqa: BLE001 — Drive push must never fail the upload
            drive_queued = False

    prune_customer_backups(customer.id)

    return {
        "ok": True,
        "status": artifact.result_status,
        "stored": stored,
        "artifact_id": artifact.id,
        "backup_reference": backup_reference,
        "size": artifact.size,
        "drive": "queued" if drive_queued else None,
    }


def _spawn_drive_upload(app: Flask, customer_id: int, file_path: Path, name: str) -> None:
    """Upload a stored backup to the customer's Google Drive off the request thread."""
    import threading

    def _worker() -> None:
        with app.app_context():
            try:
                from . import google_drive as gd
                gd.upload_backup(int(customer_id), file_path, name)
            except Exception:  # noqa: BLE001 — background, best-effort
                pass

    try:
        threading.Thread(target=_worker, name="gdrive-upload", daemon=True).start()
    except Exception:  # noqa: BLE001
        pass


BACKUP_RETENTION_DAYS = 30


def prune_customer_backups(customer_id: int, *, days: int = BACKUP_RETENTION_DAYS) -> int:
    """Delete a customer's backup artifacts (and stored files) older than `days`.

    Mirrors the 30-day retention enforced on the instance's local backups.
    Quiet/safe: rolls back on any error. Returns the count removed.
    """
    from datetime import timedelta

    if days <= 0:
        return 0
    cutoff = utcnow() - timedelta(days=days)
    try:
        stale = CustomerBackupArtifact.query.filter(
            CustomerBackupArtifact.customer_id == int(customer_id),
            CustomerBackupArtifact.received_at < cutoff,
        ).all()
        if not stale:
            return 0
        cust_dir = (_backups_root() / str(customer_id)).resolve()
        for art in stale:
            if art.stored_filename:
                try:
                    fp = (cust_dir / art.stored_filename).resolve()
                    if cust_dir in fp.parents and fp.exists():
                        fp.unlink()
                except OSError:
                    pass
            db.session.delete(art)
        db.session.commit()
        return len(stale)
    except Exception:  # noqa: BLE001 — retention must never break an upload
        db.session.rollback()
        return 0


def list_customer_backups(customer_id: int, *, limit: int = 50) -> list[CustomerBackupArtifact]:
    return (
        CustomerBackupArtifact.query.filter_by(customer_id=int(customer_id))
        .order_by(CustomerBackupArtifact.received_at.desc(), CustomerBackupArtifact.id.desc())
        .limit(int(limit))
        .all()
    )


# Tables we surface in the per-backup content summary, with Arabic labels.
# The stored file is the customer's RADIUS instance SQLite database; we only
# read row counts (never the data) and skip tables that don't exist.
_SUMMARY_TABLES: list[tuple[str, str]] = [
    ("subscribers", "المشتركون"),
    ("cards", "الكروت"),
    ("access_plans", "الباقات"),
    ("card_batches", "دفعات الكروت"),
    ("vouchers", "القسائم"),
    ("subscriber_recharges", "عمليات التعبئة"),
]


def _count_known_tables(path: Path) -> list[dict[str, Any]]:
    """Read-only row counts for the known tables present in a SQLite file.

    Tries a read-only URI first, then a plain open as a fallback (some SQLite
    builds reject the `mode=ro` URI for certain files). Raises on a genuinely
    unreadable file so the caller can report it.
    """
    import sqlite3

    last_exc: Exception | None = None
    for connect_args in (
        {"database": f"file:{path.as_posix()}?mode=ro", "uri": True, "timeout": 3},
        {"database": str(path), "timeout": 3},
    ):
        try:
            con = sqlite3.connect(**connect_args)
        except sqlite3.Error as exc:  # try the next strategy
            last_exc = exc
            continue
        try:
            cur = con.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            present = {str(r[0]) for r in cur.fetchall()}
            items: list[dict[str, Any]] = []
            for table, label in _SUMMARY_TABLES:
                if table not in present:
                    continue
                try:
                    cur.execute('SELECT COUNT(*) FROM "%s"' % table)  # noqa: S608 — name from fixed allow-list
                    items.append({"key": table, "label": label, "count": int(cur.fetchone()[0])})
                except sqlite3.Error:
                    continue
            return items
        finally:
            con.close()
    if last_exc:
        raise last_exc
    return []


def summarize_backup_content(customer_id: int, artifact_id: int) -> dict[str, Any]:
    """Open a stored backup (read-only) and count rows in known tables.

    Returns {"ok": bool, "items": [{key,label,count}], "error"?}. Never writes
    to the file and never raises — a corrupt/locked file yields ok=False.
    """
    resolved = get_artifact_file(int(customer_id), int(artifact_id))
    if not resolved:
        return {"ok": False, "error": "no_content", "items": []}
    path, _ = resolved
    try:
        items = _count_known_tables(path)
    except Exception:  # noqa: BLE001 — never raise to the request
        return {"ok": False, "error": "unreadable", "items": []}
    return {"ok": True, "items": items}


def get_artifact_file(customer_id: int, artifact_id: int) -> tuple[Path, str] | None:
    """Resolve a stored backup file path for download, or None if unavailable."""
    artifact = CustomerBackupArtifact.query.filter_by(
        id=int(artifact_id), customer_id=int(customer_id)
    ).first()
    if not artifact or not artifact.has_content:
        return None
    base = (_backups_root() / str(customer_id)).resolve()
    path = (base / artifact.stored_filename).resolve()
    if base not in path.parents or not path.exists():
        return None
    download_name = f"{_safe_reference(artifact.backup_reference)}.sqlite3"
    return path, download_name


def delete_customer_backup(customer_id: int, artifact_id: int) -> dict[str, Any]:
    """Delete one stored backup artifact (row + file) for a customer.

    Commits the session. Returns {"ok": bool, "backup_reference"?}.
    """
    artifact = CustomerBackupArtifact.query.filter_by(
        id=int(artifact_id), customer_id=int(customer_id)
    ).first()
    if not artifact:
        return {"ok": False, "error": "not_found"}
    reference = artifact.backup_reference
    if artifact.stored_filename:
        try:
            base = (_backups_root() / str(customer_id)).resolve()
            fp = (base / artifact.stored_filename).resolve()
            if base in fp.parents and fp.exists():
                fp.unlink()
        except OSError:
            pass
    db.session.delete(artifact)
    db.session.commit()
    return {"ok": True, "backup_reference": reference}


def _safe_int(value: Any, default: int) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return default
