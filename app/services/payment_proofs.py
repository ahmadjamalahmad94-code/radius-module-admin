"""Receipt-image storage + validation for manual bank-transfer payments.

Files are stored OUTSIDE the public static tree, under
``{instance_path}/payment_proofs/{payment_request_id}/receipt.<ext>`` so a
guessed URL can never serve a customer's receipt. Admins fetch the image
through an authenticated route that streams the file.

We intentionally do NOT shell out to ImageMagick or PIL — keeping deps minimal
and the trust surface small. Validation is by magic-byte sniffing + size cap.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import IO, Any, Optional

from flask import current_app
from werkzeug.utils import secure_filename

from ..extensions import db
from ..models import LicensePaymentProof, LicensePaymentRequest, utcnow


# ────────────────────────────────────────────────────────────────────
# Validation policy (kept explicit, no Pillow / ImageMagick deps)
# ────────────────────────────────────────────────────────────────────

ALLOWED_EXTENSIONS: frozenset[str] = frozenset({"jpg", "jpeg", "png", "webp", "pdf"})

# 5 MB — receipts are mostly phone-camera JPGs. PDF cap kept the same.
MAX_BYTES: int = 5 * 1024 * 1024

# Magic-byte prefixes per type. We only accept files whose first bytes match.
_MAGIC: dict[str, tuple[bytes, ...]] = {
    "jpg":  (b"\xff\xd8\xff",),
    "jpeg": (b"\xff\xd8\xff",),
    "png":  (b"\x89PNG\r\n\x1a\n",),
    "webp": (b"RIFF",),   # actual marker is RIFF....WEBP; we recheck "WEBP" too
    "pdf":  (b"%PDF-",),
}


class ReceiptValidationError(ValueError):
    """Stable codes used by the route layer to render Arabic messages."""

    @property
    def code(self) -> str:
        return super().__str__()

    @property
    def message_ar(self) -> str:
        return {
            "missing":      "لم يتم إرفاق صورة الإيصال.",
            "empty":        "ملف الإيصال فارغ.",
            "bad_ext":      "صيغة الملف غير مدعومة. الصيغ المقبولة: JPG / PNG / WEBP / PDF.",
            "too_large":    "حجم الملف يتجاوز ٥ ميغابايت.",
            "bad_content":  "محتوى الملف لا يطابق صيغته المُعلنة.",
            "io_error":     "تعذّر حفظ الملف على الخادم.",
        }.get(self.code, self.code)


# ────────────────────────────────────────────────────────────────────
# Internal helpers
# ────────────────────────────────────────────────────────────────────

def _instance_root() -> Path:
    root = Path(current_app.instance_path) / "payment_proofs"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _ext_of(filename: str) -> str:
    name = secure_filename(filename or "")
    if "." not in name:
        return ""
    return name.rsplit(".", 1)[-1].strip().lower()


def _magic_ok(head: bytes, ext: str) -> bool:
    prefixes = _MAGIC.get(ext, ())
    for p in prefixes:
        if head.startswith(p):
            if ext == "webp" and b"WEBP" not in head[:16]:
                return False
            return True
    return False


def _size_of(fp: IO[bytes]) -> int:
    """Best-effort size by seeking. Returns -1 if not seekable."""
    try:
        cur = fp.tell()
        fp.seek(0, os.SEEK_END)
        n = fp.tell()
        fp.seek(cur, os.SEEK_SET)
        return int(n)
    except Exception:  # noqa: BLE001
        return -1


# ────────────────────────────────────────────────────────────────────
# Public API
# ────────────────────────────────────────────────────────────────────

def validate_receipt(file_storage: Any) -> tuple[str, bytes]:
    """Validate an uploaded receipt; return (extension, full_bytes).

    Raises :class:`ReceiptValidationError` on any policy violation.

    ``file_storage`` is duck-typed against ``werkzeug.datastructures.FileStorage``
    (`.filename`, `.stream` or read()/seek()/tell()) so unit tests can pass a
    plain ``io.BytesIO`` wrapper.
    """
    if file_storage is None:
        raise ReceiptValidationError("missing")
    filename = getattr(file_storage, "filename", "") or ""
    ext = _ext_of(filename)
    if not ext or ext not in ALLOWED_EXTENSIONS:
        raise ReceiptValidationError("bad_ext")

    # Stream may be the FileStorage itself or .stream — try both.
    stream: IO[bytes] = getattr(file_storage, "stream", None) or file_storage

    # Size: prefer seek; fall back to reading once and capping.
    size = _size_of(stream)
    if size == 0:
        raise ReceiptValidationError("empty")
    if size > MAX_BYTES:
        raise ReceiptValidationError("too_large")

    # Magic-byte check on the first 16 bytes (more than enough for our types).
    try:
        head = stream.read(16)
        stream.seek(0)
    except Exception as exc:  # noqa: BLE001
        raise ReceiptValidationError("io_error") from exc

    if not head:
        raise ReceiptValidationError("empty")
    if not _magic_ok(head, ext):
        raise ReceiptValidationError("bad_content")

    # Full read with size guard (covers non-seekable streams).
    body = stream.read(MAX_BYTES + 1)
    if not body:
        raise ReceiptValidationError("empty")
    if len(body) > MAX_BYTES:
        raise ReceiptValidationError("too_large")
    return ext, body


def save_receipt(payment_request: LicensePaymentRequest, file_storage: Any) -> str:
    """Validate + persist the receipt to disk; return the relative path stored
    on :class:`LicensePaymentProof.image_path`.

    The path is RELATIVE (e.g. ``42/receipt.jpg``) so the disk root can move
    without rewriting DB rows. Callers join with ``_instance_root()`` to read.
    """
    ext, body = validate_receipt(file_storage)
    rid = int(payment_request.id)
    target_dir = _instance_root() / str(rid)
    target_dir.mkdir(parents=True, exist_ok=True)
    rel = f"{rid}/receipt.{ext}"
    target = target_dir / f"receipt.{ext}"
    # Wipe any older receipt in case the customer re-uploaded with a different ext.
    for prior in target_dir.iterdir():
        if prior.is_file() and prior.name.startswith("receipt."):
            try:
                prior.unlink()
            except OSError:
                pass
    try:
        target.write_bytes(body)
    except OSError as exc:
        raise ReceiptValidationError("io_error") from exc
    return rel


def receipt_full_path(image_path: str) -> Optional[Path]:
    """Resolve a relative image_path to an absolute Path under the instance
    folder, guarding against directory traversal."""
    if not image_path:
        return None
    root = _instance_root().resolve()
    candidate = (root / image_path).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    if not candidate.is_file():
        return None
    return candidate


def receipt_mime(ext_or_path: str | Path) -> str:
    """Return a safe Content-Type for a stored receipt."""
    p = str(ext_or_path).lower()
    if p.endswith(".pdf"):
        return "application/pdf"
    if p.endswith(".png"):
        return "image/png"
    if p.endswith(".webp"):
        return "image/webp"
    return "image/jpeg"  # jpg / jpeg


def submit_manual_proof_with_receipt(
    *,
    payment_request: LicensePaymentRequest,
    reference_number: str,
    note: str,
    receipt: Any,
) -> LicensePaymentProof:
    """Single entry point for the customer's manual-transfer submission.

    Mirrors ``LicensePaymentProofService.submit_manual_proof`` but also accepts
    a receipt file and stores it. We call the existing proof service first
    (which sets ``status='proof_submitted'`` and writes the
    :class:`LicensePaymentProof` row); on success, we save the image, populate
    ``proof.image_path`` and commit.

    Raises :class:`LicensePaymentValidationError` from the proof service or
    :class:`ReceiptValidationError` from receipt validation. If the receipt
    fails, the proof row is rolled back so we don't leave an image-less proof.
    """
    from .license_payments import LicensePaymentProofService  # local to avoid cycles

    proof = LicensePaymentProofService().submit_manual_proof(
        payment_request=payment_request,
        reference_number=reference_number,
        note=note,
    )
    try:
        rel = save_receipt(payment_request, receipt)
    except ReceiptValidationError:
        # Roll the proof row back: best-effort revert of the new proof + status.
        try:
            db.session.delete(proof)
            payment_request.status = "pending"
            db.session.add(payment_request)
            db.session.commit()
        except Exception:  # noqa: BLE001
            db.session.rollback()
        raise
    proof.image_path = rel
    proof.submitted_at = proof.submitted_at or utcnow()
    db.session.add(proof)
    db.session.commit()
    return proof


__all__ = [
    "ALLOWED_EXTENSIONS",
    "MAX_BYTES",
    "ReceiptValidationError",
    "receipt_full_path",
    "receipt_mime",
    "save_receipt",
    "submit_manual_proof_with_receipt",
    "validate_receipt",
]
