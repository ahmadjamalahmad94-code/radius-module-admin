"""fleet.registry.secrets_vault — Phase 3 task T2 (encrypted-at-rest secrets).

Store CHR-side secrets (WireGuard private keys, one-time RouterOS bootstrap
passwords, future per-CHR shared secrets, …) **encrypted at rest** in the
panel DB, never as plaintext columns.

The encryption layer is reused verbatim from
:mod:`app.services.whatsapp.crypto` — the same Fernet wrapper that already
protects ``whatsapp_embedded.app_secret`` and the customer-vault key. The
master key (``WHATSAPP_FERNET_KEY``) is env-only and is read fresh from
``current_app.config`` on every call; it is NEVER persisted.

Threat model
------------
* "Steal the panel DB" → attacker gets ciphertext only; the Fernet wrapper
  prevents decryption without the env-side master key.
* "Steal the env without the DB" → attacker has the master but no targets.
* "Steal both" → encryption-at-rest cannot help here; the threat is
  documented in the customer-vault settings page (the operator must keep
  env-var backups separate from DB backups).

Public API
----------
* :class:`VaultRef`  — opaque handle stored on the owning record.
* :func:`store_secret`     — encrypt + persist; returns the ref.
* :func:`retrieve_secret`  — decrypt and return the plaintext (audited).
* :func:`forget_secret`    — wipe a secret (idempotent).
* :func:`has_secret`       — refs-exist check that does NOT decrypt.

The ORM table this module owns is ``fleet_chr_secrets``. It is created by
``db.create_all()`` whenever this module is imported (importing it registers
the model on ``db.metadata``). It carries no plaintext column by construction.
"""
from __future__ import annotations

import dataclasses
import secrets

from app.extensions import db
from app.models import TimestampMixin, utcnow
from app.services.whatsapp.crypto import (
    WhatsAppCryptoError,
    decrypt_secret as _master_decrypt,
    encrypt_secret as _master_encrypt,
    mask_secret as _mask,
)


# ───────────────────────── exceptions ─────────────────────────

class VaultError(RuntimeError):
    """Raised for any vault failure surfaced to a caller (encryption,
    missing master key, unknown ref, etc.). Never carries the plaintext."""


# ───────────────────────── ORM model ─────────────────────────

class ChrSecret(TimestampMixin, db.Model):
    """One encrypted secret belonging to a CHR / onboarding job.

    Columns
    -------
    ``ref``         the random opaque handle the owning record persists.
                   ~22 url-safe chars; unique. The caller never has to look
                   inside.
    ``owner``      stable id of the owning entity, e.g. ``"chr:11"`` or
                   ``"onboarding:42"``. Used for audit and bulk cleanup
                   (``forget_owner``). NOT a foreign key — owners may be
                   created OR deleted in any order, and a ``SET NULL`` cascade
                   complicates the audit story.
    ``purpose``    short tag distinguishing multiple secrets per owner
                   (``"wg_mgmt"``, ``"wg_data"``, ``"bootstrap_password"``).
    ``kind``       documentation-only tag for the SHAPE of the plaintext
                   (``"wg_private_key"``, ``"password"``, ``"token"``).
                   Useful when the same vault holds heterogeneous payloads.
    ``ciphertext`` the Fernet token — encrypted under the panel master key.
                   NEVER decrypted on its way into the DB / a query.
    ``last_revealed_at``  set whenever :func:`retrieve_secret` returns the
                   plaintext. Lets the UI surface "this secret was last read
                   N minutes ago" without exposing the value.

    There is **no plaintext column on this table by construction**. The
    test ``test_no_plaintext_columns_on_chr_secrets`` enforces it.
    """

    __tablename__ = "fleet_chr_secrets"
    __table_args__ = (
        db.UniqueConstraint("ref", name="uq_fleet_chr_secrets_ref"),
        db.Index("idx_fleet_chr_secrets_owner", "owner"),
        db.Index("idx_fleet_chr_secrets_owner_purpose", "owner", "purpose"),
    )

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ref = db.Column(db.String(40), nullable=False)
    owner = db.Column(db.String(80), nullable=False, index=True)
    purpose = db.Column(db.String(40), nullable=False)
    kind = db.Column(db.String(40), nullable=False, default="opaque")
    ciphertext = db.Column(db.Text, nullable=False)
    last_revealed_at = db.Column(db.DateTime, nullable=True)

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return (
            f"<ChrSecret id={self.id} owner={self.owner!r} "
            f"purpose={self.purpose!r} kind={self.kind!r}>"
        )


# ───────────────────────── public ref ─────────────────────────

@dataclasses.dataclass(frozen=True)
class VaultRef:
    """Opaque handle the owning record persists.

    Surfaced as a plain string (``str(ref)``) so it fits cleanly into a
    ``VARCHAR`` column like ``fleet_onboarding_jobs.wg_keypair_ref``. The
    dataclass exists so callers can pass a typed handle around in code.
    """

    ref: str

    def __str__(self) -> str:
        return self.ref


# ───────────────────────── helpers ─────────────────────────

def _new_ref() -> str:
    """Random url-safe ref ~22 chars. Cryptographically uniform; ~128 bits."""
    return "vr_" + secrets.token_urlsafe(16)


def _require_master_key_ready() -> None:
    """Raise :class:`VaultError` if the panel master key is not configured.

    Storing a new ciphertext requires the master key (we'd just be writing
    garbage otherwise). The probe is "can we encrypt 1 byte?" — cheap,
    matches how ``embedded_settings.encryption_ready`` does it.
    """
    try:
        _master_encrypt("probe")
    except WhatsAppCryptoError as exc:
        raise VaultError(
            "تخزين أسرار الفلوت يتطلّب ضبط WHATSAPP_FERNET_KEY في بيئة الخادم."
        ) from exc


# ───────────────────────── public API ─────────────────────────

def store_secret(
    *,
    owner: str,
    purpose: str,
    plaintext: str,
    kind: str = "opaque",
) -> VaultRef:
    """Encrypt ``plaintext`` and persist a new ``fleet_chr_secrets`` row.

    Returns the :class:`VaultRef` the caller should store on the owning
    record. The function COMMITS the session so the secret is durable
    immediately (mirrors how ``customer_vault_crypto.save_vault_key_in_db``
    leaves committing to the route handler — except here we commit, since
    every caller wants persistence).

    Raises :class:`VaultError` if the master key is missing, if ``plaintext``
    is empty (refusing to encrypt nothing is a common safety check — see the
    customer-vault crypto helper), or if encryption itself fails.
    """
    if not owner or not purpose:
        raise VaultError("vault entries require non-empty owner + purpose")
    if not plaintext:
        raise VaultError("refusing to vault an empty secret")
    _require_master_key_ready()
    try:
        ciphertext = _master_encrypt(plaintext)
    except WhatsAppCryptoError as exc:
        # Never leak the plaintext in the error message.
        raise VaultError("encryption failed (master key invalid?)") from exc
    row = ChrSecret(
        ref=_new_ref(),
        owner=owner,
        purpose=purpose,
        kind=kind,
        ciphertext=ciphertext,
    )
    db.session.add(row)
    db.session.commit()
    return VaultRef(ref=row.ref)


def retrieve_secret(ref: VaultRef | str) -> str:
    """Return the plaintext for ``ref`` and stamp ``last_revealed_at``.

    Side-effect: bumps ``last_revealed_at`` on the row so the UI can
    truthfully say "this secret was last read at …". Callers that want
    a quiet read (e.g. a unit test) can use :func:`has_secret` instead.

    Raises :class:`VaultError` on an unknown ref or a tampered ciphertext.
    NEVER includes the plaintext in any raised message.
    """
    ref_value = ref.ref if isinstance(ref, VaultRef) else str(ref)
    row = _get_row(ref_value)
    try:
        plaintext = _master_decrypt(row.ciphertext)
    except WhatsAppCryptoError as exc:
        raise VaultError("vault entry corrupted or wrong master key") from exc
    row.last_revealed_at = utcnow()
    db.session.add(row)
    db.session.commit()
    return plaintext


def has_secret(ref: VaultRef | str) -> bool:
    """True iff a vault entry exists for ``ref``. Does NOT decrypt."""
    ref_value = ref.ref if isinstance(ref, VaultRef) else str(ref)
    return (
        db.session.query(ChrSecret.id).filter_by(ref=ref_value).first() is not None
    )


def forget_secret(ref: VaultRef | str) -> bool:
    """Delete the vault entry for ``ref``. Idempotent.

    Returns True if a row was deleted, False if nothing existed. The CALLER
    is responsible for clearing the ref from the owning record AFTER calling
    this — there's no FK so we can't enforce it from here.
    """
    ref_value = ref.ref if isinstance(ref, VaultRef) else str(ref)
    row = db.session.query(ChrSecret).filter_by(ref=ref_value).first()
    if row is None:
        return False
    db.session.delete(row)
    db.session.commit()
    return True


def forget_owner(owner: str) -> int:
    """Bulk-delete every vault entry belonging to ``owner``. Returns count.

    Used by the onboarding service when a job is fully aborted, or when a
    CHR is decommissioned and its secrets must be purged.
    """
    if not owner:
        return 0
    count = (
        db.session.query(ChrSecret).filter_by(owner=owner).delete(synchronize_session=False)
    )
    db.session.commit()
    return count


def describe_secret(ref: VaultRef | str) -> dict:
    """UI-safe metadata snapshot — owner / purpose / kind / mask of ciphertext.

    Never returns the plaintext. The ``masked`` value is a hash-of-hash
    style preview of the CIPHERTEXT (via :func:`mask_secret`) so the operator
    can confirm "yes, the same blob is still here" without revealing
    anything secret. Returns ``None`` for unknown refs.
    """
    ref_value = ref.ref if isinstance(ref, VaultRef) else str(ref)
    row = db.session.query(ChrSecret).filter_by(ref=ref_value).first()
    if row is None:
        return {}
    return {
        "ref": row.ref,
        "owner": row.owner,
        "purpose": row.purpose,
        "kind": row.kind,
        "masked": _mask(row.ciphertext),
        "last_revealed_at": row.last_revealed_at,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    }


def _get_row(ref_value: str) -> ChrSecret:
    row = db.session.query(ChrSecret).filter_by(ref=ref_value).first()
    if row is None:
        raise VaultError(f"unknown vault ref: {ref_value!r}")
    return row


__all__ = [
    "ChrSecret",
    "VaultError",
    "VaultRef",
    "describe_secret",
    "forget_owner",
    "forget_secret",
    "has_secret",
    "retrieve_secret",
    "store_secret",
]
