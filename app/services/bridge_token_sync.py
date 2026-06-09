"""Bridge token bidirectional sync service.

What problem this solves
------------------------
Before this module, the long-lived "bridge token" between the panel and a
customer's radius-module was a **deterministic derivation**::

    license_integration_secret(app, license_key) =
        HMAC(LICENSE_CHECK_HMAC_SECRET, "hoberadius-license-integration:" + license_key)

That value is identical on both sides for free (the customer side gets it
once via ``POST /api/integration/hoberadius/instance/activate`` and saves
it), so the two sides cannot diverge — but they also cannot ROTATE without
changing either the global root or the license key. The owner wants per-
customer rotation that reflects bidirectionally:

  «بس يكونو الاثنين نفس المصدر... لو هو عمله يظهر عندي»
  → "Just make both sides one source — if HE rotates it shows up on MY side."

What this module owns
---------------------
- One canonical row per license (``bridge_token_states``) holding the
  current plaintext token (Fernet-encrypted), its monotonic ``version``,
  and a SHA-256 fingerprint we can safely log / show / compare.
- ``rotate_token(license, actor)`` — panel-side rotation.
- ``apply_customer_report(license, ...)`` — reverse-channel adoption with
  conflict resolution (higher version wins; on a tie the panel wins).
- ``serialize_for_contract(license)`` — the block the runtime-contract
  pull response carries so the customer converges automatically on next
  poll.
- ``verify_signing_secret(license, candidate_secret)`` — used by
  ``app.license_signing.verify_license_signature`` so a signature made
  with the *current* bridge token validates, alongside the legacy
  derived secret.

Security invariants
-------------------
- Plaintext token never lives in DB or logs. Only the Fernet ciphertext
  and the SHA-256 fingerprint are persisted.
- Plaintext leaves the panel ONLY over HTTPS-guarded, signed integration
  responses (runtime-contract pull) or the one-shot admin rotation API
  response (super-admin-only, audited).
- Fingerprint comparison uses ``hmac.compare_digest``.
- Bootstrap seed is the existing derived ``license_integration_secret``
  (so existing customers do not break the first time they poll after
  this lands).
- Respects [[chr-creds-must-stay-central]]: this secret is the BRIDGE
  auth secret, not a central CHR/admin secret; the customer side still
  never sees CHR or admin credentials.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets as _secrets
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable

from flask import current_app

from ..extensions import db
from ..license_signing import license_integration_secret
from ..models import License, TimestampMixin, utcnow
from .customer_vault_crypto import (
    VaultCryptoError,
    decrypt_secret,
    encrypt_secret,
    encryption_available,
)


logger = logging.getLogger(__name__)

#: Where the rotation came from. Stored on the row so the audit log
#: shows which side initiated each version bump.
ROTATION_SOURCES: tuple[str, ...] = ("bootstrap", "panel", "customer")


# ════════════════════════════════════════════════════════════════════════════
# ORM model
# ════════════════════════════════════════════════════════════════════════════
class BridgeTokenState(TimestampMixin, db.Model):
    """One row per license. The canonical store for the bridge token.

    ``token_ciphertext`` carries a Fernet-encrypted plaintext token. The
    project's vault key (``CUSTOMER_VAULT_ENCRYPTION_KEY``) wraps it —
    same crypto layer the customer vault + WhatsApp settings already use.

    ``token_fingerprint`` is the SHA-256 hex of the plaintext, lowercased.
    Safe to display and log (8-char prefix is plenty for UI). Both sides
    compute it identically so a fingerprint match proves the two stores
    hold the same value WITHOUT ever sending plaintext alongside.
    """

    __tablename__ = "bridge_token_states"

    id = db.Column(db.Integer, primary_key=True)
    license_id = db.Column(
        db.Integer, db.ForeignKey("licenses.id"), nullable=False,
        unique=True, index=True,
    )
    token_ciphertext = db.Column(db.Text, nullable=False)
    token_fingerprint = db.Column(db.String(64), nullable=False, index=True)
    version = db.Column(db.Integer, nullable=False, default=1)
    rotated_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    rotated_by = db.Column(db.String(20), nullable=False, default="bootstrap")
    last_seen_at = db.Column(db.DateTime)
    last_seen_fingerprint = db.Column(db.String(64), default="")

    license = db.relationship("License")

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return (
            f"<BridgeTokenState license_id={self.license_id} v{self.version} "
            f"fp={self.token_fingerprint[:8]}…>"
        )


# ════════════════════════════════════════════════════════════════════════════
# Public exception
# ════════════════════════════════════════════════════════════════════════════
class BridgeTokenError(RuntimeError):
    """Raised when the operation cannot proceed (missing key, bad input)."""

    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(message or code)
        self.code = code
        self.message = message or code


# ════════════════════════════════════════════════════════════════════════════
# Crypto helpers
# ════════════════════════════════════════════════════════════════════════════
def fingerprint_of(plaintext: str) -> str:
    """Return the canonical fingerprint (SHA-256 hex, lowercase) of a token.

    Safe to log/display: it cannot be reversed and a leak alone does not
    let an attacker forge a signature.
    """
    if not isinstance(plaintext, str):
        raise BridgeTokenError("invalid_token", "token must be a string")
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def fingerprints_equal(a: str, b: str) -> bool:
    """Constant-time equality for fingerprints (defence-in-depth)."""
    a = (a or "").strip().lower()
    b = (b or "").strip().lower()
    if not a or not b:
        return False
    return hmac.compare_digest(a, b)


def _generate_plaintext() -> str:
    """Generate a fresh bridge token. 32 url-safe bytes ≈ 256 bits.

    URL-safe so it round-trips through JSON / headers / log redactors
    cleanly. Long enough that brute force is not a credible threat even
    if the fingerprint were to leak.
    """
    return _secrets.token_urlsafe(32)


def _encrypt(plaintext: str) -> str:
    """Wrap the plaintext at rest. Refuses an empty plaintext."""
    if not plaintext:
        raise BridgeTokenError("empty_token", "refusing to store empty token")
    if not encryption_available():
        raise BridgeTokenError(
            "vault_unavailable",
            "CUSTOMER_VAULT_ENCRYPTION_KEY missing — cannot persist bridge token",
        )
    try:
        return encrypt_secret(plaintext)
    except VaultCryptoError as exc:
        raise BridgeTokenError("vault_unavailable", str(exc)) from exc


def _decrypt(ciphertext: str) -> str:
    if not ciphertext:
        return ""
    try:
        return decrypt_secret(ciphertext)
    except VaultCryptoError as exc:
        raise BridgeTokenError("vault_unavailable", str(exc)) from exc


# ════════════════════════════════════════════════════════════════════════════
# Lookup / bootstrap
# ════════════════════════════════════════════════════════════════════════════
def _bootstrap_seed_for(license: License) -> str:
    """Initial plaintext for an unseeded license.

    We DELIBERATELY reuse ``license_integration_secret`` as the bootstrap
    seed. Why: customers already activated on the legacy path have that
    value saved as their shared secret. Seeding the new canonical store
    with the same string makes the cutover invisible — the customer's
    saved secret keeps validating signatures until the next rotation.

    Empty fall-back (when the root HMAC secret is unset, e.g. dev /
    tests) → a freshly-generated random token. The bridge still works;
    only the "legacy values keep validating" property is lost.
    """
    seed = license_integration_secret(current_app, license.license_key)
    return seed or _generate_plaintext()


def get_state(license: License) -> BridgeTokenState | None:
    """Return the row for this license, or ``None`` if not bootstrapped yet."""
    if license is None or license.id is None:
        return None
    return BridgeTokenState.query.filter_by(license_id=license.id).first()


def ensure_state(license: License) -> BridgeTokenState:
    """Return the state row, creating it (with the bootstrap seed) if absent.

    Idempotent. Caller is responsible for ``db.session.commit()``.
    """
    state = get_state(license)
    if state is not None:
        return state
    plaintext = _bootstrap_seed_for(license)
    state = BridgeTokenState(
        license_id=license.id,
        token_ciphertext=_encrypt(plaintext),
        token_fingerprint=fingerprint_of(plaintext),
        version=1,
        rotated_at=utcnow(),
        rotated_by="bootstrap",
        last_seen_at=None,
        last_seen_fingerprint="",
    )
    db.session.add(state)
    db.session.flush()
    logger.info(
        "bridge_token: bootstrapped license_id=%s v=%s fp=%s",
        license.id, state.version, state.token_fingerprint[:8],
    )
    return state


def current_plaintext(license: License) -> str:
    """Decrypted bridge token for the license. Bootstraps on first call.

    Plaintext is returned only to callers that need to deliver it over a
    signed, HTTPS-guarded response (the runtime-contract builder) or to
    a super-admin in the rotation response. Never log it.
    """
    state = ensure_state(license)
    return _decrypt(state.token_ciphertext)


# ════════════════════════════════════════════════════════════════════════════
# Rotation paths (panel + customer)
# ════════════════════════════════════════════════════════════════════════════
@dataclass(frozen=True)
class RotationResult:
    """Outcome envelope shared by ``rotate_token`` and ``apply_customer_report``."""

    state: BridgeTokenState
    plaintext: str
    version: int
    fingerprint: str
    rotated_at: datetime
    rotated_by: str
    outcome: str   # "rotated" | "no_change" | "adopted_customer" | "panel_wins" | "stale_report"


def rotate_token(license: License, *, actor: str) -> RotationResult:
    """Panel-side rotation. Generates a new plaintext, bumps the version.

    ``actor`` is ``"panel"`` for the admin button and ``"bootstrap"`` for
    forced internal resets. The result's plaintext is for one-time
    delivery to the actor; do not persist it elsewhere.
    """
    if actor not in {"panel", "bootstrap"}:
        raise BridgeTokenError("invalid_actor", f"unexpected actor {actor!r}")
    state = ensure_state(license)
    new_plain = _generate_plaintext()
    state.token_ciphertext = _encrypt(new_plain)
    state.token_fingerprint = fingerprint_of(new_plain)
    state.version = (state.version or 0) + 1
    state.rotated_at = utcnow()
    state.rotated_by = actor
    db.session.flush()
    logger.info(
        "bridge_token: rotated license_id=%s by=%s v=%s fp=%s",
        license.id, actor, state.version, state.token_fingerprint[:8],
    )
    return RotationResult(
        state=state, plaintext=new_plain,
        version=state.version, fingerprint=state.token_fingerprint,
        rotated_at=state.rotated_at, rotated_by=state.rotated_by,
        outcome="rotated",
    )


def apply_customer_report(
    license: License,
    *,
    claimed_token: str,
    claimed_version: int | None,
    claimed_fingerprint: str | None,
) -> RotationResult:
    """Adopt (or reject) a customer-reported bridge token.

    Conflict resolver (the operative rule):

      * ``claimed_version > current.version`` ⇒ adopt the customer's
        token at ``claimed_version``. The customer rotated locally; the
        panel converges. Outcome ``"adopted_customer"``.
      * ``claimed_version == current.version`` AND fingerprints match ⇒
        no-op heartbeat. The customer is just confirming. Outcome
        ``"no_change"``.
      * ``claimed_version == current.version`` AND fingerprints differ ⇒
        the **panel wins**. Customer should overwrite with the panel's
        current token. Outcome ``"panel_wins"``.
      * ``claimed_version < current.version`` ⇒ stale report; the
        customer is behind. Panel returns current so the customer can
        catch up. Outcome ``"stale_report"``.
    """
    if not isinstance(claimed_token, str) or len(claimed_token) < 16:
        raise BridgeTokenError("invalid_token", "claimed_token missing or too short")
    state = ensure_state(license)

    claimed_fp = (claimed_fingerprint or fingerprint_of(claimed_token)).strip().lower()
    if claimed_fingerprint and not fingerprints_equal(
        claimed_fingerprint, fingerprint_of(claimed_token)
    ):
        # The customer's own fingerprint disagrees with the plaintext they
        # sent — corruption in flight or a buggy emitter. Reject loudly.
        raise BridgeTokenError(
            "fingerprint_mismatch",
            "claimed_fingerprint does not match SHA-256(claimed_token)",
        )

    try:
        cv = int(claimed_version) if claimed_version is not None else 0
    except (TypeError, ValueError):
        raise BridgeTokenError("invalid_version", "claimed_version must be int")

    now = utcnow()
    current_v = int(state.version or 0)

    if cv > current_v:
        state.token_ciphertext = _encrypt(claimed_token)
        state.token_fingerprint = claimed_fp
        state.version = cv
        state.rotated_at = now
        state.rotated_by = "customer"
        state.last_seen_at = now
        state.last_seen_fingerprint = claimed_fp
        db.session.flush()
        logger.info(
            "bridge_token: adopted customer rotation license_id=%s v=%s fp=%s",
            license.id, state.version, state.token_fingerprint[:8],
        )
        return RotationResult(
            state=state, plaintext=claimed_token,
            version=state.version, fingerprint=state.token_fingerprint,
            rotated_at=state.rotated_at, rotated_by=state.rotated_by,
            outcome="adopted_customer",
        )

    # cv <= current_v — panel does NOT change ciphertext.
    panel_plain = _decrypt(state.token_ciphertext)
    panel_fp = state.token_fingerprint or fingerprint_of(panel_plain)

    if cv == current_v and fingerprints_equal(claimed_fp, panel_fp):
        outcome = "no_change"
        logger.info(
            "bridge_token: customer heartbeat license_id=%s v=%s fp=%s",
            license.id, current_v, panel_fp[:8],
        )
    elif cv == current_v:
        outcome = "panel_wins"
        logger.info(
            "bridge_token: panel wins same-version mismatch license_id=%s v=%s",
            license.id, current_v,
        )
    else:
        outcome = "stale_report"
        logger.info(
            "bridge_token: stale customer report license_id=%s claimed_v=%s current_v=%s",
            license.id, cv, current_v,
        )

    state.last_seen_at = now
    state.last_seen_fingerprint = claimed_fp
    db.session.flush()
    return RotationResult(
        state=state, plaintext=panel_plain,
        version=state.version, fingerprint=state.token_fingerprint,
        rotated_at=state.rotated_at, rotated_by=state.rotated_by,
        outcome=outcome,
    )


# ════════════════════════════════════════════════════════════════════════════
# Contract serialisation (panel → customer)
# ════════════════════════════════════════════════════════════════════════════
def serialize_for_contract(license: License) -> dict[str, Any]:
    """Block dropped into the runtime-contract pull response.

    The customer reads this each poll and overwrites its local copy when
    its ``version`` is below the panel's. Shape::

        "bridge_token": {
            "token":        "<plaintext>",
            "version":      3,
            "fingerprint":  "<sha256-hex>",
            "rotated_at":   "...Z",
            "rotated_by":   "panel" | "customer" | "bootstrap"
        }
    """
    state = ensure_state(license)
    plaintext = _decrypt(state.token_ciphertext)
    return {
        "token": plaintext,
        "version": int(state.version),
        "fingerprint": state.token_fingerprint,
        "rotated_at": state.rotated_at.isoformat() + "Z" if state.rotated_at else None,
        "rotated_by": state.rotated_by or "bootstrap",
    }


def serialize_for_admin(license: License) -> dict[str, Any]:
    """Safe (no-plaintext) shape for the admin UI.

    Only the 8-char fingerprint prefix + version + timestamps. The
    rotation API response is the only place the plaintext is delivered
    to a human operator.
    """
    state = get_state(license)
    if state is None:
        return {
            "exists": False,
            "version": 0,
            "fingerprint": "",
            "fingerprint_prefix": "",
            "rotated_at": None,
            "rotated_by": "",
            "last_seen_at": None,
            "last_seen_fingerprint_prefix": "",
        }
    return {
        "exists": True,
        "version": int(state.version),
        "fingerprint": state.token_fingerprint,
        "fingerprint_prefix": (state.token_fingerprint or "")[:8],
        "rotated_at": state.rotated_at.isoformat() + "Z" if state.rotated_at else None,
        "rotated_by": state.rotated_by or "",
        "last_seen_at": state.last_seen_at.isoformat() + "Z" if state.last_seen_at else None,
        "last_seen_fingerprint_prefix": (state.last_seen_fingerprint or "")[:8],
    }


# ════════════════════════════════════════════════════════════════════════════
# Signature-verify integration
# ════════════════════════════════════════════════════════════════════════════
def verify_signing_secret(license: License, candidate_secret: str) -> bool:
    """True iff ``candidate_secret`` equals the current bridge token.

    Called from ``app.license_signing.verify_license_signature`` as the
    THIRD accepted secret after the global root and the legacy derived
    per-license secret. Constant-time comparison.
    """
    if not license or not candidate_secret:
        return False
    state = get_state(license)
    if state is None:
        return False
    try:
        current = _decrypt(state.token_ciphertext)
    except BridgeTokenError:
        # If the vault key is missing we cannot prove equality —
        # fall through to the legacy paths.
        return False
    if not current:
        return False
    return hmac.compare_digest(candidate_secret, current)


def signing_secrets_for(license: License) -> Iterable[str]:
    """Iterator over every plaintext secret that the panel will accept
    as a signing key for this license.

    Used by ``verify_license_signature`` so the caller doesn't need to
    know about ``BridgeTokenState``. The list is short-circuited as soon
    as the signature matches.
    """
    if license is None:
        return
    state = get_state(license)
    if state is None:
        return
    try:
        current = _decrypt(state.token_ciphertext)
    except BridgeTokenError:
        return
    if current:
        yield current


__all__ = [
    "ROTATION_SOURCES",
    "BridgeTokenError",
    "BridgeTokenState",
    "RotationResult",
    "apply_customer_report",
    "current_plaintext",
    "ensure_state",
    "fingerprint_of",
    "fingerprints_equal",
    "get_state",
    "rotate_token",
    "serialize_for_admin",
    "serialize_for_contract",
    "signing_secrets_for",
    "verify_signing_secret",
]
