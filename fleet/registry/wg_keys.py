"""fleet.registry.wg_keys — Phase 3 task T2 (WireGuard keys).

Generates the control-tunnel (``wg-mgmt``) WireGuard keypair the panel mints
during onboarding (per ``docs/chr_fleet/06_ONBOARDING_WIZARD.md §6.3``).

Wire format
-----------
A WireGuard keypair is two 32-byte Curve25519 (X25519) keys, both encoded as
**base64** (Curve25519's RFC 7748 raw form, 44 chars including ``=`` padding).
Public keys are stored in ``fleet_chr_nodes.wg_mgmt_pubkey`` (plain text — it
IS public). Private keys are SECRET and MUST be passed to the vault layer
(:mod:`fleet.registry.secrets_vault`) via :func:`generate_keypair_with_vault`
so they never leave this module as a plaintext string longer than necessary,
and never touch disk in cleartext.

Why not shell out to ``wg genkey``?
-----------------------------------
The repo already depends on the ``cryptography`` package (it's how the
customer vault, WhatsApp embedded settings, and the panel's app master Fernet
key all work). Using ``X25519PrivateKey`` keeps the entropy source consistent,
avoids spawning a subprocess on every onboarding, and works on Windows where
``wg`` isn't installed by default.
"""
from __future__ import annotations

import base64
import dataclasses
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

if TYPE_CHECKING:  # pragma: no cover - typing only
    from fleet.registry.secrets_vault import VaultRef


#: WireGuard keys are base64-encoded 32-byte values → exactly 44 chars including
#: padding (32 bytes → 44 chars of urlsafe base64 with ``=`` padding for the
#: standard alphabet ``wg`` uses). This is a hard invariant we validate on.
WG_KEY_B64_LEN = 44
WG_KEY_RAW_LEN = 32


class WgKeyError(ValueError):
    """Raised when a WireGuard key fails structural validation."""


@dataclasses.dataclass(frozen=True)
class WgKeypair:
    """A freshly minted WireGuard keypair.

    * ``private_key`` is the Curve25519 private scalar, base64-encoded. This
      is the SECRET — callers must hand it to the secrets vault immediately
      and drop the in-memory copy.
    * ``public_key`` is the matching Curve25519 public point, base64-encoded.
      It's safe to log, persist plaintext, ship over the wire, etc.

    ``__repr__`` deliberately redacts the private half so an accidental
    ``log.info(kp)`` cannot leak it. ``str(kp)`` is the same.
    """

    private_key: str
    public_key: str

    def __repr__(self) -> str:
        return f"WgKeypair(public_key={self.public_key!r}, private_key='<redacted>')"

    __str__ = __repr__


# ───────────────────────── core generation ─────────────────────────

def generate_keypair() -> WgKeypair:
    """Generate a fresh Curve25519 keypair encoded in WireGuard's wire format.

    Uses ``cryptography``'s X25519 (the same Curve25519 RFC 7748 form
    WireGuard's userspace ``wg`` command emits) and base64-encodes both
    halves. The result satisfies WireGuard's validator:

    * Both keys are 44-char standard-alphabet base64 with ``=`` padding.
    * The private key's high three bits are cleared / the low three bits
      set (RFC 7748 §5 "clamping") — handled internally by the X25519
      primitive so we get a valid scalar by construction.
    """
    private = X25519PrivateKey.generate()
    private_raw = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_raw = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return WgKeypair(
        private_key=base64.b64encode(private_raw).decode("ascii"),
        public_key=base64.b64encode(public_raw).decode("ascii"),
    )


# ───────────────────────── validation ─────────────────────────

def is_valid_wg_key(value: str) -> bool:
    """True iff ``value`` is a structurally valid WG-format base64 key.

    A WireGuard key is exactly 32 raw bytes → 44 base64 chars (with one ``=``
    of padding). We re-base64-decode and check the length; we deliberately do
    NOT check the scalar's bit pattern here because a public key is just a
    point — not a clamped scalar — and using the same validator for both halves
    keeps callers simple. The X25519 primitive itself will reject malformed
    points when the key is actually used.
    """
    if not isinstance(value, str) or len(value) != WG_KEY_B64_LEN:
        return False
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error):
        return False
    return len(raw) == WG_KEY_RAW_LEN


def derive_public_key(private_b64: str) -> str:
    """Given a private key in WG/base64 form, return its matching public key.

    Useful when a private key was stored (in the vault) without its public
    counterpart — e.g. when verifying that the public key we persisted on
    ``fleet_chr_nodes.wg_mgmt_pubkey`` still matches the vault-stored secret.
    Raises :class:`WgKeyError` on a malformed input.
    """
    if not is_valid_wg_key(private_b64):
        raise WgKeyError("not a valid WireGuard base64 key (len/charset)")
    try:
        raw = base64.b64decode(private_b64, validate=True)
        priv = X25519PrivateKey.from_private_bytes(raw)
    except (ValueError, base64.binascii.Error) as exc:
        raise WgKeyError("malformed Curve25519 private key") from exc
    pub_raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(pub_raw).decode("ascii")


# ───────────────────────── integration with the vault ─────────────────────────

def generate_keypair_with_vault(owner: str, *, purpose: str = "wg_mgmt") -> tuple[str, "VaultRef"]:
    """Generate a keypair and SHIP the private key straight to the vault.

    Returns ``(public_key_b64, vault_ref)``. ``vault_ref`` is an opaque token
    the caller persists in ``fleet_onboarding_jobs.wg_keypair_ref``; the
    plaintext private key is dropped from memory inside this function and
    never returned to the caller.

    The ``owner`` is a stable, deterministic id of the CHR/job the secret
    belongs to (e.g. ``"chr:11"`` or ``"onboarding:42"``). It scopes the
    vault entry and makes the audit trail meaningful.

    ``purpose`` distinguishes multiple secrets per owner — the WG mgmt key,
    the WG data key, a bootstrap RouterOS password, etc.
    """
    # Imported lazily so this module can be tested for key correctness even
    # outside a Flask app context.
    from fleet.registry.secrets_vault import store_secret

    kp = generate_keypair()
    ref = store_secret(
        owner=owner,
        purpose=purpose,
        plaintext=kp.private_key,
        kind="wg_private_key",
    )
    # Public key is safe to return — caller stores it on the node row.
    return kp.public_key, ref


__all__ = [
    "WgKeypair",
    "WgKeyError",
    "WG_KEY_B64_LEN",
    "WG_KEY_RAW_LEN",
    "generate_keypair",
    "generate_keypair_with_vault",
    "is_valid_wg_key",
    "derive_public_key",
]
