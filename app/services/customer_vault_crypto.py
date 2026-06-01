"""
Customer Secure Vault — encryption helpers (Fernet / AES-128-CBC + HMAC).

The key comes from CUSTOMER_VAULT_ENCRYPTION_KEY (environment only). It is never
stored in the database and never committed. If the key is missing or invalid,
encryption is unavailable: secret create/reveal must be blocked, but the rest of
the panel keeps working.

Never log plaintext secrets. Never persist plaintext anywhere.
"""
from __future__ import annotations

from flask import current_app


class VaultCryptoError(RuntimeError):
    """Raised when encryption/decryption cannot be performed."""


def _key() -> str:
    return str((current_app.config.get("CUSTOMER_VAULT_ENCRYPTION_KEY") or "")).strip()


def _fernet():
    from cryptography.fernet import Fernet

    key = _key()
    if not key:
        raise VaultCryptoError("CUSTOMER_VAULT_ENCRYPTION_KEY not configured")
    try:
        return Fernet(key.encode("utf-8"))
    except (ValueError, TypeError) as exc:  # malformed key
        raise VaultCryptoError("CUSTOMER_VAULT_ENCRYPTION_KEY is invalid") from exc


def encryption_available() -> bool:
    """True only when a valid Fernet key is configured."""
    try:
        _fernet()
        return True
    except VaultCryptoError:
        return False
    except Exception:  # pragma: no cover - defensive
        return False


def encrypt_secret(plaintext: str) -> str:
    """Encrypt a plaintext secret -> token string. Empty input is rejected."""
    if plaintext is None or plaintext == "":
        raise VaultCryptoError("Refusing to encrypt an empty secret")
    token = _fernet().encrypt(plaintext.encode("utf-8"))
    return token.decode("utf-8")


def decrypt_secret(ciphertext: str) -> str:
    """Decrypt a token string -> plaintext. Raises on tamper/invalid key."""
    from cryptography.fernet import InvalidToken

    if not ciphertext:
        return ""
    try:
        plaintext = _fernet().decrypt(ciphertext.encode("utf-8"))
    except InvalidToken as exc:
        raise VaultCryptoError("Invalid or tampered vault secret (wrong key?)") from exc
    return plaintext.decode("utf-8")


def mask_secret(value: str) -> str:
    """A safe, non-reversible preview of a secret for the UI / hints.

    Examples:
      - short password -> ••••••••
      - long token     -> EAAB••••9xQ
      - PEM key        -> -----BEGIN…KEY-----
    """
    if not value:
        return ""
    v = str(value)
    stripped = v.strip()
    if "-----BEGIN" in stripped:
        return "-----BEGIN…KEY-----"
    n = len(v)
    if n <= 8:
        return "•" * max(n, 6)
    head = v[:4]
    tail = v[-3:]
    return f"{head}••••{tail}"
