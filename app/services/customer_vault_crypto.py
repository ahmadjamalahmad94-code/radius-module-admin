"""
Customer Secure Vault — encryption helpers (Fernet / AES-128-CBC + HMAC).

Resolution order for the vault key:
  1. DB-stored ``customer_vault.encryption_key`` (encrypted at rest with the
     panel's app master Fernet key — same wrapping as
     ``whatsapp_embedded.app_secret``).
  2. Environment ``CUSTOMER_VAULT_ENCRYPTION_KEY`` (legacy / bootstrap).

If neither is present (or both are invalid), encryption is unavailable: secret
create/reveal must be blocked, the rest of the panel keeps working, and the UI
shows a friendly empty-state pointing the operator to the Settings page.

Never log plaintext secrets. Never persist plaintext anywhere.
"""
from __future__ import annotations

from flask import current_app

from ..extensions import db
from ..models import Setting
from .whatsapp.crypto import (
    WhatsAppCryptoError,
    decrypt_secret as _app_decrypt,
    encrypt_secret as _app_encrypt,
    mask_secret as _mask,
)


VAULT_KEY_SETTING = "customer_vault.encryption_key"


class VaultCryptoError(RuntimeError):
    """Raised when encryption/decryption cannot be performed."""


# ───────────────────────── key resolution ─────────────────────────

def _db_value(key: str) -> str:
    row = db.session.get(Setting, key)
    return (row.value or "") if row else ""


def _set_db_value(key: str, value: str) -> None:
    row = db.session.get(Setting, key)
    if not row:
        row = Setting(key=key)
    row.value = value
    db.session.add(row)


def _key_from_db() -> str:
    """Return the plaintext vault Fernet key stored in the DB, or empty string.

    The value in the DB is a Fernet token wrapping the actual vault key. We
    unwrap it with the panel's app master Fernet key (``WHATSAPP_FERNET_KEY``).
    On any failure (missing app key, corrupt token) return empty so the caller
    falls back to the env key.
    """
    raw = _db_value(VAULT_KEY_SETTING)
    if not raw:
        return ""
    try:
        return _app_decrypt(raw).strip()
    except WhatsAppCryptoError:
        return ""
    except Exception:  # pragma: no cover - defensive
        return ""


def _key_from_env() -> str:
    return str((current_app.config.get("CUSTOMER_VAULT_ENCRYPTION_KEY") or "")).strip()


def _resolve_key() -> tuple[str, str]:
    """Return ``(plaintext_key, source)`` where source ∈ panel|env|unset."""
    panel = _key_from_db()
    if panel:
        return panel, "panel"
    env = _key_from_env()
    if env:
        return env, "env"
    return "", "unset"


def _key() -> str:
    return _resolve_key()[0]


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
    """True only when a valid Fernet key is configured (DB or env)."""
    try:
        _fernet()
        return True
    except VaultCryptoError:
        return False
    except Exception:  # pragma: no cover - defensive
        return False


# ───────────────────────── app master key probe ─────────────────────────

def app_master_key_ready() -> bool:
    """True iff the panel's app master Fernet key is configured.

    Storing a new vault key in the DB requires the app master key (it wraps
    the vault key at rest). We probe by encrypting a tiny string.
    """
    try:
        _app_encrypt("probe")
        return True
    except WhatsAppCryptoError:
        return False


# ───────────────────────── encrypt / decrypt vault secrets ─────────────────

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


# ───────────────────────── settings-UI helpers ─────────────────────────

def generate_fernet_key() -> str:
    """Return a freshly generated, base64-urlsafe Fernet key (44 chars)."""
    from cryptography.fernet import Fernet
    return Fernet.generate_key().decode("utf-8")


def is_valid_fernet_key(value: str) -> bool:
    """True iff ``value`` is a structurally valid Fernet key."""
    from cryptography.fernet import Fernet

    if not value:
        return False
    try:
        Fernet(value.strip().encode("utf-8"))
        return True
    except (ValueError, TypeError):
        return False


def vault_key_state() -> dict:
    """UI-safe snapshot of where the vault key lives and whether it works."""
    key, source = _resolve_key()
    return {
        "configured": bool(key),
        "source": source,                  # panel | env | unset
        "masked": _mask(key) if key else "—",
        "app_master_ready": app_master_key_ready(),
        "encryption_ok": encryption_available(),
    }


def save_vault_key_in_db(plaintext_key: str) -> None:
    """Validate a new vault Fernet key and persist it in the DB, encrypted at
    rest with the app master key.

    The caller commits the session and records an audit row. Raises
    :class:`VaultCryptoError` (Arabic-aware message) on validation failures.
    """
    plain = (plaintext_key or "").strip()
    if not plain:
        raise VaultCryptoError("لم يتم إدخال أي مفتاح.")
    if not is_valid_fernet_key(plain):
        raise VaultCryptoError(
            "المفتاح غير صالح — يجب أن يكون Fernet (base64-urlsafe بطول 32 بايت)."
        )
    if not app_master_key_ready():
        raise VaultCryptoError(
            "تخزين مفتاح الخزنة يتطلّب ضبط مفتاح التشفير العام للتطبيق "
            "(WHATSAPP_FERNET_KEY) في بيئة الخادم."
        )
    try:
        wrapped = _app_encrypt(plain)
    except WhatsAppCryptoError as exc:
        raise VaultCryptoError(str(exc)) from exc
    _set_db_value(VAULT_KEY_SETTING, wrapped)


def clear_vault_key_in_db() -> None:
    """Remove the DB-stored vault key. The caller commits + audits."""
    _set_db_value(VAULT_KEY_SETTING, "")
