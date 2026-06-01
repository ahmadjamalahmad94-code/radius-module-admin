from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken
from flask import current_app


class WhatsAppCryptoError(Exception):
    """Raised when a WhatsApp secret cannot be encrypted or decrypted."""


def _fernet() -> Fernet:
    """Build a Fernet from the configured key.

    Never falls back to a random/ephemeral key: doing so would silently make
    every previously-stored token unrecoverable after a process restart.
    """
    key = (current_app.config.get("WHATSAPP_FERNET_KEY") or "").strip()
    if not key:
        raise WhatsAppCryptoError("WHATSAPP_FERNET_KEY not configured")
    try:
        return Fernet(key.encode("utf-8") if isinstance(key, str) else key)
    except (ValueError, TypeError) as exc:
        raise WhatsAppCryptoError("WHATSAPP_FERNET_KEY not configured") from exc


def encrypt_secret(plaintext: str) -> str:
    """Encrypt a secret, returning a Fernet token string. Empty input -> ""."""
    if not plaintext:
        return ""
    token = _fernet().encrypt(plaintext.encode("utf-8"))
    return token.decode("utf-8")


def decrypt_secret(token: str) -> str:
    """Decrypt a Fernet token back to plaintext. Empty input -> "".

    Raises WhatsAppCryptoError on an invalid/tampered token.
    """
    if not token:
        return ""
    try:
        plaintext = _fernet().decrypt(
            token.encode("utf-8") if isinstance(token, str) else token
        )
    except InvalidToken as exc:
        raise WhatsAppCryptoError("Invalid or tampered WhatsApp secret") from exc
    return plaintext.decode("utf-8")


def mask_secret(value: str) -> str:
    """Mask a secret/token for display: first 4 + "…" + last 3.

    Works for either plaintext or an encrypted token (it only masks the
    string). Never reveals the middle. Returns "—" for empty input.
    """
    if not value:
        return "—"
    if len(value) <= 7:
        # Too short to safely show both ends without overlap; hide the middle.
        return value[:1] + "…"
    return f"{value[:4]}…{value[-3:]}"
