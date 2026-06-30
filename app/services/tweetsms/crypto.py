"""Fernet encryption for the OWNER's TweetSMS credentials.

Mirrors ``services/firebase_fcm._fernet``: prefer an explicit key
(``TWEETSMS_FERNET_KEY`` → ``WHATSAPP_FERNET_KEY``), else derive a stable key
from the Flask ``SECRET_KEY`` so the panel works out of the box without a hard
failure. Secrets (api_key, pass) are stored encrypted at rest — never plaintext,
never logged. ``mask_secret`` is reused from the WhatsApp crypto module.
"""
from __future__ import annotations

import base64
import hashlib

from flask import current_app

from ..whatsapp.crypto import mask_secret  # noqa: F401 — re-exported for callers


def _fernet():
    from cryptography.fernet import Fernet

    app = current_app
    explicit = (
        str(app.config.get("TWEETSMS_FERNET_KEY") or "").strip()
        or str(app.config.get("WHATSAPP_FERNET_KEY") or "").strip()
    )
    if explicit:
        key = explicit.encode("utf-8")
    else:
        secret = str(app.config.get("SECRET_KEY") or "hoberadius").encode("utf-8")
        key = base64.urlsafe_b64encode(hashlib.sha256(secret).digest())
    return Fernet(key)


def encrypt_secret(plaintext: str) -> str:
    """Encrypt a secret → Fernet token string. Empty input → ""."""
    if not plaintext:
        return ""
    return _fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_secret(token: str) -> str:
    """Decrypt a Fernet token → plaintext. Empty/invalid input → "" (never raises
    so a corrupt value degrades to "unset" rather than a 500)."""
    if not token:
        return ""
    try:
        return _fernet().decrypt(token.encode("ascii")).decode("utf-8")
    except Exception:  # noqa: BLE001 — corrupt/tampered ciphertext → treat as unset
        return ""
