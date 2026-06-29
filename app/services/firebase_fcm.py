"""Central Firebase Cloud Messaging (FCM) authority for the LICENSING panel.

The HobeRadius mobile app is ONE global app (``com.hoberadius.app``) that
connects to ALL customer radius instances, backed by a single CENTRAL Firebase
project (``hoberadius``). So the Firebase service-account credential and the
FCM sender live HERE, in the licensing panel — never in a per-customer radius
panel. Customer radius panels FORWARD push requests over the signed bridge;
this module performs the actual send.

This mirrors the centralized Google Drive model (``services/google_drive.py``):
the owner uploads the credential from Settings → integrations, it is stored
securely server-side, and a lazily-imported sender uses it. The app boots fine
without the credential or the ``firebase-admin`` package (status reports the
gap; sending is a graceful no-op).

Credential storage (secret)
---------------------------
The uploaded ``firebase-admin-sdk.json`` is a SECRET (it holds a private key).
It is NEVER committed and NEVER rendered back. It is stored two ways:

  1. A chmod-600 file under ``instance/firebase/firebase-admin-sdk.json``
     (the instance dir is gitignored, beside the live DB). This is the
     source of truth the sender reads.
  2. An ENCRYPTED (Fernet) copy in the ``settings`` table
     (``firebase_admin_sdk_json_enc``) for disaster recovery — so the file can
     be regenerated if the instance volume is lost. Public, non-secret
     identity fields (project_id / client_email / uploaded_at) are stored as
     plain settings for the masked status display.

Only the masked status is ever exposed (project_id + masked client_email).
"""
from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence, Tuple

from flask import Flask, current_app

from ..extensions import db
from ..models import Setting

_LOG = logging.getLogger(__name__)

# Secret credential filename under instance/firebase/.
CRED_FILENAME = "firebase-admin-sdk.json"

# Settings keys. The encrypted JSON is the only secret; the rest are public
# identity fields shown in the masked status.
_K_JSON_ENC = "firebase_admin_sdk_json_enc"
_K_PROJECT = "firebase_project_id"
_K_EMAIL = "firebase_client_email"
_K_UPLOADED = "firebase_uploaded_at"

# Required fields of a valid Firebase service-account JSON.
_REQUIRED_FIELDS = ("type", "project_id", "private_key", "client_email")

# Optional manual kill-switch (credential present but sending disabled).
_DISABLE_ENV_VAR = "HOBERADIUS_FCM_DISABLED"

# Lazy firebase_admin app init state (per process), lock-guarded.
_lock = threading.Lock()
_init_done = False
_enabled = False
_fb_app = None  # firebase_admin.App


class FirebaseCredentialError(Exception):
    """Raised when an uploaded credential is not a valid service account."""


# ── credential storage location ─────────────────────────────────────────
def _cred_dir() -> Path:
    root = Path(current_app.instance_path) / "firebase"
    root.mkdir(parents=True, exist_ok=True)
    return root


def stored_file_path() -> Path:
    return _cred_dir() / CRED_FILENAME


# ── settings helpers (Setting table) ────────────────────────────────────
def _setting(key: str, default: str = "") -> str:
    row = db.session.get(Setting, key)
    return (row.value if row and row.value else "") or default


def _set_setting(key: str, value: str) -> None:
    row = db.session.get(Setting, key)
    if not row:
        row = Setting(key=key)
    row.value = value or ""
    db.session.add(row)


# ── encryption (Fernet) — mirrors google_drive._fernet ──────────────────
def _fernet():
    from cryptography.fernet import Fernet
    import base64
    import hashlib

    app = current_app
    explicit = (
        str(app.config.get("FIREBASE_FERNET_KEY") or "").strip()
        or str(app.config.get("WHATSAPP_FERNET_KEY") or "").strip()
    )
    if explicit:
        key = explicit.encode("utf-8")
    else:
        # Derive a stable Fernet key from the Flask SECRET_KEY so the encrypted
        # recovery copy works out of the box (the chmod-600 file is the primary
        # source of truth regardless).
        secret = str(app.config.get("SECRET_KEY") or "hoberadius").encode("utf-8")
        key = base64.urlsafe_b64encode(hashlib.sha256(secret).digest())
    return Fernet(key)


# ── validation ──────────────────────────────────────────────────────────
def validate_service_account(raw: bytes) -> Tuple[bool, Optional[dict], str]:
    """Validate that ``raw`` is a real Firebase service-account JSON.

    Returns ``(ok, data, arabic_error)``. ``data`` is None on rejection.
    """
    try:
        text = raw.decode("utf-8")
    except Exception:  # noqa: BLE001
        return False, None, "تعذّر قراءة الملفّ كنصّ UTF-8."
    try:
        data = json.loads(text)
    except Exception:  # noqa: BLE001
        return False, None, "الملفّ ليس JSON صالحًا."
    if not isinstance(data, dict):
        return False, None, "بنية الملفّ غير صحيحة (يُتوقَّع كائن JSON)."
    if str(data.get("type") or "").strip() != "service_account":
        return False, None, "هذا ليس ملفّ حساب خدمة Firebase (type ≠ service_account)."
    missing = [f for f in _REQUIRED_FIELDS if not str(data.get(f) or "").strip()]
    if missing:
        return False, None, "الملفّ ينقصه حقول حساب الخدمة: " + "، ".join(missing) + "."
    if "PRIVATE KEY" not in str(data.get("private_key") or ""):
        return False, None, "المفتاح الخاصّ في الملفّ غير صالح."
    return True, data, ""


# ── store / clear ───────────────────────────────────────────────────────
def store_uploaded(raw: bytes) -> dict:
    """Validate + store an uploaded credential (chmod-600 file + encrypted DB
    recovery copy + public identity settings).

    Raises :class:`FirebaseCredentialError` (Arabic message) on an invalid
    file. Returns a safe-to-display ``{project_id, client_email}`` on success.
    """
    ok, data, err = validate_service_account(raw)
    if not ok or data is None:
        raise FirebaseCredentialError(err or "ملفّ اعتماد غير صالح.")

    # (1) Write the secret file atomically + restrict perms.
    path = stored_file_path()
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(raw)
    os.replace(tmp, path)
    try:  # best-effort; chmod is a no-op on Windows.
        os.chmod(path, 0o600)
    except Exception:  # noqa: BLE001
        pass

    # (2) Encrypted recovery copy + public identity fields in settings.
    from datetime import datetime, timezone
    try:
        enc = _fernet().encrypt(raw).decode("ascii")
        _set_setting(_K_JSON_ENC, enc)
    except Exception:  # noqa: BLE001 — file already written; recovery is best-effort
        _LOG.warning("FCM credential DB recovery copy failed (file written)", exc_info=True)
    _set_setting(_K_PROJECT, str(data.get("project_id") or ""))
    _set_setting(_K_EMAIL, str(data.get("client_email") or ""))
    _set_setting(_K_UPLOADED, datetime.now(timezone.utc).isoformat())
    db.session.commit()

    reset_for_test()  # pick up the new credential on next send
    return {"project_id": str(data.get("project_id") or ""),
            "client_email": str(data.get("client_email") or "")}


def clear() -> bool:
    """Remove the stored credential (file + encrypted copy + identity fields)."""
    removed = False
    path = stored_file_path()
    try:
        if path.is_file():
            path.unlink()
            removed = True
    except Exception:  # noqa: BLE001
        pass
    for k in (_K_JSON_ENC, _K_PROJECT, _K_EMAIL, _K_UPLOADED):
        _set_setting(k, "")
    db.session.commit()
    reset_for_test()
    return removed


# ── credential resolution (file → encrypted DB copy → env) ──────────────
def resolve_credential_path() -> str:
    """Return a usable credential file path, or '' if none is configured.

    Order: (1) uploaded file in instance/firebase/ → (2) decrypt the DB
    recovery copy and rewrite the file → (3) env (GOOGLE_APPLICATION_CREDENTIALS
    / FIREBASE_CREDENTIALS_PATH) for compatibility.
    """
    path = stored_file_path()
    if path.is_file():
        return str(path)
    enc = _setting(_K_JSON_ENC)
    if enc.strip():
        try:
            raw = _fernet().decrypt(enc.encode("ascii"))
            path.write_bytes(raw)
            try:
                os.chmod(path, 0o600)
            except Exception:  # noqa: BLE001
                pass
            return str(path)
        except Exception:  # noqa: BLE001
            _LOG.warning("FCM credential restore-from-DB failed", exc_info=True)
    for var in ("FIREBASE_CREDENTIALS_PATH", "GOOGLE_APPLICATION_CREDENTIALS"):
        raw = (os.environ.get(var) or "").strip()
        if raw and os.path.isfile(raw):
            return raw
    return ""


# ── library probe + sender ──────────────────────────────────────────────
def library_available() -> bool:
    """Is ``firebase-admin`` importable on the server? Always safe to call."""
    try:
        import firebase_admin  # noqa: F401
        return True
    except Exception:  # noqa: BLE001
        return False


def _manually_disabled() -> bool:
    return (os.environ.get(_DISABLE_ENV_VAR) or "").strip().lower() in (
        "1", "true", "yes", "on")


def reset_for_test() -> None:
    """Reset the cached firebase_admin init (tests / after credential change)."""
    global _init_done, _enabled, _fb_app
    with _lock:
        _init_done = False
        _enabled = False
        _fb_app = None


def _ensure_init() -> bool:
    """Initialize the firebase_admin app once (lazy, cached). Returns whether
    the sender is enabled (package + credential + init all OK)."""
    global _init_done, _enabled, _fb_app
    if _init_done:
        return _enabled
    with _lock:
        if _init_done:
            return _enabled
        _init_done = True
        _enabled = False

        if _manually_disabled():
            _LOG.info("FCM disabled via %s", _DISABLE_ENV_VAR)
            return False
        path = resolve_credential_path()
        if not path:
            _LOG.info("FCM disabled: no Firebase credential uploaded/configured")
            return False
        try:
            import firebase_admin
            from firebase_admin import credentials
        except Exception as exc:  # noqa: BLE001 — package not installed
            _LOG.info("FCM disabled: firebase-admin not importable (%s)", exc)
            return False
        try:
            cred = credentials.Certificate(path)
            try:
                _fb_app = firebase_admin.get_app("hoberadius-fcm")
            except ValueError:
                _fb_app = firebase_admin.initialize_app(cred, name="hoberadius-fcm")
            _enabled = True
            _LOG.info("FCM enabled (credential: %s)", path)
        except Exception as exc:  # noqa: BLE001 — init failed → disable quietly
            _LOG.warning("FCM disabled: init failed (%s)", exc)
            _enabled = False
        return _enabled


def is_enabled() -> bool:
    """Is the sender ready (credential present + init OK)? Always safe to call."""
    try:
        return _ensure_init()
    except Exception:  # noqa: BLE001
        return False


def is_configured() -> bool:
    """Is a credential stored (file or encrypted DB copy)? (May be configured
    even when ``firebase-admin`` is not yet installed.)"""
    try:
        if stored_file_path().is_file():
            return True
        return bool(_setting(_K_JSON_ENC).strip())
    except Exception:  # noqa: BLE001
        return False


def _coerce_data(data: Optional[Mapping[str, Any]]) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in (data or {}).items():
        if v is None:
            continue
        out[str(k)] = str(v)
    return out


def send_to_tokens(tokens: Sequence[str], title: str, body: str,
                   data: Optional[Mapping[str, Any]] = None) -> dict:
    """Send an FCM multicast to ``tokens``. Returns a diagnostic dict and NEVER
    raises: ``{ok, sent, failed, invalid_tokens, disabled?, reason}``.

    ``invalid_tokens`` are tokens FCM reported as unregistered/invalid so the
    caller can prune them. No-op (no network) when disabled or token-less.
    """
    toks = [str(t).strip() for t in (tokens or []) if str(t).strip()]
    if not toks:
        return {"ok": False, "disabled": False, "reason": "no_tokens",
                "sent": 0, "failed": 0, "invalid_tokens": []}
    if not is_enabled():
        return {"ok": False, "disabled": True, "reason": "fcm_disabled",
                "sent": 0, "failed": 0, "invalid_tokens": []}
    try:
        from firebase_admin import messaging
    except Exception as exc:  # noqa: BLE001
        _LOG.info("FCM send skipped: messaging import failed (%s)", exc)
        return {"ok": False, "disabled": True, "reason": "import_failed",
                "sent": 0, "failed": 0, "invalid_tokens": []}

    payload = _coerce_data(data)
    try:
        message = messaging.MulticastMessage(
            tokens=toks,
            notification=messaging.Notification(title=title or "", body=body or ""),
            data=payload,
        )
        sender = (getattr(messaging, "send_each_for_multicast", None)
                  or getattr(messaging, "send_multicast", None))
        if sender is None:  # pragma: no cover — defensive compat
            return {"ok": False, "disabled": True, "reason": "no_sender",
                    "sent": 0, "failed": 0, "invalid_tokens": []}
        resp = sender(message, app=_fb_app)
    except Exception as exc:  # noqa: BLE001 — network/server failure
        _LOG.warning("FCM send failed (%s)", exc)
        return {"ok": False, "disabled": False, "reason": "send_error",
                "sent": 0, "failed": len(toks), "invalid_tokens": []}

    invalid = _collect_invalid(resp, toks)
    success = int(getattr(resp, "success_count", 0) or 0)
    failure = int(getattr(resp, "failure_count", 0) or 0)
    return {"ok": True, "disabled": False, "reason": "sent",
            "sent": success, "failed": failure, "invalid_tokens": invalid}


def _collect_invalid(resp, tokens: Sequence[str]) -> list[str]:
    invalid: list[str] = []
    for idx, r in enumerate(list(getattr(resp, "responses", None) or [])):
        if getattr(r, "success", False) or idx >= len(tokens):
            continue
        if _is_invalid_token_error(getattr(r, "exception", None)):
            invalid.append(tokens[idx])
    return invalid


def _is_invalid_token_error(exc) -> bool:
    if exc is None:
        return False
    try:
        from firebase_admin import messaging
        invalid_types = tuple(
            t for t in (
                getattr(messaging, "UnregisteredError", None),
                getattr(messaging, "SenderIdMismatchError", None),
            ) if t is not None
        )
        if invalid_types and isinstance(exc, invalid_types):
            return True
    except Exception:  # noqa: BLE001
        pass
    name = type(exc).__name__.lower()
    return ("unregistered" in name or "invalidargument" in name
            or "senderidmismatch" in name)


# ── masked status (never reveals the secret) ────────────────────────────
def _mask_email(email: str) -> str:
    email = (email or "").strip()
    if "@" not in email:
        return "—"
    local, _, domain = email.partition("@")
    head = local[:18] + ("…" if len(local) > 18 else "")
    return f"{head}@{domain}"


def status() -> dict:
    """Masked credential + sender status for the Settings UI. Never reveals the
    secret; reads identity fields from the actual file when possible."""
    out = {"configured": False, "enabled": False, "library_ok": False,
           "project_id": "", "client_email": "", "uploaded_at": ""}
    try:
        out["library_ok"] = library_available()
        out["uploaded_at"] = _setting(_K_UPLOADED)
        data: Optional[dict] = None
        path = stored_file_path()
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except Exception:  # noqa: BLE001
                data = None
        if isinstance(data, dict) and str(data.get("type") or "") == "service_account":
            out["configured"] = True
            out["project_id"] = str(data.get("project_id") or "")
            out["client_email"] = _mask_email(str(data.get("client_email") or ""))
        elif _setting(_K_JSON_ENC).strip():
            out["configured"] = True
            out["project_id"] = _setting(_K_PROJECT)
            out["client_email"] = _mask_email(_setting(_K_EMAIL))
        out["enabled"] = bool(out["configured"]) and is_enabled()
    except Exception:  # noqa: BLE001 — status never breaks the page
        return out
    return out


__all__ = [
    "CRED_FILENAME",
    "FirebaseCredentialError",
    "stored_file_path",
    "validate_service_account",
    "store_uploaded",
    "clear",
    "resolve_credential_path",
    "library_available",
    "is_enabled",
    "is_configured",
    "send_to_tokens",
    "reset_for_test",
    "status",
]
