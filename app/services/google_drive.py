"""Per-customer Google Drive OAuth + backup upload.

Each customer connects THEIR OWN Google account from the customer portal.
We request the least-privilege scope (drive.file), store the per-customer
refresh token ENCRYPTED (Fernet), and upload that customer's backups only to
their own Drive folder. Admins never see the raw token.

All Google libraries are imported lazily inside functions so the app boots
even before the libraries are installed (status will report "library missing").
"""
from __future__ import annotations

import base64
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Any

from flask import Flask, current_app, url_for

from ..extensions import db
from ..models import CustomerGoogleDrive, Setting, utcnow


SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/drive.file",
]
DEFAULT_FOLDER_NAME = "HobeRadius Backups"
_STATE_SALT = "hoberadius-gdrive-oauth"
_TOKEN_URI = "https://oauth2.googleapis.com/token"
_AUTH_URI = "https://accounts.google.com/o/oauth2/auth"
_REVOKE_URI = "https://oauth2.googleapis.com/revoke"


class GoogleDriveError(Exception):
    pass


# ── library availability ────────────────────────────────────────────
def libs_available() -> bool:
    try:
        import google_auth_oauthlib.flow  # noqa: F401
        import googleapiclient.discovery  # noqa: F401
        from google.oauth2.credentials import Credentials  # noqa: F401
        return True
    except Exception:
        return False


# ── configuration (Setting overrides env) ───────────────────────────
def _setting(key: str, default: str = "") -> str:
    row = db.session.get(Setting, key)
    return (row.value if row and row.value else "") or default


def oauth_client(app: Flask | None = None) -> tuple[str, str]:
    app = app or current_app
    cid = _setting("google_oauth_client_id") or str(app.config.get("GOOGLE_OAUTH_CLIENT_ID") or "")
    csec = _setting("google_oauth_client_secret") or str(app.config.get("GOOGLE_OAUTH_CLIENT_SECRET") or "")
    return cid.strip(), csec.strip()


def is_configured(app: Flask | None = None) -> bool:
    cid, csec = oauth_client(app)
    return bool(cid and csec)


def redirect_uri() -> str:
    override = _setting("google_oauth_redirect_uri")
    if override:
        return override.strip()
    return url_for("public.google_drive_callback", _external=True)


# ── encryption (Fernet) ─────────────────────────────────────────────
def _fernet():
    from cryptography.fernet import Fernet

    app = current_app
    explicit = str(app.config.get("GOOGLE_TOKEN_ENC_KEY") or "").strip()
    if explicit:
        key = explicit.encode("utf-8")
    else:
        # Derive a stable Fernet key from the Flask SECRET_KEY.
        secret = str(app.config.get("SECRET_KEY") or "hoberadius").encode("utf-8")
        key = base64.urlsafe_b64encode(hashlib.sha256(secret).digest())
    return Fernet(key)


def encrypt_token(plaintext: str) -> str:
    if not plaintext:
        return ""
    return _fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_token(ciphertext: str) -> str:
    if not ciphertext:
        return ""
    return _fernet().decrypt(ciphertext.encode("ascii")).decode("utf-8")


# ── OAuth state (signed customer id) ────────────────────────────────
def _serializer():
    from itsdangerous import URLSafeTimedSerializer

    return URLSafeTimedSerializer(str(current_app.config.get("SECRET_KEY") or ""), salt=_STATE_SALT)


def make_state(customer_id: int) -> str:
    return _serializer().dumps(int(customer_id))


def read_state(state: str, max_age: int = 600) -> int | None:
    try:
        return int(_serializer().loads(state, max_age=max_age))
    except Exception:
        return None


# ── OAuth flow ──────────────────────────────────────────────────────
def _flow(state: str | None = None):
    from google_auth_oauthlib.flow import Flow

    cid, csec = oauth_client()
    cfg = {
        "web": {
            "client_id": cid,
            "client_secret": csec,
            "auth_uri": _AUTH_URI,
            "token_uri": _TOKEN_URI,
            "redirect_uris": [redirect_uri()],
        }
    }
    flow = Flow.from_client_config(cfg, scopes=SCOPES, state=state)
    flow.redirect_uri = redirect_uri()
    return flow


def authorization_url(customer_id: int) -> tuple[str, str]:
    """Return (auth_url, code_verifier). The verifier MUST be kept (session)
    and passed to exchange_callback, or Google rejects with 'Missing code
    verifier' (PKCE)."""
    flow = _flow(state=make_state(customer_id))
    url, _ = flow.authorization_url(
        access_type="offline", prompt="consent", include_granted_scopes="true"
    )
    return url, getattr(flow, "code_verifier", None) or ""


def exchange_callback(authorization_response_url: str, code_verifier: str = "") -> tuple[str, str]:
    """Exchange the OAuth callback for (refresh_token, google_email)."""
    flow = _flow()
    if code_verifier:
        flow.code_verifier = code_verifier
    flow.fetch_token(authorization_response=authorization_response_url)
    creds = flow.credentials
    refresh_token = getattr(creds, "refresh_token", "") or ""
    if not refresh_token:
        raise GoogleDriveError("لم يصل refresh token من Google. أعد المحاولة مع منح الصلاحية الكاملة.")
    email = _fetch_email(creds)
    return refresh_token, email


def _fetch_email(creds) -> str:
    try:
        from googleapiclient.discovery import build

        svc = build("oauth2", "v2", credentials=creds, cache_discovery=False)
        info = svc.userinfo().get().execute()
        return str(info.get("email") or "")
    except Exception:
        return ""


def _credentials_from_refresh(refresh_token: str):
    from google.oauth2.credentials import Credentials
    from google.auth.transport.requests import Request

    cid, csec = oauth_client()
    creds = Credentials(
        token=None,
        refresh_token=refresh_token,
        token_uri=_TOKEN_URI,
        client_id=cid,
        client_secret=csec,
        scopes=SCOPES,
    )
    creds.refresh(Request())
    return creds


def _drive_service(creds):
    from googleapiclient.discovery import build

    return build("drive", "v3", credentials=creds, cache_discovery=False)


# ── connection record helpers ───────────────────────────────────────
def get_connection(customer_id: int) -> CustomerGoogleDrive | None:
    return CustomerGoogleDrive.query.filter_by(customer_id=int(customer_id)).first()


def store_connection(customer_id: int, *, refresh_token: str, email: str) -> CustomerGoogleDrive:
    conn = get_connection(customer_id) or CustomerGoogleDrive(customer_id=int(customer_id))
    conn.refresh_token_enc = encrypt_token(refresh_token)
    conn.google_email = (email or "")[:255]
    conn.connected = True
    conn.scopes = " ".join(SCOPES)[:500]
    conn.connected_at = utcnow()
    conn.last_error = ""
    db.session.add(conn)
    db.session.commit()
    return conn


def disconnect(customer_id: int) -> bool:
    conn = get_connection(customer_id)
    if not conn:
        return False
    token = ""
    try:
        token = decrypt_token(conn.refresh_token_enc)
    except Exception:
        token = ""
    if token:
        try:
            import urllib.parse
            import urllib.request

            data = urllib.parse.urlencode({"token": token}).encode("ascii")
            req = urllib.request.Request(_REVOKE_URI, data=data, method="POST")
            urllib.request.urlopen(req, timeout=8)
        except Exception:
            pass
    conn.connected = False
    conn.refresh_token_enc = ""
    conn.folder_id = ""
    conn.connected_at = None
    db.session.add(conn)
    db.session.commit()
    return True


def _ensure_folder(service, conn: CustomerGoogleDrive) -> str:
    """Return a valid Drive folder id, creating the app folder if needed."""
    if conn.folder_id:
        try:
            service.files().get(fileId=conn.folder_id, fields="id, trashed").execute()
            return conn.folder_id
        except Exception:
            pass  # folder gone — recreate
    meta = {"name": conn.folder_name or DEFAULT_FOLDER_NAME, "mimeType": "application/vnd.google-apps.folder"}
    created = service.files().create(body=meta, fields="id").execute()
    conn.folder_id = created["id"]
    db.session.add(conn)
    db.session.commit()
    return conn.folder_id


def upload_backup(customer_id: int, file_path: str | Path, filename: str) -> dict[str, Any]:
    """Upload a backup file to the customer's own Drive folder.

    Returns {ok, file_id|error}. Never raises to the caller's flow.
    """
    if not libs_available():
        return {"ok": False, "error": "google_libs_missing"}
    conn = get_connection(customer_id)
    if not conn or not conn.connected or not conn.refresh_token_enc:
        return {"ok": False, "error": "not_connected"}
    path = Path(file_path)
    if not path.exists():
        return {"ok": False, "error": "file_missing"}
    try:
        from googleapiclient.http import MediaFileUpload

        creds = _credentials_from_refresh(decrypt_token(conn.refresh_token_enc))
        service = _drive_service(creds)
        folder_id = _ensure_folder(service, conn)
        media = MediaFileUpload(str(path), mimetype="application/x-sqlite3", resumable=False)
        meta = {"name": filename, "parents": [folder_id]}
        created = service.files().create(body=meta, media_body=media, fields="id").execute()
        conn.last_upload_at = utcnow()
        conn.last_error = ""
        db.session.add(conn)
        db.session.commit()
        return {"ok": True, "file_id": created.get("id")}
    except Exception as exc:  # noqa: BLE001
        try:
            conn.last_error = str(exc)[:500]
            db.session.add(conn)
            db.session.commit()
        except Exception:
            db.session.rollback()
        return {"ok": False, "error": str(exc)}


def status(customer_id: int) -> dict[str, Any]:
    conn = get_connection(customer_id)
    return {
        "configured": is_configured(),
        "libs": libs_available(),
        "connected": bool(conn and conn.connected),
        "email": conn.google_email if conn else "",
        "folder_name": (conn.folder_name if conn else DEFAULT_FOLDER_NAME),
        "last_upload_at": conn.last_upload_at if conn else None,
        "last_error": conn.last_error if conn else "",
    }
