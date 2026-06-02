"""Meta WhatsApp Embedded Signup — OAuth code exchange + asset discovery.

Self-service onboarding (replaces manual token paste as the primary path):

  1. The browser runs Meta's Embedded Signup popup (``FB.login`` with the
     configured ``config_id``). On success Meta returns, via a ``message``
     event, the selected ``waba_id`` + ``phone_number_id`` and an authorization
     ``code``.
  2. The page POSTs ``{code, waba_id, phone_number_id}`` to the backend.
  3. :func:`complete_signup` exchanges the code for a business access token,
     reads the granted scopes (``/debug_token``), discovers the phone-number +
     WABA metadata, subscribes our app to the WABA (so webhooks flow), and
     persists an *encrypted* connection through the existing
     ``settings.upsert_account`` — then flips ``connection_status='connected'``.

Design rules (mirrors ``providers.py``):

* The ONLY network access points are :func:`_graph_get` / :func:`_graph_post`.
  Tests monkeypatch them and never hit Meta.
* Secrets (app secret, access token, code) are NEVER logged, never placed in
  exception messages. Surfaced errors are :class:`EmbeddedSignupError` with a
  stable ``code`` and a non-technical Arabic ``message``.
* All config comes from the environment via ``current_app.config`` — never
  hardcoded. When unconfigured, :func:`embedded_signup_available` is ``False``
  and the UI hides the CTA (manual path still works).
"""
from __future__ import annotations

import hashlib
import json
import secrets
import socket
import urllib.error
import urllib.parse
import urllib.request
from datetime import timedelta
from typing import Any

from flask import current_app

from ...extensions import db
from ...models import WhatsAppEmbeddedSignupAttempt, utcnow
from . import settings as wa_settings
from .providers import MetaCloudWhatsAppProvider, WhatsAppProviderError


class EmbeddedSignupError(Exception):
    """A self-service onboarding failure surfaced to the customer portal.

    Carries a stable machine ``code`` and a non-technical Arabic ``message``.
    Its string form never contains a token, code, or app secret.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return f"[{self.code}] {self.message}"


# ───────────────────────────── audit taxonomy ─────────────────────────────
#
# Spec event names for the embedded-signup lifecycle. During a transition window
# the older names (``whatsapp_embedded_connected`` / ``..._disconnected``) are
# emitted ALONGSIDE the new ones via :func:`_emit_audit`, so existing dashboards
# and queries keep working while consumers migrate.
AUDIT_STARTED = "embedded_signup_started"
AUDIT_SUCCEEDED = "embedded_signup_succeeded"
AUDIT_FAILED = "embedded_signup_failed"
AUDIT_SYNCED = "whatsapp_connection_synced"
AUDIT_DISCONNECTED = "whatsapp_connection_disconnected"
AUDIT_RECONNECTED = "whatsapp_connection_reconnected"
AUDIT_TEST_SENT = "whatsapp_tenant_test_message_sent"
AUDIT_TEST_FAILED = "whatsapp_tenant_test_message_failed"

_LEGACY_CONNECTED = "whatsapp_embedded_connected"
_LEGACY_DISCONNECTED = "whatsapp_embedded_disconnected"

# Error codes raised by state/nonce validation (vs. Meta exchange failures). The
# route uses these to decide NOT to flip a (possibly connected) account to error.
STATE_ERROR_CODES = frozenset({"invalid_state", "expired_state", "missing_state"})

# Non-technical Arabic surfaced when an onboarding state is missing/expired.
_STATE_INVALID_AR = "جلسة الربط غير صالحة. أعد المحاولة من زر «ربط واتساب»."
_STATE_EXPIRED_AR = "انتهت مهلة جلسة الربط. أعد المحاولة من زر «ربط واتساب»."


def _emit_audit(event: str, legacy: str | None, entity_type: str, entity_id,
                summary: str, metadata: dict | None = None) -> None:
    """Append the spec audit ``event`` (+ optional ``legacy`` alias). Caller commits."""
    wa_settings._audit(event, entity_type, entity_id, summary, metadata)
    if legacy:
        wa_settings._audit(legacy, entity_type, entity_id, summary, metadata)


# ───────────────────────── state/nonce sessions ─────────────────────────
#
# Server-issued, single-use ``state`` + ``nonce`` bind Meta's popup to the
# session customer. Only SHA-256 hashes are persisted (raw values are handed to
# the browser once); the completion callback (P4) must echo a ``state`` matching
# a live pending attempt for the SAME customer. Additive + feature-flagged.

def _hash(value: str) -> str:
    return hashlib.sha256((value or "").encode("utf-8")).hexdigest()


def _attempt_ttl_seconds() -> int:
    try:
        return int(current_app.config.get("META_EMBEDDED_ATTEMPT_TTL_SECONDS") or 600)
    except (TypeError, ValueError):
        return 600


def start_session(customer_id: int, *, license_id: int | None = None,
                  initiated_by: int | None = None) -> dict:
    """Begin a server-bound embedded-signup attempt for one customer.

    Issues a one-time ``state`` + ``nonce``, persists only their hashes as a
    *pending* attempt (with ``expires_at`` + ``initiated_by``), expires any
    older live attempts for the customer, and audits ``embedded_signup_started``.

    Returns the RAW ``{"state", "nonce"}`` for the browser to echo back on
    completion. The raw values are never stored.
    """
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(16)
    now = utcnow()

    # Single active state: invalidate any prior live attempts for this customer.
    WhatsAppEmbeddedSignupAttempt.query.filter_by(
        customer_id=int(customer_id), status="pending",
    ).update({"status": "expired", "completed_at": now}, synchronize_session=False)

    attempt = WhatsAppEmbeddedSignupAttempt(
        customer_id=int(customer_id),
        license_id=license_id,
        state_hash=_hash(state),
        nonce_hash=_hash(nonce),
        status="pending",
        initiated_by=initiated_by,
        expires_at=now + timedelta(seconds=_attempt_ttl_seconds()),
    )
    db.session.add(attempt)
    db.session.commit()

    _emit_audit(
        AUDIT_STARTED, None,
        "whatsapp_embedded_attempt", attempt.id,
        "Embedded Signup started",
        {"customer_id": int(customer_id)},
    )
    db.session.commit()
    return {"state": state, "nonce": nonce}


def _consume_state(customer_id: int, state: str, *, nonce: str | None = None):
    """Validate an echoed ``state`` (+ optional ``nonce``) for this customer.

    Returns the matching live *pending* :class:`WhatsAppEmbeddedSignupAttempt`
    so the caller (P4) can finalize it after the code exchange. Raises
    :class:`EmbeddedSignupError` when no live attempt matches the SESSION
    customer, or when it is expired / already consumed. Tenant-isolated: an
    attempt belonging to another customer never matches.
    """
    state = (state or "").strip()
    if not state:
        raise EmbeddedSignupError("invalid_state", _STATE_INVALID_AR)
    attempt = WhatsAppEmbeddedSignupAttempt.query.filter_by(state_hash=_hash(state)).first()
    if attempt is None or attempt.customer_id != int(customer_id) or attempt.status != "pending":
        raise EmbeddedSignupError("invalid_state", _STATE_INVALID_AR)
    if attempt.expires_at and attempt.expires_at < utcnow():
        attempt.status = "expired"
        attempt.completed_at = utcnow()
        db.session.commit()
        raise EmbeddedSignupError("expired_state", _STATE_EXPIRED_AR)
    if nonce is not None and _hash((nonce or "").strip()) != (attempt.nonce_hash or ""):
        raise EmbeddedSignupError("invalid_state", _STATE_INVALID_AR)
    return attempt


def _finalize_attempt(attempt, *, status: str, error_code: str | None = None,
                      error_message: str | None = None) -> None:
    """Mark an attempt terminal (``completed``/``failed``/``expired``). Commits."""
    if attempt is None:
        return
    attempt.status = status
    attempt.completed_at = utcnow()
    attempt.error_code = error_code
    attempt.error_message = error_message
    db.session.commit()


# ───────────────────────────── config ─────────────────────────────

def _cfg() -> dict[str, str]:
    c = current_app.config
    return {
        "app_id": (c.get("META_APP_ID") or "").strip(),
        "app_secret": (c.get("META_APP_SECRET") or "").strip(),
        "config_id": (c.get("META_CONFIG_ID") or "").strip(),
        "version": (c.get("META_GRAPH_VERSION") or c.get("WHATSAPP_GRAPH_API_VERSION") or "v21.0").strip("/"),
        "base": (c.get("WHATSAPP_GRAPH_BASE") or "https://graph.facebook.com").rstrip("/"),
    }


def embedded_signup_available() -> bool:
    """True iff embedded signup is enabled AND the minimum creds are present."""
    if not current_app.config.get("META_EMBEDDED_SIGNUP_ENABLED", False):
        return False
    cfg = _cfg()
    return bool(cfg["app_id"] and cfg["app_secret"] and cfg["config_id"])


def public_config() -> dict[str, str]:
    """Non-secret values the browser JS SDK needs (never the app secret)."""
    cfg = _cfg()
    return {"app_id": cfg["app_id"], "config_id": cfg["config_id"], "graph_version": cfg["version"]}


def _timeout() -> int:
    try:
        return int(current_app.config.get("WHATSAPP_HTTP_TIMEOUT_SECONDS") or 15)
    except (TypeError, ValueError):
        return 15


# ───────────────────────────── network (mockable) ─────────────────────────────

def _graph_get(path: str, params: dict[str, Any]) -> dict:
    """GET a Graph API node. Single mockable network point. Never logs secrets."""
    cfg = _cfg()
    url = f"{cfg['base']}/{cfg['version']}/{path.lstrip('/')}?{urllib.parse.urlencode(params)}"
    return _do(urllib.request.Request(url, method="GET"))


def _graph_post(path: str, data: dict[str, Any]) -> dict:
    """POST to a Graph API node (form-encoded). Single mockable network point."""
    cfg = _cfg()
    url = f"{cfg['base']}/{cfg['version']}/{path.lstrip('/')}"
    body = urllib.parse.urlencode(data).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    return _do(req)


def _do(req: urllib.request.Request) -> dict:
    try:
        with urllib.request.urlopen(req, timeout=_timeout()) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        try:
            parsed = json.loads(exc.read().decode("utf-8") or "{}")
        except Exception:  # pragma: no cover - defensive
            parsed = {}
        raise _classify(parsed) from None
    except (urllib.error.URLError, socket.timeout, TimeoutError, OSError):
        raise EmbeddedSignupError("meta_unreachable", "تعذّر الاتصال بخدمة Meta. حاول مرة أخرى.") from None
    try:
        parsed = json.loads(raw.decode("utf-8") or "{}")
    except (ValueError, UnicodeDecodeError):
        parsed = {}
    return parsed if isinstance(parsed, dict) else {}


def _classify(body: dict) -> EmbeddedSignupError:
    """Map a Meta OAuth error body to a safe EmbeddedSignupError. No raw echo."""
    err = body.get("error") if isinstance(body, dict) else None
    code = ""
    if isinstance(err, dict):
        code = str(err.get("code") or err.get("type") or "")
    # 190 = invalid/expired token or code; treat as a retryable user re-auth.
    if code in {"190", "OAuthException"}:
        return EmbeddedSignupError(
            "auth_failed",
            "تعذّر إكمال الربط. حاول إعادة الاتصال أو تحقق من صلاحيات Meta.",
        )
    return EmbeddedSignupError("meta_error", "تعذّر إكمال الربط مع Meta. حاول مرة أخرى لاحقًا.")


# ───────────────────────────── flow steps ─────────────────────────────

def exchange_code(code: str, redirect_uri: str = "") -> dict:
    """Exchange the Embedded Signup authorization ``code`` for an access token.

    Returns ``{"access_token": str, "expires_in": int|None}``. Raises
    :class:`EmbeddedSignupError` on any failure.
    """
    code = (code or "").strip()
    if not code:
        raise EmbeddedSignupError("missing_code", "رمز الربط مفقود. أعد المحاولة.")
    cfg = _cfg()
    if not (cfg["app_id"] and cfg["app_secret"]):
        raise EmbeddedSignupError("not_configured", "خدمة الربط غير مُهيأة بعد. تواصل مع الدعم.")
    params = {
        "client_id": cfg["app_id"],
        "client_secret": cfg["app_secret"],
        "code": code,
    }
    if redirect_uri:
        params["redirect_uri"] = redirect_uri
    resp = _graph_get("oauth/access_token", params)
    token = (resp.get("access_token") or "").strip()
    if not token:
        raise EmbeddedSignupError("no_token", "لم تُرجع Meta رمز وصول صالحًا. أعد المحاولة.")
    expires_in = resp.get("expires_in")
    return {"access_token": token, "expires_in": int(expires_in) if expires_in else None}


def granted_scopes(token: str) -> list[str]:
    """Read granted scopes for ``token`` via /debug_token (best-effort)."""
    cfg = _cfg()
    app_token = f"{cfg['app_id']}|{cfg['app_secret']}"
    try:
        resp = _graph_get("debug_token", {"input_token": token, "access_token": app_token})
    except EmbeddedSignupError:
        return []
    data = resp.get("data") if isinstance(resp, dict) else None
    scopes = data.get("scopes") if isinstance(data, dict) else None
    return [str(s) for s in scopes] if isinstance(scopes, list) else []


def _phone_metadata(token: str, phone_number_id: str) -> dict:
    resp = _graph_get(
        phone_number_id,
        {"fields": "display_phone_number,verified_name,quality_rating,messaging_limit_tier",
         "access_token": token},
    )
    return {
        "display_phone_number": resp.get("display_phone_number") or "",
        "business_display_name": resp.get("verified_name") or "",
        "quality_rating": resp.get("quality_rating") or "",
        "messaging_limit_tier": resp.get("messaging_limit_tier") or "",
    }


def _waba_metadata(token: str, waba_id: str) -> dict:
    try:
        resp = _graph_get(waba_id, {"fields": "name,owner_business_info", "access_token": token})
    except EmbeddedSignupError:
        return {"name": "", "business_id": ""}
    owner = resp.get("owner_business_info") if isinstance(resp, dict) else None
    business_id = owner.get("id") if isinstance(owner, dict) else ""
    return {"name": resp.get("name") or "", "business_id": business_id or ""}


def subscribe_app_to_waba(token: str, waba_id: str) -> bool:
    """Subscribe our app to the WABA so delivery webhooks flow. Best-effort."""
    try:
        resp = _graph_post(f"{waba_id}/subscribed_apps", {"access_token": token})
        return bool(resp.get("success", True))
    except EmbeddedSignupError:
        return False


def complete_signup(
    customer_id: int,
    *,
    code: str,
    waba_id: str,
    phone_number_id: str,
    redirect_uri: str = "",
    license_id: int | None = None,
) -> dict:
    """Run the full server-side embedded-signup completion for one customer.

    Returns a status dict ``{ok, status, display_phone_number, business_name}``.
    Raises :class:`EmbeddedSignupError` on failure (the route turns it into a
    friendly portal message + audited error state).
    """
    waba_id = (waba_id or "").strip()
    phone_number_id = (phone_number_id or "").strip()
    if not waba_id or not phone_number_id:
        raise EmbeddedSignupError(
            "missing_assets",
            "لم يكتمل اختيار حساب واتساب أو الرقم. أعد المحاولة من زر الربط.",
        )

    token = exchange_code(code, redirect_uri=redirect_uri)["access_token"]
    scopes = granted_scopes(token)
    phone = _phone_metadata(token, phone_number_id)
    waba = _waba_metadata(token, waba_id)
    subscribe_app_to_waba(token, waba_id)

    account = wa_settings.upsert_account(
        customer_id,
        license_id=license_id,
        meta_business_id=waba.get("business_id", ""),
        whatsapp_business_account_id=waba_id,
        phone_number_id=phone_number_id,
        display_phone_number=phone.get("display_phone_number", ""),
        business_display_name=phone.get("business_display_name") or waba.get("name", ""),
        access_token=token,
    )
    # Embedded-signup metadata + connected state (fields upsert_account doesn't own).
    account.onboarding_method = "embedded"
    account.scopes = " ".join(scopes) if scopes else None
    account.quality_rating = phone.get("quality_rating") or account.quality_rating
    account.messaging_limit_tier = phone.get("messaging_limit_tier") or account.messaging_limit_tier
    account.connection_status = "connected"
    account.connected_at = utcnow()
    account.last_sync_at = utcnow()
    account.last_error_code = None
    account.last_error_message = None
    db.session.commit()

    _emit_audit(
        AUDIT_SUCCEEDED, _LEGACY_CONNECTED,
        "whatsapp_account",
        account.id,
        "WhatsApp connected via Embedded Signup",
        {"customer_id": int(customer_id), "waba_id": waba_id,
         "phone_number_id": phone_number_id, "onboarding_method": "embedded"},
    )
    db.session.commit()

    return {
        "ok": True,
        "status": "connected",
        "display_phone_number": phone.get("display_phone_number", ""),
        "business_name": account.business_display_name or "",
    }


def complete_with_state(
    customer_id: int,
    *,
    code: str,
    waba_id: str,
    phone_number_id: str,
    state: str = "",
    nonce: str = "",
    license_id: int | None = None,
    require_state: bool | None = None,
) -> dict:
    """State-validated, idempotent embedded-signup completion (the route entry).

    Wraps :func:`complete_signup` with:

    * **State/nonce enforcement** — when ``state`` is supplied it MUST match a
      live pending attempt for THIS customer (tenant-scoped); otherwise an
      ``EmbeddedSignupError`` (``invalid_state``/``expired_state``) is raised.
    * **Safe degrade** — when no ``state`` is supplied the legacy direct path is
      used, UNLESS ``require_state`` (``META_EMBEDDED_REQUIRE_STATE``) forces it.
    * **Idempotency** — a replayed callback whose ``state`` was already consumed
      and whose account is already connected returns the existing connection
      (``idempotent=True``) without a second code exchange or a duplicate row.
    * **Failure auditing** — any failure (state or Meta) finalizes the attempt
      ``failed`` and audits ``embedded_signup_failed`` with a safe code only.

    Returns the same dict shape as :func:`complete_signup` (+ ``idempotent``).
    """
    state = (state or "").strip()
    nonce = (nonce or "").strip()
    if require_state is None:
        require_state = bool(current_app.config.get("META_EMBEDDED_REQUIRE_STATE", False))

    # A "reconnect" replaces a LIVE connection. The old credentials stay intact
    # until (and unless) the new exchange succeeds — complete_signup only upserts
    # the token after a successful exchange, so a failed reconnect leaves the
    # working connection untouched (we do NOT flip it to error).
    account_before = wa_settings.get_account(customer_id)
    was_connected = bool(
        account_before is not None
        and account_before.connection_status == "connected"
        and account_before.access_token_encrypted
    )

    attempt = None
    try:
        if state:
            existing = WhatsAppEmbeddedSignupAttempt.query.filter_by(state_hash=_hash(state)).first()
            # Idempotent replay: same state already completed + account connected.
            if (existing is not None
                    and existing.customer_id == int(customer_id)
                    and existing.status == "completed"):
                account = wa_settings.get_account(customer_id)
                if account is not None and account.connection_status == "connected":
                    return {
                        "ok": True, "status": "connected", "idempotent": True,
                        "display_phone_number": account.display_phone_number or "",
                        "business_name": account.business_display_name or "",
                    }
            # Otherwise require a live pending attempt (raises on bad/expired/reused).
            attempt = _consume_state(customer_id, state, nonce=nonce or None)
        elif require_state:
            raise EmbeddedSignupError("missing_state", _STATE_INVALID_AR)
        # else: no state supplied and not required → legacy direct path.

        result = complete_signup(
            customer_id,
            code=code,
            waba_id=waba_id,
            phone_number_id=phone_number_id,
            license_id=license_id,
        )
    except EmbeddedSignupError as exc:
        if attempt is not None:
            _finalize_attempt(attempt, status="failed",
                              error_code=exc.code, error_message=exc.message)
        # Mark the account 'error' ONLY when it isn't a live connection and the
        # failure was a real exchange error (not a state rejection). A failed
        # reconnect of a connected account keeps its 'connected' state + token.
        if (not was_connected and account_before is not None
                and exc.code not in STATE_ERROR_CODES):
            wa_settings.set_connection_status(
                customer_id, "error", error_code=exc.code, error_message=exc.message
            )
        _emit_audit(
            AUDIT_FAILED, None,
            "whatsapp_embedded_attempt", attempt.id if attempt else int(customer_id),
            "Embedded Signup failed",
            {"customer_id": int(customer_id), "code": exc.code,
             "reconnect": bool(was_connected)},
        )
        db.session.commit()
        raise

    if attempt is not None:
        _finalize_attempt(attempt, status="completed")
    if was_connected:
        account = wa_settings.get_account(customer_id)
        _emit_audit(
            AUDIT_RECONNECTED, None,
            "whatsapp_account", account.id if account else int(customer_id),
            "WhatsApp reconnected via Embedded Signup",
            {"customer_id": int(customer_id)},
        )
        db.session.commit()
    return result


def validate_connection(customer_id: int) -> dict:
    """Re-probe Meta for the stored account and sync health. Never raises.

    Returns ``{ok, status, ...}``. Used by the portal status refresh + after
    connect to confirm the number is live.
    """
    account = wa_settings.get_account(customer_id)
    if account is None or not account.access_token_encrypted:
        return {"ok": False, "status": "disconnected"}
    provider = MetaCloudWhatsAppProvider()
    try:
        info = provider.validate_credentials(account)
    except WhatsAppProviderError as exc:
        wa_settings.set_connection_status(
            customer_id, "error", error_code=exc.code, error_message=exc.message
        )
        return {"ok": False, "status": "error", "code": exc.code}
    account.display_phone_number = info.get("display_phone_number") or account.display_phone_number
    account.business_display_name = info.get("business_display_name") or account.business_display_name
    account.quality_rating = info.get("quality_rating") or account.quality_rating
    account.messaging_limit_tier = info.get("messaging_limit_tier") or account.messaging_limit_tier
    account.connection_status = "connected"
    account.last_sync_at = utcnow()
    account.last_error_code = None
    account.last_error_message = None
    db.session.commit()
    _emit_audit(
        AUDIT_SYNCED, None,
        "whatsapp_account", account.id,
        "WhatsApp connection synced",
        {"customer_id": int(customer_id)},
    )
    db.session.commit()
    return {"ok": True, "status": "connected", **info}


def disconnect(customer_id: int) -> bool:
    """Soft-disconnect: clear the stored token, mark disconnected, audit.

    Idempotent — repeating a disconnect on an already-disconnected account is a
    safe no-op (no second audit row, audit history preserved). Returns False
    only when there is no account at all.
    """
    account = wa_settings.get_account(customer_id)
    if account is None:
        return False
    # Already soft-disconnected → no-op (keep history, don't re-audit).
    if account.connection_status == "disconnected" and not account.access_token_encrypted:
        return True
    account.access_token_encrypted = None
    account.webhook_secret_encrypted = None
    account.connection_status = "disconnected"
    account.disconnected_at = utcnow()
    account.last_sync_at = utcnow()
    db.session.commit()
    _emit_audit(
        AUDIT_DISCONNECTED, _LEGACY_DISCONNECTED,
        "whatsapp_account",
        account.id,
        "WhatsApp disconnected",
        {"customer_id": int(customer_id)},
    )
    db.session.commit()
    return True
