from __future__ import annotations

import hashlib
import hmac
import json
import time
from collections import OrderedDict
from typing import Any

from flask import Flask


class LicenseSignatureError(RuntimeError):
    pass


def canonical_license_payload(body: dict[str, Any]) -> str:
    payload = {
        key: value
        for key, value in body.items()
        if key not in {"signature", "hmac_signature"}
    }
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def sign_license_payload(body: dict[str, Any], secret: str) -> str:
    canonical = canonical_license_payload(body)
    return hmac.new(secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()


def _hmac_root_secret(app: Flask) -> str:
    """DB-first resolver for the HMAC root secret.

    The owner sets/rotates the secret in the UI; it's stored encrypted in
    the ``Setting`` table. The env var ``LICENSE_CHECK_HMAC_SECRET`` is the
    fallback for bootstrap (first boot before the owner has touched the UI).
    """
    try:
        from .services import platform_settings as ps
        with app.app_context() if not _has_app_context() else _noop():
            db_val = ps.get_secret("LICENSE_CHECK_HMAC_SECRET")
        if db_val:
            return db_val
    except Exception:  # noqa: BLE001 - never crash signature check on settings error
        pass
    return str(app.config.get("LICENSE_CHECK_HMAC_SECRET") or "")


def _has_app_context() -> bool:
    try:
        from flask import has_app_context
        return bool(has_app_context())
    except Exception:  # noqa: BLE001
        return False


class _noop:
    def __enter__(self): return self
    def __exit__(self, *a): return False


def license_integration_secret(app: Flask, license_key: str) -> str:
    root_secret = _hmac_root_secret(app)
    key = str(license_key or "").strip().upper()
    if not root_secret or not key:
        return ""
    message = f"hoberadius-license-integration:{key}"
    return hmac.new(root_secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()


def mask_license_key(license_key: str) -> str:
    """Display/log-safe form of a license key: ``HBR-…-1234``.

    In bearer mode the key IS the credential, so it must never land in
    logs or audit metadata in full. Keeps the prefix (key family) and the
    last group (enough for the owner to match it against his panel)."""
    key = str(license_key or "").strip().upper()
    if not key:
        return ""
    parts = key.split("-")
    if len(parts) >= 3:
        return f"{parts[0]}-…-{parts[-1]}"
    return key[:3] + "…" + key[-2:] if len(key) > 6 else "…"


def bearer_auth_enabled(app: Flask) -> bool:
    """Is simple-link bearer auth on? DB knob first, config fallback (default True)."""
    try:
        from .services import platform_settings as ps
        return bool(ps.get_bool("LICENSE_BEARER_AUTH_ENABLED"))
    except Exception:  # noqa: BLE001 - settings table unavailable → config
        return bool(app.config.get("LICENSE_BEARER_AUTH_ENABLED", True))


def _bearer_license_key_ok(body: dict[str, Any]) -> bool:
    """True iff the body's ``license_key`` resolves to a real license.

    The key is the bearer credential (docs/SIMPLE_LINK_CONTRACT.md §4): it
    travels only over HTTPS (the integration endpoints already 426 plain
    HTTP) and is compared constant-time against the stored key."""
    key = str(body.get("license_key") or "").strip().upper()
    if not key:
        return False
    try:
        from .models import License
        lic = License.query.filter_by(license_key=key).first()
    except Exception:  # noqa: BLE001 - no app/db context (signing-only scripts)
        return False
    if lic is None:
        return False
    return hmac.compare_digest(str(lic.license_key or "").strip().upper(), key)


def verify_license_signature(app: Flask, body: dict[str, Any]) -> str:
    signature = str(body.get("signature") or body.get("hmac_signature") or "").strip().lower()
    # DB-first policy knobs (UI-editable). The env var stays as the bootstrap
    # fallback so behavior is unchanged on a fresh install before the owner
    # touches /admin/settings/platform.
    try:
        from .services import platform_settings as ps
        required = ps.get_bool("LICENSE_CHECK_SIGNATURE_REQUIRED")
        allow_unsigned = ps.get_bool("LICENSE_CHECK_ALLOW_UNSIGNED")
    except Exception:  # noqa: BLE001
        required = bool(app.config.get("LICENSE_CHECK_SIGNATURE_REQUIRED"))
        allow_unsigned = bool(app.config.get("LICENSE_CHECK_ALLOW_UNSIGNED"))

    if not signature:
        # Simple-link bearer mode (docs/SIMPLE_LINK_CONTRACT.md): the license
        # key in the BODY is the credential — no signature required. Checked
        # BEFORE the unsigned-allowed fallback so a valid key authenticates
        # even in strict (signature-required) postures. A missing/unknown key
        # falls through to the legacy rules (401 in strict, "unsigned" in
        # lenient), so old behaviour is fully preserved when the flag is off
        # or the key doesn't resolve.
        if bearer_auth_enabled(app) and _bearer_license_key_ok(body):
            return "bearer"
        if required or not allow_unsigned:
            raise LicenseSignatureError("فشل التحقق من صلاحية فحص الترخيص.")
        return "unsigned"

    secret = _hmac_root_secret(app)
    if not secret:
        raise LicenseSignatureError("فشل التحقق من صلاحية فحص الترخيص.")

    timestamp = _parse_timestamp(body.get("timestamp"))
    nonce = str(body.get("nonce") or body.get("request_id") or "").strip()
    if not nonce:
        raise LicenseSignatureError("فشل التحقق من صلاحية فحص الترخيص.")

    now = int(time.time())
    try:
        from .services import platform_settings as ps
        skew = ps.get_int("LICENSE_CHECK_MAX_CLOCK_SKEW_SECONDS")
    except Exception:  # noqa: BLE001
        skew = int(app.config.get("LICENSE_CHECK_MAX_CLOCK_SKEW_SECONDS", 300))
    if abs(now - timestamp) > skew:
        raise LicenseSignatureError("فشل التحقق من صلاحية فحص الترخيص.")

    expected = sign_license_payload(body, secret)
    accepted = hmac.compare_digest(signature, expected)
    if not accepted:
        per_license_secret = license_integration_secret(app, str(body.get("license_key") or ""))
        if per_license_secret:
            accepted = hmac.compare_digest(signature, sign_license_payload(body, per_license_secret))
    if not accepted:
        # Final fallback: a per-license rotatable bridge token (panel-canonical,
        # bidirectionally synced — see app/services/bridge_token_sync.py). Once
        # the panel or the customer side rotates, signatures get made with the
        # new value; we accept it here so the bridge keeps working without
        # waiting for the customer to re-poll the runtime contract.
        accepted = _verify_with_rotatable_bridge_token(app, body, signature)
    if not accepted:
        raise LicenseSignatureError("فشل التحقق من صلاحية فحص الترخيص.")

    _remember_nonce(app, nonce, now)
    return "signed"


def _verify_with_rotatable_bridge_token(app: Flask, body: dict[str, Any], signature: str) -> bool:
    """Try the per-license rotatable bridge token (panel-canonical store).

    Returns True if the signature was made with the current bridge token
    for the license referenced in ``body``. Returns False on any miss
    (unknown license, no state row yet, vault key missing, or just a
    plain mismatch) — caller treats False as "keep looking / fail".

    Imported lazily so this module stays usable when the app context
    is not yet pushed (e.g. signing-only helpers in scripts/tests that
    skip the DB).
    """
    license_key = str(body.get("license_key") or "").strip().upper()
    if not license_key:
        return False
    try:
        from .models import License
        from .services.bridge_token_sync import signing_secrets_for
    except Exception:  # pragma: no cover - defensive against partial app boots
        return False
    try:
        lic = License.query.filter_by(license_key=license_key).first()
    except Exception:  # pragma: no cover - no app/db context
        return False
    if lic is None:
        return False
    for candidate in signing_secrets_for(lic):
        if not candidate:
            continue
        try:
            expected = sign_license_payload(body, candidate)
        except Exception:  # pragma: no cover - defensive
            continue
        if hmac.compare_digest(signature, expected):
            return True
    return False


def _parse_timestamp(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise LicenseSignatureError("فشل التحقق من صلاحية فحص الترخيص.") from exc


def _remember_nonce(app: Flask, nonce: str, now: int) -> None:
    try:
        from .services import platform_settings as ps
        replay_window = ps.get_int("LICENSE_CHECK_REPLAY_WINDOW_SECONDS")
    except Exception:  # noqa: BLE001
        replay_window = int(app.config.get("LICENSE_CHECK_REPLAY_WINDOW_SECONDS", 600))
    # NONCE_CACHE_MAX stays env-only — it's a memory cap, not an operational
    # knob, and changes per-process state that callers can't observe.
    max_items = int(app.config.get("LICENSE_CHECK_NONCE_CACHE_MAX", 5000))
    cache: OrderedDict[str, int] = app.extensions.setdefault("license_nonce_cache", OrderedDict())

    for key, expires_at in list(cache.items()):
        if expires_at <= now:
            cache.pop(key, None)

    if nonce in cache:
        raise LicenseSignatureError("فشل التحقق من صلاحية فحص الترخيص.")

    cache[nonce] = now + replay_window
    while len(cache) > max_items:
        cache.popitem(last=False)
