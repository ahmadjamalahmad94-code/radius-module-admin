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


def license_integration_secret(app: Flask, license_key: str) -> str:
    root_secret = str(app.config.get("LICENSE_CHECK_HMAC_SECRET") or "")
    key = str(license_key or "").strip().upper()
    if not root_secret or not key:
        return ""
    message = f"hoberadius-license-integration:{key}"
    return hmac.new(root_secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_license_signature(app: Flask, body: dict[str, Any]) -> str:
    signature = str(body.get("signature") or body.get("hmac_signature") or "").strip().lower()
    required = bool(app.config.get("LICENSE_CHECK_SIGNATURE_REQUIRED"))
    allow_unsigned = bool(app.config.get("LICENSE_CHECK_ALLOW_UNSIGNED"))

    if not signature:
        if required or not allow_unsigned:
            raise LicenseSignatureError("فشل التحقق من صلاحية فحص الترخيص.")
        return "unsigned"

    secret = str(app.config.get("LICENSE_CHECK_HMAC_SECRET") or "")
    if not secret:
        raise LicenseSignatureError("فشل التحقق من صلاحية فحص الترخيص.")

    timestamp = _parse_timestamp(body.get("timestamp"))
    nonce = str(body.get("nonce") or body.get("request_id") or "").strip()
    if not nonce:
        raise LicenseSignatureError("فشل التحقق من صلاحية فحص الترخيص.")

    now = int(time.time())
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
        raise LicenseSignatureError("فشل التحقق من صلاحية فحص الترخيص.")

    _remember_nonce(app, nonce, now)
    return "signed"


def _parse_timestamp(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise LicenseSignatureError("فشل التحقق من صلاحية فحص الترخيص.") from exc


def _remember_nonce(app: Flask, nonce: str, now: int) -> None:
    replay_window = int(app.config.get("LICENSE_CHECK_REPLAY_WINDOW_SECONDS", 600))
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
