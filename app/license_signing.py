"""Bridge auth — bearer mode ONLY.

The legacy HMAC-signed bridge has been retired (owner decision: "the license
key is the credential, nothing else"). What survives:

* :func:`verify_license_signature` — kept as the legacy name; now a pure
  bearer check. Any request whose body's ``license_key`` resolves to a
  real ``License`` row is accepted; anything else is rejected.
* :func:`mask_license_key` — display/log-safe form (``HBR-…-1234``) so
  the bearer credential never lands in plain log lines.
* :func:`canonical_license_payload` / :func:`sign_license_payload` — kept
  as thin helpers because a handful of TEST harnesses and old assertion
  utilities still call them to construct payloads. They do NOT sign any
  live request and the panel does not verify any signature.

What is GONE (do not reintroduce):

* The candidate-secrets chain (root HMAC secret + derived per-license
  secret + rotatable bridge-token).
* The derived "bind secret" / ``license_integration_secret``.
* The ``LICENSE_BEARER_AUTH_ENABLED`` toggle — bearer is the only mode.
* The signature / timestamp / nonce / replay-window machinery.
* The strict-signature config knobs (``LICENSE_CHECK_SIGNATURE_REQUIRED``
  / ``LICENSE_CHECK_ALLOW_UNSIGNED``).
"""
from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

from flask import Flask


class LicenseSignatureError(RuntimeError):
    """Raised when the bridge auth check fails.

    Name kept for back-compat with the (still mounted) ``except`` blocks in
    ``app/api/routes.py``. The error is now always raised for one reason:
    the body's ``license_key`` did not resolve to a known ``License``.
    """


def canonical_license_payload(body: dict[str, Any]) -> str:
    """Deterministic JSON for a payload — utility only, no live caller.

    Kept because a few test helpers + the radius-module client still build
    canonical bodies. The panel itself never compares hashes against this.
    """
    payload = {
        key: value
        for key, value in body.items()
        if key not in {"signature", "hmac_signature"}
    }
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def sign_license_payload(body: dict[str, Any], secret: str) -> str:
    """HMAC helper — utility only, no live caller.

    Kept solely so unit tests that construct sample bodies don't break.
    The live bridge does not verify signatures.
    """
    canonical = canonical_license_payload(body)
    return hmac.new(secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()


# ── SEC C1 — outbound bridge-RESPONSE signing ────────────────────────────────
#
# This is NOT a return to the retired request-auth secret chain. Request auth
# stays bearer-only. This signs the RESPONSE the panel sends to a radius
# instance, keyed by that instance's own ``license_key`` — a secret both sides
# already hold and which never travels except in the request the customer
# itself made over TLS. Its sole purpose: let the customer prove an
# identity-sync response (which can carry admin_super_overrides / owner_admins)
# really came from the panel that knows its key, so a rogue/repointed endpoint
# cannot forge privilege-escalation directives.
#
# Canonical spec (MUST stay identical to the radius-module verifier):
#   msg = json.dumps(payload_without__bridge_sig,
#                    ensure_ascii=False, separators=(",", ":"), sort_keys=True)
#   sig = hex( HMAC-SHA256( key=license_key.strip().upper().utf8, msg.utf8 ) )
_BRIDGE_SIG_FIELD = "_bridge_sig"


def canonical_bridge_response(payload: dict[str, Any]) -> str:
    body = {k: v for k, v in payload.items() if k != _BRIDGE_SIG_FIELD}
    return json.dumps(body, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def sign_bridge_response(payload: dict[str, Any], license_key: str) -> str:
    """HMAC-SHA256 (hex) of the canonical payload, keyed by the license key."""
    key = str(license_key or "").strip().upper().encode("utf-8")
    return hmac.new(
        key, canonical_bridge_response(payload).encode("utf-8"), hashlib.sha256
    ).hexdigest()


def attach_bridge_signature(payload: dict[str, Any], license_key: str) -> dict[str, Any]:
    """Return ``payload`` with a ``_bridge_sig`` field added (mutates + returns).

    A no-op when there's no license key to sign with — the customer then simply
    finds no signature and (correctly) refuses to apply escalation directives.
    """
    if license_key:
        payload[_BRIDGE_SIG_FIELD] = sign_bridge_response(payload, license_key)
    return payload


def mask_license_key(license_key: str) -> str:
    """Display/log-safe form of a license key: ``HBR-…-1234``.

    The license key IS the bearer credential — it must never land in
    audit metadata or logs in full. Keeps the prefix (key family) and
    the last group so the owner can still match it against their panel.
    """
    key = str(license_key or "").strip().upper()
    if not key:
        return ""
    parts = key.split("-")
    if len(parts) >= 3:
        return f"{parts[0]}-…-{parts[-1]}"
    return key[:3] + "…" + key[-2:] if len(key) > 6 else "…"


def verify_license_signature(app: Flask, body: dict[str, Any]) -> str:
    """Bearer-only auth: the body's ``license_key`` must resolve to a row.

    Returns the literal string ``"bearer"`` on success — kept so callers
    that branched on the return value (``"signed"`` / ``"unsigned"`` /
    ``"bearer"``) compile unchanged. On failure raises
    :class:`LicenseSignatureError`, which the route handlers map to HTTP
    401 with the existing Arabic message.

    The ``app`` parameter is unused; kept in the signature for API
    stability with the many call sites that pass ``current_app``.
    """
    del app  # signature stability — not used in bearer mode
    key = str(body.get("license_key") or "").strip().upper()
    if not key:
        raise LicenseSignatureError("فشل التحقق من صلاحية فحص الترخيص.")
    try:
        from .models import License
        lic = License.query.filter_by(license_key=key).first()
    except Exception as exc:  # pragma: no cover — only reachable from script harnesses w/o app context
        raise LicenseSignatureError("فشل التحقق من صلاحية فحص الترخيص.") from exc
    if lic is None or not hmac.compare_digest(
        str(lic.license_key or "").strip().upper(), key
    ):
        raise LicenseSignatureError("فشل التحقق من صلاحية فحص الترخيص.")
    return "bearer"
