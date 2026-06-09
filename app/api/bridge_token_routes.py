"""Reverse channel: customer reports its bridge-token state.

POST /api/integration/hoberadius/bridge-token/report

Mirrors ``/api/integration/hoberadius/admins/report`` and
``/api/integration/hoberadius/backups/upload``: the customer's
radius-module POSTs into the panel via the same guard triad as the rest
of the bridge — HTTPS + HMAC signature + license resolution. The
sender is the customer's radius after a LOCAL rotation; the panel's
``apply_customer_report`` decides whether to adopt the new value, treat
it as a heartbeat, or tell the customer it is stale (the panel wins on
same-version disagreement).

Request body (signed) — keys in addition to the standard ``license_key``,
``server_fingerprint``, ``timestamp``, ``nonce``, ``signature`` fields::

    {
        "bridge_token":         "<plaintext>",          // required
        "bridge_token_version": 5,                       // required
        "bridge_token_fingerprint": "<sha256 hex>",      // optional; if
                                                        // present, must
                                                        // match SHA256
                                                        // of bridge_token
        "rotated_by":           "customer"               // informational
    }

Response::

    200 — success. ``outcome`` is one of:
          "adopted_customer" | "no_change" | "panel_wins" | "stale_report"
          The body ALWAYS carries the panel's current canonical state in
          ``token`` (plaintext, since this is signed/HTTPS), ``version``,
          and ``fingerprint``. The customer overwrites its local copy with
          this whenever ``outcome != "adopted_customer"``.
    400 — malformed payload (bad token, fingerprint mismatch, etc.).
    401 — bad signature (LicenseSignatureError).
    404 — license / customer not found.
    426 — plaintext HTTP (the integration triad refuses cleartext).

Security
--------
- The plaintext token transits ONLY over this signed, HTTPS-guarded
  channel (the triad enforces both).
- Never logged in plaintext. Only the fingerprint prefix lands in logs.
- Replay-protected by the standard ``timestamp``/``nonce`` machinery
  inherited from ``verify_license_signature`` — no extra cache here.
"""

from __future__ import annotations

import logging

from flask import Blueprint, current_app, jsonify, request

from ..extensions import db
from ..license_signing import LicenseSignatureError, verify_license_signature
from ..services.bridge_token_sync import (
    BridgeTokenError,
    apply_customer_report,
)
from ..services.customer_control import audit_customer_control


logger = logging.getLogger(__name__)

bp = Blueprint("bridge_token_api", __name__, url_prefix="/api/integration/hoberadius")


def _integration_request_is_secure() -> bool:
    """Same secure-channel rule the rest of the integration endpoints use."""
    if request.is_secure:
        return True
    if (
        current_app.config.get("TRUST_PROXY_HEADERS")
        and request.headers.get("X-Forwarded-Proto", "").lower() == "https"
    ):
        return True
    return False


def _checked_license(body: dict):
    """Resolve + verify the license referenced in the body.

    Returns ``(license, customer, None)`` on success; otherwise
    ``(None, None, (response, status))``.
    """
    from ..services.license_service import check_license
    from ..security import clean_text
    from ..models import License

    try:
        license_key = clean_text(body.get("license_key"), 32).upper()
        fingerprint = clean_text(body.get("server_fingerprint"), 255)
    except ValueError as exc:
        return None, None, (jsonify({"ok": False, "status": "invalid_request",
                                     "message": str(exc)}), 422)
    if not license_key or not fingerprint:
        return None, None, (jsonify({"ok": False, "status": "invalid_request",
                                     "message": "license_key and server_fingerprint are required."}), 422)

    # Look up the license row; the customer side has already proven HMAC.
    lic = License.query.filter_by(license_key=license_key).first()
    if lic is None or lic.customer is None:
        return None, None, (jsonify({"ok": False, "status": "not_found",
                                     "message": "ترخيص غير موجود."}), 404)
    return lic, lic.customer, None


@bp.post("/bridge-token/report")
def bridge_token_report():
    """Reverse channel — customer reports its current bridge token state."""
    body = request.get_json(silent=True) or {}

    if not _integration_request_is_secure():
        return jsonify({"ok": False, "status": "https_required",
                        "message": "تقرير مفتاح الجسر يتطلب HTTPS."}), 426

    try:
        verify_license_signature(current_app, body)
    except LicenseSignatureError:
        return jsonify({"ok": False, "status": "denied",
                        "message": "فشل التحقق من صلاحية التكامل."}), 401

    lic, customer, error = _checked_license(body)
    if error is not None:
        return error

    claimed_token = body.get("bridge_token")
    claimed_version = body.get("bridge_token_version")
    claimed_fingerprint = body.get("bridge_token_fingerprint") or ""

    try:
        result = apply_customer_report(
            lic,
            claimed_token=claimed_token if isinstance(claimed_token, str) else "",
            claimed_version=claimed_version,
            claimed_fingerprint=claimed_fingerprint if isinstance(claimed_fingerprint, str) else None,
        )
    except BridgeTokenError as exc:
        return jsonify({"ok": False, "status": exc.code,
                        "message": exc.message}), 400

    audit_customer_control(
        actor_admin_id=None,
        action=f"bridge_token_report_{result.outcome}",
        entity_type="license",
        entity_id=str(lic.id),
        summary=f"تقرير مفتاح الجسر من العميل {customer.company_name} ({result.outcome})",
        metadata={
            "license_id": lic.id,
            "customer_id": customer.id,
            "version": result.version,
            "fingerprint_prefix": result.fingerprint[:8],
            "outcome": result.outcome,
            "claimed_version": int(claimed_version) if claimed_version is not None else None,
        },
    )
    db.session.commit()

    logger.info(
        "bridge_token: customer report license_id=%s outcome=%s v=%s fp=%s",
        lic.id, result.outcome, result.version, result.fingerprint[:8],
    )

    return jsonify({
        "ok": True,
        "status": "ok",
        "outcome": result.outcome,
        "license_key": lic.license_key,
        # Plaintext is delivered ONLY over this signed/HTTPS channel.
        "token": result.plaintext,
        "version": result.version,
        "fingerprint": result.fingerprint,
        "rotated_at": result.rotated_at.isoformat() + "Z" if result.rotated_at else None,
        "rotated_by": result.rotated_by,
    }), 200


__all__ = ["bp"]
