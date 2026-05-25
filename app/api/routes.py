from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request

from ..extensions import db
from ..license_signing import LicenseSignatureError, verify_license_signature
from ..security import clean_text, client_ip
from ..services.license_payments import (
    LicensePaymentRequestRepository,
    LicensePaymentRequestService,
    LicensePaymentValidationError,
    instructions_for_request,
)
from ..services.license_service import check_license

bp = Blueprint("api", __name__, url_prefix="/api")


@bp.get("/health")
def health():
    return jsonify({"ok": True, "status": "healthy"})


@bp.post("/license/check")
def license_check():
    body = request.get_json(silent=True) or {}
    try:
        verify_license_signature(current_app, body)
    except LicenseSignatureError:
        return jsonify({
            "active": False,
            "status": "denied",
            "mode": "denied",
            "message": "License check authorization failed.",
        }), 401

    try:
        license_key = clean_text(body.get("license_key"), 32).upper()
        fingerprint = clean_text(body.get("server_fingerprint"), 255)
        hostname = clean_text(body.get("hostname"), 255)
        version = clean_text(body.get("version"), 80)
        install_id = clean_text(body.get("install_id"), 120)
        domain = clean_text(body.get("domain") or body.get("server_domain"), 255)
    except ValueError as exc:
        return jsonify({
            "active": False,
            "status": "invalid_request",
            "mode": "denied",
            "message": str(exc),
        }), 422

    if not license_key or not fingerprint:
        return jsonify({
            "active": False,
            "status": "invalid_request",
            "mode": "denied",
            "message": "license_key and server_fingerprint are required.",
        }), 422

    result = check_license(
        license_key=license_key,
        fingerprint=fingerprint,
        hostname=hostname,
        version=version,
        install_id=install_id,
        domain=domain,
        ip_address=client_ip(current_app.config.get("TRUST_PROXY_HEADERS", False)),
    )
    return jsonify(result.to_response())


def _payment_error(message: str, status_code: int = 400):
    return jsonify({"ok": False, "error": message}), status_code


@bp.post("/license-payments/requests")
def create_license_payment_request():
    body = request.get_json(silent=True) or {}
    body.pop("status", None)
    try:
        payment_request = LicensePaymentRequestService().create_request(body)
    except (LicensePaymentValidationError, ValueError) as exc:
        return _payment_error(str(exc), 400)
    db.session.commit()
    return jsonify({"ok": True, "payment_request": LicensePaymentRequestService().portal_payload(payment_request)}), 201


@bp.get("/license-payments/requests/<int:payment_request_id>/instructions")
def license_payment_instructions(payment_request_id: int):
    token = (request.args.get("token") or "").strip()
    payment_request = LicensePaymentRequestRepository().get_for_portal(payment_request_id, token)
    if not payment_request:
        return _payment_error("not_found", 404)
    return jsonify({"ok": True, "instructions": instructions_for_request(payment_request)})
