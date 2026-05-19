from __future__ import annotations

from flask import Blueprint, jsonify, request

from ..services.license_service import check_license

bp = Blueprint("api", __name__, url_prefix="/api")


@bp.get("/health")
def health():
    return jsonify({"ok": True, "status": "healthy"})


@bp.post("/license/check")
def license_check():
    body = request.get_json(silent=True) or {}
    license_key = (body.get("license_key") or "").strip()
    fingerprint = (body.get("server_fingerprint") or "").strip()
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
        hostname=(body.get("hostname") or "").strip(),
        version=(body.get("version") or "").strip(),
        install_id=(body.get("install_id") or "").strip(),
        domain=(body.get("domain") or body.get("server_domain") or "").strip(),
        ip_address=(body.get("ip_address") or request.headers.get("X-Forwarded-For") or request.remote_addr or "").split(",")[0].strip(),
    )
    return jsonify(result.to_response())

