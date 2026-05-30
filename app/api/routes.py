from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request

from ..extensions import db
from ..license_signing import LicenseSignatureError, verify_license_signature
from ..models import CustomerUser
from ..security import clean_text, client_ip
from ..services.license_payments import (
    LicensePaymentProofService,
    LicensePaymentRequestRepository,
    LicensePaymentRequestService,
    LicensePaymentValidationError,
    instructions_for_request,
    payment_error_message,
    proof_to_dict,
)
from ..services.license_service import check_license
from ..services.customer_control import (
    CustomerControlValidationError,
    audit_customer_control,
    build_identity_sync_contract,
    build_runtime_contract_for_license,
    clean_username,
    create_customer_service_request,
)

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


@bp.post("/integration/hoberadius/identity-sync")
def hoberadius_identity_sync():
    body = request.get_json(silent=True) or {}
    if not _integration_request_is_secure():
        return jsonify({"ok": False, "status": "https_required", "message": "مزامنة الهوية تتطلب HTTPS."}), 426
    signed = _verify_integration_signature(body)
    if signed is not None:
        return signed
    result, error_response = _checked_license_from_integration_body(body)
    if error_response is not None:
        return error_response
    if not result.license:
        return jsonify({"ok": False, "status": result.status, "users": []}), 404
    return jsonify(build_identity_sync_contract(
        result.license,
        license_active=result.active,
        status=result.status,
    ))


@bp.post("/integration/hoberadius/runtime-contract")
def hoberadius_runtime_contract():
    body = request.get_json(silent=True) or {}
    if not _integration_request_is_secure():
        return jsonify({"ok": False, "status": "https_required", "message": "عقد runtime يتطلب HTTPS."}), 426
    signed = _verify_integration_signature(body)
    if signed is not None:
        return signed
    result, error_response = _checked_license_from_integration_body(body)
    if error_response is not None:
        return error_response
    contract = build_runtime_contract_for_license(
        result.license,
        license_active=result.active,
        status=result.status,
    )
    return jsonify({
        "ok": True,
        "status": result.status,
        "contract": contract,
        **contract,
    })


@bp.post("/integration/hoberadius/capacity-contract")
def hoberadius_capacity_contract():
    body = request.get_json(silent=True) or {}
    if not _integration_request_is_secure():
        return jsonify({"ok": False, "status": "https_required", "message": "عقد السعة يتطلب HTTPS."}), 426
    signed = _verify_integration_signature(body)
    if signed is not None:
        return signed
    result, error_response = _checked_license_from_integration_body(body)
    if error_response is not None:
        return error_response
    contract = build_runtime_contract_for_license(
        result.license,
        license_active=result.active,
        status=result.status,
    )
    return jsonify({
        "ok": True,
        "status": result.status,
        "contract": contract,
        "limits": contract["limits"],
        "services": contract["services"],
    })


@bp.post("/integration/hoberadius/service-requests")
def hoberadius_service_requests():
    body = request.get_json(silent=True) or {}
    if not _integration_request_is_secure():
        return jsonify({"ok": False, "status": "https_required", "message": "طلبات الخدمات تتطلب HTTPS."}), 426
    signed = _verify_integration_signature(body)
    if signed is not None:
        return signed
    result, error_response = _checked_license_from_integration_body(body)
    if error_response is not None:
        return error_response
    if not result.license or not result.active:
        return jsonify({"ok": False, "status": result.status, "message": "الترخيص ليس نشطًا."}), 403
    try:
        service_request = create_customer_service_request(
            customer=result.license.customer,
            service_key=body.get("service_key") or "",
            request_type=body.get("request_type") or "activation",
            notes=body.get("notes") or "",
            desired_limits=body.get("desired_limits") if isinstance(body.get("desired_limits"), dict) else {},
        )
    except CustomerControlValidationError as exc:
        return jsonify({"ok": False, "status": "invalid_request", "message": str(exc)}), 422
    db.session.commit()
    return jsonify({
        "ok": True,
        "status": "pending",
        "service_request": {
            "id": service_request.id,
            "service_key": service_request.service_key,
            "request_type": service_request.request_type,
            "status": service_request.status,
        },
    }), 201


@bp.post("/integration/hoberadius/customer-users/password-change")
def hoberadius_customer_user_password_change():
    body = request.get_json(silent=True) or {}
    if not _integration_request_is_secure():
        return jsonify({"ok": False, "status": "https_required", "message": "تغيير كلمات المرور يتطلب HTTPS."}), 426
    signed = _verify_integration_signature(body)
    if signed is not None:
        return signed
    result, error_response = _checked_license_from_integration_body(body)
    if error_response is not None:
        return error_response
    if not result.license or not result.active:
        return jsonify({"ok": False, "status": result.status, "message": "الترخيص ليس نشطًا."}), 403
    try:
        user = _customer_user_from_password_change_body(result.license.customer_id, body)
        new_password = str(body.get("new_password") or "")
        if len(new_password) < 8:
            raise CustomerControlValidationError("كلمة المرور الجديدة يجب أن تكون 8 أحرف على الأقل.")
        if not user.active:
            return jsonify({"ok": False, "status": "disabled", "message": "حساب مستخدم العميل معطّل."}), 403
        user.set_password(new_password, increment_version=True)
        audit_customer_control(
            actor_admin_id=None,
            action="customer_user_password_changed_from_runtime",
            entity_type="customer_user",
            entity_id=str(user.id),
            summary=f"مستخدم العميل {user.username} غيّر كلمة المرور من runtime الريدياس",
            metadata={"customer_id": user.customer_id, "password_version": user.password_version},
        )
        db.session.commit()
    except CustomerControlValidationError as exc:
        return jsonify({"ok": False, "status": "invalid_request", "message": str(exc)}), 422
    return jsonify({
        "ok": True,
        "status": "updated",
        "customer_id": user.customer_id,
        "external_user_id": user.id,
        "username": user.username,
        "password_version": int(user.password_version or 0),
        "updated_at": user.updated_at.replace(microsecond=0).isoformat() + "Z" if user.updated_at else None,
    })


def _customer_user_from_password_change_body(customer_id: int, body: dict) -> CustomerUser:
    user = None
    external_user_id = body.get("external_user_id")
    if external_user_id not in (None, ""):
        try:
            user = CustomerUser.query.filter_by(id=int(external_user_id), customer_id=customer_id).first()
        except (TypeError, ValueError):
            raise CustomerControlValidationError("معرّف المستخدم الخارجي غير صحيح.")
    if not user:
        username = clean_username(body.get("username") or "")
        user = CustomerUser.query.filter_by(customer_id=customer_id, username=username).first()
    if not user:
        raise CustomerControlValidationError("لم يتم العثور على مستخدم العميل لهذا الترخيص.")
    return user


def _verify_integration_signature(body: dict):
    try:
        verify_license_signature(current_app, body)
    except LicenseSignatureError:
        return jsonify({"ok": False, "status": "denied", "message": "فشل التحقق من صلاحية التكامل."}), 401
    return None


def _checked_license_from_integration_body(body: dict):
    try:
        license_key = clean_text(body.get("license_key"), 32).upper()
        fingerprint = clean_text(body.get("server_fingerprint"), 255)
        hostname = clean_text(body.get("hostname"), 255)
        version = clean_text(body.get("version"), 80)
        install_id = clean_text(body.get("install_id"), 120)
        domain = clean_text(body.get("domain") or body.get("server_domain"), 255)
    except ValueError as exc:
        return None, (jsonify({"ok": False, "status": "invalid_request", "message": str(exc)}), 422)
    if not license_key or not fingerprint:
        return None, (jsonify({"ok": False, "status": "invalid_request", "message": "license_key and server_fingerprint are required."}), 422)
    result = check_license(
        license_key=license_key,
        fingerprint=fingerprint,
        hostname=hostname,
        version=version,
        install_id=install_id,
        domain=domain,
        ip_address=client_ip(current_app.config.get("TRUST_PROXY_HEADERS", False)),
    )
    return result, None


def _integration_request_is_secure() -> bool:
    if request.is_secure:
        return True
    if current_app.config.get("TRUST_PROXY_HEADERS") and request.headers.get("X-Forwarded-Proto", "").lower() == "https":
        return True
    return False


def _payment_error(message: str, status_code: int = 400, *, detail: str = ""):
    payload = {"ok": False, "error": message}
    if detail:
        payload["message"] = detail
    return jsonify(payload), status_code


@bp.post("/license-payments/requests")
def create_license_payment_request():
    body = request.get_json(silent=True) or {}
    body.pop("status", None)
    try:
        payment_request = LicensePaymentRequestService().create_request(body)
    except (LicensePaymentValidationError, ValueError) as exc:
        if isinstance(exc, LicensePaymentValidationError):
            return _payment_error(exc.code, 400, detail=exc.message_ar)
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


@bp.post("/license-payments/requests/<int:payment_request_id>/proofs")
def submit_license_payment_proof(payment_request_id: int):
    body = request.get_json(silent=True) or {}
    token = str(body.get("token") or request.args.get("token") or "").strip()
    payment_request = LicensePaymentRequestRepository().get_for_portal(payment_request_id, token)
    if not payment_request:
        return _payment_error("not_found", 404)
    try:
        proof = LicensePaymentProofService().submit_manual_proof(
            payment_request=payment_request,
            reference_number=body.get("reference_number") or "",
            note=body.get("note") or "",
        )
    except LicensePaymentValidationError as exc:
        return _payment_error(exc.code, 400, detail=payment_error_message(exc))
    return jsonify({"ok": True, "proof": proof_to_dict(proof), "status": payment_request.status}), 201
