from __future__ import annotations

from flask import Blueprint, Response, abort, current_app, jsonify, request, url_for

from ..extensions import db
from ..license_signing import LicenseSignatureError, verify_license_signature
from ..models import CustomerUser, utcnow
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
    import_radius_admins,
)
from ..services.whatsapp import policy as wa_policy
from ..services.whatsapp import queue as wa_queue
from ..services.whatsapp import settings as wa_settings
from ..services.whatsapp import webhook as wa_webhook
from ..services.whatsapp import worker as wa_worker

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
            "message": "فشل التحقق من صلاحية فحص الترخيص.",
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
        return jsonify({"ok": False, "status": "https_required", "message": "عقد التشغيل يتطلب اتصالًا آمنًا."}), 426
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
    audit_customer_control(
        actor_admin_id=None,
        action="customer_service_request_created",
        entity_type="customer_service_request",
        entity_id=str(service_request.id),
        summary=f"فتح الريدياس طلب خدمة {service_request.public_reference}",
        metadata={"customer_id": result.license.customer_id, "service_key": service_request.service_key},
    )
    db.session.commit()
    return jsonify({
        "ok": True,
        "status": "pending",
        "service_request": {
            "id": service_request.id,
            "reference": service_request.public_reference,
            "title": service_request.title,
            "service_key": service_request.service_key,
            "request_type": service_request.request_type,
            "status": service_request.status,
        },
    }), 201


@bp.post("/integration/hoberadius/portal-sso")
def hoberadius_portal_sso():
    """Mint a short-lived SSO link so the radius can open the customer portal."""
    body = request.get_json(silent=True) or {}
    if not _integration_request_is_secure():
        return jsonify({"ok": False, "status": "https_required", "message": "الدخول الموحّد يتطلب HTTPS."}), 426
    signed = _verify_integration_signature(body)
    if signed is not None:
        return signed
    result, error_response = _checked_license_from_integration_body(body)
    if error_response is not None:
        return error_response
    if not result.license or not result.active:
        return jsonify({"ok": False, "status": result.status, "message": "الترخيص ليس نشطًا."}), 403
    customer = result.license.customer
    user = customer.users.filter_by(active=True).order_by(CustomerUser.id.asc()).first() if customer else None
    if not user:
        return jsonify({"ok": False, "status": "no_user", "message": "لا يوجد مستخدم عميل نشط."}), 404
    from itsdangerous import URLSafeTimedSerializer

    serializer = URLSafeTimedSerializer(str(current_app.config.get("SECRET_KEY") or ""), salt="hoberadius-portal-sso")
    sso_token = serializer.dumps({"uid": user.id, "cid": customer.id})
    sso_url = url_for("public.customer_portal_sso", _external=True) + "?t=" + sso_token
    return jsonify({"ok": True, "status": "ok", "sso_url": sso_url, "expires_in": 90})


@bp.post("/integration/hoberadius/google-drive/status")
def hoberadius_google_drive_status():
    """Report the customer's Google Drive connection status to the radius."""
    body = request.get_json(silent=True) or {}
    if not _integration_request_is_secure():
        return jsonify({"ok": False, "status": "https_required"}), 426
    signed = _verify_integration_signature(body)
    if signed is not None:
        return signed
    result, error_response = _checked_license_from_integration_body(body)
    if error_response is not None:
        return error_response
    if not result.license or not result.license.customer:
        return jsonify({"ok": False, "status": "not_found"}), 404
    from ..services.google_drive import status as gd_status

    st = gd_status(result.license.customer.id)
    last = st.get("last_upload_at")
    return jsonify({
        "ok": True,
        "connected": bool(st.get("connected")),
        "email": st.get("email") or "",
        "folder_name": st.get("folder_name") or "",
        "last_upload_at": (last.strftime("%Y-%m-%d %H:%M") if hasattr(last, "strftime") else (str(last) if last else "")),
    })


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
            summary=f"مستخدم العميل {user.username} غيّر كلمة المرور من واجهة الريدياس التشغيلية",
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


@bp.post("/integration/hoberadius/admins/report")
def hoberadius_admins_report():
    """القناة العكسية: يبلّغ الراديوس اللوحةَ بجرد أدمنياته المحلية.

    نفس ثلاثية الحماية المشتركة (HTTPS + توقيع HMAC + حلّ الترخيص). تُحدَّث لقطة
    ``CustomerRadiusAdmin`` (للعرض والتحكم في تفاصيل العميل). الحقل المملوك
    للّوحة ``force_super`` لا يُداس — هو تحكّم اللوحة وحدها. لا تُخزَّن ولا تُعاد
    أي كلمات مرور.
    """
    body = request.get_json(silent=True) or {}
    if not _integration_request_is_secure():
        return jsonify({"ok": False, "status": "https_required", "message": "بلاغ الأدمن يتطلب HTTPS."}), 426
    signed = _verify_integration_signature(body)
    if signed is not None:
        return signed
    result, error_response = _checked_license_from_integration_body(body)
    if error_response is not None:
        return error_response
    if not result.license or not result.license.customer:
        return jsonify({"ok": False, "status": "not_found"}), 404
    admins = body.get("admins")
    imported = import_radius_admins(result.license.customer, result.license, admins if isinstance(admins, list) else [])
    db.session.commit()
    return jsonify({"ok": True, "status": "ok", "imported": imported})


@bp.post("/integration/hoberadius/backups/upload")
def hoberadius_backup_upload():
    body = request.get_json(silent=True) or {}
    if not _integration_request_is_secure():
        return jsonify({"ok": False, "status": "https_required", "message": "رفع النسخ الاحتياطية يتطلب HTTPS."}), 426
    from ..services.customer_backups import BackupUploadError, record_backup_upload

    # Accept the secret from the header OR the JSON body — reverse proxies
    # often strip custom request headers, so the instance also sends it in body.
    provided_secret = request.headers.get("X-HobeRadius-Admin-Secret", "") or str(body.get("admin_secret") or "")
    try:
        result = record_backup_upload(
            license_key=body.get("license_key") or "",
            payload=body,
            provided_secret=provided_secret,
        )
    except BackupUploadError as exc:
        return jsonify({"ok": False, "status": exc.code, "message": exc.message}), exc.status_code
    return jsonify(result), 201


# ─────────────────────────────────────────────────────────────────────────
# WhatsApp integration APIs (signed, called by the radius_module runtime)
#
# Every endpoint reuses the SAME guard triad as the other integration
# endpoints above: HTTPS (_integration_request_is_secure -> 426),
# HMAC signature (_verify_integration_signature -> 401 on unsigned/bad), then
# license resolution (_checked_license_from_integration_body). The customer is
# resolved once from the verified license (result.license.customer). Secrets
# (access token, app secret, verify token) are NEVER placed in any response.
# Business rejections (policy gate, missing template, not found) return HTTP
# 200 with ``ok: false`` so the caller can branch on the body — they are not
# transport/auth failures and must never surface as a 5xx.
# ─────────────────────────────────────────────────────────────────────────
def _whatsapp_integration_context(body: dict):
    """Run the shared integration guard triad and resolve the customer.

    Returns ``(customer, license_id, None)`` on success, or
    ``(None, None, response)`` where ``response`` is the Flask response/tuple to
    return immediately (HTTPS / signature / license / no-customer failure).
    """
    if not _integration_request_is_secure():
        return None, None, (jsonify({"ok": False, "status": "https_required", "message": "تكامل واتساب يتطلب HTTPS."}), 426)
    signed = _verify_integration_signature(body)
    if signed is not None:
        return None, None, signed
    result, error_response = _checked_license_from_integration_body(body)
    if error_response is not None:
        return None, None, error_response
    if not result.license or not result.license.customer:
        return None, None, (jsonify({"ok": False, "status": "not_found"}), 404)
    return result.license.customer, result.license.id, None


def _whatsapp_inline_drain() -> None:
    """Best-effort inline send so OTP/test messages go out promptly.

    The panel has no resident worker, so we drain a tiny batch synchronously.
    This must NEVER change the API response: any failure (provider, DB) is
    swallowed and the row simply stays queued for the systemd drain timer.
    """
    try:
        wa_worker.drain_once(batch_size=5)
    except Exception:  # noqa: BLE001 — inline drain is best-effort only.
        pass


@bp.post("/integration/hoberadius/whatsapp/status")
def hoberadius_whatsapp_status():
    """Report the customer's WhatsApp gateway status (secret-free)."""
    body = request.get_json(silent=True) or {}
    customer, _license_id, error_response = _whatsapp_integration_context(body)
    if error_response is not None:
        return error_response

    from ..services.whatsapp import embedded_signup as wa_embed

    settings = wa_settings.get_settings(customer.id)
    account = wa_settings.get_account(customer.id)
    account_public = wa_settings.account_public_dict(account)
    usage = wa_settings.get_usage(customer.id, utcnow())

    templates = [
        {
            "local_key": template.local_key,
            "status": template.status,
            "language": template.language,
        }
        for template in wa_settings.list_templates(customer.id)
    ]

    # A coarse onboarding state the thin client can render directly (so it can
    # tell "needs setup" — never connected — apart from "not connected" — set up
    # before, now disconnected/error). Secret-free, derived from existing fields.
    account_status = account_public.get("connection_status") or "disconnected"
    has_account = account is not None and bool((account.phone_number_id or "").strip())
    if account_status == "connected":
        onboarding_state = "connected"
    elif has_account:
        onboarding_state = "not_connected"
    else:
        onboarding_state = "needs_setup"

    return jsonify({
        "ok": True,
        "enabled": bool(settings.enabled),
        "account_status": account_status,
        "onboarding_state": onboarding_state,
        "embedded_available": bool(wa_embed.embedded_signup_available()),
        "display_phone_number": account_public.get("display_phone_number") or "",
        "business_display_name": account_public.get("business_display_name") or "",
        "limits": {
            "daily": {
                "used": usage["daily"]["sent"],
                "limit": settings.daily_message_limit,
            },
            "monthly": {
                "used": usage["monthly"]["sent"],
                "limit": settings.monthly_message_limit,
            },
        },
        "allowed_events": {
            "otp": bool(settings.allow_otp),
            "expiry_notice": bool(settings.allow_expiry_notice),
            "quota_warning": bool(settings.allow_quota_notice),
            "maintenance_notice": bool(settings.allow_maintenance_notice),
            "password_reset": bool(settings.allow_password_reset),
        },
        "templates": templates,
    })


@bp.post("/integration/hoberadius/whatsapp/messages/enqueue")
def hoberadius_whatsapp_enqueue():
    """Queue an outbound WhatsApp message after the send-policy gate passes."""
    body = request.get_json(silent=True) or {}
    customer, license_id, error_response = _whatsapp_integration_context(body)
    if error_response is not None:
        return error_response

    source_event_type = str(body.get("source_event_type") or "")
    recipient_phone = str(body.get("recipient_phone") or "")
    template_key = body.get("template_key") or None
    language = body.get("language") or "ar"
    variables = body.get("variables")
    idempotency_key = str(body.get("idempotency_key") or "")
    subscriber_id = body.get("subscriber_id")
    # Scope the idempotency key per-customer (the column is globally unique), so
    # one tenant's key can never collide with — or read back — another's row.
    scoped_key = f"c{customer.id}:{idempotency_key}" if idempotency_key else ""

    decision = wa_policy.can_send(
        customer.id,
        event_type=source_event_type,
        recipient_phone=recipient_phone,
        template_key=template_key,
        subscriber_id=subscriber_id,
        idempotency_key=scoped_key,
    )
    if not decision.allowed:
        return jsonify({
            "ok": False,
            "error_code": decision.reason,
            "message_ar": decision.message_ar,
        })

    row, created = wa_queue.enqueue(
        customer.id,
        source_system="radius_module",
        source_event_type=source_event_type,
        recipient_phone=recipient_phone,
        normalized_recipient_phone=decision.normalized_phone,
        template_key=template_key,
        language=language,
        variables=variables,
        idempotency_key=scoped_key,
        subscriber_id=subscriber_id,
        license_id=license_id,
    )

    _whatsapp_inline_drain()
    row = wa_queue.get_message(row.id) or row

    return jsonify({
        "ok": True,
        "message_id": row.id,
        "status": row.status,
        "already_exists": (not created),
    })


@bp.post("/integration/hoberadius/whatsapp/messages/test")
def hoberadius_whatsapp_test_message():
    """Send a test message via an approved template (operator-triggered)."""
    body = request.get_json(silent=True) or {}
    customer, license_id, error_response = _whatsapp_integration_context(body)
    if error_response is not None:
        return error_response

    from ..services.whatsapp import embedded_signup as wa_embed

    recipient_phone = str(body.get("recipient_phone") or "")
    idempotency_key = str(body.get("idempotency_key") or "")
    scoped_key = f"c{customer.id}:{idempotency_key}" if idempotency_key else ""

    # The send always goes through the connected TENANT account (the worker reads
    # the per-customer encrypted token) — never the house Cloud API credentials
    # (those are the separate /cloud-test path). Default template: hello_world,
    # else the first recommended approved template.
    preferred = body.get("template_key") or None
    chosen = wa_settings.pick_test_template(customer.id, preferred_local_key=preferred)
    if chosen is None:
        wa_embed.audit_tenant_test_message(
            customer.id, ok=False, recipient=recipient_phone,
            error_code="template_not_approved",
        )
        return jsonify({
            "ok": False,
            "error_code": "template_not_approved",
            "message_ar": "لا يوجد قالب واتساب معتمد لإرسال رسالة تجربة.",
        })

    decision = wa_policy.can_send(
        customer.id,
        event_type="test_message",
        recipient_phone=recipient_phone,
        template_key=chosen.local_key,
        idempotency_key=scoped_key,
    )
    if not decision.allowed:
        wa_embed.audit_tenant_test_message(
            customer.id, ok=False, recipient=recipient_phone,
            template_key=chosen.local_key, error_code=decision.reason,
        )
        return jsonify({
            "ok": False,
            "error_code": decision.reason,
            "message_ar": decision.message_ar,
        })

    row, created = wa_queue.enqueue(
        customer.id,
        source_system="admin_panel",
        source_event_type="test_message",
        recipient_phone=recipient_phone,
        normalized_recipient_phone=decision.normalized_phone,
        template_key=chosen.local_key,
        language=chosen.language or "ar",
        idempotency_key=scoped_key,
        license_id=license_id,
    )

    _whatsapp_inline_drain()
    row = wa_queue.get_message(row.id) or row

    sent = (row.status == "sent")
    wa_embed.audit_tenant_test_message(
        customer.id, ok=sent, recipient=recipient_phone, template_key=chosen.local_key,
        message_id=row.id, error_code=(row.error_code or ""), error_message=(row.error_message or ""),
    )
    if sent:
        return jsonify({
            "ok": True,
            "message_id": row.id,
            "status": row.status,
            "provider_message_id": row.provider_message_id or "",
            "already_exists": (not created),
        })
    return jsonify({
        "ok": False,
        "message_id": row.id,
        "status": row.status,
        "error_code": row.error_code or "send_failed",
        "message_ar": row.error_message or "تعذّر إرسال رسالة الاختبار.",
    })


@bp.post("/integration/hoberadius/whatsapp/cloud-test")
def hoberadius_whatsapp_cloud_test():
    """Bridge: send a TEST WhatsApp message via the panel's HOUSE Cloud API
    credentials (the settings panel) — test-only, no customer queue.

    Authenticated by the same integration guard triad (HTTPS + signature +
    license). The resolved customer is intentionally unused: the house
    credentials are panel-wide, and this endpoint sends nothing but a test
    template (variables auto-filled, media templates refused). Returns the
    provider message id or a friendly Arabic error."""
    body = request.get_json(silent=True) or {}
    _customer, _license_id, error_response = _whatsapp_integration_context(body)
    if error_response is not None:
        return error_response

    from ..auth.routes import audit
    from ..services.whatsapp import cloud_settings as wac

    if not wac.enabled():
        return jsonify({"ok": False, "error_code": "disabled",
                        "message_ar": "قسم واتساب Cloud API غير مُفعّل في اللوحة."}), 403
    recipient = str(body.get("recipient_phone") or body.get("recipient") or "")
    template_name = str(body.get("template_name") or "")
    language = str(body.get("language") or "")
    try:
        result = wac.send_test_message(
            recipient, template_name=template_name, language=language, actor_audit=audit,
        )
    except wac.CloudSettingsError as exc:
        db.session.rollback()
        return jsonify({"ok": False, "error_code": "validation", "message_ar": str(exc)}), 400
    db.session.commit()
    if result.get("ok"):
        return jsonify({"ok": True, "provider_message_id": result.get("provider_message_id") or ""})
    return jsonify({"ok": False, "error_code": result.get("code") or "send_failed",
                    "message_ar": result.get("message") or "تعذّر إرسال رسالة الاختبار."})


@bp.post("/integration/hoberadius/whatsapp/subscriber-preferences/sync")
def hoberadius_whatsapp_subscriber_sync():
    """Batch-upsert subscriber WhatsApp consent/preferences (capped)."""
    body = request.get_json(silent=True) or {}
    customer, _license_id, error_response = _whatsapp_integration_context(body)
    if error_response is not None:
        return error_response

    subscribers = body.get("subscribers")
    items = subscribers if isinstance(subscribers, list) else []
    # Cap the batch defensively; upsert_subscriber_prefs also caps at 500.
    affected = wa_settings.upsert_subscriber_prefs(customer.id, items[:500])
    return jsonify({"ok": True, "synced": len(affected)})


@bp.post("/integration/hoberadius/whatsapp/messages/status")
def hoberadius_whatsapp_message_status():
    """Report the delivery status of a queued message (customer-scoped)."""
    body = request.get_json(silent=True) or {}
    customer, _license_id, error_response = _whatsapp_integration_context(body)
    if error_response is not None:
        return error_response

    row = None
    idempotency_key = body.get("idempotency_key")
    if idempotency_key not in (None, ""):
        row = wa_queue.get_by_idempotency_key(f"c{customer.id}:{idempotency_key}")
    elif body.get("message_id") not in (None, ""):
        try:
            row = wa_queue.get_message(int(body.get("message_id")))
        except (TypeError, ValueError):
            row = None

    # Scope strictly to the verified customer — never leak another tenant's row.
    if row is None or row.customer_id != customer.id:
        return jsonify({"ok": False, "error_code": "not_found"})

    return jsonify({
        "ok": True,
        "status": row.status,
        "provider_message_id": row.provider_message_id,
        "error_code": row.error_code,
        "error_message": row.error_message,
        "attempts": row.attempts,
    })


# ─────────────────────────────────────────────────────────────────────────
# VPN tunnel provisioning bridge (signed, called by the radius_module runtime)
#
# Same guard triad as the other integration endpoints (HTTPS + HMAC signature +
# license). The panel provisions tunnel accounts CENTRALLY on the owner's CHR
# and delivers credentials here; the customer panel NEVER holds CHR access. The
# clear password is returned only until the customer acknowledges delivery.
# Business rejections (limit reached, CHR not configured) return HTTP 200 with
# ``ok: false`` + a machine ``error_code`` so the caller can branch.
# ─────────────────────────────────────────────────────────────────────────
def _vpn_integration_context(body: dict, *, require_active: bool):
    """Run the shared guard triad and resolve (customer, license).

    Returns ``(customer, license, None)`` on success, or ``(None, None, response)``.
    """
    if not _integration_request_is_secure():
        return None, None, (jsonify({"ok": False, "status": "https_required", "message": "تزويد الأنفاق يتطلب HTTPS."}), 426)
    signed = _verify_integration_signature(body)
    if signed is not None:
        return None, None, signed
    result, error_response = _checked_license_from_integration_body(body)
    if error_response is not None:
        return None, None, error_response
    if not result.license or not result.license.customer:
        return None, None, (jsonify({"ok": False, "status": "not_found"}), 404)
    if require_active and not result.active:
        return None, None, (jsonify({"ok": False, "status": result.status, "message": "الترخيص ليس نشطًا."}), 403)
    return result.license.customer, result.license, None


@bp.post("/integration/hoberadius/vpn/tunnels/request")
def hoberadius_vpn_tunnel_request():
    """Auto-provision an SSTP tunnel for the customer and return its credentials.

    The credentials are returned ONCE here; the customer can also re-fetch any
    not-yet-acknowledged tunnel via the list endpoint below (at-least-once)."""
    body = request.get_json(silent=True) or {}
    customer, license_obj, error_response = _vpn_integration_context(body, require_active=True)
    if error_response is not None:
        return error_response

    from ..services import vpn_tunnels as vt

    tunnel_type = str(body.get("tunnel_type") or "sstp").strip().lower()
    if tunnel_type not in vt.BRIDGE_AUTO_TYPES:
        return jsonify({
            "ok": False,
            "error_code": "type_not_auto",
            "message_ar": "هذا النوع لا يُزوَّد تلقائيًا عبر الجسر؛ يُنشئه المدير يدويًا.",
        })

    try:
        tunnel = vt.provision_tunnel(
            customer,
            license_obj,
            tunnel_type=tunnel_type,
            source="bridge_request",
        )
    except vt.VpnTunnelError as exc:
        db.session.rollback()
        return jsonify({"ok": False, "error_code": exc.code, "message_ar": exc.message})

    audit_customer_control(
        actor_admin_id=None,
        action="customer_vpn_tunnel_provisioned",
        entity_type="customer_vpn_tunnel",
        entity_id=str(tunnel.id),
        summary=f"تزويد نفق {tunnel.tunnel_type} تلقائيًا عبر الجسر للعميل {customer.company_name}",
        metadata={"customer_id": customer.id, "tunnel_type": tunnel.tunnel_type, "username": tunnel.username},
    )
    db.session.commit()
    return jsonify({"ok": True, "tunnel": vt.serialize_tunnel(tunnel, include_password=True)}), 201


@bp.post("/integration/hoberadius/vpn/tunnels")
def hoberadius_vpn_tunnels_list():
    """List the customer's tunnels. Clear passwords are included only for
    tunnels whose delivery has not yet been acknowledged."""
    body = request.get_json(silent=True) or {}
    customer, _license_obj, error_response = _vpn_integration_context(body, require_active=False)
    if error_response is not None:
        return error_response

    from ..services import vpn_tunnels as vt

    tunnels = [vt.serialize_tunnel(t, include_password=True) for t in vt.deliverable_tunnels(customer)]
    return jsonify({"ok": True, "tunnels": tunnels})


@bp.post("/integration/hoberadius/vpn/tunnels/ack")
def hoberadius_vpn_tunnels_ack():
    """Acknowledge delivery of one or more tunnels (stops returning the clear
    password for them)."""
    body = request.get_json(silent=True) or {}
    customer, _license_obj, error_response = _vpn_integration_context(body, require_active=False)
    if error_response is not None:
        return error_response

    from ..services import vpn_tunnels as vt

    usernames = body.get("usernames")
    items = usernames if isinstance(usernames, list) else []
    count = vt.acknowledge_delivery(customer, items)
    db.session.commit()
    return jsonify({"ok": True, "acknowledged": count})


@bp.post("/integration/hoberadius/service-activations/poll")
def hoberadius_service_activations_poll():
    """يُعيد نسخة الترخيص + تخصيصات الخدمة النشطة للوحة العميل لتزامنها محليًا."""
    body = request.get_json(silent=True) or {}
    signed = _verify_integration_signature(body)
    if signed is not None:
        return signed
    result, error_response = _checked_license_from_integration_body(body)
    if error_response is not None:
        return error_response
    if not result.license:
        return jsonify({"ok": False, "status": result.status}), 404

    from ..models import ServiceAllocation
    lic = result.license
    plan = lic.plan

    snapshot = {
        "remote_license_id": lic.id,
        "plan_name": plan.name if plan else "",
        "max_subscribers": (plan.max_subscribers if plan else 0) or 0,
        "max_cards": (plan.max_cards if plan else 0) or 0,
        "max_active_users": (plan.max_active_users if plan else 0) or 0,
        "max_routers": (plan.max_routers if plan else 0) or 0,
        "license_status": result.status,
        "starts_at": lic.starts_at.isoformat() + "Z" if lic.starts_at else None,
        "expires_at": lic.expires_at.isoformat() + "Z" if lic.expires_at else None,
    }

    allocs = ServiceAllocation.query.filter(
        ServiceAllocation.customer_id == lic.customer_id,
        ServiceAllocation.status.in_(["active", "pending"]),
    ).all()

    alloc_list = []
    for a in allocs:
        node = a.chr_node
        alloc_list.append({
            "id": a.id,
            "service_type": a.service_type,
            "status": a.status,
            "chr_node_name": node.name if node else "",
            "chr_node_public_ip": node.public_ip if node else "",
            "speed_limit_mbps": a.speed_limit_mbps or 0,
            "max_accounts": a.max_accounts or 0,
            "max_peers": a.max_peers or 0,
            "transfer_limit_bytes": a.transfer_limit_bytes,
            "expires_at": a.expires_at.isoformat() + "Z" if a.expires_at else None,
        })

    return jsonify({
        "ok": True,
        "status": result.status,
        "license_snapshot": snapshot,
        "allocations": alloc_list,
    })


@bp.post("/integration/hoberadius/instance-ops/heartbeat")
def hoberadius_instance_heartbeat():
    """لوحة العميل تُرسل نبضة حياة — يُحدَّث last_seen_at لـ CustomerRadiusInstance."""
    from datetime import datetime, timezone
    from ..models import CustomerRadiusInstance

    body = request.get_json(silent=True) or {}
    signed = _verify_integration_signature(body)
    if signed is not None:
        return signed
    result, error_response = _checked_license_from_integration_body(body)
    if error_response is not None:
        return error_response
    if not result.license:
        return jsonify({"ok": False, "status": result.status}), 404

    instance = CustomerRadiusInstance.query.filter_by(
        customer_id=result.license.customer_id
    ).first()
    if instance:
        instance.last_seen_at = datetime.now(timezone.utc).replace(tzinfo=None)
        if result.active and instance.status != "active":
            instance.status = "active"
        db.session.commit()

    return jsonify({
        "ok": True,
        "status": "recorded",
        "license_status": result.status,
        "instance_found": instance is not None,
    })


@bp.post("/integration/hoberadius/usage-snapshot/push")
def hoberadius_usage_snapshot_push():
    """لوحة العميل تُرسل ملخّص استخدام الخدمات — يُحفظ في ServiceUsageSnapshot.

    Payload من لوحة العميل:
    {
        "license_key": "...", "server_fingerprint": "...",
        "allocations": [
            {
                "remote_allocation_id": 5,
                "service_type": "sstp",
                "active_accounts": 3,
                "active_peers": 0,
                "used_transfer_bytes": 0,
                "current_mbps": 0.0,
                "health_status": "ok"
            }
        ],
        "overall_health": "ok"
    }
    """
    from datetime import datetime, timezone
    from ..models import ServiceAllocation, ServiceUsageSnapshot

    body = request.get_json(silent=True) or {}
    signed = _verify_integration_signature(body)
    if signed is not None:
        return signed
    result, error_response = _checked_license_from_integration_body(body)
    if error_response is not None:
        return error_response
    if not result.license:
        return jsonify({"ok": False, "status": result.status}), 404

    allocations_data = body.get("allocations") or []
    overall_health   = str(body.get("overall_health") or "unknown")[:20]
    now              = datetime.now(timezone.utc).replace(tzinfo=None)
    saved            = 0

    for item in allocations_data:
        remote_id = item.get("remote_allocation_id")
        if not remote_id:
            continue
        alloc = ServiceAllocation.query.filter_by(
            id=remote_id,
            customer_id=result.license.customer_id,
        ).first()
        if not alloc:
            continue

        hs = str(item.get("health_status") or "unknown")[:20]
        snap = ServiceUsageSnapshot(
            service_allocation_id=alloc.id,
            measured_at=now,
            current_mbps=float(item.get("current_mbps") or 0),
            used_transfer_bytes=int(item.get("used_transfer_bytes") or 0),
            active_accounts=int(item.get("active_accounts") or 0),
            active_peers=int(item.get("active_peers") or 0),
            health_status=hs,
        )
        db.session.add(snap)
        saved += 1

    if saved:
        db.session.commit()

    return jsonify({
        "ok": True,
        "status": "recorded",
        "snapshots_saved": saved,
        "overall_health": overall_health,
    })


# ─────────────────────────────────────────────────────────────────────────
# WhatsApp Meta Cloud webhook (called by Meta, NOT by the radius runtime)
#
# Unlike the integration endpoints above, Meta does NOT speak our HMAC triad
# and sends NO CSRF token / login. This route therefore must be reachable
# unauthenticated. It is CSRF-exempt automatically because ``_install_csrf``
# (app/__init__.py) skips every ``request.path`` that starts with ``/api/``;
# no per-route opt-out is required. Meta authenticates instead via the
# GET verify-token handshake and the POST ``X-Hub-Signature-256`` app-secret
# signature, both handled inside ``app/services/whatsapp/webhook.py``.
#
# The POST ALWAYS returns HTTP 200 after attempting to store events — a 5xx
# would make Meta retry the same delivery repeatedly (a retry storm), so any
# unexpected failure is logged and still answered 200.
# ─────────────────────────────────────────────────────────────────────────
@bp.route("/whatsapp/webhook", methods=["GET", "POST"])
def whatsapp_webhook():
    if request.method == "GET":
        challenge = wa_webhook.verify_challenge(request.args)
        if challenge is not None:
            return Response(challenge, mimetype="text/plain")
        abort(403)

    raw = request.get_data()
    payload = request.get_json(silent=True) or {}
    signature = request.headers.get("X-Hub-Signature-256")
    try:
        summary = wa_webhook.ingest(payload, signature_header=signature, raw_body=raw)
    except Exception:  # noqa: BLE001 — never 5xx to Meta; that triggers retries.
        current_app.logger.exception("WhatsApp webhook ingest failed")
        db.session.rollback()
        return jsonify({"ok": True, "stored": 0, "processed": 0, "skipped_duplicates": 0})
    return jsonify({"ok": True, **summary})


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
