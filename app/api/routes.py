from __future__ import annotations

from flask import Blueprint, Response, abort, current_app, jsonify, request, url_for

from ..extensions import db
from ..license_signing import (
    LicenseSignatureError,
    attach_bridge_signature,
    mask_license_key as _mask_license_key,
    verify_license_signature,
)
from ..models import CustomerServiceRequest, CustomerUser, utcnow
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
    add_service_request_message,
    audit_customer_control,
    build_identity_sync_contract,
    build_runtime_contract_for_license,
    clean_username,
    create_customer_service_request,
    ensure_active_portal_user,
    import_radius_admins,
    visible_service_request_messages,
)
from ..services import panel_messaging
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

    # Simple-link: the fingerprint is OPTIONAL/informational now — only the
    # license key is required (docs/SIMPLE_LINK_CONTRACT.md §4). When sent it
    # is still recorded + slot-rotated by check_license for the devices list.
    if not license_key:
        return jsonify({
            "active": False,
            "status": "invalid_request",
            "mode": "denied",
            "message": "license_key is required.",
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
    payload = build_identity_sync_contract(
        result.license,
        license_active=result.active,
        status=result.status,
    )
    # SEC C1 — sign the response with the customer's own license key so it can
    # verify these (possibly privilege-escalating) directives really came from
    # us. Additive field; older clients ignore it.
    attach_bridge_signature(payload, str(result.license.license_key or ""))
    return jsonify(payload)


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


@bp.route("/integration/hoberadius/update/latest", methods=["GET", "POST"])
def hoberadius_update_latest():
    """OPT-IN self-update feed: the LATEST module version advertised to this
    customer, PLUS the cumulative changelog of everything they missed. The
    instance's OWN panel decides whether to install — this only ADVERTISES
    availability + Arabic changelog (no forced push).

    Same integration guard triad as every other bridge endpoint (HTTPS + HMAC
    signature + license_key/server_fingerprint resolution). Accepts BOTH GET and
    POST: the radius side POSTs the signed envelope as the request BODY because a
    plain GET-with-body gets its body stripped by reverse proxies. The handler
    reads the envelope from ``request.get_json`` (body) + ``request.args``
    (query) either way, so both methods behave identically. The customer is
    resolved from the verified license; only THAT customer's applicable releases
    are ever returned.

    Accumulated updates: a customer on 1.0.0 who skipped 1.1/1.2/1.3 updates
    once to the latest. The caller's CURRENT version is read from
    ``current_version`` (body or ``?current_version=`` query) and falls back to
    the envelope ``version``. The response returns the latest at the top and the
    concatenated notes of every release ABOVE the caller's version.

    Response — the exact contract the radius side consumes:
        {
          "version": "1.3.0",              # latest applicable release
          "released_at": "..Z",
          "mandatory": false,              # true if ANY missed release is mandatory
          "min_version": "1.0.0" | null,   # hard floor to jump straight to latest
          "changelog_md": "<all missed notes, newest-first>",
          "releases": [                    # each missed release, newest-first
            {"version": "..", "released_at": "..Z", "changelog_md": "..", "mandatory": bool},
            ...
          ]
        }
    Nothing published/applicable, or already at/above the latest → ``{"version":
    null}``. Advertised regardless of license active-state: an update check must
    keep working even on an expired license so the customer can update.
    """
    from ..services.module_updates import build_update_feed

    body = request.get_json(silent=True) or {}
    if not _integration_request_is_secure():
        return jsonify({"ok": False, "status": "https_required", "message": "فحص التحديثات يتطلب HTTPS."}), 426
    signed = _verify_integration_signature(body)
    if signed is not None:
        return signed
    result, error_response = _checked_license_from_integration_body(body)
    if error_response is not None:
        return error_response
    customer = getattr(getattr(result, "license", None), "customer", None) if result else None
    if customer is None:
        # No customer bound to this license → nothing to advertise (never leak).
        return jsonify({"version": None})
    # Caller's current version: explicit override wins, else the running version
    # reported in the signed envelope. An over-long/garbage value degrades to
    # "unknown" (→ show the full backlog) rather than erroring.
    def _ver(*vals: object) -> str:
        for v in vals:
            try:
                cleaned = clean_text(v, 40)
            except ValueError:
                continue
            if cleaned:
                return cleaned
        return ""
    current_version = _ver(
        body.get("current_version"), request.args.get("current_version"), body.get("version")
    )
    return jsonify(build_update_feed(customer, current_version))


# ════════════════════════════════════════════════════════════════════════════
# Central FCM push — the ONE global mobile app (com.hoberadius.app) connects to
# ALL radius instances and is backed by a single central Firebase project owned
# by THIS licensing panel. So device tokens are registered HERE and FCM is sent
# HERE. A customer radius instance never holds the Firebase key: it FORWARDS
# both (a) the app's token registration and (b) push requests over this signed
# bridge, authenticating with its ``license_key`` bearer. The customer is
# resolved from that license; the push reaches only that customer's devices.
# ════════════════════════════════════════════════════════════════════════════


def _customer_from_result(result):
    """Resolve the Customer from a checked license result, or None."""
    return getattr(getattr(result, "license", None), "customer", None) if result else None


@bp.post("/integration/hoberadius/push/register-token")
def hoberadius_push_register_token():
    """Register/upsert the global app's FCM token for this customer.

    The radius instance forwards the app's ``token`` (+ platform/app_version/
    external_user_id) here; it is stored centrally keyed to the resolved
    customer. Idempotent on the token."""
    body = request.get_json(silent=True) or {}
    if not _integration_request_is_secure():
        return jsonify({"ok": False, "status": "https_required", "message": "تسجيل رمز الجهاز يتطلب HTTPS."}), 426
    signed = _verify_integration_signature(body)
    if signed is not None:
        return signed
    result, error_response = _checked_license_from_integration_body(body)
    if error_response is not None:
        return error_response
    customer = _customer_from_result(result)
    if customer is None:
        return jsonify({"ok": False, "status": "not_found", "message": "لا يوجد عميل مرتبط بهذا الترخيص."}), 404
    try:
        token = clean_text(body.get("token") or body.get("fcm_token"), 512)
        platform = clean_text(body.get("platform"), 16)
        app_version = clean_text(body.get("app_version"), 40)
        external_user_id = clean_text(body.get("external_user_id"), 120)
    except ValueError as exc:
        return jsonify({"ok": False, "status": "invalid_request", "message": str(exc)}), 422
    if not token:
        return jsonify({"ok": False, "status": "invalid_request", "message": "رمز الجهاز (token) مطلوب."}), 422
    from ..services import device_tokens
    device_tokens.register(customer.id, token, platform=platform,
                           app_version=app_version, external_user_id=external_user_id)
    return jsonify({"ok": True, "status": "registered",
                    "devices": device_tokens.count_for_customer(customer.id)}), 201


@bp.post("/integration/hoberadius/push/unregister-token")
def hoberadius_push_unregister_token():
    """Unregister the global app's FCM token (app logout). Idempotent."""
    body = request.get_json(silent=True) or {}
    if not _integration_request_is_secure():
        return jsonify({"ok": False, "status": "https_required", "message": "إلغاء رمز الجهاز يتطلب HTTPS."}), 426
    signed = _verify_integration_signature(body)
    if signed is not None:
        return signed
    result, error_response = _checked_license_from_integration_body(body)
    if error_response is not None:
        return error_response
    if _customer_from_result(result) is None:
        return jsonify({"ok": False, "status": "not_found", "message": "لا يوجد عميل مرتبط بهذا الترخيص."}), 404
    try:
        token = clean_text(body.get("token") or body.get("fcm_token"), 512)
    except ValueError as exc:
        return jsonify({"ok": False, "status": "invalid_request", "message": str(exc)}), 422
    if not token:
        return jsonify({"ok": False, "status": "invalid_request", "message": "رمز الجهاز (token) مطلوب."}), 422
    from ..services import device_tokens
    removed = device_tokens.unregister(token)
    return jsonify({"ok": True, "status": "unregistered", "removed": removed})


@bp.post("/integration/hoberadius/push/send")
def hoberadius_push_send():
    """Dispatch an FCM push to the customer's registered devices.

    A radius instance forwards a notification's ``title``/``body`` (+ optional
    ``data``/``link``/``type``) here; licensing sends the FCM to that customer's
    devices. ``mode="sync"`` dispatches inline and returns the result (used by
    the «أرسل إشعار تجريبي» test-push so the owner sees it); the default
    ``async`` mode queues off-thread and returns ``{queued, devices}`` so a
    normal notification never blocks on the FCM network."""
    body = request.get_json(silent=True) or {}
    if not _integration_request_is_secure():
        return jsonify({"ok": False, "status": "https_required", "message": "دفع الإشعار يتطلب HTTPS."}), 426
    signed = _verify_integration_signature(body)
    if signed is not None:
        return signed
    result, error_response = _checked_license_from_integration_body(body)
    if error_response is not None:
        return error_response
    customer = _customer_from_result(result)
    if customer is None:
        return jsonify({"ok": False, "status": "not_found", "message": "لا يوجد عميل مرتبط بهذا الترخيص."}), 404
    try:
        title = clean_text(body.get("title"), 200)
        msg = clean_text(body.get("body") or body.get("message"), 1000)
        link = clean_text(body.get("link"), 500)
        ntype = clean_text(body.get("type"), 40)
    except ValueError as exc:
        return jsonify({"ok": False, "status": "invalid_request", "message": str(exc)}), 422
    if not title and not msg:
        return jsonify({"ok": False, "status": "invalid_request", "message": "عنوان أو نصّ الإشعار مطلوب."}), 422
    raw_data = body.get("data")
    data = {str(k): str(v) for k, v in raw_data.items()} if isinstance(raw_data, dict) else {}
    if link:
        data.setdefault("link", link)
    if ntype:
        data.setdefault("type", ntype)

    from ..services import device_tokens, push_dispatch
    devices = device_tokens.count_for_customer(customer.id)
    if str(body.get("mode") or "").strip().lower() == "sync":
        res = push_dispatch.dispatch_to_customer(customer.id, title=title, body=msg, data=data)
        return jsonify({"ok": bool(res.get("ok")), "status": res.get("reason") or "sent",
                        "sent": res.get("sent", 0), "failed": res.get("failed", 0),
                        "devices": devices})
    push_dispatch.spawn_dispatch(current_app._get_current_object(), customer.id,
                                 title=title, body=msg, data=data)
    return jsonify({"ok": True, "status": "queued", "devices": devices}), 202


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
    # The public «الباقات والأسعار» deep-link — the radius points its
    # renew/«اعرض الباقات» CTA (pricing_url) here so a locked/expired customer
    # lands on the offers. Best-effort: never fail the contract on a URL build.
    try:
        pricing_url = url_for("pricing_page", _external=True)
    except Exception:  # noqa: BLE001
        pricing_url = "/pricing"
    return jsonify({
        "ok": True,
        "status": result.status,
        "contract": contract,
        "pricing_url": pricing_url,
        # Top-level mirrors of the contract blocks so the radius gate finds them
        # whether it reads the nested contract or the response root. The
        # `license` mirror is CRITICAL: without it the lifecycle gate saw no
        # license status next to provider_grants and locked the panel
        # (no_successful_license_snapshot) even for an active license.
        "license": contract["license"],
        "limits": contract["limits"],
        "services": contract["services"],
        "provider_grants": contract["provider_grants"],
        "fingerprint": contract["fingerprint"],
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
    _svc_key = body.get("service_key") or ""
    # IP-change intake: normalize the customer's requested_speed_mbps + monthly/
    # unlimited intent into desired_limits so it lands in the approval inbox with
    # the speed + computed price (the customer panel pushes this over the bridge).
    if _svc_key == "ip_change_vpn":
        from ..services.ip_change_pricing import normalize_request_desired_limits
        _desired = normalize_request_desired_limits(body)
    else:
        _desired = body.get("desired_limits") if isinstance(body.get("desired_limits"), dict) else {}
    try:
        service_request = create_customer_service_request(
            customer=result.license.customer,
            service_key=_svc_key,
            request_type=body.get("request_type") or "activation",
            notes=body.get("notes") or "",
            desired_limits=_desired,
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


@bp.post("/integration/hoberadius/service-requests/messages")
def hoberadius_service_request_messages():
    """Bidirectional ticket thread over the bridge.

    The radius PULLS the visible message thread for one of its tickets (so the
    provider's «رد» replies reach the customer's panel) and may POST a customer
    reply onto the thread (``message`` field) — closing the support-ticket loop
    without requiring a portal SSO round-trip.
    """
    body = request.get_json(silent=True) or {}
    if not _integration_request_is_secure():
        return jsonify({"ok": False, "status": "https_required", "message": "رسائل الطلبات تتطلب HTTPS."}), 426
    signed = _verify_integration_signature(body)
    if signed is not None:
        return signed
    result, error_response = _checked_license_from_integration_body(body)
    if error_response is not None:
        return error_response
    if not result.license:
        return jsonify({"ok": False, "status": result.status, "message": "الترخيص غير معروف."}), 404
    reference = clean_text(body.get("reference"), 40)
    sr = (CustomerServiceRequest.query
          .filter_by(customer_id=result.license.customer_id, public_reference=reference)
          .first()) if reference else None
    if sr is None:
        return jsonify({"ok": False, "status": "not_found", "message": "لم يتم العثور على الطلب."}), 404
    # Optional customer reply onto the thread (customer → provider).
    reply = (body.get("message") or "").strip()
    if reply:
        try:
            add_service_request_message(sr, body=reply, sender_type="customer", event_type="message")
        except CustomerControlValidationError as exc:
            return jsonify({"ok": False, "status": "invalid_request", "message": str(exc)}), 422
        audit_customer_control(
            actor_admin_id=None, action="customer_service_request_message",
            entity_type="customer_service_request", entity_id=str(sr.id),
            summary=f"رد الزبون على الطلب {sr.public_reference} عبر الجسر",
            metadata={"customer_id": sr.customer_id})
        db.session.commit()
    messages = [{
        "id": m.id,
        "sender": m.sender_type,
        "event": m.event_type,
        "body": m.body,
        "created_at": (m.created_at.replace(microsecond=0).isoformat() + "Z") if m.created_at else None,
    } for m in visible_service_request_messages(sr)]
    return jsonify({
        "ok": True,
        "service_request": {
            "id": sr.id, "reference": sr.public_reference, "title": sr.title,
            "service_key": sr.service_key, "status": sr.status,
        },
        "messages": messages,
    })


@bp.post("/integration/hoberadius/messages/poll")
def hoberadius_messages_poll():
    """The radius pulls provider→customer panel messages (notices + chat replies)
    it hasn't received yet; they're stamped delivered so the next poll is clean."""
    body = request.get_json(silent=True) or {}
    if not _integration_request_is_secure():
        return jsonify({"ok": False, "status": "https_required", "message": "الرسائل تتطلب HTTPS."}), 426
    signed = _verify_integration_signature(body)
    if signed is not None:
        return signed
    result, error_response = _checked_license_from_integration_body(body)
    if error_response is not None:
        return error_response
    if not result.license:
        return jsonify({"ok": False, "status": result.status, "messages": []}), 404
    rows = panel_messaging.poll_undelivered(result.license.customer, mark_delivered=True)
    db.session.commit()
    return jsonify({
        "ok": True,
        "messages": [panel_messaging.to_bridge_dict(m) for m in rows],
        "count": len(rows),
    })


@bp.post("/integration/hoberadius/messages/send")
def hoberadius_messages_send():
    """The radius posts a customer→provider chat/support message into the inbox."""
    body = request.get_json(silent=True) or {}
    if not _integration_request_is_secure():
        return jsonify({"ok": False, "status": "https_required", "message": "الرسائل تتطلب HTTPS."}), 426
    signed = _verify_integration_signature(body)
    if signed is not None:
        return signed
    result, error_response = _checked_license_from_integration_body(body)
    if error_response is not None:
        return error_response
    if not result.license or not result.active:
        return jsonify({"ok": False, "status": result.status, "message": "الترخيص ليس نشطًا."}), 403
    try:
        msg = panel_messaging.record_from_customer(
            result.license.customer,
            body=body.get("body") or body.get("message") or "",
            subject=body.get("subject") or "",
            channel=body.get("channel") or "chat",
            license=result.license,
            sender_label=clean_text(body.get("sender_label"), 120) or "لوحة الزبون",
        )
    except panel_messaging.PanelMessagingError as exc:
        return jsonify({"ok": False, "status": "invalid_request", "message": str(exc)}), 422
    audit_customer_control(
        actor_admin_id=None, action="panel_message_from_customer",
        entity_type="panel_message", entity_id=str(msg.id),
        summary=f"رسالة دعم واردة من {result.license.customer.company_name}",
        metadata={"customer_id": result.license.customer_id, "channel": msg.channel})
    db.session.commit()
    return jsonify({"ok": True, "status": "received", "message_id": msg.id}), 201


@bp.post("/integration/hoberadius/messages/ack")
def hoberadius_messages_ack():
    """The radius confirms the customer saw provider messages (ids list)."""
    body = request.get_json(silent=True) or {}
    if not _integration_request_is_secure():
        return jsonify({"ok": False, "status": "https_required", "message": "الرسائل تتطلب HTTPS."}), 426
    signed = _verify_integration_signature(body)
    if signed is not None:
        return signed
    result, error_response = _checked_license_from_integration_body(body)
    if error_response is not None:
        return error_response
    if not result.license:
        return jsonify({"ok": False, "status": result.status, "acked": 0}), 404
    ids = body.get("message_ids") or body.get("ids") or []
    acked = panel_messaging.ack_seen(result.license.customer, ids if isinstance(ids, list) else [])
    db.session.commit()
    return jsonify({"ok": True, "acked": acked})


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
    if not customer:
        return jsonify({"ok": False, "status": "not_found", "message": "لا يوجد عميل مرتبط بهذا الترخيص."}), 404
    user = customer.users.filter_by(active=True).order_by(CustomerUser.id.asc()).first()
    if not user:
        # No portal user yet → provision one on demand so the SSO link can be
        # minted. Without this a brand-new customer could never reach their
        # /portal Drive-connect page from the radius button.
        try:
            user = ensure_active_portal_user(customer)
            db.session.commit()
        except Exception:  # noqa: BLE001 — never 500 the bridge
            db.session.rollback()
            return jsonify({"ok": False, "status": "no_user", "message": "تعذّر تجهيز مستخدم البوابة. أنشئ مستخدمًا للعميل من ملف العميل ثم أعد المحاولة."}), 409
    from itsdangerous import URLSafeTimedSerializer

    serializer = URLSafeTimedSerializer(str(current_app.config.get("SECRET_KEY") or ""), salt="hoberadius-portal-sso")
    sso_token = serializer.dumps({"uid": user.id, "cid": customer.id})
    sso_url = url_for("public.customer_portal_sso", _external=True) + "?t=" + sso_token + "&focus=gdrive"
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

    البلاغ **جرد كامل** افتراضاً، فتُقلَّم أيُّ لقطة لأدمن لم يَعُد في البلاغ
    (يختفي المحذوف على الراديوس). يمرّر الراديوس ``full_snapshot: false`` صراحةً
    فقط إن أرسل دفعةً جزئية لا يجوز التقليم عليها. يُرضي البلاغُ أيضاً طلب
    «مزامنة الآن» المعلّق فيُمسح.
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
    # A full inventory prunes stale rows; older clients omit the flag → default True.
    prune = bool(body.get("full_snapshot", True))
    imported = import_radius_admins(
        result.license.customer, result.license,
        admins if isinstance(admins, list) else [], prune=prune,
    )
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
        # Normalized 3-state badge (Connected / Needs action / Disconnected) so
        # the radius client can render the spec's status without re-mapping.
        "integration_status": account_public.get("integration_status", "disconnected"),
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
    """Bridge heartbeat + RADIUS auto-provision.

    The radius-module hits this endpoint right after a successful bearer
    authentication. The panel:

    1. validates the license key (bearer auth — see ``verify_license_signature``);
    2. auto-creates / refreshes the customer's ``CustomerRadiusInstance``
       and ``ProxyRealmRoute`` from whatever the radius-module reports
       about its own RADIUS server (see
       :func:`app.services.radius_auto_provision.provision_on_link`);
    3. echoes the resolved instance + route shape in the response so the
       radius-module can confirm the chain is wired end-to-end.

    Contract — the radius-module SHOULD include (all optional; the panel
    fills in sensible defaults for missing fields):

    .. code-block:: json

        {
          "license_key": "HBR-…",                  // required (bearer)
          "instance_url": "https://…",             // optional informational
          "realm": "client5",                      // optional — slug fallback
          "radius_auth_ip": "187.77.70.18",        // RADIUS server IP
          "radius_auth_port": 1812,                // default 1812
          "radius_acct_port": 1813,                // default 1813
          "shared_secret": "…",                    // optional — panel mints one when omitted
          "mgmt_wg_ip": "10.250.0.X",              // optional, informational
          "hostname": "client5-radius",
          "server_fingerprint": "…"
        }

    The response always carries the resolved ``realm`` / ``radius_target``
    and the ``route_id`` so the operator can correlate. When the panel
    minted a fresh shared secret it is returned ONCE in
    ``shared_secret`` so the radius-module can configure its own RADIUS
    to match in the same round-trip — after this call the plaintext is
    only persisted at rest (Setting, Fernet-encrypted when the vault key
    is configured).
    """
    body = request.get_json(silent=True) or {}
    signed = _verify_integration_signature(body)
    if signed is not None:
        return signed
    result, error_response = _checked_license_from_integration_body(body)
    if error_response is not None:
        return error_response
    if not result.license:
        return jsonify({"ok": False, "status": result.status}), 404

    from ..services.radius_auto_provision import provision_on_link
    provision = provision_on_link(
        current_app,
        result.license,
        instance_url=str(body.get("instance_url") or "")[:255],
        realm=str(body.get("realm") or ""),
        radius_auth_ip=str(body.get("radius_auth_ip") or "")[:64],
        radius_auth_port=body.get("radius_auth_port"),
        radius_acct_port=body.get("radius_acct_port"),
        shared_secret=str(body.get("shared_secret") or ""),
        mgmt_wg_ip=str(body.get("mgmt_wg_ip") or "")[:64],
        hostname=str(body.get("hostname") or "")[:255],
        fingerprint=str(body.get("server_fingerprint") or "")[:255],
    )

    # CUSTOMER_RADIUS_TUNNEL_DESIGN §3 — receive ``wg_radius`` report +
    # respond with ``radius_tunnel``. Idempotent: the response is the
    # full desired state every heartbeat; the customer side only
    # rewrites local config when its stored ``config_fingerprint``
    # disagrees with ours. Drift bookkeeping for §6.4 lives in the
    # service module — never log the per-customer secret here.
    radius_tunnel_payload = None
    try:
        from ..models import CustomerRadiusInstance as _Inst
        from ..services.customer_radius_tunnel import (
            build_tunnel_config as _build_tc,
            ingest_wg_radius_report as _ingest_wg,
        )
        instance = (
            _Inst.query.filter_by(customer_id=result.license.customer_id).first()
            if result.license and result.license.customer_id else None
        )
        if instance is not None:
            tc = _build_tc(instance)
            radius_tunnel_payload = tc.as_payload()
            _ingest_wg(
                instance,
                body.get("wg_radius") if isinstance(body.get("wg_radius"), dict) else None,
                published_fingerprint=tc.fingerprint,
            )
    except Exception:  # noqa: BLE001 — degrade gracefully, never break the heartbeat
        current_app.logger.exception(
            "instance-heartbeat: radius_tunnel block degraded to no-op",
        )

    # Registered-inventory snapshot — persist the REAL registered-entity counts
    # the customer radius reports so the licensing usage bars («أجهزة NAS»،
    # «المشتركون») show the truth instead of a proxy (previously the admin
    # roster / accounting history inflated "NAS used"). ``nas_count`` here is
    # COUNT(nas_devices) on the customer side (radacct-independent). Never
    # breaks the heartbeat; a missing/blank inventory simply leaves the prior
    # value untouched.
    try:
        _persist_reported_inventory(result.license, body.get("inventory"))
    except Exception:  # noqa: BLE001 — inventory persistence must never break the heartbeat
        current_app.logger.exception(
            "instance-heartbeat: inventory persistence degraded to no-op",
        )

    db.session.commit()

    response_body: dict = {
        "ok": True,
        "status": "recorded",
        "license_status": result.status,
        "instance_found": True,
        "provision": provision,
    }
    if radius_tunnel_payload is not None:
        response_body["radius_tunnel"] = radius_tunnel_payload
    # Capacity-contract change signal: the radius compares this cheap
    # fingerprint each heartbeat and re-pulls the full capacity-contract when it
    # changed (e.g. right after the owner saves a tariff) — so a disable/hide/
    # limit propagates on the next heartbeat, not after a long delay.
    try:
        contract = build_runtime_contract_for_license(
            result.license, license_active=result.active, status=result.status)
        response_body["capacity_fingerprint"] = contract["fingerprint"]
    except Exception:  # noqa: BLE001 — never break the heartbeat over a hint
        current_app.logger.exception("instance-heartbeat: capacity_fingerprint degraded")
    return jsonify(response_body)


def _persist_reported_inventory(license_obj, inventory) -> None:
    """Store the heartbeat's registered-inventory snapshot on the customer's
    ``CustomerRadiusInstance`` (the per-customer instance record).

    Only ``nas_count`` / ``subscribers_total`` are persisted today — the fields
    the licensing usage bars display. Values are clamped to ``>= 0``; a missing
    key leaves the prior stored value untouched (partial reports never regress a
    good number to the "-1 = never reported" sentinel). The caller wraps this in
    try/except so a bad payload can never break the heartbeat.
    """
    if not isinstance(inventory, dict) or not inventory:
        return
    customer_id = getattr(license_obj, "customer_id", None)
    if not customer_id:
        return
    from datetime import datetime, timezone

    from ..models import CustomerRadiusInstance
    instance = CustomerRadiusInstance.query.filter_by(customer_id=customer_id).first()
    if instance is None:
        return

    def _clamped(key):
        if key not in inventory:
            return None
        try:
            return max(0, int(inventory.get(key)))
        except (TypeError, ValueError):
            return None

    nas = _clamped("nas_count")
    subs = _clamped("subscribers_total")
    touched = False
    if nas is not None:
        instance.reported_nas_count = nas
        touched = True
    if subs is not None:
        instance.reported_subscribers_count = subs
        touched = True
    if touched:
        instance.inventory_reported_at = datetime.now(timezone.utc).replace(tzinfo=None)


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

    # Authenticate Meta's POST against the app-secret X-Hub-Signature-256 BEFORE
    # storing anything. Policy (see app/services/whatsapp/webhook.py):
    #   * a secret is configured (per-tenant or app-level) -> a MISSING,
    #     malformed, or non-matching signature is rejected with 401 (strict).
    #   * no secret configured yet (tenant mid-onboarding) -> we cannot verify;
    #     accept but flag the events unverified and log a warning (Phase-1).
    # We NEVER log the signature or the secret.
    sig_status = wa_webhook.verify_signature(payload, signature, raw)
    if sig_status == wa_webhook.SIG_FAILED:
        current_app.logger.warning(
            "WhatsApp webhook rejected (401): app-secret signature missing or invalid"
        )
        abort(401)
    if sig_status == wa_webhook.SIG_UNVERIFIED_NO_SECRET:
        current_app.logger.warning(
            "WhatsApp webhook accepted UNVERIFIED: no app secret configured for the "
            "targeted account; events stored but not applied. Configure the tenant "
            "webhook secret or META_APP_SECRET to enable strict verification."
        )

    try:
        summary = wa_webhook.ingest(payload, signature_status=sig_status)
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


#: Customer-status values that block the bridge end-to-end.
#:
#: FIX #5 of mock-inventory remediation. The customer-edit form lets an
#: admin set ``customer.status`` to any of {pending, active, inactive,
#: blocked}, but until now the bridge only checked ``license.status``. So
#: marking a customer "blocked" hid them from the portal yet they kept
#: receiving the runtime / identity-sync / capacity contracts. This set
#: defines what counts as "not authorised to operate" — see
#: ``app/admin/routes.py:_fill_customer`` for the source of truth on
#: allowed values.
_BRIDGE_BLOCKED_CUSTOMER_STATUSES = frozenset({"blocked", "inactive", "pending"})


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
    # Simple-link: only the license key is required; the fingerprint is
    # optional/informational (docs/SIMPLE_LINK_CONTRACT.md §4).
    if not license_key:
        return None, (jsonify({"ok": False, "status": "invalid_request", "message": "license_key is required."}), 422)
    result = check_license(
        license_key=license_key,
        fingerprint=fingerprint,
        hostname=hostname,
        version=version,
        install_id=install_id,
        domain=domain,
        ip_address=client_ip(current_app.config.get("TRUST_PROXY_HEADERS", False)),
    )
    # ─── Customer-status gate (FIX #5) ────────────────────────────────
    # Run AFTER license resolution so we can read the resolved customer.
    # We mark the result inactive and emit a clean Arabic reason that every
    # downstream handler already forwards verbatim in its response shape.
    customer = getattr(getattr(result, "license", None), "customer", None) if result else None
    if customer is not None:
        cstatus = (customer.status or "").strip().lower()
        if cstatus in _BRIDGE_BLOCKED_CUSTOMER_STATUSES:
            denial_status = (
                "customer_pending" if cstatus == "pending"
                else "customer_blocked"
            )
            denial_msg = (
                "حساب العميل بانتظار التفعيل من الإدارة." if cstatus == "pending"
                else "حساب العميل موقوف. تواصل مع الدعم."
            )
            # Machine-readable denial: clients branch on ``reason`` to show a
            # friendly message instead of a bare 403 (the proxy-era confusion
            # was exactly this gate denying silently — see SIMPLE_LINK_CONTRACT §2).
            return None, (jsonify({
                "ok": False,
                "status": denial_status,
                "reason": denial_status,
                "message": denial_msg,
                "customer_status": cstatus,
            }), 403)
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


# NOTE: the one-time-activation-code endpoint
#   POST /api/integration/hoberadius/instance/activate
# was retired with the linking-auth cleanup. The owner wanted "license key,
# nothing else"; there's nothing to "activate" anymore — the radius-module
# uses the license key directly as the bearer credential. The route is
# unmounted so old clients trying to call it now get a 404, and the admin-
# side token-mint endpoint is gone too. The ``InstanceActivationToken`` ORM
# stays in models.py for the database heal block (dropping the table is
# done by a follow-up migration; until then, leftover rows are inert).


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
