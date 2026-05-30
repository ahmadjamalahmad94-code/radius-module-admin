from __future__ import annotations

from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for

from ..extensions import db
from ..license_signing import license_integration_secret
from ..models import Customer, CustomerServiceRequest, CustomerUser, License, LicensePaymentProof, LicensePaymentRequest, Setting
from ..services.customer_control import (
    CustomerControlValidationError,
    add_service_request_message,
    audit_customer_control,
    build_runtime_contract_for_license,
    clean_username,
    create_customer_service_request,
    normalize_contact_email,
    normalize_contact_phone,
    service_catalog_items,
    service_label,
    service_limit_summary,
    visible_service_request_messages,
    validate_unique_customer_contact,
    validate_unique_customer_user_email,
)
from ..services.license_payments import (
    LicensePaymentProofService,
    LicensePaymentRequestRepository,
    LicensePaymentRequestService,
    LicensePaymentValidationError,
    instructions_for_request,
    payment_error_message,
)
from ..services.vpn_entitlements import find_best_customer_license, license_allows_vpn_services

bp = Blueprint("public", __name__)


@bp.get("/privacy")
def privacy_policy():
    return render_template(
        "public/privacy.html",
        support_email=current_app.config.get("SUPPORT_EMAIL", ""),
        support_phone=current_app.config.get("SUPPORT_PHONE", ""),
    )


@bp.get("/terms")
def terms_of_service():
    return render_template(
        "public/terms.html",
        support_email=current_app.config.get("SUPPORT_EMAIL", ""),
        support_phone=current_app.config.get("SUPPORT_PHONE", ""),
    )


def _get_portal_request(request_id: int) -> LicensePaymentRequest | None:
    token = (request.args.get("token") or request.form.get("token") or "").strip()
    return LicensePaymentRequestRepository().get_for_portal(request_id, token)


@bp.get("/payments/requests/<int:request_id>")
def payment_portal(request_id: int):
    payment_request = _get_portal_request(request_id)
    if not payment_request:
        return render_template("public/payment_not_found.html"), 404
    return render_template(
        "public/payment_portal.html",
        payment_request=payment_request,
        instructions=instructions_for_request(payment_request),
        token=request.args.get("token") or "",
        proofs=payment_request.proofs.order_by(LicensePaymentProof.submitted_at.desc()).all(),
    )


@bp.post("/payments/requests/<int:request_id>/proofs")
def payment_portal_submit_proof(request_id: int):
    payment_request = _get_portal_request(request_id)
    token = request.form.get("token") or request.args.get("token") or ""
    if not payment_request:
        return render_template("public/payment_not_found.html"), 404
    try:
        LicensePaymentProofService().submit_manual_proof(
            payment_request=payment_request,
            reference_number=request.form.get("reference_number") or "",
            note=request.form.get("note") or "",
        )
    except LicensePaymentValidationError as exc:
        flash(payment_error_message(exc), "error")
        return redirect(url_for("public.payment_portal", request_id=request_id, token=token))
    flash("تم إرسال إثبات الدفع. بانتظار مراجعة الدفع من المدير.", "success")
    return redirect(url_for("public.payment_portal", request_id=request_id, token=token))


@bp.get("/portal/login")
def customer_portal_login():
    if session.get("customer_user_id"):
        return redirect(url_for("public.customer_portal_dashboard"))
    return render_template("public/customer_portal_login.html")


@bp.get("/portal/signup")
def customer_portal_signup():
    if session.get("customer_user_id"):
        return redirect(url_for("public.customer_portal_dashboard"))
    return render_template("public/customer_portal_signup.html")


@bp.post("/portal/signup")
def customer_portal_signup_post():
    try:
        username = clean_username(request.form.get("username") or "")
        email = normalize_contact_email(request.form.get("email") or "")
        phone = normalize_contact_phone(request.form.get("phone") or "")
        password = request.form.get("password") or ""
        password_confirm = request.form.get("password_confirm") or ""
        if not email:
            raise CustomerControlValidationError("البريد الإلكتروني مطلوب.")
        if len(password) < 8:
            raise CustomerControlValidationError("كلمة المرور يجب أن تكون 8 أحرف على الأقل.")
        if password != password_confirm:
            raise CustomerControlValidationError("تأكيد كلمة المرور غير مطابق.")
        if CustomerUser.query.filter_by(username=username).first():
            raise CustomerControlValidationError("اسم المستخدم مستخدم بالفعل.")

        customer = Customer(
            company_name=(request.form.get("company_name") or "").strip()[:180] or email,
            contact_name=(request.form.get("full_name") or "").strip()[:160],
            email=email,
            phone=phone,
            country=(request.form.get("country") or "").strip()[:100],
            city=(request.form.get("city") or "").strip()[:100],
            status="pending",
        )
        user = CustomerUser(
            customer=customer,
            username=username,
            email=email,
            full_name=(request.form.get("full_name") or "").strip()[:160],
            role_key="owner",
            active=False,
        )
        validate_unique_customer_contact(customer, email, phone)
        validate_unique_customer_user_email(user, email)
        user.set_password(password, increment_version=False)
        user.password_version = max(1, int(user.password_version or 0))
        db.session.add(customer)
        db.session.add(user)
        db.session.flush()
        audit_customer_control(
            actor_admin_id=None,
            action="customer_self_signup_pending",
            entity_type="customer",
            entity_id=str(customer.id),
            summary=f"طلب حساب عميل جديد بانتظار الموافقة: {customer.company_name}",
            metadata={"customer_user_id": user.id, "username": username},
        )
        db.session.commit()
    except CustomerControlValidationError as exc:
        flash(str(exc), "error")
        return render_template("public/customer_portal_signup.html", form=request.form), 400
    flash("تم إنشاء طلب الحساب. بانتظار موافقة الإدارة وتفعيل الترخيص والخدمات.", "success")
    return redirect(url_for("public.customer_portal_login"))


@bp.post("/portal/login")
def customer_portal_login_post():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    user = CustomerUser.query.filter(
        (CustomerUser.username == username) | (CustomerUser.email == username)
    ).first()
    if not user or not user.active or not user.customer or user.customer.status != "active" or not user.check_password(password):
        flash("بيانات الدخول غير صحيحة أو الحساب غير مفعل.", "error")
        return render_template("public/customer_portal_login.html", username=username), 401
    session["customer_user_id"] = user.id
    session["customer_id"] = user.customer_id
    session["customer_name"] = user.full_name or user.username
    flash("مرحبًا بك في لوحة العميل.", "success")
    return redirect(url_for("public.customer_portal_dashboard"))


@bp.post("/portal/account/password")
def customer_portal_password_update():
    user = _current_customer_user()
    if not user:
        return redirect(url_for("public.customer_portal_login"))
    current_password = request.form.get("current_password") or ""
    new_password = request.form.get("new_password") or ""
    confirm_password = request.form.get("confirm_password") or ""
    if not user.check_password(current_password):
        flash("كلمة المرور الحالية غير صحيحة.", "error")
        return redirect(url_for("public.customer_portal_dashboard"))
    if len(new_password) < 8:
        flash("كلمة المرور الجديدة يجب أن تكون 8 أحرف على الأقل.", "error")
        return redirect(url_for("public.customer_portal_dashboard"))
    if new_password != confirm_password:
        flash("تأكيد كلمة المرور غير مطابق.", "error")
        return redirect(url_for("public.customer_portal_dashboard"))
    user.set_password(new_password, increment_version=True)
    audit_customer_control(
        actor_admin_id=None,
        action="customer_user_password_changed_from_portal",
        entity_type="customer_user",
        entity_id=str(user.id),
        summary=f"مستخدم العميل {user.username} غيّر كلمة المرور من بوابة العميل",
        metadata={"customer_id": user.customer_id, "password_version": user.password_version},
    )
    db.session.commit()
    flash("تم تحديث كلمة المرور من لوحة التراخيص. سيستلم الريدياس الإصدار الجديد عند المزامنة.", "success")
    return redirect(url_for("public.customer_portal_dashboard"))


@bp.post("/portal/logout")
def customer_portal_logout():
    for key in ("customer_user_id", "customer_id", "customer_name"):
        session.pop(key, None)
    flash("تم تسجيل الخروج.", "info")
    return redirect(url_for("public.customer_portal_login"))


@bp.get("/portal")
def customer_portal_dashboard():
    user = _current_customer_user()
    if not user:
        return redirect(url_for("public.customer_portal_login"))
    customer = user.customer
    lic = find_best_customer_license(customer)
    contract = build_runtime_contract_for_license(
        lic,
        license_active=license_allows_vpn_services(lic),
        status=lic.status if lic else "not_found",
    )
    from ..services import google_drive as gd
    gdrive = gd.status(customer.id)
    gdrive["backups_active"] = bool((contract.get("services") or {}).get("backups", {}).get("enabled"))
    return render_template(
        "public/customer_portal_dashboard.html",
        customer=customer,
        customer_user=user,
        current_license=lic,
        contract=contract,
        gdrive=gdrive,
        runtime_setup=_runtime_setup_for_license(lic),
        service_catalog=service_catalog_items(),
        service_limit_summary=service_limit_summary,
        licenses=customer.licenses.order_by(License.created_at.desc()).all(),
        payment_requests=LicensePaymentRequest.query.filter_by(customer_id=customer.id).order_by(LicensePaymentRequest.created_at.desc()).limit(20).all(),
        service_requests=CustomerServiceRequest.query.filter_by(customer_id=customer.id).order_by(CustomerServiceRequest.created_at.desc()).limit(20).all(),
    )


@bp.post("/portal/services/<service_key>/request")
def customer_portal_service_request(service_key: str):
    user = _current_customer_user()
    if not user:
        return redirect(url_for("public.customer_portal_login"))
    try:
        service_request = create_customer_service_request(
            customer=user.customer,
            customer_user_id=user.id,
            service_key=service_key,
            request_type=request.form.get("request_type") or "activation",
            notes=request.form.get("notes") or "",
        )
        amount = (request.form.get("amount") or "").strip()
        payment_request = None
        if amount:
            payment_request = LicensePaymentRequestService().create_request({
                "customer_id": user.customer_id,
                "license_id": request.form.get("license_id") or "",
                "purpose": "capacity_increase",
                "amount": amount,
            })
        audit_customer_control(
            actor_admin_id=None,
            action="customer_service_request_created",
            entity_type="customer_service_request",
            entity_id=str(service_request.id),
            summary=f"فتح العميل طلب خدمة {service_request.public_reference}",
            metadata={"customer_id": user.customer_id, "customer_user_id": user.id, "service_key": service_key},
        )
    except (CustomerControlValidationError, LicensePaymentValidationError, ValueError) as exc:
        flash(payment_error_message(exc), "error")
        return redirect(url_for("public.customer_portal_dashboard"))
    db.session.commit()
    svc_name = service_label(service_key)
    if payment_request:
        flash(f"تم إنشاء طلب تفعيل «{svc_name}» وطلب الدفع اليدوي.", "success")
        return redirect(url_for("public.payment_portal", request_id=payment_request.id, token=payment_request.access_token))
    req_type = service_request.request_type or "activation"
    verb = "ترقية" if req_type == "upgrade" else "تفعيل"
    flash(f"تم تسجيل طلب {verb} خدمة «{svc_name}» بنجاح. ستتم مراجعته وإشعارك عند التفعيل.", "success")
    return redirect(url_for("public.customer_portal_dashboard"))


def _backups_service_active(customer) -> bool:
    """Is the paid `backups` service active for this customer's contract?"""
    try:
        lic = find_best_customer_license(customer)
        contract = build_runtime_contract_for_license(
            lic, license_active=license_allows_vpn_services(lic),
            status=lic.status if lic else "not_found",
        )
        return bool((contract.get("services") or {}).get("backups", {}).get("enabled"))
    except Exception:
        return False


@bp.get("/portal/google-drive/connect")
def google_drive_connect():
    user = _current_customer_user()
    if not user:
        return redirect(url_for("public.customer_portal_login"))
    from ..services import google_drive as gd
    # Google Drive is the customer's OWN free account — it is NOT the paid
    # service. (The paid service is uploading to the license-panel file.)
    if not gd.is_configured():
        flash("لم يتم إعداد تكامل Google من الإدارة بعد. تواصل مع الدعم.", "error")
        return redirect(url_for("public.customer_portal_dashboard"))
    if not gd.libs_available():
        flash("مكتبات Google غير مثبّتة على الخادم بعد. تواصل مع الدعم.", "error")
        return redirect(url_for("public.customer_portal_dashboard"))
    try:
        auth_url = gd.authorization_url(user.customer_id)
    except Exception as exc:  # noqa: BLE001
        flash(f"تعذّر بدء ربط Google Drive: {exc}", "error")
        return redirect(url_for("public.customer_portal_dashboard"))
    return redirect(auth_url)


@bp.get("/portal/google-drive/callback")
def google_drive_callback():
    user = _current_customer_user()
    if not user:
        return redirect(url_for("public.customer_portal_login"))
    from ..services import google_drive as gd
    if request.args.get("error"):
        flash("تم إلغاء ربط Google Drive.", "warning")
        return redirect(url_for("public.customer_portal_dashboard"))
    state_customer = gd.read_state(request.args.get("state") or "")
    if state_customer != user.customer_id:
        flash("جلسة الربط غير صالحة أو منتهية. أعد المحاولة.", "error")
        return redirect(url_for("public.customer_portal_dashboard"))
    # Rebuild the authorization response on the canonical (https) redirect URI
    # so the OAuth library never trips on a proxied http scheme.
    qs = request.query_string.decode("utf-8")
    auth_response = gd.redirect_uri() + (("?" + qs) if qs else "")
    try:
        refresh_token, email = gd.exchange_callback(auth_response)
        gd.store_connection(user.customer_id, refresh_token=refresh_token, email=email)
        audit_customer_control(
            actor_admin_id=None,
            action="customer_google_drive_connected",
            entity_type="customer",
            entity_id=str(user.customer_id),
            summary=f"ربط العميل حساب Google Drive ({email})",
            metadata={"customer_id": user.customer_id, "google_email": email},
        )
        db.session.commit()
        flash("تم ربط Google Drive بنجاح. ستُرفع نسخك الاحتياطية إلى درايفك الخاص تلقائيًا.", "success")
    except Exception as exc:  # noqa: BLE001
        flash(f"تعذّر إكمال ربط Google Drive: {exc}", "error")
    return redirect(url_for("public.customer_portal_dashboard"))


@bp.post("/portal/google-drive/disconnect")
def google_drive_disconnect():
    user = _current_customer_user()
    if not user:
        return redirect(url_for("public.customer_portal_login"))
    from ..services import google_drive as gd
    gd.disconnect(user.customer_id)
    audit_customer_control(
        actor_admin_id=None,
        action="customer_google_drive_disconnected",
        entity_type="customer",
        entity_id=str(user.customer_id),
        summary="فصل العميل حساب Google Drive",
        metadata={"customer_id": user.customer_id},
    )
    db.session.commit()
    flash("تم فصل Google Drive. لن تُرفع نسخ جديدة إلى درايفك.", "info")
    return redirect(url_for("public.customer_portal_dashboard"))


@bp.get("/portal/service-requests/<int:request_id>")
def customer_portal_service_request_detail(request_id: int):
    user = _current_customer_user()
    if not user:
        return redirect(url_for("public.customer_portal_login"))
    service_request = CustomerServiceRequest.query.filter_by(id=request_id, customer_id=user.customer_id).first_or_404()
    return render_template(
        "public/customer_service_request_detail.html",
        customer=user.customer,
        customer_user=user,
        service_request=service_request,
        messages=visible_service_request_messages(service_request),
        payment_request=service_request.payment_request,
    )


@bp.post("/portal/service-requests/<int:request_id>/reply")
def customer_portal_service_request_reply(request_id: int):
    user = _current_customer_user()
    if not user:
        return redirect(url_for("public.customer_portal_login"))
    service_request = CustomerServiceRequest.query.filter_by(id=request_id, customer_id=user.customer_id).first_or_404()
    try:
        add_service_request_message(
            service_request,
            sender_type="customer",
            customer_user_id=user.id,
            body=request.form.get("message") or "",
        )
        if service_request.status == "pending":
            service_request.status = "under_review"
        audit_customer_control(
            actor_admin_id=None,
            action="customer_service_request_replied",
            entity_type="customer_service_request",
            entity_id=str(service_request.id),
            summary=f"رد العميل على طلب الخدمة {service_request.public_reference}",
            metadata={"customer_id": user.customer_id, "customer_user_id": user.id},
        )
        db.session.commit()
        flash("تم إرسال رسالتك للإدارة.", "success")
    except CustomerControlValidationError as exc:
        db.session.rollback()
        flash(str(exc), "error")
    return redirect(url_for("public.customer_portal_service_request_detail", request_id=service_request.id))


def _current_customer_user() -> CustomerUser | None:
    user_id = session.get("customer_user_id")
    if not user_id:
        return None
    try:
        return db.session.get(CustomerUser, int(user_id))
    except (TypeError, ValueError):
        return None


def _runtime_setup_for_license(lic: License | None) -> dict:
    setting = db.session.get(Setting, "license_api_base_url")
    base_url = str(current_app.config.get("LICENSE_API_BASE_URL") or (setting.value if setting else "")).strip().rstrip("/")
    if not base_url:
        base_url = request.url_root.rstrip("/")
    if not lic:
        return {
            "available": False,
            "base_url": base_url,
            "license_key": "",
            "integration_secret": "",
            "env_snippet": "",
        }
    integration_secret = license_integration_secret(current_app, lic.license_key)
    env_snippet = "\n".join([
        "HOBERADIUS_ADMIN_BRIDGE_ENABLED=true",
        f"HOBERADIUS_ADMIN_BASE_URL={base_url}",
        f"HOBERADIUS_LICENSE_KEY={lic.license_key}",
        f"HOBERADIUS_ADMIN_SHARED_SECRET={integration_secret}",
        "HOBERADIUS_ADMIN_RUNTIME_CONTRACT_SYNC=1",
        "HOBERADIUS_ADMIN_IDENTITY_SYNC_ENABLED=1",
        "HOBERADIUS_ADMIN_IDENTITY_SYNC_ON_LOGIN=1",
        "HOBERADIUS_ADMIN_BRIDGE_WORKER=1",
        "HOBERADIUS_ADMIN_BRIDGE_SYNC_INTERVAL_SECONDS=300",
    ])
    return {
        "available": True,
        "base_url": base_url,
        "license_key": lic.license_key,
        "integration_secret": integration_secret,
        "env_snippet": env_snippet,
    }
