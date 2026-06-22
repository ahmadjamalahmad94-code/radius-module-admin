from __future__ import annotations

from flask import Blueprint, current_app, flash, jsonify, redirect, render_template, request, send_file, session, url_for

from ..extensions import db
# Legacy ``license_integration_secret`` import retired with the linking-auth
# cleanup — the customer portal used to surface the derived secret as «سر
# التوقيع», which no longer exists.
from ..models import Customer, CustomerBackupArtifact, CustomerServiceRequest, CustomerUser, License, LicensePaymentProof, LicensePaymentRequest, Setting, utcnow
from ..services.customer_control import (
    CustomerControlValidationError,
    add_service_request_message,
    audit_customer_control,
    build_runtime_contract_for_license,
    clean_username,
    create_customer_service_request,
    customer_service_map,
    normalize_contact_email,
    normalize_contact_phone,
    service_catalog_items,
    service_label,
    service_limit_fields,
    service_limit_summary,
    service_spec_fields,
    service_tier_for_entitlement,
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
from ..services.customer_backups import (
    delete_customer_backup,
    get_artifact_file,
    list_customer_backups,
    summarize_backup_content,
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
    """Customer submits proof of a manual bank transfer.

    A receipt image (jpg/png/webp/pdf, ≤ 5 MB) is REQUIRED — the owner can't
    review a manual payment without it. Bare-text submissions are rejected
    at the form level (see `public/payment_portal.html`); we also defend
    here so the API can't be bypassed.
    """
    from ..services.payment_proofs import (
        ReceiptValidationError,
        submit_manual_proof_with_receipt,
    )

    payment_request = _get_portal_request(request_id)
    token = request.form.get("token") or request.args.get("token") or ""
    if not payment_request:
        return render_template("public/payment_not_found.html"), 404
    receipt = request.files.get("receipt")
    try:
        submit_manual_proof_with_receipt(
            payment_request=payment_request,
            reference_number=request.form.get("reference_number") or "",
            note=request.form.get("note") or "",
            receipt=receipt,
        )
    except ReceiptValidationError as exc:
        flash(exc.message_ar, "error")
        return redirect(url_for("public.payment_portal", request_id=request_id, token=token))
    except LicensePaymentValidationError as exc:
        flash(payment_error_message(exc), "error")
        return redirect(url_for("public.payment_portal", request_id=request_id, token=token))
    flash("تم إرسال إثبات الدفع مع صورة الإيصال. بانتظار مراجعة المدير.", "success")
    return redirect(url_for("public.payment_portal", request_id=request_id, token=token))


# ───────────────────────────────────────────────────────────────────────────
# Customer-initiated payment submission (manual bank transfer + receipt OR
# redirect to a configured API gateway). This complements the admin-created
# payment request path: a logged-in customer can declare a payment they made
# offline (bank transfer with a phone-camera receipt) and submit it in one go.
# ───────────────────────────────────────────────────────────────────────────

PAYMENT_METHODS_ORDER = ("manual_transfer", "jawalpay", "palpay", "bank_of_palestine")
PAYMENT_METHOD_LABELS = {
    "manual_transfer":   "تحويل بنكي يدوي + إيصال",
    "jawalpay":          "جوال باي",
    "palpay":            "بال باي",
    "bank_of_palestine": "بنك فلسطين",
}


def _payment_methods_for_picker():
    """Build the (key, label, enabled, configured) tuples for the picker.

    Manual transfer is ALWAYS available (no API creds required). The three
    API gateways appear with an "enabled" flag — if they're disabled or not
    configured, the radio is rendered disabled with a friendly hint.
    """
    from ..services import payment_gateways as pg
    out = [("manual_transfer", PAYMENT_METHOD_LABELS["manual_transfer"], True, True)]
    for name in pg.GATEWAY_ORDER:
        enabled = pg.adapter_enabled(name)
        creds = pg.resolved_credentials(name)
        configured = pg.get_adapter(name).configured(creds)
        out.append((name, PAYMENT_METHOD_LABELS.get(name, name),
                    enabled and configured, configured))
    return out


@bp.get("/portal/pay")
def customer_portal_pay_new():
    """Customer-facing payment-submission form."""
    user = _current_customer_user()
    if not user:
        return redirect(url_for("public.customer_portal_login"))
    return render_template(
        "public/customer_portal_pay_new.html",
        customer=user.customer,
        customer_user=user,
        methods=_payment_methods_for_picker(),
        currencies=("USD", "ILS", "JOD", "EUR", "SAR", "AED", "EGP"),
        default_currency=user.customer.currency or "USD",
        purposes=(
            ("renewal", "تجديد اشتراك"),
            ("upgrade", "ترقية الخطة"),
            ("capacity_increase", "زيادة سعة / إضافة خدمة"),
            ("setup_fee", "رسم إعداد"),
        ),
        form=request.args,
    )


@bp.post("/portal/pay")
def customer_portal_pay_submit():
    """Create a new payment request from the customer side.

    For ``manual_transfer``: also accept a receipt image and submit the proof
    in one go (status ends at ``proof_submitted``, ready for owner review).

    For ``jawalpay`` / ``palpay`` / ``bank_of_palestine``: open the gateway
    session (single TODO seam returns an error until the owner supplies API
    keys) and redirect the customer to the provider.
    """
    from decimal import Decimal, InvalidOperation
    from ..services import payment_gateways as pg
    from ..services.payment_gateways import CreatePaymentInput, NotConfiguredError
    from ..services.payment_proofs import (
        ReceiptValidationError,
        submit_manual_proof_with_receipt,
    )

    user = _current_customer_user()
    if not user:
        return redirect(url_for("public.customer_portal_login"))

    method = (request.form.get("method") or "manual_transfer").strip()
    if method not in PAYMENT_METHODS_ORDER:
        flash("طريقة دفع غير معروفة.", "error")
        return redirect(url_for("public.customer_portal_pay_new"))

    purpose = (request.form.get("purpose") or "renewal").strip()
    amount_raw = (request.form.get("amount") or "").strip()
    try:
        amount = Decimal(amount_raw)
        if amount <= 0:
            raise InvalidOperation
    except (InvalidOperation, ValueError):
        flash("المبلغ غير صحيح.", "error")
        return redirect(url_for("public.customer_portal_pay_new"))

    currency = (request.form.get("currency") or user.customer.currency or "USD").strip().upper()

    # Create the LicensePaymentRequest row that anchors the rest of the flow.
    try:
        payment_request = LicensePaymentRequestService().create_request({
            "customer_id": user.customer_id,
            "purpose": purpose,
            "amount": str(amount),
            "currency": currency,
        })
    except LicensePaymentValidationError as exc:
        flash(payment_error_message(exc), "error")
        return redirect(url_for("public.customer_portal_pay_new"))

    if method == "manual_transfer":
        receipt = request.files.get("receipt")
        try:
            submit_manual_proof_with_receipt(
                payment_request=payment_request,
                reference_number=request.form.get("reference_number") or "",
                note=request.form.get("note") or "",
                receipt=receipt,
            )
        except ReceiptValidationError as exc:
            flash(exc.message_ar, "error")
            return redirect(url_for("public.customer_portal_pay_new"))
        except LicensePaymentValidationError as exc:
            flash(payment_error_message(exc), "error")
            return redirect(url_for("public.customer_portal_pay_new"))
        flash("تم استلام دفعتك مع صورة الإيصال. سيتم تفعيل الخدمة بعد مراجعة المدير.", "success")
        return redirect(url_for("public.customer_portal_dashboard"))

    # API gateway path — call the adapter to open a payment at the provider.
    if not pg.adapter_enabled(method):
        flash("هذه البوابة معطّلة حالياً. اختر تحويل بنكي يدوي أو تواصل مع الدعم.", "error")
        return redirect(url_for("public.customer_portal_pay_new"))
    adapter = pg.get_adapter(method)
    creds = pg.resolved_credentials(method)
    try:
        result = adapter.create_payment(creds, CreatePaymentInput(
            amount=amount,
            currency=currency,
            reference=payment_request.reference_code,
            description=f"{purpose} - {user.customer.company_name}",
            callback_url=url_for("public.customer_portal_dashboard", _external=True),
            customer_phone=user.customer.phone or "",
        ))
    except NotConfiguredError:
        flash("بيانات البوابة المختارة غير مكتملة. اختر تحويل بنكي يدوي.", "error")
        return redirect(url_for("public.customer_portal_pay_new"))
    if not result.ok or not result.redirect_url:
        flash(result.message or "تعذّر فتح الدفع لدى البوابة.", "error")
        return redirect(url_for("public.customer_portal_pay_new"))
    flash("جاري تحويلك لإكمال الدفع لدى البوابة.", "info")
    return redirect(result.redirect_url)


@bp.get("/portal/sso")
def customer_portal_sso():
    """One-click SSO from the radius into the customer portal (short-lived token)."""
    from itsdangerous import URLSafeTimedSerializer

    token = request.args.get("t") or ""
    serializer = URLSafeTimedSerializer(str(current_app.config.get("SECRET_KEY") or ""), salt="hoberadius-portal-sso")
    try:
        data = serializer.loads(token, max_age=90)
    except Exception:
        flash("رابط الدخول الموحّد غير صالح أو انتهت صلاحيته. أعد المحاولة من الريدياس.", "error")
        return redirect(url_for("public.customer_portal_login"))
    user = db.session.get(CustomerUser, int(data.get("uid", 0) or 0))
    if not user or not user.active or not user.customer or user.customer.status != "active":
        flash("تعذّر إكمال الدخول الموحّد.", "error")
        return redirect(url_for("public.customer_portal_login"))
    session["customer_user_id"] = user.id
    session["customer_id"] = user.customer_id
    session["customer_name"] = user.full_name or user.username
    flash("تم الدخول إلى بوابة العميل من الريدياس.", "success")
    return redirect(url_for("public.customer_portal_dashboard"))


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
    # License countdown + package (for the «التراخيص» view + renew CTA).
    _days_left = None
    if lic and lic.expires_at:
        _days_left = (lic.expires_at - utcnow()).days
    _plan = lic.plan if lic else None
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
        service_limit_fields=service_limit_fields,
        service_spec_fields=service_spec_fields,
        # License view extras.
        license_days_left=_days_left,
        license_package=getattr(_plan, "name", "") or "",
        plan_admin_limit=getattr(_plan, "max_admins", None),
        pricing_url=url_for("pricing_page"),
        # The customer's own users/admins (portal + radius identities).
        portal_users=customer.users.order_by(CustomerUser.created_at.desc()).all(),
        licenses=customer.licenses.order_by(License.created_at.desc()).all(),
        payment_requests=LicensePaymentRequest.query.filter_by(customer_id=customer.id).order_by(LicensePaymentRequest.created_at.desc()).limit(20).all(),
        service_requests=CustomerServiceRequest.query.filter_by(customer_id=customer.id).order_by(CustomerServiceRequest.created_at.desc()).limit(20).all(),
        customer_backups=list_customer_backups(customer.id),
        # Integrated WhatsApp pane (sidebar) — locked/account/settings/templates/usage/step.
        **whatsapp_pane_context(user),
    )


@bp.get("/portal/backups/<int:artifact_id>/download")
def customer_portal_backup_download(artifact_id: int):
    user = _current_customer_user()
    if not user:
        return redirect(url_for("public.customer_portal_login"))
    resolved = get_artifact_file(user.customer_id, artifact_id)
    if not resolved:
        flash("ملف النسخة غير متاح للتنزيل (ربما لم تُرفع بمحتواها).", "error")
        return redirect(url_for("public.customer_portal_dashboard"))
    path, download_name = resolved
    return send_file(str(path), as_attachment=True, download_name=download_name)


@bp.post("/portal/backups/<int:artifact_id>/delete")
def customer_portal_backup_delete(artifact_id: int):
    """Delete a panel-stored backup from the customer's file — strong-confirmed."""
    user = _current_customer_user()
    if not user:
        return redirect(url_for("public.customer_portal_login"))
    artifact = CustomerBackupArtifact.query.filter_by(id=artifact_id, customer_id=user.customer_id).first()
    if not artifact:
        flash("النسخة المطلوبة غير موجودة.", "error")
        return redirect(url_for("public.customer_portal_dashboard"))
    if (request.form.get("ack") or "").strip() != "1":
        flash("يجب الإقرار بحذف النسخة نهائيًا من ملفك.", "error")
        return redirect(url_for("public.customer_portal_dashboard"))
    if (request.form.get("confirm") or "").strip().upper() != "DELETE":
        flash("لإتمام الحذف يجب كتابة كلمة التأكيد DELETE بشكل صحيح.", "error")
        return redirect(url_for("public.customer_portal_dashboard"))
    reference = artifact.backup_reference
    audit_customer_control(
        actor_admin_id=None,
        action="customer_backup_deleted",
        entity_type="customer_backup",
        entity_id=str(artifact.id),
        summary=f"حذف العميل النسخة الاحتياطية {reference} من ملفه",
        metadata={"customer_id": user.customer_id, "backup_reference": reference, "artifact_id": artifact.id},
    )
    delete_customer_backup(user.customer_id, artifact_id)  # commits row + audit
    flash(f"تم حذف النسخة «{reference}» من ملفك نهائيًا.", "success")
    return redirect(url_for("public.customer_portal_dashboard"))


@bp.get("/portal/backups/<int:artifact_id>/summary")
def customer_portal_backup_summary(artifact_id: int):
    """JSON content summary (row counts) for one stored backup — loaded on demand."""
    user = _current_customer_user()
    if not user:
        return jsonify({"ok": False, "error": "unauthorized", "items": []}), 401
    return jsonify(summarize_backup_content(user.customer_id, artifact_id))


@bp.post("/portal/backups/<int:artifact_id>/restore")
def customer_portal_backup_restore(artifact_id: int):
    """Record a strongly-confirmed restore request for a panel-stored backup.

    Restoring a backup overwrites the live RADIUS database, so the actual swap
    is executed on the customer's own instance. From the portal we register an
    audited restore request (and notify support) after a hard confirmation.
    """
    user = _current_customer_user()
    if not user:
        return redirect(url_for("public.customer_portal_login"))
    artifact = CustomerBackupArtifact.query.filter_by(id=artifact_id, customer_id=user.customer_id).first()
    if not artifact:
        flash("النسخة المطلوبة غير موجودة.", "error")
        return redirect(url_for("public.customer_portal_dashboard"))
    if (request.form.get("ack") or "").strip() != "1":
        flash("يجب الإقرار بأن الاستعادة ستستبدل قاعدة البيانات الحالية.", "error")
        return redirect(url_for("public.customer_portal_dashboard"))
    if (request.form.get("confirm") or "").strip().upper() != "RESTORE":
        flash("لإتمام طلب الاستعادة يجب كتابة كلمة التأكيد RESTORE بشكل صحيح.", "error")
        return redirect(url_for("public.customer_portal_dashboard"))
    try:
        service_request = create_customer_service_request(
            customer=user.customer,
            customer_user_id=user.id,
            service_key="backups",
            request_type="restore",
            notes=(
                f"طلب استعادة النسخة الاحتياطية «{artifact.backup_reference}» "
                f"(بتاريخ {artifact.remote_created_at or artifact.received_at}). "
                "سيتم تنفيذ الاستعادة على ريدياس العميل بعد المراجعة."
            ),
        )
        audit_customer_control(
            actor_admin_id=None,
            action="customer_backup_restore_requested",
            entity_type="customer_backup",
            entity_id=str(artifact.id),
            summary=f"طلب العميل استعادة النسخة {artifact.backup_reference}",
            metadata={
                "customer_id": user.customer_id,
                "backup_reference": artifact.backup_reference,
                "artifact_id": artifact.id,
            },
        )
    except (CustomerControlValidationError, ValueError) as exc:
        flash(payment_error_message(exc), "error")
        return redirect(url_for("public.customer_portal_dashboard"))
    db.session.commit()
    flash(
        f"تم تسجيل طلب استعادة النسخة «{artifact.backup_reference}» (طلب {service_request.public_reference}). "
        "ستتم مراجعته وتنفيذ الاستعادة على الريدياس بأمان، ويمكنك أيضًا تنزيل النسخة لاستعادتها يدويًا.",
        "success",
    )
    return redirect(url_for("public.customer_portal_dashboard"))


@bp.post("/portal/services/<service_key>/request")
def customer_portal_service_request(service_key: str):
    user = _current_customer_user()
    if not user:
        return redirect(url_for("public.customer_portal_login"))
    # The activation / upgrade modal collects spec inputs as `spec_<field_key>`
    # (e.g. spec_max_total). Build a desired_limits dict from whatever the
    # service's own limit fields are, then append a human-readable summary
    # of the requested specs to the customer's notes so the admin sees them
    # in the service-request inbox.
    desired_limits: dict[str, object] = {}  # ints for quantity specs; str for choice (method)
    spec_summary_parts: list[str] = []
    try:
        # SMART per-type schema (service_spec_fields): entitlement limit
        # fields enriched with bounds + request-only extras (e.g. the VPN
        # per-direction speeds). Values are clamped server-side to the
        # field's min/max so a tampered form can't request absurd specs.
        for field in service_spec_fields(service_key):
            field_key = field["key"]
            raw = (request.form.get(f"spec_{field_key}") or "").strip()
            if not raw:
                continue
            # CHOICE fields (e.g. the IP-change method) carry a value from a fixed
            # option set — validated against the option values, stored as a string.
            if str(field.get("type") or "") == "choice":
                allowed = {str(o.get("value")) for o in (field.get("options") or [])}
                if raw not in allowed:
                    continue
                desired_limits[field_key] = raw
                chosen = next((o for o in field["options"] if str(o.get("value")) == raw), None)
                spec_summary_parts.append(f"{field['label']}: {chosen['label'] if chosen else raw}")
                continue
            try:
                value = int(raw)
            except ValueError:
                continue
            if value < 0:
                continue
            f_min = field.get("min")
            f_max = field.get("max")
            if f_min is not None:
                value = max(int(f_min), value)
            if f_max is not None:
                value = min(int(f_max), value)
            desired_limits[field_key] = value
            unit = str(field.get("unit") or "").strip()
            shown = f"{value} {unit}".strip()
            spec_summary_parts.append(f"{field['label']}: {shown}")
        notes = (request.form.get("notes") or "").strip()
        if spec_summary_parts:
            preamble = "المواصفات المطلوبة — " + "، ".join(spec_summary_parts)
            notes = f"{preamble}\n\n{notes}" if notes else preamble
        service_request = create_customer_service_request(
            customer=user.customer,
            customer_user_id=user.id,
            service_key=service_key,
            request_type=request.form.get("request_type") or "activation",
            notes=notes,
            desired_limits=desired_limits or None,
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
        auth_url, code_verifier = gd.authorization_url(user.customer_id)
    except Exception as exc:  # noqa: BLE001
        flash(f"تعذّر بدء ربط Google Drive: {exc}", "error")
        return redirect(url_for("public.customer_portal_dashboard"))
    session["gdrive_code_verifier"] = code_verifier
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
    code_verifier = session.pop("gdrive_code_verifier", "") or ""
    try:
        refresh_token, email = gd.exchange_callback(auth_response, code_verifier=code_verifier)
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


# ───────────────────────────────────────────────────────────────────────────
# Customer-portal WhatsApp wizard (the customer's OWN WhatsApp Business number)
#
# Locked unless the `whatsapp_gateway` service entitlement is granted for this
# customer. Everything is scoped to the SESSION customer — a customer_id in the
# form is never trusted. The only thing that talks to Meta is
# MetaCloudWhatsAppProvider().validate_credentials (a real call, wrapped).
# ───────────────────────────────────────────────────────────────────────────
WHATSAPP_GATEWAY_SERVICE_KEY = "whatsapp_gateway"


def _whatsapp_gateway_granted(customer: Customer) -> bool:
    """True iff the `whatsapp_gateway` service entitlement is granted (active).

    Mirrors the admin grant (entitlement.enabled True + status "active"); any
    other state (missing / disabled / suspended / expired) is LOCKED.
    """
    entitlement = customer_service_map(customer).get(WHATSAPP_GATEWAY_SERVICE_KEY)
    return bool(entitlement and entitlement.enabled and entitlement.status == "active")


def _whatsapp_current_step(account, settings, templates) -> int:
    """Resolve the wizard step (1..6) from the account/settings/templates state.

    1: no account credentials saved yet.
    2: creds saved but the connection is not yet `connected`.
    3: connected but no approved template mapped.
    4: an approved template exists but the service is not enabled (offer test).
    5: service enabled (configure event toggles).
    6: done — connected + approved template + service enabled.
    """
    if account is None or not (account.phone_number_id or "").strip():
        return 1
    if account.connection_status != "connected":
        return 2
    has_approved = any(t.status == "approved" and (t.provider_template_name or "").strip() for t in templates)
    if not has_approved:
        return 3
    if not settings.enabled:
        return 4
    return 6


#: Deep-link to the integrated WhatsApp pane inside the customer dashboard
#: (the standalone page was retired — this lands the user on the pane with the
#: post-redirect flash, and the SPA router activates it from ``?view=``).
WHATSAPP_DASHBOARD_VIEW = "whatsapp"


def _whatsapp_pane_url() -> str:
    """URL of the dashboard with the WhatsApp pane pre-selected (PRG target)."""
    return url_for("public.customer_portal_dashboard") + "?view=" + WHATSAPP_DASHBOARD_VIEW


def whatsapp_pane_context(user: CustomerUser) -> dict:
    """Build the template context the integrated WhatsApp pane needs.

    Returned keys are merged into the dashboard render context. Reuses the same
    helpers as the (now retired) standalone page so the experience is identical:
    ``wa_locked`` / ``wa_account`` / ``wa_account_public`` / ``wa_settings`` /
    ``wa_templates`` / ``wa_usage`` / ``wa_recent_messages`` / ``wa_current_step``.
    A ``wa_`` prefix avoids clashing with the dashboard's own ``settings`` etc.
    """
    from ..services.whatsapp import settings as wa_settings
    from ..services.whatsapp import embedded_signup as wa_embed
    from ..models import WhatsAppMessageQueue, utcnow

    customer = user.customer
    locked = not _whatsapp_gateway_granted(customer)
    if locked:
        return {
            "wa_locked": True,
            "wa_account": None,
            "wa_account_public": {},
            "wa_settings": None,
            "wa_templates": [],
            "wa_usage": {"daily": {}, "monthly": {}},
            "wa_recent_messages": [],
            "wa_current_step": 1,
            "wa_embedded_available": False,
            "wa_embedded_setup_incomplete": False,
            "wa_embedded_config": {},
        }

    now = utcnow()
    account = wa_settings.get_account(customer.id)
    settings_row = wa_settings.get_settings(customer.id)
    templates = wa_settings.list_templates(customer.id)
    usage = wa_settings.get_usage(customer.id, now)
    recent_messages = (
        WhatsAppMessageQueue.query.filter_by(customer_id=customer.id)
        .order_by(WhatsAppMessageQueue.created_at.desc(), WhatsAppMessageQueue.id.desc())
        .limit(10)
        .all()
    )
    return {
        "wa_locked": False,
        "wa_account": account,
        "wa_account_public": wa_settings.account_public_dict(account),
        "wa_settings": settings_row,
        "wa_templates": templates,
        "wa_usage": usage,
        "wa_recent_messages": recent_messages,
        "wa_current_step": _whatsapp_current_step(account, settings_row, templates),
        # Embedded Signup (primary, self-service) availability + browser config.
        "wa_embedded_available": wa_embed.embedded_signup_available(),
        # True when the flag is ON but the panel creds are missing — drives the
        # "admin config incomplete" state (a friendly warning, never a broken CTA).
        "wa_embedded_setup_incomplete": bool(
            current_app.config.get("META_EMBEDDED_SIGNUP_ENABLED", False)
        ) and not wa_embed.embedded_signup_available(),
        "wa_embedded_config": wa_embed.public_config(),
    }


@bp.get("/portal/whatsapp")
def customer_portal_whatsapp():
    """Legacy standalone URL — now deep-links into the integrated dashboard pane.

    The WhatsApp experience lives inside the customer dashboard sidebar; this
    route is kept so old links/bookmarks keep working by redirecting to the
    dashboard with ``?view=whatsapp`` (the SPA then activates the pane).
    """
    user = _current_customer_user()
    if not user:
        return redirect(url_for("public.customer_portal_login"))
    return redirect(_whatsapp_pane_url())


@bp.post("/portal/whatsapp")
def customer_portal_whatsapp_post():
    """Single PRG endpoint dispatched by an `action` field. Always scoped to the
    session customer — a customer_id in the form is intentionally ignored."""
    user = _current_customer_user()
    if not user:
        return redirect(url_for("public.customer_portal_login"))
    customer = user.customer
    # The service must be granted to mutate anything.
    if not _whatsapp_gateway_granted(customer):
        flash("هذه الخدمة غير مفعلة في خطتك الحالية. يمكنك طلب تفعيلها من الإدارة.", "error")
        return redirect(_whatsapp_pane_url())

    from ..services.whatsapp import settings as wa_settings

    action = (request.form.get("action") or "").strip()

    if action == "save_credentials":
        access_token = (request.form.get("access_token") or "").strip()
        wa_settings.upsert_account(
            customer.id,
            meta_business_id=(request.form.get("meta_business_id") or "").strip(),
            whatsapp_business_account_id=(request.form.get("whatsapp_business_account_id") or "").strip(),
            phone_number_id=(request.form.get("phone_number_id") or "").strip(),
            display_phone_number=(request.form.get("display_phone_number") or "").strip(),
            business_display_name=(request.form.get("business_display_name") or "").strip(),
            # Only overwrite the token when a new value is supplied (write-only).
            access_token=access_token or None,
        )
        flash("تم حفظ بيانات الربط. لا يظهر الـ Token بعد حفظه — يمكنك استبداله فقط.", "success")
        return redirect(_whatsapp_pane_url())

    if action == "validate":
        from ..services.whatsapp.providers import (
            MetaCloudWhatsAppProvider,
            WhatsAppProviderError,
        )
        from ..models import utcnow

        account = wa_settings.get_account(customer.id)
        if account is None:
            flash("أدخل بيانات الربط ثم اضغط فحص الربط.", "error")
            return redirect(_whatsapp_pane_url())
        try:
            result = MetaCloudWhatsAppProvider().validate_credentials(account)
        except WhatsAppProviderError as exc:
            wa_settings.set_connection_status(
                customer.id, "error", error_code=exc.code, error_message=exc.message
            )
            flash("يوجد خطأ في الربط. راجع البيانات أو Token. " + (exc.message or ""), "error")
            return redirect(_whatsapp_pane_url())
        # Success: refresh display fields then mark connected.
        account.display_phone_number = result.get("display_phone_number") or account.display_phone_number
        account.business_display_name = result.get("business_display_name") or account.business_display_name
        account.quality_rating = result.get("quality_rating") or account.quality_rating
        account.messaging_limit_tier = result.get("messaging_limit_tier") or account.messaging_limit_tier
        account.last_health_check_at = utcnow()
        db.session.commit()
        wa_settings.set_connection_status(customer.id, "connected")
        flash("تم التحقق من الربط بنجاح.", "success")
        return redirect(_whatsapp_pane_url())

    if action == "save_template":
        local_key = (request.form.get("local_key") or "").strip()
        if not local_key:
            flash("المفتاح المحلي للقالب مطلوب.", "error")
            return redirect(_whatsapp_pane_url())
        language = (request.form.get("language") or "ar").strip() or "ar"
        category = (request.form.get("category") or "UTILITY").strip().upper()
        if category not in ("UTILITY", "MARKETING", "AUTHENTICATION"):
            category = "UTILITY"
        approve = (request.form.get("approve") or "").strip() == "1"
        wa_settings.upsert_template(
            customer.id,
            local_key=local_key,
            provider_template_name=(request.form.get("provider_template_name") or "").strip(),
            language=language,
            category=category,
            body_preview=(request.form.get("body_preview") or "").strip(),
            status="approved" if approve else None,
        )
        if approve:
            wa_settings.set_template_status(customer.id, local_key, language, "approved")
        flash("تم حفظ القالب." + (" وتم اعتماده." if approve else ""), "success")
        return redirect(_whatsapp_pane_url())

    if action == "send_test":
        # Sends through the connected TENANT account (the worker reads the
        # per-customer encrypted token) — never the house credentials.
        from ..services.whatsapp import policy as wa_policy
        from ..services.whatsapp import queue as wa_queue
        from ..services.whatsapp import worker as wa_worker
        from ..services.whatsapp import embedded_signup as wa_embed
        from ..services.whatsapp.phone import WhatsAppPhoneError, normalize_phone_for_whatsapp
        from ..models import utcnow

        recipient = (request.form.get("recipient") or "").strip()
        if not recipient:
            flash("أدخل رقم المستلم للتجربة.", "error")
            return redirect(_whatsapp_pane_url())
        try:
            normalized = normalize_phone_for_whatsapp(recipient)
        except WhatsAppPhoneError as exc:
            flash(str(exc), "error")
            return redirect(_whatsapp_pane_url())

        # Honour the chosen template, else default to hello_world / first approved.
        preferred = (request.form.get("template_key") or "").strip() or None
        chosen = wa_settings.pick_test_template(customer.id, preferred_local_key=preferred)
        if chosen is None:
            flash("لا يوجد قالب واتساب معتمد لإرسال رسالة تجربة. اعتمد قالبًا أولًا.", "error")
            return redirect(_whatsapp_pane_url())

        idem = f"portal-test:{customer.id}:{normalized}:{int(utcnow().timestamp())}"
        decision = wa_policy.can_send(
            customer.id,
            event_type="test_message",
            recipient_phone=recipient,
            template_key=chosen.local_key,
            idempotency_key=idem,
        )
        if not decision.allowed:
            wa_embed.audit_tenant_test_message(
                customer.id, ok=False, recipient=recipient,
                template_key=chosen.local_key, error_code=decision.reason,
            )
            flash(decision.message_ar or "تعذّر إرسال رسالة التجربة.", "error")
            return redirect(_whatsapp_pane_url())

        row, _created = wa_queue.enqueue(
            customer.id,
            source_system="customer_portal",
            source_event_type="test_message",
            recipient_phone=recipient,
            normalized_recipient_phone=decision.normalized_phone or normalized,
            idempotency_key=idem,
            template_key=chosen.local_key,
            template_name=chosen.provider_template_name,
            language=chosen.language or "ar",
        )
        try:
            wa_worker.drain_once()
        except Exception:  # noqa: BLE001 — drain is best-effort.
            db.session.rollback()
        row = wa_queue.get_message(row.id) or row

        sent = (row.status == "sent")
        wa_embed.audit_tenant_test_message(
            customer.id, ok=sent, recipient=recipient, template_key=chosen.local_key,
            message_id=row.id, error_code=(row.error_code or ""), error_message=(row.error_message or ""),
        )
        if sent:
            flash("تم إرسال رسالة التجربة بنجاح ✅. تابع حالتها في سجل الرسائل.", "success")
        else:
            flash("تعذّر إرسال رسالة التجربة. " + (row.error_message or "راجع الربط والقالب ثم أعد المحاولة."), "error")
        return redirect(_whatsapp_pane_url())

    if action in ("enable_events", "save_settings"):
        fields: dict = {
            "enabled": bool(request.form.get("enabled")),
            "require_subscriber_opt_in": bool(request.form.get("require_subscriber_opt_in")),
        }
        for toggle in (
            "allow_otp",
            "allow_expiry_notice",
            "allow_quota_notice",
            "allow_maintenance_notice",
            "allow_password_reset",
            "allow_marketing",
        ):
            fields[toggle] = bool(request.form.get(toggle))
        wa_settings.update_settings(customer.id, **fields)
        flash("تم حفظ الإعدادات.", "success")
        return redirect(_whatsapp_pane_url())

    if action == "disable_service":
        wa_settings.update_settings(customer.id, enabled=False)
        flash("تم إيقاف الخدمة.", "warning")
        return redirect(_whatsapp_pane_url())

    if action == "refresh_status":
        # Re-probe Meta for the connected tenant account and sync health.
        # validate_connection never raises and never leaks the token; it updates
        # last_sync_at/status/last_error and audits whatsapp_connection_synced.
        from ..services.whatsapp import embedded_signup as wa_embed
        account = wa_settings.get_account(customer.id)
        if account is None or not account.access_token_encrypted:
            flash("لا يوجد حساب واتساب مربوط لتحديث حالته.", "error")
            return redirect(_whatsapp_pane_url())
        result = wa_embed.validate_connection(customer.id)
        if result.get("ok"):
            flash("تم تحديث حالة الربط بنجاح.", "success")
        else:
            flash("تعذّر تحديث الحالة. تحقق من الربط أو أعد الاتصال.", "error")
        return redirect(_whatsapp_pane_url())

    if action == "disconnect":
        from ..services.whatsapp import embedded_signup as wa_embed
        wa_embed.disconnect(customer.id)
        flash("تم فصل حساب واتساب. يمكنك إعادة الربط في أي وقت.", "warning")
        return redirect(_whatsapp_pane_url())

    flash("إجراء غير معروف.", "error")
    return redirect(_whatsapp_pane_url())


@bp.get("/portal/whatsapp/embedded/config")
def customer_portal_whatsapp_embedded_config():
    """Safe, non-secret config the browser SDK needs (never the app secret).

    Returns ``{ok, enabled, app_id, config_id, graph_version}``. When embedded
    signup is unavailable (flag off or creds missing) ``enabled`` is False and
    the id fields are blank, so the UI can show the setup-incomplete state
    instead of a broken button. Requires a logged-in portal user.
    """
    user = _current_customer_user()
    if not user:
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    from ..services.whatsapp import embedded_signup as wa_embed
    enabled = wa_embed.embedded_signup_available()
    cfg = wa_embed.public_config() if enabled else {"app_id": "", "config_id": "", "graph_version": ""}
    return jsonify({"ok": True, "enabled": enabled, **cfg})


@bp.post("/portal/whatsapp/embedded/start")
def customer_portal_whatsapp_embedded_start():
    """Begin a server-bound embedded-signup attempt; return one-time state+nonce.

    Issues + persists (hashed) a pending attempt for the SESSION customer and
    audits ``embedded_signup_started``. Tenant-isolated — any customer_id in the
    body is ignored. Behind the feature flag (503 when unavailable). CSRF is
    enforced by the global before_request (X-CSRFToken header).
    """
    user = _current_customer_user()
    if not user:
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    customer = user.customer
    if not _whatsapp_gateway_granted(customer):
        return jsonify({"ok": False, "error": "locked",
                        "message": "هذه الخدمة غير مفعلة في خطتك الحالية."}), 403
    from ..services.whatsapp import embedded_signup as wa_embed
    if not wa_embed.embedded_signup_available():
        return jsonify({"ok": False, "error": "unavailable",
                        "message": "خدمة الربط التلقائي غير مهيأة بعد. استخدم الإعداد المتقدم."}), 503

    issued = wa_embed.start_session(
        customer.id,
        license_id=getattr(customer, "license_id", None) or None,
        initiated_by=user.id,
    )
    return jsonify({
        "ok": True,
        "state": issued["state"],
        "nonce": issued["nonce"],
        "config": wa_embed.public_config(),
    })


@bp.post("/portal/whatsapp/embedded/complete")
def customer_portal_whatsapp_embedded_complete():
    """Finish Meta Embedded Signup for the SESSION customer (AJAX → JSON).

    The browser popup returns {code, waba_id, phone_number_id, state, nonce}; we
    validate the server-issued state (tenant-scoped), complete the exchange +
    storage, and return JSON so the pane updates without a full reload. Scoped to
    the session customer — any customer_id in the body is ignored. A replayed
    callback returns the existing connection without creating a duplicate. CSRF
    is enforced by the global before_request (X-CSRFToken header).
    """
    user = _current_customer_user()
    if not user:
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    customer = user.customer
    if not _whatsapp_gateway_granted(customer):
        return jsonify({"ok": False, "error": "locked",
                        "message": "هذه الخدمة غير مفعلة في خطتك الحالية."}), 403

    from ..services.whatsapp import embedded_signup as wa_embed
    if not wa_embed.embedded_signup_available():
        return jsonify({"ok": False, "error": "unavailable",
                        "message": "خدمة الربط التلقائي غير مهيأة بعد. استخدم الإعداد المتقدم."}), 503

    payload = request.get_json(silent=True) or {}
    try:
        result = wa_embed.complete_with_state(
            customer.id,
            code=(payload.get("code") or "").strip(),
            waba_id=(payload.get("waba_id") or "").strip(),
            phone_number_id=(payload.get("phone_number_id") or "").strip(),
            state=(payload.get("state") or "").strip(),
            nonce=(payload.get("nonce") or "").strip(),
            license_id=getattr(customer, "license_id", None) or None,
        )
    except wa_embed.EmbeddedSignupError as exc:
        # Account status on failure is owned by complete_with_state: a real Meta
        # error marks a non-live account 'error', a failed reconnect keeps the
        # live connection, and a state rejection touches nothing.
        return jsonify({"ok": False, "error": exc.code, "message": exc.message}), 400

    return jsonify({"ok": True, **result, "message": "تم ربط واتساب بنجاح ✅",
                    "redirect": _whatsapp_pane_url()})


def _runtime_setup_for_license(lic: License | None) -> dict:
    """Bridge setup snippet shown in the customer portal.

    Bearer-only: the license key IS the credential, so the previous
    ``HOBERADIUS_ADMIN_SHARED_SECRET`` env var is gone. ``integration_secret``
    is kept in the return dict as an empty string so any existing template
    that reads the key doesn't blow up (the admin customer page no longer
    references it).
    """
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
    env_snippet = "\n".join([
        "HOBERADIUS_ADMIN_BRIDGE_ENABLED=true",
        f"HOBERADIUS_ADMIN_BASE_URL={base_url}",
        f"HOBERADIUS_LICENSE_KEY={lic.license_key}",
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
        "integration_secret": "",
        "env_snippet": env_snippet,
    }
