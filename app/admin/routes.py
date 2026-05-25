from __future__ import annotations

from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation

from flask import Blueprint, flash, jsonify, redirect, render_template, request, session, url_for
from sqlalchemy import func

from ..auth.routes import audit, current_admin, login_required
from ..extensions import db
from ..models import AuditLog, Customer, License, LicenseCheck, LicensePaymentProof, LicensePaymentRequest, LicensePaymentTransaction, Plan, ProvisioningOrder, Renewal, Setting, utcnow
from ..services.license_payments import (
    LicensePaymentRequestRepository,
    LicensePaymentRequestService,
    LicensePaymentReviewService,
    LicensePaymentValidationError,
    PlatformPaymentSettingsRepository,
    instructions_for_request,
    request_to_dict,
    settings_to_dict,
)
from ..services.license_service import (
    default_grace_days,
    generate_license_key,
    renew_license,
    reset_fingerprints,
    set_license_status,
)

bp = Blueprint("admin", __name__, url_prefix="/admin")

FEATURES = [
    ("cards", "البطاقات"),
    ("mikrotik", "MikroTik"),
    ("reports", "التقارير"),
    ("api_access", "API"),
    ("multi_admin", "عدة مدراء"),
    ("backups", "النسخ الاحتياطي"),
    ("advanced_logs", "السجلات المتقدمة"),
]


def _int(name: str, default: int = 0) -> int:
    try:
        return int(request.form.get(name) or default)
    except (TypeError, ValueError):
        return default


def _decimal(name: str, default: str = "0") -> Decimal:
    try:
        return Decimal(request.form.get(name) or default)
    except (InvalidOperation, TypeError):
        return Decimal(default)


def _dt(name: str, default: datetime | None = None) -> datetime | None:
    raw = (request.form.get(name) or "").strip()
    if not raw:
        return default
    try:
        return datetime.fromisoformat(raw.replace("Z", ""))
    except ValueError:
        return default


def _setting(key: str, default: str = "") -> str:
    row = db.session.get(Setting, key)
    return row.value if row else default


def _set_setting(key: str, value: str) -> None:
    row = db.session.get(Setting, key)
    if not row:
        row = Setting(key=key)
    row.value = value
    db.session.add(row)


@bp.get("/")
@bp.get("/dashboard")
@login_required
def dashboard():
    now = utcnow()
    soon = now + timedelta(days=7)
    stats = {
        "customers": Customer.query.count(),
        "active": License.query.filter_by(status="active").count(),
        "expired": License.query.filter(License.expires_at < now).count(),
        "suspended": License.query.filter_by(status="suspended").count(),
        "expiring_soon": License.query.filter(License.expires_at >= now, License.expires_at <= soon).count(),
    }
    recent_checks = LicenseCheck.query.order_by(LicenseCheck.checked_at.desc()).limit(8).all()
    recent_renewals = Renewal.query.order_by(Renewal.created_at.desc()).limit(8).all()
    health = {
        "env": _setting("environment_label", "local"),
        "support_email": _setting("support_email", ""),
        "api_base": _setting("license_api_base_url", ""),
    }
    return render_template("admin/dashboard.html", stats=stats, recent_checks=recent_checks, recent_renewals=recent_renewals, health=health)


@bp.get("/customers")
@login_required
def customers_list():
    q = Customer.query
    search = (request.args.get("q") or "").strip()
    status = (request.args.get("status") or "").strip()
    if search:
        like = f"%{search}%"
        q = q.filter(Customer.company_name.ilike(like) | Customer.contact_name.ilike(like) | Customer.email.ilike(like))
    if status:
        q = q.filter_by(status=status)
    customers = q.order_by(Customer.created_at.desc()).all()
    return render_template("admin/customers_list.html", customers=customers, search=search, status=status)


@bp.get("/customers/new")
@login_required
def customer_new():
    return render_template("admin/customer_form.html", customer=Customer(), is_new=True)


@bp.post("/customers/new")
@login_required
def customer_create():
    customer = Customer()
    _fill_customer(customer)
    db.session.add(customer)
    db.session.flush()
    audit("customer_created", "customer", str(customer.id), f"Created customer {customer.company_name}")
    db.session.commit()
    flash("تم إنشاء العميل.", "success")
    return redirect(url_for("admin.customer_detail", customer_id=customer.id))


@bp.get("/customers/<int:customer_id>")
@login_required
def customer_detail(customer_id: int):
    customer = db.get_or_404(Customer, customer_id)
    licenses = customer.licenses.order_by(License.created_at.desc()).all()
    return render_template("admin/customer_detail.html", customer=customer, licenses=licenses)


@bp.get("/customers/<int:customer_id>/edit")
@login_required
def customer_edit(customer_id: int):
    customer = db.get_or_404(Customer, customer_id)
    return render_template("admin/customer_form.html", customer=customer, is_new=False)


@bp.post("/customers/<int:customer_id>/edit")
@login_required
def customer_update(customer_id: int):
    customer = db.get_or_404(Customer, customer_id)
    _fill_customer(customer)
    audit("customer_updated", "customer", str(customer.id), f"Updated customer {customer.company_name}")
    db.session.commit()
    flash("تم تحديث العميل.", "success")
    return redirect(url_for("admin.customer_detail", customer_id=customer.id))


@bp.post("/customers/<int:customer_id>/delete")
@login_required
def customer_delete(customer_id: int):
    customer = db.get_or_404(Customer, customer_id)
    if customer.licenses.count():
        flash("لا يمكن حذف عميل لديه تراخيص. غيّر حالته إلى غير نشط بدل الحذف.", "error")
        return redirect(url_for("admin.customer_detail", customer_id=customer.id))
    audit("customer_deleted", "customer", str(customer.id), f"Deleted customer {customer.company_name}")
    db.session.delete(customer)
    db.session.commit()
    flash("تم حذف العميل.", "success")
    return redirect(url_for("admin.customers_list"))


def _fill_customer(customer: Customer) -> None:
    customer.company_name = (request.form.get("company_name") or "").strip()
    customer.contact_name = (request.form.get("contact_name") or "").strip()
    customer.email = (request.form.get("email") or "").strip()
    customer.phone = (request.form.get("phone") or "").strip()
    customer.country = (request.form.get("country") or "").strip()
    customer.city = (request.form.get("city") or "").strip()
    customer.notes = (request.form.get("notes") or "").strip()
    customer.status = request.form.get("status") or "active"


@bp.get("/plans")
@login_required
def plans_list():
    plans = Plan.query.order_by(Plan.monthly_price.asc(), Plan.name.asc()).all()
    return render_template("admin/plans_list.html", plans=plans)


@bp.get("/plans/new")
@login_required
def plan_new():
    return render_template("admin/plan_form.html", plan=Plan(currency=_setting("default_currency", "USD")), features=FEATURES, is_new=True)


@bp.post("/plans/new")
@login_required
def plan_create():
    plan = Plan()
    _fill_plan(plan)
    errors = _validate_plan(plan)
    if errors:
        for message in errors:
            flash(message, "error")
        return render_template("admin/plan_form.html", plan=plan, features=FEATURES, is_new=True), 400
    db.session.add(plan)
    db.session.flush()
    audit("plan_created", "plan", str(plan.id), f"Created plan {plan.name}")
    db.session.commit()
    flash("تم إنشاء الخطة.", "success")
    return redirect(url_for("admin.plans_list"))


@bp.get("/plans/<int:plan_id>/edit")
@login_required
def plan_edit(plan_id: int):
    plan = db.get_or_404(Plan, plan_id)
    return render_template("admin/plan_form.html", plan=plan, features=FEATURES, is_new=False)


@bp.post("/plans/<int:plan_id>/edit")
@login_required
def plan_update(plan_id: int):
    plan = db.get_or_404(Plan, plan_id)
    _fill_plan(plan)
    errors = _validate_plan(plan)
    if errors:
        for message in errors:
            flash(message, "error")
        return render_template("admin/plan_form.html", plan=plan, features=FEATURES, is_new=False), 400
    audit("plan_updated", "plan", str(plan.id), f"Updated plan {plan.name}")
    db.session.commit()
    flash("تم تحديث الخطة.", "success")
    return redirect(url_for("admin.plans_list"))


@bp.post("/plans/<int:plan_id>/delete")
@login_required
def plan_delete(plan_id: int):
    plan = db.get_or_404(Plan, plan_id)
    if plan.licenses.count():
        flash("لا يمكن حذف خطة مستخدمة في تراخيص.", "error")
        return redirect(url_for("admin.plans_list"))
    audit("plan_deleted", "plan", str(plan.id), f"Deleted plan {plan.name}")
    db.session.delete(plan)
    db.session.commit()
    flash("تم حذف الخطة.", "success")
    return redirect(url_for("admin.plans_list"))


def _fill_plan(plan: Plan) -> None:
    plan.name = (request.form.get("name") or "").strip()
    plan.slug = (request.form.get("slug") or "").strip().lower()
    plan.monthly_price = _decimal("monthly_price")
    plan.currency = (request.form.get("currency") or _setting("default_currency", "USD")).strip()
    plan.max_users = _int("max_users", 100)
    plan.max_nas = _int("max_nas", 1)
    plan.max_admins = _int("max_admins", 1)
    plan.max_devices = _int("max_devices", 1)
    plan.status = request.form.get("status") or "active"
    plan.features = {key: bool(request.form.get(f"feature_{key}")) for key, _label in FEATURES}


def _validate_plan(plan: Plan) -> list[str]:
    errors: list[str] = []
    if not plan.name:
        errors.append("اسم الخطة مطلوب.")
    if not plan.slug:
        errors.append("المعرّف المختصر مطلوب.")
        return errors

    with db.session.no_autoflush:
        duplicate = Plan.query.filter(Plan.slug == plan.slug)
        if plan.id:
            duplicate = duplicate.filter(Plan.id != plan.id)
        if duplicate.first():
            errors.append("المعرّف المختصر مستخدم في خطة أخرى.")
    return errors


@bp.get("/licenses")
@login_required
def licenses_list():
    q = License.query.join(Customer).join(Plan)
    status = (request.args.get("status") or "").strip()
    search = (request.args.get("q") or "").strip()
    if status:
        q = q.filter(License.status == status)
    if search:
        like = f"%{search}%"
        q = q.filter(License.license_key.ilike(like) | Customer.company_name.ilike(like) | Plan.name.ilike(like))
    licenses = q.order_by(License.created_at.desc()).all()
    return render_template("admin/licenses_list.html", licenses=licenses, status=status, search=search)


@bp.get("/licenses/new")
@login_required
def license_new():
    customers = Customer.query.order_by(Customer.company_name.asc()).all()
    plans = Plan.query.filter_by(status="active").order_by(Plan.name.asc()).all()
    today = utcnow()
    return render_template("admin/license_form.html", customers=customers, plans=plans, today=today)


@bp.post("/licenses/new")
@login_required
def license_create():
    customer = db.get_or_404(Customer, _int("customer_id"))
    plan = db.get_or_404(Plan, _int("plan_id"))
    starts_at = _dt("starts_at", utcnow()) or utcnow()
    expires_at = _dt("expires_at", starts_at + timedelta(days=30)) or (starts_at + timedelta(days=30))
    lic = License(
        customer_id=customer.id,
        plan_id=plan.id,
        license_key=generate_license_key(),
        status=request.form.get("status") or "active",
        starts_at=starts_at,
        expires_at=expires_at,
        grace_until=_dt("grace_until", expires_at + timedelta(days=default_grace_days())),
        max_fingerprints=_int("max_fingerprints", plan.max_devices or 1),
        notes=(request.form.get("notes") or "").strip(),
    )
    db.session.add(lic)
    db.session.flush()
    audit("license_generated", "license", str(lic.id), f"Generated license {lic.license_key}", {
        "customer_id": customer.id,
        "plan_id": plan.id,
    })
    db.session.commit()
    flash("تم إنشاء الترخيص.", "success")
    return redirect(url_for("admin.license_detail", license_id=lic.id))


@bp.get("/licenses/<int:license_id>")
@login_required
def license_detail(license_id: int):
    lic = db.get_or_404(License, license_id)
    checks = lic.checks.order_by(LicenseCheck.checked_at.desc()).limit(30).all()
    renewals = lic.renewals.order_by(Renewal.created_at.desc()).limit(20).all()
    fingerprint_count = len(lic.fingerprints)
    suspicious = fingerprint_count > 1 or db.session.query(func.count(func.distinct(LicenseCheck.ip_address))).filter(
        LicenseCheck.license_id == lic.id,
        LicenseCheck.ip_address != "",
    ).scalar() > 3
    return render_template("admin/license_detail.html", license=lic, checks=checks, renewals=renewals, suspicious=suspicious)


@bp.post("/licenses/<int:license_id>/renew")
@login_required
def license_renew(license_id: int):
    lic = db.get_or_404(License, license_id)
    renew_license(
        lic,
        months=_int("period_months", 1),
        amount=_decimal("amount", str(lic.plan.monthly_price or 0)),
        method=request.form.get("method") or "manual",
        payment_status=request.form.get("status") or "paid",
        notes=(request.form.get("notes") or "").strip(),
        actor_admin_id=session.get("admin_id"),
    )
    flash("تم تجديد الترخيص.", "success")
    return redirect(url_for("admin.license_detail", license_id=lic.id))


@bp.post("/licenses/<int:license_id>/suspend")
@login_required
def license_suspend(license_id: int):
    lic = db.get_or_404(License, license_id)
    set_license_status(lic, "suspended", session.get("admin_id"))
    flash("تم تعليق الترخيص.", "warning")
    return redirect(url_for("admin.license_detail", license_id=lic.id))


@bp.post("/licenses/<int:license_id>/activate")
@login_required
def license_activate(license_id: int):
    lic = db.get_or_404(License, license_id)
    set_license_status(lic, "active", session.get("admin_id"))
    flash("تم تفعيل الترخيص.", "success")
    return redirect(url_for("admin.license_detail", license_id=lic.id))


@bp.post("/licenses/<int:license_id>/revoke")
@login_required
def license_revoke(license_id: int):
    lic = db.get_or_404(License, license_id)
    set_license_status(lic, "revoked", session.get("admin_id"))
    flash("تم إلغاء الترخيص.", "error")
    return redirect(url_for("admin.license_detail", license_id=lic.id))


@bp.post("/licenses/<int:license_id>/reset-fingerprints")
@login_required
def license_reset_fingerprints(license_id: int):
    lic = db.get_or_404(License, license_id)
    reset_fingerprints(lic, session.get("admin_id"))
    flash("تم مسح البصمات.", "success")
    return redirect(url_for("admin.license_detail", license_id=lic.id))


@bp.post("/licenses/<int:license_id>/fingerprints/add")
@login_required
def license_add_fingerprint(license_id: int):
    lic = db.get_or_404(License, license_id)
    fp = (request.form.get("fingerprint") or "").strip()
    items = lic.fingerprints
    if fp and fp not in items:
        items.append(fp)
        lic.fingerprints = items
        audit("fingerprint_added", "license", str(lic.id), f"Added fingerprint to {lic.license_key}", {"fingerprint": fp})
        db.session.commit()
        flash("تمت إضافة البصمة.", "success")
    return redirect(url_for("admin.license_detail", license_id=lic.id))


@bp.post("/licenses/<int:license_id>/fingerprints/remove")
@login_required
def license_remove_fingerprint(license_id: int):
    lic = db.get_or_404(License, license_id)
    fp = (request.form.get("fingerprint") or "").strip()
    items = [item for item in lic.fingerprints if item != fp]
    lic.fingerprints = items
    audit("fingerprint_removed", "license", str(lic.id), f"Removed fingerprint from {lic.license_key}", {"fingerprint": fp})
    db.session.commit()
    flash("تم حذف البصمة.", "success")
    return redirect(url_for("admin.license_detail", license_id=lic.id))


@bp.get("/checks")
@login_required
def checks_list():
    q = LicenseCheck.query
    result = (request.args.get("result") or "").strip()
    search = (request.args.get("q") or "").strip()
    if result:
        q = q.filter_by(result=result)
    if search:
        like = f"%{search}%"
        q = q.filter(LicenseCheck.license_key.ilike(like) | LicenseCheck.fingerprint.ilike(like) | LicenseCheck.hostname.ilike(like))
    checks = q.order_by(LicenseCheck.checked_at.desc()).limit(500).all()
    return render_template("admin/checks_list.html", checks=checks, result=result, search=search)


@bp.get("/renewals")
@login_required
def renewals_list():
    renewals = Renewal.query.order_by(Renewal.created_at.desc()).limit(500).all()
    return render_template("admin/renewals_list.html", renewals=renewals)


@bp.get("/audit-logs")
@login_required
def audit_logs():
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(500).all()
    return render_template("admin/audit_logs.html", logs=logs)


@bp.get("/settings")
@login_required
def settings_page():
    settings = {row.key: row.value for row in Setting.query.order_by(Setting.key.asc()).all()}
    return render_template("admin/settings.html", settings=settings)


@bp.post("/settings")
@login_required
def settings_update():
    for key in (
        "product_name",
        "license_api_base_url",
        "default_grace_days",
        "default_currency",
        "support_email",
        "support_phone",
        "check_interval_recommendation",
        "environment_label",
    ):
        _set_setting(key, (request.form.get(key) or "").strip())
    audit("settings_updated", "settings", "global", "Updated system settings")
    db.session.commit()
    flash("تم حفظ الإعدادات.", "success")
    return redirect(url_for("admin.settings_page"))


def _payment_error(message: str, status_code: int = 400):
    return jsonify({"ok": False, "error": message}), status_code


@bp.get("/api/payments/settings")
@login_required
def payment_settings_api_get():
    settings = PlatformPaymentSettingsRepository().get()
    return jsonify({"ok": True, "settings": settings_to_dict(settings)})


@bp.patch("/api/payments/settings")
@login_required
def payment_settings_api_patch():
    body = request.get_json(silent=True) or {}
    try:
        settings = PlatformPaymentSettingsRepository().upsert(**body)
    except (LicensePaymentValidationError, ValueError) as exc:
        return _payment_error(str(exc), 400)
    audit("payment_settings_updated", "platform_payment_settings", str(settings.id), "Updated license payment settings")
    db.session.commit()
    return jsonify({"ok": True, "settings": settings_to_dict(settings)})


@bp.get("/api/payments/requests")
@login_required
def payment_requests_api_list():
    items = LicensePaymentRequestRepository().list_filtered(
        status=(request.args.get("status") or "").strip(),
        purpose=(request.args.get("purpose") or "").strip(),
        customer_id=int(request.args["customer_id"]) if request.args.get("customer_id") else None,
    )
    return jsonify({"ok": True, "items": [request_to_dict(item, include_internal=True) for item in items]})


@bp.get("/api/payments/requests/<int:payment_request_id>")
@login_required
def payment_requests_api_detail(payment_request_id: int):
    payment_request = db.get_or_404(LicensePaymentRequest, payment_request_id)
    return jsonify({
        "ok": True,
        "payment_request": request_to_dict(payment_request, include_internal=True),
        "instructions": instructions_for_request(payment_request),
    })


@bp.post("/api/payments/requests")
@login_required
def payment_requests_api_create():
    body = request.get_json(silent=True) or {}
    body.pop("status", None)
    try:
        payment_request = LicensePaymentRequestService().create_request(body)
    except (LicensePaymentValidationError, ValueError) as exc:
        return _payment_error(str(exc), 400)
    audit("payment_request_created", "license_payment_request", str(payment_request.id), f"Created payment request {payment_request.reference_code}")
    db.session.commit()
    return jsonify({"ok": True, "payment_request": LicensePaymentRequestService().portal_payload(payment_request)}), 201


@bp.get("/payments/review-queue")
@login_required
def payment_review_queue():
    status = (request.args.get("status") or "proof_submitted").strip()
    query = LicensePaymentRequest.query
    if status:
        query = query.filter_by(status=status)
    requests = query.order_by(LicensePaymentRequest.updated_at.desc()).all()
    return render_template("admin/payment_review_queue.html", requests=requests, status=status)


@bp.get("/payments/requests/<int:payment_request_id>")
@login_required
def payment_request_detail(payment_request_id: int):
    payment_request = db.get_or_404(LicensePaymentRequest, payment_request_id)
    proofs = payment_request.proofs.order_by(LicensePaymentProof.submitted_at.desc()).all()
    transactions = payment_request.transactions.order_by(LicensePaymentTransaction.created_at.desc()).all()
    orders = ProvisioningOrder.query.filter_by(license_payment_request_id=payment_request.id).all()
    return render_template(
        "admin/payment_request_detail.html",
        payment_request=payment_request,
        proofs=proofs,
        transactions=transactions,
        orders=orders,
    )


@bp.post("/payments/requests/<int:payment_request_id>/approve")
@login_required
def payment_request_approve(payment_request_id: int):
    payment_request = db.get_or_404(LicensePaymentRequest, payment_request_id)
    try:
        LicensePaymentReviewService().approve(
            payment_request=payment_request,
            reviewed_by=session.get("admin_id"),
            review_note=request.form.get("review_note") or "",
        )
    except LicensePaymentValidationError as exc:
        flash(str(exc), "error")
        return redirect(url_for("admin.payment_request_detail", payment_request_id=payment_request.id))
    audit("license_payment_approved", "license_payment_request", str(payment_request.id), f"Approved payment {payment_request.reference_code}")
    db.session.commit()
    flash("تم قبول الدفع اليدوي. لم يتم تفعيل الترخيص تلقائيًا بعد.", "success")
    return redirect(url_for("admin.payment_request_detail", payment_request_id=payment_request.id))


@bp.post("/payments/requests/<int:payment_request_id>/reject")
@login_required
def payment_request_reject(payment_request_id: int):
    payment_request = db.get_or_404(LicensePaymentRequest, payment_request_id)
    try:
        LicensePaymentReviewService().reject(
            payment_request=payment_request,
            reviewed_by=session.get("admin_id"),
            review_note=request.form.get("review_note") or "",
        )
    except LicensePaymentValidationError as exc:
        flash(str(exc), "error")
        return redirect(url_for("admin.payment_request_detail", payment_request_id=payment_request.id))
    audit("license_payment_rejected", "license_payment_request", str(payment_request.id), f"Rejected payment {payment_request.reference_code}")
    db.session.commit()
    flash("تم رفض إثبات الدفع.", "warning")
    return redirect(url_for("admin.payment_request_detail", payment_request_id=payment_request.id))
