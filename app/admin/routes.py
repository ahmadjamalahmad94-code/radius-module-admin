from __future__ import annotations

from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation

from flask import Blueprint, flash, jsonify, redirect, render_template, request, session, url_for
from sqlalchemy import func

from ..auth.routes import audit, current_admin, login_required
from ..extensions import db
from ..models import (
    AuditLog,
    Customer,
    CustomerVpnEntitlement,
    License,
    LicenseCheck,
    LicensePaymentProof,
    LicensePaymentRequest,
    LicensePaymentTransaction,
    Plan,
    ProvisioningOrder,
    Renewal,
    Setting,
    VpnServicePlan,
    utcnow,
)
from ..services.license_payments import (
    LicensePaymentApplyService,
    LicensePaymentReportingService,
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
from ..services.vpn_entitlements import (
    VpnEntitlementValidationError,
    apply_plan_defaults,
    build_effective_vpn_entitlement,
    clean_vpn_plan_code,
    find_best_customer_license,
    get_or_create_customer_vpn_entitlement,
    license_allows_vpn_services,
    parse_optional_decimal,
    parse_optional_positive_int,
    serialize_vpn_contract,
    validate_customer_vpn_entitlement,
    validate_entitlement_status,
    validate_positive_limit,
    validate_vpn_plan,
    validate_vpn_speed,
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


def _nullable_decimal(name: str) -> Decimal | None:
    return parse_optional_decimal(request.form.get(name), name)


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


@bp.get("/customers/<int:customer_id>/vpn-service")
@login_required
def customer_vpn_service(customer_id: int):
    customer = db.get_or_404(Customer, customer_id)
    entitlement = get_or_create_customer_vpn_entitlement(customer)
    return _render_customer_vpn_service(customer, entitlement)


@bp.post("/customers/<int:customer_id>/vpn-service")
@login_required
def customer_vpn_service_update(customer_id: int):
    customer = db.get_or_404(Customer, customer_id)
    entitlement = get_or_create_customer_vpn_entitlement(customer)
    try:
        _fill_customer_vpn_entitlement(customer, entitlement)
    except VpnEntitlementValidationError as exc:
        flash(str(exc), "error")
        return _render_customer_vpn_service(customer, entitlement), 400
    db.session.add(entitlement)
    db.session.flush()
    audit(
        "customer_vpn_entitlement_updated",
        "customer_vpn_entitlement",
        str(entitlement.id),
        f"Updated VPN entitlement for {customer.company_name}",
        {
            "customer_id": customer.id,
            "status": entitlement.status,
            "enabled": entitlement.enabled,
            "download_mbps": entitlement.download_mbps,
            "upload_mbps": entitlement.upload_mbps,
            "max_vpn_users": entitlement.max_vpn_users,
        },
    )
    db.session.commit()
    flash("تم حفظ خدمة تغيير IP / VPN للعميل.", "success")
    return redirect(url_for("admin.customer_vpn_service", customer_id=customer.id))


def _render_customer_vpn_service(customer: Customer, entitlement: CustomerVpnEntitlement):
    vpn_plans = VpnServicePlan.query.order_by(VpnServicePlan.is_active.desc(), VpnServicePlan.download_mbps.asc()).all()
    licenses = customer.licenses.order_by(License.created_at.desc()).all()
    current_license = entitlement.license or find_best_customer_license(customer)
    effective = build_effective_vpn_entitlement(
        current_license,
        license_allows_services=license_allows_vpn_services(current_license),
    )
    return render_template(
        "admin/customer_vpn_service.html",
        customer=customer,
        entitlement=entitlement,
        vpn_plans=vpn_plans,
        licenses=licenses,
        current_license=current_license,
        contract=serialize_vpn_contract(effective),
    )


def _fill_customer_vpn_entitlement(customer: Customer, entitlement: CustomerVpnEntitlement) -> None:
    action = (request.form.get("action") or "save").strip()
    requested_status = validate_entitlement_status(request.form.get("status") or "disabled")
    requested_enabled = bool(request.form.get("enabled"))
    will_be_active = action == "activate" or (action == "save" and requested_enabled and requested_status == "active")
    plan_id = _int("vpn_plan_id") if request.form.get("vpn_plan_id") else None
    selected_plan = db.session.get(VpnServicePlan, plan_id) if plan_id else None
    if plan_id and not selected_plan:
        raise VpnEntitlementValidationError("Selected VPN plan was not found.")

    license_id = _int("license_id") if request.form.get("license_id") else None
    selected_license = customer.licenses.filter_by(id=license_id).first() if license_id else None
    if license_id and not selected_license:
        raise VpnEntitlementValidationError("Selected license does not belong to this customer.")

    entitlement.customer_id = customer.id
    entitlement.license_id = selected_license.id if selected_license else None
    entitlement.vpn_plan_id = selected_plan.id if selected_plan else None
    entitlement.expires_at = _dt("expires_at")
    entitlement.notes = (request.form.get("notes") or "").strip()[:2000]
    entitlement.updated_by_admin_id = session.get("admin_id")

    if selected_plan and _should_apply_vpn_plan_defaults():
        apply_plan_defaults(entitlement, selected_plan)
    elif will_be_active:
        entitlement.download_mbps = validate_vpn_speed(request.form.get("download_mbps"), "download_mbps")
        entitlement.upload_mbps = validate_vpn_speed(request.form.get("upload_mbps"), "upload_mbps")
        entitlement.max_vpn_users = validate_positive_limit(request.form.get("max_vpn_users"), "max_vpn_users")
        entitlement.max_locations = validate_positive_limit(request.form.get("max_locations") or 1, "max_locations")
    else:
        entitlement.download_mbps = parse_optional_positive_int(request.form.get("download_mbps"), "download_mbps")
        entitlement.upload_mbps = parse_optional_positive_int(request.form.get("upload_mbps"), "upload_mbps")
        entitlement.max_vpn_users = parse_optional_positive_int(request.form.get("max_vpn_users"), "max_vpn_users")
        entitlement.max_locations = parse_optional_positive_int(request.form.get("max_locations"), "max_locations") or 1

    if action == "activate":
        entitlement.enabled = True
        entitlement.status = "active"
    elif action == "suspend":
        entitlement.enabled = False
        entitlement.status = "suspended"
    elif action == "disable":
        entitlement.enabled = False
        entitlement.status = "disabled"
    else:
        entitlement.enabled = requested_enabled
        entitlement.status = requested_status if requested_enabled else "disabled"
        if entitlement.status != "active":
            entitlement.enabled = False

    validate_customer_vpn_entitlement(entitlement)


def _should_apply_vpn_plan_defaults() -> bool:
    if request.form.get("apply_plan_defaults"):
        return True
    return not any((request.form.get(name) or "").strip() for name in (
        "download_mbps",
        "upload_mbps",
        "max_vpn_users",
        "max_locations",
    ))


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


@bp.get("/vpn-services")
@login_required
def vpn_services_list():
    vpn_plans = VpnServicePlan.query.order_by(VpnServicePlan.is_active.desc(), VpnServicePlan.download_mbps.asc()).all()
    return render_template("admin/vpn_services_list.html", vpn_plans=vpn_plans)


@bp.get("/vpn-services/new")
@login_required
def vpn_service_new():
    return render_template("admin/vpn_service_form.html", vpn_plan=VpnServicePlan(max_locations=1, is_active=True), is_new=True)


@bp.post("/vpn-services/new")
@login_required
def vpn_service_create():
    vpn_plan = VpnServicePlan()
    try:
        _fill_vpn_plan(vpn_plan)
        _validate_unique_vpn_plan_code(vpn_plan)
    except VpnEntitlementValidationError as exc:
        flash(str(exc), "error")
        return render_template("admin/vpn_service_form.html", vpn_plan=vpn_plan, is_new=True), 400
    db.session.add(vpn_plan)
    db.session.flush()
    audit("vpn_service_plan_created", "vpn_service_plan", str(vpn_plan.id), f"Created VPN service plan {vpn_plan.code}")
    db.session.commit()
    flash("تم إنشاء خطة خدمة تغيير IP / VPN.", "success")
    return redirect(url_for("admin.vpn_services_list"))


@bp.get("/vpn-services/<int:vpn_plan_id>/edit")
@login_required
def vpn_service_edit(vpn_plan_id: int):
    vpn_plan = db.get_or_404(VpnServicePlan, vpn_plan_id)
    return render_template("admin/vpn_service_form.html", vpn_plan=vpn_plan, is_new=False)


@bp.post("/vpn-services/<int:vpn_plan_id>/edit")
@login_required
def vpn_service_update(vpn_plan_id: int):
    vpn_plan = db.get_or_404(VpnServicePlan, vpn_plan_id)
    try:
        _fill_vpn_plan(vpn_plan)
        _validate_unique_vpn_plan_code(vpn_plan)
    except VpnEntitlementValidationError as exc:
        flash(str(exc), "error")
        return render_template("admin/vpn_service_form.html", vpn_plan=vpn_plan, is_new=False), 400
    audit("vpn_service_plan_updated", "vpn_service_plan", str(vpn_plan.id), f"Updated VPN service plan {vpn_plan.code}")
    db.session.commit()
    flash("تم تحديث خطة خدمة تغيير IP / VPN.", "success")
    return redirect(url_for("admin.vpn_services_list"))


@bp.post("/vpn-services/<int:vpn_plan_id>/disable")
@login_required
def vpn_service_disable(vpn_plan_id: int):
    vpn_plan = db.get_or_404(VpnServicePlan, vpn_plan_id)
    vpn_plan.is_active = False
    audit("vpn_service_plan_disabled", "vpn_service_plan", str(vpn_plan.id), f"Disabled VPN service plan {vpn_plan.code}")
    db.session.commit()
    flash("تم إيقاف خطة خدمة تغيير IP / VPN.", "warning")
    return redirect(url_for("admin.vpn_services_list"))


@bp.post("/vpn-services/<int:vpn_plan_id>/enable")
@login_required
def vpn_service_enable(vpn_plan_id: int):
    vpn_plan = db.get_or_404(VpnServicePlan, vpn_plan_id)
    vpn_plan.is_active = True
    audit("vpn_service_plan_enabled", "vpn_service_plan", str(vpn_plan.id), f"Enabled VPN service plan {vpn_plan.code}")
    db.session.commit()
    flash("تم تفعيل خطة خدمة تغيير IP / VPN.", "success")
    return redirect(url_for("admin.vpn_services_list"))


def _fill_vpn_plan(vpn_plan: VpnServicePlan) -> None:
    vpn_plan.name = (request.form.get("name") or "").strip()
    vpn_plan.code = clean_vpn_plan_code(request.form.get("code") or "")
    vpn_plan.description = (request.form.get("description") or "").strip()[:2000]
    vpn_plan.download_mbps = validate_vpn_speed(request.form.get("download_mbps"), "download_mbps")
    vpn_plan.upload_mbps = validate_vpn_speed(request.form.get("upload_mbps"), "upload_mbps")
    vpn_plan.max_vpn_users = validate_positive_limit(request.form.get("max_vpn_users"), "max_vpn_users")
    vpn_plan.max_locations = validate_positive_limit(request.form.get("max_locations") or 1, "max_locations")
    vpn_plan.traffic_quota_gb = parse_optional_positive_int(request.form.get("traffic_quota_gb"), "traffic_quota_gb")
    vpn_plan.price_monthly = _nullable_decimal("price_monthly")
    vpn_plan.is_active = bool(request.form.get("is_active"))
    validate_vpn_plan(vpn_plan)


def _validate_unique_vpn_plan_code(vpn_plan: VpnServicePlan) -> None:
    with db.session.no_autoflush:
        duplicate = VpnServicePlan.query.filter(VpnServicePlan.code == vpn_plan.code)
        if vpn_plan.id:
            duplicate = duplicate.filter(VpnServicePlan.id != vpn_plan.id)
        if duplicate.first():
            raise VpnEntitlementValidationError("VPN plan code is already used.")


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


@bp.post("/payments/requests/<int:payment_request_id>/apply-license")
@login_required
def payment_request_apply_license(payment_request_id: int):
    payment_request = db.get_or_404(LicensePaymentRequest, payment_request_id)
    try:
        result = LicensePaymentApplyService().apply_paid_payment(
            payment_request=payment_request,
            actor_admin_id=session.get("admin_id"),
            period_months=_int("period_months", 1),
        )
    except LicensePaymentValidationError as exc:
        flash(str(exc), "error")
        return redirect(url_for("admin.payment_request_detail", payment_request_id=payment_request.id))
    flash(f"تم تنفيذ ربط الدفع بالترخيص: {result.get('status')}", "success")
    return redirect(url_for("admin.payment_request_detail", payment_request_id=payment_request.id))


@bp.get("/payments/reports")
@login_required
def payment_reports():
    service = LicensePaymentReportingService()
    return render_template(
        "admin/payment_reports.html",
        report=service.report(),
        reconciliation=service.reconciliation(),
    )


@bp.get("/api/payments/reports")
@login_required
def payment_reports_api():
    return jsonify({"ok": True, "report": LicensePaymentReportingService().report()})


@bp.get("/api/payments/reconciliation")
@login_required
def payment_reconciliation_api():
    return jsonify({"ok": True, "reconciliation": LicensePaymentReportingService().reconciliation()})


@bp.post("/payments/reports/expire-pending")
@login_required
def payment_expire_pending():
    count = LicensePaymentReportingService().expire_pending_requests()
    audit("license_payments_expired", "license_payment_request", "batch", f"Expired {count} pending payment request(s)")
    db.session.commit()
    flash(f"تم تعليم {count} طلب دفع منتهي كـ expired.", "success")
    return redirect(url_for("admin.payment_reports"))
