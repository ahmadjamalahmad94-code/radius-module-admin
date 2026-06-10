from __future__ import annotations

import re
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation

from pathlib import Path

from flask import Blueprint, abort, current_app, flash, jsonify, redirect, render_template, request, send_file, session, url_for
from sqlalchemy import func

from ..auth.routes import audit, current_admin, login_required, super_admin_required
from ..extensions import db
from ..models import (
    AuditLog,
    ChrSpeedProfile,
    Customer,
    CustomerRadiusAdmin,
    CustomerServiceEntitlement,
    CustomerServiceRequest,
    CustomerServiceRequestMessage,
    CustomerUser,
    CustomerVpnEntitlement,
    InstanceActivationToken,
    License,
    LicenseCheck,
    LicensePaymentProof,
    LicensePaymentRequest,
    LicensePaymentTransaction,
    LicenseServiceOverride,
    Plan,
    ProvisioningOrder,
    Renewal,
    ServiceCatalogItem,
    Setting,
    VpnServicePlan,
    WhatsAppMessageQueue,
    WhatsAppServiceSettings,
    WhatsAppTenantAccount,
    WhatsAppWebhookEvent,
    utcnow,
)
from ..services.customer_control import (
    CustomerControlValidationError,
    add_service_request_message,
    audit_customer_control,
    build_runtime_contract_for_license,
    clean_role_key,
    clean_service_request_status,
    clean_service_key,
    clean_service_status,
    clean_username,
    customer_service_map,
    customer_users_version,
    get_or_create_service_entitlement,
    parse_json_object,
    parse_optional_datetime,
    parse_optional_decimal as parse_service_decimal,
    normalize_contact_email,
    normalize_contact_phone,
    radius_admins_for_customer,
    service_catalog_items,
    service_label,
    service_limit_fields,
    service_limit_summary,
    validate_unique_customer_contact,
    validate_unique_customer_user_email,
)
from ..services.customer_backups import (
    get_artifact_file,
    list_customer_backups,
)
from ..services.license_payments import (
    LicensePaymentApplyService,
    LicensePaymentReportingService,
    LicensePaymentRequestRepository,
    LicensePaymentRequestService,
    LicensePaymentReviewService,
    LicensePaymentValidationError,
    PlatformPaymentSettingsRepository,
    LicensePaymentProofService,
    instructions_for_request,
    payment_error_message,
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


# FIX #4: server-enforce section visibility. Hidden sections now 404 on
# direct URL hits in addition to disappearing from the sidebar.
@bp.before_request
def _enforce_section_visibility():
    from flask import request as _req
    from .section_visibility import is_endpoint_hidden
    if is_endpoint_hidden(_req.endpoint or ""):
        abort(404)


FEATURES = [
    ("cards", "البطاقات"),
    ("mikrotik", "إدارة MikroTik"),
    ("reports", "التقارير"),
    ("api_access", "واجهة التكامل"),
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


def _customer_user_return_url(customer_id: int) -> str:
    """عند العمل من صفحة «مستخدمو العميل» المستقلة نعود إليها بدل صفحة العميل 360."""
    target = (request.form.get("return_to") or request.args.get("return_to") or "").strip()
    if target == "users":
        return url_for("admin.customer_users", customer_id=customer_id)
    return url_for("admin.customer_detail", customer_id=customer_id)


def _fill_customer_user(customer_user: CustomerUser, *, require_password: bool) -> None:
    username = clean_username(request.form.get("username") or "")
    with db.session.no_autoflush:
        duplicate = CustomerUser.query.filter(CustomerUser.username == username)
        if customer_user.id:
            duplicate = duplicate.filter(CustomerUser.id != customer_user.id)
        if duplicate.first():
            raise CustomerControlValidationError("اسم المستخدم مستخدم بالفعل.")
        email = normalize_contact_email(request.form.get("email") or "")
        validate_unique_customer_user_email(customer_user, email)
    customer_user.username = username
    customer_user.email = email
    customer_user.full_name = (request.form.get("full_name") or "").strip()[:160]
    customer_user.role_key = clean_role_key(request.form.get("role_key") or "owner")
    # سوبر يوزر صريح: يضمن صلاحية كاملة على راديوس العميل عبر الجسر دائماً.
    customer_user.is_super = bool(request.form.get("is_super"))
    customer_user.active = bool(request.form.get("active"))
    password = request.form.get("password") or ""
    if require_password and not password:
        raise CustomerControlValidationError("كلمة المرور مطلوبة.")
    if password:
        if len(password) < 8:
            raise CustomerControlValidationError("كلمة المرور يجب أن تكون 8 أحرف على الأقل.")
        customer_user.set_password(password, increment_version=not require_password)
        if require_password and not customer_user.password_version:
            customer_user.password_version = 1


def _fill_customer_service_entitlement(customer: Customer, entitlement: CustomerServiceEntitlement) -> None:
    status = clean_service_status(request.form.get("status") or "disabled")
    action = (request.form.get("action") or "save").strip()
    if action == "activate":
        status = "active"
    elif action == "suspend":
        status = "suspended"
    elif action == "disable":
        status = "disabled"
    license_id = _int("license_id") if request.form.get("license_id") else None
    selected_license = customer.licenses.filter_by(id=license_id).first() if license_id else None
    if license_id and not selected_license:
        raise CustomerControlValidationError("الترخيص المختار لا ينتمي لهذا العميل.")
    entitlement.license_id = selected_license.id if selected_license else None
    entitlement.status = status
    entitlement.enabled = status == "active" and bool(request.form.get("enabled", "1"))
    if status != "active":
        entitlement.enabled = False
    entitlement.plan_code = (request.form.get("plan_code") or "").strip()[:80]
    entitlement.limits = _service_limits_from_request(entitlement.service_key)
    entitlement.config = parse_json_object(request.form.get("config_json"), field="إعدادات الخدمة")
    entitlement.price_monthly = parse_service_decimal(request.form.get("price_monthly"), field="price_monthly")
    entitlement.expires_at = parse_optional_datetime(request.form.get("expires_at"))
    entitlement.notes = (request.form.get("notes") or "").strip()[:2000]
    entitlement.updated_by_admin_id = session.get("admin_id")


def _service_limits_from_request(service_key: str) -> dict:
    if "limits_json" in request.form:
        return parse_json_object(request.form.get("limits_json"), field="حدود الخدمة")
    limits = {}
    for field_key, _label, _hint in service_limit_fields(service_key):
        raw = (request.form.get(f"limit_{field_key}") or "").strip()
        if not raw:
            continue
        try:
            value = int(raw)
        except ValueError as exc:
            raise CustomerControlValidationError("حدود الخدمة يجب أن تكون أرقامًا صحيحة.") from exc
        if value < 0:
            raise CustomerControlValidationError("حدود الخدمة لا يمكن أن تكون سالبة.")
        limits[field_key] = value
    return limits


def _sync_generic_vpn_entitlement(customer: Customer, entitlement: CustomerServiceEntitlement) -> None:
    vpn_entitlement = get_or_create_customer_vpn_entitlement(customer)
    if entitlement.status in {"disabled", "suspended", "expired"}:
        vpn_entitlement.enabled = False
        vpn_entitlement.status = entitlement.status
        vpn_entitlement.notes = entitlement.notes
        vpn_entitlement.updated_by_admin_id = session.get("admin_id")
        db.session.add(vpn_entitlement)


def _service_request_status_options() -> tuple[str, ...]:
    return (
        "pending",
        "under_review",
        "payment_pending",
        "trial_active",
        "approved",
        "rejected",
        "completed",
        "cancelled",
    )


def _service_request_query(status: str = "", q: str = ""):
    query = CustomerServiceRequest.query.join(Customer)
    if status:
        query = query.filter(CustomerServiceRequest.status == status)
    if q:
        like = f"%{q}%"
        query = query.filter(
            CustomerServiceRequest.public_reference.ilike(like)
            | CustomerServiceRequest.title.ilike(like)
            | Customer.company_name.ilike(like)
            | Customer.contact_name.ilike(like)
            | Customer.email.ilike(like)
        )
    return query.order_by(CustomerServiceRequest.updated_at.desc(), CustomerServiceRequest.created_at.desc())


def _request_amount(default_amount=None) -> Decimal:
    raw = request.form.get("amount")
    if raw not in (None, ""):
        return parse_service_decimal(raw, field="amount") or Decimal("0")
    if default_amount not in (None, ""):
        return Decimal(default_amount)
    return Decimal("0")


def _request_trial_expiry() -> datetime:
    expires_at = parse_optional_datetime(request.form.get("expires_at"))
    if expires_at:
        return expires_at
    days = _int("trial_days", 7)
    days = max(1, min(days, 365))
    return utcnow() + timedelta(days=days)


def _apply_vpn_service_request(service_request: CustomerServiceRequest, *, expires_at: datetime | None = None) -> None:
    customer = service_request.customer
    vpn_entitlement = get_or_create_customer_vpn_entitlement(customer)
    selected_license = customer.licenses.filter_by(id=_int("license_id")).first() if request.form.get("license_id") else find_best_customer_license(customer)
    selected_plan = None
    if request.form.get("vpn_plan_id"):
        selected_plan = VpnServicePlan.query.filter_by(id=_int("vpn_plan_id"), is_active=True).first()
        if not selected_plan:
            raise CustomerControlValidationError("باقة خدمة تغيير العنوان غير صحيحة.")
    if not selected_plan and not vpn_entitlement.vpn_plan_id:
        selected_plan = VpnServicePlan.query.filter_by(is_active=True).order_by(VpnServicePlan.download_mbps.asc()).first()
    if selected_plan:
        apply_plan_defaults(vpn_entitlement, selected_plan)

    desired = service_request.desired_limits or {}
    if request.form.get("download_mbps") or desired.get("download_mbps"):
        vpn_entitlement.download_mbps = validate_vpn_speed(request.form.get("download_mbps") or desired.get("download_mbps"), "download_mbps")
    if request.form.get("upload_mbps") or desired.get("upload_mbps"):
        vpn_entitlement.upload_mbps = validate_vpn_speed(request.form.get("upload_mbps") or desired.get("upload_mbps"), "upload_mbps")
    if request.form.get("max_vpn_users") or desired.get("max_vpn_users"):
        vpn_entitlement.max_vpn_users = validate_positive_limit(request.form.get("max_vpn_users") or desired.get("max_vpn_users"), "max_vpn_users")
    if request.form.get("max_locations") or desired.get("max_locations"):
        vpn_entitlement.max_locations = validate_positive_limit(request.form.get("max_locations") or desired.get("max_locations"), "max_locations")
    if not vpn_entitlement.download_mbps:
        vpn_entitlement.download_mbps = 10
    if not vpn_entitlement.upload_mbps:
        vpn_entitlement.upload_mbps = 10
    if not vpn_entitlement.max_vpn_users:
        vpn_entitlement.max_vpn_users = 10
    if not vpn_entitlement.max_locations:
        vpn_entitlement.max_locations = 1
    vpn_entitlement.license_id = selected_license.id if selected_license else None
    vpn_entitlement.enabled = True
    vpn_entitlement.status = "active"
    vpn_entitlement.expires_at = expires_at
    vpn_entitlement.notes = (request.form.get("admin_note") or service_request.admin_note or "").strip()[:2000]
    vpn_entitlement.updated_by_admin_id = session.get("admin_id")
    validate_customer_vpn_entitlement(vpn_entitlement)
    db.session.add(vpn_entitlement)


def _apply_generic_service_request(service_request: CustomerServiceRequest, *, expires_at: datetime | None = None) -> CustomerServiceEntitlement:
    customer = service_request.customer
    key = clean_service_key(service_request.service_key)
    entitlement = get_or_create_service_entitlement(customer, key)
    selected_license = customer.licenses.filter_by(id=_int("license_id")).first() if request.form.get("license_id") else find_best_customer_license(customer)
    entitlement.license_id = selected_license.id if selected_license else None
    entitlement.status = "active"
    entitlement.enabled = True
    entitlement.plan_code = (request.form.get("plan_code") or entitlement.plan_code or "").strip()[:80]
    limits = _service_limits_from_request(key)
    if not limits:
        limits = service_request.desired_limits or {}
    entitlement.limits = limits
    entitlement.config = parse_json_object(request.form.get("config_json"), field="إعدادات الخدمة") if "config_json" in request.form else entitlement.config
    entitlement.price_monthly = parse_service_decimal(request.form.get("price_monthly"), field="price_monthly") if request.form.get("price_monthly") else entitlement.price_monthly
    entitlement.expires_at = expires_at
    entitlement.notes = (request.form.get("admin_note") or service_request.admin_note or "").strip()[:2000]
    entitlement.updated_by_admin_id = session.get("admin_id")
    db.session.add(entitlement)
    if key == "ip_change_vpn":
        _apply_vpn_service_request(service_request, expires_at=expires_at)
    return entitlement


def _mark_service_request(
    service_request: CustomerServiceRequest,
    status: str,
    *,
    note: str = "",
    event_type: str = "status",
    public: bool = True,
) -> None:
    service_request.status = clean_service_request_status(status)
    service_request.admin_note = (note or service_request.admin_note or "").strip()[:2000]
    now = utcnow()
    if status in {"approved", "active", "trial_active"}:
        service_request.approved_by_admin_id = session.get("admin_id")
        service_request.approved_at = service_request.approved_at or now
    if status in {"approved", "active", "trial_active", "completed"}:
        service_request.activated_by_admin_id = session.get("admin_id")
        service_request.activated_at = service_request.activated_at or now
    if status == "completed":
        service_request.completed_at = service_request.completed_at or now
    if status == "rejected":
        service_request.rejected_at = service_request.rejected_at or now
    if public:
        add_service_request_message(
            service_request,
            sender_type="admin",
            admin_id=session.get("admin_id"),
            event_type=event_type,
            body=note or "تم تحديث حالة طلب الخدمة.",
        )
    db.session.add(service_request)


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
    return render_template("admin/dashboard_new.html", stats=stats, recent_checks=recent_checks, recent_renewals=recent_renewals, health=health)


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
    total_customers = Customer.query.count()
    active_count = Customer.query.filter_by(status="active").count()
    inactive_count = total_customers - active_count
    return render_template(
        "admin/customers/list_new.html",
        customers=customers,
        search=search,
        status=status,
        total_count=total_customers,
        total_customers=total_customers,
        active_count=active_count,
        inactive_count=inactive_count,
    )


@bp.get("/customers/new")
@login_required
def customer_new():
    from ..services.geo_data import picker_payload
    return render_template(
        "admin/customers/add_new.html",
        customer=Customer(),
        is_new=True,
        form_data={},
        form_errors={},
        msg=None,
        countries_payload=picker_payload(),
    )


@bp.post("/customers/new")
@login_required
def customer_create():
    from ..services.geo_data import picker_payload
    customer = Customer()
    try:
        _fill_customer(customer)
    except CustomerControlValidationError as exc:
        flash(str(exc), "error")
        return render_template(
            "admin/customers/add_new.html",
            customer=customer,
            is_new=True,
            form_data=request.form,
            form_errors={"_": str(exc)},
            msg=str(exc),
            countries_payload=picker_payload(),
        ), 400
    db.session.add(customer)
    db.session.flush()
    audit("customer_created", "customer", str(customer.id), f"Created customer {customer.company_name}")
    db.session.commit()
    # Owner notification (no-op when event/channels disabled); never blocks the request.
    from ..services.messaging import dispatch_lifecycle as _dispatch_lifecycle
    from ..services.messaging import notify_owner as _notify_owner
    _notify_owner("customer_created", detail=f"عميل: {customer.company_name}",
                  extra={"id": customer.id})
    # Customer-facing welcome message — silent no-op when the lifecycle event
    # is disabled or the customer has no phone on file.
    _dispatch_lifecycle("welcome", customer)
    flash("تم إنشاء العميل.", "success")
    return redirect(url_for("admin.customer_detail", customer_id=customer.id))


@bp.get("/customers/<int:customer_id>")
@login_required
def customer_detail(customer_id: int):
    customer = db.get_or_404(Customer, customer_id)
    licenses = customer.licenses.order_by(License.created_at.desc()).all()
    current_license = find_best_customer_license(customer)
    contract = build_runtime_contract_for_license(
        current_license,
        license_active=license_allows_vpn_services(current_license),
        status=current_license.status if current_license else "not_found",
    )
    _plan = current_license.plan if current_license else None
    _customer_users = customer.users.order_by(CustomerUser.created_at.desc()).all()
    _payment_requests = LicensePaymentRequest.query.filter_by(customer_id=customer.id).order_by(LicensePaymentRequest.created_at.desc()).limit(20).all()
    _paid_count = sum(1 for pr in _payment_requests if getattr(pr, "status", "") == "paid")
    _pending_count = sum(1 for pr in _payment_requests if getattr(pr, "status", "") in ("pending", "proof_submitted"))
    _total_paid = sum(getattr(pr, "amount", 0) or 0 for pr in _payment_requests if getattr(pr, "status", "") == "paid")
    return render_template(
        "admin/customers/detail_new.html",
        customer=customer,
        licenses=licenses,
        current_license=current_license,
        contract=contract,
        customer_users=_customer_users,
        service_catalog=service_catalog_items(),
        service_entitlements=customer_service_map(customer),
        payment_requests=_payment_requests,
        service_requests=CustomerServiceRequest.query.filter_by(customer_id=customer.id).order_by(CustomerServiceRequest.created_at.desc()).limit(20).all(),
        audit_logs=AuditLog.query.filter_by(entity_type="customer", entity_id=str(customer.id)).order_by(AuditLog.created_at.desc()).limit(12).all(),
        users_version=customer_users_version(customer),
        service_limit_fields=service_limit_fields,
        service_limit_summary=service_limit_summary,
        customer_backups=list_customer_backups(customer.id),
        customer_gdrive=_customer_gdrive_status(customer.id),
        radius_admins=radius_admins_for_customer(customer),
        nas_devices=radius_admins_for_customer(customer),
        max_nas=getattr(_plan, "max_nas", None),
        max_sub=getattr(_plan, "max_users", None),
        cur_nas=len(radius_admins_for_customer(customer)),
        cur_sub=len(_customer_users),
        paid_count=_paid_count,
        pending_count=_pending_count,
        total_paid=_total_paid,
    )


def _customer_gdrive_status(customer_id: int) -> dict:
    """Read-only Google Drive connection status for the admin (never the token)."""
    try:
        from ..services import google_drive as gd
        return gd.status(customer_id)
    except Exception:  # noqa: BLE001
        return {"connected": False, "email": "", "last_upload_at": None}


@bp.get("/service-requests")
@login_required
def service_requests_list():
    status = (request.args.get("status") or "").strip()
    q = (request.args.get("q") or "").strip()
    if status:
        try:
            clean_service_request_status(status)
        except CustomerControlValidationError:
            status = ""
    service_requests = _service_request_query(status=status, q=q).all()
    counts = {
        item_status: count
        for item_status, count in db.session.query(CustomerServiceRequest.status, func.count(CustomerServiceRequest.id)).group_by(CustomerServiceRequest.status).all()
    }
    return render_template(
        "admin/service_requests_list.html",
        service_requests=service_requests,
        status=status,
        q=q,
        counts=counts,
        status_options=_service_request_status_options(),
    )


@bp.get("/service-requests/<int:request_id>")
@login_required
def service_request_detail(request_id: int):
    service_request = db.get_or_404(CustomerServiceRequest, request_id)
    customer = service_request.customer
    return render_template(
        "admin/service_request_detail.html",
        service_request=service_request,
        customer=customer,
        messages=service_request.messages.order_by(CustomerServiceRequestMessage.created_at.asc()).all(),
        current_license=find_best_customer_license(customer),
        licenses=customer.licenses.order_by(License.created_at.desc()).all(),
        payment_request=service_request.payment_request,
        service_limit_fields=service_limit_fields(service_request.service_key),
        vpn_plans=VpnServicePlan.query.filter_by(is_active=True).order_by(VpnServicePlan.download_mbps.asc()).all(),
        desired_limits=service_request.desired_limits or {},
    )


@bp.post("/service-requests/<int:request_id>/reply")
@login_required
def service_request_reply(request_id: int):
    service_request = db.get_or_404(CustomerServiceRequest, request_id)
    message = (request.form.get("message") or "").strip()
    try:
        add_service_request_message(
            service_request,
            sender_type="admin",
            admin_id=session.get("admin_id"),
            body=message,
        )
        if service_request.status == "pending":
            service_request.status = "under_review"
        audit_customer_control(
            actor_admin_id=session.get("admin_id"),
            action="customer_service_request_replied",
            entity_type="customer_service_request",
            entity_id=str(service_request.id),
            summary=f"تمت إضافة رد على طلب الخدمة {service_request.public_reference}",
            metadata={"customer_id": service_request.customer_id, "service_key": service_request.service_key},
        )
        db.session.commit()
        flash("تم إرسال الرد للعميل داخل صفحة الرسائل.", "success")
    except CustomerControlValidationError as exc:
        db.session.rollback()
        flash(str(exc), "error")
    return redirect(url_for("admin.service_request_detail", request_id=service_request.id))


@bp.post("/service-requests/<int:request_id>/payment-request")
@login_required
def service_request_create_payment(request_id: int):
    service_request = db.get_or_404(CustomerServiceRequest, request_id)
    catalog_item = ServiceCatalogItem.query.filter_by(service_key=service_request.service_key).first()
    try:
        amount = _request_amount(catalog_item.price_monthly if catalog_item else None)
        if amount <= 0:
            raise CustomerControlValidationError("المبلغ يجب أن يكون أكبر من صفر.")
        payment_request = LicensePaymentRequestService().create_request({
            "customer_id": service_request.customer_id,
            "license_id": request.form.get("license_id") or (service_request.license_id or ""),
            "purpose": request.form.get("purpose") or "capacity_increase",
            "amount": amount,
            "currency": request.form.get("currency") or _setting("default_currency", "USD"),
        })
        service_request.payment_request_id = payment_request.id
        service_request.amount = payment_request.amount
        service_request.currency = payment_request.currency
        service_request.payment_status = "pending"
        _mark_service_request(
            service_request,
            "payment_pending",
            note=(
                f"تم إنشاء طلب دفع بقيمة {payment_request.amount} {payment_request.currency}. "
                "ارفع إثبات الدفع من صفحة الدفع ليتم اعتماد الخدمة."
            ),
            event_type="payment_request",
        )
        audit_customer_control(
            actor_admin_id=session.get("admin_id"),
            action="customer_service_request_payment_requested",
            entity_type="customer_service_request",
            entity_id=str(service_request.id),
            summary=f"تم إنشاء طلب دفع لطلب الخدمة {service_request.public_reference}",
            metadata={"payment_request_id": payment_request.id, "customer_id": service_request.customer_id},
        )
        db.session.commit()
        flash("تم إنشاء طلب الدفع وربطه بتذكرة الخدمة.", "success")
    except (CustomerControlValidationError, LicensePaymentValidationError, ValueError) as exc:
        db.session.rollback()
        flash(payment_error_message(exc), "error")
    return redirect(url_for("admin.service_request_detail", request_id=service_request.id))


@bp.post("/service-requests/<int:request_id>/confirm-payment")
@login_required
def service_request_confirm_payment(request_id: int):
    service_request = db.get_or_404(CustomerServiceRequest, request_id)
    try:
        payment_request = service_request.payment_request
        if not payment_request:
            catalog_item = ServiceCatalogItem.query.filter_by(service_key=service_request.service_key).first()
            amount = _request_amount(catalog_item.price_monthly if catalog_item else None)
            if amount <= 0:
                raise CustomerControlValidationError("حدد المبلغ المستلم قبل تأكيد الدفع.")
            payment_request = LicensePaymentRequestService().create_request({
                "customer_id": service_request.customer_id,
                "license_id": request.form.get("license_id") or (service_request.license_id or ""),
                "purpose": request.form.get("purpose") or "capacity_increase",
                "amount": amount,
                "currency": request.form.get("currency") or _setting("default_currency", "USD"),
            })
            service_request.payment_request_id = payment_request.id
            service_request.amount = payment_request.amount
            service_request.currency = payment_request.currency
        if payment_request.status == "pending":
            LicensePaymentProofService().submit_manual_proof(
                payment_request=payment_request,
                reference_number=request.form.get("manual_reference") or f"manual:{payment_request.reference_code}",
                note=request.form.get("review_note") or "تأكيد استلام يدوي من الإدارة.",
            )
        if payment_request.status in {"proof_submitted", "under_review"}:
            LicensePaymentReviewService().approve(
                payment_request=payment_request,
                reviewed_by=session.get("admin_id"),
                review_note=request.form.get("review_note") or "تم تأكيد استلام المبلغ من الإدارة.",
            )
        service_request.payment_status = "paid"
        if service_request.status in {"pending", "payment_pending"}:
            service_request.status = "under_review"
        add_service_request_message(
            service_request,
            sender_type="admin",
            admin_id=session.get("admin_id"),
            event_type="payment_confirmed",
            body="تم تأكيد استلام المبلغ. الطلب بانتظار قرار التفعيل النهائي من الإدارة.",
        )
        audit_customer_control(
            actor_admin_id=session.get("admin_id"),
            action="customer_service_request_payment_confirmed",
            entity_type="customer_service_request",
            entity_id=str(service_request.id),
            summary=f"تم تأكيد دفع طلب الخدمة {service_request.public_reference}",
            metadata={"payment_request_id": payment_request.id, "customer_id": service_request.customer_id},
        )
        db.session.commit()
        flash("تم تأكيد الدفع. لم يتم تفعيل الخدمة إلا إذا ضغطت اعتماد وتفعيل.", "success")
    except (CustomerControlValidationError, LicensePaymentValidationError, ValueError) as exc:
        db.session.rollback()
        flash(payment_error_message(exc), "error")
    return redirect(url_for("admin.service_request_detail", request_id=service_request.id))


@bp.post("/service-requests/<int:request_id>/trial")
@login_required
def service_request_open_trial(request_id: int):
    service_request = db.get_or_404(CustomerServiceRequest, request_id)
    try:
        expires_at = _request_trial_expiry()
        _apply_generic_service_request(service_request, expires_at=expires_at)
        _mark_service_request(
            service_request,
            "trial_active",
            note=f"تم فتح تجربة للخدمة حتى {expires_at.strftime('%Y-%m-%d')}.",
            event_type="trial",
        )
        audit_customer_control(
            actor_admin_id=session.get("admin_id"),
            action="customer_service_request_trial_opened",
            entity_type="customer_service_request",
            entity_id=str(service_request.id),
            summary=f"تم فتح تجربة لطلب الخدمة {service_request.public_reference}",
            metadata={"customer_id": service_request.customer_id, "service_key": service_request.service_key},
        )
        db.session.commit()
        flash("تم فتح التجربة. الريدياس سيأخذ الصلاحية عند المزامنة القادمة.", "success")
    except (CustomerControlValidationError, VpnEntitlementValidationError) as exc:
        db.session.rollback()
        flash(str(exc), "error")
    return redirect(url_for("admin.service_request_detail", request_id=service_request.id))


@bp.post("/service-requests/<int:request_id>/approve")
@login_required
def service_request_approve(request_id: int):
    service_request = db.get_or_404(CustomerServiceRequest, request_id)
    try:
        _apply_generic_service_request(service_request, expires_at=parse_optional_datetime(request.form.get("expires_at")))
        _mark_service_request(
            service_request,
            "approved",
            note=request.form.get("admin_note") or "تمت الموافقة على الطلب وتفعيل الخدمة.",
            event_type="approved",
        )
        audit_customer_control(
            actor_admin_id=session.get("admin_id"),
            action="customer_service_request_approved",
            entity_type="customer_service_request",
            entity_id=str(service_request.id),
            summary=f"تم اعتماد طلب الخدمة {service_request.public_reference}",
            metadata={"customer_id": service_request.customer_id, "service_key": service_request.service_key},
        )
        db.session.commit()
        flash("تم اعتماد الطلب وتحديث صلاحيات العميل. الريدياس يطبقها بعد المزامنة.", "success")
    except (CustomerControlValidationError, VpnEntitlementValidationError) as exc:
        db.session.rollback()
        flash(str(exc), "error")
    return redirect(url_for("admin.service_request_detail", request_id=service_request.id))


@bp.post("/service-requests/<int:request_id>/reject")
@login_required
def service_request_reject(request_id: int):
    service_request = db.get_or_404(CustomerServiceRequest, request_id)
    reason = (request.form.get("reason") or "").strip()
    if not reason:
        flash("سبب الرفض مطلوب حتى يفهم العميل القرار.", "error")
        return redirect(url_for("admin.service_request_detail", request_id=service_request.id))
    _mark_service_request(
        service_request,
        "rejected",
        note=reason,
        event_type="rejected",
    )
    audit_customer_control(
        actor_admin_id=session.get("admin_id"),
        action="customer_service_request_rejected",
        entity_type="customer_service_request",
        entity_id=str(service_request.id),
        summary=f"تم رفض طلب الخدمة {service_request.public_reference}",
        metadata={"customer_id": service_request.customer_id, "service_key": service_request.service_key},
    )
    db.session.commit()
    flash("تم رفض الطلب وإرسال السبب للعميل داخل صفحة الرسائل.", "warning")
    return redirect(url_for("admin.service_requests_list"))


_ALLOWED_PORTAL_SECTIONS = frozenset({
    "account", "password", "services", "payments", "requests", "tech_setup"
})


@bp.post("/customers/<int:customer_id>/portal-config")
@login_required
def customer_portal_config_save(customer_id: int):
    customer = db.get_or_404(Customer, customer_id)
    raw_hidden = request.form.getlist("hidden_sections")
    hidden = sorted({s for s in raw_hidden if s in _ALLOWED_PORTAL_SECTIONS})
    cfg = customer.portal_config
    cfg["hidden_sections"] = hidden
    customer.portal_config = cfg
    audit_customer_control(
        actor_admin_id=session.get("admin_id"),
        action="customer_portal_config_updated",
        entity_type="customer",
        entity_id=str(customer.id),
        summary=f"تحديث إعدادات بوابة العميل {customer.company_name} — أقسام مخفية: {hidden or 'لا شيء'}",
        metadata={"hidden_sections": hidden},
    )
    db.session.commit()
    if hidden:
        flash(f"تم حفظ الإعدادات. أقسام مخفية: {len(hidden)}.", "success")
    else:
        flash("تم حفظ الإعدادات. جميع الأقسام ظاهرة الآن.", "success")
    return redirect(url_for("admin.customer_detail", customer_id=customer.id))


@bp.get("/customers/<int:customer_id>/backups/<int:artifact_id>/download")
@login_required
def customer_backup_download(customer_id: int, artifact_id: int):
    customer = db.get_or_404(Customer, customer_id)
    resolved = get_artifact_file(customer.id, artifact_id)
    if not resolved:
        abort(404)
    path, download_name = resolved
    audit(
        "customer_backup_downloaded",
        "customer_backup",
        str(artifact_id),
        f"Downloaded backup {download_name} for customer {customer.company_name}",
    )
    db.session.commit()
    return send_file(str(path), as_attachment=True, download_name=download_name)


@bp.get("/customers/<int:customer_id>/users")
@login_required
def customer_users(customer_id: int):
    """صفحة مستقلة لمستخدمي العميل — نظير للمعلومات الأساسية.

    تجمع بين مستخدمي البوابة (CustomerUser) ولقطة هويات الراديوس
    (CustomerRadiusAdmin) المستوردة عبر الجسر.
    """
    customer = db.get_or_404(Customer, customer_id)
    portal_users = customer.users.order_by(CustomerUser.created_at.desc()).all()
    return render_template(
        "admin/customers/users_new.html",
        customer=customer,
        customer_users=portal_users,
        radius_admins=radius_admins_for_customer(customer),
        users_version=customer_users_version(customer),
    )


@bp.get("/customers/<int:customer_id>/users/new")
@login_required
def customer_user_new(customer_id: int):
    customer = db.get_or_404(Customer, customer_id)
    return render_template("admin/customer_user_form.html", customer=customer, customer_user=CustomerUser(active=True, role_key="owner"), is_new=True)


@bp.post("/customers/<int:customer_id>/users/new")
@login_required
def customer_user_create(customer_id: int):
    customer = db.get_or_404(Customer, customer_id)
    customer_user = CustomerUser(customer_id=customer.id, active=True)
    # Capture the plaintext password BEFORE _fill_customer_user hashes it.
    # Held only on this stack frame and never persisted/logged.
    _plain_password = (request.form.get("password") or "")
    try:
        _fill_customer_user(customer_user, require_password=True)
    except CustomerControlValidationError as exc:
        flash(str(exc), "error")
        return render_template("admin/customer_user_form.html", customer=customer, customer_user=customer_user, is_new=True), 400
    db.session.add(customer_user)
    db.session.flush()
    audit_customer_control(
        actor_admin_id=session.get("admin_id"),
        action="customer_user_created",
        entity_type="customer_user",
        entity_id=str(customer_user.id),
        summary=f"تم إنشاء مستخدم العميل {customer_user.username} لـ {customer.company_name}",
        metadata={"customer_id": customer.id, "role_key": customer_user.role_key, "is_super": customer_user.is_effective_super},
    )
    db.session.commit()
    # Send login credentials to the CUSTOMER's own phone. Silent no-op when
    # the `credentials` lifecycle event is disabled or the customer has no
    # phone on file. Never logs the plaintext password.
    from ..services.messaging import send_credentials as _send_credentials
    _send_credentials(customer, username=customer_user.username, password=_plain_password)
    flash("تم إنشاء مستخدم العميل. كلمة المرور ستصل للريدياس كنسخة مشفرة فقط عند مزامنة الهوية.", "success")
    return redirect(_customer_user_return_url(customer.id))


@bp.get("/customers/<int:customer_id>/users/<int:user_id>/edit")
@login_required
def customer_user_edit(customer_id: int, user_id: int):
    customer = db.get_or_404(Customer, customer_id)
    customer_user = CustomerUser.query.filter_by(id=user_id, customer_id=customer.id).first_or_404()
    return render_template("admin/customer_user_form.html", customer=customer, customer_user=customer_user, is_new=False)


@bp.post("/customers/<int:customer_id>/users/<int:user_id>/edit")
@login_required
def customer_user_update(customer_id: int, user_id: int):
    customer = db.get_or_404(Customer, customer_id)
    customer_user = CustomerUser.query.filter_by(id=user_id, customer_id=customer.id).first_or_404()
    # Capture the plaintext password BEFORE _fill_customer_user hashes it.
    # Blank means "leave existing password unchanged" — no credential message.
    _plain_password = (request.form.get("password") or "")
    try:
        _fill_customer_user(customer_user, require_password=False)
    except CustomerControlValidationError as exc:
        flash(str(exc), "error")
        return render_template("admin/customer_user_form.html", customer=customer, customer_user=customer_user, is_new=False), 400
    audit_customer_control(
        actor_admin_id=session.get("admin_id"),
        action="customer_user_updated",
        entity_type="customer_user",
        entity_id=str(customer_user.id),
        summary=f"تم تحديث مستخدم العميل {customer_user.username}",
        metadata={"customer_id": customer.id, "password_version": customer_user.password_version, "is_super": customer_user.is_effective_super},
    )
    db.session.commit()
    if _plain_password:
        # Password was actually changed → re-send credentials. Same gating as
        # customer_user_create; no-op when the lifecycle event is off.
        from ..services.messaging import send_credentials as _send_credentials
        _send_credentials(customer, username=customer_user.username, password=_plain_password)
    flash("تم تحديث مستخدم العميل.", "success")
    return redirect(_customer_user_return_url(customer.id))


@bp.post("/customers/<int:customer_id>/users/<int:user_id>/password")
@login_required
def customer_user_password_set(customer_id: int, user_id: int):
    customer = db.get_or_404(Customer, customer_id)
    customer_user = CustomerUser.query.filter_by(id=user_id, customer_id=customer.id).first_or_404()
    password = request.form.get("password") or ""
    password_confirm = request.form.get("password_confirm") or ""
    if len(password) < 8:
        flash("كلمة المرور يجب أن تكون 8 أحرف على الأقل.", "error")
        return redirect(_customer_user_return_url(customer.id))
    if password != password_confirm:
        flash("تأكيد كلمة المرور غير مطابق.", "error")
        return redirect(_customer_user_return_url(customer.id))
    customer_user.set_password(password, increment_version=True)
    audit_customer_control(
        actor_admin_id=session.get("admin_id"),
        action="customer_user_password_set_by_admin",
        entity_type="customer_user",
        entity_id=str(customer_user.id),
        summary=f"تم تعيين كلمة مرور مستخدم العميل {customer_user.username} من الإدارة",
        metadata={"customer_id": customer.id, "password_version": customer_user.password_version},
    )
    db.session.commit()
    # Send the NEW credentials to the customer's own phone. Silent no-op when
    # disabled or when the customer has no phone on file.
    from ..services.messaging import send_credentials as _send_credentials
    _send_credentials(customer, username=customer_user.username, password=password)
    flash("تم تعيين كلمة مرور العميل. سيستلم الريدياس النسخة المشفرة الجديدة عند مزامنة الهوية.", "success")
    return redirect(_customer_user_return_url(customer.id))


@bp.post("/customers/<int:customer_id>/users/<int:user_id>/disable")
@login_required
def customer_user_disable(customer_id: int, user_id: int):
    customer = db.get_or_404(Customer, customer_id)
    customer_user = CustomerUser.query.filter_by(id=user_id, customer_id=customer.id).first_or_404()
    customer_user.active = False
    audit_customer_control(
        actor_admin_id=session.get("admin_id"),
        action="customer_user_disabled",
        entity_type="customer_user",
        entity_id=str(customer_user.id),
        summary=f"تم تعطيل مستخدم العميل {customer_user.username}",
        metadata={"customer_id": customer.id},
    )
    db.session.commit()
    flash("تم تعطيل مستخدم العميل. بعد المزامنة لن يستطيع الدخول للريدياس.", "warning")
    return redirect(_customer_user_return_url(customer.id))


@bp.post("/customers/<int:customer_id>/users/<int:user_id>/enable")
@login_required
def customer_user_enable(customer_id: int, user_id: int):
    customer = db.get_or_404(Customer, customer_id)
    customer_user = CustomerUser.query.filter_by(id=user_id, customer_id=customer.id).first_or_404()
    customer_user.active = True
    audit_customer_control(
        actor_admin_id=session.get("admin_id"),
        action="customer_user_enabled",
        entity_type="customer_user",
        entity_id=str(customer_user.id),
        summary=f"تم تفعيل مستخدم العميل {customer_user.username}",
        metadata={"customer_id": customer.id},
    )
    db.session.commit()
    flash("تم تفعيل مستخدم العميل.", "success")
    return redirect(_customer_user_return_url(customer.id))


@bp.post("/customers/<int:customer_id>/radius-admins/<int:row_id>/super")
@login_required
def customer_radius_admin_super(customer_id: int, row_id: int):
    """تفعيل/إلغاء فرض «سوبر يوزر» على أدمن راديوس محلي معروض في اللوحة.

    عند التفعيل تُدفع التعليمة للراديوس عبر عقد مزامنة الهوية ليضبط
    is_super_admin=1 لهذا الأدمن في كل دورة (idempotent) دون كسر دخوله المحلي.
    """
    customer = db.get_or_404(Customer, customer_id)
    row = CustomerRadiusAdmin.query.filter_by(id=row_id, customer_id=customer.id).first_or_404()
    enable = (request.form.get("action") or "enable") != "disable"
    row.force_super = enable
    audit_customer_control(
        actor_admin_id=session.get("admin_id"),
        action="radius_admin_force_super_enabled" if enable else "radius_admin_force_super_disabled",
        entity_type="customer_radius_admin",
        entity_id=str(row.id),
        summary=(
            f"تم فرض سوبر يوزر على أدمن الراديوس {row.username}" if enable
            else f"تم إلغاء فرض سوبر يوزر عن أدمن الراديوس {row.username}"
        ),
        metadata={"customer_id": customer.id, "radius_admin_id": row.radius_admin_id, "username": row.username},
    )
    db.session.commit()
    flash(
        "تم فرض «سوبر يوزر»؛ سيُطبَّق على راديوس العميل عند المزامنة التالية." if enable
        else "تم إلغاء فرض «سوبر يوزر» لهذا الأدمن.",
        "success",
    )
    return redirect(_customer_user_return_url(customer.id))


@bp.post("/customers/<int:customer_id>/services/<service_key>")
@login_required
def customer_service_update(customer_id: int, service_key: str):
    customer = db.get_or_404(Customer, customer_id)
    try:
        key = clean_service_key(service_key)
        entitlement = get_or_create_service_entitlement(customer, key)
        _fill_customer_service_entitlement(customer, entitlement)
    except CustomerControlValidationError as exc:
        flash(str(exc), "error")
        return redirect(url_for("admin.customer_detail", customer_id=customer.id))
    db.session.flush()
    if key == "ip_change_vpn":
        _sync_generic_vpn_entitlement(customer, entitlement)
    audit_customer_control(
        actor_admin_id=session.get("admin_id"),
        action="customer_service_entitlement_updated",
        entity_type="customer_service_entitlement",
        entity_id=str(entitlement.id),
        summary=f"تم تحديث خدمة {service_label(key)} للعميل {customer.company_name}",
        metadata={"customer_id": customer.id, "service_key": key, "status": entitlement.status, "enabled": entitlement.enabled},
    )
    db.session.commit()
    flash("تم حفظ خدمة العميل. لوحة التراخيص ترسل الاستحقاق، والريدياس يطبق محليًا.", "success")
    return redirect(url_for("admin.customer_detail", customer_id=customer.id))


@bp.post("/customers/<int:customer_id>/services/<service_key>/payment-request")
@login_required
def customer_service_payment_request(customer_id: int, service_key: str):
    customer = db.get_or_404(Customer, customer_id)
    try:
        key = clean_service_key(service_key)
        catalog_item = ServiceCatalogItem.query.filter_by(service_key=key).first_or_404()
        amount = parse_service_decimal(request.form.get("amount") or catalog_item.price_monthly or "0", field="amount")
        if not amount or amount <= 0:
            raise CustomerControlValidationError("المبلغ يجب أن يكون أكبر من صفر.")
        payment_request = LicensePaymentRequestService().create_request({
            "customer_id": customer.id,
            "license_id": request.form.get("license_id") or "",
            "purpose": request.form.get("purpose") or "capacity_increase",
            "amount": amount,
            "currency": request.form.get("currency") or _setting("default_currency", "USD"),
        })
    except (CustomerControlValidationError, LicensePaymentValidationError, ValueError) as exc:
        flash(payment_error_message(exc), "error")
        return redirect(url_for("admin.customer_detail", customer_id=customer.id))
    audit_customer_control(
        actor_admin_id=session.get("admin_id"),
        action="customer_service_payment_request_created",
        entity_type="license_payment_request",
        entity_id=str(payment_request.id),
        summary=f"تم إنشاء طلب دفع لخدمة {service_label(key)}",
        metadata={"customer_id": customer.id, "service_key": key, "reference_code": payment_request.reference_code},
    )
    db.session.commit()
    flash("تم إنشاء طلب دفع يدوي للخدمة.", "success")
    return redirect(url_for("admin.payment_request_detail", payment_request_id=payment_request.id))


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
        f"تم تحديث خدمة الشبكة الخاصة للعميل {customer.company_name}",
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
    flash("تم حفظ خدمة تغيير العنوان والشبكة الخاصة للعميل.", "success")
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
        raise VpnEntitlementValidationError("لم يتم العثور على باقة الشبكة الخاصة المختارة.")

    license_id = _int("license_id") if request.form.get("license_id") else None
    selected_license = customer.licenses.filter_by(id=license_id).first() if license_id else None
    if license_id and not selected_license:
        raise VpnEntitlementValidationError("الترخيص المختار لا ينتمي لهذا العميل.")

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


# ── Central CHR tunnels for a customer (Customer 360) ──────────────────────
@bp.get("/customers/<int:customer_id>/vpn-tunnels")
@login_required
def customer_vpn_tunnels(customer_id: int):
    customer = db.get_or_404(Customer, customer_id)
    return _render_customer_vpn_tunnels(customer)


@bp.post("/customers/<int:customer_id>/vpn-tunnels")
@login_required
def customer_vpn_tunnel_create(customer_id: int):
    customer = db.get_or_404(Customer, customer_id)
    from ..services import vpn_tunnels as vt

    tunnel_type = (request.form.get("tunnel_type") or "").strip().lower()
    if tunnel_type not in vt.MANUAL_TYPES:
        flash("نوع النفق غير مدعوم.", "error")
        return _render_customer_vpn_tunnels(customer), 400
    license_obj = find_best_customer_license(customer)
    try:
        max_connections = int(request.form.get("max_connections") or 1)
    except (TypeError, ValueError):
        max_connections = 1
    # السرعة: بروفايل محفوظ أو سرعة مخصّصة (يحلّها vt.provision_tunnel).
    try:
        speed_profile_id = int(request.form.get("speed_profile_id") or 0) or None
    except (TypeError, ValueError):
        speed_profile_id = None
    try:
        tunnel = vt.provision_tunnel(
            customer,
            license_obj,
            tunnel_type=tunnel_type,
            profile=request.form.get("profile") or "",
            max_connections=max_connections,
            speed_profile_id=speed_profile_id,
            download_mbps=request.form.get("download_mbps") or None,
            upload_mbps=request.form.get("upload_mbps") or None,
            monthly_quota_gb=request.form.get("monthly_quota_gb") or None,
            throttle_down_mbps=request.form.get("throttle_down_mbps") or None,
            throttle_up_mbps=request.form.get("throttle_up_mbps") or None,
            source="admin_manual",
            created_by_admin_id=session.get("admin_id"),
            notes=request.form.get("notes") or "",
        )
    except vt.VpnTunnelError as exc:
        db.session.rollback()
        flash(str(exc), "error")
        return _render_customer_vpn_tunnels(customer), 400
    audit(
        "customer_vpn_tunnel_provisioned",
        "customer_vpn_tunnel",
        str(tunnel.id),
        f"تزويد نفق {tunnel.tunnel_type} يدويًا للعميل {customer.company_name}",
        {"customer_id": customer.id, "tunnel_type": tunnel.tunnel_type, "username": tunnel.username},
    )
    db.session.commit()
    flash(f"تم إنشاء النفق {tunnel.username} ({tunnel.tunnel_type}). يُسلَّم للعميل عبر الجسر.", "success")
    return redirect(url_for("admin.customer_vpn_tunnels", customer_id=customer.id))


@bp.post("/customers/<int:customer_id>/vpn-tunnels/<int:tunnel_id>/revoke")
@login_required
def customer_vpn_tunnel_revoke(customer_id: int, tunnel_id: int):
    customer = db.get_or_404(Customer, customer_id)
    from ..models import CustomerVpnTunnel
    from ..services import vpn_tunnels as vt

    tunnel = CustomerVpnTunnel.query.filter_by(id=tunnel_id, customer_id=customer.id).first()
    if not tunnel:
        flash("لم يتم العثور على النفق.", "error")
        return redirect(url_for("admin.customer_vpn_tunnels", customer_id=customer.id))
    try:
        vt.revoke_tunnel(tunnel)
    except vt.VpnTunnelError as exc:
        db.session.rollback()
        flash(str(exc), "error")
        return redirect(url_for("admin.customer_vpn_tunnels", customer_id=customer.id))
    audit(
        "customer_vpn_tunnel_revoked",
        "customer_vpn_tunnel",
        str(tunnel.id),
        f"إلغاء نفق {tunnel.username} للعميل {customer.company_name}",
        {"customer_id": customer.id, "username": tunnel.username},
    )
    db.session.commit()
    flash("تم إلغاء النفق وحذفه من CHR.", "success")
    return redirect(url_for("admin.customer_vpn_tunnels", customer_id=customer.id))


@bp.post("/customers/<int:customer_id>/vpn-tunnels/<int:tunnel_id>/status")
@login_required
def customer_vpn_tunnel_status(customer_id: int, tunnel_id: int):
    customer = db.get_or_404(Customer, customer_id)
    from ..models import CustomerVpnTunnel
    from ..services import vpn_tunnels as vt

    tunnel = CustomerVpnTunnel.query.filter_by(id=tunnel_id, customer_id=customer.id).first()
    if not tunnel:
        flash("لم يتم العثور على النفق.", "error")
        return redirect(url_for("admin.customer_vpn_tunnels", customer_id=customer.id))
    target = (request.form.get("status") or "").strip().lower()
    try:
        vt.set_tunnel_status(tunnel, target)
    except vt.VpnTunnelError as exc:
        db.session.rollback()
        flash(str(exc), "error")
        return redirect(url_for("admin.customer_vpn_tunnels", customer_id=customer.id))
    audit(
        "customer_vpn_tunnel_status_changed",
        "customer_vpn_tunnel",
        str(tunnel.id),
        f"تغيير حالة نفق {tunnel.username} إلى {tunnel.status}",
        {"customer_id": customer.id, "username": tunnel.username, "status": tunnel.status},
    )
    db.session.commit()
    flash("تم تحديث حالة النفق.", "success")
    return redirect(url_for("admin.customer_vpn_tunnels", customer_id=customer.id))


def _render_customer_vpn_tunnels(customer: Customer):
    from ..services import chr_settings as chr_svc
    from ..services import speed_profiles as sp
    from ..services import vpn_tunnels as vt

    tunnels = vt.list_tunnels(customer)
    _type_count = {}
    for t in tunnels:
        _type_count[getattr(t, "tunnel_type", "unknown")] = _type_count.get(getattr(t, "tunnel_type", "unknown"), 0) + 1
    return render_template(
        "admin/infra/vpn_tunnels_new.html",
        customer=customer,
        tunnels=tunnels,
        type_count=_type_count,
        type_key=vt.TUNNEL_TYPE_LABELS if hasattr(vt, "TUNNEL_TYPE_LABELS") else {},
        chr_enabled=chr_svc.enabled(),
        chr_configured=(chr_svc.get_state().get("configured") if chr_svc.enabled() else False),
        allowance=vt.effective_connection_allowance(customer),
        active_count=vt.count_active_tunnels(customer),
        manual_types=sorted(vt.MANUAL_TYPES),
        type_labels=vt.TUNNEL_TYPE_LABELS if hasattr(vt, "TUNNEL_TYPE_LABELS") else {},
        speed_profiles=sp.list_profiles(active_only=True),
    )


# ── CHR speed profiles (central, mapped to /ppp/profile rate-limit) ─────────
@bp.get("/chr/speed-profiles")
@login_required
def chr_speed_profiles():
    from ..services import speed_profiles as sp
    from ..services import chr_settings as chr_svc
    return render_template(
        "admin/chr_speed_profiles.html",
        profiles=sp.list_profiles(),
        rate_limit_string=sp.rate_limit_string,
        chr_enabled=chr_svc.enabled(),
    )


@bp.post("/chr/speed-profiles")
@login_required
def chr_speed_profile_create():
    from ..services import speed_profiles as sp
    try:
        profile = sp.create_profile(request.form)
    except sp.SpeedProfileError as exc:
        db.session.rollback()
        flash(str(exc), "error")
        return redirect(url_for("admin.chr_speed_profiles"))
    audit("chr_speed_profile_created", "chr_speed_profile", str(profile.id),
          f"إنشاء بروفايل سرعة {profile.name} ({profile.download_mbps}↓/{profile.upload_mbps}↑)",
          {"code": profile.code, "download_mbps": profile.download_mbps, "upload_mbps": profile.upload_mbps})
    db.session.commit()
    flash(f"تم إنشاء بروفايل السرعة «{profile.name}».", "success")
    return redirect(url_for("admin.chr_speed_profiles"))


@bp.post("/chr/speed-profiles/<int:profile_id>/edit")
@login_required
def chr_speed_profile_edit(profile_id: int):
    from ..services import speed_profiles as sp
    profile = db.get_or_404(ChrSpeedProfile, profile_id)
    try:
        sp.update_profile(profile, request.form)
    except sp.SpeedProfileError as exc:
        db.session.rollback()
        flash(str(exc), "error")
        return redirect(url_for("admin.chr_speed_profiles"))
    audit("chr_speed_profile_updated", "chr_speed_profile", str(profile.id),
          f"تعديل بروفايل سرعة {profile.name}",
          {"download_mbps": profile.download_mbps, "upload_mbps": profile.upload_mbps, "active": profile.active})
    db.session.commit()
    flash(f"تم تحديث بروفايل السرعة «{profile.name}».", "success")
    return redirect(url_for("admin.chr_speed_profiles"))


@bp.post("/chr/speed-profiles/<int:profile_id>/delete")
@login_required
def chr_speed_profile_delete(profile_id: int):
    from ..services import speed_profiles as sp
    profile = db.get_or_404(ChrSpeedProfile, profile_id)
    name = profile.name
    try:
        sp.delete_profile(profile)
    except sp.SpeedProfileError as exc:
        db.session.commit()  # delete_profile may have deactivated it
        flash(str(exc), "warning")
        return redirect(url_for("admin.chr_speed_profiles"))
    audit("chr_speed_profile_deleted", "chr_speed_profile", str(profile_id), f"حذف بروفايل سرعة {name}", {})
    db.session.commit()
    flash(f"تم حذف بروفايل السرعة «{name}».", "success")
    return redirect(url_for("admin.chr_speed_profiles"))


@bp.post("/chr/speed-profiles/<int:profile_id>/sync")
@login_required
def chr_speed_profile_sync(profile_id: int):
    """يهيّئ /ppp/profile المقابل على CHR بالـrate-limit (للتحقق اليدوي)."""
    from ..services import speed_profiles as sp
    from ..services import chr_settings as chr_svc
    from ..services.routeros_client import RouterOSError
    profile = db.get_or_404(ChrSpeedProfile, profile_id)
    try:
        sp.ensure_on_chr(profile)
    except chr_svc.ChrSettingsError as exc:
        flash(str(exc), "error")
        return redirect(url_for("admin.chr_speed_profiles"))
    except RouterOSError as exc:
        flash("تعذّرت المزامنة مع CHR: " + exc.message, "error")
        return redirect(url_for("admin.chr_speed_profiles"))
    audit("chr_speed_profile_synced", "chr_speed_profile", str(profile.id),
          f"مزامنة بروفايل سرعة {profile.name} مع CHR", {"chr_profile": profile.effective_chr_profile_name})
    db.session.commit()
    flash(f"تمت تهيئة «{profile.effective_chr_profile_name}» على CHR بسرعة "
          f"{profile.download_mbps}↓/{profile.upload_mbps}↑ Mbps.", "success")
    return redirect(url_for("admin.chr_speed_profiles"))


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
    try:
        _fill_customer(customer)
    except CustomerControlValidationError as exc:
        flash(str(exc), "error")
        return render_template("admin/customer_form.html", customer=customer, is_new=False), 400
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
    from ..services.geo_data import country_by_iso

    customer.company_name = (request.form.get("company_name") or "").strip()
    customer.contact_name = (request.form.get("contact_name") or "").strip()
    customer.email = normalize_contact_email(request.form.get("email") or "")
    customer.phone = normalize_contact_phone(request.form.get("phone") or "")
    # Country: prefer the picker's ISO code (stable key); resolve the display
    # name from the curated table. Free-text "country" stays for backwards
    # compat when no ISO is provided (legacy callers / older forms).
    iso_raw = (request.form.get("country_iso") or "").strip().upper()[:2]
    info = country_by_iso(iso_raw) if iso_raw else None
    if info:
        customer.country_iso = info["iso"]
        customer.country = info["name_ar"]
        # Dial-code: trust the curated table over whatever the client posted.
        customer.dial_code = info["dial"]
    else:
        customer.country_iso = ""
        customer.country = (request.form.get("country") or "").strip()
        # Dial-code may still be posted by the legacy/free-text path; keep it
        # only if it looks like a sane "+digits" string.
        dial_raw = (request.form.get("dial_code") or "").strip()[:8]
        customer.dial_code = dial_raw if re.match(r"^\+\d{1,7}$", dial_raw) else ""
    customer.city = (request.form.get("city") or "").strip()[:100]
    customer.runtime_url = _clean_runtime_url(request.form.get("runtime_url") or "")
    customer.notes = (request.form.get("notes") or "").strip()
    validate_unique_customer_contact(customer, customer.email, customer.phone)
    status = (request.form.get("status") or "active").strip().lower()
    if status not in {"pending", "active", "inactive", "blocked"}:
        raise CustomerControlValidationError("حالة العميل غير مسموحة.")
    customer.status = status
    from ..services.license_payments import CURRENCIES
    currency = (request.form.get("currency") or "USD").strip().upper()[:12]
    if currency not in CURRENCIES:
        raise CustomerControlValidationError("عملة الفوترة غير مدعومة.")
    customer.currency = currency


def _clean_runtime_url(value: str) -> str:
    text = str(value or "").strip()[:255]
    if text and not text.lower().startswith(("http://", "https://")):
        raise CustomerControlValidationError("رابط الريدياس يجب أن يبدأ بـ http:// أو https://.")
    return text


@bp.post("/customers/<int:customer_id>/approve")
@login_required
def customer_approve(customer_id: int):
    customer = db.get_or_404(Customer, customer_id)
    customer.status = "active"
    enabled_users = 0
    for user in customer.users.order_by(CustomerUser.id.asc()).all():
        if not user.active:
            user.active = True
            enabled_users += 1
    audit_customer_control(
        actor_admin_id=session.get("admin_id"),
        action="customer_approved",
        entity_type="customer",
        entity_id=str(customer.id),
        summary=f"تمت الموافقة على العميل {customer.company_name}",
        metadata={"enabled_users": enabled_users},
    )
    db.session.commit()
    flash("تمت الموافقة على العميل وتفعيل مستخدميه للمزامنة مع الريدياس.", "success")
    return redirect(url_for("admin.customer_detail", customer_id=customer.id))


@bp.get("/plans")
@login_required
def plans_list():
    plans = Plan.query.order_by(Plan.monthly_price.asc(), Plan.name.asc()).all()
    return render_template("admin/licenses/plans_new.html", plans=plans)


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
    plan.slug = _plan_slug(plan, request.form.get("slug") or "")
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


def _plan_slug(plan: Plan, raw_slug: str) -> str:
    explicit = (raw_slug or "").strip().lower()
    if explicit:
        return re.sub(r"[^a-z0-9_-]+", "-", explicit).strip("-_")[:80]
    if plan.slug:
        return plan.slug
    base = re.sub(r"[^a-z0-9]+", "-", (plan.name or "").strip().lower()).strip("-") or "plan"
    base = base[:60]
    candidate = base
    suffix = 2
    with db.session.no_autoflush:
        while Plan.query.filter(Plan.slug == candidate).first():
            candidate = f"{base}-{suffix}"[:80]
            suffix += 1
    return candidate


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
    audit("vpn_service_plan_created", "vpn_service_plan", str(vpn_plan.id), f"تم إنشاء باقة الشبكة الخاصة {vpn_plan.code}")
    db.session.commit()
    flash("تم إنشاء خطة خدمة تغيير العنوان والشبكة الخاصة.", "success")
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
    audit("vpn_service_plan_updated", "vpn_service_plan", str(vpn_plan.id), f"تم تحديث باقة الشبكة الخاصة {vpn_plan.code}")
    db.session.commit()
    flash("تم تحديث خطة خدمة تغيير العنوان والشبكة الخاصة.", "success")
    return redirect(url_for("admin.vpn_services_list"))


@bp.post("/vpn-services/<int:vpn_plan_id>/disable")
@login_required
def vpn_service_disable(vpn_plan_id: int):
    vpn_plan = db.get_or_404(VpnServicePlan, vpn_plan_id)
    vpn_plan.is_active = False
    audit("vpn_service_plan_disabled", "vpn_service_plan", str(vpn_plan.id), f"تم إيقاف باقة الشبكة الخاصة {vpn_plan.code}")
    db.session.commit()
    flash("تم إيقاف خطة خدمة تغيير العنوان والشبكة الخاصة.", "warning")
    return redirect(url_for("admin.vpn_services_list"))


@bp.post("/vpn-services/<int:vpn_plan_id>/enable")
@login_required
def vpn_service_enable(vpn_plan_id: int):
    vpn_plan = db.get_or_404(VpnServicePlan, vpn_plan_id)
    vpn_plan.is_active = True
    audit("vpn_service_plan_enabled", "vpn_service_plan", str(vpn_plan.id), f"تم تفعيل باقة الشبكة الخاصة {vpn_plan.code}")
    db.session.commit()
    flash("تم تفعيل خطة خدمة تغيير العنوان والشبكة الخاصة.", "success")
    return redirect(url_for("admin.vpn_services_list"))


def _fill_vpn_plan(vpn_plan: VpnServicePlan) -> None:
    vpn_plan.name = (request.form.get("name") or "").strip()
    vpn_plan.description = (request.form.get("description") or "").strip()[:2000]
    vpn_plan.download_mbps = validate_vpn_speed(request.form.get("download_mbps"), "download_mbps")
    vpn_plan.upload_mbps = validate_vpn_speed(request.form.get("upload_mbps"), "upload_mbps")
    raw_code = (request.form.get("code") or "").strip() or f"vpn_{vpn_plan.download_mbps}m"
    vpn_plan.code = clean_vpn_plan_code(raw_code)
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
            raise VpnEntitlementValidationError("توجد باقة شبكة خاصة بنفس التعريف الداخلي.")


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
    now_ts = utcnow()
    soon_ts = now_ts + timedelta(days=7)
    _lic_stats = {
        "total": License.query.count(),
        "active": License.query.filter_by(status="active").count(),
        "expired": License.query.filter(License.expires_at < now_ts).count(),
        "suspended": License.query.filter_by(status="suspended").count(),
        "expiring_soon": License.query.filter(License.expires_at >= now_ts, License.expires_at <= soon_ts).count(),
    }
    return render_template("admin/licenses/list_new.html", licenses=licenses, status=status, search=search, stats=_lic_stats)


@bp.get("/licenses/new")
@login_required
def license_new():
    customers = Customer.query.order_by(Customer.company_name.asc()).all()
    plans = Plan.query.filter_by(status="active").order_by(Plan.name.asc()).all()
    today = utcnow()
    return render_template("admin/licenses/create_new.html", customers=customers, plans=plans, today=today, timedelta=timedelta)


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
        max_fingerprints=_int("max_fingerprints", max(3, plan.max_devices or 3)),
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
    _plan = lic.plan
    def _pct(used, mx):
        if not mx:
            return 0
        return min(100, int(used * 100 / mx))
    _used_users = lic.customer.users.count() if lic.customer else 0
    _used_nas = len(radius_admins_for_customer(lic.customer)) if lic.customer else 0
    _used_admins = AuditLog.query.filter_by(entity_type="license", entity_id=str(lic.id)).count()
    _used_fp = len(lic.fingerprints)
    return render_template(
        "admin/licenses/detail_new.html",
        license=lic,
        checks=checks,
        renewals=renewals,
        suspicious=suspicious,
        max_users=getattr(_plan, "max_users", None),
        max_nas=getattr(_plan, "max_nas", None),
        max_admins=getattr(_plan, "max_admins", None),
        max_fp=getattr(lic, "max_fingerprints", None),
        max_bk=None,
        max_wa=None,
        used_users=_used_users,
        used_nas=_used_nas,
        used_admins=_used_admins,
        used_fp=_used_fp,
        used_bk=0,
        used_wa=0,
        pct_users=_pct(_used_users, getattr(_plan, "max_users", 0)),
        pct_nas=_pct(_used_nas, getattr(_plan, "max_nas", 0)),
        pct_admins=_pct(_used_admins, getattr(_plan, "max_admins", 0)),
        pct_fp=_pct(_used_fp, getattr(lic, "max_fingerprints", 0) or 0),
        pct_bk=0,
        pct_wa=0,
    )


def _effective_services_for_license(lic: License) -> list[dict]:
    """يبني قائمة الخدمات الفعّالة للترخيص.

    FIX #6 of the mock-inventory remediation: replaces the previous mock
    ``current``/``max`` numbers that were rendered as if they were live
    usage. Behaviour now:

      * Catalogue **metadata** (icon, category label, default max,
        limits label) comes from ``ServiceCatalogItem.catalog_metadata``
        when available; ``SERVICES_MOCK`` is the bootstrap seed only.
      * ``limits.current`` is set to ``None`` — the template renders
        «بانتظار تفعيل تقارير الاستخدام» instead of a fake number. Real
        per-cycle counts will land when the customer-radius bridge ships
        a usage-snapshot producer; see the SEAM below.
      * ``status`` / ``max_limit`` are still overridden by
        ``LicenseServiceOverride`` for side-agreement activations.

    SEAM for real usage counts (one place to wire): once the customer
    radius reports per-service usage via
    ``POST /api/integration/hoberadius/usage-snapshot/push`` (already
    implemented at panel side, see ``app/api/routes.py``), look up the
    current cycle's ``ServiceUsageSnapshot`` for this license's
    customer and replace ``svc["limits"]["current"] = …``. This is the
    only function that needs the change.
    """
    from .services_data import SERVICES_MOCK
    import copy

    services = copy.deepcopy(SERVICES_MOCK)
    # Catalogue-metadata enrichment from the DB (when present). The catalogue
    # is the source of truth for icon/cat_label/default_max; SERVICES_MOCK
    # is only consulted for service_keys the DB hasn't seen yet.
    catalogue_by_key: dict[str, dict] = {}
    try:
        for item in ServiceCatalogItem.query.all():
            md = item.catalog_metadata or {}
            catalogue_by_key[item.service_key] = {
                "name": md.get("name_ar") or item.title or item.service_key,
                "description": item.short_description or "",
                "category": item.category or "",
                "icon": md.get("icon") or "",
                "status": (item.status or "active").lower() if item.is_active else (item.status or "unavailable").lower(),
                "default_max": md.get("default_max"),
                "limits_label": md.get("limits_label"),
            }
    except Exception:  # noqa: BLE001 — DB unavailable (tests) → fall back to MOCK
        catalogue_by_key = {}

    for svc in services:
        svc.setdefault("is_granted", False)
        svc["plan_status"] = svc.get("status", "unavailable")

        # 🩹 KILL THE FAKE CURRENT-USAGE NUMBER. Live values require the
        # customer-radius bridge producer (see SEAM in docstring above).
        if svc.get("limits") and isinstance(svc["limits"], dict):
            svc["limits"] = dict(svc["limits"])
            svc["limits"]["current"] = None

        # Enrich with real catalogue metadata when the DB has a row.
        cat = catalogue_by_key.get(svc["key"])
        if cat:
            if cat.get("name"):
                svc["name"] = cat["name"]
            if cat.get("description"):
                svc["description"] = cat["description"]
            if cat.get("category"):
                svc["category"] = cat["category"]
            if cat.get("icon"):
                svc["icon"] = cat["icon"]
            if cat.get("status"):
                svc["status"] = cat["status"]
                svc["plan_status"] = cat["status"]
            if cat.get("default_max") is not None and svc.get("limits"):
                svc["limits"]["max"] = cat["default_max"]
            if cat.get("limits_label") and svc.get("limits"):
                svc["limits"]["label"] = cat["limits_label"]

    overrides = LicenseServiceOverride.query.filter_by(license_id=lic.id).all()
    by_key = {o.service_key: o for o in overrides}

    for svc in services:
        ov = by_key.get(svc["key"])
        if not ov:
            continue
        plan_status = svc["plan_status"]
        if ov.status == "active" and plan_status == "unavailable":
            svc["is_granted"] = True
        svc["status"] = ov.status
        if ov.max_limit is not None and svc.get("limits"):
            svc["limits"] = dict(svc["limits"])
            svc["limits"]["max"] = ov.max_limit

    return services


def _get_service_def(service_key: str) -> dict | None:
    from .services_data import SERVICES_MOCK
    for svc in SERVICES_MOCK:
        if svc["key"] == service_key:
            return svc
    return None


def _upsert_override(lic: License, service_key: str, *, status: str | None = None,
                     max_limit: int | None = None, mark_grant: bool = False) -> LicenseServiceOverride:
    """ينشئ أو يحدّث override خدمة واحدة لترخيص."""
    ov = LicenseServiceOverride.query.filter_by(
        license_id=lic.id, service_key=service_key
    ).one_or_none()
    if ov is None:
        ov = LicenseServiceOverride(
            license_id=lic.id,
            service_key=service_key,
            status=status or "active",
            granted_by_admin_id=session.get("admin_id"),
        )
        db.session.add(ov)
    if status is not None:
        ov.status = status
    if max_limit is not None:
        ov.max_limit = max_limit
    if mark_grant:
        ov.notes = "side_agreement"
        ov.granted_by_admin_id = session.get("admin_id")
    return ov


@bp.get("/licenses/<int:license_id>/services")
@login_required
def license_services(license_id: int):
    """صفحة إدارة خدمات الترخيص: خدمات الباقة + تفعيلات الاتفاق الجانبي."""
    lic = db.get_or_404(License, license_id)
    services = _effective_services_for_license(lic)
    return render_template(
        "admin/licenses/services_new.html",
        services=services,
        license=lic,
        license_id=license_id,
    )


@bp.get("/licenses/<int:license_id>/services/<service_key>")
@login_required
def license_service_detail(license_id: int, service_key: str):
    """شاشة تحكم لخدمة واحدة — تعديل/تفعيل/إيقاف."""
    lic = db.get_or_404(License, license_id)
    base = _get_service_def(service_key)
    if base is None:
        abort(404)
    services = _effective_services_for_license(lic)
    svc = next((s for s in services if s["key"] == service_key), None)
    if svc is None:
        abort(404)
    return render_template(
        "admin/licenses/service_detail_new.html",
        license=lic,
        license_id=license_id,
        svc=svc,
    )


@bp.post("/licenses/<int:license_id>/services/<service_key>/grant")
@login_required
def license_service_grant(license_id: int, service_key: str):
    """تفعيل خدمة لترخيص واحد بالاتفاق الجانبي — دون ترقية الباقة."""
    lic = db.get_or_404(License, license_id)
    base = _get_service_def(service_key)
    if base is None:
        abort(404)
    _upsert_override(lic, service_key, status="active", mark_grant=True)
    audit(
        "license.service.grant", "license", lic.id,
        f"تفعيل خدمة {base['name']} بالاتفاق الجانبي",
        metadata={"service_key": service_key},
    )
    db.session.commit()
    flash(f"تم تفعيل خدمة «{base['name']}» لهذا العميل بالاتفاق الجانبي.", "success")
    return redirect(url_for("admin.license_services", license_id=lic.id))


@bp.post("/licenses/<int:license_id>/services/<service_key>/revoke")
@login_required
def license_service_revoke(license_id: int, service_key: str):
    """إلغاء تفعيل الاتفاق الجانبي لخدمة — تعود الخدمة للحالة الافتراضية."""
    lic = db.get_or_404(License, license_id)
    base = _get_service_def(service_key)
    if base is None:
        abort(404)
    ov = LicenseServiceOverride.query.filter_by(
        license_id=lic.id, service_key=service_key
    ).one_or_none()
    if ov is not None:
        db.session.delete(ov)
        audit(
            "license.service.revoke", "license", lic.id,
            f"إلغاء تفعيل خدمة {base['name']} (اتفاق جانبي)",
            metadata={"service_key": service_key},
        )
        db.session.commit()
        flash(f"تم إلغاء تفعيل خدمة «{base['name']}».", "warning")
    return redirect(url_for("admin.license_services", license_id=lic.id))


@bp.post("/licenses/<int:license_id>/services/<service_key>/freeze")
@login_required
def license_service_freeze(license_id: int, service_key: str):
    lic = db.get_or_404(License, license_id)
    base = _get_service_def(service_key)
    if base is None:
        abort(404)
    _upsert_override(lic, service_key, status="frozen")
    audit("license.service.freeze", "license", lic.id,
          f"تجميد خدمة {base['name']}",
          metadata={"service_key": service_key})
    db.session.commit()
    flash(f"تم تجميد خدمة «{base['name']}».", "warning")
    return redirect(url_for("admin.license_services", license_id=lic.id))


@bp.post("/licenses/<int:license_id>/services/<service_key>/unfreeze")
@login_required
def license_service_unfreeze(license_id: int, service_key: str):
    lic = db.get_or_404(License, license_id)
    base = _get_service_def(service_key)
    if base is None:
        abort(404)
    _upsert_override(lic, service_key, status="active")
    audit("license.service.unfreeze", "license", lic.id,
          f"تفعيل خدمة {base['name']} بعد التجميد",
          metadata={"service_key": service_key})
    db.session.commit()
    flash(f"تم تفعيل خدمة «{base['name']}».", "success")
    return redirect(url_for("admin.license_services", license_id=lic.id))


@bp.post("/licenses/<int:license_id>/services/<service_key>/hide")
@login_required
def license_service_hide(license_id: int, service_key: str):
    lic = db.get_or_404(License, license_id)
    base = _get_service_def(service_key)
    if base is None:
        abort(404)
    _upsert_override(lic, service_key, status="hidden")
    audit("license.service.hide", "license", lic.id,
          f"إخفاء خدمة {base['name']}",
          metadata={"service_key": service_key})
    db.session.commit()
    flash(f"تم إخفاء خدمة «{base['name']}» عن واجهة العميل.", "info")
    return redirect(url_for("admin.license_services", license_id=lic.id))


@bp.post("/licenses/<int:license_id>/services/<service_key>/show")
@login_required
def license_service_show(license_id: int, service_key: str):
    lic = db.get_or_404(License, license_id)
    base = _get_service_def(service_key)
    if base is None:
        abort(404)
    _upsert_override(lic, service_key, status="active")
    audit("license.service.show", "license", lic.id,
          f"إظهار خدمة {base['name']}",
          metadata={"service_key": service_key})
    db.session.commit()
    flash(f"تم إظهار خدمة «{base['name']}» للعميل.", "success")
    return redirect(url_for("admin.license_services", license_id=lic.id))


@bp.post("/licenses/<int:license_id>/services/<service_key>/edit-limit")
@login_required
def license_service_edit_limit(license_id: int, service_key: str):
    lic = db.get_or_404(License, license_id)
    base = _get_service_def(service_key)
    if base is None:
        abort(404)
    try:
        new_limit = int(request.form.get("new_limit") or 0)
    except (TypeError, ValueError):
        new_limit = 0
    if new_limit < 1:
        flash("الرجاء إدخال رقم صحيح أكبر من صفر.", "error")
        return redirect(url_for("admin.license_services", license_id=lic.id))
    _upsert_override(lic, service_key, max_limit=new_limit)
    audit("license.service.edit_limit", "license", lic.id,
          f"تعديل حد {base['name']} → {new_limit}",
          metadata={"service_key": service_key, "new_limit": new_limit})
    db.session.commit()
    flash(f"تم تعديل حد خدمة «{base['name']}» إلى {new_limit}.", "success")
    return redirect(url_for("admin.license_services", license_id=lic.id))


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
@super_admin_required          # FIX #7 — terminal action, super-only.
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
    _now = utcnow()
    _today_start = _now.replace(hour=0, minute=0, second=0, microsecond=0)
    _week_start = _now - timedelta(days=7)
    _audit_stats = {
        "total": AuditLog.query.count(),
        "today": AuditLog.query.filter(AuditLog.created_at >= _today_start).count(),
        "week": AuditLog.query.filter(AuditLog.created_at >= _week_start).count(),
        "errors": AuditLog.query.filter(AuditLog.action.ilike("%error%") | AuditLog.action.ilike("%fail%")).count(),
    }
    _total = _audit_stats["total"]
    _per = 50
    _total_pages = max(1, (_total + _per - 1) // _per)
    _page = min(max(1, int(request.args.get("page") or 1)), _total_pages)
    logs = (
        AuditLog.query
        .order_by(AuditLog.created_at.desc())
        .offset((_page - 1) * _per)
        .limit(_per)
        .all()
    )
    # نافذة أرقام الصفحات مع '...' (مثل: 1 … 4 5 [6] 7 8 … 20)
    _page_tokens, _prev = [], 0
    for _n in range(1, _total_pages + 1):
        if _n <= 2 or _n > _total_pages - 2 or abs(_n - _page) <= 1:
            if _prev and _n - _prev > 1:
                _page_tokens.append("...")
            _page_tokens.append(_n)
            _prev = _n
    _pagination = {
        "page": _page,
        "from": (min((_page - 1) * _per + 1, _total) if _total else 0),
        "to": min(_page * _per, _total),
        "total": _total,
        "pages": _page_tokens,
        "total_pages": _total_pages,
    }
    return render_template(
        "admin/logs/audit_new.html",
        logs=logs,
        stats=_audit_stats,
        pagination=_pagination,
    )


@bp.get("/settings")
@login_required
def settings_page():
    from ..services.whatsapp import cloud_settings as wac
    from ..services.whatsapp import embedded_settings as wae
    from ..services import chr_settings as chr_svc
    from ..services import customer_vault_crypto as vc
    from ..models import ProxyRealmRoute
    settings = {row.key: row.value for row in Setting.query.order_by(Setting.key.asc()).all()}
    return render_template(
        "admin/settings/general_new.html",
        settings=settings,
        customer_name=_setting("product_name", ""),
        support_email=_setting("support_email", ""),
        wac_enabled=wac.enabled(),
        wac_state=wac.get_state() if wac.enabled() else None,
        wae_state=wae.get_state(),
        chr_enabled=chr_svc.enabled(),
        chr_state=chr_svc.get_state() if chr_svc.enabled() else None,
        proxy_route_count=ProxyRealmRoute.query.filter_by(status="active").count(),
        vault_key_state=vc.vault_key_state(),
    )


@bp.get("/settings/whatsapp")
@login_required
def settings_whatsapp():
    """Legacy URL — redirect to the REAL WhatsApp Cloud settings panel on
    the main Settings page. The old standalone whatsapp_new.html template
    was a dead duplicate (every form posted to ``action="#"``). The live
    handlers (``whatsapp_cloud_save/test/reveal``) read state from
    ``cloud_settings.get_state()`` and write through the encrypted Setting
    store — they live inline in ``settings_page`` under the anchor below.
    """
    return redirect(url_for("admin.settings_page") + "#whatsapp-cloud")


@bp.route("/settings/sections", methods=["GET", "POST"])
@login_required
def sections_settings():
    from .section_visibility import get_hidden_sections, save_visibility
    if request.method == "POST":
        data = request.get_json() or {}
        save_visibility(data)
        return jsonify({"success": True})
    hidden = get_hidden_sections()
    return render_template("admin/settings/sections_new.html", hidden_sections=hidden)


@bp.get("/settings/admins")
@login_required
def settings_admins():
    from ..models import Admin as _Admin
    admins = _Admin.query.order_by(_Admin.id.asc()).all()
    class _AdminProxy:
        def __init__(self, a):
            self._a = a
        def __getattr__(self, name):
            return getattr(self._a, name)
        @property
        def role(self):
            return "super_admin" if self._a.is_super_admin else "operator"
        @property
        def enabled(self):
            return self._a.active
    return render_template(
        "admin/settings/admins_new.html",
        admins=[_AdminProxy(a) for a in admins],
    )


# ────────────────────────────────────────────────────────────────────────────
# /settings/admins — CRUD wired (FIX #1 of mock-inventory remediation).
#
# Owner-rule: every admin operation comes from the UI; no terminal.
# Auth: super_admin_required — managing admins must not be open to operators.
# Audit: every mutation logged via audit().
# UX: username derived from email's local part (the UI hides the column);
#     password ≥ 8 chars on create; optional on edit.
# Role mapping: the template offers four labels (super_admin / operator /
#     support / viewer). The auth model has two tiers (is_super_admin), so
#     "super_admin" → True, everything else → False. The non-super tiers
#     differ only in UI semantics today — when finer-grained roles ship the
#     existing `is_super_admin` boolean plus a future `role_key` column slots
#     in without breaking these handlers.
# ────────────────────────────────────────────────────────────────────────────


def _admin_role_to_super(role: str) -> bool:
    """Map the UI role choice onto the binary auth tier."""
    return (role or "").strip().lower() == "super_admin"


def _admin_validate_password(password: str) -> str | None:
    if len(password) < 8:
        return "كلمة المرور يجب أن تكون 8 أحرف على الأقل."
    return None


def _admin_resolve_username(email: str, full_name: str) -> str:
    """Derive a stable username from email's local part; fall back to full name."""
    base = ""
    if email and "@" in email:
        base = email.split("@", 1)[0]
    if not base:
        base = (full_name or "").strip().replace(" ", ".").lower()
    base = re.sub(r"[^a-zA-Z0-9._-]", "", base)[:60].lower() or "admin"
    return base


@bp.post("/settings/admins")
@super_admin_required
def settings_admins_post():
    """Single POST endpoint — branches on the form's ``action`` field
    (create / edit / enable / disable / delete) so the template's existing
    hidden ``action`` input keeps working."""
    from ..models import Admin as _Admin

    action = (request.form.get("action") or "").strip().lower()
    me = current_admin()

    # ─── CREATE ────────────────────────────────────────────────────────
    if action == "create":
        full_name = (request.form.get("full_name") or "").strip()[:160]
        email = (request.form.get("email") or "").strip().lower()[:160]
        password = request.form.get("password") or ""
        role = (request.form.get("role") or "operator").strip().lower()
        if not full_name:
            flash("الاسم الكامل مطلوب.", "error")
            return redirect(url_for("admin.settings_admins"))
        if not email or "@" not in email:
            flash("البريد الإلكتروني غير صالح.", "error")
            return redirect(url_for("admin.settings_admins"))
        err = _admin_validate_password(password)
        if err:
            flash(err, "error")
            return redirect(url_for("admin.settings_admins"))
        if _Admin.query.filter(func.lower(_Admin.email) == email).first():
            flash("البريد الإلكتروني مستخدم بالفعل.", "error")
            return redirect(url_for("admin.settings_admins"))
        username = _admin_resolve_username(email, full_name)
        # Disambiguate username collisions deterministically.
        if _Admin.query.filter_by(username=username).first():
            i = 2
            while _Admin.query.filter_by(username=f"{username}{i}").first():
                i += 1
            username = f"{username}{i}"
        admin = _Admin(
            username=username,
            email=email,
            full_name=full_name,
            active=True,
            is_super_admin=_admin_role_to_super(role),
        )
        admin.set_password(password)
        db.session.add(admin)
        db.session.flush()
        audit(
            "admin_user_created", "admin", str(admin.id),
            f"تم إنشاء مشرف جديد {admin.username} ({admin.full_name}) — الدور: {role}",
            metadata={"username": admin.username, "email": admin.email, "role": role,
                      "is_super_admin": admin.is_super_admin},
        )
        db.session.commit()
        flash(f"تم إنشاء المشرف «{admin.full_name}».", "success")
        return redirect(url_for("admin.settings_admins"))

    # ─── EDIT ──────────────────────────────────────────────────────────
    if action == "edit":
        target_username = (request.form.get("edit_username") or "").strip()
        admin = _Admin.query.filter_by(username=target_username).first()
        if admin is None:
            flash("المشرف غير موجود.", "error")
            return redirect(url_for("admin.settings_admins"))
        full_name = (request.form.get("full_name") or "").strip()[:160]
        email = (request.form.get("email") or "").strip().lower()[:160]
        role = (request.form.get("role") or "operator").strip().lower()
        password = request.form.get("password") or ""
        if not full_name:
            flash("الاسم الكامل مطلوب.", "error")
            return redirect(url_for("admin.settings_admins"))
        if not email or "@" not in email:
            flash("البريد الإلكتروني غير صالح.", "error")
            return redirect(url_for("admin.settings_admins"))
        if _Admin.query.filter(
            func.lower(_Admin.email) == email, _Admin.id != admin.id
        ).first():
            flash("البريد الإلكتروني مستخدم لمشرف آخر.", "error")
            return redirect(url_for("admin.settings_admins"))
        # Prevent self-demotion to non-super when no other super exists — would
        # lock the panel out of super-only routes.
        new_super = _admin_role_to_super(role)
        if me and me.id == admin.id and admin.is_super_admin and not new_super:
            other_super = _Admin.query.filter(
                _Admin.is_super_admin.is_(True), _Admin.id != admin.id,
                _Admin.active.is_(True),
            ).count()
            if other_super == 0:
                flash("لا يمكنك خفض رتبة نفسك — أنت المسؤول العام الوحيد المُفعَّل.", "error")
                return redirect(url_for("admin.settings_admins"))
        admin.full_name = full_name
        admin.email = email
        admin.is_super_admin = new_super
        if password:
            err = _admin_validate_password(password)
            if err:
                flash(err, "error")
                return redirect(url_for("admin.settings_admins"))
            admin.set_password(password)
        audit(
            "admin_user_updated", "admin", str(admin.id),
            f"تم تحديث المشرف {admin.username} ({admin.full_name})",
            metadata={"role": role, "is_super_admin": admin.is_super_admin,
                      "password_changed": bool(password)},
        )
        db.session.commit()
        flash(f"تم تحديث المشرف «{admin.full_name}».", "success")
        return redirect(url_for("admin.settings_admins"))

    # ─── ENABLE / DISABLE ──────────────────────────────────────────────
    if action in {"enable", "disable"}:
        target_username = (request.form.get("username") or "").strip()
        admin = _Admin.query.filter_by(username=target_username).first()
        if admin is None:
            flash("المشرف غير موجود.", "error")
            return redirect(url_for("admin.settings_admins"))
        if me and me.id == admin.id and action == "disable":
            flash("لا يمكنك إيقاف حسابك الحالي.", "error")
            return redirect(url_for("admin.settings_admins"))
        admin.active = (action == "enable")
        audit(
            f"admin_user_{action}d", "admin", str(admin.id),
            f"تم {'تفعيل' if action == 'enable' else 'إيقاف'} المشرف {admin.username}",
        )
        db.session.commit()
        flash(
            f"تم {'تفعيل' if action == 'enable' else 'إيقاف'} المشرف «{admin.full_name or admin.username}».",
            "success",
        )
        return redirect(url_for("admin.settings_admins"))

    # ─── DELETE ────────────────────────────────────────────────────────
    if action == "delete":
        target_username = (request.form.get("username") or "").strip()
        admin = _Admin.query.filter_by(username=target_username).first()
        if admin is None:
            flash("المشرف غير موجود.", "error")
            return redirect(url_for("admin.settings_admins"))
        if me and me.id == admin.id:
            flash("لا يمكنك حذف حسابك الحالي.", "error")
            return redirect(url_for("admin.settings_admins"))
        # Refuse deletion of the last active super-admin.
        if admin.is_super_admin:
            other_super = _Admin.query.filter(
                _Admin.is_super_admin.is_(True), _Admin.id != admin.id,
                _Admin.active.is_(True),
            ).count()
            if other_super == 0:
                flash("لا يمكن حذف المسؤول العام الأخير المُفعَّل.", "error")
                return redirect(url_for("admin.settings_admins"))
        display = admin.full_name or admin.username
        audit(
            "admin_user_deleted", "admin", str(admin.id),
            f"تم حذف المشرف {admin.username} ({display})",
            metadata={"email": admin.email, "is_super_admin": admin.is_super_admin},
        )
        db.session.delete(admin)
        db.session.commit()
        flash(f"تم حذف المشرف «{display}».", "success")
        return redirect(url_for("admin.settings_admins"))

    flash("إجراء غير معروف.", "error")
    return redirect(url_for("admin.settings_admins"))


# ════════════════════════════════════════════════════════════════════════════
# /settings/section — unified handler for site-info / payments / email forms
# on the General Settings page (FIX #2 of mock-inventory remediation).
#
# The template renders one <form> per panel with a hidden ``section`` field.
# Each panel's keys are whitelisted below so a malicious POST can't smuggle
# arbitrary keys into the ``Setting`` table.
#
# Logo upload: persisted under app/static/uploads/site_logo.<ext> and the
# URL written to the ``site_logo`` Setting.
#
# SMTP password: encrypted at rest with the existing WHATSAPP_FERNET_KEY
# (same pattern as the WhatsApp/CHR/Fleet secrets vault). Never echoed.
# ════════════════════════════════════════════════════════════════════════════


_SETTINGS_SECTION_KEYS = {
    "site_info": (
        "site_name", "site_tagline", "site_address",
        "support_email", "support_phone", "site_url", "timezone",
    ),
    "payment": (
        "default_currency", "tax_rate", "grace_days", "invoice_prefix",
        "gateway_cash", "gateway_bank", "gateway_stripe",
        "gateway_paypal", "gateway_whatsapp",
    ),
    "email": (
        "smtp_host", "smtp_port", "smtp_username",
        "from_name", "from_email", "email_signature",
    ),
}

# Settings keys whose values are booleans (checkbox: present="1", absent="").
_SETTINGS_BOOL_KEYS = {
    "gateway_cash", "gateway_bank", "gateway_stripe",
    "gateway_paypal", "gateway_whatsapp",
}

# Settings keys whose values must be encrypted at rest.
_SETTINGS_SECRET_KEYS = {"smtp_password"}

# Allowed image MIME types + extension map for the logo upload.
_LOGO_EXT_BY_MIME = {
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/jpg": ".jpg",
    "image/gif": ".gif",
    "image/webp": ".webp",
    "image/svg+xml": ".svg",
}
_LOGO_MAX_BYTES = 500 * 1024  # 500 KB (matches the template hint)


@bp.post("/settings/section")
@login_required
def settings_section_save():
    section = (request.form.get("section") or "").strip().lower()
    allowed = _SETTINGS_SECTION_KEYS.get(section)
    if not allowed:
        flash("قسم الإعدادات غير معروف.", "error")
        return redirect(url_for("admin.settings_page"))

    # ─── Logo upload (site_info panel) ────────────────────────────────
    if section == "site_info":
        logo = request.files.get("site_logo")
        if logo and getattr(logo, "filename", ""):
            ext = _LOGO_EXT_BY_MIME.get((logo.mimetype or "").lower())
            if ext is None:
                flash("صيغة الشعار غير مدعومة. اختر PNG أو SVG أو JPG.", "error")
                return redirect(url_for("admin.settings_page"))
            # Read once + size-cap before writing.
            blob = logo.read(_LOGO_MAX_BYTES + 1)
            if len(blob) > _LOGO_MAX_BYTES:
                flash("الشعار أكبر من 500 كيلوبايت. اختصره وأعد المحاولة.", "error")
                return redirect(url_for("admin.settings_page"))
            uploads_dir = Path(current_app.static_folder) / "uploads"
            uploads_dir.mkdir(parents=True, exist_ok=True)
            target = uploads_dir / f"site_logo{ext}"
            try:
                target.write_bytes(blob)
            except OSError as exc:
                current_app.logger.warning("settings_section: logo write failed: %s", exc)
                flash("تعذّر حفظ ملف الشعار على الخادم.", "error")
                return redirect(url_for("admin.settings_page"))
            _set_setting("site_logo", url_for("static", filename=f"uploads/site_logo{ext}"))

    # ─── Whitelisted text/bool keys ────────────────────────────────────
    for key in allowed:
        if key in _SETTINGS_BOOL_KEYS:
            _set_setting(key, "1" if request.form.get(key) else "")
        else:
            value = (request.form.get(key) or "").strip()[:500]
            _set_setting(key, value)

    # ─── Email panel — encrypt SMTP password if provided ───────────────
    if section == "email":
        new_password = (request.form.get("smtp_password") or "").strip()
        if new_password:
            try:
                from ..services.whatsapp.crypto import encrypt_secret, WhatsAppCryptoError
                _set_setting("smtp_password", encrypt_secret(new_password))
            except WhatsAppCryptoError:
                flash("لم يُضبط مفتاح التشفير على الخادم — راجع إعداد WHATSAPP_FERNET_KEY.", "error")
                return redirect(url_for("admin.settings_page"))

    audit("settings_section_updated", "settings", section, f"تم حفظ قسم الإعدادات {section}",
          metadata={"section": section})
    db.session.commit()
    flash("تم حفظ الإعدادات.", "success")
    return redirect(url_for("admin.settings_page"))


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
        "google_oauth_client_id",
        "google_oauth_client_secret",
        "google_oauth_redirect_uri",
    ):
        _set_setting(key, (request.form.get(key) or "").strip())
    audit("settings_updated", "settings", "global", "Updated system settings")
    db.session.commit()
    flash("تم حفظ الإعدادات.", "success")
    return redirect(url_for("admin.settings_page"))


# ── Platform settings — operational knobs migrated from env to the DB ────────
# Resolution chain per key: Setting row -> app.config -> built-in default. The
# owner edits every value here; nothing else needs editing in env in prod.
@bp.get("/settings/platform")
@login_required
def settings_platform():
    from ..services import platform_settings as ps
    return render_template(
        "admin/settings/platform_new.html",
        groups=ps.snapshot(),
        health=ps.health(),
    )


@bp.post("/settings/platform")
@login_required
def settings_platform_save():
    from ..services import platform_settings as ps
    try:
        result = ps.save_form(request.form, actor_audit=audit)
    except ps.PlatformSettingsError as exc:
        db.session.rollback()
        flash(str(exc), "error")
        return redirect(url_for("admin.settings_platform"))
    # Re-apply LOG_LEVEL live if the operator just changed it. Other knobs are
    # read on every request through the resolver, so no extra apply step.
    import logging
    new_level = ps.get_str("LOG_LEVEL", "INFO").upper()
    new_int = getattr(logging, new_level, logging.INFO)
    logging.getLogger().setLevel(new_int)
    try:
        request.environ.get("flask.app").logger.setLevel(new_int)  # type: ignore[union-attr]
    except Exception:  # noqa: BLE001
        pass
    db.session.commit()
    flash(
        f"تم حفظ {result['saved']} حقلًا (تجاوُز قاعدة البيانات الآن مفعّل)."
        + (f" دوّرت {len(result['secrets_rotated'])} سرّ." if result['secrets_rotated'] else ""),
        "success",
    )
    return redirect(url_for("admin.settings_platform"))


@bp.post("/settings/platform/<key>/reset")
@login_required
def settings_platform_reset(key: str):
    """Clear the DB row for one key so the resolver falls back to env/default."""
    from ..services import platform_settings as ps
    if key not in ps.KEYS:
        abort(404)
    row = db.session.get(Setting, key)
    if row is not None:
        row.value = ""
        db.session.add(row)
        # Drop the per-request cache so subsequent reads see the fallback.
        ps._invalidate_cache()
        audit("platform_settings_reset", "platform_settings", key,
              f"إعادة {key} إلى قيمة البيئة/الافتراضي.", {"key": key})
        db.session.commit()
        flash(f"تمت إعادة {ps.KEYS[key].label_ar} إلى القيمة الافتراضية.", "info")
    return redirect(url_for("admin.settings_platform"))


# ── WhatsApp Cloud API settings (admin-managed house credentials) ──────────
def _wac_redirect():
    return redirect(url_for("admin.settings_page") + "#whatsapp-cloud")


def _wac_guard():
    """Return None if enabled; else a redirect (feature flag off)."""
    from ..services.whatsapp import cloud_settings as wac
    if not wac.enabled():
        flash("قسم واتساب Cloud API غير مُفعّل.", "error")
        return _wac_redirect()
    return None


@bp.post("/settings/whatsapp-cloud")
@login_required
def whatsapp_cloud_save():
    from ..services.whatsapp import cloud_settings as wac
    blocked = _wac_guard()
    if blocked:
        return blocked
    try:
        wac.validate_and_save(request.form, actor_audit=audit)
    except wac.CloudSettingsError as exc:
        db.session.rollback()
        flash(str(exc), "error")
        return _wac_redirect()
    db.session.commit()
    flash("تم حفظ إعدادات واتساب Cloud API بنجاح.", "success")
    return _wac_redirect()


@bp.post("/settings/whatsapp-cloud/test")
@login_required
def whatsapp_cloud_test():
    from ..services.whatsapp import cloud_settings as wac
    blocked = _wac_guard()
    if blocked:
        return blocked
    try:
        result = wac.test_connection(actor_audit=audit)
    except wac.CloudSettingsError as exc:
        db.session.rollback()
        flash(str(exc), "error")
        return _wac_redirect()
    db.session.commit()
    if result.get("ok"):
        phone = result.get("display_phone_number") or "—"
        waba = "ومتاح" if result.get("waba_reachable") else "لكن تعذّر فحص الحساب"
        flash(f"نجح الاتصال ✅ — الرقم {phone} {waba}.", "success")
    else:
        flash("فشل الاتصال: " + (result.get("message") or "تحقّق من البيانات."), "error")
    return _wac_redirect()


@bp.post("/settings/whatsapp-cloud/test-message")
@login_required
def whatsapp_cloud_test_message():
    from ..services.whatsapp import cloud_settings as wac
    blocked = _wac_guard()
    if blocked:
        return blocked
    try:
        result = wac.send_test_message(
            request.form.get("recipient") or "",
            template_name=request.form.get("template_name") or "",
            language=request.form.get("language") or "",
            actor_audit=audit,
        )
    except wac.CloudSettingsError as exc:
        db.session.rollback()
        flash(str(exc), "error")
        return _wac_redirect()
    db.session.commit()
    if result.get("ok"):
        flash("تم إرسال رسالة الاختبار ✅ — تحقّق من واتساب المستلم.", "success")
    else:
        flash("تعذّر إرسال رسالة الاختبار: " + (result.get("message") or "حاول مرة أخرى."), "error")
    return _wac_redirect()


@bp.post("/settings/whatsapp-cloud/reveal")
@super_admin_required
def whatsapp_cloud_reveal():
    """Temporarily reveal a stored secret (super-admin only, audited, JSON)."""
    from ..services.whatsapp import cloud_settings as wac
    if not wac.enabled():
        return jsonify({"ok": False, "message": "القسم غير مُفعّل."}), 403
    field = (request.form.get("field") or "").strip()
    try:
        value = wac.reveal(field, actor_audit=audit)
    except wac.CloudSettingsError as exc:
        db.session.rollback()
        return jsonify({"ok": False, "message": str(exc)}), 400
    db.session.commit()
    return jsonify({"ok": True, "value": value})


@bp.post("/settings/whatsapp-cloud/templates")
@login_required
def whatsapp_cloud_templates():
    """List the WABA's message templates so the admin can pick a real one (JSON)."""
    from ..services.whatsapp import cloud_settings as wac
    if not wac.enabled():
        return jsonify({"ok": False, "message": "القسم غير مُفعّل."}), 403
    try:
        result = wac.list_message_templates()
    except wac.CloudSettingsError as exc:
        return jsonify({"ok": False, "message": str(exc)}), 400
    return jsonify(result)


# ── WhatsApp Embedded Signup settings (panel-managed, zero-terminal) ───────
def _wae_redirect():
    return redirect(url_for("admin.settings_page") + "#whatsapp-embedded")


@bp.post("/settings/whatsapp-embedded")
@login_required
def whatsapp_embedded_save():
    from ..services.whatsapp import embedded_settings as wae
    try:
        wae.validate_and_save(request.form, actor_audit=audit)
    except wae.EmbeddedSettingsError as exc:
        db.session.rollback()
        flash(str(exc), "error")
        return _wae_redirect()
    db.session.commit()
    flash("تم حفظ إعدادات الربط التلقائي (Embedded Signup) بنجاح.", "success")
    return _wae_redirect()


@bp.post("/settings/whatsapp-embedded/reveal")
@super_admin_required
def whatsapp_embedded_reveal():
    """Temporarily reveal the stored App Secret (super-admin only, audited, JSON)."""
    from ..services.whatsapp import embedded_settings as wae
    field = (request.form.get("field") or "").strip()
    try:
        value = wae.reveal(field, actor_audit=audit)
    except wae.EmbeddedSettingsError as exc:
        db.session.rollback()
        return jsonify({"ok": False, "message": str(exc)}), 400
    db.session.commit()
    return jsonify({"ok": True, "value": value})


# ── MikroTik CHR connection settings (owner-managed, encrypted) ────────────
def _chr_redirect():
    return redirect(url_for("admin.settings_page") + "#chr-settings")


def _chr_guard():
    """Return None if enabled; else a redirect (feature flag off)."""
    from ..services import chr_settings as chr_svc
    if not chr_svc.enabled():
        flash("تزويد CHR غير مُفعّل.", "error")
        return _chr_redirect()
    return None


@bp.post("/settings/chr")
@login_required
def chr_settings_save():
    from ..services import chr_settings as chr_svc
    blocked = _chr_guard()
    if blocked:
        return blocked
    # تغيير اتصال مقفل يتطلّب: مسؤول عام + تأكيد صريح في النموذج. غير المسؤول العام
    # لا يستطيع تجاوز القفل مهما أرسل من حقول.
    admin = current_admin()
    is_super = bool(getattr(admin, "is_super_admin", False))
    confirmed = (request.form.get("confirm_locked_change") or "").strip().lower() in {"1", "yes", "on", "true"}
    allow_locked_change = is_super and confirmed
    try:
        chr_svc.validate_and_save(request.form, actor_audit=audit, allow_locked_change=allow_locked_change)
    except chr_svc.ChrSettingsError as exc:
        db.session.rollback()
        flash(str(exc), "error")
        return _chr_redirect()
    db.session.commit()
    flash("تم حفظ بيانات اتصال CHR بنجاح.", "success")
    return _chr_redirect()


@bp.post("/settings/chr/lock")
@super_admin_required
def chr_settings_lock():
    """يقفل اتصال CHR صراحةً (مسؤول عام فقط، مُدقَّق)."""
    from ..services import chr_settings as chr_svc
    blocked = _chr_guard()
    if blocked:
        return blocked
    admin = current_admin()
    try:
        chr_svc.lock(actor_audit=audit, actor_label=(admin.username if admin else ""))
    except chr_svc.ChrSettingsError as exc:
        db.session.rollback()
        flash(str(exc), "error")
        return _chr_redirect()
    db.session.commit()
    flash("تم قفل اتصال CHR. لن يُداس إلا بتأكيد صريح.", "success")
    return _chr_redirect()


@bp.post("/settings/chr/unlock")
@super_admin_required
def chr_settings_unlock():
    """يفكّ قفل اتصال CHR صراحةً (مسؤول عام فقط، مُدقَّق)."""
    from ..services import chr_settings as chr_svc
    blocked = _chr_guard()
    if blocked:
        return blocked
    admin = current_admin()
    try:
        chr_svc.unlock(actor_audit=audit, actor_label=(admin.username if admin else ""))
    except chr_svc.ChrSettingsError as exc:
        db.session.rollback()
        flash(str(exc), "error")
        return _chr_redirect()
    db.session.commit()
    flash("تم فكّ قفل اتصال CHR — أصبح قابلًا للتعديل.", "success")
    return _chr_redirect()


@bp.post("/settings/chr/test")
@login_required
def chr_settings_test():
    from ..services import chr_settings as chr_svc
    blocked = _chr_guard()
    if blocked:
        return blocked
    try:
        result = chr_svc.test_connection(actor_audit=audit)
    except chr_svc.ChrSettingsError as exc:
        db.session.rollback()
        flash(str(exc), "error")
        return _chr_redirect()
    db.session.commit()
    if result.get("ok"):
        flash(
            f"نجح الاتصال بـ CHR ✅ — {result.get('identity') or '—'} (RouterOS {result.get('version') or '—'}).",
            "success",
        )
    else:
        flash("فشل الاتصال بـ CHR: " + (result.get("message") or "تحقّق من البيانات."), "error")
    return _chr_redirect()


@bp.post("/settings/chr/reveal")
@super_admin_required
def chr_settings_reveal():
    """Temporarily reveal the stored CHR password (super-admin only, audited)."""
    from ..services import chr_settings as chr_svc
    if not chr_svc.enabled():
        return jsonify({"ok": False, "message": "القسم غير مُفعّل."}), 403
    try:
        value = chr_svc.reveal(actor_audit=audit)
    except chr_svc.ChrSettingsError as exc:
        db.session.rollback()
        return jsonify({"ok": False, "message": str(exc)}), 400
    db.session.commit()
    return jsonify({"ok": True, "value": value})


# ── Customer Vault encryption key (owner-managed, encrypted at rest) ───────
def _vault_settings_redirect():
    return redirect(url_for("admin.settings_page") + "#vault")


@bp.post("/settings/vault/key")
@super_admin_required
def vault_settings_save_key():
    """Persist a Fernet vault key in the DB, encrypted with the app master key.

    Super-admin only. The previous key (if any) is overwritten in the same
    commit. Existing ciphertext encrypted under the old key becomes unreadable
    on key change — the form warns about this explicitly.
    """
    from ..services import customer_vault_crypto as vc
    new_key = (request.form.get("new_key") or "").strip()
    try:
        vc.save_vault_key_in_db(new_key)
    except vc.VaultCryptoError as exc:
        db.session.rollback()
        flash(str(exc), "error")
        return _vault_settings_redirect()
    audit("vault_key_saved", "settings", "customer_vault.encryption_key",
          "حفظ مفتاح تشفير الخزنة عبر لوحة الإدارة", {})
    db.session.commit()
    flash("تم حفظ مفتاح تشفير الخزنة بنجاح.", "success")
    return _vault_settings_redirect()


@bp.post("/settings/vault/key/clear")
@super_admin_required
def vault_settings_clear_key():
    """Remove the DB-stored vault key. Falls back to the env key (if any).

    Super-admin only. Existing ciphertext stays in the DB; if the env key is
    different, secrets become unreadable until the right key is restored.
    """
    from ..services import customer_vault_crypto as vc
    vc.clear_vault_key_in_db()
    audit("vault_key_cleared", "settings", "customer_vault.encryption_key",
          "حذف مفتاح تشفير الخزنة من قاعدة البيانات", {})
    db.session.commit()
    flash("تم حذف المفتاح المخزّن في قاعدة البيانات.", "success")
    return _vault_settings_redirect()


@bp.post("/settings/vault/key/generate")
@super_admin_required
def vault_settings_generate_key():
    """Return a freshly generated Fernet key as JSON (NOT persisted).

    The UI fills it into the input so the operator can review + save.
    """
    from ..services import customer_vault_crypto as vc
    return jsonify({"ok": True, "key": vc.generate_fernet_key()})


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
        if isinstance(exc, LicensePaymentValidationError):
            return jsonify({"ok": False, "error": exc.code, "message": exc.message_ar}), 400
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
        if isinstance(exc, LicensePaymentValidationError):
            return jsonify({"ok": False, "error": exc.code, "message": exc.message_ar}), 400
        return _payment_error(str(exc), 400)
    audit("payment_request_created", "license_payment_request", str(payment_request.id), f"Created payment request {payment_request.reference_code}")
    db.session.commit()
    # Owner notification (no-op when event/channels disabled); never blocks the response.
    from ..services.messaging import notify_owner as _notify_owner
    _notify_owner("payment_request_created",
                  detail=f"طلب دفع: {payment_request.reference_code}",
                  extra={"id": payment_request.id})
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
@super_admin_required          # FIX #7 — financial action; super-only.
def payment_request_approve(payment_request_id: int):
    payment_request = db.get_or_404(LicensePaymentRequest, payment_request_id)
    try:
        LicensePaymentReviewService().approve(
            payment_request=payment_request,
            reviewed_by=session.get("admin_id"),
            review_note=request.form.get("review_note") or "",
        )
    except LicensePaymentValidationError as exc:
        flash(payment_error_message(exc), "error")
        return redirect(url_for("admin.payment_request_detail", payment_request_id=payment_request.id))
    audit("license_payment_approved", "license_payment_request", str(payment_request.id), f"Approved payment {payment_request.reference_code}")
    db.session.commit()
    # Customer-facing "payment received" confirmation. Silent no-op when off.
    from ..services.messaging import dispatch_lifecycle as _dispatch_lifecycle
    if payment_request.customer:
        _dispatch_lifecycle("payment_received", payment_request.customer, variables={
            "company": payment_request.customer.company_name,
            "reference_code": payment_request.reference_code,
            "amount": str(payment_request.amount),
            "currency": payment_request.currency,
        })
    flash("تم قبول الدفع اليدوي. لم يتم تفعيل الترخيص تلقائيًا بعد.", "success")
    return redirect(url_for("admin.payment_request_detail", payment_request_id=payment_request.id))


@bp.post("/payments/requests/<int:payment_request_id>/reject")
@super_admin_required          # FIX #7 — financial action; super-only.
def payment_request_reject(payment_request_id: int):
    payment_request = db.get_or_404(LicensePaymentRequest, payment_request_id)
    try:
        LicensePaymentReviewService().reject(
            payment_request=payment_request,
            reviewed_by=session.get("admin_id"),
            review_note=request.form.get("review_note") or "",
        )
    except LicensePaymentValidationError as exc:
        flash(payment_error_message(exc), "error")
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
        flash(payment_error_message(exc), "error")
        return redirect(url_for("admin.payment_request_detail", payment_request_id=payment_request.id))
    # Customer-facing "license activated" confirmation. Silent no-op when off.
    from ..services.messaging import dispatch_lifecycle as _dispatch_lifecycle
    if payment_request.customer:
        _plan = getattr(payment_request.license, "plan", None) if payment_request.license else None
        _expires = getattr(payment_request.license, "expires_at", "") if payment_request.license else ""
        _dispatch_lifecycle("payment_applied", payment_request.customer, variables={
            "company": payment_request.customer.company_name,
            "reference_code": payment_request.reference_code,
            "plan_name": getattr(_plan, "name", "") if _plan else "",
            "expires_on": _expires.strftime("%Y-%m-%d") if _expires else "",
        })
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
    audit("license_payments_expired", "license_payment_request", "batch", f"تم إنهاء {count} طلب دفع معلّق")
    db.session.commit()
    flash(f"تم تعليم {count} طلب دفع معلّق كمنتهي.", "success")
    return redirect(url_for("admin.payment_reports"))


# ═══════════════════════════════════════════════════════════════════════════
# WhatsApp Gateway — operator admin UI
#
# All business logic lives in app/services/whatsapp/*. The routes below only
# read + aggregate via those services, render the templates, and on every
# mutating POST: call the service, wrap REAL Meta calls in try/except
# WhatsAppProviderError, write an AuditLog row via audit(...), flash, redirect.
# A token is NEVER rendered — only account_public_dict's masked preview.
# ═══════════════════════════════════════════════════════════════════════════

_WHATSAPP_PLAN_CODES = ("whatsapp_basic", "whatsapp_pro", "whatsapp_business")
_WHATSAPP_TEMPLATE_CATEGORIES = ("UTILITY", "AUTHENTICATION", "MARKETING")
_WHATSAPP_TEMPLATE_STATUSES = ("draft", "submitted", "approved", "rejected", "paused", "disabled")
_WHATSAPP_SETTINGS_TOGGLES = (
    "allow_otp",
    "allow_expiry_notice",
    "allow_quota_notice",
    "allow_maintenance_notice",
    "allow_password_reset",
    "allow_bulk_utility",
    "allow_marketing",
)


def _whatsapp_message_count_this_month(customer_id: int):
    """Counted (non-canceled/failed) queue rows created this calendar month."""
    from ..services.whatsapp import settings as wa_settings

    return wa_settings.count_month(customer_id, utcnow())


def _whatsapp_customer_row(customer: Customer) -> dict:
    """One dashboard row: account state + monthly volume + settings.enabled."""
    from ..services.whatsapp import settings as wa_settings

    account = wa_settings.get_account(customer.id)
    public = wa_settings.account_public_dict(account)
    settings_row = wa_settings.get_settings(customer.id)
    return {
        "customer": customer,
        "account": account,
        "public": public,
        "settings": settings_row,
        "enabled": bool(settings_row.enabled),
        "status": (account.connection_status if account else "not_configured"),
        "phone": public.get("display_phone_number") or "",
        "messages_month": _whatsapp_message_count_this_month(customer.id),
        "last_error": (public.get("last_error") or {}).get("message") or "",
        "last_health_check_at": account.last_health_check_at if account else None,
    }


@bp.get("/whatsapp-gateway")
@login_required
def whatsapp_gateway():
    """Global WhatsApp gateway dashboard: KPI cards + per-customer table."""
    from ..services.whatsapp import settings as wa_settings

    now = utcnow()
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)

    # Only customers that actually have an account or settings row appear.
    account_customer_ids = {a.customer_id for a in WhatsAppTenantAccount.query.all()}
    settings_customer_ids = {s.customer_id for s in WhatsAppServiceSettings.query.all()}
    customer_ids = account_customer_ids | settings_customer_ids
    customers = (
        Customer.query.filter(Customer.id.in_(customer_ids))
        .order_by(Customer.company_name.asc())
        .all()
        if customer_ids
        else []
    )

    rows = [_whatsapp_customer_row(customer) for customer in customers]

    connected = sum(1 for r in rows if r["status"] == "connected")
    pending_setup = sum(1 for r in rows if r["status"] in ("disconnected", "not_configured", "pending"))
    error_or_suspended = sum(1 for r in rows if r["status"] in ("error", "suspended"))

    # Global message KPIs straight off the queue (counted statuses only).
    counted = WhatsAppMessageQueue.status.notin_(("canceled", "failed"))
    messages_today = WhatsAppMessageQueue.query.filter(
        WhatsAppMessageQueue.created_at >= midnight, counted
    ).count()
    delivered_today = WhatsAppMessageQueue.query.filter(
        WhatsAppMessageQueue.delivered_at.isnot(None),
        WhatsAppMessageQueue.delivered_at >= midnight,
    ).count()
    failed_today = WhatsAppMessageQueue.query.filter(
        WhatsAppMessageQueue.failed_at.isnot(None),
        WhatsAppMessageQueue.failed_at >= midnight,
    ).count()
    messages_month = WhatsAppMessageQueue.query.filter(
        WhatsAppMessageQueue.created_at >= month_start, counted
    ).count()

    kpis = {
        "connected": connected,
        "pending_setup": pending_setup,
        "error_or_suspended": error_or_suspended,
        "messages_today": messages_today,
        "delivered_today": delivered_today,
        "failed_today": failed_today,
        "messages_month": messages_month,
    }
    return render_template("admin/whatsapp_gateway.html", rows=rows, kpis=kpis)


def _whatsapp_message_query():
    """Filtered WhatsAppMessageQueue query from request.args (newest first)."""
    query = WhatsAppMessageQueue.query
    customer_id = (request.args.get("customer_id") or "").strip()
    status = (request.args.get("status") or "").strip()
    event = (request.args.get("event") or "").strip()
    phone = (request.args.get("phone") or "").strip()
    provider_message_id = (request.args.get("provider_message_id") or "").strip()
    date_from = _parse_iso_date(request.args.get("date_from"))
    date_to = _parse_iso_date(request.args.get("date_to"))

    if customer_id:
        try:
            query = query.filter(WhatsAppMessageQueue.customer_id == int(customer_id))
        except (TypeError, ValueError):
            pass
    if status:
        query = query.filter(WhatsAppMessageQueue.status == status)
    if event:
        query = query.filter(WhatsAppMessageQueue.source_event_type == event)
    if phone:
        like = f"%{phone}%"
        query = query.filter(
            WhatsAppMessageQueue.recipient_phone.ilike(like)
            | WhatsAppMessageQueue.normalized_recipient_phone.ilike(like)
        )
    if provider_message_id:
        query = query.filter(WhatsAppMessageQueue.provider_message_id.ilike(f"%{provider_message_id}%"))
    if date_from:
        query = query.filter(WhatsAppMessageQueue.created_at >= date_from)
    if date_to:
        query = query.filter(WhatsAppMessageQueue.created_at < (date_to + timedelta(days=1)))
    return query.order_by(WhatsAppMessageQueue.created_at.desc(), WhatsAppMessageQueue.id.desc())


def _parse_iso_date(raw: str | None) -> datetime | None:
    text = (raw or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


@bp.get("/whatsapp-gateway/messages")
@login_required
def whatsapp_messages():
    """Outbound message log: filters + pagination + per-row retry/cancel."""
    page = max(1, _int_arg("page", 1))
    per_page = _int_arg("per_page", 20)
    if per_page not in (10, 20, 50, 100):
        per_page = 20
    query = _whatsapp_message_query()
    total = query.count()
    messages = query.limit(per_page).offset((page - 1) * per_page).all()
    customers = Customer.query.order_by(Customer.company_name.asc()).all()
    return render_template(
        "admin/whatsapp_message_log.html",
        messages=messages,
        customers=customers,
        page=page,
        per_page=per_page,
        total=total,
        filters={
            "customer_id": (request.args.get("customer_id") or "").strip(),
            "status": (request.args.get("status") or "").strip(),
            "event": (request.args.get("event") or "").strip(),
            "phone": (request.args.get("phone") or "").strip(),
            "provider_message_id": (request.args.get("provider_message_id") or "").strip(),
            "date_from": (request.args.get("date_from") or "").strip(),
            "date_to": (request.args.get("date_to") or "").strip(),
        },
    )


def _int_arg(name: str, default: int) -> int:
    try:
        return int(request.args.get(name) or default)
    except (TypeError, ValueError):
        return default


@bp.post("/whatsapp-gateway/messages/<int:message_id>/retry")
@login_required
def whatsapp_message_retry(message_id: int):
    """Re-queue a failed+retryable message, then best-effort drain it once."""
    from ..services.whatsapp import queue as wa_queue
    from ..services.whatsapp import worker as wa_worker

    row = wa_queue.get_message(message_id)
    if row is None:
        abort(404)
    if row.status != "failed" or int(row.attempts or 0) >= int(row.max_attempts or 0):
        flash("لا يمكن إعادة المحاولة: الرسالة ليست في حالة فشل قابلة لإعادة الإرسال.", "error")
        return redirect(url_for("admin.whatsapp_messages"))

    wa_queue.schedule_retry(row, 0, utcnow())
    audit(
        "whatsapp_message_retry",
        "whatsapp_message",
        str(row.id),
        f"إعادة محاولة إرسال رسالة واتساب رقم {row.id}",
        {"customer_id": row.customer_id, "event": row.source_event_type},
    )
    db.session.commit()
    try:
        wa_worker.drain_once()
    except Exception:  # noqa: BLE001 — drain is best-effort; row stays queued.
        db.session.rollback()
    flash("تمت إعادة جدولة الرسالة وتشغيل التصريف.", "success")
    return redirect(url_for("admin.whatsapp_messages"))


@bp.post("/whatsapp-gateway/messages/<int:message_id>/cancel")
@login_required
def whatsapp_message_cancel(message_id: int):
    """Cancel a queued (or failed) message."""
    from ..services.whatsapp import queue as wa_queue

    row = wa_queue.get_message(message_id)
    if row is None:
        abort(404)
    if not wa_queue.cancel_message(row):
        flash("لا يمكن إلغاء هذه الرسالة في حالتها الحالية.", "error")
        return redirect(url_for("admin.whatsapp_messages"))
    audit(
        "whatsapp_message_cancel",
        "whatsapp_message",
        str(row.id),
        f"إلغاء رسالة واتساب رقم {row.id}",
        {"customer_id": row.customer_id, "event": row.source_event_type},
    )
    db.session.commit()
    flash("تم إلغاء الرسالة.", "warning")
    return redirect(url_for("admin.whatsapp_messages"))


@bp.get("/whatsapp-gateway/webhooks")
@login_required
def whatsapp_webhooks():
    """Recent inbound webhook events (status callbacks + inbound messages)."""
    events = (
        WhatsAppWebhookEvent.query.order_by(
            WhatsAppWebhookEvent.received_at.desc(), WhatsAppWebhookEvent.id.desc()
        )
        .limit(200)
        .all()
    )
    return render_template("admin/whatsapp_webhook_events.html", events=events)


# ── Per-customer WhatsApp control page ──────────────────────────────────────
def _render_customer_whatsapp(customer: Customer):
    from ..services.whatsapp import settings as wa_settings

    now = utcnow()
    account = wa_settings.get_account(customer.id)
    settings_row = wa_settings.get_settings(customer.id)
    templates = wa_settings.list_templates(customer.id)
    usage = wa_settings.get_usage(customer.id, now)
    recent_messages = (
        WhatsAppMessageQueue.query.filter_by(customer_id=customer.id)
        .order_by(WhatsAppMessageQueue.created_at.desc(), WhatsAppMessageQueue.id.desc())
        .limit(15)
        .all()
    )
    webhook_events = (
        WhatsAppWebhookEvent.query.filter_by(customer_id=customer.id)
        .order_by(WhatsAppWebhookEvent.received_at.desc(), WhatsAppWebhookEvent.id.desc())
        .limit(15)
        .all()
    )
    return render_template(
        "admin/customer_whatsapp.html",
        customer=customer,
        account=account,
        account_public=wa_settings.account_public_dict(account),
        settings=settings_row,
        templates=templates,
        usage=usage,
        recent_messages=recent_messages,
        webhook_events=webhook_events,
        plan_codes=_WHATSAPP_PLAN_CODES,
        template_categories=_WHATSAPP_TEMPLATE_CATEGORIES,
        template_statuses=_WHATSAPP_TEMPLATE_STATUSES,
        settings_toggles=_WHATSAPP_SETTINGS_TOGGLES,
    )


@bp.get("/customers/<int:customer_id>/whatsapp")
@login_required
def customer_whatsapp(customer_id: int):
    customer = db.get_or_404(Customer, customer_id)
    return _render_customer_whatsapp(customer)


@bp.post("/customers/<int:customer_id>/whatsapp/credentials")
@login_required
def customer_whatsapp_credentials(customer_id: int):
    """Save Meta connection fields + (write-only) access token."""
    from ..services.whatsapp import settings as wa_settings

    customer = db.get_or_404(Customer, customer_id)
    access_token = (request.form.get("access_token") or "").strip()
    account = wa_settings.upsert_account(
        customer.id,
        meta_business_id=(request.form.get("meta_business_id") or "").strip(),
        whatsapp_business_account_id=(request.form.get("whatsapp_business_account_id") or "").strip(),
        phone_number_id=(request.form.get("phone_number_id") or "").strip(),
        display_phone_number=(request.form.get("display_phone_number") or "").strip(),
        business_display_name=(request.form.get("business_display_name") or "").strip(),
        access_token=access_token or None,
    )
    token_expiry = _dt("token_expires_at")
    if token_expiry is not None:
        account.token_expires_at = token_expiry
        db.session.commit()
    audit(
        "whatsapp_credentials_saved",
        "whatsapp_account",
        str(account.id),
        f"حفظ بيانات ربط واتساب للعميل {customer.company_name}",
        {"customer_id": customer.id, "token_replaced": bool(access_token)},
    )
    db.session.commit()
    flash("تم حفظ بيانات الربط. لا يظهر الـ Token بعد حفظه — يمكنك استبداله فقط.", "success")
    return redirect(url_for("admin.customer_whatsapp", customer_id=customer.id))


@bp.post("/customers/<int:customer_id>/whatsapp/validate")
@login_required
def customer_whatsapp_validate(customer_id: int):
    """Probe the stored credentials against Meta (REAL call) and record state."""
    from ..services.whatsapp import settings as wa_settings
    from ..services.whatsapp.providers import (
        MetaCloudWhatsAppProvider,
        WhatsAppProviderError,
    )

    customer = db.get_or_404(Customer, customer_id)
    account = wa_settings.get_account(customer.id)
    if account is None:
        flash("احفظ بيانات الربط أولًا قبل الفحص.", "error")
        return redirect(url_for("admin.customer_whatsapp", customer_id=customer.id))

    try:
        result = MetaCloudWhatsAppProvider().validate_credentials(account)
    except WhatsAppProviderError as exc:
        wa_settings.set_connection_status(
            customer.id, "error", error_code=exc.code, error_message=exc.message
        )
        account.last_health_check_at = utcnow()
        audit(
            "whatsapp_credentials_validated",
            "whatsapp_account",
            str(account.id),
            f"فشل فحص ربط واتساب للعميل {customer.company_name}",
            {"customer_id": customer.id, "ok": False, "code": exc.code},
        )
        db.session.commit()
        flash(f"فشل الفحص: {exc.message}", "error")
        return redirect(url_for("admin.customer_whatsapp", customer_id=customer.id))

    # Success: refresh display fields + mark connected.
    account.display_phone_number = result.get("display_phone_number") or account.display_phone_number
    account.business_display_name = result.get("business_display_name") or account.business_display_name
    account.quality_rating = result.get("quality_rating") or account.quality_rating
    account.messaging_limit_tier = result.get("messaging_limit_tier") or account.messaging_limit_tier
    account.last_health_check_at = utcnow()
    db.session.commit()
    wa_settings.set_connection_status(customer.id, "connected")
    audit(
        "whatsapp_credentials_validated",
        "whatsapp_account",
        str(account.id),
        f"نجح فحص ربط واتساب للعميل {customer.company_name}",
        {"customer_id": customer.id, "ok": True},
    )
    db.session.commit()
    flash("تم التحقق من بيانات الربط بنجاح والاتصال متصل الآن.", "success")
    return redirect(url_for("admin.customer_whatsapp", customer_id=customer.id))


@bp.post("/customers/<int:customer_id>/whatsapp/settings")
@login_required
def customer_whatsapp_settings(customer_id: int):
    """Save plan + limits + policy toggles (+ apply preset on plan change)."""
    from ..services.whatsapp import settings as wa_settings

    customer = db.get_or_404(Customer, customer_id)
    current = wa_settings.get_settings(customer.id)
    previous_plan = current.plan_code
    plan_code = (request.form.get("plan_code") or previous_plan or "whatsapp_basic").strip()

    fields = {
        "plan_code": plan_code,
        "monthly_message_limit": _int("monthly_message_limit", current.monthly_message_limit or 0),
        "daily_message_limit": _int("daily_message_limit", current.daily_message_limit or 0),
        "per_minute_limit": _int("per_minute_limit", current.per_minute_limit or 0),
        "require_subscriber_opt_in": bool(request.form.get("require_subscriber_opt_in")),
        "quiet_hours_enabled": bool(request.form.get("quiet_hours_enabled")),
        "quiet_hours_start": (request.form.get("quiet_hours_start") or "").strip() or None,
        "quiet_hours_end": (request.form.get("quiet_hours_end") or "").strip() or None,
    }
    for toggle in _WHATSAPP_SETTINGS_TOGGLES:
        fields[toggle] = bool(request.form.get(toggle))

    wa_settings.update_settings(customer.id, **fields)
    if plan_code != previous_plan:
        wa_settings.apply_plan_preset(customer.id, plan_code)
    audit(
        "whatsapp_settings_changed",
        "whatsapp_settings",
        str(current.id),
        f"تحديث إعدادات خدمة واتساب للعميل {customer.company_name}",
        {"customer_id": customer.id, "plan_code": plan_code, "plan_changed": plan_code != previous_plan},
    )
    db.session.commit()
    flash("تم حفظ إعدادات الخدمة.", "success")
    return redirect(url_for("admin.customer_whatsapp", customer_id=customer.id))


@bp.post("/customers/<int:customer_id>/whatsapp/service")
@login_required
def customer_whatsapp_service_toggle(customer_id: int):
    """Enable / disable the WhatsApp service for this customer."""
    from ..services.whatsapp import settings as wa_settings

    customer = db.get_or_404(Customer, customer_id)
    enable = (request.form.get("action") or "").strip() == "enable"
    wa_settings.update_settings(customer.id, enabled=enable)
    audit(
        "whatsapp_service_enabled" if enable else "whatsapp_service_disabled",
        "whatsapp_settings",
        str(customer.id),
        f"{'تفعيل' if enable else 'إيقاف'} خدمة واتساب للعميل {customer.company_name}",
        {"customer_id": customer.id, "enabled": enable},
    )
    db.session.commit()
    flash("تم تفعيل الخدمة." if enable else "تم إيقاف الخدمة.", "success" if enable else "warning")
    return redirect(url_for("admin.customer_whatsapp", customer_id=customer.id))


@bp.post("/customers/<int:customer_id>/whatsapp/account-status")
@login_required
def customer_whatsapp_account_status(customer_id: int):
    """Suspend or re-enable (mark disconnected) the connection."""
    from ..services.whatsapp import settings as wa_settings

    customer = db.get_or_404(Customer, customer_id)
    account = wa_settings.get_account(customer.id)
    if account is None:
        flash("لا يوجد حساب واتساب لهذا العميل بعد.", "error")
        return redirect(url_for("admin.customer_whatsapp", customer_id=customer.id))
    action = (request.form.get("action") or "").strip()
    if action == "suspend":
        wa_settings.set_connection_status(customer.id, "suspended")
        audit(
            "whatsapp_account_suspended",
            "whatsapp_account",
            str(account.id),
            f"إيقاف حساب واتساب للعميل {customer.company_name}",
            {"customer_id": customer.id},
        )
        db.session.commit()
        flash("تم إيقاف الحساب.", "warning")
    else:
        wa_settings.set_connection_status(customer.id, "disconnected")
        audit(
            "whatsapp_account_reactivated",
            "whatsapp_account",
            str(account.id),
            f"إعادة تفعيل حساب واتساب للعميل {customer.company_name}",
            {"customer_id": customer.id},
        )
        db.session.commit()
        flash("تم إعادة تفعيل الحساب. افحص الربط لإعادته إلى حالة متصل.", "success")
    return redirect(url_for("admin.customer_whatsapp", customer_id=customer.id))


@bp.post("/customers/<int:customer_id>/whatsapp/templates")
@login_required
def customer_whatsapp_template_save(customer_id: int):
    """Create/update a template; optionally mark it approved (manual)."""
    from ..services.whatsapp import settings as wa_settings

    customer = db.get_or_404(Customer, customer_id)
    local_key = (request.form.get("local_key") or "").strip()
    if not local_key:
        flash("المفتاح المحلي للقالب مطلوب.", "error")
        return redirect(url_for("admin.customer_whatsapp", customer_id=customer.id))
    language = (request.form.get("language") or "ar").strip() or "ar"
    category = (request.form.get("category") or "UTILITY").strip().upper()
    if category not in _WHATSAPP_TEMPLATE_CATEGORIES:
        category = "UTILITY"
    approve = (request.form.get("action") or "").strip() == "approve"

    template = wa_settings.upsert_template(
        customer.id,
        local_key=local_key,
        provider_template_name=(request.form.get("provider_template_name") or "").strip(),
        language=language,
        category=category,
        body_preview=(request.form.get("body_preview") or "").strip(),
        status="approved" if approve else (request.form.get("status") or None),
    )
    if approve:
        wa_settings.set_template_status(customer.id, local_key, language, "approved")
    audit(
        "whatsapp_template_saved",
        "whatsapp_template",
        str(template.id),
        f"حفظ قالب واتساب {local_key} للعميل {customer.company_name}",
        {"customer_id": customer.id, "local_key": local_key, "approved": approve},
    )
    db.session.commit()
    flash("تم حفظ القالب." + (" وتم اعتماده يدويًا." if approve else ""), "success")
    return redirect(url_for("admin.customer_whatsapp", customer_id=customer.id))


@bp.post("/customers/<int:customer_id>/whatsapp/test")
@login_required
def customer_whatsapp_test(customer_id: int):
    """Send a test message: enqueue via the queue, then best-effort drain once."""
    from ..services.whatsapp import queue as wa_queue
    from ..services.whatsapp import settings as wa_settings
    from ..services.whatsapp import worker as wa_worker
    from ..services.whatsapp.phone import WhatsAppPhoneError, normalize_phone_for_whatsapp

    customer = db.get_or_404(Customer, customer_id)
    recipient = (request.form.get("recipient") or "").strip()
    template_key = (request.form.get("template_key") or "").strip()
    if not recipient:
        flash("أدخل رقم المستلم للتجربة.", "error")
        return redirect(url_for("admin.customer_whatsapp", customer_id=customer.id))
    if not template_key:
        flash("اختر قالبًا معتمدًا لإرسال التجربة.", "error")
        return redirect(url_for("admin.customer_whatsapp", customer_id=customer.id))
    try:
        normalized = normalize_phone_for_whatsapp(recipient)
    except WhatsAppPhoneError as exc:
        flash(str(exc), "error")
        return redirect(url_for("admin.customer_whatsapp", customer_id=customer.id))

    template = wa_settings.get_template(customer.id, template_key, "ar")
    row, created = wa_queue.enqueue(
        customer.id,
        source_system="admin_panel",
        source_event_type="admin_test",
        recipient_phone=recipient,
        normalized_recipient_phone=normalized,
        idempotency_key=f"admin-test:{customer.id}:{template_key}:{normalized}:{int(utcnow().timestamp())}",
        template_key=template_key,
        template_name=(template.provider_template_name if template else None),
        language=(template.language if template else "ar"),
    )
    audit(
        "whatsapp_test_message_enqueued",
        "whatsapp_message",
        str(row.id),
        f"إرسال رسالة تجربة واتساب للعميل {customer.company_name}",
        {"customer_id": customer.id, "template_key": template_key, "created": created},
    )
    db.session.commit()
    try:
        wa_worker.drain_once()
    except Exception:  # noqa: BLE001 — drain is best-effort.
        db.session.rollback()
    flash("تمت جدولة رسالة التجربة وتشغيل التصريف. تابع حالتها في آخر الرسائل.", "success")
    return redirect(url_for("admin.customer_whatsapp", customer_id=customer.id))


# ── Admin Bridge Activation Tokens ───────────────────────────────────────────

@bp.post("/customers/<int:customer_id>/activation-token/generate")
@super_admin_required
def generate_activation_token(customer_id: int):
    """Generate a single-use Admin Bridge activation token for a customer.

    Super-admin only. Returns JSON ``{ok, token, expires_at}`` where ``token``
    is the plaintext activation code in ``XXXXXXXX-XXXXXXXX-XXXXXXXX`` format.
    The plaintext is shown ONCE and is not stored — only its SHA-256 hash is
    persisted in the database.
    """
    from datetime import timezone as _tz

    customer = db.get_or_404(Customer, customer_id)
    admin = current_admin()

    raw_token = InstanceActivationToken.generate()
    token_hash = InstanceActivationToken.hash_code(raw_token)

    now = utcnow()
    expires_at = now + timedelta(minutes=InstanceActivationToken.ACTIVATION_TOKEN_TTL_MINUTES)

    record = InstanceActivationToken(
        customer_id=customer.id,
        token_hash=token_hash,
        expires_at=expires_at,
        created_by_admin_id=(admin.id if admin else None),
    )
    db.session.add(record)
    db.session.flush()  # assign record.id before we reference it

    audit(
        "activation_token_generate", "customer", str(customer.id),
        f"تم إنشاء كود تفعيل Admin Bridge للعميل {customer.company_name} (token_id={record.id})",
        {
            "token_id": record.id,
            "expires_at": expires_at.isoformat(),
            "ttl_minutes": InstanceActivationToken.ACTIVATION_TOKEN_TTL_MINUTES,
        },
    )
    db.session.commit()

    return jsonify({
        "ok": True,
        "token": raw_token,
        "token_id": record.id,
        "expires_at": expires_at.isoformat(),
        "ttl_minutes": InstanceActivationToken.ACTIVATION_TOKEN_TTL_MINUTES,
    })
