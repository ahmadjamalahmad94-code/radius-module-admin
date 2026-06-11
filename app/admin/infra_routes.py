"""بنية CHR المتعددة — مسارات المسؤول (blueprint: admin_infra).

تغطي هذه الوحدة:
- سجل عقد CHR المخصّصة (ChrNode) + مقاييسها
- تسجيل نسخ RADIUS العملاء (CustomerRadiusInstance)
- تخصيصات الخدمة لكل عميل (ServiceAllocation)
- مسارات التوجيه في وكيل RADIUS المركزي (ProxyRealmRoute)

الحماية: كل المسارات تستلزم تسجيل الدخول بالتلقائي عبر login_required.
إنشاء وتعديل ServiceAllocation يتطلّب صلاحية super_admin لأنها قرارات تجارية.
"""
from __future__ import annotations

from datetime import datetime, timezone

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for
from sqlalchemy import func

from ..auth.routes import audit, current_admin, login_required, super_admin_required
from ..extensions import db
from ..models import (
    ChrNode,
    ChrNodeMetric,
    Customer,
    CustomerRadiusInstance,
    ProxyRealmRoute,
    SERVICE_TYPE_CHOICES,
    ServiceAllocation,
    ServiceUsageSnapshot,
    utcnow,
)
from ..services.chr_metrics import collect_all_nodes as _collect_all_nodes, is_stale as _is_stale

bp = Blueprint("admin_infra", __name__, url_prefix="/admin/infra")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _int(val, default=None):
    try:
        return int(str(val).strip())
    except (TypeError, ValueError):
        return default


def _str(val, max_len=255) -> str:
    return (str(val or "").strip())[:max_len]


def _parse_dt(val: str) -> datetime | None:
    val = (val or "").strip()
    if not val:
        return None
    for fmt in ("%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(val, fmt)
        except ValueError:
            continue
    return None


def _reserved_mbps(node: ChrNode) -> int:
    """Sum of speed_limit_mbps for active/pending allocations on this node."""
    result = db.session.query(
        func.coalesce(func.sum(ServiceAllocation.speed_limit_mbps), 0)
    ).filter(
        ServiceAllocation.chr_node_id == node.id,
        ServiceAllocation.status.in_(["active", "pending"]),
    ).scalar()
    return int(result or 0)


def _capacity_badge(reserved: int, max_reserved: int) -> str:
    if max_reserved <= 0:
        return "unknown"
    pct = reserved / max_reserved * 100
    if pct >= 85:
        return "full"
    if pct >= 70:
        return "warning"
    return "ok"


def _usage_health(used: int, max_val: int) -> str:
    """سياسة السعة الموحّدة: <70% ok، 70-85% warning، >85% critical."""
    if max_val <= 0:
        return "ok"
    pct = used / max_val * 100
    if pct >= 85:
        return "critical"
    if pct >= 70:
        return "warning"
    return "ok"


def _latest_snapshot(alloc_id: int) -> ServiceUsageSnapshot | None:
    return (
        ServiceUsageSnapshot.query
        .filter_by(service_allocation_id=alloc_id)
        .order_by(ServiceUsageSnapshot.measured_at.desc())
        .first()
    )


def _encrypt_node_password(raw: str) -> str:
    """يشفّر كلمة مرور RouterOS للعقدة (Fernet). يُعيد '' عند فشل التشفير."""
    try:
        from ..services.customer_vault_crypto import encrypt_secret, encryption_available
        if not encryption_available():
            return ""
        return encrypt_secret(raw)
    except Exception:
        return ""


# ──────────────────────────────────────────────────────────────────────────────
# CHR Nodes
# ──────────────────────────────────────────────────────────────────────────────

@bp.get("/chr-nodes")
@login_required
def chr_nodes_list():
    nodes = ChrNode.query.order_by(ChrNode.status, ChrNode.name).all()
    node_stats = []
    for n in nodes:
        reserved = _reserved_mbps(n)
        node_stats.append({
            "node": n,
            "reserved_mbps": reserved,
            "available_mbps": max(0, n.max_reserved_mbps - reserved),
            "capacity_badge": _capacity_badge(reserved, n.max_reserved_mbps),
            "active_allocs": ServiceAllocation.query.filter_by(
                chr_node_id=n.id, status="active"
            ).count(),
            "is_stale": _is_stale(n),
        })
    return render_template(
        "admin/infra/chr_nodes_new.html",
        node_stats=node_stats,
        service_choices=SERVICE_TYPE_CHOICES,
    )


@bp.post("/chr-nodes/create")
@super_admin_required
def chr_node_create():
    """Retired — node creation moved to the fleet onboarding wizard.

    The handler is preserved (kept registered) so any tab the operator still
    has open POSTs to a friendly redirect instead of a 404. The legacy table
    is read-only from now on; step 5 (legacy→fleet migration) is the right
    way to bring existing nodes into the fleet, and step 6 drops the table.
    """
    flash(
        "إنشاء عقدة CHR من هذه الصفحة أُلغي. أضف العقد الجديدة من «معالج إضافة CHR».",
        "warning",
    )
    return redirect(url_for("fleet_ui.onboarding_wizard"))


@bp.get("/chr-nodes/<int:node_id>")
@login_required
def chr_node_detail(node_id: int):
    node = ChrNode.query.get_or_404(node_id)
    reserved = _reserved_mbps(node)
    recent_metrics = (
        ChrNodeMetric.query
        .filter_by(chr_node_id=node_id)
        .order_by(ChrNodeMetric.measured_at.desc())
        .limit(24)
        .all()
    )
    allocations = (
        ServiceAllocation.query
        .filter_by(chr_node_id=node_id)
        .order_by(ServiceAllocation.status, ServiceAllocation.created_at.desc())
        .all()
    )
    # Live-health derivation — the detail page was reading telemetry into the
    # metrics LOG but the header still showed the raw lifecycle field
    # (``status='pending'``) even while fresh CPU/RAM/session samples were
    # arriving, which read as "connected here, not there". Surface the latest
    # sample + a single ``is_live`` flag (fresh telemetry) so the UI can show
    # an accurate live state alongside the (separate) registration lifecycle.
    stale = _is_stale(node)
    latest_metric = recent_metrics[0] if recent_metrics else None
    is_live = bool(latest_metric) and not stale
    return render_template(
        "admin/infra/chr_detail_new.html",
        node=node,
        reserved_mbps=reserved,
        available_mbps=max(0, node.max_reserved_mbps - reserved),
        capacity_badge=_capacity_badge(reserved, node.max_reserved_mbps),
        recent_metrics=recent_metrics,
        latest_metric=latest_metric,
        is_live=is_live,
        active_alloc_count=sum(1 for a in allocations if a.status == "active"),
        allocations=allocations,
        service_choices=SERVICE_TYPE_CHOICES,
        stale=stale,
    )


@bp.post("/chr-nodes/<int:node_id>/edit")
@super_admin_required
def chr_node_edit(node_id: int):
    """Retired — edit lifecycle moved to the fleet registry API.

    See ``chr_node_create`` docstring for the rationale. Operators editing
    a still-shown legacy row should run the migration (step 5) to move the
    node into the fleet, where it can be edited normally.
    """
    # Make sure the id resolves so we 404 on garbage IDs rather than silently
    # redirecting. This keeps audit/intrusion logs meaningful.
    ChrNode.query.get_or_404(node_id)
    flash(
        "تعديل عقد CHR من هذه الصفحة أُلغي. شغّل الترحيل إلى الأسطول ثم عدّلها من «لوحة الأسطول».",
        "warning",
    )
    return redirect(url_for("fleet_ui.fleet_dashboard"))


@bp.post("/chr-nodes/<int:node_id>/poll")
@super_admin_required
def chr_node_poll(node_id: int):
    """Retired — the fleet metrics-poller writes telemetry every cycle."""
    ChrNode.query.get_or_404(node_id)
    flash(
        "الاستطلاع اليدوي لم يعد ضروريًا — جامع مقاييس الأسطول يعمل في الخلفية.",
        "info",
    )
    return redirect(url_for("fleet_ui.fleet_dashboard"))


@bp.post("/chr-nodes/poll-all")
@super_admin_required
def chr_nodes_poll_all():
    """Retired — fleet metrics-poller covers this in the background."""
    flash(
        "الاستطلاع اليدوي لم يعد ضروريًا — جامع مقاييس الأسطول يعمل في الخلفية.",
        "info",
    )
    return redirect(url_for("fleet_ui.fleet_dashboard"))


# ──────────────────────────────────────────────────────────────────────────────
# Customer RADIUS Instances
# ──────────────────────────────────────────────────────────────────────────────

@bp.get("/radius-instances")
@login_required
def radius_instances_list():
    instances = (
        CustomerRadiusInstance.query
        .join(Customer)
        .order_by(CustomerRadiusInstance.status, Customer.company_name)
        .all()
    )
    return render_template("admin/infra/radius_instances.html", instances=instances)


@bp.get("/radius-instances/customer/<int:customer_id>")
@login_required
def radius_instance_for_customer(customer_id: int):
    customer = Customer.query.get_or_404(customer_id)
    instance = CustomerRadiusInstance.query.filter_by(customer_id=customer_id).first()
    return render_template(
        "admin/infra/radius_instance_form.html",
        customer=customer,
        instance=instance,
    )


@bp.post("/radius-instances/customer/<int:customer_id>/save")
@super_admin_required
def radius_instance_save(customer_id: int):
    customer = Customer.query.get_or_404(customer_id)
    instance = CustomerRadiusInstance.query.filter_by(customer_id=customer_id).first()
    realm = _str(request.form.get("realm"), 80).lower()
    if not realm:
        flash("الـ Realm مطلوب.", "error")
        return redirect(url_for("admin_infra.radius_instance_for_customer", customer_id=customer_id))
    # Uniqueness check on realm (skip self)
    existing = CustomerRadiusInstance.query.filter_by(realm=realm).first()
    if existing and existing.customer_id != customer_id:
        flash(f"الـ Realm «{realm}» مستخدم لعميل آخر.", "error")
        return redirect(url_for("admin_infra.radius_instance_for_customer", customer_id=customer_id))

    if instance is None:
        instance = CustomerRadiusInstance(customer_id=customer_id)
        db.session.add(instance)

    instance.instance_name = _str(request.form.get("instance_name"), 80)
    instance.mgmt_wg_ip = _str(request.form.get("mgmt_wg_ip"), 64)
    instance.radius_auth_ip = _str(request.form.get("radius_auth_ip"), 64)
    instance.radius_auth_port = _int(request.form.get("radius_auth_port"), 1812)
    instance.radius_acct_port = _int(request.form.get("radius_acct_port"), 1813)
    instance.realm = realm
    instance.secret_vault_ref = _str(request.form.get("secret_vault_ref"), 120)
    instance.status = _str(request.form.get("status"), 20) or "unknown"
    instance.notes = _str(request.form.get("notes"), 1000)

    db.session.flush()
    audit(
        "radius_instance_save", "customer_radius_instance", instance.id,
        f"حفظ RADIUS Instance للعميل {customer.company_name} (realm: {realm})", {},
    )
    db.session.commit()
    flash("تم حفظ RADIUS Instance.", "success")
    return redirect(url_for("admin_infra.radius_instance_for_customer", customer_id=customer_id))


# ──────────────────────────────────────────────────────────────────────────────
# Service Allocations
# ──────────────────────────────────────────────────────────────────────────────

@bp.get("/service-allocations")
@login_required
def service_allocations_list():
    allocations = (
        ServiceAllocation.query
        .join(Customer)
        .order_by(ServiceAllocation.status, Customer.company_name)
        .all()
    )
    return render_template(
        "admin/infra/service_allocations.html",
        allocations=allocations,
        service_choices=SERVICE_TYPE_CHOICES,
    )


@bp.get("/service-allocations/customer/<int:customer_id>")
@login_required
def customer_service_allocations(customer_id: int):
    customer = Customer.query.get_or_404(customer_id)
    allocations = (
        ServiceAllocation.query
        .filter_by(customer_id=customer_id)
        .order_by(ServiceAllocation.status, ServiceAllocation.created_at.desc())
        .all()
    )
    chr_nodes = ChrNode.query.filter_by(status="active").order_by(ChrNode.name).all()
    node_stats = {
        n.id: {
            "reserved": _reserved_mbps(n),
            "badge": _capacity_badge(_reserved_mbps(n), n.max_reserved_mbps),
        }
        for n in chr_nodes
    }
    radius_instance = CustomerRadiusInstance.query.filter_by(customer_id=customer_id).first()

    # آخر usage snapshot لكل تخصيص (للـ capacity bars)
    latest_snapshots = {a.id: _latest_snapshot(a.id) for a in allocations}

    return render_template(
        "admin/infra/customer_service_allocations.html",
        customer=customer,
        allocations=allocations,
        chr_nodes=chr_nodes,
        node_stats=node_stats,
        radius_instance=radius_instance,
        service_choices=SERVICE_TYPE_CHOICES,
        latest_snapshots=latest_snapshots,
        usage_health=_usage_health,
    )


@bp.post("/service-allocations/customer/<int:customer_id>/create")
@super_admin_required
def service_allocation_create(customer_id: int):
    customer = Customer.query.get_or_404(customer_id)
    service_type = _str(request.form.get("service_type"), 30)
    if service_type not in SERVICE_TYPE_CHOICES:
        flash("نوع الخدمة غير صالح.", "error")
        return redirect(url_for("admin_infra.customer_service_allocations", customer_id=customer_id))

    chr_node_id = _int(request.form.get("chr_node_id"))
    # wireguard_data may run on customer VPS (no CHR)
    if service_type != "wireguard_data" and not chr_node_id:
        flash("لازم تختار عقدة CHR لهذه الخدمة.", "error")
        return redirect(url_for("admin_infra.customer_service_allocations", customer_id=customer_id))

    if chr_node_id:
        node = ChrNode.query.get(chr_node_id)
        if not node:
            flash("عقدة CHR غير موجودة.", "error")
            return redirect(url_for("admin_infra.customer_service_allocations", customer_id=customer_id))
        reserved = _reserved_mbps(node)
        speed = _int(request.form.get("speed_limit_mbps"), 0) or 0
        if reserved + speed > node.max_reserved_mbps:
            flash(
                f"السرعة المطلوبة ({speed} Mbps) تتجاوز السعة المتاحة "
                f"على {node.name} ({node.max_reserved_mbps - reserved} Mbps متبقية).",
                "error",
            )
            return redirect(url_for("admin_infra.customer_service_allocations", customer_id=customer_id))

    radius_instance = CustomerRadiusInstance.query.filter_by(customer_id=customer_id).first()
    alloc = ServiceAllocation(
        customer_id=customer_id,
        radius_instance_id=radius_instance.id if radius_instance else None,
        service_type=service_type,
        status="pending",
        chr_node_id=chr_node_id,
        speed_limit_mbps=_int(request.form.get("speed_limit_mbps"), 0) or 0,
        transfer_limit_bytes=_int(request.form.get("transfer_limit_gb")) and
                              (_int(request.form.get("transfer_limit_gb")) * 1024 ** 3),
        max_accounts=_int(request.form.get("max_accounts"), 0) or 0,
        max_peers=_int(request.form.get("max_peers"), 0) or 0,
        starts_at=_parse_dt(request.form.get("starts_at")),
        expires_at=_parse_dt(request.form.get("expires_at")),
        commercial_notes=_str(request.form.get("commercial_notes"), 2000),
        created_by_admin_id=current_admin().id if current_admin() else None,
    )
    db.session.add(alloc)
    db.session.flush()
    audit(
        "service_allocation_create", "service_allocation", alloc.id,
        f"إنشاء تخصيص {service_type} للعميل {customer.company_name}",
        {"service_type": service_type, "chr_node_id": chr_node_id},
    )
    db.session.commit()
    flash(f"تم إنشاء تخصيص {alloc.service_label_ar} بنجاح.", "success")
    return redirect(url_for("admin_infra.customer_service_allocations", customer_id=customer_id))


@bp.post("/service-allocations/<int:alloc_id>/status")
@super_admin_required
def service_allocation_set_status(alloc_id: int):
    alloc = ServiceAllocation.query.get_or_404(alloc_id)
    new_status = _str(request.form.get("status"), 20)
    valid = {"pending", "active", "suspended", "expired", "cancelled"}
    if new_status not in valid:
        flash("حالة غير صالحة.", "error")
        return redirect(url_for("admin_infra.customer_service_allocations", customer_id=alloc.customer_id))
    old_status = alloc.status
    alloc.status = new_status
    audit(
        "service_allocation_status", "service_allocation", alloc.id,
        f"تغيير حالة التخصيص من {old_status} إلى {new_status}",
        {"old": old_status, "new": new_status},
    )
    db.session.commit()
    flash(f"تم تغيير حالة الخدمة إلى «{new_status}».", "success")
    return redirect(url_for("admin_infra.customer_service_allocations", customer_id=alloc.customer_id))


@bp.post("/service-allocations/<int:alloc_id>/edit")
@super_admin_required
def service_allocation_edit(alloc_id: int):
    alloc = ServiceAllocation.query.get_or_404(alloc_id)
    alloc.speed_limit_mbps = _int(request.form.get("speed_limit_mbps"), alloc.speed_limit_mbps)
    alloc.max_accounts = _int(request.form.get("max_accounts"), alloc.max_accounts)
    alloc.max_peers = _int(request.form.get("max_peers"), alloc.max_peers)
    alloc.transfer_limit_bytes = (
        _int(request.form.get("transfer_limit_gb")) * 1024 ** 3
        if _int(request.form.get("transfer_limit_gb"))
        else None
    )
    alloc.expires_at = _parse_dt(request.form.get("expires_at"))
    alloc.commercial_notes = _str(request.form.get("commercial_notes"), 2000)
    audit(
        "service_allocation_edit", "service_allocation", alloc.id,
        f"تعديل تخصيص {alloc.service_type} للعميل #{alloc.customer_id}", {},
    )
    db.session.commit()
    flash("تم حفظ التعديلات.", "success")
    return redirect(url_for("admin_infra.customer_service_allocations", customer_id=alloc.customer_id))



# ──────────────────────────────────────────────────────────────────────────────
# Proxy Realm Routes
# ──────────────────────────────────────────────────────────────────────────────

@bp.get("/proxy-routes")
@login_required
def proxy_routes_list():
    """List proxy-realm routes + render the create modal.

    The modal exposes BOTH CHR sources side by side: the legacy
    CHR-console table (``app.models.ChrNode``) and the fleet registry
    (``fleet.registry.models_chr.FleetChrNode``, populated by the
    onboarding wizard). Prior to this fix the modal only listed legacy
    nodes — a fleet CHR onboarded via the wizard was invisible, which
    is why the live deployment debug needed manual SQL on
    ``allowed_chr_node_ids_json``.
    """
    routes = (
        ProxyRealmRoute.query
        .join(Customer)
        .order_by(ProxyRealmRoute.status, ProxyRealmRoute.realm)
        .all()
    )
    chr_nodes = ChrNode.query.filter_by(status="active").order_by(ChrNode.name).all()
    fleet_chr_nodes = []
    try:
        from fleet.registry.models_chr import FleetChrNode  # noqa: WPS433
        fleet_chr_nodes = (
            FleetChrNode.query
            .filter(FleetChrNode.enabled.is_(True))
            .filter(FleetChrNode.status.notin_(("disabled",)))
            .order_by(FleetChrNode.name.asc())
            .all()
        )
    except Exception as exc:  # noqa: BLE001 — defensive
        current_app.logger.warning(
            "proxy_routes_list: fleet_chr_nodes load failed (%s); skipping fleet source",
            exc.__class__.__name__,
        )
    customers_without_instance = (
        Customer.query
        .outerjoin(CustomerRadiusInstance, CustomerRadiusInstance.customer_id == Customer.id)
        .filter(CustomerRadiusInstance.id.is_(None))
        .order_by(Customer.company_name)
        .all()
    )
    instances = CustomerRadiusInstance.query.order_by(CustomerRadiusInstance.realm).all()
    return render_template(
        "admin/infra/proxy_routes_new.html",
        routes=routes,
        chr_nodes=chr_nodes,
        fleet_chr_nodes=fleet_chr_nodes,
        instances=instances,
        customers_without_instance=customers_without_instance,
    )


# Accepted status values for the create form. Default is ``active`` so
# the create-and-activate flow is one click (operators were having to
# create as "draft" then POST status=active separately — that two-step
# is what the live debug ran into; the routing-table query filters by
# status=active, so a freshly-created "draft" route published zero realms).
_PROXY_ROUTE_STATUSES = {"active", "suspended", "draft"}


@bp.post("/proxy-routes/create")
@super_admin_required
def proxy_route_create():
    realm = _str(request.form.get("realm"), 80).lower()
    radius_instance_id = _int(request.form.get("radius_instance_id"))
    if not realm or not radius_instance_id:
        flash("الـ Realm ونسخة RADIUS مطلوبان.", "error")
        return redirect(url_for("admin_infra.proxy_routes_list"))
    if ProxyRealmRoute.query.filter_by(realm=realm).first():
        flash(f"مسار الـ Realm \u00ab{realm}\u00bb موجود مسبقًا.", "error")
        return redirect(url_for("admin_infra.proxy_routes_list"))
    instance = CustomerRadiusInstance.query.get_or_404(radius_instance_id)
    # Two separate allow-lists \u2014 legacy and fleet \u2014 because the two
    # tables have independent autoincrement sequences and their ids
    # would otherwise collide. routing-table queries union both at
    # resolve time.
    allowed_node_ids = [_int(x) for x in request.form.getlist("allowed_chr_node_ids") if _int(x)]
    allowed_fleet_node_ids = [_int(x) for x in request.form.getlist("allowed_fleet_chr_node_ids") if _int(x)]
    raw_status = _str(request.form.get("status"), 20) or "active"
    status = raw_status if raw_status in _PROXY_ROUTE_STATUSES else "active"
    route = ProxyRealmRoute(
        realm=realm,
        customer_id=instance.customer_id,
        radius_instance_id=radius_instance_id,
        target_radius_ip=_str(request.form.get("target_radius_ip"), 64) or instance.radius_auth_ip,
        target_auth_port=_int(request.form.get("target_auth_port"), 1812),
        target_acct_port=_int(request.form.get("target_acct_port"), 1813),
        secret_vault_ref=_str(request.form.get("secret_vault_ref"), 120),
        status=status,
    )
    route.allowed_chr_node_ids = allowed_node_ids
    route.allowed_fleet_chr_node_ids = allowed_fleet_node_ids
    db.session.add(route)
    db.session.flush()
    audit(
        "proxy_route_create", "proxy_realm_route", route.id,
        f"\u0625\u0646\u0634\u0627\u0621 \u0645\u0633\u0627\u0631 Proxy \u0644\u0644\u0640 Realm: {realm}",
        {
            "status": status,
            "allowed_legacy_chr_ids": allowed_node_ids,
            "allowed_fleet_chr_ids": allowed_fleet_node_ids,
        },
    )
    db.session.commit()
    flash(
        f"\u062a\u0645 \u0625\u0646\u0634\u0627\u0621 \u0645\u0633\u0627\u0631 Realm \u00ab{realm}\u00bb"
        + (" \u0648\u062a\u0641\u0639\u064a\u0644\u0647." if status == "active" else f" \u0628\u062d\u0627\u0644\u0629 {status}."),
        "success",
    )
    return redirect(url_for("admin_infra.proxy_routes_list"))


@bp.post("/proxy-routes/<int:route_id>/status")
@super_admin_required
def proxy_route_set_status(route_id: int):
    route = ProxyRealmRoute.query.get_or_404(route_id)
    new_status = _str(request.form.get("status"), 20)
    if new_status not in {"active", "suspended", "draft"}:
        flash("\u062d\u0627\u0644\u0629 \u063a\u064a\u0631 \u0635\u0627\u0644\u062d\u0629.", "error")
        return redirect(url_for("admin_infra.proxy_routes_list"))
    route.status = new_status
    audit("proxy_route_status", "proxy_realm_route", route.id, f"\u062a\u063a\u064a\u064a\u0631 \u062d\u0627\u0644\u0629 \u0645\u0633\u0627\u0631 {route.realm} \u0625\u0644\u0649 {new_status}", {})
    db.session.commit()
    flash("\u062a\u0645 \u062a\u062d\u062f\u064a\u062b \u0627\u0644\u062d\u0627\u0644\u0629.", "success")
    return redirect(url_for("admin_infra.proxy_routes_list"))

# ──────────────────────────────────────────────────────────────────────────────
# Macros / Scripts Library
# ──────────────────────────────────────────────────────────────────────────────

_BUILTIN_MACROS = [
    {"name": "PPPoE Server Setup", "description": "إعداد PPPoE Server على عقدة CHR بالخطوات الأساسية", "category": "vpn", "code": "# PPPoE Server\n/interface pppoe-server server add service-name=pppoe interface=ether1 authentication=pap chap mschapv1 mschapv2"},
    {"name": "Firewall Basic Rules", "description": "قواعد جدار حماية أساسية لحماية الشبكة", "category": "firewall", "code": "# Basic Firewall\n/ip firewall filter add chain=input action=accept connection-state=established,related"},
    {"name": "RADIUS Client Config", "description": "ضبط عميل RADIUS للمصادقة مع الخادم المركزي", "category": "routing", "code": "# RADIUS Client\n/radius add service=ppp,login address=<server-ip> secret=<secret>"},
    {"name": "CPU & Memory Monitor", "description": "سكربت مراقبة استخدام المعالج والذاكرة وإرسال تنبيه عند تجاوز الحد", "category": "monitoring", "code": "# Monitor\n:local cpu [/system resource get cpu-load]\n:if ($cpu > 80) do={:log warning (\"High CPU: \" . $cpu . \"%\")}"},
    {"name": "User Profile Sync", "description": "مزامنة بروفايلات المستخدمين بين RouterOS و RADIUS", "category": "users", "code": "# User Sync\n/ppp secret print terse"},
    {"name": "Config Backup Script", "description": "أخذ نسخة احتياطية من إعدادات RouterOS وحفظها محلياً", "category": "backup", "code": "# Backup\n/system backup save name=backup-auto\n/export file=config-export"},
]


@bp.get("/macros")
@login_required
def macros_list():
    macro_categories = sorted({m["category"] for m in _BUILTIN_MACROS})
    return render_template(
        "admin/infra/macros_new.html",
        macros=_BUILTIN_MACROS,
        macro_categories=macro_categories,
    )


# ──────────────────────────────────────────────────────────────────────────────
# System Health Dashboard  (logs/health_new.html)
# ──────────────────────────────────────────────────────────────────────────────

def _health_cls(pct: float) -> str:
    if pct >= 85:
        return "error"
    if pct >= 70:
        return "warn"
    return "ok"


@bp.get("/system-health")
@login_required
def system_health():
    """Render «صحة الخدمات» — host CPU/RAM/Disk + DB/Proxy/WhatsApp + fleet poller.

    The template (`admin/logs/health_new.html`) consumes EVERYTHING through a
    single nested ``health`` dict — ``health.resources.cpu_pct``,
    ``health.server.uptime``, ``health.database.response_ms`` etc. The view
    must therefore build that nested shape; passing the same values as flat
    kwargs (the previous behavior) gets silently shadowed by the template's
    ``{% set %}`` rebinding, which is why this page used to render 0% / «—»
    everywhere even on a healthy host.
    """
    import os
    import time as _time
    now = _utcnow()

    # ── Host resources via psutil (fall back to /proc + statvfs when missing) ──
    cpu_pct: float = 0.0
    mem_pct: float = 0.0
    disk_pct: float = 0.0
    cpu_cores = "—"
    load_avg = "—"
    mem_used_mb = "—"
    mem_total_mb = "—"
    disk_used_gb = "—"
    disk_total_gb = "—"
    disk_free_gb = "—"
    disk_path = "/"
    try:
        import psutil
        cpu_pct = psutil.cpu_percent(interval=0.1)
        try:
            cpu_cores = psutil.cpu_count(logical=True) or "—"
        except Exception:
            pass
        try:
            la = psutil.getloadavg()
            load_avg = f"{la[0]:.2f} / {la[1]:.2f} / {la[2]:.2f}"
        except Exception:
            pass
        vm = psutil.virtual_memory()
        mem_pct = vm.percent
        mem_used_mb = round((vm.total - vm.available) / (1024 * 1024))
        mem_total_mb = round(vm.total / (1024 * 1024))
        # On Windows the root is the system drive ("C:\\"); psutil accepts it.
        probe_path = os.path.abspath(os.sep)
        du = psutil.disk_usage(probe_path)
        disk_pct = du.percent
        disk_used_gb = round(du.used / (1024 ** 3), 1)
        disk_total_gb = round(du.total / (1024 ** 3), 1)
        disk_free_gb = round(du.free / (1024 ** 3), 1)
        disk_path = probe_path
    except Exception:
        # psutil missing — fall through to the stdlib-only probes so the page
        # still shows something useful on hosts where psutil isn't installed.
        try:
            la = os.getloadavg()
            load_avg = f"{la[0]:.2f} / {la[1]:.2f} / {la[2]:.2f}"
            # Approximate CPU% from 1-min load avg / core count when psutil
            # isn't available. Not perfect but better than a hard 0.
            try:
                cores = os.cpu_count() or 1
                cpu_cores = cores
                cpu_pct = min(100.0, round(la[0] / cores * 100.0, 1))
            except Exception:
                pass
        except (AttributeError, OSError):
            pass
        try:
            with open("/proc/meminfo") as fh:
                lines = {k.strip(): v.strip() for k, v in (ln.split(":", 1) for ln in fh if ":" in ln)}
            total_kb = int(lines.get("MemTotal", "1 kB").split()[0]) or 1
            avail_kb = int(lines.get("MemAvailable", "1 kB").split()[0])
            mem_pct = round((1 - avail_kb / total_kb) * 100, 1)
            mem_total_mb = round(total_kb / 1024)
            mem_used_mb = round((total_kb - avail_kb) / 1024)
        except Exception:
            pass
        try:
            # shutil.disk_usage is stdlib + cross-platform (Linux + Windows).
            import shutil
            probe_path = os.path.abspath(os.sep)
            usage = shutil.disk_usage(probe_path)
            disk_pct = round(usage.used / usage.total * 100, 1) if usage.total else 0.0
            disk_total_gb = round(usage.total / (1024 ** 3), 1)
            disk_free_gb = round(usage.free / (1024 ** 3), 1)
            disk_used_gb = round(usage.used / (1024 ** 3), 1)
            disk_path = probe_path
        except Exception:
            pass

    # ── DB ping ──
    db_ok = False
    db_ms = 0.0
    try:
        t0 = _time.monotonic()
        from ..extensions import db as _db
        _db.session.execute(_db.text("SELECT 1"))
        db_ms = round((_time.monotonic() - t0) * 1000, 1)
        db_ok = True
    except Exception:
        pass

    # ── WhatsApp accounts (best-effort) ──
    try:
        from ..models import WhatsAppAccount
        wa_total = WhatsAppAccount.query.count()
        wa_conn = WhatsAppAccount.query.filter_by(status="active").count()
    except Exception:
        wa_total = 0
        wa_conn = 0

    # ── Fleet metrics-poller liveness — last write to fleet_chr_metrics.
    # We treat a write within the last 5 minutes as "healthy" (matches the
    # poller's 60s default cadence with generous slack). Missing tables on
    # fresh installs degrade silently to "unknown".
    poller_last_at = None
    poller_status = "unknown"
    poller_age_s: int | str = "—"
    try:
        from fleet.health.models_health import FleetChrMetric
        poller_last_at = (
            db.session.query(db.func.max(FleetChrMetric.ts)).scalar()
        )
        if poller_last_at is not None:
            poller_age_s = max(0, int((now - poller_last_at).total_seconds()))
            poller_status = "ok" if poller_age_s <= 300 else ("warn" if poller_age_s <= 900 else "error")
    except Exception:
        pass

    # ── Recent errors — adapt AuditLog rows to the template's `err.*` keys. ──
    from ..models import AuditLog
    audit_rows = (
        AuditLog.query
        .filter(AuditLog.action.ilike("%error%") | AuditLog.action.ilike("%fail%"))
        .order_by(AuditLog.created_at.desc())
        .limit(10)
        .all()
    )
    recent_errors = [
        {
            "message": (row.summary or row.action or "—"),
            "occurred_at": row.created_at,
            "service": (row.entity_type or ""),
            "code": (row.action or ""),
        }
        for row in audit_rows
    ]

    proxy_routes_active = ProxyRealmRoute.query.filter_by(status="active").count()
    # Pre-compute server-side health classes so the template's *_cls kwargs
    # stay populated (the template reads them via {% set %}-defaults too,
    # but having them here keeps the toggle deterministic across all renders).
    server_status = "ok"
    db_status = "ok" if db_ok else "error"
    px_status = "ok" if proxy_routes_active >= 0 else "warn"
    wa_status = "ok" if wa_conn > 0 else "warn"

    health = {
        "status": "ok",
        "resources": {
            "cpu_pct": round(cpu_pct, 1),
            "mem_pct": round(mem_pct, 1),
            "disk_pct": round(disk_pct, 1),
            "cpu_cores": cpu_cores,
            "load_avg": load_avg,
            "mem_used_mb": mem_used_mb,
            "mem_total_mb": mem_total_mb,
            "disk_used_gb": disk_used_gb,
            "disk_total_gb": disk_total_gb,
            "disk_free_gb": disk_free_gb,
            "disk_path": disk_path,
        },
        "server": {
            "status": server_status,
            "uptime": "—",
            "requests_per_min": "—",
            "version": current_app.config.get("APP_VERSION", "—"),
            "workers": "—",
            # Fleet metrics-poller liveness, surfaced inside the server card.
            "poller_status": poller_status,
            "poller_last_at": poller_last_at,
            "poller_age_s": poller_age_s,
        },
        "database": {
            "status": db_status,
            "response_ms": db_ms,
            "connections": "—",
            "size_mb": "—",
            "queries_per_min": "—",
            "ok": db_ok,
        },
        "proxy": {
            "status": px_status,
            "active_routes": proxy_routes_active,
            "auth_reqs_min": "—",
            "acct_reqs_min": "—",
            "reject_rate_pct": "—",
        },
        "whatsapp": {
            "status": wa_status,
            "msgs_today": "—",
            "delivered_pct": "—",
            "failed_today": "—",
            "phone_display": f"{wa_conn}/{wa_total} متصل",
        },
    }

    return render_template(
        "admin/logs/health_new.html",
        now=now,
        # Top-level *_cls kwargs are preserved for backward-compat — newer
        # template revisions read them from `health.<block>.status` via {% set %}
        # but the legacy chrome still references them in a few places.
        cpu_cls=_health_cls(cpu_pct),
        mem_cls=_health_cls(mem_pct),
        disk_cls=_health_cls(disk_pct),
        sv_cls=server_status,
        db_cls=db_status,
        px_cls=px_status,
        wa_cls=wa_status,
        health=health,
        # Pre-rendered keys the template still expects flat (charts / errors).
        pts_arr=[],
        mpts=[],
        recent_errors=recent_errors,
        err=None,
    )


# ════════════════════════════════════════════════════════════════════════════
# Legacy → Fleet consolidation (step 5 of docs/CONSOLIDATION.md)
#
# UI-runnable, idempotent migration. The page lets the owner preview the move
# (dry-run) and then execute it — no terminal, no SQL. All endpoints are
# super_admin only; results are audited.
# ════════════════════════════════════════════════════════════════════════════
@bp.get("/consolidation")
@super_admin_required
def consolidation_page():
    """Preview + run the legacy chr_nodes → fleet_chr_nodes migration."""
    from ..services.fleet_consolidation import (
        fleet_tables_available,
        legacy_chr_node_id_column_present,
        plan_migration,
    )
    legacy_count = ChrNode.query.count()
    if not fleet_tables_available():
        plan = None
        error = "fleet_schema_not_ready"
    elif not legacy_chr_node_id_column_present():
        plan = None
        error = "schema_heal_pending"
    else:
        plan = plan_migration()
        error = plan.error
    return render_template(
        "admin/infra/consolidation.html",
        legacy_count=legacy_count,
        plan=plan,
        error=error,
    )


@bp.post("/consolidation/run")
@super_admin_required
def consolidation_run():
    """Execute the migration for real. Idempotent — safe to click twice."""
    from ..services.fleet_consolidation import run_migration, to_jsonable
    result = run_migration(dry_run=False)
    payload = to_jsonable(result)
    audit(
        "fleet_consolidation_run",
        "chr_node",
        0,
        f"ترحيل {result.imported} عقدة CHR قديمة إلى الأسطول "
        f"(تم سابقًا: {result.skipped_existing}، متعذّر: {result.skipped_invalid}، "
        f"تخصيصات أُعيد توجيهها: {result.allocations_rewritten}).",
        payload,
    )
    db.session.commit()
    if result.error:
        flash(f"تعذّر إكمال الترحيل: {result.error}", "error")
    else:
        flash(
            f"تم الترحيل: استيراد {result.imported}، تم سابقًا {result.skipped_existing}، "
            f"تخطٍّ {result.skipped_invalid}، تخصيصات أُعيد توجيهها {result.allocations_rewritten}.",
            "success" if result.imported or result.allocations_rewritten else "info",
        )
    return redirect(url_for("admin_infra.consolidation_page"))
