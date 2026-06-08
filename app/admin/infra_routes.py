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

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
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
        "admin/infra/chr_nodes.html",
        node_stats=node_stats,
        service_choices=SERVICE_TYPE_CHOICES,
    )


@bp.post("/chr-nodes/create")
@super_admin_required
def chr_node_create():
    name = _str(request.form.get("name"), 80)
    if not name:
        flash("اسم العقدة مطلوب.", "error")
        return redirect(url_for("admin_infra.chr_nodes_list"))
    if ChrNode.query.filter_by(name=name).first():
        flash(f"اسم العقدة «{name}» مستخدم مسبقًا.", "error")
        return redirect(url_for("admin_infra.chr_nodes_list"))

    enabled_svcs = request.form.getlist("enabled_services")
    node = ChrNode(
        name=name,
        public_ip=_str(request.form.get("public_ip"), 64),
        management_ip=_str(request.form.get("management_ip"), 64),
        domain=_str(request.form.get("domain")),
        location=_str(request.form.get("location"), 100),
        capacity_mbps=_int(request.form.get("capacity_mbps"), 1000),
        max_reserved_mbps=_int(request.form.get("max_reserved_mbps"), 850),
        max_active_sessions=_int(request.form.get("max_active_sessions")),
        max_customers=_int(request.form.get("max_customers")),
        routeros_host=_str(request.form.get("routeros_host")),
        routeros_user=_str(request.form.get("routeros_user"), 80),
        routeros_port=_int(request.form.get("routeros_port"), 443),
        notes=_str(request.form.get("notes"), 1000),
        status="pending",
    )
    raw_password = request.form.get("routeros_password", "").strip()
    if raw_password:
        node.routeros_password_enc = _encrypt_node_password(raw_password)
    node.enabled_services = [s for s in enabled_svcs if s in SERVICE_TYPE_CHOICES]
    db.session.add(node)
    db.session.flush()
    audit("chr_node_create", "chr_node", node.id, f"إنشاء عقدة CHR: {name}", {})
    db.session.commit()
    flash(f"تم إنشاء عقدة CHR «{name}».", "success")
    return redirect(url_for("admin_infra.chr_node_detail", node_id=node.id))


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
    return render_template(
        "admin/infra/chr_node_detail.html",
        node=node,
        reserved_mbps=reserved,
        available_mbps=max(0, node.max_reserved_mbps - reserved),
        capacity_badge=_capacity_badge(reserved, node.max_reserved_mbps),
        recent_metrics=recent_metrics,
        allocations=allocations,
        service_choices=SERVICE_TYPE_CHOICES,
        stale=_is_stale(node),
    )


@bp.post("/chr-nodes/<int:node_id>/edit")
@super_admin_required
def chr_node_edit(node_id: int):
    node = ChrNode.query.get_or_404(node_id)
    enabled_svcs = request.form.getlist("enabled_services")
    node.public_ip = _str(request.form.get("public_ip"), 64)
    node.management_ip = _str(request.form.get("management_ip"), 64)
    node.domain = _str(request.form.get("domain"))
    node.location = _str(request.form.get("location"), 100)
    node.capacity_mbps = _int(request.form.get("capacity_mbps"), node.capacity_mbps)
    node.max_reserved_mbps = _int(request.form.get("max_reserved_mbps"), node.max_reserved_mbps)
    node.max_active_sessions = _int(request.form.get("max_active_sessions"))
    node.max_customers = _int(request.form.get("max_customers"))
    node.routeros_host = _str(request.form.get("routeros_host"))
    node.routeros_user = _str(request.form.get("routeros_user"), 80)
    node.routeros_port = _int(request.form.get("routeros_port"), node.routeros_port)
    node.status = _str(request.form.get("status"), 20) or node.status
    node.notes = _str(request.form.get("notes"), 1000)
    node.enabled_services = [s for s in enabled_svcs if s in SERVICE_TYPE_CHOICES]
    # كلمة المرور تُحدَّث فقط إذا أُرسلت — الإرسال الفارغ يُبقي القيمة المحفوظة
    raw_password = request.form.get("routeros_password", "").strip()
    if raw_password:
        node.routeros_password_enc = _encrypt_node_password(raw_password)
    audit("chr_node_edit", "chr_node", node.id, f"تعديل عقدة CHR: {node.name}", {})
    db.session.commit()
    flash("تم حفظ التعديلات.", "success")
    return redirect(url_for("admin_infra.chr_node_detail", node_id=node_id))


@bp.post("/chr-nodes/<int:node_id>/poll")
@super_admin_required
def chr_node_poll(node_id: int):
    """تشغيل يدوي لجمع مقاييس عقدة CHR واحدة فورًا."""
    from ..services.chr_metrics import _collect_one

    node = ChrNode.query.get_or_404(node_id)
    try:
        metric = _collect_one(node)
        if metric:
            db.session.add(metric)
            db.session.commit()
            flash("تم جمع المقاييس بنجاح.", "success")
        else:
            flash("تعذّر الاتصال بالعقدة — تحقق من بيانات RouterOS.", "error")
    except Exception as exc:
        db.session.rollback()
        flash(f"خطأ أثناء جمع المقاييس: {exc}", "error")
    return redirect(url_for("admin_infra.chr_node_detail", node_id=node_id))


@bp.post("/chr-nodes/poll-all")
@super_admin_required
def chr_nodes_poll_all():
    """تشغيل يدوي لجمع مقاييس كل العقد النشطة."""
    summary = _collect_all_nodes()
    flash(
        f"جمع المقاييس: {summary['ok']} ناجح / "
        f"{summary['skipped']} متجاهل / {summary['errors']} خطأ.",
        "success" if not summary["errors"] else "warning",
    )
    return redirect(url_for("admin_infra.chr_nodes_list"))


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


@bp.get("/service-allocations/<int:alloc_id>/snapshots")
@login_required
def allocation_snapshots(alloc_id: int):
    """عرض تاريخ usage snapshots لتخصيص محدد (آخر 100 سجل)."""
    alloc = ServiceAllocation.query.get_or_404(alloc_id)
    snapshots = (
        ServiceUsageSnapshot.query
        .filter_by(service_allocation_id=alloc_id)
        .order_by(ServiceUsageSnapshot.measured_at.desc())
        .limit(100)
        .all()
    )
    return render_template(
        "admin/infra/allocation_snapshots.html",
        alloc=alloc,
        snapshots=snapshots,
        usage_health=_usage_health,
    )


@bp.get("/health-overview")
@login_required
def health_overview():
    """نظرة عامة على صحة خدمات كل العملاء (بناءً على آخر usage snapshot)."""
    from ..models import License

    customers = Customer.query.order_by(Customer.company_name).all()
    customer_rows = []
    for c in customers:
        active_allocs = (
            ServiceAllocation.query
            .filter_by(customer_id=c.id, status="active")
            .all()
        )
        if not active_allocs:
            continue

        alloc_rows = []
        health_values = []
        for a in active_allocs:
            snap = _latest_snapshot(a.id)
            hs = (snap.health_status if snap else "unknown")
            health_values.append(hs)
            alloc_rows.append({"alloc": a, "snap": snap, "health": hs})

        if "critical" in health_values:
            overall = "critical"
        elif "warning" in health_values:
            overall = "warning"
        elif all(h == "ok" for h in health_values):
            overall = "ok"
        else:
            overall = "unknown"

        customer_rows.append({
            "customer": c,
            "allocs": alloc_rows,
            "overall_health": overall,
        })

    # ترتيب: critical أولاً، ثم warning، ثم ok، ثم unknown
    _order = {"critical": 0, "warning": 1, "ok": 2, "unknown": 3}
    customer_rows.sort(key=lambda r: _order.get(r["overall_health"], 99))

    return render_template(
        "admin/infra/health_overview.html",
        customer_rows=customer_rows,
    )


# ──────────────────────────────────────────────────────────────────────────────
# Proxy Realm Routes
# ──────────────────────────────────────────────────────────────────────────────

@bp.get("/proxy-routes")
@login_required
def proxy_routes_list():
    routes = (
        ProxyRealmRoute.query
        .join(Customer)
        .order_by(ProxyRealmRoute.status, ProxyRealmRoute.realm)
        .all()
    )
    chr_nodes = ChrNode.query.filter_by(status="active").order_by(ChrNode.name).all()
    instances = CustomerRadiusInstance.query.order_by(CustomerRadiusInstance.realm).all()
    return render_template(
        "admin/infra/proxy_routes.html",
        routes=routes,
        chr_nodes=chr_nodes,
        instances=instances,
    )


@bp.post("/proxy-routes/create")
@super_admin_required
def proxy_route_create():
    realm = _str(request.form.get("realm"), 80).lower()
    radius_instance_id = _int(request.form.get("radius_instance_id"))
    if not realm or not radius_instance_id:
        flash("الـ Realm ونسخة RADIUS مطلوبان.", "error")
        return redirect(url_for("admin_infra.proxy_routes_list"))
    if ProxyRealmRoute.query.filter_by(realm=realm).first():
        flash(f"مسار الـ Realm «{realm}» موجود مسبقًا.", "error")
        return redirect(url_for("admin_infra.proxy_routes_list"))
    instance = CustomerRadiusInstance.query.get_or_404(radius_instance_id)
    allowed_node_ids = [_int(x) for x in request.form.getlist("allowed_chr_node_ids") if _int(x)]
    route = ProxyRealmRoute(
        realm=realm,
        customer_id=instance.customer_id,
        radius_instance_id=radius_instance_id,
        target_radius_ip=_str(request.form.get("target_radius_ip"), 64) or instance.radius_auth_ip,
        target_auth_port=_int(request.form.get("target_auth_port"), 1812),
        target_acct_port=_int(request.form.get("target_acct_port"), 1813),
        secret_vault_ref=_str(request.form.get("secret_vault_ref"), 120),
        status="draft",
    )
    route.allowed_chr_node_ids = allowed_node_ids
    db.session.add(route)
    db.session.flush()
    audit("proxy_route_create", "proxy_realm_route", route.id, f"إنشاء مسار Proxy للـ Realm: {realm}", {})
    db.session.commit()
    flash(f"تم إنشاء مسار Realm «{realm}».", "success")
    return redirect(url_for("admin_infra.proxy_routes_list"))


@bp.post("/proxy-routes/<int:route_id>/status")
@super_admin_required
def proxy_route_set_status(route_id: int):
    route = ProxyRealmRoute.query.get_or_404(route_id)
    new_status = _str(request.form.get("status"), 20)
    if new_status not in {"active", "suspended", "draft"}:
        flash("حالة غير صالحة.", "error")
        return redirect(url_for("admin_infra.proxy_routes_list"))
    route.status = new_status
    audit("proxy_route_status", "proxy_realm_route", route.id, f"تغيير حالة مسار {route.realm} إلى {new_status}", {})
    db.session.commit()
    flash("تم تحديث الحالة.", "success")
    return redirect(url_for("admin_infra.proxy_routes_list"))
