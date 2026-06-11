"""مسارات «اتصالات الوصول» — لوحة موحَّدة (PPTP/SSTP/IPsec/WireGuard).

السياسة:
    * كل العمليات داخل الجلسة الإدارية المُصادَق عليها (``login_required``).
    * كل إنشاء/إلغاء يكتب في ``AuditLog`` ويُسلَّم للعميل لاحقًا عبر الجسر القائم.
    * أي تكوين/مفاتيح حساسة لا تُعرض إلا في رد الإنشاء نفسه (مرة واحدة).
"""
from __future__ import annotations

from flask import Blueprint, flash, jsonify, redirect, render_template, request, session, url_for

from ..auth.routes import audit, login_required
from ..extensions import db
from ..models import Customer, CustomerVpnTunnel, License, WireguardPeer
from ..services import access_connections as ac
from ..services import fleet_node_router
from ..services import speed_profiles as sp
from ..services import vpn_tunnels as vt
from ..services import wireguard_peers as wg
from ..services.vpn_entitlements import find_best_customer_license

bp = Blueprint("admin_access", __name__, url_prefix="/admin/access-connections")


# ───────────────────────── landing ─────────────────────────


@bp.get("")
@login_required
def index():
    """صفحة الهبوط: 4 بطاقات بروتوكول + جدول الاتصالات + KPIs.

    Zero-central: the operator picks a fleet node in each provisioning
    modal («على أي عقدة؟»). The dropdown defaults to the brain's best
    pick — the internal load balancer — so the common case is one click.
    """
    protocol_filter = (request.args.get("protocol") or "").strip().lower()
    connections = ac.list_connections(protocol=protocol_filter)
    fleet_nodes = fleet_node_router.available_nodes()
    default_node = fleet_node_router.auto_pick_best_node()
    return render_template(
        "admin/access_connections/index.html",
        protocols=ac.protocol_overview(),
        protocol_order=ac.PROTOCOL_ORDER,
        protocol_meta=ac.PROTOCOLS,
        connections=connections,
        stats=ac.stats(),
        protocol_filter=protocol_filter,
        # Replaces the legacy chr_settings.enabled() / get_state() — the new
        # readiness check is "does the fleet have any eligible node?".
        chr_enabled=bool(fleet_nodes),
        chr_configured=bool(fleet_nodes),
        fleet_nodes=fleet_nodes,
        default_fleet_node_id=(default_node.id if default_node else None),
        default_fleet_node_name=(default_node.name if default_node else ""),
        customers=ac.customer_options(),
        speed_profiles=sp.list_profiles(active_only=True),
        ppp_types=sorted(vt.MANUAL_TYPES - {"sstp"}) + ["sstp"],
        ppp_type_labels=vt.TUNNEL_TYPE_LABELS,
        wg_default_supernet=(wg._supernet().with_prefixlen),
        wg_keepalive_default=wg.DEFAULT_KEEPALIVE_SECONDS,
    )


# ───────────────────────── ajax: license picker ─────────────────────────


@bp.get("/api/customer/<int:customer_id>/licenses")
@login_required
def api_customer_licenses(customer_id: int):
    """تراخيص العميل ⇒ JSON لاستهلاكها من المودال (تحديث القائمة بعد اختيار العميل)."""
    db.get_or_404(Customer, customer_id)
    return jsonify({"licenses": ac.license_options(customer_id)})


@bp.get("/api/radius-link-preview")
@login_required
def api_radius_link_preview():
    """RADIUS-transport chain audit for the SSTP modal.

    Owner's architectural intent: the SSTP tunnel created here links the
    subscriber's MikroTik to the customer's RADIUS — auth + accounting +
    CoA all travel on it. The modal calls this endpoint whenever the
    operator changes the customer or fleet node so it can preview the
    realm + RADIUS target + whether the chain is complete BEFORE the
    create-and-provision happens.
    """
    customer_id = _safe_int(request.args.get("customer_id"))
    fleet_chr_node_id = _safe_int(request.args.get("fleet_chr_node_id"))
    return jsonify(ac.radius_link_preview(customer_id, fleet_chr_node_id))


# ───────────────────────── create: PPP / IPsec ─────────────────────────


@bp.post("/ppp")
@login_required
def create_ppp():
    """ينشئ نفقًا من نوع SSTP/PPTP/L2TP/IPsec للعميل المختار، ويزوّده على CHR."""
    customer_id = _safe_int(request.form.get("customer_id"))
    if not customer_id:
        flash("اختر العميل أولًا.", "error")
        return redirect(url_for("admin_access.index"))
    customer = db.get_or_404(Customer, customer_id)
    tunnel_type = (request.form.get("tunnel_type") or "").strip().lower()
    if tunnel_type not in vt.MANUAL_TYPES:
        flash("نوع البروتوكول غير مدعوم.", "error")
        return redirect(url_for("admin_access.index"))
    license_id = _safe_int(request.form.get("license_id"))
    license_obj = (
        License.query.filter_by(id=license_id, customer_id=customer.id).first()
        if license_id
        else find_best_customer_license(customer)
    )
    speed_profile_id = _safe_int(request.form.get("speed_profile_id"))
    # Operator's fleet-node pick — empty/missing = let the brain pick the
    # best-eligible node (the internal load balancer).
    fleet_chr_node_id = _safe_int(request.form.get("fleet_chr_node_id"))

    # ── Architectural intent guard for SSTP =====================================
    # SSTP in this flow is the RADIUS-transport link between the panel's
    # RADIUS and the subscriber's MikroTik. If the customer has no
    # CustomerRadiusInstance / no active ProxyRealmRoute / picked node
    # not in the realm's allow-list, the tunnel will still create on the
    # CHR but the RADIUS path won't reach the customer's RADIUS. We
    # surface the chain status as an Arabic flash; we do NOT block the
    # create (the operator may be staging things in a specific order).
    if tunnel_type == "sstp":
        preview = ac.radius_link_preview(customer.id, fleet_chr_node_id)
        if not preview.get("ok"):
            flash(
                "تنبيه — رابط SSTP يحمل حركة RADIUS بين راديوس العميل وميكروتيك المشترك: "
                + (preview.get("message") or "السلسلة غير مكتملة."),
                "warning",
            )
    # ===========================================================================

    # «السرعة المتماثلة»: قيمة واحدة ⇒ تنزيل = رفع (سياسة المالك). الواجهة
    # الجديدة ترسل ``speed_mbps``؛ نُعطيها الأولوية على القيمتين المنفصلتين كي
    # لا تتسرَّب قيمة غير متماثلة بالخطأ.
    _sym_speed = (request.form.get("speed_mbps") or "").strip()
    _down_raw = _sym_speed or request.form.get("download_mbps")
    _up_raw = _sym_speed or request.form.get("upload_mbps")
    try:
        tunnel = vt.provision_tunnel(
            customer,
            license_obj,
            tunnel_type=tunnel_type,
            profile=request.form.get("profile") or "",
            max_connections=_safe_int(request.form.get("max_connections")) or 1,
            speed_profile_id=speed_profile_id,
            download_mbps=_down_raw or None,
            upload_mbps=_up_raw or None,
            monthly_quota_gb=request.form.get("monthly_quota_gb") or None,
            throttle_down_mbps=request.form.get("throttle_down_mbps") or None,
            throttle_up_mbps=request.form.get("throttle_up_mbps") or None,
            source="admin_manual",
            created_by_admin_id=session.get("admin_id"),
            notes=request.form.get("notes") or "",
            fleet_chr_node_id=fleet_chr_node_id,
        )
    except vt.VpnTunnelError as exc:
        db.session.rollback()
        flash(str(exc), "error")
        return redirect(url_for("admin_access.index"))
    audit(
        "access_connection_ppp_created",
        "customer_vpn_tunnel",
        str(tunnel.id),
        f"إنشاء اتصال {tunnel.tunnel_type} للعميل {customer.company_name} من «اتصالات الوصول»",
        {"customer_id": customer.id, "tunnel_type": tunnel.tunnel_type, "username": tunnel.username,
         "fleet_chr_node_id": tunnel.fleet_chr_node_id},
    )
    db.session.commit()
    # The SSTP success toast names the RADIUS-transport role explicitly so
    # the operator remembers what they just created. Other PPP tunnel
    # types stick with the generic «اتصال» wording.
    if tunnel.tunnel_type == "sstp":
        flash(
            f"تم إنشاء رابط RADIUS عبر SSTP ({tunnel.username}) على عقدة الأسطول — "
            "سيتسلّم العميل بياناته عبر الجسر ثم يُدخلها في إعدادات SSTP-Client على ميكروتيك المشترك.",
            "success",
        )
    else:
        flash(
            f"تم إنشاء اتصال {vt.TUNNEL_TYPE_LABELS.get(tunnel.tunnel_type, tunnel.tunnel_type)} "
            f"({tunnel.username}) — سيُسلَّم للعميل عبر الجسر.",
            "success",
        )
    return redirect(url_for("admin_access.index"))


@bp.post("/ppp/<int:tunnel_id>/revoke")
@login_required
def revoke_ppp(tunnel_id: int):
    tunnel = db.session.get(CustomerVpnTunnel, tunnel_id)
    if not tunnel:
        flash("لم يتم العثور على الاتصال.", "error")
        return redirect(url_for("admin_access.index"))
    try:
        vt.revoke_tunnel(tunnel)
    except vt.VpnTunnelError as exc:
        db.session.rollback()
        flash(str(exc), "error")
        return redirect(url_for("admin_access.index"))
    audit(
        "access_connection_ppp_revoked",
        "customer_vpn_tunnel",
        str(tunnel.id),
        f"إلغاء اتصال {tunnel.username}",
        {"customer_id": tunnel.customer_id, "username": tunnel.username},
    )
    db.session.commit()
    flash("تم إلغاء الاتصال وحذفه من CHR.", "success")
    return redirect(url_for("admin_access.index"))


# ───────────────────────── create: WireGuard ─────────────────────────


@bp.post("/wireguard")
@login_required
def create_wireguard():
    """يولّد قرين WireGuard (أو يقبل مفتاحًا عامًا من المالك) ويزوّده على CHR."""
    customer_id = _safe_int(request.form.get("customer_id"))
    if not customer_id:
        flash("اختر العميل أولًا.", "error")
        return redirect(url_for("admin_access.index"))
    customer = db.get_or_404(Customer, customer_id)
    license_id = _safe_int(request.form.get("license_id"))
    license_obj = (
        License.query.filter_by(id=license_id, customer_id=customer.id).first()
        if license_id
        else find_best_customer_license(customer)
    )
    use_preshared = bool(request.form.get("use_preshared"))
    keepalive = _safe_int(request.form.get("keepalive_seconds")) or wg.DEFAULT_KEEPALIVE_SECONDS
    fleet_chr_node_id = _safe_int(request.form.get("fleet_chr_node_id"))
    try:
        peer = wg.provision_peer(
            customer,
            license_obj,
            label=request.form.get("label") or "",
            public_key=request.form.get("public_key") or "",
            allowed_ips=request.form.get("allowed_ips") or "",
            use_preshared=use_preshared,
            dns_servers=request.form.get("dns_servers") or "",
            keepalive_seconds=keepalive,
            created_by_admin_id=session.get("admin_id"),
            notes=request.form.get("notes") or "",
            fleet_chr_node_id=fleet_chr_node_id,
        )
    except wg.WireguardPeerError as exc:
        db.session.rollback()
        flash(str(exc), "error")
        return redirect(url_for("admin_access.index"))
    audit(
        "access_connection_wireguard_created",
        "customer_wireguard_peer",
        str(peer.id),
        f"إنشاء قرين WireGuard «{peer.peer_name}» للعميل {customer.company_name}",
        {
            "customer_id": customer.id,
            "peer_name": peer.peer_name,
            "allowed_ips": peer.allowed_ips,
        },
    )
    db.session.commit()
    flash(
        f"تم إنشاء قرين WireGuard «{peer.peer_name}». نزّل التكوين الآن — لن يُعرض المفتاح الخاص مرة أخرى.",
        "success",
    )
    return redirect(url_for("admin_access.peer_view", peer_id=peer.id))


@bp.get("/wireguard/<int:peer_id>")
@login_required
def peer_view(peer_id: int):
    """تفاصيل قرين + تنزيل التكوين (مرة واحدة، حتى التأكيد)."""
    peer = db.session.get(WireguardPeer, peer_id)
    if not peer:
        flash("لم يتم العثور على القرين.", "error")
        return redirect(url_for("admin_access.index"))
    can_reveal = (peer.delivery_status != "delivered" and peer.status != "revoked")
    config_text = wg.render_peer_config(peer) if can_reveal else ""
    return render_template(
        "admin/access_connections/wireguard_detail.html",
        peer=peer,
        config_text=config_text,
        can_reveal=can_reveal,
    )


@bp.post("/wireguard/<int:peer_id>/acknowledge")
@login_required
def peer_acknowledge(peer_id: int):
    peer = db.session.get(WireguardPeer, peer_id)
    if not peer:
        flash("لم يتم العثور على القرين.", "error")
        return redirect(url_for("admin_access.index"))
    wg.acknowledge_delivery(peer.customer, [peer.peer_name])
    audit(
        "access_connection_wireguard_delivered",
        "customer_wireguard_peer",
        str(peer.id),
        f"تأكيد تسليم قرين WireGuard «{peer.peer_name}»",
        {"customer_id": peer.customer_id},
    )
    db.session.commit()
    flash("تم تأكيد التسليم؛ لن يُعرض المفتاح الخاص مجددًا.", "success")
    return redirect(url_for("admin_access.peer_view", peer_id=peer.id))


@bp.post("/wireguard/<int:peer_id>/revoke")
@login_required
def revoke_wireguard(peer_id: int):
    peer = db.session.get(WireguardPeer, peer_id)
    if not peer:
        flash("لم يتم العثور على القرين.", "error")
        return redirect(url_for("admin_access.index"))
    try:
        wg.revoke_peer(peer)
    except wg.WireguardPeerError as exc:
        db.session.rollback()
        flash(str(exc), "error")
        return redirect(url_for("admin_access.index"))
    audit(
        "access_connection_wireguard_revoked",
        "customer_wireguard_peer",
        str(peer.id),
        f"إلغاء قرين WireGuard «{peer.peer_name}»",
        {"customer_id": peer.customer_id, "peer_name": peer.peer_name},
    )
    db.session.commit()
    flash("تم إلغاء قرين WireGuard وحذفه من CHR.", "success")
    return redirect(url_for("admin_access.index"))


@bp.post("/wireguard/<int:peer_id>/status")
@login_required
def status_wireguard(peer_id: int):
    peer = db.session.get(WireguardPeer, peer_id)
    if not peer:
        flash("لم يتم العثور على القرين.", "error")
        return redirect(url_for("admin_access.index"))
    target = (request.form.get("status") or "").strip().lower()
    try:
        wg.set_peer_status(peer, target)
    except wg.WireguardPeerError as exc:
        db.session.rollback()
        flash(str(exc), "error")
        return redirect(url_for("admin_access.index"))
    audit(
        "access_connection_wireguard_status_changed",
        "customer_wireguard_peer",
        str(peer.id),
        f"تغيير حالة قرين «{peer.peer_name}» إلى {peer.status}",
        {"customer_id": peer.customer_id, "status": peer.status},
    )
    db.session.commit()
    flash("تم تحديث حالة القرين.", "success")
    return redirect(url_for("admin_access.index"))


# ───────────────────────── helpers ─────────────────────────


def _safe_int(value) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None
