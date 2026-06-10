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
from ..services import chr_settings as chr_svc
from ..services import speed_profiles as sp
from ..services import vpn_tunnels as vt
from ..services import wireguard_peers as wg
from ..services.vpn_entitlements import find_best_customer_license

bp = Blueprint("admin_access", __name__, url_prefix="/admin/access-connections")


# ───────────────────────── landing ─────────────────────────


@bp.get("")
@login_required
def index():
    """صفحة الهبوط: 4 بطاقات بروتوكول + جدول الاتصالات + KPIs."""
    protocol_filter = (request.args.get("protocol") or "").strip().lower()
    connections = ac.list_connections(protocol=protocol_filter)
    return render_template(
        "admin/access_connections/index.html",
        protocols=ac.protocol_overview(),
        protocol_order=ac.PROTOCOL_ORDER,
        protocol_meta=ac.PROTOCOLS,
        connections=connections,
        stats=ac.stats(),
        protocol_filter=protocol_filter,
        chr_enabled=chr_svc.enabled(),
        chr_configured=chr_svc.get_state().get("configured", False),
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
    try:
        tunnel = vt.provision_tunnel(
            customer,
            license_obj,
            tunnel_type=tunnel_type,
            profile=request.form.get("profile") or "",
            max_connections=_safe_int(request.form.get("max_connections")) or 1,
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
        return redirect(url_for("admin_access.index"))
    audit(
        "access_connection_ppp_created",
        "customer_vpn_tunnel",
        str(tunnel.id),
        f"إنشاء اتصال {tunnel.tunnel_type} للعميل {customer.company_name} من «اتصالات الوصول»",
        {"customer_id": customer.id, "tunnel_type": tunnel.tunnel_type, "username": tunnel.username},
    )
    db.session.commit()
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
