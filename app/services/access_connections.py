"""خدمة موحَّدة لـ«اتصالات الوصول» — البروتوكولات الأربعة (PPTP/SSTP/IPsec/WG).

تقع هذه الطبقة فوق ``vpn_tunnels`` و``wireguard_peers``: نفس البيانات الأساسية،
عرض موحَّد للواجهة. الهدف: أن يجد المالك مكانًا واحدًا واضحًا للإضافة/المراقبة
بدل أن يلاحق الأنفاق لكل عميل على حدة، أو يُضطرّ لأوامر CLI.

الواجهة العامة:
    * :func:`protocol_overview` — صورة لكل بروتوكول (الوصف، الحالة، العدّ).
    * :func:`list_connections`  — صفّ موحَّد لكل الاتصالات (PPP + IPsec + WG).
    * :func:`stats`             — KPIs للهيرو.
"""
from __future__ import annotations

from dataclasses import dataclass

from flask import current_app

from ..extensions import db
from ..models import Customer, CustomerVpnTunnel, License, WireguardPeer, utcnow
from . import fleet_node_router, vpn_tunnels, wireguard_peers


# ───────────────────────── protocol descriptors ─────────────────────────


@dataclass(frozen=True)
class ProtocolDescriptor:
    """وصف عرضي ثابت لكل بروتوكول — يُغذّي البطاقات في الواجهة."""

    key: str
    name: str
    short: str        # «اعرفني»
    detail: str       # المزيد
    icon: str
    chip: str
    default_port: int


PROTOCOLS: dict[str, ProtocolDescriptor] = {
    "sstp": ProtocolDescriptor(
        key="sstp",
        name="SSTP — رابط RADIUS",
        short="قناة نقل RADIUS بين راديوس العميل وميكروتيك المشترك عبر TCP/443.",
        detail=(
            "هذه ليست خدمة VPN عامة — إنها قناة النقل بين راديوس العميل "
            "(على نسخة RADIUS المسجَّلة) وميكروتيك المشترك. يتصل ميكروتيك "
            "المشترك عبر SSTP بعقدة الأسطول المختارة، ثم تمرّ حركة "
            "RADIUS كاملة (auth/acct/CoA) عبر النفق إلى وكيل RADIUS الذي "
            "يوجّهها إلى راديوس العميل. شهادة TLS على CHR مطلوبة."
        ),
        icon="route",
        chip="violet",
        default_port=443,
    ),
    "pptp": ProtocolDescriptor(
        key="pptp",
        name="PPTP",
        short="نفق كلاسيكي خفيف الإعداد (TCP 1723 + GRE).",
        detail=(
            "نفق قديم يأتي مدمجًا في كل أنظمة التشغيل تقريبًا، لا يحتاج شهادة. "
            "أمانه أضعف من SSTP/IKEv2؛ مناسب للاختبار أو الشبكات الداخلية الموثوقة."
        ),
        icon="plug",
        chip="amber",
        default_port=1723,
    ),
    "ipsec": ProtocolDescriptor(
        key="ipsec",
        name="IPsec / IKEv2",
        short="نفق قياسي للأجهزة المحمولة (UDP 500 + 4500).",
        detail=(
            "IKEv2 مع EAP-MSCHAPv2 على RouterOS — تكامل ممتاز مع iOS/Android/ويندوز "
            "المضمّن. يحتاج شهادة IKEv2 موثوقة على CHR."
        ),
        icon="shield-halved",
        chip="blue",
        default_port=4500,
    ),
    "wireguard": ProtocolDescriptor(
        key="wireguard",
        name="WireGuard",
        short="نفق حديث سريع جدًا بنواة بسيطة (UDP 51822).",
        detail=(
            "أحدث جيل من أنفاق VPN: شفرة صغيرة، أداء عالٍ، مفاتيح Curve25519. "
            "اللوحة تولّد زوج المفاتيح للعميل وتنشئ القرين على CHR تلقائيًا."
        ),
        icon="bolt",
        chip="green",
        default_port=51822,
    ),
}

# الترتيب الذي يراه المالك على الشاشة (الأهم/الأسهل أولًا).
PROTOCOL_ORDER = ("wireguard", "sstp", "ipsec", "pptp")


# ───────────────────────── snapshot ─────────────────────────


def _ppp_counts() -> dict[str, dict[str, int]]:
    """عدّ كل نفق PPP/IPsec حسب النوع والحالة."""
    rows = (
        db.session.query(CustomerVpnTunnel.tunnel_type, CustomerVpnTunnel.status, db.func.count())
        .group_by(CustomerVpnTunnel.tunnel_type, CustomerVpnTunnel.status)
        .all()
    )
    out: dict[str, dict[str, int]] = {}
    for ttype, status, count in rows:
        bucket = out.setdefault(str(ttype or "unknown"), {"total": 0, "active": 0})
        bucket["total"] += int(count or 0)
        if str(status) == "active":
            bucket["active"] += int(count or 0)
    return out


def _wg_counts() -> dict[str, int]:
    rows = (
        db.session.query(WireguardPeer.status, db.func.count())
        .group_by(WireguardPeer.status)
        .all()
    )
    total = sum(int(c or 0) for _s, c in rows)
    active = sum(int(c or 0) for s, c in rows if str(s) == "active")
    return {"total": total, "active": active}


def protocol_overview() -> list[dict]:
    """يعيد بطاقة جاهزة لكل بروتوكول (وصف + حالة + عدد + المنفذ المُكوَّن).

    Zero-central: port overrides come from the fleet settings (Setting
    rows under ``fleet.port.<svc>``), and «configured» means «the fleet
    has at least one eligible node». The legacy chr_settings singleton
    is gone.
    """
    ppp = _ppp_counts()
    wg = _wg_counts()
    fleet_nodes = fleet_node_router.available_nodes()
    chr_configured = bool(fleet_nodes)
    # Resolve a single fleet endpoint (host + per-service ports) using the
    # brain's pick — every protocol card shares the same port mapping.
    sample_node = fleet_node_router.auto_pick_best_node()
    if sample_node is not None:
        ep = fleet_node_router.endpoint_for(sample_node)
        fleet_ports = ep.ports
    else:
        fleet_ports = dict(fleet_node_router.HARD_DEFAULT_PORTS)

    def port_for(key: str, default: int) -> int:
        return int(fleet_ports.get(key) or default)

    cards: list[dict] = []
    for key in PROTOCOL_ORDER:
        desc = PROTOCOLS[key]
        if key == "wireguard":
            counts = wg
        else:
            counts = ppp.get(key, {"total": 0, "active": 0})

        availability = "ready" if chr_configured else "unconfigured"

        cards.append({
            "key": desc.key,
            "name": desc.name,
            "short": desc.short,
            "detail": desc.detail,
            "icon": desc.icon,
            "chip": desc.chip,
            "port": port_for(desc.key, desc.default_port),
            "total": counts.get("total", 0),
            "active": counts.get("active", 0),
            "availability": availability,
        })
    return cards


def stats() -> dict:
    """KPIs مجمَّعة لرأس الصفحة."""
    ppp = _ppp_counts()
    wg = _wg_counts()
    total = sum(b["total"] for b in ppp.values()) + wg["total"]
    active = sum(b["active"] for b in ppp.values()) + wg["active"]
    return {
        "total": total,
        "active": active,
        "protocols_enabled": sum(1 for k in PROTOCOL_ORDER if PROTOCOLS[k] is not None),
        "chr_configured": bool(fleet_node_router.available_nodes()),
    }


# ───────────────────────── unified list ─────────────────────────


def _serialize_ppp(row: CustomerVpnTunnel) -> dict:
    return {
        "kind": "ppp",
        "id": row.id,
        "customer_id": row.customer_id,
        "company_name": row.customer.company_name if row.customer else "",
        "protocol": row.tunnel_type,
        "label": row.username,
        "status": row.status,
        "delivery_status": row.delivery_status,
        "chr_provisioned": bool(row.chr_provisioned),
        "download_mbps": row.download_mbps,
        "upload_mbps": row.upload_mbps,
        "created_at": row.created_at,
        "manage_url": f"/admin/customers/{row.customer_id}/vpn-tunnels",
        "revoke_action": (
            f"/admin/access-connections/ppp/{row.id}/revoke"
        ),
    }


def _serialize_wg(row: WireguardPeer) -> dict:
    return {
        "kind": "wireguard",
        "id": row.id,
        "customer_id": row.customer_id,
        "company_name": row.customer.company_name if row.customer else "",
        "protocol": "wireguard",
        "label": row.peer_name,
        "status": row.status,
        "delivery_status": row.delivery_status,
        "chr_provisioned": bool(row.chr_provisioned),
        "download_mbps": None,
        "upload_mbps": None,
        "created_at": row.created_at,
        "allowed_ips": row.allowed_ips,
        "manage_url": f"/admin/access-connections/wireguard/{row.id}",
        "revoke_action": f"/admin/access-connections/wireguard/{row.id}/revoke",
    }


def list_connections(*, protocol: str = "", customer_id: int | None = None) -> list[dict]:
    """قائمة موحَّدة عبر البروتوكولات الأربعة، مفلترة (اختياريًا) بالنوع/العميل."""
    proto = (protocol or "").strip().lower()
    out: list[dict] = []
    if proto in {"", "wireguard"}:
        wg_q = WireguardPeer.query
        if customer_id:
            wg_q = wg_q.filter_by(customer_id=customer_id)
        for row in wg_q.order_by(WireguardPeer.id.desc()).all():
            out.append(_serialize_wg(row))
    if proto != "wireguard":
        ppp_q = CustomerVpnTunnel.query
        if proto:
            ppp_q = ppp_q.filter(CustomerVpnTunnel.tunnel_type == proto)
        if customer_id:
            ppp_q = ppp_q.filter(CustomerVpnTunnel.customer_id == customer_id)
        for row in ppp_q.order_by(CustomerVpnTunnel.id.desc()).all():
            out.append(_serialize_ppp(row))
    out.sort(key=lambda r: r.get("created_at") or utcnow(), reverse=True)
    return out


# ───────────────────────── customer/license pickers ─────────────────────────


def customer_options(limit: int = 200) -> list[dict]:
    """قائمة عملاء مختصرة لاختيار الهدف من المودال."""
    rows = (
        Customer.query.filter(Customer.status != "deleted")
        .order_by(Customer.company_name.asc())
        .limit(limit)
        .all()
    )
    return [
        {"id": c.id, "name": c.company_name, "status": c.status}
        for c in rows
    ]


def license_options(customer_id: int) -> list[dict]:
    """تراخيص نشطة (أو متاحة) لعميل بعينه — لاختيار الترخيص الذي يُربط به النفق."""
    if not customer_id:
        return []
    rows = (
        License.query.filter_by(customer_id=customer_id)
        .filter(License.status.in_(["active", "trial", "grace", "expired"]))
        .order_by(License.id.desc())
        .limit(20)
        .all()
    )
    return [
        {
            "id": l.id,
            "key": l.license_key,
            "status": l.status,
        }
        for l in rows
    ]


# ════════════════════════════════════════════════════════════════════════
# RADIUS-transport link readiness (architectural intent: the SSTP tunnel
# carries RADIUS traffic from the subscriber's MikroTik back to the
# customer's RADIUS instance).
#
# The end-to-end path is:
#   1. The subscriber's MikroTik dials SSTP on the fleet CHR (the SSTP
#      server / aggregation point). Username + password come from this
#      tunnel record; host:port from fleet_node.public_ip + 443.
#   2. RADIUS auth/acct/CoA packets the subscriber's MikroTik sends
#      (with realm in User-Name → user@<realm>) travel up the SSTP
#      tunnel to the CHR.
#   3. The CHR forwards them to the central RADIUS proxy via wg-data.
#   4. The proxy looks the realm up in ``ProxyRealmRoute`` and ships
#      the packets to the customer's RADIUS VPS (``radius_auth_ip``
#      from ``CustomerRadiusInstance``).
#
# For step 4 to work, the customer must have:
#   * a CustomerRadiusInstance (the realm + the customer's RADIUS IP),
#   * a ProxyRealmRoute pointing at that instance, status=active,
#   * the picked fleet CHR in the route's allowed_fleet_chr_node_ids
#     allow-list (otherwise the proxy drops the RADIUS packet).
#
# The helper below packages that check so the UI can show a clear
# preview before the operator clicks "Create" and the route handler
# can flash an Arabic warning when something's missing.
# ════════════════════════════════════════════════════════════════════════

def radius_link_preview(customer_id: int, fleet_chr_node_id: int | None) -> dict:
    """Audit the RADIUS-transport chain for a customer + chosen fleet node.

    Returns a structured dict the SSTP modal can render and the create
    handler can validate against. Never raises — missing pieces show up
    as ``ok=False`` with an Arabic ``message`` and per-step booleans
    (``has_radius_instance``, ``has_proxy_route``, ``node_in_allowlist``).
    Empty / unknown values collapse to safe defaults; this is read-only.
    """
    from ..models import CustomerRadiusInstance, ProxyRealmRoute

    customer = Customer.query.get(int(customer_id)) if customer_id else None
    if customer is None:
        return {
            "ok": False, "message": "اختر عميلًا أولًا.",
            "customer_name": "", "realm": "", "radius_target": "",
            "has_radius_instance": False, "has_proxy_route": False,
            "node_in_allowlist": False, "fleet_chr_node_id": fleet_chr_node_id,
        }

    instance = (
        CustomerRadiusInstance.query
        .filter_by(customer_id=customer.id)
        .first()
    )
    if instance is None:
        return {
            "ok": False,
            "message": (
                "لا توجد «نسخة RADIUS» مسجَّلة لهذا العميل بعد. "
                "بدون تسجيلها لا يعرف الوكيل أين يُرسل حركة RADIUS. "
                "سجّلها من «أسطول CHR ← نسخ RADIUS» ثم أعد المحاولة."
            ),
            "customer_name": customer.company_name,
            "realm": "", "radius_target": "",
            "has_radius_instance": False, "has_proxy_route": False,
            "node_in_allowlist": False, "fleet_chr_node_id": fleet_chr_node_id,
        }

    route = (
        ProxyRealmRoute.query
        .filter_by(customer_id=customer.id, radius_instance_id=instance.id)
        .first()
    )
    radius_target = f"{instance.radius_auth_ip}:{instance.radius_auth_port}"
    if route is None:
        return {
            "ok": False,
            "message": (
                "نسخة RADIUS مسجَّلة لكن لا يوجد «وكيل RADIUS» يربط الـRealm بها. "
                "أنشئ مسار Realm من «أسطول CHR ← وكيل RADIUS» ثم أعد المحاولة."
            ),
            "customer_name": customer.company_name,
            "realm": instance.realm, "radius_target": radius_target,
            "has_radius_instance": True, "has_proxy_route": False,
            "node_in_allowlist": False, "fleet_chr_node_id": fleet_chr_node_id,
        }

    allowed_ids = route.allowed_fleet_chr_node_ids or []
    node_in_allowlist = (
        # An empty allow-list means «all eligible nodes», which is fine.
        not allowed_ids
        or (fleet_chr_node_id is not None and int(fleet_chr_node_id) in allowed_ids)
    )
    route_active = (route.status == "active")
    ok = route_active and node_in_allowlist

    if not route_active:
        message = (
            f"مسار الـRealm «{route.realm}» موجود لكن حالته «{route.status}». "
            "حوّله إلى «active» من «وكيل RADIUS» قبل إنشاء الرابط."
        )
    elif not node_in_allowlist:
        message = (
            "العقدة المختارة ليست ضمن «العقد المسموحة» في مسار الـRealm. "
            "أضِف العقدة إلى قائمة المسار أو اختر عقدة أخرى مسموحة، "
            "وإلا سيُسقط الوكيل حِزَم RADIUS قادمة منها."
        )
    else:
        message = "السلسلة كاملة: عقدة فعّالة ⇄ مسار Realm نشط ⇄ نسخة RADIUS العميل."

    return {
        "ok": ok,
        "message": message,
        "customer_name": customer.company_name,
        "realm": route.realm or instance.realm,
        "radius_target": radius_target,
        "has_radius_instance": True,
        "has_proxy_route": True,
        "route_status": route.status,
        "node_in_allowlist": bool(node_in_allowlist),
        "fleet_chr_node_id": fleet_chr_node_id,
    }
