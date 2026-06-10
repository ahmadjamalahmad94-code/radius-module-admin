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
from . import chr_settings, vpn_tunnels, wireguard_peers


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
        name="SSTP",
        short="نفق آمن عبر HTTPS (TCP 443) — يمرّ من أصعب الجدران النارية.",
        detail=(
            "نفق آمن مبني على TLS فوق TCP/443؛ مناسب جدًا للعملاء خلف شبكات حظر "
            "لأنه يبدو كزيارة موقع HTTPS. يحتاج شهادة TLS موثوقة على CHR."
        ),
        icon="lock",
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
    """يعيد بطاقة جاهزة لكل بروتوكول (وصف + حالة + عدد + المنفذ المُكوَّن)."""
    ppp = _ppp_counts()
    wg = _wg_counts()
    chr_state = chr_settings.get_state()
    fields = chr_state.get("fields", {})

    def port_for(key: str, default: int) -> int:
        raw = fields.get("port_" + key, {}).get("value") if key != "wireguard" else None
        if raw and str(raw).isdigit():
            return int(raw)
        if key == "wireguard":
            return int(
                current_app.config.get("CHR_WIREGUARD_LISTEN_PORT")
                or wireguard_peers.DEFAULT_LISTEN_PORT
            )
        return default

    cards: list[dict] = []
    chr_configured = chr_state.get("configured", False)
    for key in PROTOCOL_ORDER:
        desc = PROTOCOLS[key]
        if key == "wireguard":
            counts = wg
        else:
            counts = ppp.get(key, {"total": 0, "active": 0})

        # حالة الخدمة على CHR: متاحة إن CHR مكوَّن وله شهادة (SSTP/IKEv2)؛
        # PPTP يعمل دون شهادة؛ WG يعتمد على إعدادات WG.
        if not chr_configured:
            availability = "unconfigured"
        elif key == "sstp" and not chr_state["fields"].get("ipsec_certificate", {}).get("present", False):
            availability = "ready"  # SSTP cert independent — assume admin set it on CHR
        else:
            availability = "ready"

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
        "chr_configured": chr_settings.get_state().get("configured", False),
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
