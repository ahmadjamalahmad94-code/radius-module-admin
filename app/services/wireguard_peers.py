"""تزويد أقران WireGuard مركزيًا على CHR (الطبقة الأساسية).

WireGuard على RouterOS نظام مستقل عن ``/ppp/secret``: تُربط الواجهة
(``/interface/wireguard``) بمنفذ مستمع وملف خاص يبقى داخل الراوتر، ثم تُضاف
الأقران (``/interface/wireguard/peers``) كل واحد بمفتاحه العام و``allowed-address``
الخاصة. تُولَّد أزواج المفاتيح هنا في اللوحة (X25519) ويُرسَل المفتاح العام إلى
CHR؛ ويُخزَّن المفتاح الخاص مشفّرًا (Fernet عبر ``customer_vault_crypto``) ويُسلَّم
للعميل مرة واحدة فقط (نفس نمط أنفاق PPP).

التصميم متعمَّد ليطابق ``vpn_tunnels.py``: نفس الاستثناءات، نفس دورة الحياة
(``provision`` / ``revoke`` / ``set_status``)، نفس مكتبة التشفير. فتُعامَل أقران
WG في الواجهة كـ"نفق آخر" دون شفرة موازية مكرّرة.
"""
from __future__ import annotations

import base64
import ipaddress
import re
import secrets

from flask import current_app

from ..extensions import db
from ..models import Customer, License, WireguardPeer, utcnow
from . import fleet_node_router
from .fleet_node_router import FleetNodeUnavailable
from .customer_vault_crypto import decrypt_secret, encrypt_secret
from .routeros_client import RouterOSError

# ── default interface / pool / port ───────────────────────────────────────
DEFAULT_INTERFACE = "wg-vpn"
DEFAULT_LISTEN_PORT = 51822
DEFAULT_CLIENT_SUPERNET = "10.97.0.0/24"
DEFAULT_KEEPALIVE_SECONDS = 25

# مفتاح Setting يحفظ المفتاح العام للواجهة على CHR بعد إنشائها (لا داعي لقراءته
# من الراوتر في كل مرة). فارغ ⇒ نسأل CHR عند أول استدعاء.
SERVER_PUBKEY_SETTING = "chr.wireguard.server_pubkey"
INTERFACE_INIT_SETTING = "chr.wireguard.interface_ready"


# ───────────────────────── exceptions ─────────────────────────


class WireguardPeerError(ValueError):
    """خطأ تزويد WireGuard يُعرض للمستدعي — رسالة عربية."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


# ───────────────────────── keypair generation ─────────────────────────


def generate_keypair() -> tuple[str, str]:
    """يولّد زوج مفاتيح Curve25519 لـ WireGuard (private, public) base64.

    private 32 بايت عشوائية → public = X25519(priv, base). RouterOS تتوقّع
    تمثيل base64 (44 حرفًا).
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    priv = X25519PrivateKey.generate()
    priv_raw = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return (
        base64.b64encode(priv_raw).decode("ascii"),
        base64.b64encode(pub_raw).decode("ascii"),
    )


def generate_preshared_key() -> str:
    """يولّد مفتاح PSK مشترك (32 بايت عشوائية) ⇒ base64."""
    return base64.b64encode(secrets.token_bytes(32)).decode("ascii")


_B64_PUBKEY_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")


def is_valid_wg_pubkey(value: str) -> bool:
    """التحقق الشكلي من مفتاح WG عام (32 بايت ⇒ 43 + '=' = 44 حرفًا base64)."""
    if not value:
        return False
    return bool(_B64_PUBKEY_RE.match(value.strip()))


# ───────────────────────── allowed-ip allocation ─────────────────────────


def _supernet() -> ipaddress.IPv4Network:
    raw = (current_app.config.get("CHR_WIREGUARD_CLIENT_SUPERNET") or DEFAULT_CLIENT_SUPERNET).strip()
    try:
        return ipaddress.ip_network(raw, strict=False)
    except (ValueError, TypeError):
        return ipaddress.ip_network(DEFAULT_CLIENT_SUPERNET)


def _used_ips() -> set[str]:
    rows = WireguardPeer.query.filter(WireguardPeer.status != "revoked").all()
    used: set[str] = set()
    for row in rows:
        for cidr in (row.allowed_ips or "").split(","):
            cidr = cidr.strip()
            if "/" in cidr:
                used.add(cidr.split("/", 1)[0])
    return used


def allocate_client_address() -> str:
    """يلتقط عنوان IPv4 حرّ من شبكة العملاء (يتخطّى أول عنوانين).

    يعيد سلسلة ``a.b.c.d/32``. يرفع :class:`WireguardPeerError` عند النفاد.
    """
    net = _supernet()
    used = _used_ips()
    skip = 2  # network + gateway
    for idx, addr in enumerate(net.hosts()):
        if idx < skip - 1:
            continue
        if str(addr) in used:
            continue
        return f"{addr}/32"
    raise WireguardPeerError("subnet_full", "نفدت عناوين شبكة WireGuard المتاحة.")


# ───────────────────────── CHR interface bootstrap ─────────────────────────


def _setting_value(key: str) -> str:
    from ..models import Setting

    row = db.session.get(Setting, key)
    return (row.value or "") if row else ""


def _set_setting(key: str, value: str) -> None:
    from ..models import Setting

    row = db.session.get(Setting, key)
    if not row:
        row = Setting(key=key)
    row.value = value
    db.session.add(row)


def ensure_server_interface(client) -> str:
    """يضمن وجود واجهة WG-VPN على CHR ويعيد مفتاحها العام (base64).

    Idempotent. يُحفظ المفتاح العام في Setting كي نقرأه دون نداء CHR لاحقًا.
    """
    cached = _setting_value(SERVER_PUBKEY_SETTING)
    name = (current_app.config.get("CHR_WIREGUARD_INTERFACE") or DEFAULT_INTERFACE).strip() or DEFAULT_INTERFACE
    port = int(current_app.config.get("CHR_WIREGUARD_LISTEN_PORT") or DEFAULT_LISTEN_PORT)
    iface = client.ensure_wireguard_interface(name=name, listen_port=port)
    pubkey = str(iface.get("public-key") or "")
    if pubkey:
        if pubkey != cached:
            _set_setting(SERVER_PUBKEY_SETTING, pubkey)
            _set_setting(INTERFACE_INIT_SETTING, "1")
        return pubkey
    # Some RouterOS builds withhold the pubkey from PUT — re-fetch explicitly.
    fresh = client.find_wireguard_interface(name)
    pubkey = str((fresh or {}).get("public-key") or "")
    if pubkey:
        _set_setting(SERVER_PUBKEY_SETTING, pubkey)
        _set_setting(INTERFACE_INIT_SETTING, "1")
    return pubkey or cached


def server_public_key_cached() -> str:
    return _setting_value(SERVER_PUBKEY_SETTING)


def server_endpoint(node=None) -> dict:
    """العنوان والمنفذ العام لخدمة WireGuard كما يتصل بها العميل.

    Derives the host:port for THIS peer's fleet node — node-aware so a
    customer on chr-vpn-3 doesn't get chr-vpn-1's WAN address in their
    config. ``node`` is required for new peers; legacy callers (no
    fleet node yet) get the brain's best pick as a soft fallback.
    """
    if node is None:
        node = fleet_node_router.auto_pick_best_node()
    if node is None:
        # No fleet at all — degrade to the unknown-host marker; the
        # caller (peer config builder) decides whether to surface this.
        return {"public_host": "", "port": int(current_app.config.get("CHR_WIREGUARD_LISTEN_PORT") or DEFAULT_LISTEN_PORT)}
    endpoint = fleet_node_router.endpoint_for(node)
    # Fleet endpoint already includes a wireguard port; prefer that, fall
    # back to the env override when the operator hasn't seeded a fleet port.
    port = int(endpoint.ports.get("wireguard") or current_app.config.get("CHR_WIREGUARD_LISTEN_PORT") or DEFAULT_LISTEN_PORT)
    return {"public_host": endpoint.public_host, "port": port}


# ───────────────────────── helpers ─────────────────────────


def _unique_peer_name(customer: Customer, label: str) -> str:
    base = (label or "peer").strip()[:60] or "peer"
    base = re.sub(r"[^A-Za-z0-9_\-.؀-ۿ ]", "", base).strip() or "peer"
    candidate = f"c{customer.id}-{base}"
    existing = {p.peer_name for p in WireguardPeer.query.filter_by(customer_id=customer.id).all()}
    if candidate not in existing:
        return candidate
    for n in range(2, 50):
        cand = f"{candidate}-{n}"
        if cand not in existing:
            return cand
    suffix = secrets.token_hex(3)
    return f"{candidate}-{suffix}"


def _store_private_key(peer: WireguardPeer, plaintext: str) -> None:
    if plaintext:
        peer.private_key_encrypted = encrypt_secret(plaintext)


def _store_preshared_key(peer: WireguardPeer, plaintext: str) -> None:
    if plaintext:
        peer.preshared_key_encrypted = encrypt_secret(plaintext)


def get_private_key(peer: WireguardPeer) -> str:
    if not peer.private_key_encrypted:
        return ""
    return decrypt_secret(peer.private_key_encrypted)


def get_preshared_key(peer: WireguardPeer) -> str:
    if not peer.preshared_key_encrypted:
        return ""
    return decrypt_secret(peer.preshared_key_encrypted)


# ───────────────────────── provisioning ─────────────────────────


def provision_peer(
    customer: Customer,
    license_obj: License | None,
    *,
    label: str = "",
    public_key: str = "",
    allowed_ips: str = "",
    use_preshared: bool = True,
    dns_servers: str = "",
    keepalive_seconds: int | None = None,
    created_by_admin_id: int | None = None,
    notes: str = "",
    fleet_chr_node_id: int | None = None,
) -> WireguardPeer:
    """يحجز عنوانًا، ينشئ القرين على CHR، ويعيد السجل (دون commit).

    سياسة المفاتيح:
      * إذا مرّر المالك ``public_key`` نخزّنه ولا نولّد مفتاحًا خاصًا.
      * إذا تُرك فارغًا نولّد زوجًا (X25519) ونخزّن الخاص مشفّرًا (Fernet) ونرسل
        العام لـ CHR. هذا هو السلوك الافتراضي لأن أغلب المالكين لا يملكون
        مولّدًا جاهزًا وسيرتاحون لكون اللوحة تجهّز التكوين كاملاً.

    Zero-central placement: when the operator passes ``fleet_chr_node_id``
    we provision on that exact node; otherwise we ask the fleet brain for
    the best-eligible up/enabled/non-drain node — the internal load balancer.

    يرفع :class:`WireguardPeerError` على أي فشل ولا يكتب شيئًا للقاعدة عند فشل CHR.
    """
    try:
        node = fleet_node_router.resolve_node(fleet_chr_node_id)
        client = fleet_node_router.build_client_for(node)
    except FleetNodeUnavailable as exc:
        raise WireguardPeerError("chr_not_configured", exc.message) from exc

    pub = (public_key or "").strip()
    priv = ""
    if not pub:
        priv, pub = generate_keypair()
    elif not is_valid_wg_pubkey(pub):
        raise WireguardPeerError(
            "invalid_pubkey",
            "المفتاح العام لـ WireGuard غير صالح (يجب 44 حرف base64).",
        )

    allowed = (allowed_ips or "").strip() or allocate_client_address()
    psk = generate_preshared_key() if use_preshared else ""

    try:
        server_pubkey = ensure_server_interface(client)
    except RouterOSError as exc:
        raise WireguardPeerError(
            "chr_iface_failed",
            "تعذّر تهيئة واجهة WireGuard على CHR: " + exc.message,
        ) from exc

    comment = f"hoberadius c{customer.id} {customer.company_name}"[:255]
    iface_name = (
        current_app.config.get("CHR_WIREGUARD_INTERFACE") or DEFAULT_INTERFACE
    ).strip() or DEFAULT_INTERFACE
    try:
        created = client.create_wireguard_peer(
            interface=iface_name,
            public_key=pub,
            allowed_address=allowed,
            preshared_key=psk,
            comment=comment,
            persistent_keepalive=(
                f"{int(keepalive_seconds or DEFAULT_KEEPALIVE_SECONDS)}s"
            ),
        )
    except RouterOSError as exc:
        raise WireguardPeerError(
            "chr_create_failed",
            "تعذّر إنشاء قرين WireGuard على CHR: " + exc.message,
        ) from exc

    peer_id = str(created.get(".id") or created.get("id") or "")
    endpoint = server_endpoint(node)
    name = _unique_peer_name(customer, label)
    peer = WireguardPeer(
        customer_id=customer.id,
        license_id=license_obj.id if license_obj else None,
        peer_name=name,
        interface_name=iface_name,
        public_key=pub,
        allowed_ips=allowed,
        endpoint_host=endpoint["public_host"],
        endpoint_port=endpoint["port"],
        server_public_key=server_pubkey,
        dns_servers=(dns_servers or "").strip()[:255],
        keepalive_seconds=int(keepalive_seconds or DEFAULT_KEEPALIVE_SECONDS),
        status="active",
        provisioning="manual",
        source="admin_manual",
        chr_provisioned=True,
        chr_peer_id=peer_id,
        chr_host=(node.public_ip or node.wg_mgmt_ip or "").strip(),
        fleet_chr_node_id=node.id,
        delivery_status="pending",
        created_by_admin_id=created_by_admin_id,
        notes=(notes or "").strip()[:2000],
    )
    _store_private_key(peer, priv)
    _store_preshared_key(peer, psk)
    db.session.add(peer)
    db.session.flush()
    return peer


def revoke_peer(peer: WireguardPeer) -> None:
    """يحذف القرين من CHR ويعلّم السجل ملغيًا. لا يُنفّذ commit.

    Targets the peer's home fleet node (the one ``provision_peer`` placed
    it on). Legacy peers with no fleet node id stamped fall back to the
    brain's pick — best-effort, but the operator should expect a manual
    cleanup if the legacy node has been removed.
    """
    if peer.chr_provisioned and peer.chr_peer_id:
        node = peer.fleet_chr_node or fleet_node_router.auto_pick_best_node()
        if node is None:
            raise WireguardPeerError(
                "no_fleet_node",
                "لا توجد عقدة في الأسطول لإلغاء القرين منها.",
            )
        try:
            client = fleet_node_router.build_client_for(node)
            client.remove_wireguard_peer(peer.chr_peer_id)
        except FleetNodeUnavailable as exc:
            raise WireguardPeerError("chr_not_configured", exc.message) from exc
        except RouterOSError as exc:
            raise WireguardPeerError(
                "chr_remove_failed",
                "تعذّر حذف القرين من CHR: " + exc.message,
            ) from exc
    peer.status = "revoked"
    peer.chr_provisioned = False


def set_peer_status(peer: WireguardPeer, status: str) -> None:
    """يعلّق/يفعّل القرين على CHR. نفس عقد العقدة في ``revoke_peer`` —
    الاستدعاء القديم عبر ``chr_settings`` كان يشير لموديول محذوف (NameError)."""
    target = (status or "").strip().lower()
    if target not in {"active", "suspended"}:
        raise WireguardPeerError("invalid_status", "حالة القرين غير مسموحة.")
    if peer.chr_provisioned and peer.chr_peer_id:
        node = peer.fleet_chr_node or fleet_node_router.auto_pick_best_node()
        if node is None:
            raise WireguardPeerError(
                "no_fleet_node",
                "لا توجد عقدة في الأسطول لتحديث حالة القرين عليها.",
            )
        try:
            client = fleet_node_router.build_client_for(node)
            client.set_wireguard_peer_disabled(peer.chr_peer_id, disabled=(target == "suspended"))
        except FleetNodeUnavailable as exc:
            raise WireguardPeerError("chr_not_configured", exc.message) from exc
        except RouterOSError as exc:
            raise WireguardPeerError(
                "chr_update_failed",
                "تعذّر تحديث القرين على CHR: " + exc.message,
            ) from exc
    peer.status = target


# ───────────────────────── delivery + serialization ─────────────────────────


def list_peers(customer: Customer | None = None) -> list[WireguardPeer]:
    q = WireguardPeer.query
    if customer is not None:
        q = q.filter_by(customer_id=customer.id)
    return q.order_by(WireguardPeer.created_at.desc(), WireguardPeer.id.desc()).all()


def acknowledge_delivery(customer: Customer, peer_names: list[str]) -> int:
    names = {str(n).strip() for n in (peer_names or []) if str(n).strip()}
    if not names:
        return 0
    rows = WireguardPeer.query.filter(
        WireguardPeer.customer_id == customer.id,
        WireguardPeer.peer_name.in_(names),
        WireguardPeer.delivery_status != "delivered",
    ).all()
    now = utcnow()
    for row in rows:
        row.delivery_status = "delivered"
        row.delivered_at = now
    return len(rows)


def render_peer_config(peer: WireguardPeer) -> str:
    """يُعيد تكوين قرين WireGuard جاهزًا للتثبيت (نص .conf).

    يُستعمل لمرة واحدة (تنزيل/QR) — المفاتيح الخاصة لا تُعرض بعد أول تسليم.
    """
    priv = get_private_key(peer)
    psk = get_preshared_key(peer)
    lines = [
        "[Interface]",
        f"PrivateKey = {priv}" if priv else "# PrivateKey = (managed externally)",
        f"Address = {peer.allowed_ips}",
    ]
    if peer.dns_servers:
        lines.append(f"DNS = {peer.dns_servers}")
    lines.append("")
    lines.append("[Peer]")
    lines.append(f"PublicKey = {peer.server_public_key}")
    if psk:
        lines.append(f"PresharedKey = {psk}")
    lines.append("AllowedIPs = 0.0.0.0/0")
    if peer.endpoint_host:
        lines.append(f"Endpoint = {peer.endpoint_host}:{peer.endpoint_port}")
    lines.append(f"PersistentKeepalive = {peer.keepalive_seconds}")
    return "\n".join(lines) + "\n"


def serialize_peer(peer: WireguardPeer, *, include_secrets: bool = False) -> dict:
    data = {
        "id": peer.id,
        "peer_name": peer.peer_name,
        "interface_name": peer.interface_name,
        "public_key": peer.public_key,
        "allowed_ips": peer.allowed_ips,
        "endpoint_host": peer.endpoint_host,
        "endpoint_port": peer.endpoint_port,
        "server_public_key": peer.server_public_key,
        "dns_servers": peer.dns_servers,
        "keepalive_seconds": peer.keepalive_seconds,
        "status": peer.status,
        "delivery_status": peer.delivery_status,
        "chr_provisioned": bool(peer.chr_provisioned),
        "created_at": _iso_z(peer.created_at),
    }
    if include_secrets and peer.delivery_status != "delivered" and peer.status != "revoked":
        data["private_key"] = get_private_key(peer)
        data["preshared_key"] = get_preshared_key(peer)
    return data


def _iso_z(value):
    if not value:
        return None
    return value.replace(microsecond=0).isoformat() + "Z"
