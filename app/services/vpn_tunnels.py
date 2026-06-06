"""تزويد أنفاق VPN مركزيًا على CHR (الطبقة الأساسية).

يربط هذا الملف بين: توليد بيانات الاعتماد، احترام حدّ اتصالات العضو، الإنشاء
الفعلي على CHR عبر RouterOS REST، الحفظ، التدقيق، والتسليم عبر الجسر.

نموذج الأدوار:
* ``CustomerVpnEntitlement`` = الصلاحية التجارية (سرعة/مستخدمون/مواقع).
* ``CustomerVpnTunnel`` = حساب نفق فعلي على CHR (هذا الملف ينشئه).

أنواع الأنفاق:
* SSTP/PPTP/L2TP → تُنشأ فعليًا كـ ``/ppp/secret`` على CHR.
* IPsec (IKEv2) → نظام مختلف على RouterOS (``/ip/ipsec``)؛ في المرحلة الأولى
  يُسجَّل السجل ويُسلَّم عبر الجسر دون إنشاء تلقائي على CHR (يُضبط يدويًا).
  انظر التقرير/التوثيق.

كلمات مرور الأنفاق تُخزَّن مشفّرة (Fernet عبر ``customer_vault_crypto``) وتُعاد
صريحة عبر الجسر مرة واحدة فقط حتى يؤكّد العميل الاستلام (delivery_status).
"""
from __future__ import annotations

import secrets
import string

from flask import current_app

from ..extensions import db
from ..models import Customer, CustomerVpnTunnel, License, utcnow
from . import chr_settings
from .customer_vault_crypto import decrypt_secret, encrypt_secret, mask_secret
from .routeros_client import RouterOSError
from .vpn_entitlements import get_customer_vpn_entitlement

# الأنواع المدعومة وتعيينها إلى خدمة RouterOS على /ppp/secret.
PPP_SERVICES = {"sstp", "pptp", "l2tp", "ovpn"}
RECORD_ONLY_TYPES = {"ipsec"}
TUNNEL_TYPES = PPP_SERVICES | RECORD_ONLY_TYPES
# ما يُسمح بطلبه تلقائيًا عبر الجسر من لوحة العميل (SSTP فقط حسب القرار المعماري).
BRIDGE_AUTO_TYPES = {"sstp"}
# ما يُنشئه المدير يدويًا من «عرض العميل 360».
MANUAL_TYPES = {"pptp", "l2tp", "ipsec", "sstp"}

ACTIVE_STATUSES = {"pending", "active", "suspended"}

TUNNEL_TYPE_LABELS = {
    "sstp": "SSTP",
    "pptp": "PPTP",
    "l2tp": "L2TP",
    "ovpn": "OpenVPN",
    "ipsec": "IPsec",
}


class VpnTunnelError(ValueError):
    """خطأ تزويد يُعرض للمستدعي (واجهة المدير أو رد الجسر) — رسالة عربية."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


# ───────────────────────── credential generation ─────────────────────────

_USERNAME_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"
_PASSWORD_ALPHABET = string.ascii_letters + string.digits


def _generate_username(customer: Customer) -> str:
    """اسم مستخدم فريد على مستوى CHR، مرتبط بالعميل للتتبّع."""
    for _ in range(50):
        suffix = "".join(secrets.choice(_USERNAME_ALPHABET) for _ in range(8))
        username = f"c{customer.id}-{suffix}"
        if not CustomerVpnTunnel.query.filter_by(username=username).first():
            return username
    raise VpnTunnelError("username_collision", "تعذّر توليد اسم مستخدم فريد للنفق.")


def _generate_password(length: int = 20) -> str:
    return "".join(secrets.choice(_PASSWORD_ALPHABET) for _ in range(length))


def set_tunnel_password(tunnel: CustomerVpnTunnel, plaintext: str) -> None:
    tunnel.password_encrypted = encrypt_secret(plaintext)
    tunnel.password_hint = mask_secret(plaintext)


def get_tunnel_password(tunnel: CustomerVpnTunnel) -> str:
    if not tunnel.password_encrypted:
        return ""
    return decrypt_secret(tunnel.password_encrypted)


# ───────────────────────── allowance enforcement ─────────────────────────

def effective_connection_allowance(customer: Customer) -> int:
    """أقصى عدد أنفاق متزامنة مسموح للعميل: من صلاحية VPN (max_vpn_users) وإلا
    من ``CHR_DEFAULT_MAX_TUNNELS``."""
    entitlement = get_customer_vpn_entitlement(customer)
    if entitlement and entitlement.max_vpn_users:
        try:
            value = int(entitlement.max_vpn_users)
            if value > 0:
                return value
        except (TypeError, ValueError):
            pass
    return int(current_app.config.get("CHR_DEFAULT_MAX_TUNNELS", 5))


def count_active_tunnels(customer: Customer) -> int:
    return CustomerVpnTunnel.query.filter(
        CustomerVpnTunnel.customer_id == customer.id,
        CustomerVpnTunnel.status.in_(ACTIVE_STATUSES),
    ).count()


# ───────────────────────── provisioning ─────────────────────────

def provision_tunnel(
    customer: Customer,
    license_obj: License | None,
    *,
    tunnel_type: str = "sstp",
    profile: str = "",
    max_connections: int | None = None,
    source: str = "bridge_request",
    requested_by_user_id: int | None = None,
    created_by_admin_id: int | None = None,
    notes: str = "",
    enforce_allowance: bool = True,
) -> CustomerVpnTunnel:
    """يولّد بيانات اعتماد فريدة، يحترم حدّ العضو، ينشئ الحساب على CHR (لأنواع
    PPP)، يحفظ السجل ويعيده. يرفع :class:`VpnTunnelError` عند أي فشل.

    لا يُنفّذ ``commit`` — يترك ذلك للمستدعي (المسار) كي تبقى العملية ذرّية مع
    التدقيق المرافق.
    """
    ttype = (tunnel_type or "sstp").strip().lower()
    if ttype not in TUNNEL_TYPES:
        raise VpnTunnelError("invalid_type", "نوع النفق غير مدعوم.")

    if enforce_allowance:
        allowance = effective_connection_allowance(customer)
        if count_active_tunnels(customer) >= allowance:
            raise VpnTunnelError(
                "limit_reached",
                f"بلغ العميل الحدّ المسموح من الأنفاق ({allowance}). علّق أو احذف نفقًا أولًا.",
            )

    username = _generate_username(customer)
    password = _generate_password()
    profile = (profile or current_app.config.get("CHR_DEFAULT_PPP_PROFILE", "default")).strip() or "default"
    per_conn = int(max_connections) if max_connections else 1
    chr_host = ""
    chr_secret_id = ""
    chr_provisioned = False

    if ttype in PPP_SERVICES:
        if not chr_settings.enabled():
            raise VpnTunnelError("chr_disabled", "تزويد CHR غير مُفعّل في إعدادات اللوحة.")
        creds = chr_settings.resolved()
        chr_host = creds.get("host", "")
        try:
            client = chr_settings.build_client()
        except chr_settings.ChrSettingsError as exc:
            raise VpnTunnelError("chr_not_configured", str(exc)) from exc
        comment = f"hoberadius c{customer.id} {customer.company_name}"[:255]
        try:
            created = client.create_ppp_secret(
                name=username,
                password=password,
                service=ttype,
                profile=profile,
                comment=comment,
            )
        except RouterOSError as exc:
            # لا نحفظ سجلًا نصف مكتمل عند فشل CHR؛ نرفع الخطأ للمستدعي.
            raise VpnTunnelError("chr_create_failed", "تعذّر إنشاء الحساب على CHR: " + exc.message) from exc
        chr_secret_id = str(created.get(".id") or created.get("id") or "")
        chr_provisioned = True

    tunnel = CustomerVpnTunnel(
        customer_id=customer.id,
        license_id=license_obj.id if license_obj else None,
        tunnel_type=ttype,
        username=username,
        profile=profile,
        max_connections=per_conn,
        status="active",
        provisioning="auto" if source == "bridge_request" else "manual",
        source=source,
        chr_provisioned=chr_provisioned,
        chr_secret_id=chr_secret_id,
        chr_host=chr_host,
        delivery_status="pending",
        requested_by_user_id=requested_by_user_id,
        created_by_admin_id=created_by_admin_id,
        notes=(notes or "").strip()[:2000],
    )
    if ttype in RECORD_ONLY_TYPES:
        note = "نفق IPsec: سجل فقط في المرحلة الأولى — اضبط الند/الهوية على CHR يدويًا."
        tunnel.notes = (tunnel.notes + ("\n" if tunnel.notes else "") + note)[:2000]
    set_tunnel_password(tunnel, password)
    db.session.add(tunnel)
    db.session.flush()
    return tunnel


def revoke_tunnel(tunnel: CustomerVpnTunnel) -> None:
    """يحذف الحساب من CHR (إن وُجد) ويعلّم السجل ملغيًا. لا يُنفّذ commit."""
    if tunnel.chr_provisioned and tunnel.chr_secret_id and tunnel.tunnel_type in PPP_SERVICES:
        try:
            client = chr_settings.build_client()
            client.remove_ppp_secret(tunnel.chr_secret_id)
        except chr_settings.ChrSettingsError as exc:
            raise VpnTunnelError("chr_not_configured", str(exc)) from exc
        except RouterOSError as exc:
            raise VpnTunnelError("chr_remove_failed", "تعذّر حذف الحساب من CHR: " + exc.message) from exc
    tunnel.status = "revoked"
    tunnel.chr_provisioned = False


def set_tunnel_status(tunnel: CustomerVpnTunnel, status: str) -> None:
    """يعلّق/يفعّل النفق على CHR (disabled) ويحدّث الحالة. لا يُنفّذ commit."""
    target = (status or "").strip().lower()
    if target not in {"active", "suspended"}:
        raise VpnTunnelError("invalid_status", "حالة النفق غير مسموحة.")
    if tunnel.chr_provisioned and tunnel.chr_secret_id and tunnel.tunnel_type in PPP_SERVICES:
        try:
            client = chr_settings.build_client()
            client.set_ppp_secret_disabled(tunnel.chr_secret_id, disabled=(target == "suspended"))
        except chr_settings.ChrSettingsError as exc:
            raise VpnTunnelError("chr_not_configured", str(exc)) from exc
        except RouterOSError as exc:
            raise VpnTunnelError("chr_update_failed", "تعذّر تحديث الحساب على CHR: " + exc.message) from exc
    tunnel.status = target


# ───────────────────────── delivery (bridge) ─────────────────────────

def list_tunnels(customer: Customer) -> list[CustomerVpnTunnel]:
    return (
        CustomerVpnTunnel.query.filter_by(customer_id=customer.id)
        .order_by(CustomerVpnTunnel.created_at.desc(), CustomerVpnTunnel.id.desc())
        .all()
    )


def deliverable_tunnels(customer: Customer) -> list[CustomerVpnTunnel]:
    """الأنفاق غير الملغاة التي يحتاجها العميل (تُسلَّم عبر الجسر)."""
    return (
        CustomerVpnTunnel.query.filter(
            CustomerVpnTunnel.customer_id == customer.id,
            CustomerVpnTunnel.status != "revoked",
        )
        .order_by(CustomerVpnTunnel.id.asc())
        .all()
    )


def acknowledge_delivery(customer: Customer, usernames: list[str]) -> int:
    """يعلّم أنفاقًا بأن العميل استلمها (فيتوقف إرجاع كلمة المرور الصريحة لها)."""
    names = {str(u).strip() for u in (usernames or []) if str(u).strip()}
    if not names:
        return 0
    rows = CustomerVpnTunnel.query.filter(
        CustomerVpnTunnel.customer_id == customer.id,
        CustomerVpnTunnel.username.in_(names),
        CustomerVpnTunnel.delivery_status != "delivered",
    ).all()
    now = utcnow()
    for row in rows:
        row.delivery_status = "delivered"
        row.delivered_at = now
    return len(rows)


def serialize_tunnel(tunnel: CustomerVpnTunnel, *, include_password: bool = False) -> dict:
    """تمثيل JSON لنفق. كلمة المرور الصريحة تُدرَج فقط حين ``include_password`` وعند
    الحاجة (تسليم لم يُؤكَّد بعد)."""
    data = {
        "username": tunnel.username,
        "tunnel_type": tunnel.tunnel_type,
        "service": tunnel.tunnel_type,
        "profile": tunnel.profile,
        "status": tunnel.status,
        "max_connections": tunnel.max_connections,
        "chr_host": tunnel.chr_host,
        "chr_provisioned": bool(tunnel.chr_provisioned),
        "delivery_status": tunnel.delivery_status,
        "created_at": _iso_z(tunnel.created_at),
    }
    if include_password and tunnel.delivery_status != "delivered" and tunnel.status != "revoked":
        data["password"] = get_tunnel_password(tunnel)
    return data


def _iso_z(value):
    if not value:
        return None
    return value.replace(microsecond=0).isoformat() + "Z"
