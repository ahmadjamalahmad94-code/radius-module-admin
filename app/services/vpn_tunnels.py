"""تزويد أنفاق VPN مركزيًا على CHR (الطبقة الأساسية).

يربط هذا الملف بين: توليد بيانات الاعتماد، احترام حدّ اتصالات العضو، الإنشاء
الفعلي على CHR عبر RouterOS REST، الحفظ، التدقيق، والتسليم عبر الجسر.

نموذج الأدوار:
* ``CustomerVpnEntitlement`` = الصلاحية التجارية (سرعة/مستخدمون/مواقع).
* ``CustomerVpnTunnel`` = حساب نفق فعلي على CHR (هذا الملف ينشئه).

أنواع الأنفاق:
* SSTP/PPTP/L2TP → تُنشأ فعليًا كـ ``/ppp/secret`` على CHR.
* IPsec (IKEv2) → نظام مستقل على RouterOS (``/ip/ipsec``)؛ يُنشأ تلقائيًا الآن:
  تُهيَّأ البنية المشتركة (mode-config/peer/identity) مرّة واحدة (idempotent)،
  ثم لكل مستخدم تُنشأ بيانات اعتماد ``/ip/ipsec/user`` (EAP-MSCHAPv2). يمكن
  تعطيل الأتمتة (``CHR_IPSEC_AUTO_PROVISION=0``) فيعود السلوك «سجل فقط».

كلمات مرور الأنفاق تُخزَّن مشفّرة (Fernet عبر ``customer_vault_crypto``) وتُعاد
صريحة عبر الجسر مرة واحدة فقط حتى يؤكّد العميل الاستلام (delivery_status).
"""
from __future__ import annotations

import secrets
import string

from flask import current_app

from ..extensions import db
from ..models import ChrSpeedProfile, Customer, CustomerVpnTunnel, License, utcnow
from . import chr_settings
from . import speed_profiles
from .customer_vault_crypto import decrypt_secret, encrypt_secret, mask_secret
from .routeros_client import RouterOSError
from .vpn_entitlements import get_customer_vpn_entitlement

# الأنواع المدعومة وتعيينها إلى خدمة RouterOS على /ppp/secret.
PPP_SERVICES = {"sstp", "pptp", "l2tp", "ovpn"}
# IPsec/IKEv2 يُزوَّد عبر /ip/ipsec (لا /ppp/secret). تلقائي ما لم يُعطَّل بالإعداد.
IPSEC_TYPES = {"ipsec"}
TUNNEL_TYPES = PPP_SERVICES | IPSEC_TYPES
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


# ───────────────────────── speed resolution ─────────────────────────

def _resolve_speed(speed_profile_id, download_mbps, upload_mbps) -> dict:
    """يحلّ السرعة المطلوبة: بروفايل محفوظ يفوز، وإلا سرعة مخصّصة، وإلا بلا تشكيل.

    يعيد dict موحّداً: ``profile_id`` و``download_mbps`` و``upload_mbps`` و
    ``chr_profile_name`` (اسم /ppp/profile على CHR، فارغ ⇒ استخدم الافتراضي) و
    ``rate_limit`` (سلسلة RouterOS، فارغة ⇒ بلا تشكيل)."""
    blank = {"profile_id": None, "download_mbps": None, "upload_mbps": None,
             "chr_profile_name": "", "rate_limit": ""}
    if speed_profile_id:
        profile = speed_profiles.get(speed_profile_id)
        if not profile or not profile.active:
            raise VpnTunnelError("invalid_speed_profile", "بروفايل السرعة غير موجود أو معطّل.")
        return {
            "profile_id": profile.id,
            "download_mbps": profile.download_mbps,
            "upload_mbps": profile.upload_mbps,
            "chr_profile_name": profile.effective_chr_profile_name,
            "rate_limit": speed_profiles.rate_limit_string(profile.download_mbps, profile.upload_mbps),
        }
    try:
        down = int(download_mbps) if download_mbps not in (None, "") else 0
        up = int(upload_mbps) if upload_mbps not in (None, "") else 0
    except (TypeError, ValueError):
        raise VpnTunnelError("invalid_speed", "السرعة يجب أن تكون أرقامًا صحيحة (Mbps).")
    if down < 0 or up < 0:
        raise VpnTunnelError("invalid_speed", "السرعة لا يمكن أن تكون سالبة.")
    if not (down and up):
        return blank  # لم تُطلب سرعة صريحة → بلا تشكيل (البروفايل الافتراضي)
    return {
        "profile_id": None,
        "download_mbps": down,
        "upload_mbps": up,
        "chr_profile_name": speed_profiles.custom_profile_name(down, up),
        "rate_limit": speed_profiles.rate_limit_string(down, up),
    }


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
    speed_profile_id: int | None = None,
    download_mbps: int | None = None,
    upload_mbps: int | None = None,
    monthly_quota_gb: int | None = None,
    throttle_down_mbps: int | None = None,
    throttle_up_mbps: int | None = None,
    source: str = "bridge_request",
    requested_by_user_id: int | None = None,
    created_by_admin_id: int | None = None,
    notes: str = "",
    enforce_allowance: bool = True,
) -> CustomerVpnTunnel:
    """يولّد بيانات اعتماد فريدة، يحترم حدّ العضو، ينشئ الحساب على CHR (لأنواع
    PPP)، يحفظ السجل ويعيده. يرفع :class:`VpnTunnelError` عند أي فشل.

    التحكّم بالسرعة: مرّر ``speed_profile_id`` (بروفايل سرعة محفوظ) أو
    ``download_mbps``/``upload_mbps`` (سرعة مخصّصة). للأنواع PPP تُهيَّأ
    ``/ppp/profile`` بالـ``rate-limit`` المناسب على CHR ويُسنَد للحساب، فيعمل
    الاتصال بالسرعة المختارة لا الافتراضية. IPsec لا يدعم rate-limit عبر PPP —
    تُسجَّل السرعة فقط (انظر الملاحظة) دون تشكيل آلي.

    لا يُنفّذ ``commit`` — يترك ذلك للمستدعي.
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

    # حلّ السرعة: بروفايل محفوظ يفوز، وإلا سرعة مخصّصة، وإلا بلا تشكيل.
    speed = _resolve_speed(speed_profile_id, download_mbps, upload_mbps)

    username = _generate_username(customer)
    password = _generate_password()
    default_profile = (profile or current_app.config.get("CHR_DEFAULT_PPP_PROFILE", "default")).strip() or "default"
    # عند وجود سرعة، اسم البروفايل على CHR هو بروفايل السرعة؛ وإلا الافتراضي.
    profile = speed["chr_profile_name"] or default_profile
    per_conn = int(max_connections) if max_connections else 1
    chr_host = ""
    chr_secret_id = ""
    chr_provisioned = False
    record_only = False
    comment = f"hoberadius c{customer.id} {customer.company_name}"[:255]

    if ttype in PPP_SERVICES:
        if not chr_settings.enabled():
            raise VpnTunnelError("chr_disabled", "تزويد CHR غير مُفعّل في إعدادات اللوحة.")
        chr_host = chr_settings.resolved().get("host", "")
        try:
            client = chr_settings.build_client()
        except chr_settings.ChrSettingsError as exc:
            raise VpnTunnelError("chr_not_configured", str(exc)) from exc
        # هيّئ العنونة والبروفايل على CHR (idempotent) قبل إنشاء الحساب. حرج: بدون
        # local/remote-address يصادق العميل لكن لا يأخذ IPv4. نضمن pool مشترك واحد ثم
        # نضبط البروفايل (حتى الافتراضي) بالعناوين + rate-limit إن وُجد — لكل الأنواع.
        cfg = current_app.config
        pool_name = (cfg.get("CHR_PPP_ADDRESS_POOL") or "ppp-vpn-pool").strip() or "ppp-vpn-pool"
        local_addr = (cfg.get("CHR_PPP_LOCAL_ADDRESS") or "10.10.0.1").strip() or "10.10.0.1"
        pool_ranges = (cfg.get("CHR_PPP_POOL_RANGES") or "10.10.0.10-10.10.0.250").strip()
        use_enc = bool(cfg.get("CHR_PPP_USE_ENCRYPTION", True))
        # Hard guard: PPP gateway + pool ranges MUST stay out of the wg-mgmt
        # (10.99.0.0/24) and wg-data (10.98.0.0/24) reserved subnets — see
        # app/services/reserved_subnets.py. Collision there steals the
        # proxy's RADIUS path (the 2026-06 chr-vpn-1 incident).
        from .reserved_subnets import (
            ReservedSubnetError,
            assert_address_not_reserved,
            assert_pool_range_not_reserved,
        )
        try:
            assert_address_not_reserved(local_addr, field_label="CHR_PPP_LOCAL_ADDRESS")
            assert_pool_range_not_reserved(pool_ranges, field_label="CHR_PPP_POOL_RANGES")
        except ReservedSubnetError as exc:
            raise VpnTunnelError("reserved_subnet", str(exc)) from exc
        try:
            client.ensure_ip_pool(name=pool_name, ranges=pool_ranges)
            client.ensure_ppp_profile(
                name=profile,
                rate_limit=speed["rate_limit"],
                local_address=local_addr,
                remote_address=pool_name,
                use_encryption=use_enc,
            )
        except RouterOSError as exc:
            raise VpnTunnelError(
                "chr_profile_failed", "تعذّر تهيئة بروفايل/عنونة CHR: " + exc.message
            ) from exc
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
    elif ttype in IPSEC_TYPES:
        if chr_settings.enabled() and current_app.config.get("CHR_IPSEC_AUTO_PROVISION", True):
            chr_host = chr_settings.resolved().get("host", "")
            try:
                client = chr_settings.build_client()
            except chr_settings.ChrSettingsError as exc:
                raise VpnTunnelError("chr_not_configured", str(exc)) from exc
            try:
                chr_secret_id = _provision_ipsec_user(client, username, password, comment)
            except RouterOSError as exc:
                # لا نحفظ سجلًا نصف مكتمل عند فشل CHR؛ نرفع الخطأ للمستدعي.
                raise VpnTunnelError(
                    "chr_create_failed", "تعذّر إنشاء مستخدم IPsec على CHR: " + exc.message
                ) from exc
            chr_provisioned = True
        else:
            # الأتمتة معطّلة (أو CHR غير مُفعّل): سجل فقط — يُضبط على CHR يدويًا.
            record_only = True

    # IPsec لا يُشكَّل عبر rate-limit الخاص بـ PPP؛ نُبقي السرعة مسجَّلة فقط ولا نضع
    # rate_limit مُطبَّقًا، مع ملاحظة صريحة بدل تجاهل صامت.
    applied_rate_limit = speed["rate_limit"] if ttype in PPP_SERVICES else ""

    tunnel = CustomerVpnTunnel(
        customer_id=customer.id,
        license_id=license_obj.id if license_obj else None,
        tunnel_type=ttype,
        username=username,
        profile=profile,
        max_connections=per_conn,
        speed_profile_id=speed["profile_id"],
        download_mbps=speed["download_mbps"],
        upload_mbps=speed["upload_mbps"],
        rate_limit=applied_rate_limit,
        monthly_quota_gb=(int(monthly_quota_gb) if monthly_quota_gb else None),
        throttle_down_mbps=(int(throttle_down_mbps) if throttle_down_mbps else None),
        throttle_up_mbps=(int(throttle_up_mbps) if throttle_up_mbps else None),
        quota_period="",
        quota_bytes_used=0,
        quota_sample_bytes=0,
        is_throttled=False,
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
    if record_only:
        note = "نفق IPsec: سجل فقط (الأتمتة معطّلة) — اضبط mode-config/peer/identity ومستخدم IPsec على CHR يدويًا."
        tunnel.notes = (tunnel.notes + ("\n" if tunnel.notes else "") + note)[:2000]
    if ttype in IPSEC_TYPES and (speed["download_mbps"] or speed["upload_mbps"]):
        note = (
            f"السرعة المطلوبة ({speed['download_mbps']}↓/{speed['upload_mbps']}↑ Mbps) مسجَّلة فقط — "
            "IPsec لا يُشكَّل عبر rate-limit الخاص بـ PPP؛ طبّق طابورًا (simple queue) على CHR إن لزم."
        )
        tunnel.notes = (tunnel.notes + ("\n" if tunnel.notes else "") + note)[:2000]
    set_tunnel_password(tunnel, password)
    db.session.add(tunnel)
    db.session.flush()
    return tunnel


def _ipsec_infra_names() -> tuple[str, str]:
    cfg = current_app.config
    mode_config = (cfg.get("CHR_IPSEC_MODE_CONFIG") or "hoberadius").strip() or "hoberadius"
    peer = (cfg.get("CHR_IPSEC_PEER") or "hoberadius").strip() or "hoberadius"
    return mode_config, peer


def _ensure_ipsec_infra(client) -> None:
    """يهيّئ البنية المشتركة لـ IKEv2 مرّة واحدة (idempotent).

    قابل للتعطيل بـ ``CHR_IPSEC_MANAGE_INFRA=0`` إن كان المالك قد ضبط المستمع
    (responder) يدويًا — عندها نكتفي بإدارة مستخدمي ``/ip/ipsec/user``.
    """
    cfg = current_app.config
    if not cfg.get("CHR_IPSEC_MANAGE_INFRA", True):
        return
    # الشهادة ومجمّع العناوين يضبطهما المالك من الواجهة (DB→بيئة)؛ نفضّلهما على config
    # المباشر. اسم الشهادة قد يحتوي مسافات فيُستعمل حرفيًا كما خُزِّن.
    overrides = chr_settings.ipsec_overrides()
    address_pool = overrides["address_pool"] or (cfg.get("CHR_IPSEC_ADDRESS_POOL") or "").strip()
    certificate = overrides["certificate"] or (cfg.get("CHR_IPSEC_CERTIFICATE") or "").strip()
    mode_config, peer = _ipsec_infra_names()
    client.ensure_ipsec_mode_config(
        name=mode_config,
        address_pool=address_pool,
        static_dns=(cfg.get("CHR_IPSEC_DNS") or "").strip(),
    )
    client.ensure_ipsec_peer(
        name=peer,
        profile=(cfg.get("CHR_IPSEC_PROFILE") or "default").strip() or "default",
    )
    client.ensure_ipsec_identity(
        peer=peer,
        mode_config=mode_config,
        eap_methods=(cfg.get("CHR_IPSEC_EAP_METHODS") or "eap-mschapv2").strip() or "eap-mschapv2",
        certificate=certificate,
    )


def _provision_ipsec_user(client, username: str, password: str, comment: str) -> str:
    """يهيّئ البنية المشتركة ثم ينشئ ``/ip/ipsec/user`` (idempotent) ويعيد معرّفه.

    إن وُجد المستخدم سلفًا (إعادة محاولة بعد فقد رد) لا يُكرَّر — يُعاد معرّفه.
    """
    _ensure_ipsec_infra(client)
    existing = client.find_ipsec_user(username)
    if existing:
        return str(existing.get(".id") or existing.get("id") or "")
    created = client.create_ipsec_user(name=username, password=password, comment=comment)
    return str(created.get(".id") or created.get("id") or "")


def revoke_tunnel(tunnel: CustomerVpnTunnel) -> None:
    """يحذف الحساب من CHR (إن وُجد) ويعلّم السجل ملغيًا. لا يُنفّذ commit."""
    if tunnel.chr_provisioned and tunnel.chr_secret_id:
        try:
            client = chr_settings.build_client()
            if tunnel.tunnel_type in PPP_SERVICES:
                client.remove_ppp_secret(tunnel.chr_secret_id)
            elif tunnel.tunnel_type in IPSEC_TYPES:
                client.remove_ipsec_user(tunnel.chr_secret_id)
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
    if tunnel.chr_provisioned and tunnel.chr_secret_id:
        try:
            client = chr_settings.build_client()
            if tunnel.tunnel_type in PPP_SERVICES:
                client.set_ppp_secret_disabled(tunnel.chr_secret_id, disabled=(target == "suspended"))
            elif tunnel.tunnel_type in IPSEC_TYPES:
                client.set_ipsec_user_disabled(tunnel.chr_secret_id, disabled=(target == "suspended"))
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
    endpoint = chr_settings.public_endpoint()
    data = {
        "username": tunnel.username,
        "tunnel_type": tunnel.tunnel_type,
        "service": tunnel.tunnel_type,
        "profile": tunnel.profile,
        "status": tunnel.status,
        "max_connections": tunnel.max_connections,
        # السرعة المطبَّقة (معلومة لا سرّ) كي يعرضها العميل/الواجهة.
        "download_mbps": tunnel.download_mbps,
        "upload_mbps": tunnel.upload_mbps,
        # العنوان العام والمنفذ اللذان يتصل بهما عميلُ العميل لهذه الخدمة. نتعمّد عدم
        # تسريب مضيف REST الإداري (``tunnel.chr_host``) عبر الجسر: لوحة العميل لا
        # تملك ولا تحتاج نقطة إدارة CHR — فقط العنوان العام للاتصال. للتوافق نُبقي
        # مفتاح ``chr_host`` لكن نملؤه بالعنوان العام نفسه (لا المضيف الإداري).
        "chr_host": endpoint["public_host"],
        "chr_public_host": endpoint["public_host"],
        "service_port": endpoint["ports"].get(tunnel.tunnel_type),
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
