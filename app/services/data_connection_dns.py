"""DATA-connection DNS orchestration (2c) — panel side.

The panel's ENTIRE role in the cert flow is to make ``clientN.<zone>`` resolve
to the customer's RADIUS VPS, so the VPS's own certbot (HTTP-01) can issue the
SSTP cert (docs/design/ACCEL_PPP_DATA_CONNECTIONS.md §0, §2). This module is
that one job, wired together:

    customer.vps_ip  +  customer_fqdn(customer)  →  Cloudflare A record

It is the seam between the HTTP-only :mod:`app.services.cloudflare` client and
the ``Customer`` row: it reads the VPS IP + FQDN, calls the client, and writes
back ``dns_record_id`` / ``dns_synced_at`` so the operation is idempotent and
its state is surfaced read-only on the customer record.

Never raises on an API failure — returns a :class:`DnsSyncResult` the caller
turns into a toast + audit line. The cert is NOT issued here (the VPS owns it).
"""
from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass

from app.extensions import db
from app.models import Customer, utcnow

from . import cloudflare
from .customer_subdomain import assign_subdomain, customer_fqdn, get_zone_base

logger = logging.getLogger(__name__)


# Status codes a caller maps to a toast. Kept as plain strings so the audit
# log and the UI agree on vocabulary.
STATUS_OK = "ok"
STATUS_DELETED = "deleted"
STATUS_NOT_CONFIGURED = "not_configured"  # no Cloudflare token saved yet
STATUS_NO_IP = "no_ip"                    # customer has no VPS IP set
STATUS_INVALID_IP = "invalid_ip"          # VPS IP is not a valid address
STATUS_API_ERROR = "api_error"            # Cloudflare rejected the call


_AR_MESSAGES = {
    STATUS_OK: "تمت مزامنة سجل DNS للنطاق الفرعي بنجاح.",
    STATUS_DELETED: "تم حذف سجل DNS للنطاق الفرعي.",
    STATUS_NOT_CONFIGURED: "لم يتم ضبط رمز Cloudflare API في الإعدادات بعد.",
    STATUS_NO_IP: "لا يوجد عنوان IP للخادم VPS لهذا العميل.",
    STATUS_INVALID_IP: "عنوان IP للخادم VPS غير صالح.",
    STATUS_API_ERROR: "فشل الاتصال بـ Cloudflare. راجع الرمز والصلاحيات.",
}


@dataclass(frozen=True)
class DnsSyncResult:
    status: str
    fqdn: str = ""
    ip: str = ""
    record_id: str = ""
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.status in (STATUS_OK, STATUS_DELETED)

    @property
    def message_ar(self) -> str:
        base = _AR_MESSAGES.get(self.status, "تعذّر تنفيذ العملية.")
        if self.status == STATUS_API_ERROR and self.error:
            return f"{base} ({self.error})"
        return base


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address((value or "").strip())
        return True
    except ValueError:
        return False


def ensure_subdomain_record(customer: Customer, *, commit: bool = True) -> DnsSyncResult:
    """Ensure ``<subdomain>.<zone>`` is a DNS-only A record → ``customer.vps_ip``.

    Idempotent: assigns the subdomain if unset, upserts the A record, and
    records ``dns_record_id`` + ``dns_synced_at`` on the row. Gated behind a
    configured Cloudflare token — returns ``not_configured`` (no network) when
    the token is missing.
    """
    ip = (customer.vps_ip or "").strip()
    if not ip:
        return DnsSyncResult(STATUS_NO_IP)
    if not _valid_ip(ip):
        return DnsSyncResult(STATUS_INVALID_IP, ip=ip)

    # Gate on the token BEFORE assigning — on a fresh, unconfigured panel we
    # don't want a no-op click to persist a subdomain write. customer_fqdn()
    # still returns the deterministic clientN FQDN for display without writing.
    client = cloudflare.get_client()
    if client is None:
        return DnsSyncResult(STATUS_NOT_CONFIGURED, fqdn=customer_fqdn(customer), ip=ip)

    # Assign clientN now so the FQDN is concrete (no-op if already set).
    assign_subdomain(customer, commit=False)
    fqdn = customer_fqdn(customer)

    res = client.upsert_a_record(get_zone_base(), fqdn, ip)
    if not res.ok:
        return DnsSyncResult(STATUS_API_ERROR, fqdn=fqdn, ip=ip, error=res.error)

    record_id = res.record.id if res.record else ""
    customer.dns_record_id = record_id
    customer.dns_synced_at = utcnow()
    if commit:
        db.session.commit()
    else:
        db.session.flush()
    logger.info("data_connection_dns: synced %s -> %s (record=%s)", fqdn, ip, record_id)
    return DnsSyncResult(STATUS_OK, fqdn=fqdn, ip=ip, record_id=record_id)


def remove_subdomain_record(customer: Customer, *, commit: bool = True) -> DnsSyncResult:
    """Delete the customer's DNS record and clear the bookkeeping. Idempotent —
    an already-absent record is success (the client treats a 404 as gone)."""
    fqdn = customer_fqdn(customer)
    client = cloudflare.get_client()
    if client is None:
        # No token → we CANNOT delete the real Cloudflare record. Do NOT clear
        # the stored record_id: that would orphan the live record (lose the
        # handle to delete it later). Report not-configured so the operator
        # adds the token first.
        return DnsSyncResult(STATUS_NOT_CONFIGURED, fqdn=fqdn,
                             record_id=(customer.dns_record_id or "").strip())

    res = client.delete_a_record(get_zone_base(), fqdn,
                                 record_id=(customer.dns_record_id or "").strip())
    if not res.ok:
        return DnsSyncResult(STATUS_API_ERROR, fqdn=fqdn, error=res.error)

    customer.dns_record_id = ""
    customer.dns_synced_at = None
    if commit:
        db.session.commit()
    else:
        db.session.flush()
    logger.info("data_connection_dns: removed record for %s", fqdn)
    return DnsSyncResult(STATUS_DELETED, fqdn=fqdn)


@dataclass(frozen=True)
class DnsDiagnosis:
    """Read-only, non-mutating live probe of the customer-subdomain DNS state —
    answers «was the API call possible, and does the record actually exist?»."""
    token_present: bool
    token_source: str
    token_readable: bool
    zone_base: str
    fqdn: str
    expected_ip: str
    zone_ok: bool
    zone_id: str
    record_exists: bool
    record_ip: str
    record_proxied: bool
    record_matches_ip: bool
    error: str
    verdict_ar: str
    healthy: bool


def diagnose(customer: Customer) -> DnsDiagnosis:
    """Probe — WITHOUT changing anything — exactly why a customer's subdomain
    does/doesn't resolve: is the token present + readable, can we reach the
    zone, and does the A record exist (DNS-only, pointing at the VPS IP)?

    This answers "was the API call made and what did Cloudflare say".
    """
    from . import platform_settings as ps
    present, source, readable = ps.secret_state(cloudflare.CLOUDFLARE_API_TOKEN_KEY)
    zone_base = get_zone_base()
    fqdn = customer_fqdn(customer)
    ip = (customer.vps_ip or "").strip()
    rtype = "AAAA" if ":" in ip else "A"

    def _d(*, zone_ok=False, zone_id="", record_exists=False, record_ip="",
           record_proxied=False, record_matches=False, error="", verdict="", healthy=False):
        return DnsDiagnosis(present, source, readable, zone_base, fqdn, ip,
                            zone_ok, zone_id, record_exists, record_ip, record_proxied,
                            record_matches, error, verdict, healthy)

    if not ip:
        return _d(verdict="لا يوجد عنوان IP للخادم VPS — أدخله أولًا ثم زامن النطاق.")
    if not present:
        return _d(verdict=("رمز Cloudflare API غير مضبوط في إعدادات المنصة (حقل «رمز Cloudflare API»). "
                           "أضِف رمزًا بصلاحية Zone.DNS:Edit على النطاق ثم أعد المزامنة."))
    if not readable:
        return _d(error="token present but not decryptable",
                  verdict=("الرمز محفوظ لكن تعذّر فك تشفيره (تغيّر مفتاح التشفير الرئيسي للوحة؟). "
                           "أعد إدخال رمز Cloudflare في الإعدادات."))
    client = cloudflare.get_client()
    if client is None:  # defensive — present+readable should yield a client
        return _d(error="client unavailable", verdict="تعذّر بناء عميل Cloudflare رغم وجود الرمز.")

    zr = client.find_zone_id(zone_base)
    if not zr.ok:
        return _d(error=zr.error,
                  verdict=(f"تعذّر الوصول إلى النطاق {zone_base}: {zr.error}. "
                           f"تأكّد أن الرمز له صلاحية Zone.DNS:Edit على {zone_base} وأن النطاق على هذا الحساب."))
    rr = client.find_a_record(zr.zone_id, fqdn, rtype=rtype)
    if not rr.ok:
        return _d(zone_ok=True, zone_id=zr.zone_id, error=rr.error,
                  verdict=f"النطاق متاح لكن فشل الاستعلام عن سجل {fqdn}: {rr.error}.")
    if rr.record is None:
        return _d(zone_ok=True, zone_id=zr.zone_id,
                  verdict=(f"النطاق {zone_base} متاح والرمز يعمل، لكن لا يوجد سجل {fqdn} بعد. "
                           f"اضغط «مزامنة النطاق الفرعي (DNS)» لإنشائه ← {ip}."))
    rec = rr.record
    matches = rec.content.strip() == ip
    if rec.proxied:
        return _d(zone_ok=True, zone_id=zr.zone_id, record_exists=True, record_ip=rec.content,
                  record_proxied=True, record_matches=matches,
                  verdict=("السجل موجود لكنه عبر بروكسي Cloudflare (السحابة البرتقالية). يجب أن يكون «DNS فقط» "
                           "ليصل SSTP مباشرة إلى الخادم. أعد المزامنة (تُنشئه DNS-only)."))
    if not matches:
        return _d(zone_ok=True, zone_id=zr.zone_id, record_exists=True, record_ip=rec.content,
                  record_matches=False,
                  verdict=f"السجل موجود لكنه يشير إلى {rec.content} بدل {ip}. أعد المزامنة لتحديثه.")
    return _d(zone_ok=True, zone_id=zr.zone_id, record_exists=True, record_ip=rec.content,
              record_matches=True, healthy=True,
              verdict=(f"سليم: {fqdn} ← {rec.content} (DNS فقط). إن لم يُحَل بعد على جهازك، "
                       "انتظر دقيقة لانتشار DNS ثم جرّب مجددًا."))


__all__ = [
    "DnsSyncResult",
    "DnsDiagnosis",
    "diagnose",
    "ensure_subdomain_record",
    "remove_subdomain_record",
    "STATUS_OK",
    "STATUS_DELETED",
    "STATUS_NOT_CONFIGURED",
    "STATUS_NO_IP",
    "STATUS_INVALID_IP",
    "STATUS_API_ERROR",
]
