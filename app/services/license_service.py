from __future__ import annotations

import calendar
import secrets
import string
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal

from flask import current_app

from ..extensions import db
from ..license_signing import mask_license_key
from ..models import AuditLog, License, LicenseCheck, Renewal, Setting, utcnow
from .vpn_entitlements import vpn_services_contract_for_license

KEY_ALPHABET = string.ascii_uppercase + string.digits


@dataclass
class LicenseResult:
    active: bool
    status: str
    mode: str
    message: str
    result: str
    license: License | None = None

    def to_response(self) -> dict:
        data = {
            "active": self.active,
            "status": self.status,
            "mode": self.mode,
            "message": self.message,
        }
        if self.license:
            lic = self.license
            data.update({
                "expires_at": iso_z(lic.expires_at),
                "grace_until": iso_z(lic.grace_until),
                "plan": lic.plan.public_dict(),
                "features": lic.plan.features,
            })
        data["services"] = vpn_services_contract_for_license(
            self.license,
            license_allows_services=self.active,
        )
        if self.license:
            from .customer_control import build_runtime_contract_for_license

            runtime_contract = build_runtime_contract_for_license(
                self.license,
                license_active=self.active,
                status=self.status,
            )
            data["services"] = runtime_contract["services"]
            data["limits"] = runtime_contract["limits"]
            data["customer_users_version"] = runtime_contract["customer_users_version"]
        return data


def iso_z(value: datetime | None) -> str | None:
    if not value:
        return None
    return value.replace(microsecond=0).isoformat() + "Z"


def generate_license_key() -> str:
    year = utcnow().year
    while True:
        groups = [
            "".join(secrets.choice(KEY_ALPHABET) for _ in range(4))
            for _ in range(3)
        ]
        key = f"HBR-{year}-" + "-".join(groups)
        if not License.query.filter_by(license_key=key).first():
            return key


def default_grace_days() -> int:
    """Resolve grace-days from the Setting table, falling back to env then
    the built-in default. Accepts BOTH the legacy key (``default_grace_days``,
    posted by ``/settings`` general form) AND the new payment-panel key
    (``grace_days``, posted by ``/settings/section`` payment form — FIX #8
    of mock-inventory remediation). Either UI field now works."""
    for key in ("default_grace_days", "grace_days"):
        setting = db.session.get(Setting, key)
        if setting and setting.value and setting.value.isdigit():
            return int(setting.value)
    return int(current_app.config.get("DEFAULT_GRACE_DAYS", 7))


def add_months(value: datetime, months: int) -> datetime:
    month = value.month - 1 + months
    year = value.year + month // 12
    month = month % 12 + 1
    day = min(value.day, calendar.monthrange(year, month)[1])
    return value.replace(year=year, month=month, day=day)


def _audit(actor_admin_id: int | None, action: str, entity_type: str, entity_id: str, summary: str, metadata=None) -> None:
    row = AuditLog(
        actor_admin_id=actor_admin_id,
        action=action,
        entity_type=entity_type,
        entity_id=str(entity_id),
        summary=summary,
    )
    row.meta = metadata or {}
    db.session.add(row)


def check_license(
    *,
    license_key: str,
    fingerprint: str,
    hostname: str = "",
    version: str = "",
    ip_address: str = "",
    install_id: str = "",
    domain: str = "",
) -> LicenseResult:
    key = (license_key or "").strip().upper()
    fingerprint = (fingerprint or "").strip()
    now = utcnow()
    lic = License.query.filter_by(license_key=key).first() if key else None

    if not lic:
        result = LicenseResult(False, "not_found", "denied", "لم يتم العثور على مفتاح الترخيص.", "not_found")
        _log_check(None, key, fingerprint, hostname, version, ip_address, install_id, domain, result)
        db.session.commit()
        return result

    lic.last_check_at = now

    if lic.status in {"suspended", "revoked"}:
        result = LicenseResult(False, lic.status, "denied", f"الترخيص في حالة {lic.status}. الرجاء التواصل مع الدعم.", lic.status, lic)
        _log_check(lic, key, fingerprint, hostname, version, ip_address, install_id, domain, result)
        db.session.commit()
        return result

    expired = bool(lic.expires_at and lic.expires_at < now)
    in_grace = bool(expired and lic.grace_until and lic.grace_until >= now)
    if expired and not in_grace:
        result = LicenseResult(
            False,
            "expired",
            "limited",
            "انتهى الترخيص. الدخول الإداري مسموح، لكن إنشاء المستخدمين والكروت وعمليات المزامنة الجديدة معطّلة.",
            "expired",
            lic,
        )
        _log_check(lic, key, fingerprint, hostname, version, ip_address, install_id, domain, result)
        db.session.commit()
        return result

    if fingerprint:
        fingerprints = lic.fingerprints
        if fingerprint not in fingerprints:
            # Fingerprint is purely informational now (zero-touch link spec):
            # we record it for the «الأجهزة المرصودة» list on the customer
            # page and rotate the slots when they're full. Hard deny was
            # retired together with the legacy linking auth — a server
            # reboot / container restart / hardware change must never lock a
            # paying customer out.
            slot_limit = 1 if int(lic.max_fingerprints or 0) == 1 else max(3, int(lic.max_fingerprints or 0))
            if len(fingerprints) < slot_limit:
                fingerprints.append(fingerprint)
                lic.fingerprints = fingerprints
            else:
                # Slots full → rotate: keep the most recent `slot_limit`
                # fingerprints. Never deny.
                fingerprints = (fingerprints + [fingerprint])[-slot_limit:]
                lic.fingerprints = fingerprints

    if in_grace:
        result = LicenseResult(True, "grace", "active", "الترخيص في فترة السماح. الرجاء التجديد قريبًا.", "grace", lic)
        _log_check(lic, key, fingerprint, hostname, version, ip_address, install_id, domain, result)
        db.session.commit()
        return result

    result = LicenseResult(True, lic.status, "active", "الترخيص نشط", "active", lic)
    _log_check(lic, key, fingerprint, hostname, version, ip_address, install_id, domain, result)
    db.session.commit()
    return result


def _log_check(
    lic: License | None,
    key: str,
    fingerprint: str,
    hostname: str,
    version: str,
    ip_address: str,
    install_id: str,
    domain: str,
    result: LicenseResult,
) -> None:
    db.session.add(LicenseCheck(
        license_id=lic.id if lic else None,
        license_key=key,
        customer_id=lic.customer_id if lic else None,
        fingerprint=fingerprint,
        hostname=hostname or "",
        ip_address=ip_address or "",
        version=version or "",
        install_id=install_id or "",
        domain=domain or "",
        result=result.result,
        response_mode=result.mode,
        message=result.message,
    ))


def renew_license(
    lic: License,
    *,
    months: int,
    amount: Decimal,
    method: str,
    payment_status: str,
    notes: str,
    actor_admin_id: int | None,
) -> Renewal:
    months = max(1, int(months))
    now = utcnow()
    start = lic.expires_at if lic.expires_at and lic.expires_at > now else now
    end = add_months(start, months)
    lic.status = "active"
    lic.expires_at = end
    lic.grace_until = end + timedelta(days=default_grace_days())
    renewal = Renewal(
        customer_id=lic.customer_id,
        license_id=lic.id,
        amount=amount,
        currency=lic.plan.currency,
        period_months=months,
        period_start=start,
        period_end=end,
        method=method or "manual",
        status=payment_status or "paid",
        notes=notes or "",
    )
    db.session.add(renewal)
    _audit(actor_admin_id, "license_renewed", "license", str(lic.id), f"Renewed {mask_license_key(lic.license_key)} for {months} month(s)", {
        "months": months,
        "amount": str(amount),
        "period_end": iso_z(end),
    })
    db.session.commit()
    return renewal


def update_license(
    lic: License,
    *,
    plan_id: int | None = None,
    starts_at: datetime | None = None,
    expires_at: datetime | None = None,
    grace_until: datetime | None = None,
    add_days: int = 0,
    max_fingerprints: int | None = None,
    status: str | None = None,
    notes: str | None = None,
    actor_admin_id: int | None = None,
) -> License:
    """In-place edit of an EXISTING license — same ``license_key`` preserved.

    Lets an operator renew/adjust a license without minting a new key: repoint
    the plan (الباقة/العرض), set start/expiry/grace dates explicitly, extend by
    ``add_days`` (adds on top of the resolved expiry), set ``max_fingerprints``,
    ``status`` and ``notes``. When the expiry moves forward, a ``Renewal`` row is
    logged so the change surfaces in «سجل التجديدات». Emits an audit entry.

    Grace handling: an explicit ``grace_until`` wins; otherwise it is recomputed
    as expiry + ``default_grace_days()`` so it always trails the new expiry.
    """
    changes: dict = {}
    old_expiry = lic.expires_at

    if plan_id and int(plan_id) != int(lic.plan_id or 0):
        changes["plan_id"] = [lic.plan_id, int(plan_id)]
        lic.plan_id = int(plan_id)

    if starts_at:
        lic.starts_at = starts_at

    # Expiry — an explicit date wins; add_days then increments it (or the
    # current expiry when no explicit date was given).
    new_expiry = expires_at or lic.expires_at
    if add_days:
        base = new_expiry or utcnow()
        new_expiry = base + timedelta(days=int(add_days))
    if new_expiry and new_expiry != lic.expires_at:
        changes["expires_at"] = [iso_z(lic.expires_at), iso_z(new_expiry)]
        lic.expires_at = new_expiry

    # Grace — explicit, else always recompute so it trails the (new) expiry.
    if grace_until:
        lic.grace_until = grace_until
    elif lic.expires_at:
        lic.grace_until = lic.expires_at + timedelta(days=default_grace_days())

    if max_fingerprints is not None:
        lic.max_fingerprints = int(max_fingerprints)
    if status:
        changes.setdefault("status", [None, status])
        lic.status = status
    if notes is not None:
        lic.notes = notes.strip()

    db.session.add(lic)

    # Log a Renewal row whenever the expiry advanced, so «سجل التجديدات»
    # reflects the extension (day-granular; no payment attached to a manual edit).
    if lic.expires_at and old_expiry and lic.expires_at > old_expiry:
        db.session.add(Renewal(
            customer_id=lic.customer_id,
            license_id=lic.id,
            amount=Decimal("0"),
            currency=(lic.plan.currency if lic.plan else "USD"),
            period_months=0,
            period_start=old_expiry,
            period_end=lic.expires_at,
            method="manual_edit",
            status="paid",
            notes=(notes or "تعديل يدويّ للترخيص")[:500],
        ))

    _audit(actor_admin_id, "license_edited", "license", str(lic.id),
           f"Edited license {mask_license_key(lic.license_key)}", {
               "changes": changes,
               "expires_at": iso_z(lic.expires_at),
               "grace_until": iso_z(lic.grace_until),
               "status": lic.status,
           })
    db.session.commit()
    return lic


def set_license_status(lic: License, status: str, actor_admin_id: int | None) -> None:
    lic.status = status
    db.session.add(lic)
    _audit(actor_admin_id, f"license_{status}", "license", str(lic.id), f"License {mask_license_key(lic.license_key)} changed to {status}")
    db.session.commit()


def reset_fingerprints(lic: License, actor_admin_id: int | None) -> None:
    lic.fingerprints = []
    db.session.add(lic)
    _audit(actor_admin_id, "fingerprints_reset", "license", str(lic.id), f"Fingerprints reset for {mask_license_key(lic.license_key)}")
    db.session.commit()
