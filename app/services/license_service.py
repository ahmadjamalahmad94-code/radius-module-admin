from __future__ import annotations

import calendar
import secrets
import string
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal

from flask import current_app

from ..extensions import db
from ..models import AuditLog, License, LicenseCheck, Renewal, Setting, utcnow

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
    setting = db.session.get(Setting, "default_grace_days")
    if setting and setting.value.isdigit():
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
        result = LicenseResult(False, "not_found", "denied", "License key was not found.", "not_found")
        _log_check(None, key, fingerprint, hostname, version, ip_address, install_id, domain, result)
        db.session.commit()
        return result

    lic.last_check_at = now

    if lic.status in {"suspended", "revoked"}:
        result = LicenseResult(False, lic.status, "denied", f"License is {lic.status}. Contact support.", lic.status, lic)
        _log_check(lic, key, fingerprint, hostname, version, ip_address, install_id, domain, result)
        db.session.commit()
        return result

    if fingerprint:
        fingerprints = lic.fingerprints
        if fingerprint not in fingerprints:
            if len(fingerprints) < max(1, lic.max_fingerprints):
                fingerprints.append(fingerprint)
                lic.fingerprints = fingerprints
            else:
                result = LicenseResult(
                    False,
                    "fingerprint_denied",
                    "denied",
                    "Server fingerprint is not allowed for this license.",
                    "fingerprint_denied",
                    lic,
                )
                _log_check(lic, key, fingerprint, hostname, version, ip_address, install_id, domain, result)
                db.session.commit()
                return result

    if lic.expires_at and lic.expires_at < now:
        if lic.grace_until and lic.grace_until >= now:
            result = LicenseResult(True, "grace", "active", "License is in grace period. Please renew soon.", "grace", lic)
        else:
            result = LicenseResult(
                False,
                "expired",
                "limited",
                "License expired. Admin access is allowed, but new users/cards/sync actions are disabled.",
                "expired",
                lic,
            )
        _log_check(lic, key, fingerprint, hostname, version, ip_address, install_id, domain, result)
        db.session.commit()
        return result

    result = LicenseResult(True, lic.status, "active", "License active", "active", lic)
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
    _audit(actor_admin_id, "license_renewed", "license", str(lic.id), f"Renewed {lic.license_key} for {months} month(s)", {
        "months": months,
        "amount": str(amount),
        "period_end": iso_z(end),
    })
    db.session.commit()
    return renewal


def set_license_status(lic: License, status: str, actor_admin_id: int | None) -> None:
    lic.status = status
    db.session.add(lic)
    _audit(actor_admin_id, f"license_{status}", "license", str(lic.id), f"License {lic.license_key} changed to {status}")
    db.session.commit()


def reset_fingerprints(lic: License, actor_admin_id: int | None) -> None:
    lic.fingerprints = []
    db.session.add(lic)
    _audit(actor_admin_id, "fingerprints_reset", "license", str(lic.id), f"Fingerprints reset for {lic.license_key}")
    db.session.commit()
