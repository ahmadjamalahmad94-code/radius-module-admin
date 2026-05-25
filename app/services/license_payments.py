from __future__ import annotations

import secrets
import string
from datetime import timedelta
from decimal import Decimal, InvalidOperation
from typing import Any

from ..extensions import db
from ..models import (
    LicensePaymentRequest,
    LicensePaymentWebhookEvent,
    PlatformPaymentSettings,
    ProvisioningOrder,
    json_dumps,
    utcnow,
)

PAYMENT_PROVIDERS = {"manual_wallet", "jawwal_pay"}
CONFIRMATION_MODES = {"manual", "api"}
CURRENCIES = {"USD", "ILS", "JOD"}
PAYMENT_PURPOSES = {"new_subscription", "renewal", "upgrade", "capacity_increase", "setup_fee"}
PAYMENT_STATUSES = {"pending", "proof_submitted", "under_review", "paid", "rejected", "expired", "cancelled", "failed"}
PROVISIONING_STATUSES = {
    "payment_pending",
    "paid",
    "provisioning_pending",
    "provisioning_in_progress",
    "testing",
    "ready",
    "delivered",
    "failed",
    "needs_manual_review",
}


class LicensePaymentValidationError(ValueError):
    pass


def _choice(value: str, allowed: set[str], field: str) -> str:
    cleaned = str(value or "").strip()
    if cleaned not in allowed:
        raise LicensePaymentValidationError(field)
    return cleaned


def _amount(value: Any) -> Decimal:
    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, TypeError) as exc:
        raise LicensePaymentValidationError("amount") from exc
    if parsed <= 0:
        raise LicensePaymentValidationError("amount")
    return parsed


class LicensePaymentReferenceGenerator:
    def generate(self) -> str:
        alphabet = string.ascii_uppercase + string.digits
        for _ in range(100):
            suffix = "".join(secrets.choice(alphabet) for _ in range(8))
            reference = f"LIC-{suffix}"
            if not LicensePaymentRequest.query.filter_by(reference_code=reference).first():
                return reference
        raise RuntimeError("license_payment_reference_collision")


class PlatformPaymentSettingsRepository:
    def get(self) -> PlatformPaymentSettings | None:
        return PlatformPaymentSettings.query.order_by(PlatformPaymentSettings.id.asc()).first()

    def upsert(self, **kwargs: Any) -> PlatformPaymentSettings:
        settings = self.get() or PlatformPaymentSettings()
        settings.provider = _choice(kwargs.get("provider", settings.provider), PAYMENT_PROVIDERS, "provider")
        settings.enabled = bool(kwargs.get("enabled", settings.enabled))
        settings.wallet_number = str(kwargs.get("wallet_number", settings.wallet_number) or "")
        settings.wallet_owner_name = str(kwargs.get("wallet_owner_name", settings.wallet_owner_name) or "")
        settings.currency = _choice(kwargs.get("currency", settings.currency), CURRENCIES, "currency")
        settings.confirmation_mode = _choice(
            kwargs.get("confirmation_mode", settings.confirmation_mode),
            CONFIRMATION_MODES,
            "confirmation_mode",
        )
        ttl = kwargs.get("payment_request_ttl_minutes", settings.payment_request_ttl_minutes)
        settings.payment_request_ttl_minutes = int(ttl) if ttl is not None else None
        if settings.payment_request_ttl_minutes is not None and settings.payment_request_ttl_minutes <= 0:
            raise LicensePaymentValidationError("payment_request_ttl_minutes")
        db.session.add(settings)
        db.session.commit()
        return settings


class LicensePaymentRequestRepository:
    def __init__(self, reference_generator: LicensePaymentReferenceGenerator | None = None) -> None:
        self.reference_generator = reference_generator or LicensePaymentReferenceGenerator()

    def create(
        self,
        *,
        customer_id: int,
        purpose: str,
        amount: Any,
        currency: str,
        provider: str,
        receiver_wallet: str = "",
        plan_id: int | None = None,
        license_id: int | None = None,
        ttl_minutes: int | None = 1440,
    ) -> LicensePaymentRequest:
        purpose = _choice(purpose, PAYMENT_PURPOSES, "purpose")
        provider = _choice(provider, PAYMENT_PROVIDERS, "provider")
        currency = _choice(currency, CURRENCIES, "currency")
        now = utcnow()
        request = LicensePaymentRequest(
            customer_id=int(customer_id),
            plan_id=plan_id,
            license_id=license_id,
            purpose=purpose,
            amount=_amount(amount),
            currency=currency,
            provider=provider,
            receiver_wallet=receiver_wallet or "",
            reference_code=self.reference_generator.generate(),
            status="pending",
            expires_at=now + timedelta(minutes=int(ttl_minutes)) if ttl_minutes else None,
        )
        db.session.add(request)
        db.session.commit()
        return request


class ProvisioningOrderRepository:
    def create(
        self,
        *,
        customer_id: int,
        license_payment_request_id: int | None = None,
        target_plan_id: int | None = None,
        status: str = "payment_pending",
        assigned_operator: str = "",
        notes: str = "",
    ) -> ProvisioningOrder:
        status = _choice(status, PROVISIONING_STATUSES, "status")
        order = ProvisioningOrder(
            customer_id=int(customer_id),
            license_payment_request_id=license_payment_request_id,
            target_plan_id=target_plan_id,
            status=status,
            assigned_operator=assigned_operator or "",
            notes=notes or "",
        )
        db.session.add(order)
        db.session.commit()
        return order


class LicensePaymentWebhookEventRepository:
    def create(
        self,
        *,
        provider: str,
        payload: dict[str, Any] | str,
        event_id: str | None = None,
        license_payment_request_id: int | None = None,
        signature_valid: bool | None = None,
        processed: bool = False,
    ) -> LicensePaymentWebhookEvent:
        provider = _choice(provider, PAYMENT_PROVIDERS, "provider")
        if event_id:
            existing = LicensePaymentWebhookEvent.query.filter_by(
                provider=provider,
                event_id=event_id,
            ).first()
            if existing:
                return existing
        event = LicensePaymentWebhookEvent(
            provider=provider,
            event_id=event_id,
            license_payment_request_id=license_payment_request_id,
            payload=payload if isinstance(payload, str) else json_dumps(payload),
            signature_valid=signature_valid,
            processed=bool(processed),
            processed_at=utcnow() if processed else None,
        )
        db.session.add(event)
        db.session.commit()
        return event
