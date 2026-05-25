from __future__ import annotations

import secrets
import string
from datetime import timedelta
from decimal import Decimal, InvalidOperation
from typing import Any

from flask import url_for
from werkzeug.routing import BuildError

from ..extensions import db
from ..models import (
    AuditLog,
    Customer,
    License,
    LicensePaymentProof,
    LicensePaymentRequest,
    LicensePaymentTransaction,
    LicensePaymentWebhookEvent,
    Plan,
    PlatformPaymentSettings,
    ProvisioningOrder,
    Renewal,
    json_dumps,
    json_loads,
    utcnow,
)
from .license_service import add_months, default_grace_days, generate_license_key, iso_z

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


class LicensePaymentAccessTokenGenerator:
    def generate(self) -> str:
        for _ in range(100):
            token = secrets.token_urlsafe(32)
            if not LicensePaymentRequest.query.filter_by(access_token=token).first():
                return token
        raise RuntimeError("license_payment_access_token_collision")


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
    def __init__(
        self,
        reference_generator: LicensePaymentReferenceGenerator | None = None,
        token_generator: LicensePaymentAccessTokenGenerator | None = None,
    ) -> None:
        self.reference_generator = reference_generator or LicensePaymentReferenceGenerator()
        self.token_generator = token_generator or LicensePaymentAccessTokenGenerator()

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
            access_token=self.token_generator.generate(),
            status="pending",
            expires_at=now + timedelta(minutes=int(ttl_minutes)) if ttl_minutes else None,
        )
        db.session.add(request)
        db.session.commit()
        return request

    def get_for_portal(self, request_id: int, token: str) -> LicensePaymentRequest | None:
        if not token:
            return None
        return LicensePaymentRequest.query.filter_by(id=int(request_id), access_token=str(token)).first()

    def list_filtered(self, *, status: str = "", purpose: str = "", customer_id: int | None = None):
        query = LicensePaymentRequest.query
        if status:
            query = query.filter_by(status=status)
        if purpose:
            query = query.filter_by(purpose=purpose)
        if customer_id:
            query = query.filter_by(customer_id=int(customer_id))
        return query.order_by(LicensePaymentRequest.created_at.desc()).all()


class LicensePaymentProofRepository:
    def create_manual_reference(
        self,
        *,
        payment_request: LicensePaymentRequest,
        reference_number: str = "",
        note: str = "",
    ) -> LicensePaymentProof:
        proof = LicensePaymentProof(
            license_payment_request_id=payment_request.id,
            proof_type="manual_reference",
            reference_number=str(reference_number or "").strip(),
            note=str(note or "").strip(),
        )
        db.session.add(proof)
        return proof


class LicensePaymentTransactionRepository:
    def create_manual_paid(
        self,
        *,
        payment_request: LicensePaymentRequest,
        reviewed_by: int | None = None,
    ) -> LicensePaymentTransaction:
        existing = LicensePaymentTransaction.query.filter_by(
            license_payment_request_id=payment_request.id,
            status="paid_manual",
        ).first()
        if existing:
            return existing
        transaction = LicensePaymentTransaction(
            license_payment_request_id=payment_request.id,
            provider_transaction_id=f"manual:{payment_request.reference_code}",
            amount=payment_request.amount,
            currency=payment_request.currency,
            status="paid_manual",
            raw_payload=json_dumps({
                "provider": payment_request.provider,
                "reference_code": payment_request.reference_code,
                "reviewed_by": reviewed_by,
            }),
            verified_at=utcnow(),
        )
        db.session.add(transaction)
        return transaction


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

    def ensure_for_request(self, payment_request: LicensePaymentRequest) -> ProvisioningOrder:
        existing = ProvisioningOrder.query.filter_by(
            license_payment_request_id=payment_request.id,
        ).first()
        if existing:
            return existing
        return self.create(
            customer_id=payment_request.customer_id,
            license_payment_request_id=payment_request.id,
            target_plan_id=payment_request.plan_id,
            status="payment_pending",
        )


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


def settings_to_dict(settings: PlatformPaymentSettings | None) -> dict[str, Any]:
    if not settings:
        return {
            "enabled": False,
            "provider": "manual_wallet",
            "wallet_number": "",
            "wallet_owner_name": "",
            "currency": "USD",
            "confirmation_mode": "manual",
            "payment_request_ttl_minutes": 1440,
        }
    return {
        "id": settings.id,
        "enabled": bool(settings.enabled),
        "provider": settings.provider,
        "wallet_number": settings.wallet_number,
        "wallet_owner_name": settings.wallet_owner_name,
        "currency": settings.currency,
        "confirmation_mode": settings.confirmation_mode,
        "payment_request_ttl_minutes": settings.payment_request_ttl_minutes,
        "created_at": settings.created_at.isoformat() if settings.created_at else None,
        "updated_at": settings.updated_at.isoformat() if settings.updated_at else None,
    }


def request_to_dict(payment_request: LicensePaymentRequest, *, include_internal: bool = False) -> dict[str, Any]:
    payload = {
        "id": payment_request.id,
        "customer_id": payment_request.customer_id,
        "plan_id": payment_request.plan_id,
        "license_id": payment_request.license_id,
        "purpose": payment_request.purpose,
        "amount": str(payment_request.amount),
        "currency": payment_request.currency,
        "provider": payment_request.provider,
        "receiver_wallet": payment_request.receiver_wallet,
        "reference_code": payment_request.reference_code,
        "status": payment_request.status,
        "expires_at": payment_request.expires_at.isoformat() if payment_request.expires_at else None,
        "applied_at": payment_request.applied_at.isoformat() if payment_request.applied_at else None,
        "applied_action": payment_request.applied_action,
        "applied_result": json_loads(payment_request.applied_result_json, {}),
        "created_at": payment_request.created_at.isoformat() if payment_request.created_at else None,
        "updated_at": payment_request.updated_at.isoformat() if payment_request.updated_at else None,
    }
    if include_internal:
        payload["proof_count"] = payment_request.proofs.count()
        payload["transaction_count"] = payment_request.transactions.count()
    return payload


def instructions_for_request(payment_request: LicensePaymentRequest) -> dict[str, Any]:
    return {
        "payment_request_id": payment_request.id,
        "amount": str(payment_request.amount),
        "currency": payment_request.currency,
        "receiver_wallet": payment_request.receiver_wallet,
        "wallet_owner_name": settings_to_dict(PlatformPaymentSettingsRepository().get()).get("wallet_owner_name", ""),
        "reference_code": payment_request.reference_code,
        "expires_at": payment_request.expires_at.isoformat() if payment_request.expires_at else None,
        "status": payment_request.status,
        "instructions": "Use the wallet number only for routing the payment. Payment is not confirmed until an admin reviews the submitted proof.",
    }


class LicensePaymentRequestService:
    def __init__(self) -> None:
        self.settings_repo = PlatformPaymentSettingsRepository()
        self.request_repo = LicensePaymentRequestRepository()

    def create_request(self, payload: dict[str, Any]) -> LicensePaymentRequest:
        settings = self.settings_repo.get()
        if not settings or not settings.enabled:
            raise LicensePaymentValidationError("payments_disabled")
        if settings.provider != "manual_wallet":
            raise LicensePaymentValidationError("provider_not_supported")
        customer_id = int(payload.get("customer_id") or 0)
        if not db.session.get(Customer, customer_id):
            raise LicensePaymentValidationError("customer_id")
        plan_id = payload.get("plan_id")
        if plan_id not in (None, "") and not db.session.get(Plan, int(plan_id)):
            raise LicensePaymentValidationError("plan_id")
        request_row = self.request_repo.create(
            customer_id=customer_id,
            plan_id=int(plan_id) if plan_id not in (None, "") else None,
            license_id=int(payload["license_id"]) if payload.get("license_id") else None,
            purpose=payload.get("purpose", ""),
            amount=payload.get("amount", ""),
            currency=payload.get("currency") or settings.currency,
            provider=settings.provider,
            receiver_wallet=settings.wallet_number,
            ttl_minutes=settings.payment_request_ttl_minutes,
        )
        ProvisioningOrderRepository().ensure_for_request(request_row)
        db.session.commit()
        return request_row

    def portal_payload(self, payment_request: LicensePaymentRequest) -> dict[str, Any]:
        payload = request_to_dict(payment_request)
        payload["instructions"] = instructions_for_request(payment_request)
        try:
            payload["portal_url"] = url_for(
                "public.payment_portal",
                request_id=payment_request.id,
                token=payment_request.access_token,
                _external=False,
            )
        except (BuildError, RuntimeError):
            payload["portal_url"] = None
        return payload


class LicensePaymentProofService:
    allowed_submission_statuses = {"pending"}
    blocked_submission_statuses = {"paid", "expired", "cancelled", "rejected", "failed"}

    def submit_manual_proof(
        self,
        *,
        payment_request: LicensePaymentRequest,
        reference_number: str = "",
        note: str = "",
    ) -> LicensePaymentProof:
        if payment_request.status in self.blocked_submission_statuses:
            raise LicensePaymentValidationError("request_not_open_for_proof")
        if payment_request.expires_at and payment_request.expires_at < utcnow():
            payment_request.status = "expired"
            db.session.add(payment_request)
            db.session.commit()
            raise LicensePaymentValidationError("request_expired")
        if payment_request.status not in self.allowed_submission_statuses:
            raise LicensePaymentValidationError("request_not_open_for_proof")
        proof = LicensePaymentProofRepository().create_manual_reference(
            payment_request=payment_request,
            reference_number=reference_number,
            note=note,
        )
        payment_request.status = "proof_submitted"
        db.session.add(payment_request)
        db.session.add(proof)
        db.session.commit()
        return proof


class LicensePaymentReviewService:
    reviewable_statuses = {"proof_submitted", "under_review"}

    def approve(
        self,
        *,
        payment_request: LicensePaymentRequest,
        reviewed_by: int | None = None,
        review_note: str = "",
    ) -> LicensePaymentTransaction:
        if payment_request.status == "paid":
            raise LicensePaymentValidationError("request_already_paid")
        if payment_request.status not in self.reviewable_statuses:
            raise LicensePaymentValidationError("request_not_reviewable")

        latest_proof = payment_request.proofs.order_by(LicensePaymentProof.submitted_at.desc()).first()
        if not latest_proof:
            raise LicensePaymentValidationError("proof_missing")
        latest_proof.review_status = "accepted"
        latest_proof.reviewed_by = reviewed_by
        latest_proof.reviewed_at = utcnow()
        latest_proof.review_note = str(review_note or "").strip()

        payment_request.status = "paid"
        db.session.add(payment_request)
        db.session.add(latest_proof)
        transaction = LicensePaymentTransactionRepository().create_manual_paid(
            payment_request=payment_request,
            reviewed_by=reviewed_by,
        )
        order = ProvisioningOrderRepository().ensure_for_request(payment_request)
        if order.status in {"payment_pending", "paid"}:
            order.status = "provisioning_pending"
        order.paid_at = order.paid_at or utcnow()
        db.session.add(order)
        db.session.commit()
        return transaction

    def reject(
        self,
        *,
        payment_request: LicensePaymentRequest,
        reviewed_by: int | None = None,
        review_note: str = "",
    ) -> LicensePaymentProof:
        if payment_request.status not in self.reviewable_statuses:
            raise LicensePaymentValidationError("request_not_reviewable")
        latest_proof = payment_request.proofs.order_by(LicensePaymentProof.submitted_at.desc()).first()
        if not latest_proof:
            raise LicensePaymentValidationError("proof_missing")
        latest_proof.review_status = "rejected"
        latest_proof.reviewed_by = reviewed_by
        latest_proof.reviewed_at = utcnow()
        latest_proof.review_note = str(review_note or "").strip()
        payment_request.status = "rejected"
        db.session.add(payment_request)
        db.session.add(latest_proof)
        db.session.commit()
        return latest_proof


def proof_to_dict(proof: LicensePaymentProof) -> dict[str, Any]:
    return {
        "id": proof.id,
        "payment_request_id": proof.license_payment_request_id,
        "proof_type": proof.proof_type,
        "reference_number": proof.reference_number,
        "note": proof.note,
        "submitted_at": proof.submitted_at.isoformat() if proof.submitted_at else None,
        "reviewed_by": proof.reviewed_by,
        "reviewed_at": proof.reviewed_at.isoformat() if proof.reviewed_at else None,
        "review_status": proof.review_status,
        "review_note": proof.review_note,
    }


def transaction_to_dict(transaction: LicensePaymentTransaction) -> dict[str, Any]:
    return {
        "id": transaction.id,
        "payment_request_id": transaction.license_payment_request_id,
        "provider_transaction_id": transaction.provider_transaction_id,
        "amount": str(transaction.amount),
        "currency": transaction.currency,
        "status": transaction.status,
        "payload": json_loads(transaction.raw_payload, {}),
        "verified_at": transaction.verified_at.isoformat() if transaction.verified_at else None,
        "created_at": transaction.created_at.isoformat() if transaction.created_at else None,
    }


class LicensePaymentApplyService:
    def apply_paid_payment(
        self,
        *,
        payment_request: LicensePaymentRequest,
        actor_admin_id: int | None = None,
        period_months: int = 1,
    ) -> dict[str, Any]:
        if payment_request.status != "paid":
            raise LicensePaymentValidationError("request_not_paid")
        if payment_request.applied_at:
            return json_loads(payment_request.applied_result_json, {})

        purpose = payment_request.purpose
        if purpose == "renewal":
            result = self._apply_renewal(payment_request, actor_admin_id, period_months)
        elif purpose == "upgrade":
            result = self._apply_upgrade(payment_request, actor_admin_id)
        elif purpose == "new_subscription":
            result = self._apply_new_subscription(payment_request, actor_admin_id)
        elif purpose == "capacity_increase":
            result = {
                "status": "manual_follow_up",
                "message": "Capacity increase requires an entitlement override workflow before automatic apply.",
            }
            self._audit(actor_admin_id, "payment_capacity_followup", payment_request, result)
        elif purpose == "setup_fee":
            result = {
                "status": "setup_fee_recorded",
                "message": "Setup fee payment recorded; no license mutation is attached to setup_fee.",
            }
            self._audit(actor_admin_id, "payment_setup_fee_recorded", payment_request, result)
        else:
            raise LicensePaymentValidationError("purpose_not_supported")

        payment_request.applied_at = utcnow()
        payment_request.applied_action = purpose
        payment_request.applied_result_json = json_dumps(result)
        db.session.add(payment_request)
        db.session.commit()
        return result

    def _apply_renewal(
        self,
        payment_request: LicensePaymentRequest,
        actor_admin_id: int | None,
        period_months: int,
    ) -> dict[str, Any]:
        license_row = db.session.get(License, int(payment_request.license_id or 0))
        if not license_row:
            raise LicensePaymentValidationError("license_id")
        months = max(1, int(period_months or 1))
        now = utcnow()
        start = license_row.expires_at if license_row.expires_at and license_row.expires_at > now else now
        end = add_months(start, months)
        license_row.status = "active"
        license_row.expires_at = end
        license_row.grace_until = end + timedelta(days=default_grace_days())
        renewal = Renewal(
            customer_id=license_row.customer_id,
            license_id=license_row.id,
            amount=payment_request.amount,
            currency=payment_request.currency,
            period_months=months,
            period_start=start,
            period_end=end,
            method=payment_request.provider,
            status="paid",
            notes=f"Applied from payment {payment_request.reference_code}",
        )
        db.session.add(license_row)
        db.session.add(renewal)
        result = {
            "status": "renewed",
            "license_id": license_row.id,
            "license_key": license_row.license_key,
            "period_months": months,
            "expires_at": iso_z(end),
        }
        self._audit(actor_admin_id, "payment_license_renewed", payment_request, result)
        return result

    def _apply_upgrade(self, payment_request: LicensePaymentRequest, actor_admin_id: int | None) -> dict[str, Any]:
        license_row = db.session.get(License, int(payment_request.license_id or 0))
        plan = db.session.get(Plan, int(payment_request.plan_id or 0))
        if not license_row:
            raise LicensePaymentValidationError("license_id")
        if not plan:
            raise LicensePaymentValidationError("plan_id")
        old_plan_id = license_row.plan_id
        license_row.plan_id = plan.id
        license_row.max_fingerprints = max(1, int(plan.max_devices or license_row.max_fingerprints or 1))
        db.session.add(license_row)
        result = {
            "status": "upgraded",
            "license_id": license_row.id,
            "license_key": license_row.license_key,
            "old_plan_id": old_plan_id,
            "new_plan_id": plan.id,
        }
        self._audit(actor_admin_id, "payment_license_upgraded", payment_request, result)
        return result

    def _apply_new_subscription(
        self,
        payment_request: LicensePaymentRequest,
        actor_admin_id: int | None,
    ) -> dict[str, Any]:
        order = ProvisioningOrder.query.filter_by(license_payment_request_id=payment_request.id).first()
        if not order or order.status not in {"ready", "delivered"}:
            raise LicensePaymentValidationError("provisioning_not_ready")
        plan = db.session.get(Plan, int(payment_request.plan_id or order.target_plan_id or 0))
        if not plan:
            raise LicensePaymentValidationError("plan_id")
        now = utcnow()
        expires_at = add_months(now, 1)
        license_row = License(
            customer_id=payment_request.customer_id,
            plan_id=plan.id,
            license_key=generate_license_key(),
            status="active",
            starts_at=now,
            expires_at=expires_at,
            grace_until=expires_at + timedelta(days=default_grace_days()),
            max_fingerprints=max(1, int(plan.max_devices or 1)),
            notes=f"Created from paid request {payment_request.reference_code}",
        )
        db.session.add(license_row)
        db.session.flush()
        result = {
            "status": "license_created",
            "license_id": license_row.id,
            "license_key": license_row.license_key,
            "plan_id": plan.id,
            "expires_at": iso_z(expires_at),
        }
        self._audit(actor_admin_id, "payment_license_created", payment_request, result)
        return result

    def _audit(
        self,
        actor_admin_id: int | None,
        action: str,
        payment_request: LicensePaymentRequest,
        result: dict[str, Any],
    ) -> None:
        row = AuditLog(
            actor_admin_id=actor_admin_id,
            action=action,
            entity_type="license_payment_request",
            entity_id=str(payment_request.id),
            summary=f"Applied payment {payment_request.reference_code}: {result.get('status')}",
        )
        row.meta = {
            "payment_request_id": payment_request.id,
            "reference_code": payment_request.reference_code,
            "purpose": payment_request.purpose,
            "result": result,
        }
        db.session.add(row)
