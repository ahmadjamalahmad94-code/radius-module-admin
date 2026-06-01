from __future__ import annotations

import pytest

from app.extensions import db
from app.models import Customer, LicensePaymentRequest, Plan, ProvisioningOrder
from app.services.license_payments import (
    LicensePaymentRequestRepository,
    LicensePaymentRequestService,
    LicensePaymentValidationError,
    LicensePaymentWebhookEventRepository,
    PlatformPaymentSettingsRepository,
    ProvisioningOrderRepository,
)


def _customer() -> Customer:
    customer = Customer(company_name="Payment Customer", contact_name="Owner")
    db.session.add(customer)
    db.session.commit()
    return customer


def test_platform_payment_settings_create_and_update(app):
    repo = PlatformPaymentSettingsRepository()
    created = repo.upsert(
        provider="manual_wallet",
        enabled=True,
        wallet_number="0599000000",
        wallet_owner_name="Hobe Wallet",
        currency="ILS",
        confirmation_mode="manual",
    )
    assert created.enabled is True
    assert created.wallet_number == "0599000000"

    updated = repo.upsert(enabled=False, currency="USD")
    assert updated.id == created.id
    assert updated.enabled is False
    assert updated.currency == "USD"


def test_license_payment_request_creation_and_unique_reference(app):
    customer = _customer()
    plan = Plan.query.filter_by(slug="pro").first()
    repo = LicensePaymentRequestRepository()

    first = repo.create(
        customer_id=customer.id,
        plan_id=plan.id,
        purpose="new_subscription",
        amount="79.00",
        currency="USD",
        provider="manual_wallet",
        receiver_wallet="0599000000",
    )
    second = repo.create(
        customer_id=customer.id,
        plan_id=plan.id,
        purpose="renewal",
        amount="79.00",
        currency="USD",
        provider="manual_wallet",
        receiver_wallet="0599000000",
    )
    assert first.status == "pending"
    assert first.reference_code.startswith("LIC-")
    assert first.reference_code != second.reference_code
    assert LicensePaymentRequest.query.count() == 2


@pytest.mark.parametrize(
    "field, payload",
    [
        ("amount", {"amount": "0"}),
        ("provider", {"provider": "fake_provider"}),
        ("purpose", {"purpose": "card_purchase"}),
        ("currency", {"currency": "GBP"}),
    ],
)
def test_license_payment_request_rejects_invalid_values(app, field, payload):
    customer = _customer()
    data = {
        "customer_id": customer.id,
        "purpose": "new_subscription",
        "amount": "79.00",
        "currency": "USD",
        "provider": "manual_wallet",
    }
    data.update(payload)
    with pytest.raises(LicensePaymentValidationError, match=field):
        LicensePaymentRequestRepository().create(**data)


def test_payment_request_defaults_to_customer_currency(app):
    """Per-customer currency: an invoice inherits the customer's own currency
    when none is given, but an explicit per-request choice still wins."""
    PlatformPaymentSettingsRepository().upsert(
        provider="manual_wallet",
        enabled=True,
        wallet_number="0599000000",
        wallet_owner_name="Hobe Wallet",
        currency="USD",
        confirmation_mode="manual",
    )
    customer = Customer(company_name="ILS Customer", currency="ILS")
    db.session.add(customer)
    db.session.commit()

    inherited = LicensePaymentRequestService().create_request({
        "customer_id": customer.id,
        "purpose": "new_subscription",
        "amount": "120.00",
    })
    assert inherited.currency == "ILS"  # customer currency beats system default (USD)

    explicit = LicensePaymentRequestService().create_request({
        "customer_id": customer.id,
        "purpose": "renewal",
        "amount": "120.00",
        "currency": "JOD",
    })
    assert explicit.currency == "JOD"  # explicit per-request choice still wins


def test_provisioning_order_creation_and_status_validation(app):
    customer = _customer()
    order = ProvisioningOrderRepository().create(
        customer_id=customer.id,
        status="payment_pending",
        notes="awaiting payment",
    )
    assert order.status == "payment_pending"
    assert ProvisioningOrder.query.count() == 1

    with pytest.raises(LicensePaymentValidationError, match="status"):
        ProvisioningOrderRepository().create(customer_id=customer.id, status="unknown")


def test_webhook_event_id_is_idempotent(app):
    first = LicensePaymentWebhookEventRepository().create(
        provider="jawwal_pay",
        event_id="evt-1",
        payload={"status": "paid"},
        signature_valid=False,
        processed=False,
    )
    second = LicensePaymentWebhookEventRepository().create(
        provider="jawwal_pay",
        event_id="evt-1",
        payload={"status": "paid-again"},
        signature_valid=False,
        processed=False,
    )
    assert second.id == first.id
