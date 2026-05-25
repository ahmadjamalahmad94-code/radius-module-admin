from __future__ import annotations

from datetime import timedelta

from app.extensions import db
from app.models import Customer, License, LicensePaymentRequest, Plan, ProvisioningOrder, Renewal, utcnow
from app.services.license_payments import (
    LicensePaymentApplyService,
    LicensePaymentProofService,
    LicensePaymentRequestService,
    LicensePaymentReviewService,
    PlatformPaymentSettingsRepository,
)
from app.services.license_service import generate_license_key


def _enable_payments():
    PlatformPaymentSettingsRepository().upsert(
        enabled=True,
        provider="manual_wallet",
        wallet_number="0599000000",
        wallet_owner_name="Hobe Wallet",
        currency="USD",
        confirmation_mode="manual",
    )


def _customer() -> Customer:
    customer = Customer(company_name="Activation Payment Customer", contact_name="Owner")
    db.session.add(customer)
    db.session.commit()
    return customer


def _license(customer: Customer, plan: Plan) -> License:
    now = utcnow()
    lic = License(
        customer_id=customer.id,
        plan_id=plan.id,
        license_key=generate_license_key(),
        status="active",
        starts_at=now - timedelta(days=20),
        expires_at=now + timedelta(days=10),
        grace_until=now + timedelta(days=17),
        max_fingerprints=plan.max_devices,
    )
    db.session.add(lic)
    db.session.commit()
    return lic


def _paid_request(customer: Customer, purpose: str, *, plan_id=None, license_id=None) -> LicensePaymentRequest:
    _enable_payments()
    payment_request = LicensePaymentRequestService().create_request({
        "customer_id": customer.id,
        "plan_id": plan_id,
        "license_id": license_id,
        "purpose": purpose,
        "amount": "79.00",
        "currency": "USD",
    })
    LicensePaymentProofService().submit_manual_proof(payment_request=payment_request, reference_number="TX-ACT")
    LicensePaymentReviewService().approve(payment_request=db.session.get(LicensePaymentRequest, payment_request.id))
    return db.session.get(LicensePaymentRequest, payment_request.id)


def test_renewal_payment_extends_once(client):
    customer = _customer()
    plan = Plan.query.filter_by(slug="starter").first()
    lic = _license(customer, plan)
    original_expiry = lic.expires_at
    payment_request = _paid_request(customer, "renewal", license_id=lic.id)

    result = LicensePaymentApplyService().apply_paid_payment(payment_request=payment_request, period_months=1)
    second = LicensePaymentApplyService().apply_paid_payment(payment_request=db.session.get(LicensePaymentRequest, payment_request.id), period_months=1)

    refreshed = db.session.get(License, lic.id)
    assert result["status"] == "renewed"
    assert second == result
    assert refreshed.expires_at > original_expiry
    assert Renewal.query.filter_by(license_id=lic.id).count() == 1


def test_upgrade_payment_changes_plan_once(app):
    customer = _customer()
    starter = Plan.query.filter_by(slug="starter").first()
    pro = Plan.query.filter_by(slug="pro").first()
    lic = _license(customer, starter)
    payment_request = _paid_request(customer, "upgrade", plan_id=pro.id, license_id=lic.id)

    result = LicensePaymentApplyService().apply_paid_payment(payment_request=payment_request)
    LicensePaymentApplyService().apply_paid_payment(payment_request=db.session.get(LicensePaymentRequest, payment_request.id))

    refreshed = db.session.get(License, lic.id)
    assert result["status"] == "upgraded"
    assert refreshed.plan_id == pro.id
    assert db.session.get(LicensePaymentRequest, payment_request.id).applied_action == "upgrade"


def test_new_subscription_requires_ready_provisioning_order(app):
    customer = _customer()
    plan = Plan.query.filter_by(slug="pro").first()
    payment_request = _paid_request(customer, "new_subscription", plan_id=plan.id)

    try:
        LicensePaymentApplyService().apply_paid_payment(payment_request=payment_request)
    except Exception as exc:
        assert "provisioning_not_ready" in str(exc)
    else:
        raise AssertionError("new subscription applied before provisioning readiness")

    order = ProvisioningOrder.query.filter_by(license_payment_request_id=payment_request.id).one()
    order.status = "ready"
    db.session.commit()
    result = LicensePaymentApplyService().apply_paid_payment(payment_request=db.session.get(LicensePaymentRequest, payment_request.id))
    assert result["status"] == "license_created"
    assert License.query.filter_by(customer_id=customer.id).count() == 1


def test_capacity_and_setup_fee_do_not_mutate_license(app):
    customer = _customer()
    capacity_payment = _paid_request(customer, "capacity_increase")
    setup_payment = _paid_request(customer, "setup_fee")

    capacity = LicensePaymentApplyService().apply_paid_payment(payment_request=capacity_payment)
    setup = LicensePaymentApplyService().apply_paid_payment(payment_request=setup_payment)

    assert capacity["status"] == "manual_follow_up"
    assert setup["status"] == "setup_fee_recorded"
    assert License.query.count() == 0


def test_license_check_still_returns_active_after_payment_renewal(client):
    customer = _customer()
    plan = Plan.query.filter_by(slug="starter").first()
    lic = _license(customer, plan)
    payment_request = _paid_request(customer, "renewal", license_id=lic.id)
    LicensePaymentApplyService().apply_paid_payment(payment_request=payment_request)

    response = client.post("/api/license/check", json={
        "license_key": lic.license_key,
        "server_fingerprint": "fp-payment-renewal",
    })
    assert response.status_code == 200
    assert response.get_json()["active"] is True
