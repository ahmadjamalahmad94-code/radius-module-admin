from __future__ import annotations

from app.extensions import db
from app.models import Customer, LicensePaymentProof, LicensePaymentRequest, LicensePaymentTransaction, ProvisioningOrder
from app.services.license_payments import (
    LicensePaymentProofService,
    LicensePaymentRequestService,
    PlatformPaymentSettingsRepository,
)


def _login(client):
    return client.post("/login", data={"username": "admin", "password": "admin12345"})


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
    customer = Customer(company_name="Review Payment Customer", contact_name="Owner")
    db.session.add(customer)
    db.session.commit()
    return customer


def _submitted_request() -> LicensePaymentRequest:
    _enable_payments()
    customer = _customer()
    payment_request = LicensePaymentRequestService().create_request({
        "customer_id": customer.id,
        "purpose": "new_subscription",
        "amount": "79.00",
        "currency": "USD",
    })
    LicensePaymentProofService().submit_manual_proof(
        payment_request=payment_request,
        reference_number="TX-REVIEW",
        note="manual wallet transfer",
    )
    return db.session.get(LicensePaymentRequest, payment_request.id)


def test_review_queue_and_detail_render(client):
    _login(client)
    payment_request = _submitted_request()

    queue = client.get("/admin/payments/review-queue")
    assert queue.status_code == 200
    assert payment_request.reference_code in queue.get_data(as_text=True)

    detail = client.get(f"/admin/payments/requests/{payment_request.id}")
    assert detail.status_code == 200
    html = detail.get_data(as_text=True)
    assert "قبول الدفع" in html
    assert "TX-REVIEW" in html


def test_admin_approve_payment_creates_transaction_and_advances_order(client):
    _login(client)
    payment_request = _submitted_request()

    response = client.post(
        f"/admin/payments/requests/{payment_request.id}/approve",
        data={"review_note": "matched wallet"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    refreshed = db.session.get(LicensePaymentRequest, payment_request.id)
    assert refreshed.status == "paid"
    proof = LicensePaymentProof.query.filter_by(license_payment_request_id=payment_request.id).one()
    assert proof.review_status == "accepted"
    assert proof.review_note == "matched wallet"
    assert LicensePaymentTransaction.query.filter_by(license_payment_request_id=payment_request.id).count() == 1
    order = ProvisioningOrder.query.filter_by(license_payment_request_id=payment_request.id).one()
    assert order.status == "provisioning_pending"
    assert order.paid_at is not None


def test_admin_reject_payment_does_not_create_transaction(client):
    _login(client)
    payment_request = _submitted_request()

    response = client.post(
        f"/admin/payments/requests/{payment_request.id}/reject",
        data={"review_note": "not found"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    refreshed = db.session.get(LicensePaymentRequest, payment_request.id)
    assert refreshed.status == "rejected"
    proof = LicensePaymentProof.query.filter_by(license_payment_request_id=payment_request.id).one()
    assert proof.review_status == "rejected"
    assert LicensePaymentTransaction.query.count() == 0


def test_admin_cannot_approve_twice_or_duplicate_transaction(client):
    _login(client)
    payment_request = _submitted_request()
    client.post(f"/admin/payments/requests/{payment_request.id}/approve", data={"review_note": "ok"})

    second = client.post(
        f"/admin/payments/requests/{payment_request.id}/approve",
        data={"review_note": "again"},
        follow_redirects=True,
    )

    assert second.status_code == 200
    assert LicensePaymentTransaction.query.filter_by(license_payment_request_id=payment_request.id).count() == 1
    assert "تمت معالجة هذا الطلب وقبوله مسبقًا" in second.get_data(as_text=True)


def test_customer_cannot_approve_payment(client):
    payment_request = _submitted_request()
    response = client.post(f"/admin/payments/requests/{payment_request.id}/approve", data={"review_note": "bad"})
    assert response.status_code == 302
    assert LicensePaymentTransaction.query.count() == 0
