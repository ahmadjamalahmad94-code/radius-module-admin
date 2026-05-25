from __future__ import annotations

from datetime import timedelta

from app.extensions import db
from app.models import Customer, LicensePaymentProof, LicensePaymentRequest, utcnow
from app.services.license_payments import LicensePaymentRequestService, PlatformPaymentSettingsRepository


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
    customer = Customer(company_name="Portal Payment Customer", contact_name="Owner")
    db.session.add(customer)
    db.session.commit()
    return customer


def _payment_request() -> LicensePaymentRequest:
    _enable_payments()
    customer = _customer()
    return LicensePaymentRequestService().create_request({
        "customer_id": customer.id,
        "purpose": "new_subscription",
        "amount": "79.00",
        "currency": "USD",
    })


def test_portal_payment_page_renders_instructions(client):
    payment_request = _payment_request()
    response = client.get(f"/payments/requests/{payment_request.id}?token={payment_request.access_token}")

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "تعليمات دفع الاشتراك" in html
    assert "0599000000" in html
    assert payment_request.reference_code in html
    assert "رقم المحفظة لتوجيه الدفع فقط" in html


def test_portal_payment_page_requires_token(client):
    payment_request = _payment_request()
    response = client.get(f"/payments/requests/{payment_request.id}?token=bad")

    assert response.status_code == 404
    assert "طلب الدفع غير متاح" in response.get_data(as_text=True)


def test_portal_submit_text_proof_success(client):
    payment_request = _payment_request()
    response = client.post(
        f"/payments/requests/{payment_request.id}/proofs",
        data={
            "token": payment_request.access_token,
            "reference_number": "TX-123",
            "note": "sent from wallet",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    refreshed = db.session.get(LicensePaymentRequest, payment_request.id)
    assert refreshed.status == "proof_submitted"
    proof = LicensePaymentProof.query.filter_by(license_payment_request_id=payment_request.id).one()
    assert proof.reference_number == "TX-123"
    assert "بانتظار مراجعة الدفع" in response.get_data(as_text=True)


def test_portal_submit_proof_blocked_for_paid_request(client):
    payment_request = _payment_request()
    payment_request.status = "paid"
    db.session.commit()

    response = client.post(
        f"/api/license-payments/requests/{payment_request.id}/proofs",
        json={
            "token": payment_request.access_token,
            "reference_number": "TX-123",
            "status": "pending",
        },
    )

    assert response.status_code == 400
    assert response.get_json()["error"] == "request_not_open_for_proof"
    assert LicensePaymentProof.query.count() == 0


def test_portal_submit_proof_marks_expired_request(client):
    payment_request = _payment_request()
    payment_request.expires_at = utcnow() - timedelta(minutes=1)
    db.session.commit()

    response = client.post(
        f"/api/license-payments/requests/{payment_request.id}/proofs",
        json={"token": payment_request.access_token, "reference_number": "TX-123"},
    )

    assert response.status_code == 400
    assert response.get_json()["error"] == "request_expired"
    assert db.session.get(LicensePaymentRequest, payment_request.id).status == "expired"


def test_client_cannot_spoof_paid_status_when_submitting_proof(client):
    payment_request = _payment_request()
    response = client.post(
        f"/api/license-payments/requests/{payment_request.id}/proofs",
        json={
            "token": payment_request.access_token,
            "reference_number": "TX-123",
            "status": "paid",
        },
    )

    assert response.status_code == 201
    assert db.session.get(LicensePaymentRequest, payment_request.id).status == "proof_submitted"
