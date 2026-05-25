from __future__ import annotations

from datetime import timedelta

from app.extensions import db
from app.models import Customer, LicensePaymentRequest, LicensePaymentTransaction, utcnow
from app.services.license_payments import (
    LicensePaymentProofService,
    LicensePaymentReportingService,
    LicensePaymentRequestService,
    LicensePaymentReviewService,
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
    customer = Customer(company_name="Reporting Payment Customer", contact_name="Owner")
    db.session.add(customer)
    db.session.commit()
    return customer


def _request(customer: Customer, purpose="renewal", amount="79.00") -> LicensePaymentRequest:
    _enable_payments()
    return LicensePaymentRequestService().create_request({
        "customer_id": customer.id,
        "purpose": purpose,
        "amount": amount,
        "currency": "USD",
    })


def test_payment_report_aggregates_counts(client):
    customer = _customer()
    pending = _request(customer, "renewal")
    paid = _request(customer, "setup_fee", "50.00")
    LicensePaymentProofService().submit_manual_proof(payment_request=paid, reference_number="TX-REPORT")
    LicensePaymentReviewService().approve(payment_request=db.session.get(LicensePaymentRequest, paid.id))

    report = LicensePaymentReportingService().report()

    assert report["payments_by_status"]["pending"] == 1
    assert report["payments_by_status"]["paid"] == 1
    assert report["payments_by_purpose"]["renewal"] == 1
    assert report["payments_by_purpose"]["setup_fee"] == 1
    assert report["paid_not_applied_count"] == 1
    assert pending.status == "pending"


def test_reconciliation_detects_paid_without_transaction_and_paid_not_applied(app):
    customer = _customer()
    payment_request = _request(customer, "renewal")
    payment_request.status = "paid"
    db.session.commit()

    result = LicensePaymentReportingService().reconciliation()

    assert len(result["paid_without_transaction"]) == 1
    assert len(result["paid_not_applied"]) == 1
    assert result["paid_without_transaction"][0]["id"] == payment_request.id


def test_expiry_job_marks_pending_without_deleting_records(app):
    customer = _customer()
    payment_request = _request(customer, "renewal")
    payment_request.expires_at = utcnow() - timedelta(minutes=5)
    db.session.commit()

    count = LicensePaymentReportingService().expire_pending_requests()

    assert count == 1
    assert db.session.get(LicensePaymentRequest, payment_request.id).status == "expired"
    assert LicensePaymentRequest.query.count() == 1


def test_reporting_routes_return_safe_json_and_html(client):
    _login(client)
    customer = _customer()
    _request(customer, "renewal")

    report = client.get("/admin/api/payments/reports")
    assert report.status_code == 200
    assert "payments_by_status" in report.get_json()["report"]
    assert "0599000000" not in str(report.get_json())

    reconciliation = client.get("/admin/api/payments/reconciliation")
    assert reconciliation.status_code == 200
    assert "paid_not_applied" in reconciliation.get_json()["reconciliation"]

    page = client.get("/admin/payments/reports")
    assert page.status_code == 200
    html = page.get_data(as_text=True)
    assert "تقارير وتسوية الدفع" in html
    assert "تعليم الطلبات المنتهية" in html


def test_reconciliation_duplicate_provider_transaction_risk_shape(app):
    customer = _customer()
    payment_request = _request(customer, "renewal")
    transaction = LicensePaymentTransaction(
        license_payment_request_id=payment_request.id,
        provider_transaction_id=None,
        amount=payment_request.amount,
        currency=payment_request.currency,
        status="manual_pending",
    )
    db.session.add(transaction)
    db.session.commit()

    result = LicensePaymentReportingService().reconciliation()
    assert result["duplicate_provider_transaction_risks"] == []
