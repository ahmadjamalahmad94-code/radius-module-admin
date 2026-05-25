from __future__ import annotations

from app.extensions import db
from app.models import Customer, LicensePaymentRequest, Plan
from app.services.license_payments import PlatformPaymentSettingsRepository


def _login(client):
    return client.post("/login", data={"username": "admin", "password": "admin12345"})


def _customer() -> Customer:
    customer = Customer(company_name="API Payment Customer", contact_name="Owner")
    db.session.add(customer)
    db.session.commit()
    return customer


def _enable_payments():
    return PlatformPaymentSettingsRepository().upsert(
        enabled=True,
        provider="manual_wallet",
        wallet_number="0599000000",
        wallet_owner_name="Hobe Wallet",
        currency="USD",
        confirmation_mode="manual",
    )


def test_admin_payment_settings_json(client):
    _login(client)
    response = client.get("/admin/api/payments/settings")
    assert response.status_code == 200
    assert response.get_json()["settings"]["enabled"] is False

    updated = client.patch("/admin/api/payments/settings", json={
        "enabled": True,
        "provider": "manual_wallet",
        "wallet_number": "0599000000",
        "wallet_owner_name": "Hobe Wallet",
        "currency": "ILS",
        "confirmation_mode": "manual",
    })
    assert updated.status_code == 200
    body = updated.get_json()
    assert body["settings"]["enabled"] is True
    assert body["settings"]["wallet_number"] == "0599000000"


def test_create_license_payment_request_success(client):
    _login(client)
    _enable_payments()
    customer = _customer()
    plan = Plan.query.filter_by(slug="pro").first()

    response = client.post("/admin/api/payments/requests", json={
        "customer_id": customer.id,
        "plan_id": plan.id,
        "purpose": "new_subscription",
        "amount": "79.00",
        "currency": "USD",
        "status": "paid",
    })

    assert response.status_code == 201
    body = response.get_json()["payment_request"]
    assert body["status"] == "pending"
    assert body["reference_code"].startswith("LIC-")
    assert body["receiver_wallet"] == "0599000000"
    assert LicensePaymentRequest.query.count() == 1


def test_create_license_payment_request_fails_when_disabled(client):
    _login(client)
    customer = _customer()
    response = client.post("/admin/api/payments/requests", json={
        "customer_id": customer.id,
        "purpose": "new_subscription",
        "amount": "79.00",
        "currency": "USD",
    })
    assert response.status_code == 400
    assert response.get_json()["error"] == "payments_disabled"


def test_create_license_payment_request_rejects_invalid_fields(client):
    _login(client)
    _enable_payments()
    customer = _customer()
    response = client.post("/admin/api/payments/requests", json={
        "customer_id": customer.id,
        "purpose": "card_purchase",
        "amount": "0",
        "currency": "EUR",
    })
    assert response.status_code == 400
    assert LicensePaymentRequest.query.count() == 0


def test_payment_instructions_are_token_scoped_and_safe(client):
    _enable_payments()
    customer = _customer()
    created = client.post("/api/license-payments/requests", json={
        "customer_id": customer.id,
        "purpose": "renewal",
        "amount": "79.00",
        "currency": "USD",
    })
    assert created.status_code == 201
    request_body = created.get_json()["payment_request"]
    payment_request = db.session.get(LicensePaymentRequest, request_body["id"])

    denied = client.get(f"/api/license-payments/requests/{payment_request.id}/instructions?token=bad")
    assert denied.status_code == 404

    response = client.get(
        f"/api/license-payments/requests/{payment_request.id}/instructions?token={payment_request.access_token}"
    )
    assert response.status_code == 200
    payload = response.get_json()["instructions"]
    assert payload["receiver_wallet"] == "0599000000"
    assert payload["reference_code"] == payment_request.reference_code
    assert "access_token" not in str(payload)
    assert "status" in payload


def test_request_list_filters(client):
    _login(client)
    _enable_payments()
    customer = _customer()
    client.post("/admin/api/payments/requests", json={
        "customer_id": customer.id,
        "purpose": "renewal",
        "amount": "79.00",
        "currency": "USD",
    })
    client.post("/admin/api/payments/requests", json={
        "customer_id": customer.id,
        "purpose": "setup_fee",
        "amount": "50.00",
        "currency": "USD",
    })

    response = client.get("/admin/api/payments/requests?purpose=renewal")
    assert response.status_code == 200
    items = response.get_json()["items"]
    assert len(items) == 1
    assert items[0]["purpose"] == "renewal"
