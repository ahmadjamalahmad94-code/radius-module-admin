"""Billing notifications: new-invoice, payment-received, overdue."""
from __future__ import annotations

from datetime import timedelta

from app.extensions import db
from app.notifications import billing
from app.notifications.engine import scan_once
from app.notifications.models import Notification

from .conftest import BASE_NOW, seed_customer, seed_payment_request


def test_new_invoice_notification(app):
    cust = seed_customer()
    req = seed_payment_request(cust, amount=25)
    note = billing.notify_new_invoice(req)
    db.session.commit()
    assert note.type == "invoice_new"
    assert note.customer_id == cust.id
    assert "25" in note.title
    assert note.link  # deep-link to the payment-request detail
    assert note.dedupe_key == f"invoice_new:{req.id}"


def test_payment_received_notification_links_receipt(app):
    cust = seed_customer()
    req = seed_payment_request(cust, amount=40, status="paid")
    note = billing.notify_payment_received(req)
    db.session.commit()
    assert note.type == "payment_received"
    assert "إيصال" in note.body or "الإيصال" in note.body
    assert note.link
    # idempotent
    again = billing.notify_payment_received(req)
    db.session.commit()
    assert again.id == note.id


def test_engine_detects_overdue_pending_request(app):
    cust = seed_customer()
    # pending + already past due
    req = seed_payment_request(cust, status="pending",
                               expires_at=BASE_NOW - timedelta(days=1))
    scan_once(now=BASE_NOW)
    rows = Notification.query.filter_by(type="payment_overdue").all()
    assert len(rows) == 1
    assert rows[0].dedupe_key == f"payment_overdue:{req.id}"

    # not-yet-due pending request does NOT fire
    req2 = seed_payment_request(cust, status="pending",
                                expires_at=BASE_NOW + timedelta(days=5))
    scan_once(now=BASE_NOW)
    assert Notification.query.filter_by(
        dedupe_key=f"payment_overdue:{req2.id}").count() == 0


def test_paid_request_is_not_overdue(app):
    cust = seed_customer()
    seed_payment_request(cust, status="paid",
                         expires_at=BASE_NOW - timedelta(days=3))
    scan_once(now=BASE_NOW)
    assert Notification.query.filter_by(type="payment_overdue").count() == 0
