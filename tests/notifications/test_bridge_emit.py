"""Customer-targeted notifications are queued to the customer via the bridge."""
from __future__ import annotations

from app.extensions import db
from app.models import PanelMessage
from app.notifications import service

from .conftest import seed_customer


def test_customer_notification_queues_panel_message(app):
    cust = seed_customer()
    note = service.create(
        type="license_expiry", title="الاشتراك ينتهي قريباً",
        body="جدِّد قبل الانقطاع.", severity="warning",
        customer_id=cust.id, channels=["web", "panel"],
    )
    db.session.commit()

    # The bridge enqueued a to_customer PanelMessage for this customer.
    msgs = PanelMessage.query.filter_by(customer_id=cust.id, direction="to_customer").all()
    assert len(msgs) == 1
    msg = msgs[0]
    assert msg.subject == "الاشتراك ينتهي قريباً"
    assert msg.importance == "warning"
    assert msg.delivered_at is None  # waiting for the customer's next poll
    # the bridge metadata carries the notification linkage
    assert msg.message_metadata.get("notification_id") == note.id
    assert msg.message_metadata.get("type") == "license_expiry"

    # delivery result recorded on the notification
    assert note.delivery["panel"]["ok"] is True
    assert note.delivery["web"]["ok"] is True


def test_owner_notification_does_not_hit_bridge(app):
    # No customer_id → owner-only → no PanelMessage.
    before = PanelMessage.query.count()
    service.create(type="payment_overdue", title="x", body="y", channels=["web"])
    db.session.commit()
    assert PanelMessage.query.count() == before


def test_default_customer_channels_include_panel(app):
    cust = seed_customer()
    note = service.create(type="invoice_new", title="فاتورة", body="ادفع",
                          customer_id=cust.id)
    db.session.commit()
    assert "panel" in note.channels
    assert PanelMessage.query.filter_by(customer_id=cust.id).count() == 1


def test_unconfigured_channel_records_not_configured(app):
    cust = seed_customer()
    note = service.create(type="invoice_new", title="x", body="y",
                          customer_id=cust.id, channels=["web", "email", "push"])
    db.session.commit()
    # email/push are stubs — recorded but not delivered (same interface).
    assert note.delivery["email"]["code"] == "not_configured"
    assert note.delivery["push"]["code"] == "not_configured"
