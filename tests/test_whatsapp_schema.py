from __future__ import annotations

import pytest
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models import Customer, WhatsAppMessageQueue


WHATSAPP_TABLES = {
    "whatsapp_tenant_accounts",
    "whatsapp_service_settings",
    "whatsapp_templates",
    "whatsapp_message_queue",
    "whatsapp_webhook_events",
    "whatsapp_subscriber_preferences",
    "whatsapp_usage_counters",
}


def _columns(table_name: str) -> set[str]:
    return {column["name"] for column in inspect(db.engine).get_columns(table_name)}


def test_all_whatsapp_tables_exist(app):
    existing = set(inspect(db.engine).get_table_names())
    assert WHATSAPP_TABLES.issubset(existing)


def test_message_queue_key_columns_present(app):
    columns = _columns("whatsapp_message_queue")
    assert {
        "idempotency_key",
        "status",
        "next_attempt_at",
        "provider_message_id",
    }.issubset(columns)


def test_tenant_account_key_columns_present(app):
    columns = _columns("whatsapp_tenant_accounts")
    assert {
        "access_token_encrypted",
        "connection_status",
    }.issubset(columns)


def test_message_queue_idempotency_key_unique_constraint_is_enforced(app):
    customer = Customer(company_name="WhatsApp Customer")
    db.session.add(customer)
    db.session.flush()

    key = "idem-key-duplicate-0001"
    db.session.add_all([
        WhatsAppMessageQueue(
            customer_id=customer.id,
            source_system="radius_module",
            source_event_type="otp_request",
            recipient_phone="+970599000001",
            normalized_recipient_phone="970599000001",
            idempotency_key=key,
        ),
        WhatsAppMessageQueue(
            customer_id=customer.id,
            source_system="radius_module",
            source_event_type="otp_request",
            recipient_phone="+970599000002",
            normalized_recipient_phone="970599000002",
            idempotency_key=key,
        ),
    ])

    with pytest.raises(IntegrityError):
        db.session.commit()

    db.session.rollback()
