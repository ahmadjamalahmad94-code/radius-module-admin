from __future__ import annotations

from app.extensions import db
from app.models import Customer
from app.services.customer_control import (
    SERVICE_LIMIT_FIELDS,
    service_catalog_items,
)
from app.services.whatsapp import settings as wa


def make_customer(name: str = "WA Gateway ISP") -> Customer:
    customer = Customer(company_name=name, contact_name="Admin", email="wa-gw@example.test")
    db.session.add(customer)
    db.session.commit()
    return customer


# ---------------------------------------------------------------------------
# Catalog registration
# ---------------------------------------------------------------------------
def test_whatsapp_gateway_present_in_resolved_catalog(app):
    """The seeded service catalog (seed_defaults -> seed_service_catalog) must
    expose ``whatsapp_gateway`` with default_enabled False."""
    items = {item.service_key: item for item in service_catalog_items()}
    assert "whatsapp_gateway" in items
    entry = items["whatsapp_gateway"]
    assert entry.default_enabled is False
    assert entry.category == "communications"
    assert entry.name == "WhatsApp Gateway"
    assert entry.name_ar == "رسائل واتساب للمشتركين"


def test_whatsapp_gateway_limit_fields(app):
    fields = SERVICE_LIMIT_FIELDS["whatsapp_gateway"]
    keys = [key for (key, _label, _desc) in fields]
    assert keys == ["max_messages_monthly", "max_messages_daily", "max_templates"]
    # Arabic labels are carried alongside each field key.
    labels = {key: label for (key, label, _desc) in fields}
    assert labels["max_messages_monthly"] == "حد الرسائل الشهري"
    assert labels["max_messages_daily"] == "حد الرسائل اليومي"
    assert labels["max_templates"] == "حد القوالب"


# ---------------------------------------------------------------------------
# Plan presets
# ---------------------------------------------------------------------------
def test_apply_plan_preset_pro(app):
    customer = make_customer()
    settings = wa.apply_plan_preset(customer.id, "whatsapp_pro")
    assert settings.plan_code == "whatsapp_pro"
    assert settings.monthly_message_limit == 2000
    assert settings.daily_message_limit == 300
    assert settings.per_minute_limit == 30
    assert settings.allow_bulk_utility is True


def test_apply_plan_preset_unknown_falls_back_to_basic(app):
    customer = make_customer(name="WA Gateway Fallback")
    settings = wa.apply_plan_preset(customer.id, "totally_unknown_plan")
    assert settings.plan_code == "whatsapp_basic"
    assert settings.monthly_message_limit == 500
    assert settings.daily_message_limit == 100
    assert settings.per_minute_limit == 10
    assert settings.allow_bulk_utility is False
