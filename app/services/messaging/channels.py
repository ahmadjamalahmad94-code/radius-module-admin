"""Catalog of supported channels + owner event types (no I/O, no DB)."""
from __future__ import annotations

#: Channel identifiers used as DB keys, dict keys, and URL fragments.
CHANNELS: tuple[str, ...] = ("sms", "whatsapp", "telegram")

#: Arabic labels for the UI.
CHANNEL_LABELS: dict[str, str] = {
    "sms": "SMS",
    "whatsapp": "واتساب",
    "telegram": "تيليجرام",
}

#: Owner-side event types the panel can broadcast. The wire-up of any
#: individual event lives in ``admin/routes.py`` — see ``notify_owner`` calls.
OWNER_EVENTS: tuple[str, ...] = (
    "customer_created",
    "payment_request_created",
    "service_request_created",
    "license_expiring",
    "license_expired",
)

OWNER_EVENT_LABELS: dict[str, str] = {
    "customer_created": "إنشاء عميل جديد",
    "payment_request_created": "طلب دفع جديد",
    "service_request_created": "طلب خدمة جديد",
    "license_expiring": "اقتراب انتهاء ترخيص",
    "license_expired": "انتهاء ترخيص",
}
