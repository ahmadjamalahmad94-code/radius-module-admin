"""Billing / payment notifications.

Maps onto the existing payment model (there is no separate Invoice/PDF
model — FLAGGED in the report):

* ``LicensePaymentRequest`` (pending)        → new-invoice notification.
* status ``paid`` / ``paid_manual``          → payment-received (+ receipt link).
* pending & past ``expires_at``              → payment-overdue/late.

"Receipt" links to the payment-request detail page (which renders the proof
image / transaction), so the notification carries a link to the document.
All three are idempotent (dedupe per request) so they can be driven either
by the scheduled scan or by a direct hook at the payment seam.
"""
from __future__ import annotations

from typing import Optional

from app.models import LicensePaymentRequest

from . import service
from .models import Notification


def _detail_link(req: LicensePaymentRequest) -> str:
    try:
        from flask import url_for

        return url_for("admin.payment_request_detail", payment_request_id=req.id)
    except Exception:  # noqa: BLE001 — link is best-effort
        return f"/admin/payment-requests/{req.id}"


def _amount(req: LicensePaymentRequest) -> str:
    return f"{req.amount} {req.currency}".strip()


def notify_new_invoice(req: LicensePaymentRequest) -> Optional[Notification]:
    """A new payment request was issued — notify the customer (and center)."""
    if req is None:
        return None
    return service.create(
        type="invoice_new", severity="info",
        title=f"فاتورة جديدة — {_amount(req)}",
        body=(f"صدرت فاتورة جديدة بقيمة {_amount(req)} (مرجع {req.reference_code}). "
              f"اضغط للاطّلاع والدفع."),
        customer_id=req.customer_id, license_id=req.license_id,
        link=_detail_link(req),
        dedupe_key=f"invoice_new:{req.id}",
    )


def notify_payment_received(req: LicensePaymentRequest) -> Optional[Notification]:
    """Payment confirmed — issue a receipt notification linking the document."""
    if req is None:
        return None
    return service.create(
        type="payment_received", severity="info",
        title=f"تم استلام الدفعة — {_amount(req)}",
        body=(f"تم تأكيد دفعتك بقيمة {_amount(req)} (مرجع {req.reference_code}). "
              f"هذا إيصالك — اضغط لعرض الفاتورة والإيصال."),
        customer_id=req.customer_id, license_id=req.license_id,
        link=_detail_link(req),
        dedupe_key=f"payment_received:{req.id}",
    )


def notify_payment_overdue(req: LicensePaymentRequest) -> Optional[Notification]:
    """A pending request is past its due date — overdue/late notice."""
    if req is None:
        return None
    return service.create(
        type="payment_overdue", severity="warning",
        title=f"دفعة متأخرة — {_amount(req)}",
        body=(f"الفاتورة (مرجع {req.reference_code}) بقيمة {_amount(req)} "
              f"تجاوزت موعد الاستحقاق ولم تُسدَّد بعد."),
        customer_id=req.customer_id, license_id=req.license_id,
        link=_detail_link(req),
        dedupe_key=f"payment_overdue:{req.id}",
    )
