from __future__ import annotations

from flask import Blueprint, flash, redirect, render_template, request, url_for

from ..models import LicensePaymentProof, LicensePaymentRequest
from ..services.license_payments import (
    LicensePaymentProofService,
    LicensePaymentRequestRepository,
    LicensePaymentValidationError,
    instructions_for_request,
)

bp = Blueprint("public", __name__)


def _get_portal_request(request_id: int) -> LicensePaymentRequest | None:
    token = (request.args.get("token") or request.form.get("token") or "").strip()
    return LicensePaymentRequestRepository().get_for_portal(request_id, token)


@bp.get("/payments/requests/<int:request_id>")
def payment_portal(request_id: int):
    payment_request = _get_portal_request(request_id)
    if not payment_request:
        return render_template("public/payment_not_found.html"), 404
    return render_template(
        "public/payment_portal.html",
        payment_request=payment_request,
        instructions=instructions_for_request(payment_request),
        token=request.args.get("token") or "",
        proofs=payment_request.proofs.order_by(LicensePaymentProof.submitted_at.desc()).all(),
    )


@bp.post("/payments/requests/<int:request_id>/proofs")
def payment_portal_submit_proof(request_id: int):
    payment_request = _get_portal_request(request_id)
    token = request.form.get("token") or request.args.get("token") or ""
    if not payment_request:
        return render_template("public/payment_not_found.html"), 404
    try:
        LicensePaymentProofService().submit_manual_proof(
            payment_request=payment_request,
            reference_number=request.form.get("reference_number") or "",
            note=request.form.get("note") or "",
        )
    except LicensePaymentValidationError as exc:
        flash(str(exc), "error")
        return redirect(url_for("public.payment_portal", request_id=request_id, token=token))
    flash("تم إرسال الإثبات. بانتظار مراجعة الدفع من المدير.", "success")
    return redirect(url_for("public.payment_portal", request_id=request_id, token=token))
