"""PalPay (بال باي) adapter — STUB pending API credentials from the owner.

Same shape as :mod:`jawalpay`; only the wire format / namespace differs. The
single outbound HTTP seam is marked with ``# TODO(payment-gateways)``.
"""
from __future__ import annotations

import hmac
import hashlib
from decimal import Decimal
from typing import Any

from .base import CreatePaymentInput, GatewayResult, NotConfiguredError
from . import _http


class PalPayAdapter:
    name = "palpay"
    label_ar = "بال باي"
    cred_keys = ("api_url", "merchant_id", "client_id", "client_secret")

    def configured(self, creds: dict[str, str]) -> bool:
        return all((creds.get(k) or "").strip() for k in self.cred_keys)

    def create_payment(self, creds: dict[str, str], data: CreatePaymentInput) -> GatewayResult:
        if not self.configured(creds):
            raise NotConfiguredError(f"{self.name} not configured")
        amount, code = self._validate_amount(data.amount, data.currency)
        if code:
            return GatewayResult(False, code=code, message=self._msg(code))

        url = creds["api_url"].rstrip("/") + "/v1/checkout/sessions"
        payload: dict[str, Any] = {
            "merchant": creds["merchant_id"],
            "client_id": creds["client_id"],
            "external_ref": data.reference,
            "amount": str(amount),
            "currency": data.currency,
            "description": data.description,
            "return_url": data.callback_url,
        }
        headers = {
            "Content-Type": "application/json",
            # PalPay uses an HMAC-SHA256 of the canonical payload as Bearer.
            "Authorization": "Bearer " + self._sign(creds["client_secret"], payload),
        }

        # TODO(payment-gateways): PalPay create-checkout-session call. The single
        # network seam — owner replaces `api_url` (sandbox vs production) in the
        # gateway settings page. Expected response shape:
        #   { "session_id": "<id>", "checkout_url": "https://...",
        #     "state": "open|paid|cancelled" }
        result = _http.post_json(url, payload=payload, headers=headers, timeout=15.0)
        if result.error:
            return GatewayResult(False, code="http_error", message=self._msg("http_error"),
                                 meta={"error": result.error})
        if not result.ok:
            return GatewayResult(False, code="provider_error", message=self._msg("provider_error"),
                                 meta={"status": result.status})
        body = result.body or {}
        return GatewayResult(
            True, code="ok", message="تم فتح جلسة الدفع لدى بال باي.",
            provider_payment_id=str(body.get("session_id", "")),
            redirect_url=str(body.get("checkout_url", "")),
            status=self._normalize_status(str(body.get("state", "open")).lower()),
            meta={"raw": body},
        )

    def verify_callback(self, creds: dict[str, str], raw: dict[str, Any]) -> GatewayResult:
        if not self.configured(creds):
            raise NotConfiguredError(f"{self.name} not configured")
        provider_id = str(raw.get("session_id") or raw.get("payment_id") or "").strip()
        if not provider_id:
            return GatewayResult(False, code="missing_payment_id", message=self._msg("missing_payment_id"))
        if not self._signature_ok(creds, raw):
            return GatewayResult(False, code="invalid_signature", message=self._msg("invalid_signature"))
        return GatewayResult(
            True, code="ok", message="تم التحقق من رد بال باي.",
            provider_payment_id=provider_id,
            status=self._normalize_status(str(raw.get("state") or raw.get("status") or "").lower()),
            meta={"raw_state": raw.get("state") or raw.get("status")},
        )

    def status(self, creds: dict[str, str], provider_payment_id: str) -> GatewayResult:
        if not self.configured(creds):
            raise NotConfiguredError(f"{self.name} not configured")
        if not (provider_payment_id or "").strip():
            return GatewayResult(False, code="missing_payment_id", message=self._msg("missing_payment_id"))
        url = creds["api_url"].rstrip("/") + f"/v1/checkout/sessions/{provider_payment_id}"
        headers = {"Authorization": "Bearer " + self._sign(creds["client_secret"], {"sid": provider_payment_id})}

        # TODO(payment-gateways): PalPay status-poll call. Same seam shape.
        result = _http.get_json(url, headers=headers, timeout=15.0)
        if result.error:
            return GatewayResult(False, code="http_error", message=self._msg("http_error"),
                                 meta={"error": result.error})
        if not result.ok:
            return GatewayResult(False, code="provider_error", message=self._msg("provider_error"),
                                 meta={"status": result.status})
        body = result.body or {}
        return GatewayResult(
            True, code="ok", message="تم استرجاع الحالة من بال باي.",
            provider_payment_id=str(body.get("session_id", provider_payment_id)),
            status=self._normalize_status(str(body.get("state", "open")).lower()),
            meta={"raw": body},
        )

    # ────────────────────────────────────────────────────────────────────
    # Pure helpers
    # ────────────────────────────────────────────────────────────────────

    @staticmethod
    def _validate_amount(amount: Decimal, currency: str) -> tuple[Decimal, str]:
        try:
            value = Decimal(amount)
        except Exception:  # noqa: BLE001
            return Decimal(0), "invalid_amount"
        if value <= 0:
            return Decimal(0), "invalid_amount"
        if not (currency or "").strip():
            return Decimal(0), "invalid_currency"
        return value, ""

    @staticmethod
    def _msg(code: str) -> str:
        return {
            "invalid_amount":      "المبلغ غير صحيح.",
            "invalid_currency":    "العملة غير صحيحة.",
            "missing_payment_id":  "معرّف الدفع مفقود.",
            "invalid_signature":   "توقيع رد بال باي غير صحيح.",
            "http_error":          "تعذّر الاتصال ببوابة بال باي.",
            "provider_error":      "ردّت بوابة بال باي بخطأ.",
            "not_configured":      "بيانات بوابة بال باي ناقصة.",
        }.get(code, "خطأ غير معروف من بوابة بال باي.")

    def _signature_ok(self, creds: dict[str, str], raw: dict[str, Any]) -> bool:
        provided = str(raw.get("signature") or "").strip()
        if not provided:
            return False
        canonical = {k: v for k, v in raw.items() if k != "signature"}
        expected = self._sign(creds["client_secret"], canonical)
        return hmac.compare_digest(expected, provided)

    @staticmethod
    def _sign(secret: str, payload: dict[str, Any]) -> str:
        items = "&".join(f"{k}={payload[k]}" for k in sorted(payload))
        return hmac.new(secret.encode("utf-8"), items.encode("utf-8"),
                        hashlib.sha256).hexdigest()

    @staticmethod
    def _normalize_status(raw: str) -> str:
        if raw in {"paid", "completed", "captured"}:
            return "paid"
        if raw in {"failed", "declined", "cancelled", "expired"}:
            return "failed"
        if raw in {"refunded", "reversed"}:
            return "refunded"
        return "pending"


__all__ = ["PalPayAdapter"]
