"""JawalPay (جوال باي) adapter — STUB pending API credentials from the owner.

Two distinct boundaries in this file:
  1. Pure logic — credential validation, payload shape, signature check
     skeleton. This part is fully testable today.
  2. The single outbound HTTP call site — clearly marked with a
     ``# TODO(payment-gateways)`` comment so when the owner supplies the real
     API URL + credentials, the only place to change is the one ``_http_post``
     line below.

Mirrors the convention used by ``app/services/messaging/adapters/sms.py``.
"""
from __future__ import annotations

import hmac
import hashlib
from decimal import Decimal
from typing import Any

from .base import CreatePaymentInput, GatewayResult, NotConfiguredError, PaymentGateway
from . import _http


class JawalPayAdapter:
    """Jawwal-style mobile wallet gateway.

    Real provider docs will go here when the owner supplies them; the public
    Jawwal Pay (Palestine) API uses an HMAC-signed JSON POST.
    """

    name = "jawalpay"
    label_ar = "جوال باي"
    cred_keys = ("api_url", "merchant_id", "api_key", "api_secret")

    # ────────────────────────────────────────────────────────────────────
    # Contract
    # ────────────────────────────────────────────────────────────────────

    def configured(self, creds: dict[str, str]) -> bool:
        return all((creds.get(k) or "").strip() for k in self.cred_keys)

    def create_payment(self, creds: dict[str, str], data: CreatePaymentInput) -> GatewayResult:
        if not self.configured(creds):
            raise NotConfiguredError(f"{self.name} not configured")

        amount, code = self._validate_amount(data.amount, data.currency)
        if code:
            return GatewayResult(False, code=code, message=self._msg(code))

        url, payload, headers = self._build_create_request(creds, data, amount)
        return self._dispatch_create(url, payload, headers)

    def verify_callback(self, creds: dict[str, str], raw: dict[str, Any]) -> GatewayResult:
        """Verify a redirect/webhook signature without making an HTTP call."""
        if not self.configured(creds):
            raise NotConfiguredError(f"{self.name} not configured")
        provider_id = str(raw.get("payment_id") or raw.get("transaction_id") or "").strip()
        if not provider_id:
            return GatewayResult(False, code="missing_payment_id",
                                 message="لم يتضمّن رد البوابة معرّف الدفع.")
        if not self._signature_ok(creds, raw):
            return GatewayResult(False, code="invalid_signature",
                                 message="توقيع رد البوابة غير صحيح.")
        status = self._normalize_status(str(raw.get("status") or "").lower())
        return GatewayResult(True, code="ok", message="تم التحقق من الرد.",
                             provider_payment_id=provider_id, status=status,
                             meta={"raw_status": raw.get("status")})

    def status(self, creds: dict[str, str], provider_payment_id: str) -> GatewayResult:
        if not self.configured(creds):
            raise NotConfiguredError(f"{self.name} not configured")
        if not (provider_payment_id or "").strip():
            return GatewayResult(False, code="missing_payment_id",
                                 message="معرّف الدفع مفقود.")
        url, headers = self._build_status_request(creds, provider_payment_id)
        return self._dispatch_status(url, headers)

    # ────────────────────────────────────────────────────────────────────
    # Pure logic (testable without network)
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
            "invalid_amount":   "المبلغ غير صحيح.",
            "invalid_currency": "العملة غير صحيحة.",
            "missing_payment_id": "معرّف الدفع مفقود.",
            "invalid_signature":  "توقيع رد البوابة غير صحيح.",
            "http_error":         "تعذّر الاتصال ببوابة جوال باي.",
            "provider_error":     "ردّت بوابة جوال باي بخطأ.",
            "not_configured":     "بيانات بوابة جوال باي ناقصة.",
        }.get(code, "خطأ غير معروف من بوابة جوال باي.")

    def _build_create_request(
        self, creds: dict[str, str], data: CreatePaymentInput, amount: Decimal,
    ) -> tuple[str, dict[str, Any], dict[str, str]]:
        url = (creds["api_url"].rstrip("/")) + "/payments/create"
        payload: dict[str, Any] = {
            "merchant_id": creds["merchant_id"],
            "reference": data.reference,
            "amount": str(amount),
            "currency": data.currency,
            "description": data.description,
            "callback_url": data.callback_url,
            "customer_phone": data.customer_phone,
        }
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {creds['api_key']}",
            "X-Signature": self._sign(creds.get("api_secret", ""), payload),
        }
        return url, payload, headers

    def _build_status_request(
        self, creds: dict[str, str], provider_payment_id: str,
    ) -> tuple[str, dict[str, str]]:
        url = (creds["api_url"].rstrip("/")) + f"/payments/{provider_payment_id}"
        headers = {"Authorization": f"Bearer {creds['api_key']}"}
        return url, headers

    def _signature_ok(self, creds: dict[str, str], raw: dict[str, Any]) -> bool:
        provided = str(raw.get("signature") or "").strip()
        if not provided:
            return False
        canonical = {k: v for k, v in raw.items() if k != "signature"}
        expected = self._sign(creds.get("api_secret", ""), canonical)
        return hmac.compare_digest(expected, provided)

    @staticmethod
    def _sign(secret: str, payload: dict[str, Any]) -> str:
        # Stable canonical form: sorted by key, "=" joined, "&" separated.
        items = "&".join(f"{k}={payload[k]}" for k in sorted(payload))
        return hmac.new(secret.encode("utf-8"), items.encode("utf-8"),
                        hashlib.sha256).hexdigest()

    @staticmethod
    def _normalize_status(raw: str) -> str:
        if raw in {"paid", "completed", "success", "successful"}:
            return "paid"
        if raw in {"failed", "error", "declined", "rejected"}:
            return "failed"
        if raw in {"refunded", "reversed"}:
            return "refunded"
        return "pending"

    # ────────────────────────────────────────────────────────────────────
    # Single network seam (the only TODO in this file)
    # ────────────────────────────────────────────────────────────────────

    def _dispatch_create(
        self, url: str, payload: dict[str, Any], headers: dict[str, str],
    ) -> GatewayResult:
        # TODO(payment-gateways): JawalPay create-payment call. Owner supplies
        # the real `api_url` (production / sandbox) via the gateway settings
        # page. Until then this single seam returns a stub redirect URL so the
        # rest of the system can be exercised end-to-end. Real provider
        # response is expected to be:
        #   { "payment_id": "<id>", "redirect_url": "https://...",
        #     "status": "pending|paid|failed", "raw": {...} }
        result = _http.post_json(url, payload=payload, headers=headers, timeout=15.0)
        if result.error:
            return GatewayResult(False, code="http_error", message=self._msg("http_error"),
                                 meta={"error": result.error})
        if not result.ok:
            return GatewayResult(False, code="provider_error", message=self._msg("provider_error"),
                                 meta={"status": result.status})
        body = result.body or {}
        return GatewayResult(
            True, code="ok", message="تم فتح الدفع لدى بوابة جوال باي.",
            provider_payment_id=str(body.get("payment_id", "")),
            redirect_url=str(body.get("redirect_url", "")),
            status=self._normalize_status(str(body.get("status", "pending")).lower()),
            meta={"raw": body},
        )

    def _dispatch_status(self, url: str, headers: dict[str, str]) -> GatewayResult:
        # TODO(payment-gateways): JawalPay status-poll call. Same seam shape
        # as `_dispatch_create` above.
        result = _http.get_json(url, headers=headers, timeout=15.0)
        if result.error:
            return GatewayResult(False, code="http_error", message=self._msg("http_error"),
                                 meta={"error": result.error})
        if not result.ok:
            return GatewayResult(False, code="provider_error", message=self._msg("provider_error"),
                                 meta={"status": result.status})
        body = result.body or {}
        return GatewayResult(
            True, code="ok", message="تم استرجاع حالة الدفع من بوابة جوال باي.",
            provider_payment_id=str(body.get("payment_id", "")),
            status=self._normalize_status(str(body.get("status", "pending")).lower()),
            meta={"raw": body},
        )


__all__ = ["JawalPayAdapter"]
