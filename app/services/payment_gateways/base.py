"""PaymentGateway adapter contract.

Every concrete provider (JawalPay, PalPay, Bank of Palestine, …) implements
this same contract. The router / settings UI never sees provider-specific
shapes — only :class:`GatewayResult`.

This file is intentionally tiny and dependency-free. The single TODO seam in
each concrete adapter (a `_call_provider_http(...)` method) is the only place
where a real provider's HTTP shape will be wired once the owner supplies API
credentials.

Design notes (mirrored from ``app/services/messaging/adapters/base.py``):
- Adapters NEVER raise on provider-side failures. They return
  :class:`GatewayResult` with ``ok=False`` and a user-facing Arabic message.
- :class:`NotConfiguredError` is the one exception adapters may raise when
  credentials are missing — the router treats it as a soft "not configured"
  signal and surfaces a friendly empty state.
- Verification accepts an opaque, provider-shaped ``raw`` dict (HMAC body,
  query params from a redirect, or a JSON webhook payload). The adapter is
  responsible for verifying authenticity (signature / shared secret) before
  returning ``ok=True``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Protocol, runtime_checkable


class NotConfiguredError(RuntimeError):
    """Raised when an adapter is invoked without complete credentials."""


@dataclass(frozen=True)
class GatewayResult:
    """Uniform result for every adapter call.

    Attributes:
        ok: True if the call succeeded.
        code: machine-readable status code; "ok" on success, "not_configured"
            / "http_error" / "invalid_signature" / "provider_error" on failure.
        message: user-facing message in Arabic (safe to flash to the operator).
        provider_payment_id: id minted by the provider for the new payment.
        redirect_url: URL the customer is sent to to complete payment.
        status: best-effort lifecycle status: pending|paid|failed|refunded.
        meta: free-form provider-specific data (never any secrets).
    """

    ok: bool
    code: str = "ok"
    message: str = ""
    provider_payment_id: str = ""
    redirect_url: str = ""
    status: str = ""
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CreatePaymentInput:
    """Input passed to :meth:`PaymentGateway.create_payment`.

    The provider never sees customer PII beyond what the operator chose to
    pass — we keep the input small on purpose (no email/notes/etc.).
    """

    amount: Decimal
    currency: str            # ISO 4217, uppercase
    reference: str           # local LicensePaymentRequest.reference_code
    description: str = ""    # short description shown to the customer at provider
    callback_url: str = ""   # where the provider redirects after payment
    customer_phone: str = "" # optional, in E.164 (used by JawalPay / wallet flows)


@runtime_checkable
class PaymentGateway(Protocol):
    """Contract every concrete adapter satisfies.

    The 3 methods map to the 3 distinct interaction phases:
      * create_payment   — open a transaction at the provider
      * verify_callback  — confirm a redirect / webhook came from the provider
      * status           — poll the provider for an existing payment's status
    """

    #: machine name (lowercase ascii). Acts as the key in the registry and the
    #: settings-store namespace.
    name: str

    #: human-readable Arabic label shown in the admin UI / customer picker.
    label_ar: str

    #: ordered tuple of credential field names this adapter needs in Settings.
    #: Fields ending in `"_key" / "_secret" / "_token" / "password"` are encrypted.
    cred_keys: tuple[str, ...]

    def configured(self, creds: dict[str, str]) -> bool:
        """Return True only if every required credential is non-empty."""
        ...

    def create_payment(self, creds: dict[str, str], data: CreatePaymentInput) -> GatewayResult:
        """Open a new payment at the provider. Returns ok=True with a redirect_url
        on success; ok=False with a code/message on failure."""
        ...

    def verify_callback(self, creds: dict[str, str], raw: dict[str, Any]) -> GatewayResult:
        """Validate an inbound callback / webhook payload from the provider.

        The adapter checks the signature/shared secret. On success, returns
        ok=True with provider_payment_id + status set.
        """
        ...

    def status(self, creds: dict[str, str], provider_payment_id: str) -> GatewayResult:
        """Poll the provider for the current status of an existing payment."""
        ...


__all__ = [
    "CreatePaymentInput",
    "GatewayResult",
    "NotConfiguredError",
    "PaymentGateway",
]
