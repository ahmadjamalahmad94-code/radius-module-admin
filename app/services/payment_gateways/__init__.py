"""Payment-gateway adapter framework.

Three gateway integrations (JawalPay / PalPay / Bank of Palestine) and one
adapter contract. The actual outbound HTTP call for each gateway lives at a
single ``# TODO(payment-gateways)`` seam — the owner replaces the URL +
credentials once provider keys are available.

Public surface
==============
* :data:`ADAPTERS` — registry keyed by adapter name.
* :func:`get_adapter` — strict lookup; raises if name unknown.
* :func:`available_adapters` — pairs (name, label) for UI rendering.
* :func:`adapter_enabled` — DB-toggle per gateway (default off).
* :func:`resolved_credentials` — decrypts credentials from Setting rows.
* :class:`PaymentGateway`, :class:`GatewayResult`,
  :class:`CreatePaymentInput` — re-exported from .base for convenience.
"""
from __future__ import annotations

from typing import Iterable

from .base import (
    CreatePaymentInput,
    GatewayResult,
    NotConfiguredError,
    PaymentGateway,
)
from .bank_of_palestine import BankOfPalestineAdapter
from .jawalpay import JawalPayAdapter
from .palpay import PalPayAdapter


# Concrete singletons (adapters are stateless).
ADAPTERS: dict[str, PaymentGateway] = {
    "jawalpay": JawalPayAdapter(),
    "palpay":   PalPayAdapter(),
    "bank_of_palestine": BankOfPalestineAdapter(),
}

# Stable display order in the admin UI and customer picker. Manual transfer
# is NOT here — it has no API surface (the customer uploads a receipt and the
# owner approves). The manual method is handled directly in the payment form.
GATEWAY_ORDER: tuple[str, ...] = ("jawalpay", "palpay", "bank_of_palestine")


def get_adapter(name: str) -> PaymentGateway:
    key = (name or "").strip().lower()
    if key not in ADAPTERS:
        raise KeyError(f"Unknown payment gateway: {name!r}")
    return ADAPTERS[key]


def available_adapters() -> list[tuple[str, str]]:
    """List (name, arabic_label) in display order."""
    return [(n, ADAPTERS[n].label_ar) for n in GATEWAY_ORDER if n in ADAPTERS]


def required_cred_fields(name: str) -> tuple[str, ...]:
    return tuple(get_adapter(name).cred_keys)


# ────────────────────────────────────────────────────────────────────
# Settings store — encrypted at rest via app master Fernet key.
# ────────────────────────────────────────────────────────────────────

# Field-name suffixes that mark a credential as a SECRET and must be
# encrypted at rest. Adapters declare fields like "api_key", "client_secret",
# "shared_key", "password", "api_secret" — all of which match these suffixes.
_SECRET_SUFFIXES: tuple[str, ...] = (
    "_key", "_secret", "_token", "password", "shared_key",
)


def _is_secret_field(field: str) -> bool:
    f = (field or "").lower()
    return any(f.endswith(s) for s in _SECRET_SUFFIXES) or f == "password"


def _setting_key(gateway: str, field: str) -> str:
    return f"payment_gateways.{gateway}.{field}"


def _enabled_key(gateway: str) -> str:
    return f"payment_gateways.{gateway}.enabled"


def adapter_enabled(name: str) -> bool:
    """Read the per-gateway enable flag from the ``Setting`` table."""
    from ...extensions import db
    from ...models import Setting
    row = db.session.get(Setting, _enabled_key(name))
    return bool(row and (row.value or "").strip() in ("1", "true", "on", "yes"))


def set_adapter_enabled(name: str, enabled: bool) -> None:
    from ...extensions import db
    from ...models import Setting
    key = _enabled_key(name)
    row = db.session.get(Setting, key)
    if row is None:
        row = Setting(key=key)
    row.value = "1" if enabled else "0"
    db.session.add(row)


def _read_raw(field_key: str) -> str:
    from ...extensions import db
    from ...models import Setting
    row = db.session.get(Setting, field_key)
    return (row.value or "") if row else ""


def _write_raw(field_key: str, value: str) -> None:
    from ...extensions import db
    from ...models import Setting
    row = db.session.get(Setting, field_key)
    if row is None:
        row = Setting(key=field_key)
    row.value = value
    db.session.add(row)


def resolved_credentials(name: str) -> dict[str, str]:
    """Return plaintext credentials for ``name`` — INTERNAL USE ONLY.

    Secret fields are decrypted via the panel's app master Fernet key. If the
    key isn't configured (no WHATSAPP_FERNET_KEY) the secret values come back
    as empty strings so ``adapter.configured(creds)`` returns False — no
    crash, just "not configured".
    """
    from .. import whatsapp  # local import to avoid cold import at startup
    adapter = get_adapter(name)
    out: dict[str, str] = {}
    for field in adapter.cred_keys:
        raw = _read_raw(_setting_key(name, field))
        if _is_secret_field(field) and raw:
            try:
                out[field] = whatsapp.crypto.decrypt_secret(raw)
            except whatsapp.crypto.WhatsAppCryptoError:
                out[field] = ""  # secret unrecoverable → adapter sees "not configured"
        else:
            out[field] = raw
    return out


def store_credentials(name: str, plaintext_creds: dict[str, str]) -> None:
    """Persist credentials for ``name``; secrets are encrypted at rest.

    Pass an empty string to clear a field. The caller commits + audits. The
    audit metadata MUST NOT include the plaintext values — pass only the
    boolean "field present yes/no".
    """
    from .. import whatsapp
    adapter = get_adapter(name)
    for field in adapter.cred_keys:
        if field not in plaintext_creds:
            continue
        plain = (plaintext_creds.get(field) or "").strip()
        if _is_secret_field(field):
            if plain:
                try:
                    encrypted = whatsapp.crypto.encrypt_secret(plain)
                except whatsapp.crypto.WhatsAppCryptoError as exc:
                    raise RuntimeError(
                        "تخزين بيانات بوابة الدفع يتطلّب ضبط WHATSAPP_FERNET_KEY."
                    ) from exc
                _write_raw(_setting_key(name, field), encrypted)
            else:
                _write_raw(_setting_key(name, field), "")
        else:
            _write_raw(_setting_key(name, field), plain)


def masked_credentials(name: str) -> dict[str, str]:
    """UI-safe snapshot — secrets returned as ``mask`` hints, never plaintext.

    Non-secret fields (URLs, merchant_id, terminal_id) are returned as is so
    the operator can see what's configured without revealing keys.
    """
    from .. import whatsapp
    adapter = get_adapter(name)
    out: dict[str, str] = {}
    for field in adapter.cred_keys:
        raw = _read_raw(_setting_key(name, field))
        if _is_secret_field(field):
            if not raw:
                out[field] = ""
            else:
                try:
                    plain = whatsapp.crypto.decrypt_secret(raw)
                    out[field] = whatsapp.crypto.mask_secret(plain)
                except whatsapp.crypto.WhatsAppCryptoError:
                    out[field] = "—"  # secret stored but unrecoverable
        else:
            out[field] = raw
    return out


__all__ = [
    "ADAPTERS",
    "CreatePaymentInput",
    "GATEWAY_ORDER",
    "GatewayResult",
    "NotConfiguredError",
    "PaymentGateway",
    "adapter_enabled",
    "available_adapters",
    "get_adapter",
    "masked_credentials",
    "required_cred_fields",
    "resolved_credentials",
    "set_adapter_enabled",
    "store_credentials",
]
