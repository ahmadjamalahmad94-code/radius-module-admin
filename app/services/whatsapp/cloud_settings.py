"""Panel-level Meta WhatsApp Cloud API credentials — admin-managed settings.

Stores ONE house credential set in the key-value ``settings`` table. Secrets
(access token, app secret) are encrypted at rest via ``whatsapp/crypto``; the
non-secret IDs are stored as-is. Environment variables act as a FALLBACK; a DB
value overrides its env fallback only when explicitly saved.

Security rules:
* Secrets are NEVER returned to the UI in clear — only ``mask_secret`` previews
  + a ``present`` flag. Revealing clear text is a separate, audited action.
* Secrets are NEVER logged or placed in exception text.
* Test connection / send go through ``MetaCloudWhatsAppProvider`` (the single
  audited, monkeypatchable network layer) using an in-memory account shim — no
  customer account row is created or touched.
"""
from __future__ import annotations

from flask import current_app

from ...extensions import db
from ...models import Setting
from .crypto import WhatsAppCryptoError, decrypt_secret, encrypt_secret, mask_secret
from .providers import MetaCloudWhatsAppProvider, WhatsAppProviderError


class CloudSettingsError(ValueError):
    """Validation / safety error surfaced to the admin UI (Arabic message)."""


# field name → (setting_key, env_config_key, is_secret, required, numeric)
FIELDS: dict[str, tuple[str, str, bool, bool, bool]] = {
    "access_token": ("whatsapp_cloud.access_token", "WHATSAPP_ACCESS_TOKEN", True, True, False),
    "phone_number_id": ("whatsapp_cloud.phone_number_id", "WHATSAPP_PHONE_NUMBER_ID", False, True, True),
    "whatsapp_business_account_id": ("whatsapp_cloud.whatsapp_business_account_id", "WHATSAPP_BUSINESS_ACCOUNT_ID", False, True, True),
    "meta_app_id": ("whatsapp_cloud.meta_app_id", "META_APP_ID", False, False, True),
    "meta_app_secret": ("whatsapp_cloud.meta_app_secret", "META_APP_SECRET", True, False, False),
    "meta_config_id": ("whatsapp_cloud.meta_config_id", "META_CONFIG_ID", False, False, True),
}
SECRET_FIELDS = {name for name, f in FIELDS.items() if f[2]}

ARABIC_LABEL = {
    "access_token": "رمز الوصول",
    "phone_number_id": "Phone Number ID",
    "whatsapp_business_account_id": "WhatsApp Business Account ID",
    "meta_app_id": "Meta App ID",
    "meta_app_secret": "Meta App Secret",
    "meta_config_id": "Embedded Signup Config ID",
}


# ───────────────────────── config / availability ─────────────────────────

def enabled() -> bool:
    return bool(current_app.config.get("WHATSAPP_CLOUD_SETTINGS_ENABLED", False))


def graph_version() -> str:
    cfg = current_app.config
    return (cfg.get("META_GRAPH_VERSION") or cfg.get("WHATSAPP_GRAPH_API_VERSION") or "v21.0").strip("/")


# ───────────────────────── low-level store ─────────────────────────

def _db_value(key: str) -> str:
    row = db.session.get(Setting, key)
    return (row.value or "") if row else ""


def _set_db_value(key: str, value: str) -> None:
    row = db.session.get(Setting, key)
    if not row:
        row = Setting(key=key)
    row.value = value
    db.session.add(row)


def _resolve(name: str) -> tuple[str, str]:
    """Return ``(plaintext_value, source)`` where source ∈ panel|env|unset.

    DB value (decrypted for secrets) wins when present; else the env fallback.
    """
    setting_key, env_key, is_secret, _req, _num = FIELDS[name]
    raw = _db_value(setting_key)
    if raw:
        if is_secret:
            try:
                return decrypt_secret(raw), "panel"
            except WhatsAppCryptoError:
                # Corrupt ciphertext — treat as unset rather than 500.
                return "", "unset"
        return raw, "panel"
    env_val = (current_app.config.get(env_key) or "").strip()
    if env_val:
        return env_val, "env"
    return "", "unset"


# ───────────────────────── public read API ─────────────────────────

def get_state() -> dict:
    """UI-safe state. Secrets expose only ``present`` + ``masked`` (never clear).

    Non-secret fields expose their value so the form can prefill. Every field
    carries its ``source`` (panel|env|unset).
    """
    fields: dict[str, dict] = {}
    for name in FIELDS:
        value, source = _resolve(name)
        is_secret = FIELDS[name][2]
        entry = {"name": name, "label": ARABIC_LABEL[name], "source": source, "present": bool(value)}
        if is_secret:
            entry["masked"] = mask_secret(value) if value else "—"
            entry["value"] = ""  # never prefill a secret
        else:
            entry["value"] = value
        fields[name] = entry
    return {
        "fields": fields,
        "configured": all(fields[n]["present"] for n in ("access_token", "phone_number_id", "whatsapp_business_account_id")),
        "graph_version": graph_version(),
    }


def resolved() -> dict:
    """Internal: the effective plaintext values for test/send (not for the UI)."""
    return {name: _resolve(name)[0] for name in FIELDS}


# ───────────────────────── validation + save ─────────────────────────

def validate_and_save(form, *, actor_audit) -> None:
    """Validate the submitted form and persist. Secrets are write-only: a blank
    submission keeps the stored value. ``actor_audit`` is the auth.audit fn.

    Raises :class:`CloudSettingsError` (Arabic) on validation failure; the route
    commits on success.
    """
    pending: dict[str, str] = {}
    for name, (setting_key, _env, is_secret, required, numeric) in FIELDS.items():
        submitted = (form.get(name) or "").strip()
        # For secrets, a blank field means "keep existing".
        if is_secret and not submitted:
            effective, _src = _resolve(name)
            if required and not effective:
                raise CloudSettingsError(f"الحقل «{ARABIC_LABEL[name]}» مطلوب.")
            continue
        if required and not submitted:
            raise CloudSettingsError(f"الحقل «{ARABIC_LABEL[name]}» مطلوب.")
        if numeric and submitted and not submitted.isdigit():
            raise CloudSettingsError(f"الحقل «{ARABIC_LABEL[name]}» يجب أن يكون أرقامًا فقط.")
        pending[name] = submitted

    # Persist (encrypt secrets). Empty non-secret clears the stored override.
    for name, submitted in pending.items():
        setting_key, _env, is_secret, _req, _num = FIELDS[name]
        _set_db_value(setting_key, encrypt_secret(submitted) if (is_secret and submitted) else submitted)

    actor_audit("whatsapp_cloud_saved", "whatsapp_cloud", "global",
                "WhatsApp Cloud API credentials saved",
                {"fields": sorted(pending.keys())})


def reveal(field: str, *, actor_audit) -> str:
    """Return the clear text of a secret field for temporary display. Audited.

    Only ``access_token`` / ``meta_app_secret`` are revealable. Never logs the
    value; the audit row records only the field name.
    """
    if field not in SECRET_FIELDS:
        raise CloudSettingsError("لا يمكن كشف هذا الحقل.")
    value, source = _resolve(field)
    if not value:
        raise CloudSettingsError("لا توجد قيمة محفوظة لكشفها.")
    actor_audit("whatsapp_cloud_secret_revealed", "whatsapp_cloud", field,
                f"كشف مؤقت لـ {ARABIC_LABEL[field]}", {"field": field, "source": source})
    return value


# ───────────────────────── test connection / send ─────────────────────────

class _AccountShim:
    """In-memory stand-in the provider can read (token + phone). No DB row."""

    def __init__(self, token: str, phone_number_id: str) -> None:
        self.access_token_encrypted = encrypt_secret(token) if token else None
        self.phone_number_id = phone_number_id or ""


def test_connection(*, actor_audit) -> dict:
    """Verify the resolved credentials against Meta. Never raises for provider
    errors — returns a structured result. Audits success/failure."""
    creds = resolved()
    token = creds["access_token"]
    phone = creds["phone_number_id"]
    waba = creds["whatsapp_business_account_id"]
    if not (token and phone and waba):
        raise CloudSettingsError("أكمل رمز الوصول و Phone Number ID و Business Account ID أولًا.")

    provider = MetaCloudWhatsAppProvider()
    shim = _AccountShim(token, phone)
    try:
        info = provider.validate_credentials(shim)
    except WhatsAppProviderError as exc:
        actor_audit("whatsapp_cloud_test_failed", "whatsapp_cloud", "global",
                    "WhatsApp Cloud test connection failed", {"code": exc.code})
        return {"ok": False, "code": exc.code, "message": exc.message}

    # Best-effort WABA reachability (does not fail the overall check).
    waba_ok = False
    try:
        provider._request("GET", waba, token, params={"fields": "id"})
        waba_ok = True
    except WhatsAppProviderError:
        waba_ok = False

    actor_audit("whatsapp_cloud_test_success", "whatsapp_cloud", "global",
                "WhatsApp Cloud test connection succeeded",
                {"waba_reachable": waba_ok, "phone": info.get("display_phone_number") or ""})
    return {
        "ok": True,
        "display_phone_number": info.get("display_phone_number") or "",
        "business_display_name": info.get("business_display_name") or "",
        "quality_rating": info.get("quality_rating") or "",
        "waba_reachable": waba_ok,
    }


def send_test_message(recipient: str, *, actor_audit) -> dict:
    """Send a simple text test message to ``recipient``. Audited. Never raises
    for provider errors — returns a structured result."""
    recipient = (recipient or "").strip()
    if not recipient:
        raise CloudSettingsError("أدخل رقم واتساب المستلم.")
    creds = resolved()
    token = creds["access_token"]
    phone = creds["phone_number_id"]
    if not (token and phone):
        raise CloudSettingsError("أكمل رمز الوصول و Phone Number ID أولًا.")

    provider = MetaCloudWhatsAppProvider()
    shim = _AccountShim(token, phone)
    body = "رسالة اختبار من لوحة HobeRadius ✅ — تم ضبط واتساب Cloud API بنجاح."
    try:
        result = provider.send_text_message(shim, recipient=recipient, body=body)
    except WhatsAppProviderError as exc:
        actor_audit("whatsapp_cloud_test_message_failed", "whatsapp_cloud", "global",
                    "WhatsApp Cloud test message failed", {"code": exc.code})
        return {"ok": False, "code": exc.code, "message": exc.message}

    actor_audit("whatsapp_cloud_test_message_sent", "whatsapp_cloud", "global",
                "WhatsApp Cloud test message sent",
                {"provider_message_id": result.get("provider_message_id") or ""})
    return {"ok": True, "provider_message_id": result.get("provider_message_id") or ""}
