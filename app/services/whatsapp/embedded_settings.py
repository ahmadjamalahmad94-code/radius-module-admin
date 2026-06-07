"""Panel-managed Meta WhatsApp **Embedded Signup** configuration.

Lets the owner enable self-service onboarding and enter the Meta App creds from
the admin SETTINGS UI — ZERO terminal / env editing required. Mirrors the
``cloud_settings`` pattern exactly:

* One config group lives in the key-value ``settings`` table.
* The App Secret is the ONLY secret here — encrypted at rest via
  ``whatsapp/crypto`` (the same Fernet layer ``cloud_settings`` uses for the
  identical ``meta_app_secret``). App ID + Config ID are not secret → stored as
  plain text; the enable flag is a plain ``"1"``/``"0"``.
* Environment variables (``META_*``) act as a FALLBACK so existing env
  deployments keep working; a saved DB value overrides its env fallback.

Resolution order for every value: **DB setting (UI) → env var → built-in
default**. ``embedded_signup`` reads its effective config through
:func:`resolved_config` / :func:`is_enabled` so the UI fully drives availability.

Security rules (identical to ``cloud_settings``):
* The App Secret is NEVER returned to the UI in clear — only ``mask_secret`` +
  a ``present`` flag. Revealing clear text is a separate, audited super-admin
  action.
* The secret is NEVER logged or placed in exception text.
* The master encryption key stays env-only; if it is missing, saving a secret
  is refused with a clear Arabic message (the UI also warns up-front).
"""
from __future__ import annotations

from flask import current_app

from ...extensions import db
from ...models import Setting
from .crypto import WhatsAppCryptoError, decrypt_secret, encrypt_secret, mask_secret

#: Setting key for the enable toggle (plain "1"/"0").
ENABLED_KEY = "whatsapp_embedded.enabled"
#: Env fallback for the enable toggle.
ENABLED_ENV = "META_EMBEDDED_SIGNUP_ENABLED"


class EmbeddedSettingsError(ValueError):
    """Validation / safety error surfaced to the admin UI (Arabic message)."""


# field name → (setting_key, env_config_key, is_secret, numeric)
FIELDS: dict[str, tuple[str, str, bool, bool]] = {
    "app_id": ("whatsapp_embedded.app_id", "META_APP_ID", False, True),
    "app_secret": ("whatsapp_embedded.app_secret", "META_APP_SECRET", True, False),
    "config_id": ("whatsapp_embedded.config_id", "META_CONFIG_ID", False, True),
    "graph_version": ("whatsapp_embedded.graph_version", "META_GRAPH_VERSION", False, False),
}
SECRET_FIELDS = {name for name, f in FIELDS.items() if f[2]}

ARABIC_LABEL = {
    "app_id": "App ID",
    "app_secret": "App Secret",
    "config_id": "Config ID",
    "graph_version": "Graph API version",
}

#: Credentials that must ALL be present for embedded signup to be "available".
REQUIRED_FOR_AVAILABLE = ("app_id", "app_secret", "config_id")


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
    setting_key, env_key, is_secret, _num = FIELDS[name]
    raw = _db_value(setting_key)
    if raw:
        if is_secret:
            try:
                return decrypt_secret(raw), "panel"
            except WhatsAppCryptoError:
                # Corrupt ciphertext / missing key — treat as unset rather than 500.
                return "", "unset"
        return raw, "panel"
    env_val = _env_fallback(name)
    if env_val:
        return env_val, "env"
    return "", "unset"


def _env_fallback(name: str) -> str:
    """Env fallback for a field (graph_version also accepts the legacy var)."""
    _setting_key, env_key, _is_secret, _num = FIELDS[name]
    cfg = current_app.config
    val = (cfg.get(env_key) or "").strip()
    if not val and name == "graph_version":
        val = (cfg.get("WHATSAPP_GRAPH_API_VERSION") or "").strip()
    return val


# ───────────────────────── enable flag ─────────────────────────

def enabled_state() -> tuple[bool, str]:
    """Return ``(is_enabled, source)`` for the toggle. DB row wins over env."""
    raw = _db_value(ENABLED_KEY)
    if raw != "":
        return raw == "1", "panel"
    return bool(current_app.config.get(ENABLED_ENV, False)), "env"


def is_enabled() -> bool:
    return enabled_state()[0]


def graph_version() -> str:
    value, _src = _resolve("graph_version")
    return (value or "v21.0").strip("/")


# ───────────────────────── effective config (for embedded_signup) ─────────────

def resolved_config() -> dict[str, str]:
    """Effective plaintext config for ``embedded_signup`` (not for the UI)."""
    return {name: _resolve(name)[0] for name in FIELDS}


def available() -> bool:
    """True iff embedded signup is enabled AND the minimum creds are present.

    Mirrors the spec: DB-enabled (or env) AND app_id + app_secret + config_id
    present from either source.
    """
    if not is_enabled():
        return False
    return all(_resolve(name)[0] for name in REQUIRED_FOR_AVAILABLE)


# ───────────────────────── encryption readiness ─────────────────────────

def encryption_ready() -> bool:
    """True iff the Fernet master key is configured (a secret can be stored).

    Key-agnostic probe: attempts a tiny encrypt and reports whether it works,
    so the UI can warn before the owner pastes a secret that can't be saved.
    """
    try:
        encrypt_secret("probe")
        return True
    except WhatsAppCryptoError:
        return False


# ───────────────────────── public read API (UI-safe) ─────────────────────────

def get_state() -> dict:
    """UI-safe state. The secret exposes only ``present`` + ``masked``.

    Non-secret fields expose their value so the form can prefill. Every field
    carries its ``source`` (panel|env|unset).
    """
    is_on, enabled_source = enabled_state()
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
        "enabled": is_on,
        "enabled_source": enabled_source,
        "fields": fields,
        "available": available(),
        "configured": all(fields[n]["present"] for n in REQUIRED_FOR_AVAILABLE),
        "graph_version": graph_version(),
        "encryption_ready": encryption_ready(),
    }


# ───────────────────────── validation + save ─────────────────────────

def validate_and_save(form, *, actor_audit) -> None:
    """Validate the submitted form and persist. The secret is write-only: a
    blank submission keeps the stored value. ``actor_audit`` is the auth.audit fn.

    Raises :class:`EmbeddedSettingsError` (Arabic) on validation failure; the
    route commits on success.
    """
    # Enable toggle: checkbox → "1"/"0" (explicit DB row so it overrides env).
    want_enabled = (form.get("enabled") or "").strip().lower() in {"1", "on", "true", "yes"}

    pending: dict[str, str] = {}
    for name, (setting_key, _env, is_secret, numeric) in FIELDS.items():
        submitted = (form.get(name) or "").strip()
        # For the secret, a blank field means "keep existing".
        if is_secret and not submitted:
            continue
        if numeric and submitted and not submitted.isdigit():
            raise EmbeddedSettingsError(f"الحقل «{ARABIC_LABEL[name]}» يجب أن يكون أرقامًا فقط.")
        pending[name] = submitted

    # A new secret can only be stored if the master encryption key is present.
    if "app_secret" in pending and pending["app_secret"] and not encryption_ready():
        raise EmbeddedSettingsError(
            "تخزين App Secret يتطلّب ضبط مفتاح التشفير (WHATSAPP_FERNET_KEY) في البيئة."
        )

    # Persist the enable flag (always an explicit "1"/"0").
    _set_db_value(ENABLED_KEY, "1" if want_enabled else "0")

    # Persist fields (encrypt the secret). Empty non-secret clears the override.
    for name, submitted in pending.items():
        setting_key, _env, is_secret, _num = FIELDS[name]
        _set_db_value(setting_key, encrypt_secret(submitted) if (is_secret and submitted) else submitted)

    actor_audit("whatsapp_embedded_saved", "whatsapp_embedded", "global",
                "WhatsApp Embedded Signup settings saved",
                {"enabled": want_enabled, "fields": sorted(pending.keys())})


def reveal(field: str, *, actor_audit) -> str:
    """Return the clear text of the secret field for temporary display. Audited.

    Only ``app_secret`` is revealable. Never logs the value; the audit row
    records only the field name + source.
    """
    if field not in SECRET_FIELDS:
        raise EmbeddedSettingsError("لا يمكن كشف هذا الحقل.")
    value, source = _resolve(field)
    if not value:
        raise EmbeddedSettingsError("لا توجد قيمة محفوظة لكشفها.")
    actor_audit("whatsapp_embedded_secret_revealed", "whatsapp_embedded", field,
                f"كشف مؤقت لـ {ARABIC_LABEL[field]}", {"field": field, "source": source})
    return value
