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

import re

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


#: Default approved template every WhatsApp Business account ships with.
DEFAULT_TEST_TEMPLATE = "hello_world"
DEFAULT_TEST_LANGUAGE = "en_US"


def send_test_message(recipient: str, *, template_name: str = "", language: str = "", actor_audit) -> dict:
    """Send a test message to ``recipient`` via an APPROVED TEMPLATE. Audited.

    WhatsApp forbids free-form text to a recipient unless they messaged the
    business in the last 24h (the customer-service window). A test number rarely
    has an open window, so we send an approved template (default ``hello_world``)
    which Meta allows at any time. Never raises for provider errors — returns a
    structured result.
    """
    recipient = (recipient or "").strip()
    if not recipient:
        raise CloudSettingsError("أدخل رقم واتساب المستلم.")
    template_name = (template_name or "").strip() or DEFAULT_TEST_TEMPLATE
    language = (language or "").strip() or DEFAULT_TEST_LANGUAGE
    creds = resolved()
    token = creds["access_token"]
    phone = creds["phone_number_id"]
    waba = creds["whatsapp_business_account_id"]
    if not (token and phone):
        raise CloudSettingsError("أكمل رمز الوصول و Phone Number ID أولًا.")

    # Inspect the template so we can auto-fill placeholder body variables and
    # refuse media-header templates (which need a real image/video URL).
    body_params, header_format = _template_shape(token, waba, template_name, language)
    if header_format in _MEDIA_HEADERS:
        return {"ok": False, "code": "needs_media",
                "message": ("القالب «" + template_name + "» يتطلّب وسائط (صورة/فيديو/مستند) في الترويسة "
                            "ولا يمكن اختباره تلقائيًا. جرّب قالبًا نصّيًا مثل hello_world.")}
    variables = ["تجربة"] * body_params if body_params else None

    provider = MetaCloudWhatsAppProvider()
    shim = _AccountShim(token, phone)
    try:
        result = provider.send_template_message(
            shim, recipient=recipient, template_name=template_name,
            language=language, variables=variables,
        )
    except WhatsAppProviderError as exc:
        actor_audit("whatsapp_cloud_test_message_failed", "whatsapp_cloud", "global",
                    "WhatsApp Cloud test message failed",
                    {"code": exc.code, "template": template_name})
        # Add a hint for the most common cause: the template isn't approved in
        # this WABA / the name or language is wrong.
        msg = exc.message
        if exc.code == "meta_request_invalid":
            msg = (exc.message + " تأكّد أن القالب «" + template_name + "» معتمد في حسابك "
                   "وأن اللغة «" + language + "» صحيحة، وأن الرقم بصيغة دولية بدون +.")
        return {"ok": False, "code": exc.code, "message": msg}

    actor_audit("whatsapp_cloud_test_message_sent", "whatsapp_cloud", "global",
                "WhatsApp Cloud test message sent",
                {"provider_message_id": result.get("provider_message_id") or "",
                 "template": template_name})
    return {"ok": True, "provider_message_id": result.get("provider_message_id") or ""}


_PARAM_RE = re.compile(r"{{\s*\d+\s*}}")
_MEDIA_HEADERS = {"IMAGE", "VIDEO", "DOCUMENT", "LOCATION"}


def _parse_components(components) -> tuple[int, str]:
    """Return ``(body_param_count, header_format)`` for a template's components.

    ``body_param_count`` is the number of distinct ``{{n}}`` placeholders in the
    BODY text; ``header_format`` is the HEADER component's format (TEXT / IMAGE /
    VIDEO / DOCUMENT / "") so the caller can tell whether media is required.
    """
    body_params = 0
    header_format = ""
    for c in (components or []):
        if not isinstance(c, dict):
            continue
        ctype = (c.get("type") or "").upper()
        if ctype == "BODY":
            body_params = len(set(_PARAM_RE.findall(c.get("text") or "")))
        elif ctype == "HEADER":
            header_format = (c.get("format") or "").upper()
    return body_params, header_format


def _template_shape(token: str, waba: str, name: str, language: str) -> tuple[int, str]:
    """Best-effort lookup of a template's body-param count + header format.

    Used to auto-fill placeholder body variables for the test message. Returns
    ``(0, "")`` on any failure so the caller can still attempt the send.
    """
    if not (token and waba and name):
        return 0, ""
    provider = MetaCloudWhatsAppProvider()
    try:
        _status, resp = provider._request(
            "GET", f"{waba}/message_templates", token,
            params={"name": name, "fields": "name,language,status,components", "limit": 50},
        )
    except WhatsAppProviderError:
        return 0, ""
    data = resp.get("data") if isinstance(resp, dict) else None
    exact = None
    by_name = None
    for t in (data or []):
        if not isinstance(t, dict) or t.get("name") != name:
            continue
        by_name = by_name or t
        if not language or t.get("language") == language:
            exact = t
            break
    chosen = exact or by_name
    return _parse_components(chosen.get("components")) if chosen else (0, "")


def list_message_templates(limit: int = 200) -> dict:
    """List the WABA's message templates (name/language/status/category).

    Lets the admin pick a template that actually exists in their account instead
    of guessing ``hello_world``. Approved templates are returned first. Never
    raises for provider errors — returns ``{ok: False, message}``.
    """
    creds = resolved()
    token = creds["access_token"]
    waba = creds["whatsapp_business_account_id"]
    if not (token and waba):
        raise CloudSettingsError("أكمل رمز الوصول و Business Account ID أولًا.")
    provider = MetaCloudWhatsAppProvider()
    try:
        _status, resp = provider._request(
            "GET", f"{waba}/message_templates", token,
            params={"fields": "name,language,status,category,components", "limit": int(limit)},
        )
    except WhatsAppProviderError as exc:
        return {"ok": False, "message": exc.message}
    data = resp.get("data") if isinstance(resp, dict) else None
    items = []
    for t in (data or []):
        if isinstance(t, dict) and t.get("name"):
            body_params, header_format = _parse_components(t.get("components"))
            items.append({
                "name": t.get("name"),
                "language": t.get("language") or "",
                "status": (t.get("status") or "").upper(),
                "category": (t.get("category") or "").upper(),
                "body_params": body_params,
                "needs_media": header_format in _MEDIA_HEADERS,
                # quick-test friendly = approved + no media header (body params are auto-filled)
                "testable": (t.get("status") or "").upper() == "APPROVED" and header_format not in _MEDIA_HEADERS,
            })
    # approved + testable first, then by name
    items.sort(key=lambda x: (0 if x["status"] == "APPROVED" else 1, 0 if x["testable"] else 1, x["name"]))
    return {"ok": True, "templates": items}
