"""Owner-level TweetSMS credential store (encrypted, masked).

ONE provider account belongs to the OWNER (he bought the credit) and is used to
SMS his own customers. Stored in the key-value ``settings`` table under
``tweetsms.*`` keys; secrets (``api_key``, ``pass``) are encrypted at rest via
``tweetsms/crypto``. The UI only ever sees masked previews + a ``present`` flag —
clear text is returned solely by the separate, audited :func:`reveal`.

Auth is EITHER an ``api_key`` OR a ``user`` + ``pass`` pair, plus an approved
``sender`` name (required to actually send).
"""
from __future__ import annotations

from flask import current_app

from ...extensions import db
from ...models import Setting
from .crypto import decrypt_secret, encrypt_secret, mask_secret

# field → (setting_key, is_secret)
FIELDS: dict[str, tuple[str, bool]] = {
    "api_key": ("tweetsms.api_key", True),
    "user": ("tweetsms.user", False),
    "pass": ("tweetsms.pass", True),
    "sender": ("tweetsms.sender", False),
}
SECRET_FIELDS = {name for name, (_k, is_secret) in FIELDS.items() if is_secret}

ARABIC_LABEL = {
    "api_key": "مفتاح API",
    "user": "اسم المستخدم",
    "pass": "كلمة المرور",
    "sender": "اسم المُرسِل",
}


class TweetSmsSettingsError(ValueError):
    """Validation error surfaced to the admin UI (Arabic message)."""


# ── low-level kv ──────────────────────────────────────────────────────────

def _db_value(key: str) -> str:
    row = db.session.get(Setting, key)
    return (row.value or "") if row else ""


def _set_db_value(key: str, value: str) -> None:
    row = db.session.get(Setting, key)
    if not row:
        row = Setting(key=key)
    row.value = value
    db.session.add(row)


def _resolve_one(name: str) -> str:
    setting_key, is_secret = FIELDS[name]
    raw = _db_value(setting_key)
    if not raw:
        return ""
    return decrypt_secret(raw) if is_secret else raw


# ── public read API ───────────────────────────────────────────────────────

def resolved() -> dict[str, str]:
    """Plaintext creds for the adapter — INTERNAL ONLY (never a Jinja context)."""
    return {name: _resolve_one(name) for name in FIELDS}


def configured() -> bool:
    """Can we actually send? Needs auth (api_key OR user+pass) AND a sender."""
    creds = resolved()
    has_auth = bool(creds["api_key"]) or bool(creds["user"] and creds["pass"])
    return has_auth and bool(creds["sender"])


def get_state() -> dict:
    """UI-safe state: secrets expose only ``present`` + ``masked``; non-secrets
    expose their value so the form can prefill. Never leaks clear text."""
    creds = resolved()
    fields: dict[str, dict] = {}
    for name, (_key, is_secret) in FIELDS.items():
        value = creds.get(name, "") or ""
        entry: dict = {"name": name, "label": ARABIC_LABEL[name], "present": bool(value)}
        if is_secret:
            entry["masked"] = mask_secret(value) if value else "—"
            entry["value"] = ""  # never prefill a secret
        else:
            entry["value"] = value
        fields[name] = entry
    auth_mode = "api_key" if creds["api_key"] else ("user_pass" if (creds["user"] and creds["pass"]) else "none")
    return {
        "fields": fields,
        "configured": configured(),
        "auth_mode": auth_mode,
        "sender": creds["sender"],
    }


# ── validate + save ───────────────────────────────────────────────────────

def validate_and_save(form, *, actor_audit) -> None:
    """Persist the submitted form. Secrets are write-only (blank keeps stored).

    Validation: after applying the submission, there must be a usable auth set
    (api_key OR user+pass). ``actor_audit`` is :func:`auth.audit`. Raises
    :class:`TweetSmsSettingsError` (Arabic) on failure; the route commits.
    """
    pending: dict[str, str] = {}
    for name, (_key, is_secret) in FIELDS.items():
        submitted = (form.get(name) or "").strip()
        if is_secret and not submitted:
            continue  # keep existing secret
        pending[name] = submitted

    # Compute the EFFECTIVE values after this save to validate auth completeness.
    eff = resolved()
    for name, val in pending.items():
        eff[name] = val

    has_key = bool(eff["api_key"])
    has_user_pass = bool(eff["user"] and eff["pass"])
    if not (has_key or has_user_pass):
        raise TweetSmsSettingsError(
            "أدخل «مفتاح API» أو «اسم المستخدم وكلمة المرور» معًا.")

    for name, submitted in pending.items():
        setting_key, is_secret = FIELDS[name]
        _set_db_value(setting_key, encrypt_secret(submitted) if (is_secret and submitted) else submitted)

    actor_audit("tweetsms_settings_saved", "tweetsms", "global",
                "حُفظت إعدادات TweetSMS",
                {"fields": sorted(pending.keys()), "auth_mode": "api_key" if has_key else "user_pass"})


def reveal(field: str, *, actor_audit) -> str:
    """Return clear text of a secret field for temporary display (audited)."""
    if field not in SECRET_FIELDS:
        raise TweetSmsSettingsError("لا يمكن كشف هذا الحقل.")
    value = _resolve_one(field)
    if not value:
        raise TweetSmsSettingsError("لا توجد قيمة محفوظة لكشفها.")
    actor_audit("tweetsms_secret_revealed", "tweetsms", field,
                f"كشف مؤقت لـ {ARABIC_LABEL[field]}", {"field": field})
    return value


# ── balance probe ─────────────────────────────────────────────────────────

def check_balance(*, http_get=None) -> tuple[bool, str, str]:
    """Query the provider balance using the stored creds → ``(ok, balance, msg)``."""
    from . import adapter
    if not (resolved()["api_key"] or (resolved()["user"] and resolved()["pass"])):
        raise TweetSmsSettingsError("أدخل بيانات الدخول أولًا (مفتاح API أو مستخدم/كلمة مرور).")
    timeout = float(current_app.config.get("TWEETSMS_TIMEOUT", 15.0))
    return adapter.check_balance(resolved(), timeout=timeout, http_get=http_get)
