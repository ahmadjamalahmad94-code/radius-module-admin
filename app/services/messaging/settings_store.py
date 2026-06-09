"""DB-backed credential + preference storage for the messaging package.

Three concerns live here:

1. **Channel credentials** — base_url/api_key/sender_id (SMS),
   mode/phone_number_id/access_token (WhatsApp), bot_token/default_chat_id
   (Telegram). Stored under namespaced keys in the existing key-value
   ``settings`` table (``messaging.sms.base_url``, …). Secrets are encrypted at
   rest with the WhatsApp Fernet key — never plaintext in the DB.

2. **Channel enable/disable** — one boolean per channel.

3. **Owner preferences** — which channels notify_owner uses, which event types
   are routed, and the owner's destination addresses (phone for SMS+WhatsApp,
   Telegram chat id). Persisted as JSON under ``messaging.owner_prefs``.

The actual sending lives in ``router.py`` / ``layers.py``; this module just
owns the persistence boundary.
"""
from __future__ import annotations

import json
from typing import Any

from ...extensions import db
from ...models import Setting
from ..whatsapp.crypto import (
    WhatsAppCryptoError,
    decrypt_secret,
    encrypt_secret,
    mask_secret,
)
from .channels import CHANNELS, CHANNEL_LABELS, OWNER_EVENTS

#: Per-channel: ``field_name → (storage_key, is_secret)``. Storage keys are
#: namespaced so a future ``messaging`` settings page is the only place that
#: touches them.
_FIELDS: dict[str, dict[str, tuple[str, bool]]] = {
    "sms": {
        "base_url": ("messaging.sms.base_url", False),
        "api_key": ("messaging.sms.api_key", True),
        "sender_id": ("messaging.sms.sender_id", False),
    },
    "whatsapp": {
        "mode": ("messaging.whatsapp.mode", False),
        "phone_number_id": ("messaging.whatsapp.phone_number_id", False),
        "access_token": ("messaging.whatsapp.access_token", True),
    },
    "telegram": {
        "bot_token": ("messaging.telegram.bot_token", True),
        "default_chat_id": ("messaging.telegram.default_chat_id", False),
    },
}

_ENABLED_KEY = "messaging.{channel}.enabled"
_OWNER_PREFS_KEY = "messaging.owner_prefs"


class ChannelSettingsError(ValueError):
    """Validation error surfaced to the admin UI (Arabic message)."""


# ── low-level kv access ───────────────────────────────────────────────────

def _db_value(key: str) -> str:
    row = db.session.get(Setting, key)
    return (row.value or "") if row else ""


def _set_db_value(key: str, value: str) -> None:
    row = db.session.get(Setting, key)
    if not row:
        row = Setting(key=key)
    row.value = value
    db.session.add(row)


# ── credentials ──────────────────────────────────────────────────────────

def _decrypt(value: str) -> str:
    if not value:
        return ""
    try:
        return decrypt_secret(value)
    except WhatsAppCryptoError:
        return ""


def resolved_credentials(channel: str) -> dict[str, str]:
    """Return plaintext creds for ``channel`` — INTERNAL USE ONLY (router/test).

    Never leaks to a Jinja template. The owner sees only the masked UI state
    via :func:`get_channel_state`.
    """
    if channel not in _FIELDS:
        return {}
    out: dict[str, str] = {}
    for field, (storage_key, is_secret) in _FIELDS[channel].items():
        raw = _db_value(storage_key)
        out[field] = _decrypt(raw) if is_secret else raw
    return out


def channel_enabled(channel: str) -> bool:
    if channel not in _FIELDS:
        return False
    raw = _db_value(_ENABLED_KEY.format(channel=channel)).strip().lower()
    return raw in ("1", "true", "yes", "on")


def _set_channel_enabled(channel: str, enabled: bool) -> None:
    _set_db_value(_ENABLED_KEY.format(channel=channel), "1" if enabled else "0")


def get_channel_state(channel: str) -> dict[str, Any]:
    """UI-safe state for one channel: masked secrets, plain non-secrets, and
    a ``present`` boolean per field. Never leaks plaintext secrets."""
    if channel not in _FIELDS:
        raise ChannelSettingsError(f"قناة غير معروفة: {channel}")
    creds = resolved_credentials(channel)
    fields: dict[str, dict[str, Any]] = {}
    for field, (_storage_key, is_secret) in _FIELDS[channel].items():
        value = creds.get(field, "") or ""
        entry: dict[str, Any] = {"name": field, "present": bool(value)}
        if is_secret:
            entry["value"] = ""  # never prefill secrets
            entry["masked"] = mask_secret(value) if value else "—"
        else:
            entry["value"] = value
        fields[field] = entry
    return {
        "channel": channel,
        "label": CHANNEL_LABELS.get(channel, channel),
        "enabled": channel_enabled(channel),
        "configured": _adapter_configured(channel, creds),
        "fields": fields,
    }


def _adapter_configured(channel: str, creds: dict[str, str]) -> bool:
    from .adapters import ADAPTERS
    adapter = ADAPTERS.get(channel)
    if not adapter:
        return False
    try:
        return adapter.configured(creds)
    except Exception:
        return False


def save_channel(channel: str, form, *, actor_audit) -> None:
    """Persist a channel's enable flag + credential fields.

    Secrets are write-only: a blank submission keeps the stored value. Non-secret
    blanks clear the stored override. ``actor_audit`` is :func:`auth.audit`.
    """
    if channel not in _FIELDS:
        raise ChannelSettingsError(f"قناة غير معروفة: {channel}")
    enabled = (form.get("enabled") or "").strip().lower() in ("1", "true", "on", "yes")
    _set_channel_enabled(channel, enabled)

    saved_fields: list[str] = []
    for field, (storage_key, is_secret) in _FIELDS[channel].items():
        submitted = (form.get(field) or "").strip()
        if is_secret:
            if submitted:  # only overwrite on explicit input
                _set_db_value(storage_key, encrypt_secret(submitted))
                saved_fields.append(field)
        else:
            _set_db_value(storage_key, submitted)
            saved_fields.append(field)

    actor_audit(
        "messaging_channel_saved", "messaging_channel", channel,
        f"Saved {channel} channel settings",
        {"channel": channel, "enabled": enabled, "fields": saved_fields},
    )


# ── owner preferences ────────────────────────────────────────────────────

def _default_owner_prefs() -> dict[str, Any]:
    return {
        # which channels notify_owner uses (subset of CHANNELS)
        "channels": list(CHANNELS),
        # which OWNER_EVENTS are routed
        "events": list(OWNER_EVENTS),
        # owner-side destinations — phone is used for SMS + WhatsApp; chat_id
        # for Telegram. Stored as plain text (these are the owner's own
        # addresses, not customer-bound secrets).
        "owner_phone": "",
        "owner_telegram_chat_id": "",
    }


def get_owner_prefs() -> dict[str, Any]:
    raw = _db_value(_OWNER_PREFS_KEY)
    if not raw:
        return _default_owner_prefs()
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return _default_owner_prefs()
    if not isinstance(data, dict):
        return _default_owner_prefs()
    base = _default_owner_prefs()
    base["channels"] = [c for c in data.get("channels", []) if c in CHANNELS] or base["channels"]
    base["events"] = [e for e in data.get("events", []) if e in OWNER_EVENTS] or base["events"]
    base["owner_phone"] = (data.get("owner_phone") or "").strip()
    base["owner_telegram_chat_id"] = (data.get("owner_telegram_chat_id") or "").strip()
    return base


def save_owner_prefs(form, *, actor_audit) -> None:
    channels = [c for c in form.getlist("owner_channels") if c in CHANNELS]
    events = [e for e in form.getlist("owner_events") if e in OWNER_EVENTS]
    owner_phone = (form.get("owner_phone") or "").strip()
    chat_id = (form.get("owner_telegram_chat_id") or "").strip()
    data = {
        "channels": channels,
        "events": events,
        "owner_phone": owner_phone,
        "owner_telegram_chat_id": chat_id,
    }
    _set_db_value(_OWNER_PREFS_KEY, json.dumps(data, ensure_ascii=False))
    actor_audit(
        "messaging_owner_prefs_saved", "messaging_owner_prefs", "global",
        "Saved messaging owner preferences",
        {"channels": channels, "events": events},
    )


# ── test send ────────────────────────────────────────────────────────────

def test_send(channel: str, recipient: str, *, actor_audit) -> dict[str, Any]:
    """Trigger a one-off test send via the channel router. Audited."""
    from .router import send

    text = "رسالة اختبار من لوحة الترخيص — قنوات التواصل."
    result = send(channel, recipient, text)
    actor_audit(
        "messaging_test_send", "messaging_channel", channel,
        f"Test send via {channel}",
        {"ok": result.ok, "code": result.code, "recipient_present": bool(recipient)},
    )
    return result.to_dict()
