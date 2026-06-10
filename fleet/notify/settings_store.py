"""fleet.notify.settings_store — per-kind toggles + channel selection.

Phase 9 layers its own (very small) settings store on top of the existing
``settings`` key-value table:

* ``fleet.notify.kind.<kind>.enabled`` — per-event-kind boolean. Default is
  taken from :data:`fleet.notify.rules.KIND_DEFAULTS`.
* ``fleet.notify.channels`` — comma-separated subset of
  ``("sms","whatsapp","telegram")`` — which channels the FLEET alerts use.
  Defaults to all configured-and-enabled channels (probed at read time).

Owner contact details (phone, telegram chat) are NOT duplicated here —
they live in :mod:`app.services.messaging.settings_store` (the messaging
foundation's owner_prefs). The fleet notifier reads them from there.

Why a separate store? The messaging ``OWNER_EVENTS`` catalog is about
customer-domain events (new customer, payment created, …). Fleet events
have a different lifecycle (high-frequency, infra-domain) and need their
own toggles so a noisy DNS reconciliation can't drown out a
``customer_created`` notification.
"""
from __future__ import annotations

from typing import Iterable

from app.extensions import db
from app.models import Setting
from app.services.messaging.channels import CHANNELS as _MESSAGING_CHANNELS

from .rules import KIND_DEFAULTS, KIND_LABELS

# The fleet-allowed channel set. Mirrors the messaging package but kept
# distinct so a future channel that's customer-only doesn't auto-leak
# into infra alerts.
FLEET_CHANNELS: tuple[str, ...] = tuple(c for c in _MESSAGING_CHANNELS if c in ("sms", "whatsapp", "telegram"))


def _kv(key: str) -> str:
    row = db.session.get(Setting, key)
    return (row.value or "") if row else ""


def _set_kv(key: str, value: str) -> None:
    row = db.session.get(Setting, key)
    if not row:
        row = Setting(key=key)
    row.value = value
    db.session.add(row)


def _kind_key(kind: str) -> str:
    return f"fleet.notify.kind.{kind}.enabled"


# ── per-kind toggle ──────────────────────────────────────────────────────

def is_kind_enabled(kind: str) -> bool:
    """True iff the owner wants alerts for ``kind``.

    Falls back to :data:`KIND_DEFAULTS` (default-on for crit/warn) when no
    preference is saved. An unknown kind defaults to OFF — opt-in surface,
    not opt-out, for events the notifier hasn't catalogued.
    """
    raw = _kv(_kind_key(kind)).strip().lower()
    if not raw:
        return KIND_DEFAULTS.get(kind, False)
    return raw in ("1", "true", "yes", "on")


def set_kind_enabled(kind: str, enabled: bool) -> None:
    """Persist the per-kind toggle. Caller commits."""
    _set_kv(_kind_key(kind), "1" if enabled else "0")


def get_kind_states() -> list[dict]:
    """List view used by the settings UI."""
    out: list[dict] = []
    for kind, label in KIND_LABELS.items():
        out.append({
            "kind": kind,
            "label": label,
            "enabled": is_kind_enabled(kind),
            "default_enabled": KIND_DEFAULTS.get(kind, False),
            "default_severity": _default_sev(kind),
        })
    return out


def _default_sev(kind: str) -> str:
    # Cheap lookup that avoids constructing a synthetic Event just for the
    # severity column.
    if kind in ("health_down", "cap_breach"):
        return "crit"
    if kind in (
        "failover_start", "cap_warn", "dns_suppressed", "move_fail",
        "onboard_fail", "flap_suppressed", "cost_cap_nearing",
    ):
        return "warn"
    return "info"


# ── channel selection ────────────────────────────────────────────────────

_CHANNELS_KEY = "fleet.notify.channels"


def get_channels() -> list[str]:
    """Return the channels the fleet notifier uses.

    Empty/unset ⇒ derive from messaging.channel_enabled() (use every
    configured channel). Saved explicitly ⇒ honour that subset, intersected
    with the messaging-side ``FLEET_CHANNELS`` allowlist so a stale
    preference can't ship to a channel that was removed.
    """
    raw = _kv(_CHANNELS_KEY).strip()
    if not raw:
        # Probe messaging settings for "configured + enabled" channels.
        from app.services.messaging.settings_store import channel_enabled
        return [c for c in FLEET_CHANNELS if channel_enabled(c)]
    saved = [c.strip() for c in raw.split(",") if c.strip()]
    return [c for c in saved if c in FLEET_CHANNELS]


def set_channels(values: Iterable[str]) -> None:
    cleaned = [c for c in values if c in FLEET_CHANNELS]
    _set_kv(_CHANNELS_KEY, ",".join(cleaned))


__all__ = [
    "FLEET_CHANNELS",
    "get_channels",
    "get_kind_states",
    "is_kind_enabled",
    "set_channels",
    "set_kind_enabled",
]
