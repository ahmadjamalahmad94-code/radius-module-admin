"""fleet.control.live_apply_settings — UI-only switch for fleet enforcement.

The "live-apply" flag answers ONE question for the panel ↔ proxy contract:

    Should the radius-proxy actually ENFORCE the brain's decisions
    (CoA disconnects, single-session kill, rebalance moves) right now?

It is **default-OFF** for safety, and **only the admin UI** can flip it —
there is no env var or terminal shortcut by project rule. The flag lives
in the existing ``settings`` table (key
``fleet.control.live_apply_enabled``, value ``"1"`` / ``"0"``) so it
inherits the encryption-at-rest of the panel's backup story without
needing a separate Fernet wrap (it's a boolean, not a secret).

The proxy reads the flag through the existing
``GET /api/proxy/routing-table`` response — see
``docs/contracts/fleet_api.md §1.1`` — by adding ``live_apply_enabled``
to the top-level JSON. The proxy MUST treat the flag as false when:

* the key is absent (fresh install),
* the routing-table response is older than ``TTL_SECONDS``,
* anything in the response is malformed.

That "default-off everywhere" stance is what makes a typo in this
module fail closed.

Audit hook
----------
Every flip goes through :func:`set_enabled` which writes an
``AuditLog`` row (``fleet_live_apply_toggled``) before the
``Setting`` write commits. The UI is the only legitimate caller; the
audit row records who flipped it, when, and what the new value is —
so a later "why did enforcement turn back on?" investigation has a
single, queryable answer.
"""
from __future__ import annotations

from typing import TypedDict

from app.extensions import db
from app.models import Setting


# ════════════════════════════════════════════════════════════════════════
# Public constants
# ════════════════════════════════════════════════════════════════════════

#: Settings key the flag lives under. Stable so the routing-table API,
#: the dashboard, and any future migration all agree on one column.
SETTING_KEY = "fleet.control.live_apply_enabled"

#: Stringly-typed values in the Setting row. We use ``"1"`` / ``"0"`` so
#: a raw DB inspection ("psql -c 'select * from settings'") reads
#: unambiguously without needing to decode JSON.
_TRUE = "1"
_FALSE = "0"


class LiveApplyView(TypedDict):
    """Shape the dashboard reads. ``enabled`` is the canonical truth;
    ``raw_value`` is exposed so the UI can show "محفوظ بالضبط: '1'"
    diagnostics without re-querying."""

    enabled: bool
    raw_value: str


# ════════════════════════════════════════════════════════════════════════
# Public API
# ════════════════════════════════════════════════════════════════════════


def is_enabled() -> bool:
    """True iff the operator has explicitly turned live-apply ON via the UI.

    Default-OFF: any missing row, any malformed value, any DB error in
    the read path collapses to ``False``. That keeps the proxy in the
    safe (advisory-only) state when the panel is degraded.
    """
    try:
        row = db.session.get(Setting, SETTING_KEY)
    except Exception:  # noqa: BLE001 — read path must never raise out
        return False
    if row is None or row.value is None:
        return False
    return str(row.value).strip() == _TRUE


def load_view() -> LiveApplyView:
    """UI-safe snapshot of the flag for the dashboard template."""
    try:
        row = db.session.get(Setting, SETTING_KEY)
    except Exception:  # noqa: BLE001
        row = None
    raw = (row.value or "") if row is not None else ""
    return LiveApplyView(
        enabled=(str(raw).strip() == _TRUE),
        raw_value=str(raw or ""),
    )


def set_enabled(value: bool, *, actor_audit=None, actor_label: str = "") -> bool:
    """Persist a new value. Returns the new ``enabled`` boolean.

    Parameters
    ----------
    value          the desired boolean.
    actor_audit    optional callable ``(action, entity_type, entity_id, msg, payload)``
                   that writes an audit row. We pass the existing
                   ``app.auth.routes.audit`` here from the route handler;
                   tests can pass ``None`` to skip.
    actor_label    free-text label of who/what flipped the flag (admin
                   username, "system", etc.). Recorded into the audit
                   payload only.
    """
    desired = _TRUE if bool(value) else _FALSE
    row = db.session.get(Setting, SETTING_KEY)
    previous = (row.value or "") if row is not None else ""
    if row is None:
        row = Setting(key=SETTING_KEY)
    row.value = desired
    db.session.add(row)

    if actor_audit is not None:
        try:
            actor_audit(
                "fleet_live_apply_toggled",
                "fleet_settings",
                SETTING_KEY,
                f"تطبيق الفلوت الحي → {'ON' if desired == _TRUE else 'OFF'}",
                {
                    "from": previous,
                    "to": desired,
                    "actor": actor_label,
                },
            )
        except Exception:  # noqa: BLE001 — audit must never block the flip
            pass

    db.session.commit()
    return desired == _TRUE


__all__ = [
    "SETTING_KEY",
    "LiveApplyView",
    "is_enabled",
    "load_view",
    "set_enabled",
]
