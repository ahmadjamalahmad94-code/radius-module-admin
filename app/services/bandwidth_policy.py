"""Bandwidth policy per connection type — panel-controlled.

Implements §9 of ``docs/CUSTOMER_RADIUS_TUNNEL_DESIGN.md``. The owner sets
ONE default per connection type on the infra page; everything that emits
config downstream (wg-radius rate cap, VPN session `Mikrotik-Rate-Limit`,
script renderer) reads from this single source. Existing per-row
overrides (`ChrSpeedProfile`, per-tunnel `download_mbps`/`upload_mbps`)
keep winning when set — the policy only fills in the empty values.

Storage: a single ``Setting`` row keyed ``fleet.bandwidth_policy`` with a
JSON dict of ``{role: {download_mbps, upload_mbps}}``. Read returns the
documented defaults when a key is missing, so a panel that has never had
the policy edited still emits sensible numbers.

Per-direction emission is delegated to
``app.services.speed_profiles.rate_limit_string`` — the SAME formatter
``feat/bandwidth-per-direction`` rolls out — so the 850 ⇒ `850M/850M`
rule and the symmetric default are honoured without duplicate code.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

from app.extensions import db
from app.models import Setting


logger = logging.getLogger(__name__)


#: Key under ``settings`` that holds the JSON policy. A single row keeps
#: the surface flat — there is exactly one place to edit + one place to
#: read, no per-role row to drift out of sync.
SETTING_KEY: str = "fleet.bandwidth_policy"


@dataclass(frozen=True)
class TypePolicy:
    """Per-connection-type Mbps cap, per direction.

    Symmetric values (``download_mbps == upload_mbps``) are the default;
    the «متقدّم» UI toggle splits them when the operator wants asymmetric.
    """

    download_mbps: int
    upload_mbps: int

    def rate_limit(self) -> str:
        """Delegate to the shared per-direction formatter so this module
        does not own the wire shape — the bandwidth-per-direction
        sibling does. Returns ``"<upload>M/<download>M"`` or ``""``."""
        from app.services.speed_profiles import rate_limit_string
        return rate_limit_string(self.download_mbps, self.upload_mbps)

    def as_dict(self) -> dict[str, int]:
        return {"download_mbps": self.download_mbps, "upload_mbps": self.upload_mbps}


#: Fleet-wide defaults (§9.1 of the design). RADIUS-transport is
#: intentionally low — the wg-data / wg-radius planes carry only
#: RADIUS auth/acct/CoA, never user payload.
_DEFAULTS: dict[str, TypePolicy] = {
    "radius_transport": TypePolicy(download_mbps=5,   upload_mbps=5),
    "vpn_sstp":         TypePolicy(download_mbps=100, upload_mbps=100),
    "vpn_pptp":         TypePolicy(download_mbps=50,  upload_mbps=50),
    "vpn_ipsec":        TypePolicy(download_mbps=50,  upload_mbps=50),
    "vpn_wireguard":    TypePolicy(download_mbps=100, upload_mbps=100),
}

#: Public role vocabulary. Anything outside this set is rejected by the
#: setter so a typo in the UI never persists.
SUPPORTED_TYPES: tuple[str, ...] = tuple(_DEFAULTS.keys())


def _read_raw() -> dict[str, Any]:
    row = db.session.get(Setting, SETTING_KEY)
    if not row or not row.value:
        return {}
    try:
        data = json.loads(row.value)
    except (TypeError, ValueError):
        logger.warning(
            "bandwidth_policy: stored JSON is malformed; returning defaults",
        )
        return {}
    return data if isinstance(data, dict) else {}


def _normalise_one(value: Any) -> dict[str, int] | None:
    """Return ``{"download_mbps", "upload_mbps"}`` from a stored dict.

    Tolerant: int or numeric-string. Returns ``None`` on a malformed
    pair so the reader falls back to the documented default.
    """
    if not isinstance(value, dict):
        return None
    try:
        down = int(value.get("download_mbps") or 0)
        up = int(value.get("upload_mbps") or 0)
    except (TypeError, ValueError):
        return None
    if down <= 0 or up <= 0:
        return None
    return {"download_mbps": down, "upload_mbps": up}


def policy_for(connection_type: str) -> TypePolicy:
    """Return the effective policy for one connection type.

    Resolution order:
      1. Stored Setting value when present + well-formed.
      2. The default from ``_DEFAULTS`` (§9.1).

    Unknown ``connection_type`` raises ``ValueError`` — typo-safe by
    construction.
    """
    if connection_type not in _DEFAULTS:
        raise ValueError(
            f"unknown connection_type={connection_type!r}; "
            f"expected one of {SUPPORTED_TYPES}",
        )
    stored = _read_raw().get(connection_type)
    norm = _normalise_one(stored)
    if norm is None:
        return _DEFAULTS[connection_type]
    return TypePolicy(download_mbps=norm["download_mbps"],
                      upload_mbps=norm["upload_mbps"])


def all_policies() -> dict[str, TypePolicy]:
    """All five effective policies — used by the dashboard + the
    capacity allocator (§10.2)."""
    return {t: policy_for(t) for t in SUPPORTED_TYPES}


def set_policy(connection_type: str, *, download_mbps: int, upload_mbps: int) -> TypePolicy:
    """Persist a single type's policy. Caller commits.

    Raises ``ValueError`` on an unknown type OR a non-positive value
    (RouterOS rejects zero — better to fail in the panel than emit a
    bad config).
    """
    if connection_type not in _DEFAULTS:
        raise ValueError(
            f"unknown connection_type={connection_type!r}; "
            f"expected one of {SUPPORTED_TYPES}",
        )
    if not isinstance(download_mbps, int) or download_mbps <= 0:
        raise ValueError("download_mbps must be a positive integer")
    if not isinstance(upload_mbps, int) or upload_mbps <= 0:
        raise ValueError("upload_mbps must be a positive integer")

    data = _read_raw()
    data[connection_type] = {"download_mbps": download_mbps, "upload_mbps": upload_mbps}
    row = db.session.get(Setting, SETTING_KEY)
    payload = json.dumps(data, ensure_ascii=False, sort_keys=True)
    if row is None:
        row = Setting(key=SETTING_KEY, value=payload)
        db.session.add(row)
    else:
        row.value = payload
    db.session.commit()
    logger.info(
        "bandwidth_policy: set %s = %sM/%sM",
        connection_type, upload_mbps, download_mbps,
    )
    return TypePolicy(download_mbps=download_mbps, upload_mbps=upload_mbps)


def set_symmetric(connection_type: str, *, mbps: int) -> TypePolicy:
    """Symmetric shorthand — owner enters one number, both directions get it."""
    return set_policy(connection_type, download_mbps=mbps, upload_mbps=mbps)


def serialize_for_ui() -> dict[str, dict[str, Any]]:
    """Shape the infra page consumes: every type with current values +
    a flag for the «متقدّم» toggle that says whether the stored pair is
    symmetric (renders as one field) or asymmetric (renders as two)."""
    out: dict[str, dict[str, Any]] = {}
    for t, pol in all_policies().items():
        out[t] = {
            "download_mbps": pol.download_mbps,
            "upload_mbps": pol.upload_mbps,
            "rate_limit": pol.rate_limit(),
            "symmetric": pol.download_mbps == pol.upload_mbps,
        }
    return out


__all__ = [
    "SETTING_KEY",
    "SUPPORTED_TYPES",
    "TypePolicy",
    "all_policies",
    "policy_for",
    "serialize_for_ui",
    "set_policy",
    "set_symmetric",
]
