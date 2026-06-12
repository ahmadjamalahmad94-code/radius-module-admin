"""Per-customer subdomain + FQDN assignment — design §11.

Each customer gets a deterministic FQDN like ``client5.hoberadius.com``
auto-assigned on first call. A single ``Setting`` row holds the zone
base so the same panel can drive a staging zone alongside production.

The wildcard cert (one ``*.hoberadius.com`` covering every customer) is
an ops/deploy artefact — see §11.3 of
``docs/CUSTOMER_RADIUS_TUNNEL_DESIGN.md``. This module is the
panel-side data layer only: mint, persist, surface. No DNS calls; no
certbot.
"""

from __future__ import annotations

import logging
import re

from app.extensions import db
from app.models import Customer, Setting


logger = logging.getLogger(__name__)


#: Setting row that holds the zone base. Empty string means "use the
#: documented default" — keeps tests deterministic without seeding.
ZONE_BASE_SETTING_KEY: str = "fleet.tls.zone_base"

#: Default zone the panel mints subdomains under when no Setting row
#: exists yet. Operators override via ``set_zone_base`` from the UI.
DEFAULT_ZONE_BASE: str = "hoberadius.com"

#: Subdomains must look like a single DNS label — letters, digits,
#: hyphens, length 1..63 (RFC 1035 §2.3.4).
_LABEL_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")


def get_zone_base() -> str:
    """Return the operator-set zone base (or the documented default)."""
    row = db.session.get(Setting, ZONE_BASE_SETTING_KEY)
    if not row or not row.value:
        return DEFAULT_ZONE_BASE
    return row.value.strip() or DEFAULT_ZONE_BASE


def set_zone_base(value: str) -> str:
    """Persist a new zone base (e.g. ``staging.hoberadius.com``). The
    caller is the infra-settings handler; we just validate + write."""
    candidate = (value or "").strip().lower()
    if not candidate:
        raise ValueError("zone_base cannot be empty")
    # Basic DNS-label-list shape: each label is RFC-1035-safe.
    for label in candidate.split("."):
        if not _LABEL_RE.match(label):
            raise ValueError(f"invalid zone_base label: {label!r}")
    row = db.session.get(Setting, ZONE_BASE_SETTING_KEY)
    if row is None:
        row = Setting(key=ZONE_BASE_SETTING_KEY, value=candidate)
        db.session.add(row)
    else:
        row.value = candidate
    db.session.commit()
    return candidate


def _mint_subdomain(customer: Customer) -> str:
    """Deterministic per-customer subdomain. Matches the existing
    ``client<id>`` realm convention so the FQDN aligns with the realm."""
    return f"client{int(customer.id)}"


def assign_subdomain(customer: Customer, *, commit: bool = True) -> str:
    """Persist ``client<id>`` onto the row when empty. Idempotent.

    Returns the effective subdomain (existing value if already set,
    newly-minted otherwise). Never raises — a customer with a vanity
    operator-set subdomain keeps it.
    """
    existing = (customer.subdomain or "").strip()
    if existing:
        return existing
    minted = _mint_subdomain(customer)
    customer.subdomain = minted
    if commit:
        db.session.commit()
    else:
        db.session.flush()
    logger.info(
        "customer_subdomain: assigned subdomain=%s for customer_id=%s",
        minted, customer.id,
    )
    return minted


def customer_fqdn(customer: Customer) -> str:
    """``<subdomain>.<zone_base>`` — the value SSTP/IPsec clients
    validate. Empty string ONLY when the customer has no id yet
    (pre-flush); we never mint a partial FQDN."""
    if customer is None or not getattr(customer, "id", None):
        return ""
    # Don't auto-assign here — that's a write path. Read-only callers
    # (heartbeat response builder, CHR script renderer) should see the
    # current state, with empty until ``assign_subdomain`` runs.
    sub = (customer.subdomain or "").strip() or _mint_subdomain(customer)
    return f"{sub}.{get_zone_base()}"


__all__ = [
    "ZONE_BASE_SETTING_KEY",
    "DEFAULT_ZONE_BASE",
    "assign_subdomain",
    "customer_fqdn",
    "get_zone_base",
    "set_zone_base",
]
