"""Node-role tag for ``fleet_chr_nodes``.

Implements §10 of ``docs/CUSTOMER_RADIUS_TUNNEL_DESIGN.md``: a node can
simultaneously host several connection types. The tag is a SET stored
as JSON on ``fleet_chr_nodes.roles_json``; empty list ⇒ "all roles
enabled" so existing fleets keep working unchanged on the first deploy
after this column lands.

The five known roles are:

* ``radius_transport`` — wg-data / wg-radius (RADIUS auth/acct/CoA only,
  capped low per §9.1 ``radius_transport`` policy);
* ``vpn_sstp`` / ``vpn_pptp`` / ``vpn_ipsec`` / ``vpn_wireguard`` —
  user-traffic VPN terminators, with their own per-type Mbps cap from
  the §9 fleet bandwidth policy.

Other modules (provisioning, the brain ranker, the §10.2 capacity
allocator) read this surface, never the raw column — so future role
additions live in exactly one place.
"""

from __future__ import annotations

import json
import logging
from typing import Iterable

from app.extensions import db


logger = logging.getLogger(__name__)


#: The full role vocabulary. Ordered for stable display.
NODE_ROLES: tuple[str, ...] = (
    "radius_transport",
    "vpn_sstp",
    "vpn_pptp",
    "vpn_ipsec",
    "vpn_wireguard",
)

#: Default = every role enabled. Stored as empty JSON list on the row;
#: this constant is the in-memory expansion ``enabled_roles`` returns.
_DEFAULT_SET: frozenset[str] = frozenset(NODE_ROLES)


def _read_roles(node) -> list[str]:
    raw = getattr(node, "roles_json", None) or "[]"
    try:
        loaded = json.loads(raw) if isinstance(raw, str) else list(raw or [])
    except (TypeError, ValueError):
        loaded = []
    return [r for r in loaded if r in NODE_ROLES]


def enabled_roles(node) -> set[str]:
    """Return the SET of roles the node may host.

    Empty/missing ``roles_json`` means "all roles enabled" — back-compat
    rule for nodes registered before §10 landed.
    """
    raw = _read_roles(node)
    if not raw:
        return set(_DEFAULT_SET)
    return set(raw)


def node_has_role(node, role: str) -> bool:
    """True iff ``role`` is currently enabled on ``node``. Unknown roles
    return False so callers can compose with ``and`` safely."""
    if role not in NODE_ROLES:
        return False
    return role in enabled_roles(node)


def set_roles(node, roles: Iterable[str], *, commit: bool = False) -> set[str]:
    """Replace the node's role set. Invalid roles are filtered out with
    a single log line — never raises. Returns the new effective set.

    ``commit=False`` (default) so the caller can batch the change with
    other edits and commit once. Pass ``commit=True`` from a UI handler
    that wants to fire-and-forget the change.
    """
    cleaned: list[str] = []
    seen: set[str] = set()
    for r in roles or ():
        if r in NODE_ROLES and r not in seen:
            cleaned.append(r); seen.add(r)
        elif r:
            logger.info(
                "node_roles: ignoring unknown role=%r for node_id=%s",
                r, getattr(node, "id", None),
            )
    node.roles_json = json.dumps(cleaned, ensure_ascii=False)
    if commit:
        db.session.commit()
    return enabled_roles(node)


def toggle_role(node, role: str, *, commit: bool = False) -> set[str]:
    """Flip one role on/off. No-op on unknown role (logs once)."""
    if role not in NODE_ROLES:
        logger.info("node_roles: refusing to toggle unknown role=%r", role)
        return enabled_roles(node)
    current = _read_roles(node)
    if not current:
        # "all roles" — toggling off ⇒ explicit list minus the chosen role.
        current = list(NODE_ROLES)
    if role in current:
        current = [r for r in current if r != role]
    else:
        current.append(role)
    node.roles_json = json.dumps(current, ensure_ascii=False)
    if commit:
        db.session.commit()
    return enabled_roles(node)


__all__ = [
    "NODE_ROLES",
    "enabled_roles",
    "node_has_role",
    "set_roles",
    "toggle_role",
]
