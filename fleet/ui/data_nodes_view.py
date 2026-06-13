"""fleet.ui.data_nodes_view — read-model for /admin/fleet/data-nodes.

The page lets the operator:

  1. DESIGNATE which fleet CHRs carry DATA (radius_transport role) and
     toggle the other VPN roles (sstp/pptp/ipsec/wireguard).
  2. CREATE a data connection from a chosen data CHR — reuse the
     existing SSTP «رابط RADIUS» generator (POST /admin/access-
     connections/ppp). The form here just pre-fills the chosen
     fleet_chr_node_id and tunnel_type=sstp so the operator stays
     in one place.
  3. LIST connections per data CHR with the visual chain
     MikroTik → SSTP → CHR → proxy → RADIUS and per-connection
     live status. No mocks — when a status field has no live source
     we surface «غير متوفّرة بعد» rather than fake green.

The data this module reads (all real):

  * ``FleetChrNode.roles_json``   — via ``node_roles.enabled_roles``
  * ``CustomerVpnTunnel``         — every SSTP tunnel + its
                                     fleet_chr_node_id link
  * ``ProxyRealmRoute`` +
    ``CustomerRadiusInstance``   — realm + radius target + the
                                     proxy-heartbeat-driven last_seen.

Live-status sources:
  * ``CustomerVpnTunnel.status``        (pending|active|suspended|revoked|failed)
  * ``CustomerVpnTunnel.delivery_status`` (pending|delivered)
  * ``CustomerVpnTunnel.chr_provisioned`` (bool)
  * ``CustomerRadiusInstance.status`` + ``.last_seen_at``
      → updated by the proxy heartbeat in app/api/proxy_api.heartbeat
        whenever the proxy reports active_realms.

Read-only — never raises, never writes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.extensions import db
from app.services import node_roles as nr
from fleet.registry.models_chr import FleetChrNode


@dataclass(frozen=True)
class ConnectionRow:
    """One SSTP «رابط RADIUS» connection routed through a data CHR."""

    tunnel_id: int
    username: str
    customer_id: int | None
    customer_name: str
    realm: str
    radius_target: str          # "ip:port" of the customer's RADIUS
    realm_route_status: str     # active | draft | suspended | (unknown)
    realm_last_seen_at: str     # ISO timestamp from proxy heartbeat, or ""
    tunnel_status: str          # pending | active | suspended | revoked | failed
    delivery_status: str        # pending | delivered
    chr_provisioned: bool
    download_mbps: int | None
    upload_mbps: int | None
    last_error: str
    created_at: str
    # The visual chain, pre-rendered as 5 string segments the
    # template just joins with the arrow icon.
    chain: tuple[str, str, str, str, str] = ("", "", "", "", "")

    def to_dict(self) -> dict[str, Any]:
        return {
            "tunnel_id": self.tunnel_id,
            "username": self.username,
            "customer_id": self.customer_id,
            "customer_name": self.customer_name,
            "realm": self.realm,
            "radius_target": self.radius_target,
            "realm_route_status": self.realm_route_status,
            "realm_last_seen_at": self.realm_last_seen_at,
            "tunnel_status": self.tunnel_status,
            "delivery_status": self.delivery_status,
            "chr_provisioned": self.chr_provisioned,
            "download_mbps": self.download_mbps,
            "upload_mbps": self.upload_mbps,
            "last_error": self.last_error,
            "created_at": self.created_at,
            "chain": list(self.chain),
        }


@dataclass(frozen=True)
class DataNodeView:
    """One fleet CHR with its role + connections + the proxy-side route count."""

    node_id: int
    name: str
    public_ip: str
    wg_mgmt_ip: str
    status: str
    enabled: bool
    drain: bool
    needs_reimport: bool
    roles: tuple[str, ...]      # ordered subset of NODE_ROLES
    is_data: bool                # 'radius_transport' in roles
    is_data_only: bool           # roles == {'radius_transport'}
    connection_count: int
    connections: tuple[ConnectionRow, ...] = ()
    # ProxyRealmRoutes that NAME this node in their
    # allowed_fleet_chr_node_ids — the "could carry these realms" set.
    allowed_realms: tuple[str, ...] = ()


# ════════════════════════════════════════════════════════════════════════
# Helpers
# ════════════════════════════════════════════════════════════════════════


def _chain_for(node: FleetChrNode, realm: str, radius_target: str) -> tuple[str, str, str, str, str]:
    """Pre-render the visual chain for the row.

    Each segment is a short label the template stitches together with
    the existing arrow icon — kept as plain Arabic strings so a future
    redesign of the chain widget doesn't have to touch this module.
    """
    return (
        "ميكروتيك المشترك",
        f"SSTP : {node.public_ip}:443",
        f"عقدة {node.name}",
        "وكيل RADIUS (wg-data → 10.98.0.1)",
        f"راديوس العميل ({radius_target or '?'})"
        + (f" — realm={realm}" if realm else ""),
    )


def _format_iso(value) -> str:
    if value is None:
        return ""
    try:
        return value.isoformat()
    except Exception:  # noqa: BLE001
        return str(value)


def _build_connection_row(tunnel, node: FleetChrNode) -> ConnectionRow:
    """One CustomerVpnTunnel → ConnectionRow, with the realm + chain
    + live status fields hydrated from the related rows."""
    from app.models import (
        CustomerRadiusInstance, ProxyRealmRoute,
    )

    customer = tunnel.customer
    realm = ""
    radius_target = ""
    route_status = ""
    realm_last_seen_at = ""
    if customer is not None:
        inst = (
            CustomerRadiusInstance.query
            .filter_by(customer_id=customer.id)
            .first()
        )
        if inst is not None:
            realm = inst.realm or ""
            radius_target = f"{inst.radius_auth_ip}:{inst.radius_auth_port}"
            realm_last_seen_at = _format_iso(inst.last_seen_at)
            route = (
                ProxyRealmRoute.query
                .filter_by(customer_id=customer.id, radius_instance_id=inst.id)
                .first()
            )
            if route is not None:
                route_status = route.status or ""

    return ConnectionRow(
        tunnel_id=tunnel.id,
        username=tunnel.username,
        customer_id=customer.id if customer else None,
        customer_name=(customer.company_name if customer else ""),
        realm=realm,
        radius_target=radius_target,
        realm_route_status=route_status,
        realm_last_seen_at=realm_last_seen_at,
        tunnel_status=tunnel.status or "",
        delivery_status=tunnel.delivery_status or "",
        chr_provisioned=bool(tunnel.chr_provisioned),
        download_mbps=tunnel.download_mbps,
        upload_mbps=tunnel.upload_mbps,
        last_error=(tunnel.last_error or ""),
        created_at=_format_iso(tunnel.created_at),
        chain=_chain_for(node, realm, radius_target),
    )


def _realms_allowed_through(node: FleetChrNode) -> tuple[str, ...]:
    """ProxyRealmRoute realms that name this node in their allow-list."""
    from app.models import ProxyRealmRoute
    out: list[str] = []
    for r in ProxyRealmRoute.query.all():
        ids = [int(x) for x in (r.allowed_fleet_chr_node_ids or [])
               if str(x).lstrip("-").isdigit()]
        if not ids or node.id in ids:
            if r.realm:
                out.append(r.realm)
    # Dedup + sort for a stable display.
    return tuple(sorted(set(out)))


def _build_data_node_view(node: FleetChrNode) -> DataNodeView:
    from app.models import CustomerVpnTunnel
    roles = sorted(nr.enabled_roles(node))
    is_data = "radius_transport" in roles
    is_data_only = roles == ["radius_transport"]

    tunnels = (
        CustomerVpnTunnel.query
        .filter(CustomerVpnTunnel.fleet_chr_node_id == node.id)
        .filter(CustomerVpnTunnel.tunnel_type == "sstp")
        .order_by(CustomerVpnTunnel.id.desc())
        .all()
    )
    rows = tuple(_build_connection_row(t, node) for t in tunnels)

    return DataNodeView(
        node_id=node.id,
        name=node.name,
        public_ip=node.public_ip,
        wg_mgmt_ip=node.wg_mgmt_ip,
        status=node.status,
        enabled=bool(node.enabled),
        drain=bool(node.drain),
        needs_reimport=bool(node.needs_reimport),
        roles=tuple(roles),
        is_data=is_data,
        is_data_only=is_data_only,
        connection_count=len(rows),
        connections=rows,
        allowed_realms=_realms_allowed_through(node),
    )


# ════════════════════════════════════════════════════════════════════════
# Public API
# ════════════════════════════════════════════════════════════════════════


def build_all_views() -> list[DataNodeView]:
    """All fleet CHRs sorted: data nodes first, then by name."""
    nodes = (
        FleetChrNode.query
        .order_by(FleetChrNode.name.asc())
        .all()
    )
    views = [_build_data_node_view(n) for n in nodes]
    # Data nodes float to the top (most relevant for this page).
    views.sort(key=lambda v: (not v.is_data, v.name.lower()))
    return views


def build_view_for(node_id: int) -> DataNodeView | None:
    n = db.session.get(FleetChrNode, int(node_id))
    if n is None:
        return None
    return _build_data_node_view(n)


__all__ = [
    "ConnectionRow",
    "DataNodeView",
    "build_all_views",
    "build_view_for",
]
