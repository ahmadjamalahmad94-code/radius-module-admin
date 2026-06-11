"""fleet.sync.peers — desired WireGuard peer sets, derived from the registry.

The panel ALREADY knows every CHR's pubkeys (onboarding mints + stores them).
Manual hand-peering is therefore pure drift waiting to happen. These builders
turn ``fleet_chr_nodes`` into the two desired peer sets the zero-touch sync
reconciles:

* :func:`desired_panel_peers` — the wg-mgmt peers the PANEL HOST must trust
  (one ``/32`` per CHR in the 10.99.0.0/24 control pool). Applied locally via
  the scoped root helper (:mod:`fleet.sync.wg_apply`).
* :func:`desired_proxy_peers` — the wg-data peers the PROXY HOST must trust
  (one ``/32`` per CHR in the 10.98.0.0/24 data pool). Published over
  ``GET /api/proxy/wg-peers`` for the coordinated proxy agent to apply.

Eligibility mirrors ``/api/proxy/routing-table`` EXACTLY (enabled + not drain +
status != 'disabled') so a node peered here is the same node the proxy
allowlists — no third definition of "active" to drift out of sync. A node that
is intentionally drained/disabled is *excluded* (not a failure: it is correct
that we stop trusting a node we are draining).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.api.proxy_api import _derive_wg_data_ip


@dataclass(frozen=True)
class WgPeer:
    """One desired WireGuard peer (panel-side or proxy-side)."""

    name: str
    public_key: str
    allowed_ips: list[str]
    address: str                     # the /32 host address (mgmt or data)
    endpoint_hint: str = ""          # CHR public IP (informational for proxy)
    status: str = ""
    enabled: bool = True
    drain: bool = False

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "public_key": self.public_key,
            "allowed_ips": list(self.allowed_ips),
            "address": self.address,
            "endpoint_hint": self.endpoint_hint,
            "status": self.status,
            "enabled": self.enabled,
            "drain": self.drain,
        }


def _eligible_nodes() -> list:
    """Fleet nodes that should carry traffic: enabled + not draining + not
    admin-disabled. Identical predicate to proxy_api.routing_table()."""
    from fleet.registry.models_chr import FleetChrNode
    try:
        return (
            FleetChrNode.query
            .filter(FleetChrNode.enabled.is_(True))
            .filter(FleetChrNode.drain.is_(False))
            .filter(FleetChrNode.status != "disabled")
            .order_by(FleetChrNode.name.asc())
            .all()
        )
    except Exception:  # noqa: BLE001 — defensive: never crash a reconcile
        return []


def desired_panel_peers() -> list[WgPeer]:
    """The wg-mgmt peer set the panel host must trust.

    A node is included only when it has BOTH a control-plane address in the
    10.99 pool AND a wg-mgmt pubkey on file — otherwise we'd emit a peer with
    no allowed-ip or no key, which the helper would reject. Such a node surfaces
    as a FAILED stage in the sync job instead (real state, not a silent skip).
    """
    peers: list[WgPeer] = []
    for n in _eligible_nodes():
        mgmt_ip = (n.wg_mgmt_ip or "").strip()
        pub = (n.wg_mgmt_pubkey or "").strip()
        if not n.name or not mgmt_ip.startswith("10.99.") or not pub:
            continue
        peers.append(WgPeer(
            name=n.name,
            public_key=pub,
            allowed_ips=[f"{mgmt_ip}/32"],
            address=mgmt_ip,
            endpoint_hint=n.public_ip or "",
            status=n.status,
            enabled=bool(n.enabled),
            drain=bool(n.drain),
        ))
    return peers


def desired_proxy_peers() -> list[WgPeer]:
    """The wg-data peer set the proxy host must trust.

    Included only when the derived wg-data IP resolves (10.98 pool) AND the
    node has a wg-data pubkey on file (denormalized at onboarding, backfilled
    for old rows). A node missing its data pubkey is excluded here and shows as
    a FAILED 'register peer on proxy' stage so the operator knows to re-onboard.
    """
    peers: list[WgPeer] = []
    for n in _eligible_nodes():
        data_ip = _derive_wg_data_ip(n.wg_mgmt_ip)
        pub = (n.wg_data_pubkey or "").strip()
        if not n.name or not data_ip.startswith("10.98.") or not pub:
            continue
        peers.append(WgPeer(
            name=n.name,
            public_key=pub,
            allowed_ips=[f"{data_ip}/32"],
            address=data_ip,
            endpoint_hint=n.public_ip or "",
            status=n.status,
            enabled=bool(n.enabled),
            drain=bool(n.drain),
        ))
    return peers


__all__ = ["WgPeer", "desired_panel_peers", "desired_proxy_peers"]
