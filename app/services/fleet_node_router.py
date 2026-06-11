"""Zero-central fleet routing — the seam every provisioning path crosses.

The legacy ``chr_settings`` singleton is gone (see docs/CONSOLIDATION.md).
Every feature that used to call :func:`app.services.chr_settings.build_client`
on the one central CHR now goes through this module instead: it resolves a
``FleetChrNode`` either from an explicit choice or via the fleet brain's
``best_node`` ranking — the internal load-balancer — and hands back a
``RouterOSClient`` wired with the per-node credentials from
:mod:`fleet.health.routeros_creds`.

Public surface (all functions raise :class:`FleetNodeUnavailable` with a
human-readable Arabic ``message`` when the picked node has no usable
credentials yet, so callers can surface a clean toast):

* :func:`resolve_node`        — explicit id → node; ``None`` → brain pick.
* :func:`build_client_for`    — wrap a node row in a RouterOSClient.
* :func:`resolve_and_client`  — sugar: resolve_node + build_client_for.
* :func:`auto_pick_best_node` — brain pick alone (for UI prefill).
* :func:`available_nodes`     — list eligible nodes (form dropdown source).

All resolutions are SCOPED to nodes that the fleet has flagged as
``enabled=True, drain=False, status != 'disabled'`` — the same gate
``app/api/proxy_api.py`` uses for routing-table publication. The brain
adds a finer "eligible" filter on top (health, capacity, cost) so the
auto-pick is the LOAD-BALANCED choice, not "any old node".

Fleet-wide public endpoint (the host:port a customer's client dials) is
derived from the picked node: ``public_ip`` (falling back to ``wg_mgmt_ip``)
and service ports stored as Setting rows under ``fleet.port.<service>``.
This module is the only place that derivation happens.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from flask import current_app

from ..extensions import db
from ..models import Setting
from .routeros_client import RouterOSClient


class FleetNodeUnavailable(Exception):
    """Raised when no eligible fleet node has usable RouterOS credentials.

    The ``message`` attribute is the operator-facing Arabic string; views
    surface it via flash/JSON without any massaging.
    """

    def __init__(self, message: str, *, reason_code: str = "no_node") -> None:
        super().__init__(message)
        self.message = message
        self.reason_code = reason_code


# ──────────────────────────────────────────────────────────────────────────
# Setting keys for fleet-wide port + endpoint defaults. Replace the
# legacy `chr.port_<svc>` setting from chr_settings.py.
# ──────────────────────────────────────────────────────────────────────────
FLEET_PORT_SETTING_PREFIX = "fleet.port."
FLEET_PUBLIC_HOST_KEY = "fleet.public_host"   # optional — empty = use node ip
FLEET_IPSEC_CERT_KEY = "fleet.ipsec.certificate"
FLEET_IPSEC_POOL_KEY = "fleet.ipsec.address_pool"

# Hard defaults — the standard ports the unified provisioning script binds.
HARD_DEFAULT_PORTS: dict[str, int] = {
    "sstp": 443,
    "pptp": 1723,
    "l2tp": 1701,
    "ipsec": 4500,
    "wireguard": 51822,
}


@dataclass
class FleetEndpointInfo:
    """The host:port a customer's client uses to dial a specific service.

    Derived from the node + Setting overrides. Returned by
    :func:`endpoint_for` so callers (bridge response, WG config delivery)
    publish the right values without re-implementing port resolution.
    """
    node_name: str
    public_host: str
    ports: dict[str, int]   # keys: sstp/pptp/l2tp/ipsec/wireguard


# ──────────────────────────────────────────────────────────────────────────
# Node availability + resolution
# ──────────────────────────────────────────────────────────────────────────
def _fleet_node_class():
    """Lazy import so older branches without fleet still boot."""
    from fleet.registry.models_chr import FleetChrNode  # noqa: WPS433
    return FleetChrNode


def available_nodes():
    """Every node the operator can place a tunnel/peer on right now.

    Same filter the routing-table uses (enabled + not drain +
    status != disabled). Ordered by name for a stable UI dropdown.
    """
    try:
        FleetChrNode = _fleet_node_class()
    except Exception:
        return []
    return (
        FleetChrNode.query
        .filter(FleetChrNode.enabled.is_(True))
        .filter(FleetChrNode.drain.is_(False))
        .filter(FleetChrNode.status != "disabled")
        .order_by(FleetChrNode.name.asc())
        .all()
    )


def auto_pick_best_node():
    """The brain's recommended placement — the load-balanced choice.

    Returns the ``FleetChrNode`` row (not the brain's NodeScore) so callers
    can pass it straight to :func:`build_client_for`. Returns ``None`` if
    the brain finds nothing eligible (no fleet at all, or every node down).

    The brain is imported lazily because the placement package depends on
    several other fleet modules and we want this helper to remain
    importable on tests that mock the fleet.
    """
    try:
        from fleet.brain.placement import best_node  # noqa: WPS433
        score = best_node()
        if score is None:
            return None
    except Exception:
        # Brain unavailable (no fleet package, no scoring config, etc.).
        # Fall back to "first available node" so provisioning never
        # silently breaks because the brain is wedged.
        nodes = available_nodes()
        return nodes[0] if nodes else None

    # Score → ORM row. ``NodeScore.node_id`` is the fleet_chr_nodes.id.
    FleetChrNode = _fleet_node_class()
    return db.session.get(FleetChrNode, int(score.node_id))


def resolve_node(node_id: Optional[int]):
    """Explicit pick → row; falsy id → brain pick.

    Raises :class:`FleetNodeUnavailable` if the explicit id doesn't
    resolve, OR if no node is available at all when auto-picking.
    """
    if node_id:
        FleetChrNode = _fleet_node_class()
        node = db.session.get(FleetChrNode, int(node_id))
        if node is None:
            raise FleetNodeUnavailable(
                "العقدة المختارة غير موجودة في الأسطول.",
                reason_code="node_not_found",
            )
        return node
    node = auto_pick_best_node()
    if node is None:
        raise FleetNodeUnavailable(
            "لا توجد عقدة فعّالة في الأسطول لتنفيذ هذه العملية. "
            "أضف عقدة من «معالج إضافة CHR» ثم أعد المحاولة.",
            reason_code="no_eligible_node",
        )
    return node


# ──────────────────────────────────────────────────────────────────────────
# Per-node RouterOS client
# ──────────────────────────────────────────────────────────────────────────
def build_client_for(node) -> RouterOSClient:
    """Wrap a node row in a ``RouterOSClient`` using its per-node creds.

    Credentials come from :mod:`fleet.health.routeros_creds`: per-node
    overrides win; otherwise the fleet defaults at
    ``fleet.routeros.api_user/api_password_enc`` Setting rows apply. The
    REST host is the node's ``wg_mgmt_ip`` because the unified script
    binds ``www-ssl`` to the management interface only.

    Raises :class:`FleetNodeUnavailable` when the node has no usable
    credentials — :func:`fleet.health.routeros_creds.credentials_diagnostics`
    is the precise place the operator can fix it from, and the error
    message points there.
    """
    from fleet.health.routeros_creds import credentials_for, credentials_diagnostics

    creds = credentials_for(node)
    if creds is None:
        diag = credentials_diagnostics(node)
        raise FleetNodeUnavailable(
            diag.get("message_ar")
            or "بيانات اعتماد RouterOS غير مكتملة لهذه العقدة.",
            reason_code=diag.get("reason_code") or "no_credentials",
        )
    verify_tls = bool(current_app.config.get("CHR_TLS_VERIFY", False))
    return RouterOSClient(
        host=creds["host"],
        port=int(creds["port"]),
        username=creds["user"],
        password=creds["password"],
        use_tls=True,
        verify_tls=verify_tls,
        timeout=int(current_app.config.get("CHR_REST_TIMEOUT_SECONDS", 15)),
    )


def resolve_and_client(node_id: Optional[int]):
    """Sugar: resolve the node (explicit or brain pick) and build its client.

    Returns ``(node, client)``. Raises :class:`FleetNodeUnavailable` if
    either step fails.
    """
    node = resolve_node(node_id)
    return node, build_client_for(node)


# ──────────────────────────────────────────────────────────────────────────
# Fleet-wide endpoint info — the bits the bridge response publishes
# ──────────────────────────────────────────────────────────────────────────
def _setting(key: str) -> str:
    try:
        row = db.session.get(Setting, key)
        return ((row.value or "") if row else "").strip()
    except Exception:
        return ""


def _port_for(service: str) -> int:
    """Resolve a service port: setting override → hard default."""
    raw = _setting(FLEET_PORT_SETTING_PREFIX + service)
    if raw and raw.isdigit():
        return int(raw)
    return HARD_DEFAULT_PORTS.get(service, 0)


def endpoint_for(node) -> FleetEndpointInfo:
    """The host + per-service ports a customer's client uses for this node.

    Resolution: the fleet-wide ``fleet.public_host`` setting overrides
    everything (used when every CHR sits behind one front-door DNS); if
    empty, the node's ``public_ip`` is the host, or its ``wg_mgmt_ip``
    as a last resort.
    """
    fleet_override = _setting(FLEET_PUBLIC_HOST_KEY)
    host = (fleet_override
            or (node.public_ip or "").strip()
            or (node.wg_mgmt_ip or "").strip())
    ports = {svc: _port_for(svc) for svc in HARD_DEFAULT_PORTS}
    return FleetEndpointInfo(
        node_name=node.name or "",
        public_host=host,
        ports=ports,
    )


def ipsec_overrides() -> dict:
    """The IPsec fleet-constants (cert name + address pool) the
    provisioning scripts need. Empty strings when the operator hasn't
    set them — caller decides whether that's fatal."""
    return {
        "certificate": _setting(FLEET_IPSEC_CERT_KEY),
        "address_pool": _setting(FLEET_IPSEC_POOL_KEY),
    }


__all__ = [
    "FleetNodeUnavailable",
    "FleetEndpointInfo",
    "FLEET_PORT_SETTING_PREFIX",
    "FLEET_PUBLIC_HOST_KEY",
    "FLEET_IPSEC_CERT_KEY",
    "FLEET_IPSEC_POOL_KEY",
    "HARD_DEFAULT_PORTS",
    "available_nodes",
    "auto_pick_best_node",
    "resolve_node",
    "build_client_for",
    "resolve_and_client",
    "endpoint_for",
    "ipsec_overrides",
]
