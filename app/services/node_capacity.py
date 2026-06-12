"""Per-node capacity allocator — design §10.2.

Single read-only helper the dashboard + the «اتصالات الوصول» provisioner
share. Given a node + its enabled roles + a session count per role, returns
the operator-visible capacity picture: uplink, per-role allocation (from
the §9 bandwidth policy), and the spare Mbps available for additional
sessions.

This is the math behind «a 1 G CHR carrying only RADIUS shows 995 M spare,
that's the operator's cue to enable a VPN role on the same box».
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from app.services.bandwidth_policy import (
    SUPPORTED_TYPES,
    TypePolicy,
    all_policies,
)
from app.services.node_roles import enabled_roles


#: Default 1 Gbps uplink — the doc's reference number. The allocator
#: prefers the node's declared ``link_speed_mbps`` when set.
_DEFAULT_UPLINK_MBPS = 1000


@dataclass(frozen=True)
class NodeCapacity:
    """The five rows the dashboard renders per node."""

    uplink_mbps: int
    policy_by_role: dict[str, TypePolicy]
    sessions_by_role: dict[str, int]
    allocated_by_role: dict[str, int]    # sessions × policy.download_mbps per role
    enabled_roles: set[str]
    total_allocated_mbps: int
    spare_mbps: int

    def as_payload(self) -> dict:
        """Wire shape — what the dashboard JSON returns."""
        return {
            "uplink_mbps": self.uplink_mbps,
            "enabled_roles": sorted(self.enabled_roles),
            "policy_by_role": {
                role: pol.as_dict() for role, pol in self.policy_by_role.items()
            },
            "sessions_by_role": dict(self.sessions_by_role),
            "allocated_by_role": dict(self.allocated_by_role),
            "total_allocated_mbps": self.total_allocated_mbps,
            "spare_mbps": self.spare_mbps,
        }


def capacity_for(
    node,
    sessions_by_role: dict[str, int] | None = None,
    *,
    uplink_mbps: int | None = None,
) -> NodeCapacity:
    """Compute the per-node capacity picture.

    Parameters
    ----------
    node:
        A ``FleetChrNode`` (or any object with ``link_speed_mbps`` /
        ``roles_json``). The helper uses ``enabled_roles(node)`` for
        membership, so a missing ``roles_json`` is treated as "all roles
        enabled" per §10.1.
    sessions_by_role:
        Live session counts. Keys outside ``SUPPORTED_TYPES`` are
        ignored; missing keys count as zero. The caller already has this
        in hand (the P8 dashboard reads `fleet_chr_metrics.active_sessions`
        and per-tunnel tables); we accept it as a parameter to keep this
        module DB-free for testability.
    uplink_mbps:
        Override the node's declared link speed (test hook). When
        ``None``, prefers ``node.link_speed_mbps`` then falls back to
        ``_DEFAULT_UPLINK_MBPS``.
    """
    sessions = {t: int((sessions_by_role or {}).get(t, 0)) for t in SUPPORTED_TYPES}
    pol = all_policies()
    roles = enabled_roles(node)
    allocated: dict[str, int] = {}
    for t in SUPPORTED_TYPES:
        if t not in roles:
            allocated[t] = 0
            continue
        # Each active session consumes its policy's download cap on the
        # uplink. We use download_mbps as the conservative reservation
        # (downstream is usually the bottleneck on a customer VPN); the
        # operator can always switch the picker to upstream-bounded
        # accounting once §9 lands more variants.
        allocated[t] = max(0, int(pol[t].download_mbps)) * sessions[t]
    total = sum(allocated.values())
    if uplink_mbps is None:
        uplink_mbps = int(getattr(node, "link_speed_mbps", None) or _DEFAULT_UPLINK_MBPS)
    spare = max(0, uplink_mbps - total)
    return NodeCapacity(
        uplink_mbps=uplink_mbps,
        policy_by_role={t: pol[t] for t in SUPPORTED_TYPES},
        sessions_by_role=sessions,
        allocated_by_role=allocated,
        enabled_roles=roles,
        total_allocated_mbps=total,
        spare_mbps=spare,
    )


__all__ = ["NodeCapacity", "capacity_for"]
