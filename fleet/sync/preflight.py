"""fleet.sync.preflight — pre-export readiness checks for a CHR's tunnels.

The live chr-vpn-2 incident exposed a gap: the generated script imported
cleanly + the CHR's LOCAL wg-data config was correct, but the data tunnel
never handshook because the PROXY had no peer for this CHR's wg-data
pubkey. That is a REMOTE-PENDING condition, not a local failure — but
nothing on the panel surfaced it BEFORE the operator exported + imported
+ waited + got "(4) wg-data no handshake".

This module answers, from the panel's own DB (no network calls), the
question the operator needs before export:

    "Once I import this script, will the panel actually publish this
     CHR's wg-data peer to the proxy, AND is that peer well-formed +
     unique?"

It classifies into three states (mirrors the CHR-side validation split
in chr_unified.rsc.j2 §12):

  * ``ok``             — everything the panel controls is in place; the
                         peer WILL be published. Handshake then depends
                         only on the proxy polling /api/proxy/wg-peers.
  * ``pending_remote`` — local panel state is fine but the handshake is
                         expected to lag until the proxy adds the peer
                         (informational; NOT a blocker).
  * ``blocked``        — a panel-side gap that WOULD silently prevent
                         the proxy from ever peering this CHR (missing
                         wg-data pubkey, un-derivable / non-unique
                         10.98.0.X/32). Fix before export.

Read-only + crash-proof: any internal error degrades to a blocked
verdict with a machine reason, never an exception, so a caller can show
it inline without a try/except.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class WgDataPreflight:
    """Panel-side readiness verdict for a CHR's wg-data proxy peer."""

    node_id: int
    node_name: str
    state: str                       # ok | pending_remote | blocked
    wg_data_ip: str = ""
    wg_data_pubkey_present: bool = False
    allowed_ip: str = ""             # the /32 the proxy must trust
    allowed_ip_unique: bool = True
    will_publish: bool = False       # would desired_proxy_peers() include it?
    reasons: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.state == "ok"

    @property
    def blocked(self) -> bool:
        return self.state == "blocked"


def preflight_wg_data(node) -> WgDataPreflight:
    """Classify whether ``node``'s wg-data peer will reach the proxy.

    No network I/O — pure DB/derivation. Mirrors the eligibility rules
    of :func:`fleet.sync.peers.desired_proxy_peers` so the verdict
    matches what the panel will actually publish at
    ``GET /api/proxy/wg-peers``.
    """
    try:
        from app.api.proxy_api import _derive_wg_data_ip
        from fleet.registry.models_chr import FleetChrNode
    except Exception as exc:  # noqa: BLE001 — degrade, never raise
        return WgDataPreflight(
            node_id=getattr(node, "id", 0) or 0,
            node_name=getattr(node, "name", "") or "",
            state="blocked",
            reasons=[f"import_failed: {exc.__class__.__name__}"],
        )

    nid = int(getattr(node, "id", 0) or 0)
    name = (getattr(node, "name", "") or "").strip()
    reasons: list[str] = []

    data_ip = _derive_wg_data_ip(getattr(node, "wg_mgmt_ip", "") or "")
    pub = (getattr(node, "wg_data_pubkey", "") or "").strip()
    allowed_ip = f"{data_ip}/32" if data_ip else ""

    pubkey_present = bool(pub)
    if not pubkey_present:
        reasons.append(
            "wg-data pubkey missing on the node row — the proxy can't be "
            "told which key to trust. Re-run onboarding key generation "
            "(the panel mints + stores the wg-data keypair)."
        )

    derivable = bool(data_ip) and data_ip.startswith("10.98.")
    if not derivable:
        reasons.append(
            f"wg-data IP not derivable in the 10.98.0.0/24 pool from "
            f"wg_mgmt_ip={getattr(node, 'wg_mgmt_ip', '')!r} — the proxy "
            f"peer allowed-ips can't be computed."
        )

    # Uniqueness: no OTHER node may claim the same 10.98.0.X/32, or the
    # proxy peer set is ambiguous (two CHRs → one allowed-ip → RADIUS
    # from the second is mis-attributed / dropped).
    allowed_ip_unique = True
    if derivable:
        try:
            others = (
                FleetChrNode.query
                .filter(FleetChrNode.id != nid)
                .all()
            )
            for o in others:
                o_ip = _derive_wg_data_ip(o.wg_mgmt_ip or "")
                if o_ip and o_ip == data_ip:
                    allowed_ip_unique = False
                    reasons.append(
                        f"wg-data IP {data_ip}/32 COLLIDES with node "
                        f"«{o.name}» (#{o.id}) — both derive the same "
                        f"10.98.0.X. Assign a distinct wg_mgmt_ip last "
                        f"octet so each CHR gets a unique proxy peer."
                    )
                    break
        except Exception as exc:  # noqa: BLE001 — uniqueness is best-effort
            reasons.append(f"uniqueness_check_skipped: {exc.__class__.__name__}")

    # Eligibility mirror (enabled + not drain + status != disabled).
    eligible = (
        bool(getattr(node, "enabled", False))
        and not bool(getattr(node, "drain", False))
        and (getattr(node, "status", "") != "disabled")
    )
    will_publish = bool(pubkey_present and derivable and eligible)

    # State machine.
    if not pubkey_present or not derivable or not allowed_ip_unique:
        state = "blocked"
    elif not eligible:
        # Local config is fine but the node is intentionally drained/
        # disabled, so it's deliberately NOT published — surface as
        # pending_remote (not blocked: this is a correct exclusion).
        state = "pending_remote"
        reasons.append(
            "node is drained/disabled, so its wg-data peer is "
            "intentionally NOT published to the proxy."
        )
    else:
        state = "ok"
        reasons.append(
            "panel will publish this CHR's wg-data peer at "
            "/api/proxy/wg-peers; handshake appears once the proxy polls "
            "+ adds it (remote, ~poll interval)."
        )

    return WgDataPreflight(
        node_id=nid,
        node_name=name,
        state=state,
        wg_data_ip=data_ip,
        wg_data_pubkey_present=pubkey_present,
        allowed_ip=allowed_ip,
        allowed_ip_unique=allowed_ip_unique,
        will_publish=will_publish,
        reasons=reasons,
    )


__all__ = ["WgDataPreflight", "preflight_wg_data"]
