"""fleet.sync.keys — panel wg-mgmt key stability + drift cascade.

The panel's wg-mgmt keypair is the SINGLE STABLE SOURCE OF TRUTH for the whole
fleet: every CHR script injects the panel's CURRENT pubkey, and every CHR's
wg-mgmt peer must trust exactly that key. Drift here is the root cause of the
``panel_key_mismatch`` incident.

This module does NOT generate keys (that stays in
:mod:`fleet.registry.infra_settings`, reachable only from the explicit
super-admin route). What it owns is the CASCADE that MUST run whenever the panel
key legitimately changes:

* :func:`flag_fleet_needs_reimport` — mark every node's script known-stale, so
  the dashboard/troubleshoot/sync all agree the fleet needs a re-push.
* :func:`clear_node_reimport` — drop that flag for one node the moment its
  wg-mgmt handshake verifies it trusts the current panel key (real proof the
  re-import landed — see :mod:`fleet.sync.stages` stage 5).

There is deliberately no path here that writes ``PANEL_WG_PUBKEY``; key
stability is enforced by *omission* (and locked down by a test that asserts no
onboarding/render/resync code path regenerates it).
"""
from __future__ import annotations


def panel_pubkey() -> str:
    """The panel's current wg-mgmt public key (empty string if unset)."""
    from fleet.registry.infra_settings import panel_pubkey_for_display
    return (panel_pubkey_for_display() or "").strip()


def flag_fleet_needs_reimport() -> list[str]:
    """Flag EVERY fleet node as needing a script re-import (panel key drifted).

    Returns the names of the nodes flagged. Commits. Idempotent: re-running
    simply re-asserts the flag. This is the cascade the panel-keypair
    regenerate/paste routes call so a key change is never silent again.
    """
    from app.extensions import db
    from fleet.registry.models_chr import FleetChrNode

    names: list[str] = []
    nodes = FleetChrNode.query.order_by(FleetChrNode.name.asc()).all()
    for n in nodes:
        n.needs_reimport = True
        if n.name:
            names.append(n.name)
    if nodes:
        db.session.commit()
    return names


def clear_node_reimport(node, *, commit: bool = True) -> None:
    """Drop the stale-script flag for one node (its handshake proved the
    current panel key is trusted). No-op if already clear."""
    from app.extensions import db
    if getattr(node, "needs_reimport", False):
        node.needs_reimport = False
        if commit:
            db.session.commit()


__all__ = ["panel_pubkey", "flag_fleet_needs_reimport", "clear_node_reimport"]
