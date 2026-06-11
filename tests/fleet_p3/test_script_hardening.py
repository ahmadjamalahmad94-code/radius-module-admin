"""Deterministic-onboarding hardening — generated-script invariants.

Covers the field session's remaining script-side findings
(fix/fleet-deterministic-onboarding):

* WireGuard peer ``allowed-address`` is ALWAYS ``/32`` for the remote
  peer (panel / proxy) — ``/24`` there causes routing overlap with
  multiple peers. Interface addresses stay ``/24`` (prior fix).
* Firewall RULE ORDER: the wg allow rules are explicitly MOVED to the
  top of the input chain after (re-)adding, so a stale operator drop
  (the 8443 public-IP drop from the incident) can never shadow them.
* RADIUS client points at the proxy data-plane IP with the CHR's own
  data-plane IP as ``src-address``.
* The key-identity audit-trail log lines render with the real pubkeys.
* Script generation REFUSES when critical fleet bindings are missing
  (panel pubkey / endpoints / proxy pubkey / shared secret).
"""
from __future__ import annotations

import re

from fleet.registry.script_bindings_check import check_bindings, summary_ar
from fleet.registry.script_render import (
    ChrKeyMaterial,
    RouterosTemplateConfig,
    render_chr_script,
)


class _N:
    name = "chr-vpn-1"
    public_ip = "178.105.244.112"


def _cfg(**over) -> RouterosTemplateConfig:
    base = dict(
        panel_wg_pubkey="PANEL" + "p" * 38 + "=",
        panel_wg_endpoint="panel.hoberadius.com:51820",
        panel_wg_addr="10.99.0.1",
        proxy_wg_pubkey="PROXY" + "q" * 38 + "=",
        proxy_wg_endpoint="proxy.hoberadius.com:51821",
        proxy_wg_addr="10.98.0.1",
        chr_shared_secret="radsecret",
        api_user="hobe-panel", api_password="pw!", api_port=8443,
    )
    base.update(over)
    return RouterosTemplateConfig(**base)


def _render(**over) -> str:
    keys = ChrKeyMaterial(
        mgmt_privkey="MGMT==", mgmt_addr="10.99.0.11/24",
        data_privkey="DATA==", data_addr="10.98.0.11/24",
    )
    return render_chr_script(_N(), keys, _cfg(**over))


# ── peer allowed-address is /32, never /24 ──────────────────────────────


def test_peer_allowed_address_is_slash_32():
    script = _render()
    assert "allowed-address=10.99.0.1/32" in script   # panel peer on wg-mgmt
    assert "allowed-address=10.98.0.1/32" in script   # proxy peer on wg-data
    # The /24 form on a peer is the routing-overlap hazard — forbid it.
    assert "allowed-address=10.99.0.1/24" not in script
    assert "allowed-address=10.98.0.1/24" not in script


def test_interface_addresses_stay_slash_24():
    script = _render()
    assert "add interface=wg-mgmt address=10.99.0.11/24" in script
    assert "add interface=wg-data address=10.98.0.11/24" in script


# ── firewall: allows hoisted above any drop ─────────────────────────────


def test_wg_allow_rules_are_moved_to_top_after_adds():
    """The move-to-destination-0 block exists AND comes after the adds —
    first-match firewalls need our accepts above any stale drop."""
    script = _render()
    for c in ("hobe-fleet-fw-mgmt", "hobe-fleet-fw-coa", "hobe-fleet-fw-radius"):
        move_line = f'move [find comment="{c}"] destination=0'
        assert move_line in script, f"missing hoist for {c}"
        # add (the rule creation) precedes its move
        add_pos = script.index(f'comment="{c}"')
        move_pos = script.index(move_line)
        assert add_pos < move_pos, f"{c}: move must come after add"


def test_mgmt_move_order_puts_radius_first():
    """Moves execute mgmt → coa → radius, each to slot 0, so the final
    top-of-chain order is radius, coa, mgmt — all three above any drop."""
    script = _render()
    pos_mgmt = script.index('move [find comment="hobe-fleet-fw-mgmt"]')
    pos_coa = script.index('move [find comment="hobe-fleet-fw-coa"]')
    pos_radius = script.index('move [find comment="hobe-fleet-fw-radius"]')
    assert pos_mgmt < pos_coa < pos_radius


def test_our_own_drop_rule_still_exists_below():
    script = _render()
    assert 'comment="hobe-fleet-fw-no-public-radius"' in script
    # And the drop is NOT among the moved comments.
    assert 'move [find comment="hobe-fleet-fw-no-public-radius"]' not in script


# ── RADIUS wiring ────────────────────────────────────────────────────────


def test_radius_points_at_proxy_with_chr_src_address():
    script = _render()
    line_start = script.index("add service=ppp,login")
    chunk = script[line_start:line_start + 300]
    assert "address=10.98.0.1" in chunk          # the proxy data-plane IP
    assert "src-address=10.98.0.11" in chunk     # the CHR's own data IP
    assert 'comment="hobe-fleet-radius"' in chunk


# ── key-identity audit trail ─────────────────────────────────────────────


def test_pubkey_audit_log_lines_render_with_real_keys():
    script = _render()
    assert ("wg-mgmt peer expects PANEL pubkey = PANEL" + "p" * 38 + "=") in script
    assert ("wg-data peer expects PROXY pubkey = PROXY" + "q" * 38 + "=") in script
    # The CHR's own pubkey is read live on the device (not a binding).
    assert "this CHR wg-mgmt pubkey (give to panel)" in script
    assert '[/interface wireguard get [find name="wg-mgmt"] public-key]' in script


# ── generation refuses on missing fleet values ───────────────────────────


def test_check_bindings_flags_all_missing_criticals():
    missing = check_bindings({
        "PANEL_WG_PUBKEY": "", "PANEL_WG_ENDPOINT": "",
        "PROXY_WG_PUBKEY": "", "PROXY_WG_ENDPOINT": "",
        "CHR_SHARED_SECRET": "",
        "WG_MGMT_PRIVKEY": "x", "WG_DATA_PRIVKEY": "y",
    })
    keys = {m.key for m in missing}
    assert {"PANEL_WG_PUBKEY", "PANEL_WG_ENDPOINT", "PROXY_WG_PUBKEY",
            "PROXY_WG_ENDPOINT", "CHR_SHARED_SECRET"} <= keys
    # And the operator summary names them in Arabic.
    text = summary_ar(missing)
    assert "بانتظار" in text or "مفتاح" in text


def test_check_bindings_passes_on_complete_set():
    missing = check_bindings({
        "PANEL_WG_PUBKEY": "P=", "PANEL_WG_ENDPOINT": "panel.x:51820",
        "PROXY_WG_PUBKEY": "Q=", "PROXY_WG_ENDPOINT": "proxy.x:51821",
        "CHR_SHARED_SECRET": "s3cret",
        "WG_MGMT_PRIVKEY": "m=", "WG_DATA_PRIVKEY": "d=",
    })
    assert missing == []


def test_placeholder_values_count_as_missing():
    """Doc-shaped placeholders like '<PANEL_WG_PUBKEY>' must not pass."""
    missing = check_bindings({
        "PANEL_WG_PUBKEY": "<PANEL_WG_PUBKEY>",
        "PANEL_WG_ENDPOINT": "panel.x:51820",
        "PROXY_WG_PUBKEY": "Q=", "PROXY_WG_ENDPOINT": "proxy.x:51821",
        "CHR_SHARED_SECRET": "s3cret",
        "WG_MGMT_PRIVKEY": "m=", "WG_DATA_PRIVKEY": "d=",
    })
    assert any(m.key == "PANEL_WG_PUBKEY" for m in missing)
