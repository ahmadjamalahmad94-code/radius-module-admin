"""fix/fleet-script-idempotent — assert every `add` in the unified RouterOS
script is preceded by a `remove [find …]` so a re-import on the same CHR
succeeds without «already have / already exists» errors.

The bug we're fixing: the .rsc had bare `/interface wireguard add name=wg-mgmt`
with no cleanup. After a partial first run that already created `wg-mgmt`,
re-importing failed at line 12 with «already have interface with name wg-mgmt».
A provisioning script for a fleet of CHRs MUST be re-runnable.
"""
from __future__ import annotations

import re

import pytest

from fleet.registry.script_render import render_from_bindings


_BINDINGS = {
    "ROUTER_IDENTITY":    "chr-vpn-1",
    "CHR_PUBLIC_IP":      "178.105.244.112",
    "WAN_IFACE":          "ether1",
    "WG_MGMT_PRIVKEY":    "MGMT_PRIVKEY_BASE64==",
    "WG_MGMT_ADDR":       "10.99.0.11/32",
    "WG_DATA_PRIVKEY":    "DATA_PRIVKEY_BASE64==",
    "WG_DATA_ADDR":       "10.98.0.11/32",
    "WG_DATA_ADDR_IP":    "10.98.0.11",
    "PANEL_WG_PUBKEY":    "PANELPUBKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "PANEL_WG_ENDPOINT":  "control.hoberadius.com:51820",
    "PANEL_WG_ADDR":      "10.99.0.1",
    "PROXY_WG_PUBKEY":    "PROXYPUBKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQM=",
    "PROXY_WG_ENDPOINT":  "proxy.hoberadius.com:51821",
    "PROXY_WG_ADDR":      "10.98.0.1",
    "CHR_SHARED_SECRET":  "kla0FAzDKNJGoGIXdpDaCKB4Q2ytm-txZZZ_strongsecret",
    "SSTP_CERT_NAME":     "vpn-cert",
    "IKE_CERT_NAME":      "ike-cert",
    "CLIENT_SUPERNET":    "10.0.0.0/8",
    "DNS_PUSH":           "1.1.1.1",
    "GW_LOCAL_ADDR":      "10.10.0.1",
}


def _render(**overrides):
    bindings = {**_BINDINGS, **overrides}
    return render_from_bindings(bindings)


# ─── per-section idempotency claims ─────────────────────────────────────────

def test_wg_mgmt_interface_has_remove_before_add():
    """The original bug: wg-mgmt interface add MUST have remove [find name="wg-mgmt"]
    above it. Re-import previously failed at this line with «already have»."""
    script = _render()
    # Strip line continuations so we can search line-by-line cleanly.
    flat = script.replace(" \\\n", " ")
    lines = flat.splitlines()
    # Find the `add name=wg-mgmt` line for the wireguard interface (not peer).
    add_idx = None
    for i, line in enumerate(lines):
        s = line.strip()
        if s.startswith("add name=wg-mgmt"):
            add_idx = i
            break
    assert add_idx is not None, "wg-mgmt interface add line not found"

    # Look back to find the preceding /interface wireguard header and the
    # remove that must sit between it and the add.
    found_remove = False
    found_header = False
    for j in range(add_idx - 1, max(-1, add_idx - 6), -1):
        s = lines[j].strip()
        if s.startswith("remove [find name=\"wg-mgmt\"]"):
            found_remove = True
        if s == "/interface wireguard":
            found_header = True
            break
    assert found_header, "couldn't find /interface wireguard header above the add"
    assert found_remove, (
        "wg-mgmt interface `add` must be preceded by "
        "`/interface wireguard\\nremove [find name=\"wg-mgmt\"]`"
    )


def test_wg_data_interface_has_remove_before_add():
    script = _render().replace(" \\\n", " ")
    # Same pattern for wg-data.
    assert re.search(
        r"/interface wireguard\s*\n\s*remove \[find name=\"wg-data\"\]\s*\n\s*add name=wg-data ",
        script,
    ), "wg-data interface needs a `remove [find name=\"wg-data\"]` immediately before its `add`"


def test_wg_peers_remove_before_add_both_tunnels():
    """Peers reference the interface they're attached to; remove by `interface=`."""
    script = _render()
    assert 'remove [find interface="wg-mgmt"]' in script, \
        "wg-mgmt peers must be cleaned by remove [find interface=\"wg-mgmt\"]"
    assert 'remove [find interface="wg-data"]' in script, \
        "wg-data peers must be cleaned by remove [find interface=\"wg-data\"]"


def test_ip_address_remove_before_add_both_tunnels():
    """`/ip address` rows on wg-mgmt/wg-data: remove by interface filter."""
    script = _render()
    # find interface="wg-mgmt" appears twice — once for peers, once for /ip address.
    assert script.count('remove [find interface="wg-mgmt"]') >= 2
    assert script.count('remove [find interface="wg-data"]') >= 2


def test_radius_entry_tagged_and_removed_first():
    """Brief said: add stable `comment="hobe-fleet"` to the /radius row and
    remove by that tag before re-adding. Stronger tag used: hobe-fleet-radius."""
    script = _render().replace(" \\\n", " ")
    assert "/radius\nremove [find comment=\"hobe-fleet-radius\"]\nadd service=ppp,login " in script, \
        "/radius entry must be remove-by-tag then re-add with comment=\"hobe-fleet-radius\""
    assert 'comment="hobe-fleet-radius"' in script, "/radius add must carry the tag"


def test_ipsec_resources_remove_before_add():
    """ipsec profile / proposal / mode-config / peer have `name=`; identity uses
    `peer=` as its handle. Each gets a remove-before-add."""
    script = _render()
    for token in (
        'remove [find name="hobe-ike"]',
        'remove [find name="hobe-prop"]',
        'remove [find name="hobe-mc"]',
        'remove [find name="hobe-peer"]',
        'remove [find peer="hobe-peer"]',
    ):
        assert token in script, f"ipsec section missing: {token}"


def test_firewall_nat_remove_before_add():
    script = _render()
    assert 'remove [find comment="hobe-fleet-nat-egress"]' in script
    assert 'comment="hobe-fleet-nat-egress"' in script


def test_firewall_filter_uses_regex_remove_for_all_hobe_rules():
    """Multiple filter rules: one regex `remove [find comment~"^hobe-fleet-fw-"]`
    clears them all in one shot before re-adding. This also handles the case
    where SSTP/IKE openings appeared in a previous render but the cert was
    cleared since — stale rules get swept."""
    script = _render()
    assert 'remove [find comment~"^hobe-fleet-fw-"]' in script
    # Every filter add must carry the hobe-fleet-fw- tag prefix so the regex
    # remove will catch it on the next run.
    for line in script.splitlines():
        s = line.strip()
        if s.startswith("add chain=input") and "comment=" in s:
            assert 'comment="hobe-fleet-fw-' in s, \
                f"filter rule missing hobe-fleet-fw- tag: {s}"


def test_every_add_under_relevant_section_has_cleanup():
    """Belt-and-suspenders: there must be no `add` line for a resource type we
    know about without a `remove` of the same section earlier in the script."""
    script = _render()
    # All `add` lines that we expect to be idempotent + the cleanup token
    # that must appear BEFORE them somewhere in the script.
    add_lines = [l.strip() for l in script.replace(" \\\n", " ").splitlines()
                 if l.strip().startswith("add ")]
    # At minimum we expect the set of cleanup tokens to appear:
    cleanups = [
        'remove [find name="wg-mgmt"]',
        'remove [find name="wg-data"]',
        'remove [find interface="wg-mgmt"]',
        'remove [find interface="wg-data"]',
        'remove [find comment="hobe-fleet-radius"]',
        'remove [find name="hobe-ike"]',
        'remove [find name="hobe-prop"]',
        'remove [find name="hobe-mc"]',
        'remove [find comment="hobe-fleet-nat-egress"]',
        'remove [find comment~"^hobe-fleet-fw-"]',
    ]
    for token in cleanups:
        assert token in script, f"missing cleanup: {token}"
    # Sanity: there should still be a lot of add lines (we didn't strip them).
    assert len(add_lines) >= 10, f"unexpectedly few add lines: {len(add_lines)}"


# ─── set-based blocks (already idempotent) — make sure they stayed `set` ───

def test_set_based_blocks_unchanged():
    script = _render()
    for token in (
        "/radius incoming\n# Enable CoA",
        "/ppp aaa\nset use-radius=yes",
        "/ppp profile\nset default-encryption",
        "/interface pptp-server server\nset enabled=yes",
    ):
        assert token in script, f"missing/changed set-block: {token!r}"


# ─── cert-conditional skips must still work ─────────────────────────────────

def test_cert_conditional_skips_preserved():
    """The `{% if SSTP_CERT_NAME %}` and `{% if IKE_CERT_NAME %}` gates must
    still skip the relevant blocks when cert names are empty."""
    script = _render(SSTP_CERT_NAME="", IKE_CERT_NAME="")
    assert "/interface sstp-server server" not in script, \
        "SSTP block should be skipped when SSTP_CERT_NAME is empty"
    assert "/ip ipsec identity\nadd auth-method=eap-radius" not in script.replace(" \\\n", " "), \
        "IPsec identity add should be skipped when IKE_CERT_NAME is empty"
    assert "/ip ipsec peer\nadd name=hobe-peer" not in script, \
        "IPsec peer add should be skipped when IKE_CERT_NAME is empty"
    # Cleanup lines for these blocks SHOULD still be emitted so a CHR that
    # previously had certs (and the blocks) gets them swept on re-import.
    assert 'remove [find peer="hobe-peer"]' in script
    assert 'remove [find name="hobe-peer"]' in script
    # The hobe-fleet-fw-sstp + hobe-fleet-fw-ike rules should NOT be added
    # when their certs are off — but the regex remove still cleans any leftover.
    assert "hobe-fleet-fw-sstp" not in script
    assert "hobe-fleet-fw-ike" not in script
    assert 'remove [find comment~"^hobe-fleet-fw-"]' in script


# ─── double-apply ordering claim ─────────────────────────────────────────────

def test_remove_appears_before_add_for_every_managed_resource():
    """Logical double-apply check: for each managed resource, the line offset
    of its `remove` MUST be less than the line offset of its first `add`. If
    not, a re-import would fail at the `add` step."""
    script = _render()
    lines = script.splitlines()

    def first_index(needle: str) -> int:
        for i, line in enumerate(lines):
            if needle in line:
                return i
        return -1

    pairs = [
        ('remove [find name="wg-mgmt"]',                    "add name=wg-mgmt "),
        ('remove [find name="wg-data"]',                    "add name=wg-data "),
        ('remove [find interface="wg-mgmt"]',               "add interface=wg-mgmt "),
        ('remove [find interface="wg-data"]',               "add interface=wg-data "),
        ('remove [find comment="hobe-fleet-radius"]',       "add service=ppp,login"),
        ('remove [find name="hobe-ike"]',                   "add name=hobe-ike "),
        ('remove [find name="hobe-prop"]',                  "add name=hobe-prop "),
        ('remove [find name="hobe-mc"]',                    "add name=hobe-mc "),
        ('remove [find comment="hobe-fleet-nat-egress"]',   "add chain=srcnat "),
        ('remove [find comment~"^hobe-fleet-fw-"]',         "add chain=input "),
    ]
    for rem, add in pairs:
        ri = first_index(rem)
        ai = first_index(add)
        assert ri >= 0, f"missing remove: {rem}"
        assert ai >= 0, f"missing add: {add}"
        assert ri < ai, (
            f"remove `{rem}` (line {ri}) must come BEFORE add `{add}` "
            f"(line {ai}); otherwise a re-run hits «already have»."
        )
