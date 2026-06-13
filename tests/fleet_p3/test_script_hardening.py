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


def test_wg_allow_rules_use_place_before_drop_last():
    """Effective rule order is built via insertion order, not `move`.
    Every accept rule we add is anchored against the drop-last sentinel
    via `place-before=[find comment="hobe-fleet-fw-drop-last"]` so that
    on the CHR it lands ABOVE the catch-all drop even when foreign
    rules interleave between adds (the chr-vpn-3 incident)."""
    script = _render()
    anchor = 'place-before=[find comment="hobe-fleet-fw-drop-last"]'
    for c in ("hobe-fleet-fw-mgmt", "hobe-fleet-fw-coa", "hobe-fleet-fw-radius"):
        rule_re = re.compile(
            r"add chain=input[\s\S]+?comment=\"" + re.escape(c) + r"\"",
            re.MULTILINE,
        )
        m = rule_re.search(script)
        assert m, f"missing add for {c}"
        assert anchor in m.group(0), (
            f"{c} accept must anchor against drop-last via place-before; "
            f"got: {m.group(0)!r}"
        )


def test_drop_last_anchor_added_before_all_other_input_rules():
    """The anchor `hobe-fleet-fw-drop-last` must be the FIRST add in §9
    (script-text position), so every subsequent place-before find
    succeeds (no «no such item» on a fresh CHR)."""
    script = _render()
    drop_last_add = script.index(
        'add chain=input action=drop comment="hobe-fleet-fw-drop-last"'
    )
    # Every other hobe-fleet-fw-* rule must appear AFTER the anchor in the
    # script text — confirms the place-before pattern (insertion order =
    # effective order, bottom-up).
    for c in (
        "hobe-fleet-fw-conntrack",
        "hobe-fleet-fw-mgmt",
        "hobe-fleet-fw-coa",
        "hobe-fleet-fw-radius",
        "hobe-fleet-fw-no-public-radius",
    ):
        pos = script.index(f'comment="{c}"')
        assert pos > drop_last_add, (
            f"{c} must appear AFTER drop-last anchor in script text "
            f"so place-before resolves"
        )


def test_no_move_destination_zero_pattern_remains():
    """The old `move ... destination=0` hoist must be gone — replaced by
    the place-before anchor. Mixing both patterns produces races vs
    foreign rules. Match only whole-word `move` (re**move** legitimately
    occurs as a different verb)."""
    script = _render()
    legacy = re.search(r"(?<!re)move \[find comment=\"hobe-fleet-fw-", script)
    assert legacy is None, (
        "found legacy `move [find comment=\"hobe-fleet-fw-...\"]` hoist — "
        "the hoist must be replaced by place-before anchors against "
        f"hobe-fleet-fw-drop-last; near: {script[max(0, legacy.start()-40):legacy.end()+80]!r}"
    )
    code_lines = [
        ln for ln in script.splitlines()
        if "destination=0" in ln and not ln.lstrip().startswith("#")
    ]
    assert not code_lines, (
        "found `destination=0` in CODE (not a comment) — likely the old "
        f"move hoist; replace with place-before. lines: {code_lines!r}"
    )


def test_our_own_drop_rule_still_exists_below():
    script = _render()
    assert 'comment="hobe-fleet-fw-no-public-radius"' in script
    # And the drop is NOT among the moved comments.
    assert 'move [find comment="hobe-fleet-fw-no-public-radius"]' not in script


# ── RADIUS wiring ────────────────────────────────────────────────────────


def test_radius_points_at_proxy_with_chr_src_address():
    script = _render()
    # service=ppp ONLY (not ppp,login) since fix/chr-script-review-remaining —
    # RADIUS authenticates PPP/VPN users, NOT router admin login. The
    # specific anti-`login` pin lives in
    # tests/fleet_p3/test_chr_script_review_remaining.py.
    line_start = script.index("add service=ppp ")
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
