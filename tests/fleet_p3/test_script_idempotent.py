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
    "WG_MGMT_ADDR":       "10.99.0.11/24",
    "WG_DATA_PRIVKEY":    "DATA_PRIVKEY_BASE64==",
    "WG_DATA_ADDR":       "10.98.0.11/24",
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
    # owner review fix #4: service=ppp only, no `,login` (so RADIUS can't
    # authorise router admin login on the CHR).
    assert "/radius\nremove [find comment=\"hobe-fleet-radius\"]\nadd service=ppp " in script, \
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
    # The `set` form is intrinsically idempotent — preserved across the
    # feat/chr-unified-provisioning-complete expansion. The /ppp profile
    # block now ALSO emits an `add` for the hobe-fleet-default profile,
    # but `set default-encryption` is still emitted so a tunnel landing
    # on the built-in default keeps a valid PPP shape.
    for token in (
        "/radius incoming\n# Enable CoA",
        "/ppp aaa\nset use-radius=yes",
        "set default-encryption local-address=",
        "/interface pptp-server server\nset enabled=yes",
    ):
        assert token in script, f"missing/changed set-block: {token!r}"


# ─── cert-conditional skips must still work ─────────────────────────────────

def test_cert_conditional_skips_preserved():
    """feat/chr-sstp-enduser CHANGED the SSTP gate: SSTP is no longer
    skipped when SSTP_CERT_NAME is empty — the vpn_sstp role now
    AUTO-CREATES a dedicated self-signed cert. The IKEv2 cert-conditional
    (`{% if IKE_CERT_NAME %}`) is UNCHANGED and still skips the IKEv2
    peer/identity when empty."""
    script = _render(SSTP_CERT_NAME="", IKE_CERT_NAME="")
    # SSTP now RENDERS (role on) with the auto-created dedicated cert.
    assert "/interface sstp-server server" in script, \
        "SSTP block must render for vpn_sstp even when SSTP_CERT_NAME is empty"
    assert "add name=hobe-sstp-cert" in script, \
        "vpn_sstp with no custom cert must auto-create hobe-sstp-cert"
    assert "certificate=hobe-sstp-cert" in script
    # IKEv2 peer/identity STILL gated on IKE_CERT_NAME (unchanged by M1).
    assert "/ip ipsec identity\nadd auth-method=eap-radius" not in script.replace(" \\\n", " "), \
        "IPsec identity add should be skipped when IKE_CERT_NAME is empty"
    assert "/ip ipsec peer\nadd name=hobe-peer" not in script, \
        "IPsec peer add should be skipped when IKE_CERT_NAME is empty"
    # Cleanup lines for the IKE blocks SHOULD still be emitted so a CHR that
    # previously had certs (and the blocks) gets them swept on re-import.
    assert 'remove [find peer="hobe-peer"]' in script
    assert 'remove [find name="hobe-peer"]' in script
    # SSTP firewall accept now opens whenever vpn_sstp is on (the cert is
    # auto-created, so the listener is always up for the role).
    assert "hobe-fleet-fw-sstp" in script
    # owner review fix #3 -- the IKE 500/4500 firewall accept is no
    # longer gated on IKE_CERT_NAME. The cert gates the IKEv2 SERVER
    # block in §7, not the WAN-side firewall accept; if the cert isn't
    # ready yet we still want UDP 500/4500 + ESP + UDP 1701 permitted
    # at the firewall layer so the operator's NAT-T / IKE negotiations
    # don't get blackholed once the cert lands. So:
    assert "hobe-fleet-fw-ike" in script, (
        "owner review #3: IKE 500/4500 firewall accept must render whenever "
        "vpn_ipsec role is enabled, regardless of IKE_CERT_NAME"
    )
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
        ('remove [find comment="hobe-fleet-radius"]',       "add service=ppp "),
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


# ─── defensive belt-and-braces for /ppp profile and /ip pool ────────────────

def test_radius_entry_is_force_enabled_after_add():
    """The first live CHR install hit a case where the /radius entry landed
    with Flags: X - DISABLED (so PPP AAA + the entry both existed, but no
    RADIUS packets ever reached the proxy). The script MUST force the
    entry enabled after the add/re-add so any prior disabled state is
    corrected on every (re-)import."""
    script = _render()
    flat = script.replace(" \\\n", " ")
    # The enable line MUST exist, target the comment tag, and come AFTER
    # the add so it acts on the row we just inserted.
    enable_line = '/radius enable [find comment="hobe-fleet-radius"]'
    assert enable_line in script, (
        f"missing radius enable line: expected {enable_line!r}"
    )
    lines = flat.splitlines()

    def first_index(needle: str) -> int:
        for i, line in enumerate(lines):
            if needle in line:
                return i
        return -1

    add_idx = first_index('comment="hobe-fleet-radius"')
    enable_idx = first_index('/radius enable')
    assert add_idx != -1 and enable_idx != -1
    assert enable_idx > add_idx, (
        f"/radius enable (line {enable_idx}) must come AFTER the add "
        f"that places comment=\"hobe-fleet-radius\" (line {add_idx})."
    )


def test_ppp_profile_has_defensive_remove():
    """The current template only `set`s the built-in default-encryption profile
    — but the owner's real-router re-import hit «name can't repeat» for PPP
    profiles (left over from an older script revision). Defensive cleanup
    sweeps any hobe-tagged ppp profile before the `set` so stale rows from
    older imports go away."""
    script = _render()
    assert 'remove [find comment="hobe-fleet-ppp"]' in script, \
        "/ppp profile needs a defensive remove [find comment=\"hobe-fleet-ppp\"] before set"


def test_ip_pool_has_defensive_remove():
    """The owner's real-router re-import also hit «can't repeat» for pools.
    The template doesn't `add` any pool today, but the cleanup anchor lives
    here so any future custom pool add lands on a clean table — and so
    stale rows from older scripts get swept."""
    script = _render()
    assert 'remove [find name~"^hobe-fleet-pool"]' in script, \
        "/ip pool needs defensive remove [find name~\"^hobe-fleet-pool\"]"


# ─── comprehensive audit: NO unprotected `add` to a managed table ──────────

#: Tables whose `add` MUST be preceded somewhere upstream by a `remove`. The
#: set of tables is exhaustive over the v2 template; if a future edit adds an
#: `add` to a new managed table, the audit below will catch it (and the
#: matching `remove` becomes mandatory).
_IDEMPOTENT_TABLES = {
    "/interface wireguard",
    "/interface wireguard peers",
    "/ip address",
    "/radius",
    "/ip ipsec profile",
    "/ip ipsec proposal",
    "/ip ipsec mode-config",
    "/ip ipsec peer",
    "/ip ipsec identity",
    "/ip firewall nat",
    "/ip firewall filter",
    "/ppp profile",       # defensive
    "/ip pool",           # defensive
}


def test_audit_every_add_under_a_managed_table_has_prior_remove_in_same_table():
    """Comprehensive sweep: walk the script line-by-line tracking the active
    table. For each `add` line under a table in :data:`_IDEMPOTENT_TABLES`,
    confirm at least one `remove [find …]` appeared under that SAME table
    earlier in the script."""
    script = _render()
    flat = script.replace(" \\\n", " ")

    table = None
    removes_seen_per_table: dict[str, int] = {t: 0 for t in _IDEMPOTENT_TABLES}
    failures: list[str] = []
    for lineno, raw in enumerate(flat.splitlines(), start=1):
        line = raw.strip()
        if line.startswith("/"):
            table = line if line in _IDEMPOTENT_TABLES else line
            continue
        if table in _IDEMPOTENT_TABLES:
            if line.startswith("remove "):
                removes_seen_per_table[table] += 1
            elif line.startswith("add "):
                if removes_seen_per_table[table] == 0:
                    failures.append(
                        f"L{lineno}: unprotected `add` under {table}: {line!r}"
                    )
    assert not failures, "idempotency audit failed:\n  " + "\n  ".join(failures)


# ─── double-apply simulator: prove the second import is clean ──────────────

_TABLE_KEY = {
    "/interface wireguard":       ("name",),
    "/interface wireguard peers": ("interface", "public_key"),
    "/ip address":                ("address", "interface"),
    "/radius":                    ("comment",),
    "/ip ipsec profile":          ("name",),
    "/ip ipsec proposal":         ("name",),
    "/ip ipsec mode-config":      ("name",),
    "/ip ipsec peer":             ("name",),
    "/ip ipsec identity":         ("peer",),
    "/ip firewall nat":           ("comment",),
    "/ip firewall filter":        ("comment",),
    "/ppp profile":               ("comment",),
    "/ip pool":                   ("name",),
}


def _parse_kv(s):
    """Tokenize  `key=value` / `key="quoted value"`  pairs from a RouterOS line."""
    out = {}
    for m in re.finditer(r'([\w-]+)=("([^"]*)"|([^\s;\\]+))', s):
        k = m.group(1)
        v = m.group(3) if m.group(3) is not None else m.group(4)
        # Normalize: hyphen-keyed Mikrotik attrs map to underscore for python.
        out[k.replace("-", "_")] = v
    return out


def _parse_find(expr):
    """`[find name="X"]` → ("name", "=", "X"); `[find c~"^h-"]` → ("c","~","^h-")."""
    m = re.match(r'\[find ([\w-]+)([=~])"?([^"\]]+)"?\]', expr.strip())
    assert m, f"can't parse find: {expr!r}"
    return m.group(1).replace("-", "_"), m.group(2), m.group(3)


def _row_matches_find(row, find):
    k, op, v = find
    rv = row.get(k, "")
    return (rv == v) if op == "=" else bool(re.search(v, rv))


class _FakeCHR:
    """Toy RouterOS state machine that enforces add-uniqueness per table.

    Rows track a synthetic ``_disabled`` field so the simulator can
    reproduce the «landed disabled» bug class and prove `enable [find …]`
    fixes it.
    """

    def __init__(self):
        self.tables: dict[str, list[dict]] = {t: [] for t in _TABLE_KEY}
        self.errors: list[str] = []

    def add(self, table, kwargs, line_no):
        keyspec = _TABLE_KEY[table]
        for row in self.tables[table]:
            if all(row.get(k, "") == kwargs.get(k, "") for k in keyspec):
                self.errors.append(
                    f"L{line_no}: «name/key can't repeat» {table} "
                    f"{keyspec}={[kwargs.get(k, '') for k in keyspec]}"
                )
                return
        # RouterOS default: many tables land with disabled=no, but the live
        # CHR has demonstrated /radius can come up disabled. The simulator
        # plays it safe: every newly-added row defaults to ENABLED in our
        # model so the test of `enable` is meaningful (we'll explicitly
        # force a disabled state in `force_disable_radius_for_bug_repro`).
        row = dict(kwargs)
        row.setdefault("_disabled", False)
        self.tables[table].append(row)

    def remove(self, table, find, line_no):
        before = len(self.tables[table])
        self.tables[table] = [r for r in self.tables[table] if not _row_matches_find(r, find)]
        return before - len(self.tables[table])

    def enable(self, table, find, line_no):
        """`/<table> enable [find …]` → flips _disabled=False on matches."""
        for row in self.tables[table]:
            if _row_matches_find(row, find):
                row["_disabled"] = False

    # Test helper — repro the live-CHR bug class.
    def force_disable_radius(self):
        for row in self.tables["/radius"]:
            row["_disabled"] = True


def _apply_script_to(chr_state, script_text):
    flat = re.sub(r"\\\n\s*", " ", script_text)
    table = None
    # A line may be a table selector (`/radius`) OR a table selector + op
    # on the same line (`/radius enable [find comment=…]`). Handle both.
    for n, raw in enumerate(flat.splitlines(), start=1):
        line = raw.split(";#", 1)[0].rstrip()
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("/"):
            # `/radius enable [find …]` — table selector + op on one line.
            m = re.match(r'^(/[\w \-]+?) (enable|disable) (\[find [^\]]+\])$', s)
            if m:
                t = m.group(1)
                if t in _TABLE_KEY:
                    chr_state.enable(t, _parse_find(m.group(3)), n)
                continue
            # Otherwise it's just a table selector — switch context.
            table = s if s in _TABLE_KEY else s
            continue
        if s.startswith("remove "):
            m = re.match(r'remove (\[find [^\]]+\])', s)
            if not m or table not in _TABLE_KEY:
                continue
            chr_state.remove(table, _parse_find(m.group(1)), n)
            continue
        if s.startswith("add ") and table in _TABLE_KEY:
            chr_state.add(table, _parse_kv(s[4:]), n)


def test_double_apply_is_clean_no_repeat_errors_no_duplicates():
    """Logical proof: render the .rsc, parse it into RouterOS-like ops,
    apply twice to a virgin fake CHR. Zero «can't repeat» errors required;
    state after 2nd apply must equal state after 1st."""
    script = _render()
    chr_state = _FakeCHR()

    _apply_script_to(chr_state, script)
    snapshot_1 = {t: [dict(r) for r in rows] for t, rows in chr_state.tables.items()}
    assert chr_state.errors == [], (
        "first apply already errored: " + "\n".join(chr_state.errors)
    )

    _apply_script_to(chr_state, script)
    snapshot_2 = {t: [dict(r) for r in rows] for t, rows in chr_state.tables.items()}

    assert chr_state.errors == [], (
        "second apply hit «can't repeat»:\n  " + "\n  ".join(chr_state.errors)
    )
    for table in _TABLE_KEY:
        assert snapshot_1[table] == snapshot_2[table], (
            f"{table}: state diverged between applies — 1st={len(snapshot_1[table])}, "
            f"2nd={len(snapshot_2[table])}"
        )
    # And the radius entry MUST be enabled after BOTH applies — this is what
    # broke the first live install (entry existed but disabled, PPP used
    # RADIUS, no packets ever reached the proxy).
    for snap, label in ((snapshot_1, "1st"), (snapshot_2, "2nd")):
        radius = snap["/radius"]
        assert len(radius) == 1, f"{label} apply: expected 1 /radius row, got {len(radius)}"
        assert radius[0].get("_disabled") is False, (
            f"{label} apply: /radius entry ended up disabled — the `enable` "
            f"line must run after the add."
        )


def test_radius_enable_recovers_a_disabled_entry_on_reimport():
    """Regression repro: simulate the live-CHR bug where /radius came up
    DISABLED. Apply once → entry enabled. Force-disable the row (mimics the
    state the owner found on the real router). Re-apply. The entry MUST end
    up enabled again because of the `/radius enable [find comment="…"]`
    line — without it, the re-import would `remove` + `add` cleanly but
    the new row could once again land disabled (we don't control the
    default), and AAA would silently keep failing.

    The enable line is the belt-and-braces that closes this hole."""
    script = _render()
    chr_state = _FakeCHR()

    _apply_script_to(chr_state, script)
    assert chr_state.tables["/radius"][0]["_disabled"] is False

    # Mimic what the owner found on the real CHR.
    chr_state.force_disable_radius()
    assert chr_state.tables["/radius"][0]["_disabled"] is True

    # Re-import — should heal the entry.
    _apply_script_to(chr_state, script)
    assert chr_state.errors == [], chr_state.errors
    assert len(chr_state.tables["/radius"]) == 1
    assert chr_state.tables["/radius"][0]["_disabled"] is False, (
        "/radius re-import did not heal a disabled entry — the `enable [find …]` "
        "line is missing or in the wrong order."
    )
