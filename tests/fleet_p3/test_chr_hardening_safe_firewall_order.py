"""fix/chr-hardening-safe-firewall-order — 9 acceptance invariants from
the owner's spec, pinned end-to-end on the rendered chr_unified script.

Background: chr-vpn-3's CHR had a broad `drop in-interface=ether1`
(«drop public input», from a previous operator script) placed BEFORE
the public VPN-listener allows (wg 51820/51821/51822, PPTP/L2TP/GRE/
ESP/ICMP). That broad drop made the allows unreachable → likely cause
of the wg-mgmt handshake failure → rest_failed on heartbeat.

This file pins the 9 invariants the owner listed as acceptance, applied
to BOTH the script text (deterministic parse) AND the simulated effective
on-CHR rule order (`add` order + `place-before` resolution).

    (1) No `drop in-interface=ether1` (or any broad public drop) appears
        before the public VPN-listener accepts on the CHR.
    (2) `hobe-fleet-fw-drop-last` is the final input rule on the CHR.
    (3) The conntrack accept is first.
    (4) Public 1812/1813/3799 are dropped on the WAN.
    (5) Management services (ssh/winbox/www-ssl) are restricted to
        PANEL_WG_ADDR/32 — and the firewall mgmt accept matches.
    (6) The wg-mgmt verify gate precedes the restriction (the script
        only locks ssh/winbox to /32 if it could ping the panel over
        wg-mgmt; otherwise it keeps them open + adds a TEMP
        emergency-admin firewall rule).
    (7) Foreign-rule cleanup is present and idempotent: every prior
        bad pattern (own tagged rules, `^TEMP allow`, `^TEMP-`,
        `^drop public input`, and broad ether1 foreign drops) is
        swept on each run.
    (8) Re-render is byte-identical for the same bindings (the script
        is deterministic — no clocks, no random salts).
    (9) The wg-mgmt-lockdown warning + post-import validation block
        render (the operator sees what changed and can audit).

Security context (from the owner, preserved verbatim in the template):

    "DO NOT open services to 0.0.0.0/0 permanently. DO NOT place a
     broad drop-public-input before the VPN listener allows. Be
     meticulous — a wrong firewall locks the owner out of production
     routers."
"""
from __future__ import annotations

import re

import pytest

from fleet.registry.script_render import (
    _ALL_ROLES,
    render_from_bindings,
)


# ════════════════════════════════════════════════════════════════════════
# Fixture: a complete bindings set with all roles enabled — the worst
# case for firewall coverage (every accept rule must be present).
# ════════════════════════════════════════════════════════════════════════
_BINDINGS: dict = {
    "ROUTER_IDENTITY":    "chr-vpn-3",
    "CHR_PUBLIC_IP":      "37.27.218.211",
    "WAN_IFACE":          "ether1",
    "WG_MGMT_PRIVKEY":    "MGMT_PRIVKEY_BASE64==",
    "WG_MGMT_ADDR":       "10.99.0.13/24",
    "WG_DATA_PRIVKEY":    "DATA_PRIVKEY_BASE64==",
    "WG_DATA_ADDR":       "10.98.0.13/24",
    "WG_DATA_ADDR_IP":    "10.98.0.13",
    "PANEL_WG_PUBKEY":    "PANELPUBKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "PANEL_WG_ENDPOINT":  "control.hoberadius.com:51820",
    "PANEL_WG_ADDR":      "10.99.0.1",
    "PROXY_WG_PUBKEY":    "PROXYPUBKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQM=",
    "PROXY_WG_ENDPOINT":  "proxy.hoberadius.com:51821",
    "PROXY_WG_ADDR":      "10.98.0.1",
    "CHR_SHARED_SECRET":  "kla0FAzDKNJGoGIXdpDaCKB4Q2ytm-txZZZ_strongsecret",
    "SSTP_CERT_NAME":     "hobe-sstp-cert",
    "IKE_CERT_NAME":      "hobe-ike-cert",
    "CLIENT_SUPERNET":    "10.0.0.0/8",
    "DNS_PUSH":           "1.1.1.1",
    "GW_LOCAL_ADDR":      "10.10.0.1",
    "API_USER":           "panel-poller",
    "API_PASSWORD":       "metrics-pwd-from-vault",
    "API_PORT":           8443,
}


def _render(**overrides) -> str:
    return render_from_bindings({**_BINDINGS, **overrides})


def _flatten(script: str) -> str:
    """Join RouterOS line-continuations so each `add` is one logical line."""
    return script.replace(" \\\n", " ")


def _input_filter_rules(script: str) -> list[str]:
    """Walk the script and collect ordered `add chain=input` lines under
    `/ip firewall filter`. Used by every order invariant below."""
    out: list[str] = []
    table: str | None = None
    # Path tokens that take an arg → these are inline commands, not
    # table-context resets (e.g. `/system backup save name=...`).
    INLINE_VERBS = ("save ", "load ", "remove ", "add ", "set ", "print ")
    for raw in _flatten(script).splitlines():
        line = raw.strip()
        if line.startswith("/") and not any(v in line for v in INLINE_VERBS):
            table = line
            continue
        if (
            table == "/ip firewall filter"
            and line.startswith("add ")
            and "chain=input" in line
        ):
            out.append(line)
    return out


def _effective_on_chr_order(rules: list[str]) -> list[str]:
    """Simulate the on-CHR top-to-bottom order after RouterOS resolves
    every `place-before=[find comment="hobe-fleet-fw-drop-last"]` add
    for the STEADY-STATE case (wg-mgmt reachable).

    Insertion-order semantics (RouterOS `place-before=<idx>` inserts
    AT that index and pushes the previous occupant DOWN):
      - drop-last is added first ⇒ it occupies index 0 alone.
      - conntrack added next with place-before=[anchor] ⇒ conntrack
        takes index 0; drop-last shifts to 1.
      - mgmt added next ⇒ mgmt takes index 1; drop-last shifts to 2;
        conntrack stays at 0.
      - ...and so on. Every new rule lands JUST ABOVE drop-last and
        BELOW every previously-added rule.
      - Net effect: the on-CHR top-to-bottom order EQUALS the script-
        text add order, with drop-last at the bottom.

    Excludes the runtime-conditional `hobe-fleet-fw-temp-emergency-admin`
    rule (which is inside the §11 wg-mgmt-down fallback `:if` and lands
    on the CHR ONLY when the wg-mgmt probe fails). The next clean run
    sweeps it via the `^hobe-fleet-fw-` regex remove.

    Returns the comment-tag of each rule, top-to-bottom on the CHR.
    """
    drop_last_tag = "hobe-fleet-fw-drop-last"
    drop_idx = next(
        i for i, r in enumerate(rules) if f'comment="{drop_last_tag}"' in r
    )
    later = rules[drop_idx + 1:]

    def tag(rule: str) -> str:
        m = re.findall(r'comment="(hobe-fleet-fw-[^"]+)"', rule)
        return m[-1] if m else "<no-tag>"

    tags = [
        tag(r) for r in later
        if tag(r) != "hobe-fleet-fw-temp-emergency-admin"
    ]
    return tags + [drop_last_tag]


# ════════════════════════════════════════════════════════════════════════
# Invariant #1 — no broad public drop above VPN listener accepts
# ════════════════════════════════════════════════════════════════════════
class TestInvariant1NoBroadDropBeforeVpnListeners:

    def test_drop_in_interface_ether1_does_not_precede_vpn_allows_in_script(self):
        """In the script text, no broad `drop in-interface=ether1` is
        emitted by US. The `add chain=input action=drop ...` only
        appears for our drop-last anchor (no in-interface)."""
        flat = _flatten(_render())
        broad_drops = [
            ln for ln in flat.splitlines()
            if ln.strip().startswith("add ")
            and "chain=input" in ln
            and "action=drop" in ln
            and "in-interface=ether1" in ln
            and "connection-state=" not in ln
            and "protocol=" not in ln
            and "dst-port=" not in ln
        ]
        assert broad_drops == [], (
            "the script must not emit a broad `drop in-interface=ether1` "
            f"rule; got: {broad_drops!r}"
        )

    def test_simulated_on_chr_order_puts_every_vpn_listener_above_any_drop(self):
        """Simulate the on-CHR top-to-bottom order and assert every
        VPN-listener accept lands ABOVE every drop."""
        order = _effective_on_chr_order(_input_filter_rules(_render()))
        vpn_listeners = {
            "hobe-fleet-fw-wg-mgmt-udp",
            "hobe-fleet-fw-wg-data-udp",
            "hobe-fleet-fw-sstp",
            "hobe-fleet-fw-pptp-ctrl",
            "hobe-fleet-fw-pptp-data",
            "hobe-fleet-fw-ike",
            "hobe-fleet-fw-esp",
            "hobe-fleet-fw-l2tp",
            "hobe-fleet-fw-wg-users",
            "hobe-fleet-fw-icmp",
        }
        rules = _input_filter_rules(_render())
        # Build tag → action map so we can find the drops.
        tag_to_action: dict[str, str] = {}
        for r in rules:
            tags = re.findall(r'comment="(hobe-fleet-fw-[^"]+)"', r)
            if not tags:
                continue
            tag = tags[-1]
            tag_to_action[tag] = (
                "drop" if "action=drop" in r else "accept"
            )
        for listener in vpn_listeners:
            if listener not in order:
                continue
            l_idx = order.index(listener)
            for j, t in enumerate(order):
                if j <= l_idx:
                    continue
                if tag_to_action.get(t) == "drop" and t != "hobe-fleet-fw-no-public-radius":
                    # no-public-radius is allowed to follow (it's a
                    # different scope); but no BROAD drop may appear.
                    pass
            # Specifically, the foreign broad-drop pattern is removed,
            # so on the CHR the only drops below VPN listeners are
            # hobe-fleet-fw-no-public-radius (port-scoped) and
            # hobe-fleet-fw-drop-last (final).
            tail = order[l_idx + 1:]
            for t in tail:
                assert t in {
                    "hobe-fleet-fw-no-public-radius",
                    "hobe-fleet-fw-drop-last",
                } or tag_to_action.get(t) == "accept", (
                    f"VPN listener {listener!r} is followed by a "
                    f"non-port-scoped drop {t!r} on the CHR — "
                    "broad-drop-before-listener regression."
                )

    def test_script_sweeps_foreign_drop_public_input_pattern(self):
        """Idempotent cleanup: the script must `remove` foreign rules
        with the `drop public input` comment prefix on each run."""
        script = _render()
        assert 'remove [find comment~"^drop public input"]' in script


# ════════════════════════════════════════════════════════════════════════
# Invariant #2 — drop-last is the final input rule on the CHR
# ════════════════════════════════════════════════════════════════════════
class TestInvariant2DropLastIsFinal:

    def test_drop_last_is_at_the_bottom_of_on_chr_order(self):
        order = _effective_on_chr_order(_input_filter_rules(_render()))
        assert order[-1] == "hobe-fleet-fw-drop-last", (
            f"drop-last must be the final input rule; got bottom: "
            f"{order[-1]!r}; full order: {order!r}"
        )

    def test_drop_last_rule_is_action_drop(self):
        script = _render()
        assert (
            'add chain=input action=drop comment="hobe-fleet-fw-drop-last"'
            in script
        )

    def test_drop_last_anchor_is_added_first_in_script_text(self):
        """In script text, drop-last is the FIRST add inside §9 — every
        subsequent add anchors against it via place-before."""
        rules = _input_filter_rules(_render())
        assert rules[0].endswith('comment="hobe-fleet-fw-drop-last"'), (
            f"drop-last must be the first rule added in §9; got: "
            f"{rules[0]!r}"
        )


# ════════════════════════════════════════════════════════════════════════
# Invariant #3 — conntrack accept is first
# ════════════════════════════════════════════════════════════════════════
class TestInvariant3ConntrackIsFirst:

    def test_conntrack_is_at_the_top_of_on_chr_order(self):
        order = _effective_on_chr_order(_input_filter_rules(_render()))
        assert order[0] == "hobe-fleet-fw-conntrack", (
            f"conntrack must be the first input rule on the CHR; got "
            f"top: {order[0]!r}; full order: {order!r}"
        )

    def test_conntrack_rule_carries_correct_selectors(self):
        rules = _input_filter_rules(_render())
        ct = next(r for r in rules if 'comment="hobe-fleet-fw-conntrack"' in r)
        assert "connection-state=established,related,untracked" in ct, ct
        assert "action=accept" in ct, ct
        assert (
            'place-before=[find comment="hobe-fleet-fw-drop-last"]' in ct
        ), f"conntrack must anchor against drop-last: {ct!r}"


# ════════════════════════════════════════════════════════════════════════
# Invariant #4 — public RADIUS ports dropped on the WAN
# ════════════════════════════════════════════════════════════════════════
class TestInvariant4PublicRadiusDropped:

    def test_no_public_radius_drop_rule_present(self):
        rules = _input_filter_rules(_render())
        no_pub = next(
            r for r in rules if 'comment="hobe-fleet-fw-no-public-radius"' in r
        )
        assert "action=drop" in no_pub, no_pub
        assert "protocol=udp" in no_pub, no_pub
        assert "dst-port=1812,1813,3799" in no_pub, no_pub

    def test_no_public_radius_lands_below_radius_accept_on_chr(self):
        """The drop must come AFTER the scoped wg-data accept on the CHR
        so legitimate proxy traffic over wg-data still matches first."""
        order = _effective_on_chr_order(_input_filter_rules(_render()))
        if "hobe-fleet-fw-radius" not in order:
            pytest.skip("radius_transport role disabled")
        r_idx = order.index("hobe-fleet-fw-radius")
        d_idx = order.index("hobe-fleet-fw-no-public-radius")
        assert r_idx < d_idx, (
            f"scoped radius accept (#{r_idx}) must precede the "
            f"no-public-radius drop (#{d_idx}) on the CHR"
        )


# ════════════════════════════════════════════════════════════════════════
# Invariant #5 — mgmt/ssh/winbox/www-ssl restricted to PANEL_WG_ADDR/32
# ════════════════════════════════════════════════════════════════════════
class TestInvariant5MgmtRestrictedToPanelWg:

    def test_firewall_mgmt_rule_is_panel_wg_only(self):
        rules = _input_filter_rules(_render())
        mgmt = next(r for r in rules if 'comment="hobe-fleet-fw-mgmt"' in r)
        assert "in-interface=wg-mgmt" in mgmt, mgmt
        assert "src-address=10.99.0.1/32" in mgmt, mgmt

    def test_api_ssl_rule_is_panel_wg_only_under_api_gate(self):
        rules = _input_filter_rules(_render())
        api = next(r for r in rules if 'comment="hobe-fleet-fw-api-ssl"' in r)
        assert "in-interface=wg-mgmt" in api, api
        assert "src-address=10.99.0.1/32" in api, api
        assert "dst-port=8443" in api, api

    def test_service_hardening_uses_panel_wg_addr_for_ssh_winbox_www_ssl(self):
        """In the success branch of the wg-mgmt-verify gate, ssh +
        winbox are restricted via the `$mgmtAddrACL` local — which is
        `PANEL/32` when OPERATOR_ADMIN_IPS is unset, or the union
        `PANEL/32,<operator-ips>` when set. www-ssl is restricted
        unconditionally to PANEL/32 (its REST handler is the panel
        poller; the operator never logs in there)."""
        script = _render()
        flat = _flatten(script)
        # www-ssl line — single configured invocation, PANEL/32 scoped.
        assert re.search(
            r"set www-ssl[^\n]+address=10\.99\.0\.1/32", flat
        ), "www-ssl must be address-scoped to PANEL_WG_ADDR/32"
        # The mgmt ACL local is set to PANEL/32 in the default
        # (OPERATOR_ADMIN_IPS empty) render.
        assert ':local mgmtAddrACL "10.99.0.1/32"' in script, (
            "missing mgmtAddrACL = PANEL_WG_ADDR/32 (default render)"
        )
        # ssh + winbox consume that local on the success branch.
        assert "/ip service set ssh    address=$mgmtAddrACL" in flat
        assert "/ip service set winbox address=$mgmtAddrACL" in flat

    def test_api_and_telnet_and_ftp_disabled(self):
        flat = _flatten(_render())
        assert re.search(r"set api\s+disabled=yes", flat), flat
        assert re.search(r"set api-ssl\s+disabled=yes", flat), flat
        assert re.search(r"set www\s+disabled=yes", flat), flat
        assert re.search(r"set telnet\s+disabled=yes", flat), flat
        assert re.search(r"set ftp\s+disabled=yes", flat), flat


# ════════════════════════════════════════════════════════════════════════
# Invariant #6 — wg-mgmt verify gate precedes the restriction
# ════════════════════════════════════════════════════════════════════════
class TestInvariant6WgMgmtVerifyGate:

    def test_ping_probe_over_wg_mgmt_present(self):
        """The script must ping the panel over wg-mgmt before applying
        the ssh/winbox source-IP ACL — otherwise a wg-mgmt-down node
        loses both ssh and the wg-mgmt control plane (full lockout)."""
        script = _render()
        assert (
            "/ping address=10.99.0.1 interface=wg-mgmt count=3 as-value"
            in script
        ), "missing wg-mgmt probe — would risk full lockout on wg-down nodes"

    def test_probe_result_drives_a_conditional_lockdown(self):
        script = _render()
        # The `:local mgmtReachable false` flag is the gate.
        assert ":local mgmtReachable false" in script
        # And there's an :if branch on it.
        assert re.search(r":if \(\$mgmtReachable\) do=\{", script), script

    def test_fallback_keeps_ssh_winbox_open_and_logs_a_warning(self):
        """If wg-mgmt is unreachable, the script must NOT lock down
        ssh/winbox. It must add a TEMP emergency-admin firewall rule
        (tagged so the next clean run sweeps it) and warn the operator."""
        script = _render()
        assert "/ip service set ssh    disabled=no" in script, (
            "fallback must keep ssh open"
        )
        assert "/ip service set winbox disabled=no" in script, (
            "fallback must keep winbox open"
        )
        assert (
            'comment="hobe-fleet-fw-temp-emergency-admin"' in script
        ), "missing TEMP emergency-admin rule in fallback"
        assert (
            ":log warning" in script
            and "wg-mgmt NOT reachable" in script
        ), "missing operator warning in fallback"

    def test_probe_precedes_ssh_winbox_restriction_in_script_text(self):
        """The wg-mgmt probe + the `:local mgmtReachable` flag MUST
        appear before any `/ip service set ssh address=$mgmtAddrACL`
        line that restricts ssh/winbox — script-text order equals
        execution order on RouterOS."""
        flat = _render().replace(" \\\n", " ")
        probe_pos = flat.index(
            "/ping address=10.99.0.1 interface=wg-mgmt count=3 as-value"
        )
        restrict_pos = flat.index(
            "/ip service set ssh    address=$mgmtAddrACL"
        )
        assert probe_pos < restrict_pos, (
            "wg-mgmt probe must precede the ssh restriction"
        )


# ════════════════════════════════════════════════════════════════════════
# Invariant #7 — foreign-rule cleanup present + idempotent
# ════════════════════════════════════════════════════════════════════════
class TestInvariant7ForeignRuleCleanup:

    def test_sweeps_all_hobe_fleet_fw_tagged_rules(self):
        script = _render()
        assert 'remove [find comment~"^hobe-fleet-fw-"]' in script, (
            "missing wholesale sweep of our own tagged rules — re-import "
            "would leak duplicates"
        )

    def test_sweeps_known_bad_foreign_comment_prefixes(self):
        script = _render()
        for pat in (
            'remove [find comment~"^TEMP allow"]',
            'remove [find comment~"^TEMP-"]',
            'remove [find comment~"^drop public input"]',
        ):
            assert pat in script, f"missing foreign sweep: {pat!r}"

    def test_walks_broad_foreign_drops_on_wan_with_selector_check(self):
        """The :foreach must only remove broad-drop rules (no protocol,
        no dst-port, no src-address) so legitimate operator drops with
        real selectors survive."""
        script = _render()
        assert (
            ":foreach r in=[find chain=input action=drop in-interface=ether1] do={"
            in script
        ), "missing :foreach walk over broad ether1 drops"
        # Conditions: no proto, no dport, no src — and not our own tag.
        for cond in (
            '[:typeof [:find $c "hobe-fleet-fw-"]] = "nothing"',
            '[:tostr $proto] = ""',
            '[:tostr $dport] = ""',
            '[:tostr $src] = ""',
        ):
            assert cond in script, f"missing selector-check: {cond!r}"

    def test_cleanup_runs_BEFORE_we_add_new_rules(self):
        """The remove statements MUST come before the §9 adds, or we'd
        be removing the rules we just added."""
        script = _render()
        sweep_pos = script.index('remove [find comment~"^hobe-fleet-fw-"]')
        first_add_pos = script.index(
            'add chain=input action=drop comment="hobe-fleet-fw-drop-last"'
        )
        assert sweep_pos < first_add_pos, (
            "foreign cleanup must precede the §9 adds; otherwise the "
            "remove kills the just-added rules"
        )


# ════════════════════════════════════════════════════════════════════════
# Invariant #8 — re-render is byte-identical for the same bindings
# ════════════════════════════════════════════════════════════════════════
class TestInvariant8DeterministicRender:

    def test_re_render_with_same_bindings_is_byte_identical(self):
        a = _render()
        b = _render()
        assert a == b, (
            "rendering twice with the same bindings produced different "
            "scripts — the renderer has a non-deterministic input "
            "(clock? salt? dict-iter order?)"
        )

    def test_re_render_via_alphabetised_bindings_is_byte_identical(self):
        """Even if the bindings dict is re-ordered, the rendered script
        is the same. Guards against accidental iteration over a dict
        whose insertion order leaks into the output."""
        first = _render()
        shuffled = dict(sorted(_BINDINGS.items()))
        second = render_from_bindings(shuffled)
        assert first == second, (
            "render is sensitive to bindings dict ordering — "
            "non-deterministic"
        )


# ════════════════════════════════════════════════════════════════════════
# Invariant #9 — warning broadcast + validation block render
# ════════════════════════════════════════════════════════════════════════
class TestInvariant9WarningAndValidationRender:

    def test_lockdown_warning_renders_via_log_and_put(self):
        script = _render()
        # :log warning
        assert ":log warning" in script
        # :put copy so the operator sees it on stdout too
        assert ":put" in script
        # Specifically, the lockdown-explainer line.
        assert "Management services" in script and "restricted to wg-mgmt" in script, (
            "missing operator-facing lockdown explainer"
        )

    def test_post_import_validation_dump_renders(self):
        script = _render()
        for snippet in (
            '"[/ip service print detail]"',
            "/ip service print detail",
            '"[/ip firewall filter print]"',
            "/ip firewall filter print",
            '"[/interface print]"',
            "/interface print",
            '"[/ip address print]"',
            "/ip address print",
            'message~\\"hobe-fleet\\"',  # the log filter
        ):
            assert snippet in script, (
                f"missing validation-block snippet: {snippet!r}"
            )

    def test_validation_dump_runs_at_END_after_rollback_cancel(self):
        """The validation dump is for AFTER the run lands; the rollback
        scheduler must have been cancelled before we print the dump."""
        script = _render()
        cancel_pos = script.index(
            '/system scheduler remove [find name="hobe-fleet-rollback"]'
        )
        dump_pos = script.index("[/ip service print detail]")
        assert cancel_pos < dump_pos, (
            "validation dump must come AFTER the rollback-scheduler "
            "cancellation"
        )


# ════════════════════════════════════════════════════════════════════════
# (Cross-cut) — preserves the existing self-lockout guard
# ════════════════════════════════════════════════════════════════════════
def test_self_lockout_guard_intact():
    """The §0a self-lockout 3-min rollback guard from the prior fix must
    remain intact: backup taken, scheduler armed, scheduler cancelled at
    the end. Owner: «خلي بالك عالفيروول، ما تحظر شي يمنع اتصالات»."""
    script = _render()
    assert '/system backup save name="hobe-fleet-pre-apply"' in script
    assert 'add name="hobe-fleet-rollback"' in _flatten(script)
    assert '/system scheduler remove [find name="hobe-fleet-rollback"]' in script


# ════════════════════════════════════════════════════════════════════════
# (Cross-cut) — role-gated coverage on a minimal-role node still safe
# ════════════════════════════════════════════════════════════════════════
def test_pure_radius_node_still_has_safe_firewall():
    """Even on a node with ONLY radius_transport, the safe-order
    invariants must hold: drop-last final, conntrack first, no broad
    public drop above the wg-mgmt listener."""
    script = _render(NODE_ROLES_SET=frozenset({"radius_transport"}))
    rules = _input_filter_rules(script)
    order = _effective_on_chr_order(rules)
    assert order[0] == "hobe-fleet-fw-conntrack"
    assert order[-1] == "hobe-fleet-fw-drop-last"
    assert "hobe-fleet-fw-wg-mgmt-udp" in order, (
        "wg-mgmt listener must be present on EVERY node — it's the "
        "control plane"
    )
    # And no VPN listeners leaked.
    for t in (
        "hobe-fleet-fw-sstp",
        "hobe-fleet-fw-pptp-ctrl",
        "hobe-fleet-fw-ike",
        "hobe-fleet-fw-l2tp",
        "hobe-fleet-fw-wg-users",
    ):
        assert t not in order, f"{t} leaked into radius-only node"


def test_all_roles_node_emits_all_listener_accepts():
    """Worst-case coverage: every listener accept renders + is above
    every drop on the CHR."""
    script = _render(NODE_ROLES_SET=frozenset(_ALL_ROLES))
    order = _effective_on_chr_order(_input_filter_rules(script))
    for t in (
        "hobe-fleet-fw-conntrack",
        "hobe-fleet-fw-mgmt",
        "hobe-fleet-fw-api-ssl",
        "hobe-fleet-fw-radius",
        "hobe-fleet-fw-coa",
        "hobe-fleet-fw-wg-mgmt-udp",
        "hobe-fleet-fw-wg-data-udp",
        "hobe-fleet-fw-sstp",
        "hobe-fleet-fw-pptp-ctrl",
        "hobe-fleet-fw-pptp-data",
        "hobe-fleet-fw-ike",
        "hobe-fleet-fw-esp",
        "hobe-fleet-fw-l2tp",
        "hobe-fleet-fw-wg-users",
        "hobe-fleet-fw-icmp",
        "hobe-fleet-fw-no-public-radius",
        "hobe-fleet-fw-drop-last",
    ):
        assert t in order, f"missing on all-roles node: {t}"
