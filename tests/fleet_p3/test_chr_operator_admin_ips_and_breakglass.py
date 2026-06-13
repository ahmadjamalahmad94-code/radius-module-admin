"""fix/chr-hardening-safe-firewall-order — owner refinements pinned:

  (1) MANUAL ACCESS guarantee — WinBox/SSH must never be hard-locked:
        (a) Optional `OPERATOR_ADMIN_IPS` panel binding. When set, the
            script emits a SCOPED accept for tcp:22,8291 on the WAN
            from those CIDRs AND unions the `/ip service ssh + winbox`
            `address=` ACL with `PANEL_WG_ADDR/32,<operator-ips>`.
            NEVER 0.0.0.0/0 — the panel validator rejects it.
        (b) BREAK-GLASS provider-console scripts:
              `/system script add name="hobe-open-winbox"` — temporarily
                widens WinBox + adds a tagged break-glass firewall
                accept + schedules `hobe-close-winbox-auto` to revert
                in 15 min.
              `/system script add name="hobe-close-winbox"` — restores
                the hardened ACL immediately. The post-import
                validation block documents the recovery path so the
                operator sees it on every import.

  (2) CLEAN-BEFORE-WRITE everywhere — for the input chain we own, the
      script does a CLEAN REBUILD: `remove [find chain=input]` first,
      then re-emit the authoritative ordered set. forward + output
      chains are not touched; only our own tagged rules in `nat` are
      removed-by-comment in §8.

These are the acceptance tests for both refinements + the break-glass
documentation. They run on the rendered script text (StrictUndefined
catches any missing binding).

Owner brief (Arabic):
    «لازم أقدر أفوت ع WinBox، مش ينمنع خالص»
    «لازم يكون في طريقة دخول يدوي للـWinBox»
    «لازم السكربت ينظف أي شي قبله — طالما بده يكتب بمكان، ينظف قبل ما يكتب»
"""
from __future__ import annotations

import re

import pytest

from fleet.registry.script_render import render_from_bindings


_BASE: dict = {
    "ROUTER_IDENTITY":    "chr-vpn-3",
    "CHR_PUBLIC_IP":      "37.27.218.211",
    "WAN_IFACE":          "ether1",
    "WG_MGMT_PRIVKEY":    "MGMT==",
    "WG_MGMT_ADDR":       "10.99.0.13/24",
    "WG_DATA_PRIVKEY":    "DATA==",
    "WG_DATA_ADDR":       "10.98.0.13/24",
    "WG_DATA_ADDR_IP":    "10.98.0.13",
    "PANEL_WG_PUBKEY":    "P=",
    "PANEL_WG_ENDPOINT":  "control.hoberadius.com:51820",
    "PANEL_WG_ADDR":      "10.99.0.1",
    "PROXY_WG_PUBKEY":    "X=",
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
    return render_from_bindings({**_BASE, **overrides})


def _flat(script: str) -> str:
    return script.replace(" \\\n", " ")


# ════════════════════════════════════════════════════════════════════════
# (a) OPERATOR_ADMIN_IPS — firewall scoped accept + service address union
# ════════════════════════════════════════════════════════════════════════
class TestOperatorAdminIpsSet:
    """When OPERATOR_ADMIN_IPS is non-empty the rendered script must:

      1. emit `hobe-fleet-fw-operator-admin` — a scoped accept for
         tcp:22,8291 on WAN_IFACE from those CIDRs.
      2. union the `/ip service ssh + winbox` `address=` ACL with
         `PANEL_WG_ADDR/32,<operator-ips>` so the listeners themselves
         accept those sources.
      3. apply the union UNCONDITIONALLY of wg-mgmt reachability
         (because the owner's IP is the safety net — wg-mgmt-only is
         not the only path anymore).
      4. NEVER include 0.0.0.0/0 anywhere in the hardened set.
    """

    IPS = "1.2.3.4/32,5.6.7.0/24"

    def test_operator_admin_firewall_rule_renders_with_correct_selectors(self):
        script = _render(OPERATOR_ADMIN_IPS=self.IPS)
        flat = _flat(script)
        rule = next(
            (ln for ln in flat.splitlines()
             if ln.lstrip().startswith("add ")
             and 'comment="hobe-fleet-fw-operator-admin"' in ln),
            None,
        )
        assert rule, "hobe-fleet-fw-operator-admin firewall rule missing"
        assert "chain=input" in rule
        assert "in-interface=ether1" in rule
        assert f"src-address={self.IPS}" in rule, (
            f"operator-admin rule must src-ACL to OPERATOR_ADMIN_IPS verbatim; "
            f"got: {rule!r}"
        )
        assert "protocol=tcp" in rule
        assert "dst-port=22,8291" in rule
        assert "action=accept" in rule
        # Anchored to drop-last like every other §9 rule.
        assert 'place-before=[find comment="hobe-fleet-fw-drop-last"]' in rule

    def test_service_address_acl_is_panel_plus_operator_union(self):
        script = _render(OPERATOR_ADMIN_IPS=self.IPS)
        # The template builds :local mgmtAddrACL "<panel>/32,<operator-ips>"
        # and then `set ssh|winbox address=$mgmtAddrACL` consumes it.
        assert (
            f':local mgmtAddrACL "10.99.0.1/32,{self.IPS}"' in script
        ), "missing wg-mgmt+operator UNION ACL local"
        # Both setters refer to that local.
        assert "/ip service set ssh    address=$mgmtAddrACL" in script
        assert "/ip service set winbox address=$mgmtAddrACL" in script

    def test_acl_applied_unconditional_of_wg_mgmt_state_when_operator_ips_set(self):
        """When the operator-IP escape hatch is set, the script must
        skip the verify-then-restrict branching and just apply the
        union ACL — wg-mgmt-down can no longer lock the owner out."""
        script = _render(OPERATOR_ADMIN_IPS=self.IPS)
        # The «no-temp-emergency-needed» branch carries this info-log line.
        assert 'wg-mgmt reachable; ssh+winbox ACL = ' in script
        assert 'wg-mgmt NOT reachable yet, but operator-IP allow is set' in script
        # And the temp-emergency add must NOT appear in the OPERATOR_ADMIN_IPS-set branch
        # (the operator-IP accept emitted in §9 covers it). The
        # `hobe-fleet-fw-temp-emergency-admin` add is gated by the
        # `{% else %}` Jinja branch, so it must NOT render here.
        # We assert by checking that the §11 add of temp-emergency is absent.
        emerge_add_re = re.compile(
            r'\n\s+add chain=input action=accept protocol=tcp dst-port=22,8291\s+\\\n'
            r'\s+place-before=\[find comment="hobe-fleet-fw-drop-last"\]\s+\\\n'
            r'\s+comment="hobe-fleet-fw-temp-emergency-admin"',
        )
        assert not emerge_add_re.search(script), (
            "temp-emergency-admin rule must NOT render when "
            "OPERATOR_ADMIN_IPS is set (the operator-IP accept covers it)"
        )

    def test_acl_never_contains_zero_zero(self):
        """0.0.0.0/0 must NEVER appear in the HARDENED service ACL or
        in the operator-admin firewall rule.

        The break-glass `hobe-open-winbox` script body DOES use
        0.0.0.0/0 intentionally — that's the recovery widening, and
        it's bounded by the 15-min auto-revert. We accept that;
        what we forbid is `0.0.0.0/0` at the steady-state apply
        level (the top-level `/ip service set ...` and the
        operator-admin firewall rule), which is what gets configured
        on a CHR after a normal import."""
        script = _render(OPERATOR_ADMIN_IPS=self.IPS)
        flat = _flat(script)
        # Operator-admin rule must not carry 0.0.0.0/0.
        operator_rule = next(
            ln for ln in flat.splitlines()
            if 'comment="hobe-fleet-fw-operator-admin"' in ln
        )
        assert "0.0.0.0/0" not in operator_rule
        # The mgmtAddrACL local must not be 0/0.
        assert ':local mgmtAddrACL "0.0.0.0/0"' not in script
        # Steady-state apply lines use `$mgmtAddrACL` (the local set above);
        # lines INSIDE the break-glass `source=` string literal carry an
        # escaped literal address (`\"0.0.0.0/0\"`) and a trailing `\n\`
        # continuation marker — those are the break-glass body, runtime-
        # only, gated on operator invocation. Filter them out by the
        # escaped-quote signature, then assert no 0/0 remains.
        for set_line in script.splitlines():
            if not (
                "/ip service set ssh" in set_line
                or "/ip service set winbox" in set_line
            ):
                continue
            if 'address=\\"' in set_line:
                # break-glass source body — not the steady-state apply line
                continue
            assert "0.0.0.0/0" not in set_line, (
                f"steady-state service ACL must not be 0.0.0.0/0: "
                f"{set_line!r}"
            )
            # The steady-state lines should use the variable, not a literal.
            assert "address=$mgmtAddrACL" in set_line, (
                f"steady-state service ACL must consume $mgmtAddrACL "
                f"(the panel+operator union); got: {set_line!r}"
            )


class TestOperatorAdminIpsUnset:
    """When OPERATOR_ADMIN_IPS is empty (default) the prior verify-then-
    restrict behaviour stands: try wg-mgmt; if down, keep ssh/winbox
    open + temp-emergency rule + warning."""

    def test_operator_admin_firewall_rule_does_not_render(self):
        script = _render()
        assert "hobe-fleet-fw-operator-admin" not in script, (
            "operator-admin rule must NOT render when OPERATOR_ADMIN_IPS is empty"
        )

    def test_acl_local_is_panel_only(self):
        script = _render()
        assert ':local mgmtAddrACL "10.99.0.1/32"' in script
        # And no operator-IP suffix.
        assert ':local mgmtAddrACL "10.99.0.1/32,' not in script

    def test_temp_emergency_rule_still_present_in_fallback(self):
        script = _render()
        # The fallback branch must still add the temp-emergency rule
        # when wg-mgmt is down.
        assert 'comment="hobe-fleet-fw-temp-emergency-admin"' in script

    def test_warning_mentions_break_glass_recovery(self):
        """The operator-facing print/log must point at the break-glass
        recovery path so an oncall person knows what to do."""
        script = _render()
        assert "hobe-open-winbox" in script, (
            "wg-mgmt-only warning must mention the break-glass script"
        )
        assert "VPS" in script and "console" in script.lower(), (
            "warning must mention the VPS console as the recovery path"
        )


# ════════════════════════════════════════════════════════════════════════
# (b) BREAK-GLASS — /system script items render correctly
# ════════════════════════════════════════════════════════════════════════
class TestBreakGlassScripts:
    """Two named RouterOS script items provisioned on every CHR:

      `hobe-open-winbox`  — temporarily widen winbox + ssh, add tagged
                            firewall accept, schedule auto-revert.
      `hobe-close-winbox` — re-restrict immediately (or fire on
                            schedule).

    Both are managed ADD-OR-SET by name (idempotent on re-import).
    They're tagged `hobe-fleet-break-glass` so a future sweep can find
    them, and bound to the mgmt policy set."""

    def test_open_and_close_scripts_render_always(self):
        for ips in ("", "1.2.3.4/32"):
            script = _render(OPERATOR_ADMIN_IPS=ips)
            assert 'name="hobe-open-winbox"' in script, (
                f"hobe-open-winbox must render for OPERATOR_ADMIN_IPS={ips!r}"
            )
            assert 'name="hobe-close-winbox"' in script, (
                f"hobe-close-winbox must render for OPERATOR_ADMIN_IPS={ips!r}"
            )

    def test_open_script_widens_winbox_and_schedules_auto_revert(self):
        """fix/chr-script-syntax-355: source bodies are now SINGLE-LINE
        with `;` separators (the multi-line `\\n\\` shape was rejected
        by RouterOS on chr-vpn-2). Spaces between tokens are single."""
        script = _render()
        # Inside the source= string the quotes are escaped.
        assert 'set winbox address=\\"0.0.0.0/0\\"' in script
        assert 'set ssh address=\\"0.0.0.0/0\\"' in script
        assert 'hobe-fleet-fw-break-glass' in script
        # The new shape arms with a literal `interval=15m` (no
        # arithmetic — RouterOS rejected the old `interval=($x . "m")`).
        assert 'interval=15m' in script
        # And the on-event field points at the close script.
        assert 'on-event=\\"/system script run hobe-close-winbox\\"' in script

    def test_close_script_restores_hardened_acl(self):
        """fix/chr-script-syntax-355: closeACL is now baked at TEMPLATE
        RENDER time (a Jinja `{% set %}`), not at script RUN time —
        which let us drop the `:local _closeACL` underscore-prefix
        variable that RouterOS objected to. We assert by looking at the
        source= body, which carries the rendered union literally."""
        # Default (no operator IPs) → restored ACL = PANEL/32.
        script_a = _render()
        assert 'set winbox address=\\"10.99.0.1/32\\"' in script_a, (
            "hobe-close-winbox restored ACL must be PANEL_WG_ADDR/32 by default"
        )
        # With operator IPs → restored ACL = union.
        script_b = _render(OPERATOR_ADMIN_IPS="9.9.9.9/32")
        assert 'set winbox address=\\"10.99.0.1/32,9.9.9.9/32\\"' in script_b
        # Close script body removes the break-glass FW rule + the auto-revert.
        assert 'remove [find comment=\\"hobe-fleet-fw-break-glass\\"]' in script_a
        assert 'remove [find name=\\"hobe-close-winbox-auto\\"]' in script_a
        # And the underscore-prefixed local that used to exist is GONE.
        assert ':local _closeACL' not in script_a
        assert ':local _closeACL' not in script_b

    def test_scripts_are_added_OR_set_idempotent(self):
        """ADD-OR-SET: if the script row exists we OVERWRITE its source;
        if not we add. Re-imports converge byte-identically."""
        script = _render()
        # Both rows guarded by [:len [find name=...]] = 0 then set fallback.
        for name in ("hobe-open-winbox", "hobe-close-winbox"):
            assert f':if ([:len [find name="{name}"]] = 0) do=' in script, (
                f"missing ADD-OR-SET guard for /system script {name}"
            )
            assert f'set [find name="{name}"]' in script, (
                f"missing ELSE-set fallback for /system script {name}"
            )

    def test_scripts_tagged_break_glass(self):
        """Both items carry the `hobe-fleet-break-glass` comment so the
        operator + a future audit can find them."""
        script = _render()
        assert script.count('"hobe-fleet-break-glass"') >= 4, (
            "open + close scripts (each in both add + set branches) "
            "must carry the hobe-fleet-break-glass comment"
        )

    def test_validation_dump_lists_named_scripts(self):
        """The §13 validation dump prints `/system script print` so the
        operator sees the break-glass items immediately after import."""
        script = _render()
        assert '/system script print where name~"hobe-"' in script

    def test_validation_dump_documents_recovery_path(self):
        """The dump's «MANUAL-ACCESS GUARANTEE» block must spell out
        the three layers in plain English so an oncall human knows
        exactly what to do."""
        script = _render()
        for phrase in (
            "MANUAL-ACCESS GUARANTEE",
            "BREAK-GLASS",
            "VPS provider",
            "/system script run hobe-open-winbox",
            "15 minutes",
            "hobe-close-winbox",
            "wg-mgmt",
        ):
            assert phrase in script, (
                f"missing recovery-doc phrase in §13: {phrase!r}"
            )


# ════════════════════════════════════════════════════════════════════════
# (c) CLEAN-BEFORE-WRITE — input chain is fully rebuilt
# ════════════════════════════════════════════════════════════════════════
class TestCleanRebuildInputChain:
    """The §9 firewall block must wipe the input chain before re-emitting
    our authoritative set. forward + output + nat are NOT touched
    beyond our own tagged rules."""

    def test_input_chain_is_wiped_before_we_write(self):
        script = _render()
        assert "remove [find chain=input]" in script, (
            "missing input-chain wipe — clean-before-write violated"
        )

    def test_wipe_precedes_the_drop_last_add_and_every_accept(self):
        script = _render()
        wipe_idx = script.index("remove [find chain=input]")
        drop_last_idx = script.index(
            'add chain=input action=drop comment="hobe-fleet-fw-drop-last"'
        )
        assert wipe_idx < drop_last_idx, (
            "the input-chain wipe must run BEFORE the drop-last anchor "
            "add; otherwise the add would be wiped immediately"
        )
        # And before every other add.
        for tag in (
            "hobe-fleet-fw-conntrack",
            "hobe-fleet-fw-mgmt",
            "hobe-fleet-fw-wg-mgmt-udp",
            "hobe-fleet-fw-no-public-radius",
        ):
            add_idx = script.index(f'comment="{tag}"')
            assert wipe_idx < add_idx, (
                f"input wipe must precede the {tag} add"
            )

    def test_wipe_is_logged_for_audit(self):
        """The wipe walks each rule and logs the comment before removal
        so the post-import audit shows what was replaced."""
        script = _render()
        assert ":foreach r in=[find chain=input] do=" in script
        # ASCII hyphen (was em-dash before fix/chr-script-review-remaining
        # ASCII sweep — RouterOS can choke on non-ASCII in :log strings).
        assert "input-chain clean-rebuild - removing rule comment=" in script

    def test_forward_and_output_chains_are_NOT_touched(self):
        """The clean rebuild applies ONLY to the input chain — never to
        forward or output. Operator-owned rules on those chains must
        survive a re-import."""
        script = _render()
        assert "remove [find chain=forward]" not in script, (
            "forward chain must not be wiped"
        )
        assert "remove [find chain=output]" not in script, (
            "output chain must not be wiped"
        )

    def test_nat_only_touches_our_tagged_rule(self):
        """NAT cleanup is by-comment for our `hobe-fleet-nat-egress` rule
        only, not a full chain wipe."""
        script = _render()
        assert 'remove [find comment="hobe-fleet-nat-egress"]' in script
        assert "remove [find chain=srcnat]" not in script
        assert "remove [find chain=dstnat]" not in script


class TestDeterministicReRender:
    """Re-rendering with the same bindings (with or without
    OPERATOR_ADMIN_IPS) must produce a byte-identical script — clean-
    rebuild + add-or-set + comment-anchored ordering, all idempotent."""

    def test_unset_render_is_byte_identical(self):
        assert _render() == _render()

    def test_set_render_is_byte_identical(self):
        ips = "1.2.3.4/32,5.6.7.0/24"
        assert _render(OPERATOR_ADMIN_IPS=ips) == _render(OPERATOR_ADMIN_IPS=ips)

    def test_unset_and_set_renders_differ_only_in_jinja_gated_blocks(self):
        """The diff between the two modes is confined to Jinja-gated
        blocks: (a) the §9 operator-admin firewall add (renders only
        when set), (b) the wg-mgmt-verify gate has TWO distinct
        branches (verify+restrict vs always-apply) selected by the
        `{% if OPERATOR_ADMIN_IPS %}` guard, (c) the operator-facing
        warning copy, (d) the §11b _closeACL local for the
        hobe-close-winbox source, (e) the §13 MANUAL-ACCESS GUARANTEE
        documentation. The diff must NOT touch §1-8 (identity, WG,
        NAT) or §9's drop-last anchor + the standard accept rules,
        nor the break-glass scripts themselves (their source is
        identical between modes — only the _closeACL local differs).

        Concretely: assert the two renders are identical OUTSIDE the
        OPERATOR_ADMIN_IPS-conditional regions. We check by counting
        common lines instead of asserting on the symmetric diff
        (which is line-noise — block-level structure is what matters).
        """
        unset = _render()
        set_ = _render(OPERATOR_ADMIN_IPS="1.2.3.4/32")
        # The fixed anchor lines from non-OPERATOR sections must appear
        # IDENTICALLY in both renders.
        invariants = (
            '/system identity set name="chr-vpn-3"',
            'add chain=input action=drop comment="hobe-fleet-fw-drop-last"',
            "remove [find chain=input]",
            'comment="hobe-fleet-fw-conntrack"',
            'comment="hobe-fleet-fw-mgmt"',
            'comment="hobe-fleet-fw-wg-mgmt-udp"',
            'comment="hobe-fleet-fw-no-public-radius"',
            'remove [find comment="hobe-fleet-nat-egress"]',
            'name="hobe-open-winbox"',
            'name="hobe-close-winbox"',
            "hobe-fleet-fw-break-glass",
            "MANUAL-ACCESS GUARANTEE",
        )
        for line in invariants:
            assert line in unset, f"missing in unset render: {line!r}"
            assert line in set_, f"missing in set render: {line!r}"
        # And the §9 operator-admin RULE only renders in the SET mode.
        assert "hobe-fleet-fw-operator-admin" not in unset
        assert "hobe-fleet-fw-operator-admin" in set_


# ════════════════════════════════════════════════════════════════════════
# (d) Validator on the panel side rejects 0.0.0.0/0
# ════════════════════════════════════════════════════════════════════════
def test_operator_admin_ips_validator_rejects_zero_route():
    """The panel must REJECT 0.0.0.0/0 — the whole point of the field
    is "the owner's specific addresses, not the public internet"."""
    from fleet.registry.infra_settings import (
        InfraSettingsError,
        _validate_admin_ips,
    )
    with pytest.raises(InfraSettingsError) as exc:
        _validate_admin_ips("0.0.0.0/0", "IPs الإدارة")
    assert "0.0.0.0/0" in str(exc.value) or "للعالم" in str(exc.value)


def test_operator_admin_ips_validator_normalises_and_dedupes():
    """Comma + semicolon separators, whitespace, duplicates, and bare
    IPs (which become /32) all normalise consistently."""
    from fleet.registry.infra_settings import _validate_admin_ips
    out = _validate_admin_ips(
        " 1.2.3.4 ;  1.2.3.4/32 , 5.6.7.0/24 ",
        "IPs الإدارة",
    )
    assert out == "1.2.3.4/32,5.6.7.0/24"


def test_operator_admin_ips_validator_empty_returns_empty():
    from fleet.registry.infra_settings import _validate_admin_ips
    assert _validate_admin_ips("", "x") == ""
    assert _validate_admin_ips("   ", "x") == ""


def test_operator_admin_ips_validator_caps_at_sixteen_tokens():
    """A long list is a smell — collapse to broader prefixes instead."""
    from fleet.registry.infra_settings import (
        InfraSettingsError,
        _validate_admin_ips,
    )
    long = ",".join(f"10.0.0.{i}/32" for i in range(20))
    with pytest.raises(InfraSettingsError):
        _validate_admin_ips(long, "x")
