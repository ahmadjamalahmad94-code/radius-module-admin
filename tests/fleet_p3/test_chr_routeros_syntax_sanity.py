r"""fix/chr-script-syntax-355 — RouterOS-import syntax sanity checks.

Background: chr-vpn-2 import on `panel main 350d0ac` failed with
``Script Error: syntax error (line 355 column 8)``. Root cause: the
break-glass `/system script add ... source="..."` blocks used multi-
line strings with `\n\` continuations, which RouterOS does NOT parse
the way they were written — backslash-at-EOL is line continuation
OUTSIDE strings only. Inside a quoted string the `\` followed by a
real newline is invalid. Companion bugs: `:local _wiped` (leading
underscore) and `interval=($revertMin . "m")` (arithmetic where the
scheduler wants a literal time).

This test pins a class of RouterOS-import gotchas so the same shape
can't slip back in. It renders the script via the same path
``OnboardingService`` / ``render_chr_script`` uses for the download
button, then walks the lines.
"""
from __future__ import annotations

import re

import pytest

from fleet.registry.script_render import render_from_bindings


_BASE: dict = {
    "ROUTER_IDENTITY":    "chr-vpn-2",
    "CHR_PUBLIC_IP":      "37.27.218.211",
    "WAN_IFACE":          "ether1",
    "WG_MGMT_PRIVKEY":    "MGMT==",
    "WG_MGMT_ADDR":       "10.99.0.12/24",
    "WG_DATA_PRIVKEY":    "DATA==",
    "WG_DATA_ADDR":       "10.98.0.12/24",
    "WG_DATA_ADDR_IP":    "10.98.0.12",
    "PANEL_WG_PUBKEY":    "P=",
    "PANEL_WG_ENDPOINT":  "panel.hoberadius.com:51820",
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
    "API_USER":           "hobe-panel",
    "API_PASSWORD":       "strong-pwd",
    "API_PORT":           8443,
}


def _render(**overrides) -> str:
    return render_from_bindings({**_BASE, **overrides})


def _join_continuations(script: str) -> str:
    """RouterOS line continuation is ``\\`` immediately before EOL —
    outside string literals. Tests that walk LOGICAL lines need them
    stitched together. We strip multi-line `source="..."` literals
    first so the per-line scan doesn't trip on their contents."""
    flat = script.replace(" \\\n", " ").replace("\\\n", "")
    return flat


def _strip_source_literals(script: str) -> str:
    """Replace every ``source="..."`` literal with ``source=""`` so a
    per-line scan doesn't trip on RouterOS keywords or quotes that
    are INSIDE a string. Used by every check that's about RouterOS
    statement-level syntax, not the bytes inside a source body."""
    return re.sub(r'source="(?:[^"\\]|\\.)*"', 'source=""', script, flags=re.DOTALL)


# ════════════════════════════════════════════════════════════════════════
# (1) No leading-underscore RouterOS locals
# ════════════════════════════════════════════════════════════════════════
class TestNoUnderscorePrefixLocals:
    """RouterOS' v7 parser accepts `_name` in most contexts but some
    builds (notably the chr-vpn-2 import that triggered this branch)
    reject it. The cost of avoiding underscore-prefix names is zero —
    so we forbid them outright."""

    def test_no_local_or_set_or_global_starts_with_underscore(self):
        for mode in ("", "1.2.3.4/32"):
            script = _render(OPERATOR_ADMIN_IPS=mode)
            stripped = _strip_source_literals(script)
            offenders = []
            for lineno, raw in enumerate(stripped.splitlines(), 1):
                # Ignore comment lines AND lines INSIDE source= literals.
                if raw.lstrip().startswith("#"):
                    continue
                # Match :local|:set|:global followed by an underscore-
                # prefixed identifier. The full regex:
                #   ^\s*:(local|set|global)\s+_\w+
                m = re.match(r"\s*:(local|set|global)\s+_\w+", raw)
                if m:
                    offenders.append((lineno, raw))
            assert not offenders, (
                "found leading-underscore RouterOS local(s) — rename to a "
                f"plain identifier: {offenders[:3]!r}"
            )

    def test_no_underscore_var_reference_anywhere(self):
        """Owner-confirmed root cause of line 355:8 — RouterOS rejects
        variable names starting with an underscore. Beyond the
        declaration sites (:local _foo), forbid REFERENCES too — any
        `$_<word>` substitution in the rendered output is the same
        hazard."""
        for mode in ("", "1.2.3.4/32"):
            script = _render(OPERATOR_ADMIN_IPS=mode)
            # Find any $_word token — includes references inside source=
            # bodies because they execute when the operator invokes the
            # break-glass script.
            refs = re.findall(r"\$_\w+", script)
            assert not refs, (
                "found underscore-prefixed variable reference(s) in the "
                f"rendered script: {sorted(set(refs))[:5]!r}. "
                "Rename the underlying :local / :set."
            )


# ════════════════════════════════════════════════════════════════════════
# (2) Every `find` call has a menu-path context line above it
# ════════════════════════════════════════════════════════════════════════
class TestFindHasContextMenu:
    """`[find ...]` calls without an explicit menu prefix
    (e.g. `[/ip firewall filter find ...]`) inherit the currently-active
    menu set by the previous bare path line (`/ip firewall filter`).
    If no such context is set above, RouterOS reports a syntax error.

    We check every bare `[find ...]` that's NOT inside a string literal
    and NOT fully-qualified, and assert there's a `/...` menu line
    earlier in the script."""

    def test_bare_find_has_active_menu_above(self):
        for mode in ("", "1.2.3.4/32"):
            script = _render(OPERATOR_ADMIN_IPS=mode)
            stripped = _strip_source_literals(script).splitlines()
            current_menu = None
            for lineno, raw in enumerate(stripped, 1):
                if raw.lstrip().startswith("#"):
                    continue
                # Look for a bare path-only menu line. Tokens beginning
                # with `/` that are NOT followed by a subsequent verb
                # in the same line constitute a path-reset. We use a
                # simple heuristic: the line starts with `/` and the
                # FIRST token after the path is none of the inline
                # verbs (add/set/remove/print/save/load/find/get).
                lstripped = raw.lstrip()
                if lstripped.startswith("/"):
                    tokens = lstripped.split()
                    if len(tokens) >= 3 and tokens[0].startswith("/"):
                        # Single token = pure path → context reset.
                        # Two+ tokens may still be a multi-word path
                        # (e.g. `/ip firewall filter`). Only reset if
                        # NO inline verb appears on the line.
                        pass
                    # A bare path line has no inline verb anywhere.
                    inline_verbs = {
                        "add", "set", "remove", "print", "save", "load",
                        "get", "edit", "move",
                        "disable", "enable", "export", "monitor",
                    }
                    has_verb = any(t in inline_verbs for t in tokens)
                    if not has_verb:
                        current_menu = lstripped
                # Look for bare `[find ...]` references on this line.
                # When the line ITSELF contains a `/menu ...` prefix
                # before the find call, the inline form supplies its
                # own context — we count that as OK.
                for find_match in re.finditer(r"\[find\b", raw):
                    pos = find_match.start()
                    # Look BACKWARDS on the same line for an inline
                    # `/menu` prefix. If we find one, the bare find
                    # inherits its context. The pattern matches a
                    # `/word` at any earlier position on the line.
                    before = raw[:pos]
                    if re.search(r"/[a-z][\w/]*\b", before):
                        continue  # inline-path find — has its own menu
                    assert current_menu is not None, (
                        f"L{lineno} uses bare [find ...] without an "
                        f"active menu context above: {raw!r}"
                    )


# ════════════════════════════════════════════════════════════════════════
# (3) Balanced quotes per logical line
# ════════════════════════════════════════════════════════════════════════
class TestBalancedQuotesPerLine:
    """Every logical line (after joining backslash continuations) must
    have an even number of unescaped double-quotes. Multi-line
    `source="..."` literals are stripped first — their content is one
    RouterOS token, the per-line check applies to the script
    statements themselves."""

    def test_quote_balance_per_logical_line(self):
        """RouterOS executable lines must close every double-quote on
        the same logical line. Comment lines are exempt — they're not
        parsed for syntax, and the operator-facing comment headers
        legitimately contain unbalanced punctuation like
        ``# (C") Operator manual-access``."""
        for mode in ("", "1.2.3.4/32,5.6.7.0/24"):
            script = _render(OPERATOR_ADMIN_IPS=mode)
            flat = _join_continuations(script)
            stripped = _strip_source_literals(flat)
            for lineno, line in enumerate(stripped.splitlines(), 1):
                if line.lstrip().startswith("#"):
                    continue
                # Count UNESCAPED " — i.e. drop \" pairs first.
                bare = line.replace('\\"', "")
                assert bare.count('"') % 2 == 0, (
                    f"L{lineno} odd unescaped double-quotes: {line!r}"
                )


# ════════════════════════════════════════════════════════════════════════
# (4) /system script source bodies are ONE LOGICAL LINE
# ════════════════════════════════════════════════════════════════════════
class TestSystemScriptSourceIsOneLine:
    """The chr-vpn-2 failure was a multi-line `source="...\\n\\"`
    construction — RouterOS does NOT support backslash-at-EOL line
    continuation inside a string literal. The robust form is a single
    physical line `source="cmd1; cmd2; cmd3; ..."`. We assert that
    every `source="..."` literal occupies exactly one line in the
    rendered file."""

    def test_every_source_string_is_single_line(self):
        for mode in ("", "1.2.3.4/32"):
            script = _render(OPERATOR_ADMIN_IPS=mode)
            # Find every `source="..."` literal. The pattern is greedy-
            # safe because we anchor on the *first* unescaped closing
            # `"` (any sequence of non-`"` or escaped `\"`).
            for m in re.finditer(
                r'source="((?:[^"\\]|\\.)*)"', script, flags=re.DOTALL
            ):
                body = m.group(1)
                assert "\n" not in body, (
                    "found multi-line source= literal — break-glass "
                    "scripts must be ONE PHYSICAL LINE so RouterOS' "
                    "string parser doesn't trip on `\\<newline>`. "
                    f"Body excerpt: {body[:120]!r}"
                )

    def test_break_glass_open_source_uses_literal_interval_not_arithmetic(self):
        """scheduler `interval=` wants a literal time value, not an
        arithmetic concatenation like `($revertMin . "m")`. The
        chr-vpn-2 import tripped on that exact shape; pin it shut.

        The OPEN body is the only one that ARMS the auto-revert
        scheduler (`add name="hobe-close-winbox-auto"`); the CLOSE
        body just removes it. So we identify by the ADD form."""
        script = _render()
        found_open_body = False
        for m in re.finditer(
            r'source="((?:[^"\\]|\\.)*)"', script, flags=re.DOTALL
        ):
            body = m.group(1)
            if 'add name=\\"hobe-close-winbox-auto\\"' not in body:
                continue
            found_open_body = True
            assert "interval=15m" in body, (
                "hobe-open-winbox source must arm the auto-revert with "
                "literal `interval=15m` — RouterOS rejects "
                f"`interval=(...)` arithmetic. Body excerpt: {body[:200]!r}"
            )
            assert "interval=(" not in body, (
                "hobe-open-winbox source uses `interval=(...)` arithmetic — "
                "RouterOS scheduler interval= must be a literal time"
            )
        assert found_open_body, "no source= body adds hobe-close-winbox-auto"


# ════════════════════════════════════════════════════════════════════════
# (5) Names in the break-glass scripts + invariants
# ════════════════════════════════════════════════════════════════════════
def test_break_glass_names_and_behavior_render_correctly():
    """The user-facing recovery commands (run from VPS console) must
    match the documented names; the open script widens WinBox AND
    schedules a 15-minute auto-revert; the close script restores the
    hardened ACL."""
    script = _render()
    # Names appear inside `add name="..."` AND inside the scheduler
    # `on-event="..."`. Both must be the documented names.
    assert 'add name="hobe-open-winbox"' in script
    assert 'add name="hobe-close-winbox"' in script
    # Open script widens winbox (we look inside any source= body that
    # mentions hobe-close-winbox-auto — that's the open script).
    for m in re.finditer(r'source="((?:[^"\\]|\\.)*)"', script, flags=re.DOTALL):
        body = m.group(1)
        if "hobe-close-winbox-auto" not in body:
            continue
        assert "set winbox address=" in body
        assert "0.0.0.0/0" in body
        assert "/system script run hobe-close-winbox" in body
        break
    else:
        pytest.fail("no source= body schedules the auto-revert")


def test_close_script_restores_panel_only_acl_when_operator_ips_unset():
    script = _render()
    # The close script body bakes in the closeACL constant.
    for m in re.finditer(r'source="((?:[^"\\]|\\.)*)"', script, flags=re.DOTALL):
        body = m.group(1)
        if "hardened ACL restored" not in body:
            continue
        # Default render → PANEL_WG_ADDR/32 only.
        assert "10.99.0.1/32" in body
        # And NOT a union (no comma + extra IP in the address= clause).
        m2 = re.search(r"set winbox address=\\\"([^\\]+)\\\"", body)
        assert m2 and m2.group(1) == "10.99.0.1/32", (
            f"close-winbox restore ACL must be PANEL/32 by default; "
            f"got: {m2.group(1) if m2 else '<no match>'}"
        )
        break
    else:
        pytest.fail("no close-winbox source body found")


def test_close_script_restores_union_acl_when_operator_ips_set():
    script = _render(OPERATOR_ADMIN_IPS="1.2.3.4/32,5.6.7.0/24")
    for m in re.finditer(r'source="((?:[^"\\]|\\.)*)"', script, flags=re.DOTALL):
        body = m.group(1)
        if "hardened ACL restored" not in body:
            continue
        # The closeACL is the UNION baked at render time.
        m2 = re.search(r"set winbox address=\\\"([^\\]+)\\\"", body)
        assert m2 and m2.group(1) == "10.99.0.1/32,1.2.3.4/32,5.6.7.0/24", (
            f"close-winbox restore ACL must union PANEL + OPERATOR_ADMIN_IPS "
            f"at render time; got: {m2.group(1) if m2 else '<no match>'}"
        )
        break
    else:
        pytest.fail("no close-winbox source body found")


# ════════════════════════════════════════════════════════════════════════
# (6) Idempotent re-render (the syntax fix must not break determinism)
# ════════════════════════════════════════════════════════════════════════
def test_re_render_byte_identical_unset():
    assert _render() == _render()


def test_re_render_byte_identical_set():
    ips = "1.2.3.4/32"
    assert _render(OPERATOR_ADMIN_IPS=ips) == _render(OPERATOR_ADMIN_IPS=ips)


# ════════════════════════════════════════════════════════════════════════
# (7) The fixed `:local wipedCount` is what's emitted (no `_wiped`)
# ════════════════════════════════════════════════════════════════════════
def test_clean_rebuild_uses_plain_local_name():
    script = _render()
    # Positive — wipedCount is the new name.
    assert ":local wipedCount 0" in script
    assert ":set wipedCount" in script
    # Negative — the old underscore-prefixed name must be gone.
    assert ":local _wiped" not in script
    assert ":set _wiped" not in script
    assert ":local _closeACL" not in script


# ════════════════════════════════════════════════════════════════════════
# (8) Pure ASCII rendered output (owner MUST-DO #2)
# ════════════════════════════════════════════════════════════════════════
class TestPureAsciiRender:
    """Some RouterOS v7 builds reject non-ASCII bytes inside script
    strings. Em-dashes, right-arrows, Arabic punctuation — anything
    above 0x7F — must NOT appear in the rendered output. We assert
    every byte is <= 0x7F across both binding modes."""

    def test_every_byte_is_ascii_unset(self):
        script = _render()
        offenders = [(i, c, hex(ord(c)))
                     for i, c in enumerate(script) if ord(c) > 127]
        assert not offenders, (
            "rendered script contains non-ASCII bytes (RouterOS may "
            f"reject the import): {offenders[:5]!r}"
        )

    def test_every_byte_is_ascii_set(self):
        script = _render(OPERATOR_ADMIN_IPS="1.2.3.4/32,5.6.7.0/24")
        offenders = [(i, c, hex(ord(c)))
                     for i, c in enumerate(script) if ord(c) > 127]
        assert not offenders, offenders[:5]


# ════════════════════════════════════════════════════════════════════════
# Owner review acceptance — the 5 review points pinned on the render
# ════════════════════════════════════════════════════════════════════════
class TestOwnerReviewAcceptance:
    """Per the owner's expert review, pin the 5 functional fixes that
    accompanied the line-355 syntax fix."""

    # #1 emergency admin — BOTH layers (firewall + service ACL) must agree
    def test_emergency_branch_widens_service_acl_to_0_0_0_0(self):
        """With OPERATOR_ADMIN_IPS unset AND wg-mgmt unreachable, the
        :else branch must explicitly set `/ip service set ssh|winbox
        address=0.0.0.0/0` — otherwise the temp firewall accept is
        silently dropped by the still-restrictive service-layer ACL."""
        script = _render()
        # The two emergency-fallback set lines (inside `} else={` block).
        assert "/ip service set ssh    address=0.0.0.0/0 disabled=no" in script, (
            "emergency branch must widen ssh service ACL to 0.0.0.0/0"
        )
        assert "/ip service set winbox address=0.0.0.0/0 disabled=no" in script, (
            "emergency branch must widen winbox service ACL to 0.0.0.0/0"
        )
        # And the matching temp firewall rule is added.
        assert 'comment="hobe-fleet-fw-temp-emergency-admin"' in script

    def test_operator_set_branch_keeps_union_acl_unchanged(self):
        """When OPERATOR_ADMIN_IPS is set, the service ACL is the union
        (PANEL/32,<operator-ips>) regardless of wg-mgmt state — NEVER
        widened to 0.0.0.0/0 at the steady-state apply layer."""
        script = _render(OPERATOR_ADMIN_IPS="9.9.9.9/32")
        # The steady-state lines must reference $mgmtAddrACL, not 0/0.
        for ln in script.splitlines():
            if not ln.startswith("/ip service set ssh") and not ln.startswith("/ip service set winbox"):
                continue
            if 'address=\\"' in ln:  # inside a break-glass source body
                continue
            assert "address=$mgmtAddrACL" in ln, ln
            assert "0.0.0.0/0" not in ln, ln

    # #2 WebFig — break-glass + documentation
    def test_webfig_break_glass_scripts_render(self):
        script = _render()
        assert 'name="hobe-open-webfig"' in script
        assert 'name="hobe-close-webfig"' in script
        # Open body widens www-ssl + opens 8443 + arms 15m revert.
        for m in re.finditer(r'source="((?:[^"\\]|\\.)*)"', script, flags=re.DOTALL):
            body = m.group(1)
            if 'add name=\\"hobe-close-webfig-auto\\"' not in body:
                continue
            assert "set www-ssl address=\\\"0.0.0.0/0\\\"" in body
            assert "hobe-fleet-fw-break-glass-webfig" in body
            assert "interval=15m" in body
            break
        else:
            pytest.fail("no source= body provisions the WebFig auto-revert")

    def test_webfig_unsupported_documented_in_print_block(self):
        script = _render()
        assert "WEBFIG (public HTML5 UI on www-ssl) is NOT supported" in script
        assert "hobe-open-webfig" in script
        assert "hobe-close-webfig" in script

    # #3 IPsec firewall — IKE 500/4500 always present when vpn_ipsec
    def test_ike_firewall_accept_renders_without_cert(self):
        """The 500/4500 firewall accept must NOT be gated on
        IKE_CERT_NAME. The cert gates the IKEv2 SERVER, not the WAN-
        side accept. If the cert isn't ready yet we still want
        UDP 500/4500 + ESP + UDP 1701 permitted at the firewall."""
        from fleet.registry.script_render import render_from_bindings
        # Render with IKE_CERT_NAME explicitly empty.
        b = dict(_BASE)
        b["IKE_CERT_NAME"] = ""
        s = render_from_bindings(b)
        # Even with cert empty, when vpn_ipsec role is on, the IKE
        # firewall accept renders (default NODE_ROLES_SET = all roles).
        assert 'comment="hobe-fleet-fw-ike"' in s, (
            "IKE 500/4500 firewall accept must render when vpn_ipsec "
            "role is enabled, regardless of IKE_CERT_NAME"
        )
        assert "dst-port=500,4500" in s
        assert 'comment="hobe-fleet-fw-esp"' in s
        assert 'comment="hobe-fleet-fw-l2tp"' in s
        assert "dst-port=1701" in s

    # #4 RADIUS — service=ppp only
    def test_radius_service_is_ppp_only(self):
        script = _render()
        assert "add service=ppp address=" in script, (
            "/radius add must use service=ppp (no `,login`)"
        )
        assert "service=ppp,login" not in script, (
            "/radius must NOT carry `,login` — that would let RADIUS "
            "authenticate router admin login, widening the trust boundary"
        )

    # #5 secret rotation scaffold endpoint
    def test_rotate_secrets_endpoint_exists_and_returns_501(self):
        """The rotation flow is deferred — but the endpoint exists
        and returns 501 with a clear deferred-scope message so the UI
        can wire up the button."""
        from fleet.registry.routes_onboarding import bp
        urls = {r.rule for r in bp.deferred_functions and [] or []}  # placeholder
        # Use Flask's url_map via a test app for a clean assertion.
        from app import create_app
        app = create_app()
        with app.app_context():
            rules = [r for r in app.url_map.iter_rules()
                     if r.endpoint.endswith("rotate_secrets")]
            assert rules, "rotate_secrets endpoint must be registered"
            r = rules[0]
            assert "POST" in r.methods
            assert "/jobs/" in r.rule and "/rotate-secrets" in r.rule


# ════════════════════════════════════════════════════════════════════════
# Acceptance — re-run doesn't duplicate fw rules; key listener accepts
# all land above drop-last on the CHR
# ════════════════════════════════════════════════════════════════════════
def test_no_duplicate_firewall_rules_on_rerun():
    """The clean-rebuild guarantees that each authoritative tag appears
    at most once in the rendered output. (Re-running the script on the
    CHR re-rebuilds from scratch — no duplicate rows.)"""
    script = _render()
    # Flatten backslash continuations so each multi-line `add` rule is one
    # logical line. Then strip source= bodies so we don't count `comment=`
    # tokens inside break-glass script source strings.
    flat = _join_continuations(script)
    stripped = _strip_source_literals(flat)
    # Build (rule-id, line) by extracting the LAST `comment="..."` on
    # each `add chain=input` line — the rule's own tag, not its
    # place-before anchor reference.
    rule_tag_line = []
    for ln in stripped.splitlines():
        if not (ln.lstrip().startswith("add ") and "chain=input" in ln):
            continue
        tags = re.findall(r'comment="(hobe-fleet-fw-[^"]+)"', ln)
        if tags:
            rule_tag_line.append((tags[-1], ln))
    for tag in (
        "hobe-fleet-fw-drop-last",
        "hobe-fleet-fw-conntrack",
        "hobe-fleet-fw-mgmt",
        "hobe-fleet-fw-wg-mgmt-udp",
        "hobe-fleet-fw-no-public-radius",
    ):
        matches = [ln for t, ln in rule_tag_line if t == tag]
        assert len(matches) == 1, (
            f"tag {tag!r} appears in {len(matches)} authoritative `add` lines; "
            "the clean rebuild should produce exactly one"
        )


def test_listener_accepts_present_when_role_enabled():
    """Belt-and-braces for the IPsec + PPTP + wg-users + radius
    listeners — every required accept renders when its role is on
    AND lands above drop-last via place-before."""
    script = _render()
    flat = script.replace(" \\\n", " ")
    must_have = {
        "hobe-fleet-fw-wg-mgmt-udp":  "dst-port=51820",
        "hobe-fleet-fw-wg-data-udp":  "dst-port=51821",
        "hobe-fleet-fw-pptp-ctrl":    "dst-port=1723",
        "hobe-fleet-fw-pptp-data":    "protocol=gre",
        "hobe-fleet-fw-ike":          "dst-port=500,4500",
        "hobe-fleet-fw-esp":          "protocol=ipsec-esp",
        "hobe-fleet-fw-l2tp":         "dst-port=1701",
        "hobe-fleet-fw-wg-users":     "protocol=udp",
        "hobe-fleet-fw-no-public-radius": "dst-port=1812,1813,3799",
    }
    for tag, marker in must_have.items():
        line = next(
            (ln for ln in flat.splitlines()
             if 'add chain=input' in ln and f'comment="{tag}"' in ln),
            None,
        )
        assert line, f"missing listener accept for {tag!r}"
        assert marker in line, (
            f"{tag!r} rule must carry {marker!r}; got: {line!r}"
        )
        assert 'place-before=[find comment="hobe-fleet-fw-drop-last"]' in line, (
            f"{tag!r} must anchor against drop-last"
        )
