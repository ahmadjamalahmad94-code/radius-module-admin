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
