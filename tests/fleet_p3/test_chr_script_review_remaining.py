"""fix/chr-script-review-remaining — three CHR-script hardening pins.

Pinned behaviours:

  1. RADIUS service = ``ppp`` ONLY. The legacy ``service=ppp,login``
     would have let a RADIUS Access-Accept authenticate router-admin
     login — the same privilege escalation the rest of this template's
     hardening blocks (scoped REST user, restricted ssh/winbox, no
     public WebFig).

  2. EMERGENCY-ADMIN branch (wg-mgmt unreachable + OPERATOR_ADMIN_IPS
     unset) must open BOTH the firewall AND the SERVICE-layer ACL.
     A temp firewall ``accept tcp/22,8291`` is useless if
     ``/ip service ssh address=10.99.0.1/32`` still blocks the SYN.
     When OPERATOR_ADMIN_IPS is set we expect the union
     ``PANEL/32,<operator IPs>`` and NEVER 0.0.0.0/0.

  3. WebFig — public WebFig is NOT supported after hardening. The
     warning text MUST appear in the printed ``:put``/``:log`` output.
     A break-glass pair (``hobe-open-webfig`` / ``hobe-close-webfig``)
     mirrors the WinBox pair: widen ``www-ssl`` to 0.0.0.0/0 + temp
     firewall accept for tcp/8443 + auto-revert scheduler at literal
     ``interval=15m``.

Also (precaution): no em-dash / en-dash / arrow characters in COMMAND
positions (:log/:put/comment=/source= strings); no underscore-prefixed
locals; no :break / :continue in code (only in #-prefixed comments).
"""
from __future__ import annotations

import re

from fleet.registry.script_render import render_from_bindings


_BASE: dict = {
    "ROUTER_IDENTITY":    "chr-vpn-1",
    "CHR_PUBLIC_IP":      "178.105.244.112",
    "WAN_IFACE":          "ether1",
    "WG_MGMT_PRIVKEY":    "MGMT==",
    "WG_MGMT_ADDR":       "10.99.0.11/24",
    "WG_DATA_PRIVKEY":    "DATA==",
    "WG_DATA_ADDR":       "10.98.0.11/24",
    "WG_DATA_ADDR_IP":    "10.98.0.11",
    "PANEL_WG_PUBKEY":    "P=",
    "PANEL_WG_ENDPOINT":  "control.hoberadius.com:51820",
    "PANEL_WG_ADDR":      "10.99.0.1",
    "PROXY_WG_PUBKEY":    "X=",
    "PROXY_WG_ENDPOINT":  "proxy.hoberadius.com:51821",
    "PROXY_WG_ADDR":      "10.98.0.1",
    "CHR_SHARED_SECRET":  "shared-secret-32-chars-or-longer-strong",
    "SSTP_CERT_NAME":     "",
    "IKE_CERT_NAME":      "",
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
    """Stitch RouterOS line-continuations (` \\\\\\n`) so single-line
    `add ...` blocks can be grepped as one line."""
    return script.replace(" \\\n", " ")


def _strip_comments(script: str) -> str:
    """Drop RouterOS `#`-prefixed comment lines (they are operator-only
    text RouterOS ignores; the hardening rules only apply to lines that
    actually reach the parser)."""
    out = []
    for line in script.splitlines():
        if line.lstrip().startswith("#"):
            continue
        out.append(line)
    return "\n".join(out)


# ════════════════════════════════════════════════════════════════════════
# (1) RADIUS service = ppp ONLY (not ppp,login)
# ════════════════════════════════════════════════════════════════════════
class TestRadiusServiceIsPppOnly:
    """`/radius add service=ppp ...` — never `service=ppp,login`."""

    def test_radius_line_has_service_ppp_only(self):
        flat = _flat(_render())
        radius_add = next(
            (ln for ln in flat.splitlines()
             if ln.lstrip().startswith("add ") and 'comment="hobe-fleet-radius"' in ln),
            None,
        )
        assert radius_add, "RADIUS add line missing — hobe-fleet-radius comment not found"
        assert "service=ppp " in radius_add, (
            f"expected service=ppp (with trailing space), got: {radius_add!r}"
        )

    def test_radius_line_does_not_grant_login(self):
        """The dropped policy bit. `service=ppp,login` would have let a
        RADIUS server authenticate router admin login. We deliberately
        keep RADIUS to PPP/VPN user auth only."""
        flat = _flat(_render())
        radius_add = next(
            ln for ln in flat.splitlines()
            if ln.lstrip().startswith("add ") and 'comment="hobe-fleet-radius"' in ln
        )
        assert "service=ppp,login" not in radius_add, (
            "RADIUS service must be ppp ONLY — 'login' would let RADIUS "
            "auth router admin login; that escalation is what every "
            "other hardening rule in this template blocks."
        )
        # Defence in depth: also verify the bare ',login' token doesn't
        # appear anywhere on the line (catches re-ordered tokens too).
        assert ",login" not in radius_add


# ════════════════════════════════════════════════════════════════════════
# (2) Emergency-admin: open BOTH layers (service ACL + firewall)
# ════════════════════════════════════════════════════════════════════════
class TestEmergencyAdminOpensBothLayers:
    """When wg-mgmt is unreachable AND OPERATOR_ADMIN_IPS is unset, the
    emergency-admin branch must open the SERVICE-layer ACL to 0.0.0.0/0
    (else the listener's `address=10.99.0.1/32` silently blocks the
    very emergency the firewall accept is meant to allow).

    When OPERATOR_ADMIN_IPS IS set the union ACL applies and 0.0.0.0/0
    must NOT appear in the service-layer set.
    """

    def test_unreachable_branch_widens_ssh_to_zero(self):
        """The else={} branch of the mgmtReachable gate must contain
        `/ip service set ssh address=0.0.0.0/0 disabled=no`."""
        script = _render(OPERATOR_ADMIN_IPS="")
        # Locate the else-branch text (lives between `} else={` and `}`).
        m = re.search(
            r":if \(\$mgmtReachable\) do=\{(.+?)\} else=\{(.+?)\}\s*\n",
            script,
            re.DOTALL,
        )
        assert m, "could not locate the mgmtReachable if/else branches"
        reachable_branch = m.group(1)
        unreachable_branch = m.group(2)
        # Reachable branch — restricted ACL ($mgmtAddrACL = PANEL/32 only).
        assert "address=$mgmtAddrACL" in reachable_branch
        # Unreachable branch — service ACL widened so emergency accept actually works.
        assert "/ip service set ssh    address=0.0.0.0/0 disabled=no" in unreachable_branch
        assert "/ip service set winbox address=0.0.0.0/0 disabled=no" in unreachable_branch
        # And the firewall temp emergency accept is still there.
        assert 'comment="hobe-fleet-fw-temp-emergency-admin"' in unreachable_branch

    def test_unreachable_branch_logs_explain_both_layers(self):
        """Operator-facing :log warning must mention BOTH layers so the
        post-import audit log explains what happened. We grep the
        :log warning line directly (regex on the nested-brace else
        branch is unreliable; the log line is unique enough)."""
        script = _render(OPERATOR_ADMIN_IPS="")
        log_lines = [
            ln for ln in script.splitlines()
            if ln.lstrip().startswith(":log warning")
            and "wg-mgmt NOT reachable from this CHR" in ln
        ]
        assert log_lines, "expected an emergency-admin :log warning line"
        line = log_lines[0]
        assert "service ACL 0.0.0.0/0" in line
        assert "emergency-admin firewall accept" in line
        # The :put line (operator console echo) must mirror the warning.
        put_lines = [
            ln for ln in script.splitlines()
            if ln.lstrip().startswith(":put")
            and "wg-mgmt NOT reachable yet" in ln
        ]
        assert put_lines, "expected an emergency-admin :put line"
        assert "service ACL 0.0.0.0/0" in put_lines[0]

    def test_set_branch_uses_union_acl_never_zero(self):
        """When OPERATOR_ADMIN_IPS is set, the service-layer ACL on
        ssh+winbox MUST be PANEL/32,<ips> — never 0.0.0.0/0."""
        ips = "1.2.3.4/32,5.6.7.8/32"
        script = _render(OPERATOR_ADMIN_IPS=ips)
        # The renderer composes :local mgmtAddrACL = PANEL/32,<ips>
        assert f':local mgmtAddrACL "10.99.0.1/32,{ips}"' in script
        # And uses $mgmtAddrACL on ssh+winbox.
        assert "/ip service set ssh    address=$mgmtAddrACL disabled=no" in script
        assert "/ip service set winbox address=$mgmtAddrACL disabled=no" in script
        # The OPERATOR_ADMIN_IPS branch must NOT contain the
        # 0.0.0.0/0 service-ACL widen (that's only the unreachable+unset path).
        operator_block = script.split("{% if OPERATOR_ADMIN_IPS")[0]  # noop; just sanity that we're testing the rendered output
        assert "/ip service set ssh    address=0.0.0.0/0" not in script, (
            "0.0.0.0/0 service ACL must NEVER render when OPERATOR_ADMIN_IPS is set"
        )
        assert "/ip service set winbox address=0.0.0.0/0" not in script


# ════════════════════════════════════════════════════════════════════════
# (3a) WebFig warning text renders in :put / :log
# ════════════════════════════════════════════════════════════════════════
class TestWebFigWarningRenders:
    """The script's printed warning block must clearly state WebFig is
    NOT supported after hardening and tell the operator how to recover."""

    def test_warning_text_present_when_operator_ips_unset(self):
        script = _render(OPERATOR_ADMIN_IPS="")
        # The unset branch's :put line names WebFig and break-glass.
        assert "public WebFig is NOT supported" in script
        assert "hobe-open-webfig" in script
        # And the :log line spells it out for the audit log.
        assert "Public WinBox/SSH and public WebFig will NOT work after hardening" in script

    def test_warning_text_present_when_operator_ips_set(self):
        """The OPERATOR_ADMIN_IPS branch's warning also mentions WebFig
        (different :put / :log strings — both must carry the notice)."""
        script = _render(OPERATOR_ADMIN_IPS="1.2.3.4/32")
        assert "public WebFig is NOT supported" in script
        assert "hobe-open-webfig" in script

    def test_validation_dump_documents_webfig_recovery(self):
        """The §13 post-import :put block must teach the operator how
        to bring WebFig back temporarily."""
        script = _render()
        assert ":put \"  3) WEBFIG" in script
        assert "/system script run hobe-open-webfig" in script
        assert "/system script run hobe-close-webfig" in script


# ════════════════════════════════════════════════════════════════════════
# (3b) hobe-open-webfig — temp widen + 15m auto-revert
# ════════════════════════════════════════════════════════════════════════
class TestHobeOpenWebFigBreakGlass:
    """The break-glass script must:
      * widen /ip service www-ssl to 0.0.0.0/0
      * add a tagged firewall accept tcp/8443 above drop-last
      * arm a 15m scheduler that calls hobe-close-webfig
      * use literal `interval=15m` (no expressions — RouterOS rejects)
      * be idempotent (add-or-set by name).
    The close pair must restore the hardened ACL = PANEL_WG_ADDR/32 only.
    """

    def _open_source(self, script: str) -> str:
        # The script add/set lines stuff the source body on one line; we
        # grep the surrounding 4 logical lines and extract source="...".
        # The body is double-quoted with escaped inner quotes (\").
        flat = _flat(script)
        m = re.search(
            r'name="hobe-open-webfig".*?source="(.+?)"\s*\n',
            flat,
            re.DOTALL,
        )
        assert m, "hobe-open-webfig source body missing"
        return m.group(1)

    def _close_source(self, script: str) -> str:
        flat = _flat(script)
        m = re.search(
            r'name="hobe-close-webfig".*?source="(.+?)"\s*\n',
            flat,
            re.DOTALL,
        )
        assert m, "hobe-close-webfig source body missing"
        return m.group(1)

    def test_open_widens_www_ssl_to_zero(self):
        body = self._open_source(_render())
        assert "/ip service set www-ssl address=\\\"0.0.0.0/0\\\"" in body
        assert "disabled=no" in body
        assert "port=8443" in body

    def test_open_adds_tagged_firewall_accept_for_8443(self):
        body = self._open_source(_render())
        assert "comment=\\\"hobe-fleet-fw-break-glass-webfig\\\"" in body
        assert "protocol=tcp" in body
        assert "dst-port=8443" in body
        # place-before drop-last — preserves the surgical-firewall ordering.
        assert "place-before=[find comment=\\\"hobe-fleet-fw-drop-last\\\"]" in body

    def test_open_arms_scheduler_with_literal_15m(self):
        body = self._open_source(_render())
        assert 'name=\\"hobe-close-webfig-auto\\"' in body
        assert "interval=15m" in body, (
            "scheduler interval MUST be the literal `15m` — RouterOS rejects "
            "expressions like ($x . \"m\") in interval="
        )
        assert "on-event=\\\"/system script run hobe-close-webfig\\\"" in body

    def test_open_is_idempotent_add_or_set(self):
        """Same add-or-set pattern as the WinBox pair — :if find empty
        then add, else set. No remove (would error if scheduled)."""
        script = _render()
        # The block uses the same shape twice (one for add, one for set).
        add_block = re.search(
            r':if \(\[:len \[find name="hobe-open-webfig"\]\] = 0\) do=\{\s*\n'
            r'\s*add name="hobe-open-webfig"',
            script,
        )
        assert add_block, "add branch of hobe-open-webfig add-or-set missing"
        set_block = re.search(
            r'\} else=\{\s*\n\s*set \[find name="hobe-open-webfig"\]',
            script,
        )
        assert set_block, "set branch of hobe-open-webfig add-or-set missing"

    def test_close_restores_www_ssl_to_panel_only(self):
        """hobe-close-webfig restores `address=PANEL_WG_ADDR/32` (NOT the
        ssh/winbox union — WebFig stays panel-only by design)."""
        body = self._close_source(_render(OPERATOR_ADMIN_IPS="9.9.9.9/32"))
        assert "/ip service set www-ssl address=\\\"10.99.0.1/32\\\"" in body
        # Even though operator IPs are set, www-ssl is NOT widened to the union.
        assert "9.9.9.9/32" not in body, (
            "WebFig hardened ACL must be PANEL/32 only — even when "
            "operator IPs are configured for ssh/winbox, WebFig stays "
            "panel-only as a defence-in-depth choice."
        )
        # Removes the break-glass firewall rule + scheduler.
        assert "remove [find comment=\\\"hobe-fleet-fw-break-glass-webfig\\\"]" in body
        assert "remove [find name=\\\"hobe-close-webfig-auto\\\"]" in body


# ════════════════════════════════════════════════════════════════════════
# (4) Precautions — ASCII in command positions, no underscore locals,
#     no :break/:continue in code (comments OK)
# ════════════════════════════════════════════════════════════════════════
class TestRenderedScriptHygiene:
    """Sweep the rendered output for unsafe characters / patterns in
    positions RouterOS actually parses."""

    def test_no_emdash_or_endash_in_command_positions(self):
        """Em-dash / en-dash inside :log / :put / source= / comment=
        strings can choke RouterOS. # comment lines are fine."""
        script = _render(OPERATOR_ADMIN_IPS="1.2.3.4/32")
        bad: list[tuple[int, str]] = []
        for i, line in enumerate(script.splitlines(), 1):
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            if "—" in line or "–" in line:
                bad.append((i, line[:160]))
        assert not bad, (
            "found em-/en-dash in command-position string(s):\n"
            + "\n".join(f"  L{i}: {ln}" for i, ln in bad)
        )

    def test_no_arrow_chars_in_command_positions(self):
        """Right-arrow / left-arrow in :log / :put strings — replace
        with ASCII `->` (compose-line concatenation safe)."""
        script = _render(OPERATOR_ADMIN_IPS="1.2.3.4/32")
        bad: list[tuple[int, str]] = []
        for i, line in enumerate(script.splitlines(), 1):
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            if any(ch in line for ch in "→←↑↓"):
                bad.append((i, line[:160]))
        assert not bad, (
            "found arrow char in command-position string(s):\n"
            + "\n".join(f"  L{i}: {ln}" for i, ln in bad)
        )

    def test_no_underscore_prefixed_locals_in_code(self):
        """`:local _x = ...` is a syntax error in RouterOS v7."""
        script = _render()
        non_comment = _strip_comments(script)
        for i, line in enumerate(non_comment.splitlines(), 1):
            assert not re.search(r":(local|set)\s+_", line), (
                f"L{i}: underscore-prefixed local — RouterOS rejects it: {line!r}"
            )

    def test_no_break_or_continue_in_code(self):
        """`:break` / `:continue` are rejected by RouterOS v7 inside
        nested `:if do={}` — we use flag-gated loops instead.
        Comments mentioning them as documentation are fine."""
        script = _render()
        non_comment = _strip_comments(script)
        offenders = [
            (i, l)
            for i, l in enumerate(non_comment.splitlines(), 1)
            if re.search(r":(break|continue)\b", l)
        ]
        assert not offenders, (
            ":break / :continue found in code (not # comment) lines:\n"
            + "\n".join(f"  L{i}: {ln}" for i, ln in offenders)
        )
