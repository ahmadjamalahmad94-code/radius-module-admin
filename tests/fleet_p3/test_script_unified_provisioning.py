"""feat/chr-unified-provisioning-complete — assert the unified RouterOS
provisioning script lays down EVERY service the owner asked for, with a
SURGICAL firewall that never blocks a legitimate connection, role gating
that respects the per-node ``roles_json`` column, and a self-lockout
guard that auto-reverts a broken apply.

Owner's brief (Arabic):
    «بدي سكربت برمجة كامل احطو بكل سيرفر، يبرمج ويفعّل كل شي،
     الخدمات كلها وتأمين، بما لا يسبب مشاكل»
    «خلي بالك عالفيروول، ما تحظر شي يمنع اتصالات، بدي كل شي جراحي وقوي»

Invariants pinned here (one section per test class):

    (I)   FIREWALL — every enabled service has an EXACT accept rule BEFORE
          any drop; the FINAL input rule is the drop; the management accept
          precedes any drop (no self-lockout); RADIUS + API are never
          exposed on the WAN; ICMP allowed; conntrack-untracked is the
          first match so the very SSH session running this import survives.

    (II)  ROLE GATING — each VPN service block + its firewall accept is
          emitted only when its role is enabled in ``NODE_ROLES_SET``.

    (III) SELF-LOCKOUT GUARD — §0a takes a backup + arms a scheduler; §12
          cancels it on clean completion. No backup leaks; the comment
          tag matches so the scheduler is removable on re-import.

    (IV)  IDEMPOTENCY — every new ``add`` carries a hobe-fleet-* comment
          so the regex remove at §9 sweeps it on re-import.

    (V)   SINGLE-IMPORT CONTEXT — the script never relies on cross-line
          ``:local`` bindings (the helper that uses ``:do`` blocks IS the
          one exception and is bracketed).

    (VI)  SHARED RESOURCES — the IP pool name + ranges + PPP profile name
          are FLEET-CONSTANT (same on every node ⇒ roaming/failover keeps
          the same Framed-IP and rate-limit profile).

    (VII) /24 NOT /32 — the wg-mgmt + wg-data interface addresses stay
          /24 so the connected-route gives RouterOS a working return path
          (the chr-vpn-1 incident this guards against).
"""
from __future__ import annotations

import re

import pytest

from fleet.registry.script_render import (
    _ALL_ROLES,
    render_from_bindings,
)


# ════════════════════════════════════════════════════════════════════════
# Fixture: a complete, valid bindings dict for the renderer
# ════════════════════════════════════════════════════════════════════════
_BASE: dict = {
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
    bindings = {**_BASE, **overrides}
    return render_from_bindings(bindings)


def _flatten(script: str) -> str:
    """Join RouterOS line-continuations so an assertion can match a
    single semantic statement that's split across two text lines."""
    return script.replace(" \\\n", " ")


def _input_filter_rules(script: str) -> list[str]:
    """Walk the script and collect the ordered list of /ip firewall
    filter `add` lines under the `chain=input` chain. Used by the
    rule-order invariants below."""
    out: list[str] = []
    table = None
    for raw in _flatten(script).splitlines():
        line = raw.strip()
        if line.startswith("/"):
            table = line
            continue
        if (
            table == "/ip firewall filter"
            and line.startswith("add ")
            and "chain=input" in line
        ):
            out.append(line)
    return out


# ════════════════════════════════════════════════════════════════════════
# (I) SURGICAL FIREWALL
# ════════════════════════════════════════════════════════════════════════
class TestSurgicalFirewallOrder:

    def test_catch_all_drop_is_last_on_chr(self):
        """The FINAL ``chain=input`` rule ON THE CHR must be the catch-all
        ``hobe-fleet-fw-drop-last`` drop. Every accept above it; deny
        what falls through.

        RouterOS ``place-before`` semantics: a rule added LATER in the
        script with ``place-before=[find comment="hobe-fleet-fw-drop-last"]``
        lands BEFORE drop-last on the real CHR even though it appears
        below in the text. So we walk the script text and require:
          (a) drop-last exists with the right comment,
          (b) every rule AFTER drop-last in the text uses place-before
              to anchor against it (so they end up ABOVE it on the CHR).
        """
        rules = _input_filter_rules(_render())
        assert rules, "no chain=input rules in the rendered script"
        drop_idx = next(
            (i for i, r in enumerate(rules)
             if 'comment="hobe-fleet-fw-drop-last"' in r),
            None,
        )
        assert drop_idx is not None, "missing hobe-fleet-fw-drop-last rule"
        assert "action=drop" in rules[drop_idx], (
            f"drop-last must be a drop; got: {rules[drop_idx]!r}"
        )
        for later in rules[drop_idx + 1:]:
            assert "place-before=[find comment=\"hobe-fleet-fw-drop-last\"]" in later, (
                "a rule added AFTER drop-last in the text must use "
                "place-before to anchor against it (otherwise it would "
                f"end up after the drop on the CHR): {later!r}"
            )

    def test_management_accept_precedes_catch_all_drop(self):
        """No self-lockout: the panel mgmt accept must end up BEFORE the
        catch-all drop on the CHR, otherwise a re-import severs the SSH
        session running it.

        Shape change (fix/chr-hardening-safe-firewall-order): the script
        now adds drop-last FIRST in §9, then every other rule uses
        ``place-before=[find comment="hobe-fleet-fw-drop-last"]`` to land
        ABOVE drop-last on the CHR. So in script-text order drop-last is
        at idx 0; every accept comes after AND anchors against it."""
        rules = _input_filter_rules(_render())
        mgmt = next(
            (r for r in rules if 'comment="hobe-fleet-fw-mgmt"' in r),
            None,
        )
        assert mgmt is not None, "missing hobe-fleet-fw-mgmt accept"
        assert (
            'place-before=[find comment="hobe-fleet-fw-drop-last"]' in mgmt
        ), (
            f"mgmt accept must use place-before to land above drop-last "
            f"on the CHR; got: {mgmt!r}"
        )
        # Conntrack accept also anchors above the catch-all drop.
        ct = next(r for r in rules if 'comment="hobe-fleet-fw-conntrack"' in r)
        assert (
            'place-before=[find comment="hobe-fleet-fw-drop-last"]' in ct
        ), ct

    def test_management_accept_is_scoped_to_panel_only(self):
        """Surgical ≠ broad: the mgmt rule MUST scope by both
        in-interface=wg-mgmt AND src-address=PANEL_WG_ADDR/32.
        A bare ``in-interface=wg-mgmt action=accept`` would let any
        peer on the wg-mgmt subnet through — the panel ACL is the
        defence vs a stale peer that lingers on 10.99.0.0/24."""
        rules = _input_filter_rules(_render())
        mgmt = next(
            r for r in rules if 'comment="hobe-fleet-fw-mgmt"' in r
        )
        assert "in-interface=wg-mgmt" in mgmt, mgmt
        assert "src-address=10.99.0.1/32" in mgmt, (
            f"mgmt rule must src-ACL on PANEL_WG_ADDR/32; got: {mgmt!r}"
        )

    def test_conntrack_accept_is_first_match(self):
        """Established/related/untracked accept must end up as the FIRST
        match on the CHR so the SSH session running the import survives
        the firewall rebuild.

        Shape change: drop-last is added first in §9; conntrack is the
        FIRST place-before add after it, so on the CHR conntrack lands
        just before drop-last (and every later add shifts conntrack up
        by one) ⇒ conntrack ends at the top."""
        rules = _input_filter_rules(_render())
        ct = next(
            (r for r in rules if 'comment="hobe-fleet-fw-conntrack"' in r),
            None,
        )
        assert ct is not None, "missing hobe-fleet-fw-conntrack accept"
        assert (
            'place-before=[find comment="hobe-fleet-fw-drop-last"]' in ct
        ), f"conntrack must anchor against drop-last: {ct!r}"
        assert "connection-state=established,related,untracked" in ct, ct
        # And conntrack is the FIRST place-before rule after drop-last in
        # the script text (so it ends UP at the top on the CHR).
        drop_idx = next(
            i for i, r in enumerate(rules)
            if 'comment="hobe-fleet-fw-drop-last"' in r
        )
        ct_idx = next(
            i for i, r in enumerate(rules)
            if 'comment="hobe-fleet-fw-conntrack"' in r
        )
        assert ct_idx == drop_idx + 1, (
            f"conntrack must be the first add after drop-last in script "
            f"text (drop-last @ {drop_idx}, conntrack @ {ct_idx})"
        )

    def test_radius_only_over_wg_data_never_public(self):
        """RADIUS auth/acct + CoA must accept ONLY on wg-data scoped to
        the proxy IP. The §9h drop on UDP 1812/1813/3799 catches anyone
        who sneaks a packet onto a different iface."""
        script = _render()
        rules = _input_filter_rules(script)
        radius_rule = next(
            r for r in rules if 'comment="hobe-fleet-fw-radius"' in r
        )
        assert "in-interface=wg-data" in radius_rule, radius_rule
        assert "src-address=10.98.0.1/32" in radius_rule
        assert "dst-port=1812,1813" in radius_rule
        # And the public-RADIUS drop survives.
        no_pub = next(
            r for r in rules if "hobe-fleet-fw-no-public-radius" in r
        )
        assert "action=drop" in no_pub
        assert "1812,1813,3799" in no_pub

    def test_every_enabled_service_has_an_explicit_accept(self):
        """No implicit allow — every enabled service must have a
        ports/proto-exact accept rule with the matching role tag."""
        rules = _input_filter_rules(_render())
        comments = " | ".join(rules)
        # All roles enabled by default in the test fixture.
        for tag in (
            "hobe-fleet-fw-mgmt",            # mgmt
            "hobe-fleet-fw-radius",          # RADIUS over wg-data
            "hobe-fleet-fw-coa",             # CoA over wg-data
            "hobe-fleet-fw-wg-mgmt-udp",     # wg-mgmt handshake on WAN
            "hobe-fleet-fw-wg-data-udp",     # wg-data handshake on WAN
            "hobe-fleet-fw-sstp",            # SSTP 443/tcp
            "hobe-fleet-fw-pptp-ctrl",       # PPTP 1723/tcp
            "hobe-fleet-fw-pptp-data",       # GRE proto47
            "hobe-fleet-fw-ike",             # IKEv2 500,4500/udp
            "hobe-fleet-fw-esp",             # ESP proto50
            "hobe-fleet-fw-l2tp",            # L2TP 1701/udp
            "hobe-fleet-fw-wg-users",        # user-WG UDP
            "hobe-fleet-fw-icmp",            # sane ICMP
            "hobe-fleet-fw-conntrack",       # conntrack accept
        ):
            assert tag in comments, f"missing accept tagged {tag!r}"

    def test_pptp_accepts_carry_correct_protocols(self):
        rules = _input_filter_rules(_render())
        pptp_ctrl = next(
            r for r in rules if 'comment="hobe-fleet-fw-pptp-ctrl"' in r
        )
        pptp_data = next(
            r for r in rules if 'comment="hobe-fleet-fw-pptp-data"' in r
        )
        assert "protocol=tcp" in pptp_ctrl and "dst-port=1723" in pptp_ctrl
        assert "protocol=gre" in pptp_data

    def test_ipsec_accepts_cover_ike_esp_l2tp(self):
        rules = _input_filter_rules(_render())
        ike = next(r for r in rules if 'comment="hobe-fleet-fw-ike"' in r)
        esp = next(r for r in rules if 'comment="hobe-fleet-fw-esp"' in r)
        l2tp = next(r for r in rules if 'comment="hobe-fleet-fw-l2tp"' in r)
        assert "protocol=udp" in ike and "dst-port=500,4500" in ike
        assert "protocol=ipsec-esp" in esp
        assert "protocol=udp" in l2tp and "dst-port=1701" in l2tp

    def test_wg_users_accept_uses_configured_port(self):
        script = _render(WG_USERS_PORT=51822)
        rules = _input_filter_rules(script)
        wg = next(r for r in rules if 'comment="hobe-fleet-fw-wg-users"' in r)
        assert "protocol=udp" in wg and "dst-port=51822" in wg

    def test_api_accept_is_wg_mgmt_only_with_panel_acl(self):
        rules = _input_filter_rules(_render())
        api = next(r for r in rules if 'comment="hobe-fleet-fw-api-ssl"' in r)
        assert "in-interface=wg-mgmt" in api
        assert "src-address=10.99.0.1/32" in api
        assert "dst-port=8443" in api
        assert "protocol=tcp" in api
        # The §11 API rule is added AFTER §9 drop-last in script text,
        # so it uses place-before to land ABOVE drop-last on the CHR.
        assert (
            'place-before=[find comment="hobe-fleet-fw-drop-last"]' in api
        ), (
            "api-ssl rule must anchor against drop-last via place-before "
            f"or it lands AFTER the drop on the CHR: {api!r}"
        )

    def test_no_public_exposure_of_routeros_api_or_radius(self):
        """The RouterOS REST API + RADIUS ports must NEVER be open on the
        WAN interface. Asserted by walking every input accept and
        checking the WAN ones don't carry these dst-ports."""
        rules = _input_filter_rules(_render())
        wan_accepts = [
            r for r in rules
            if "in-interface=ether1" in r and "action=accept" in r
        ]
        forbidden_ports = ("1812", "1813", "3799", "8443")
        for rule in wan_accepts:
            for port in forbidden_ports:
                # Look for the exact port as a token after dst-port=.
                m = re.search(r"dst-port=([\d,]+)", rule)
                if m:
                    parts = m.group(1).split(",")
                    assert port not in parts, (
                        f"WAN accept exposes forbidden port {port}: {rule!r}"
                    )


# ════════════════════════════════════════════════════════════════════════
# (II) ROLE GATING — service blocks + firewall rules respect roles
# ════════════════════════════════════════════════════════════════════════
class TestRoleGating:

    def test_pure_radius_node_skips_vpn_services_and_their_accepts(self):
        """A node with ONLY radius_transport should NOT enable any VPN
        server OR open any VPN port in the firewall."""
        script = _render(NODE_ROLES_SET=frozenset({"radius_transport"}))
        rules_text = " | ".join(_input_filter_rules(script))
        # Radius itself is still there.
        assert "hobe-fleet-fw-radius" in rules_text
        # But no VPN service accepts.
        for tag in (
            "hobe-fleet-fw-sstp",
            "hobe-fleet-fw-pptp-ctrl",
            "hobe-fleet-fw-pptp-data",
            "hobe-fleet-fw-ike",
            "hobe-fleet-fw-esp",
            "hobe-fleet-fw-l2tp",
            "hobe-fleet-fw-wg-users",
        ):
            assert tag not in rules_text, f"{tag} leaked into radius-only node"
        # And the VPN server blocks themselves are skipped.
        assert "set enabled=yes default-profile=hobe-fleet-default \n    keepalive-timeout=30" not in script
        assert "/interface pptp-server server\nset enabled=no" in script
        assert "/interface sstp-server server\nset enabled=no" in script

    def test_pure_sstp_node_skips_other_vpns(self):
        script = _render(NODE_ROLES_SET=frozenset({"vpn_sstp"}))
        rules_text = " | ".join(_input_filter_rules(script))
        assert "hobe-fleet-fw-sstp" in rules_text
        for tag in (
            "hobe-fleet-fw-pptp-ctrl",
            "hobe-fleet-fw-ike",
            "hobe-fleet-fw-l2tp",
            "hobe-fleet-fw-wg-users",
            "hobe-fleet-fw-radius",
        ):
            assert tag not in rules_text, f"{tag} leaked into sstp-only node"
        # PPTP server set to disabled.
        assert "/interface pptp-server server\nset enabled=no" in script

    def test_empty_roles_treated_as_all_roles_enabled(self):
        """Back-compat: an empty roles list ⇒ all roles enabled.
        Mirrors app.services.node_roles.enabled_roles."""
        # We bypass enabled_roles by passing an explicit frozenset of all
        # roles (what _resolve_node_roles returns for empty roles_json).
        script = _render(NODE_ROLES_SET=frozenset(_ALL_ROLES))
        rules_text = " | ".join(_input_filter_rules(script))
        for tag in (
            "hobe-fleet-fw-radius",
            "hobe-fleet-fw-sstp",
            "hobe-fleet-fw-pptp-ctrl",
            "hobe-fleet-fw-ike",
            "hobe-fleet-fw-l2tp",
            "hobe-fleet-fw-wg-users",
        ):
            assert tag in rules_text, f"all-roles-enabled missing {tag}"


# ════════════════════════════════════════════════════════════════════════
# (III) SELF-LOCKOUT GUARD
# ════════════════════════════════════════════════════════════════════════
class TestSelfLockoutGuard:

    def test_pre_apply_backup_is_taken(self):
        script = _render()
        assert '/system backup save name="hobe-fleet-pre-apply"' in script

    def test_rollback_scheduler_armed_with_correct_delay(self):
        script = _render(SAFEMODE_ROLLBACK_DELAY="3m")
        # Scheduler armed.
        assert '/system scheduler' in script
        assert 'add name="hobe-fleet-rollback" interval=3m' in _flatten(script)

    def test_rollback_scheduler_is_cancelled_at_end(self):
        """The very last block must remove the scheduler, otherwise a
        clean run would still trigger a rollback."""
        script = _render()
        # Both armed AND cancelled present.
        arm_idx = script.index('add name="hobe-fleet-rollback"')
        cancel_idx = script.index(
            '/system scheduler remove [find name="hobe-fleet-rollback"]'
        )
        assert arm_idx < cancel_idx, (
            "arm must precede cancel — otherwise a clean run rolls back"
        )

    def test_rollback_event_loads_the_backup(self):
        script = _render()
        # The on-event runs the backup load.
        assert "/system backup load name=hobe-fleet-pre-apply" in script

    def test_pre_apply_backup_file_removed_after_cancel(self):
        """Tidy-up: the snapshot file is removed on a clean run so the
        next provisioning starts with a fresh snapshot."""
        script = _render()
        assert (
            '/file remove [find name="hobe-fleet-pre-apply.backup"]'
            in script
        )


# ════════════════════════════════════════════════════════════════════════
# (IV) IDEMPOTENCY — comment tags + remove sweep
# ════════════════════════════════════════════════════════════════════════
class TestIdempotency:

    def test_every_new_firewall_rule_carries_hobe_tag(self):
        rules = _input_filter_rules(_render())
        for rule in rules:
            assert 'comment="hobe-fleet-fw-' in rule, (
                f"untagged input rule — won't be swept on re-import: {rule!r}"
            )

    def test_regex_remove_sweeps_every_new_tag(self):
        """The one remove statement at top of §9 catches every new
        comment tag introduced by feat/chr-unified-provisioning-complete."""
        script = _render()
        assert 'remove [find comment~"^hobe-fleet-fw-"]' in script

    def test_pool_and_profile_are_idempotent(self):
        script = _render()
        # /ip pool remove before add.
        assert 'remove [find name~"^hobe-fleet-pool"]' in script
        # PPP profile remove before add.
        assert 'remove [find comment="hobe-fleet-ppp"]' in script
        # User-WG interface remove before add.
        assert 'remove [find name="wg-users"]' in script

    def test_rollback_scheduler_remove_before_add(self):
        script = _render()
        rem_idx = script.index('remove [find name="hobe-fleet-rollback"]')
        add_idx = script.index('add name="hobe-fleet-rollback"')
        assert rem_idx < add_idx, "must remove prior scheduler before re-arming"


# ════════════════════════════════════════════════════════════════════════
# (V) SINGLE-IMPORT CONTEXT — no cross-line `:local` leak
# ════════════════════════════════════════════════════════════════════════
class TestSingleImportContext:

    def test_no_top_level_local_breaks_endpoint_resolve(self):
        """The :local hobeResolve binding lives inside a do-block; if a
        future edit hoists :local panelIP / proxyIP to a context that
        an interactive `:` could swallow, :resolve would silently lose
        scope (the known live bug). We assert :local panelIP is followed
        by a `/interface wireguard peers` block within the same script
        text (i.e. flat script, no `:put` interleaving).
        """
        script = _render()
        # :local panelIP exists.
        assert ":local panelIP" in script
        # And the wg-mgmt peer is updated right after with the variable.
        idx = script.index(":local panelIP")
        following = script[idx: idx + 400]
        assert "endpoint-address=$panelIP" in following


# ════════════════════════════════════════════════════════════════════════
# (VI) SHARED RESOURCES — one source of truth for pool + profile
# ════════════════════════════════════════════════════════════════════════
class TestSharedResources:

    def test_ip_pool_uses_fleet_constant_name(self):
        script = _render(IP_POOL_NAME="hobe-fleet-pool",
                         IP_POOL_RANGES="10.50.0.10-10.50.255.254")
        assert 'add name="hobe-fleet-pool" ranges="10.50.0.10-10.50.255.254"' in script

    def test_ppp_profile_references_shared_pool(self):
        script = _render(PPP_PROFILE_NAME="hobe-fleet-default",
                         IP_POOL_NAME="hobe-fleet-pool")
        assert 'add name="hobe-fleet-default"' in script
        assert 'remote-address="hobe-fleet-pool"' in script

    def test_l2tp_server_uses_central_psk(self):
        """L2TP/IPsec server's PSK is the same central CHR_SHARED_SECRET
        — one source of truth, never a per-CHR secret."""
        script = _render()
        flat = _flatten(script)
        assert "/interface l2tp-server server" in flat
        assert 'ipsec-secret="kla0FAzDKNJGoGIXdpDaCKB4Q2ytm-txZZZ_strongsecret"' in flat


# ════════════════════════════════════════════════════════════════════════
# (VII) /24 NOT /32 — wg interface addresses stay /24
# ════════════════════════════════════════════════════════════════════════
class TestWgInterfaceMask:

    def test_wg_mgmt_address_is_slash_24(self):
        script = _render(WG_MGMT_ADDR="10.99.0.11/24")
        assert "add interface=wg-mgmt address=10.99.0.11/24" in script

    def test_wg_data_address_is_slash_24(self):
        script = _render(WG_DATA_ADDR="10.98.0.11/24")
        assert "add interface=wg-data address=10.98.0.11/24" in script

    def test_wg_users_address_is_slash_24(self):
        """User-WG interface needs the connected-route too — a /32
        leaves the CHR with no return path to its own pool."""
        script = _render(WG_USERS_ADDR="10.51.0.1/24")
        assert "add interface=wg-users address=10.51.0.1/24" in script


# ════════════════════════════════════════════════════════════════════════
# Smoke: every Jinja placeholder is substituted; quote balance holds
# ════════════════════════════════════════════════════════════════════════
class TestRenderSmoke:

    def test_no_unsubstituted_jinja_in_output(self):
        out = _render()
        assert "{{" not in out and "}}" not in out
        assert "{%" not in out and "%}" not in out

    def test_quote_balance_on_every_line(self):
        for lineno, line in enumerate(_render().splitlines(), start=1):
            assert line.count('"') % 2 == 0, (
                f"L{lineno} has odd number of double-quotes: {line!r}"
            )

    def test_renders_with_explicit_role_subsets(self):
        for roles in [
            frozenset({"radius_transport"}),
            frozenset({"vpn_sstp"}),
            frozenset({"vpn_pptp"}),
            frozenset({"vpn_ipsec"}),
            frozenset({"vpn_wireguard"}),
            frozenset({"radius_transport", "vpn_sstp"}),
            frozenset(_ALL_ROLES),
        ]:
            script = _render(NODE_ROLES_SET=roles)
            assert script  # didn't raise; lines emitted
            assert "{{" not in script and "}}" not in script
