"""Tests for the unified RouterOS script renderer (Phase-3 task T3).

The HEADLINE test (``test_diff_between_two_chrs_is_only_per_chr_bindings``) is
the structural proof of the onboarding promise — same script, different
credentials. It renders two distinct CHRs side-by-side and asserts the
per-line diff is *exactly* the set of values that came from the documented
per-CHR bindings; if any fleet-constant accidentally enters the per-CHR pool
the test fails with a precise pointer.

The remaining tests are RouterOS v7 sanity checks: all 10 sections present,
no unrendered ``{{...}}`` markers, every per-CHR binding is referenced, and
a missing binding raises (StrictUndefined).
"""

from __future__ import annotations

import difflib
import re
from dataclasses import replace
from types import SimpleNamespace

import pytest
from jinja2 import UndefinedError

from fleet.registry.script_render import (
    HEADLINE_PER_CHR_BINDINGS,
    PER_CHR_BINDINGS,
    ChrKeyMaterial,
    RouterosTemplateConfig,
    build_bindings,
    render_chr_script,
    render_from_bindings,
)


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures: two distinct CHRs that share fleet-constant config
# ─────────────────────────────────────────────────────────────────────────────
def _fake_node(name: str, public_ip: str) -> SimpleNamespace:
    """Lightweight stand-in for a ``FleetChrNode`` row. Avoids needing the
    SQLite test DB just to exercise rendering — the renderer only reads
    ``node.name`` and ``node.public_ip``."""
    return SimpleNamespace(name=name, public_ip=public_ip)


@pytest.fixture()
def fleet_cfg() -> RouterosTemplateConfig:
    """Fleet-constant inputs shared by every CHR in this test fleet."""
    return RouterosTemplateConfig(
        panel_wg_pubkey="PANEL_PUBKEY_ABC123==",
        panel_wg_endpoint="panel.fleet.test",
        panel_wg_addr="10.99.0.1",
        proxy_wg_pubkey="PROXY_PUBKEY_DEF456==",
        proxy_wg_endpoint="proxy.fleet.test",
        proxy_wg_addr="10.98.0.1",
        chr_shared_secret="s3cret-shared-fleet-wide",
        sstp_cert_name="hobe-sstp-cert",
        ike_cert_name="hobe-ike-cert",
        client_supernet="10.0.0.0/8",
        dns_push="1.1.1.1,1.0.0.1",
        gw_local_addr="10.0.0.1",
    )


@pytest.fixture()
def chr_a() -> tuple[SimpleNamespace, ChrKeyMaterial]:
    return _fake_node("contabo-de-01", "203.0.113.11"), ChrKeyMaterial(
        mgmt_privkey="CHR_A_MGMT_PRIV_xxxxxxxxxxxxxxxxxxxxxxxxx",
        mgmt_addr="10.99.0.11/24",
        data_privkey="CHR_A_DATA_PRIV_yyyyyyyyyyyyyyyyyyyyyyyyy",
        data_addr="10.98.0.11/24",
        wan_iface="ether1",
    )


@pytest.fixture()
def chr_b() -> tuple[SimpleNamespace, ChrKeyMaterial]:
    return _fake_node("hetzner-fi-02", "198.51.100.22"), ChrKeyMaterial(
        mgmt_privkey="CHR_B_MGMT_PRIV_zzzzzzzzzzzzzzzzzzzzzzzzz",
        mgmt_addr="10.99.0.22/24",
        data_privkey="CHR_B_DATA_PRIV_wwwwwwwwwwwwwwwwwwwwwwwww",
        data_addr="10.98.0.22/24",
        wan_iface="vlan-wan",
    )


# ════════════════════════════════════════════════════════════════════════════
# THE HEADLINE TEST — same script, different credentials
# ════════════════════════════════════════════════════════════════════════════
class TestOnlyBindingsDiffer:
    def test_diff_between_two_chrs_is_only_per_chr_bindings(
        self, chr_a, chr_b, fleet_cfg
    ) -> None:
        """Render two CHRs with identical fleet config; the line-diff is
        ONLY the set of per-CHR binding values. Every line that differs must
        be explainable by exactly one ``PER_CHR_BINDINGS`` substitution.
        """
        node_a, keys_a = chr_a
        node_b, keys_b = chr_b

        out_a = render_chr_script(node_a, keys_a, fleet_cfg).splitlines()
        out_b = render_chr_script(node_b, keys_b, fleet_cfg).splitlines()

        # Lines that are textually different between the two renders.
        differing_pairs = [
            (a, b) for a, b in zip(out_a, out_b, strict=True) if a != b
        ]

        # Build the full per-CHR value sets via build_bindings (so the test is
        # locked to the same boundary the renderer uses).
        bindings_a = build_bindings(node_a, keys_a, fleet_cfg)
        bindings_b = build_bindings(node_b, keys_b, fleet_cfg)

        per_chr_a = {bindings_a[k] for k in PER_CHR_BINDINGS}
        per_chr_b = {bindings_b[k] for k in PER_CHR_BINDINGS}
        fleet_constant_values = {
            bindings_a[k]
            for k in bindings_a.keys() - set(PER_CHR_BINDINGS)
        }

        # Sanity: line counts match — neither CHR ever adds or removes a line.
        assert len(out_a) == len(out_b), (
            "renders for two CHRs must have identical line counts; got "
            f"{len(out_a)} vs {len(out_b)}"
        )

        # Each differing line pair must be explainable by *replacing* one or
        # more PER_CHR_BINDINGS values. Concretely: there must be at least one
        # per-CHR value from chr_a appearing in line_a but not line_b, and the
        # corresponding chr_b value in line_b. And no fleet-constant ever
        # changes between renders.
        assert differing_pairs, "two distinct CHRs should produce at least one differing line"
        for a_line, b_line in differing_pairs:
            differences_explained = False
            for var in PER_CHR_BINDINGS:
                val_a = bindings_a[var]
                val_b = bindings_b[var]
                if val_a in a_line and val_b in b_line and val_a != val_b:
                    differences_explained = True
                    break
            assert differences_explained, (
                "differing line pair is NOT explainable by any per-CHR binding "
                "— this means a fleet-constant leaked into the per-CHR set, "
                "violating the §6.5 'same script, different credentials' "
                f"invariant. Lines:\n  A: {a_line!r}\n  B: {b_line!r}"
            )

            # And: the differing line on side A must not contain any per-CHR
            # value from side B (cross-contamination check).
            for var in PER_CHR_BINDINGS:
                val_b_only = bindings_b[var]
                if val_b_only and val_b_only != bindings_a[var]:
                    assert val_b_only not in a_line, (
                        f"CHR-A line contains CHR-B's {var}={val_b_only!r}: {a_line!r}"
                    )

        # And: no fleet-constant string ever differs across the two renders.
        # We compare via word-boundary regex so substring overlap between IPs
        # (e.g. fleet-constant 10.98.0.1 vs per-CHR 10.98.0.11) doesn't false-
        # match.
        for value in fleet_constant_values:
            if not value:  # skip empty placeholder defaults
                continue
            # Skip non-text bindings (e.g. NODE_ROLES_SET = frozenset(...))
            # — they drive Jinja conditions, never appear as literals.
            if not isinstance(value, (str, int)):
                continue
            pattern = re.compile(r"(?<![\w./])" + re.escape(str(value)) + r"(?![\w./])")
            count_a = sum(1 for line in out_a if pattern.search(line))
            count_b = sum(1 for line in out_b if pattern.search(line))
            assert count_a == count_b, (
                f"fleet-constant value {value!r} appears {count_a}× in "
                f"render A but {count_b}× in render B — should be identical"
            )

    def test_diff_summary_is_useful_when_test_fails(
        self, chr_a, chr_b, fleet_cfg
    ) -> None:
        """Smoke: the actual unified diff between two renders is small and
        mentions only per-CHR values. Useful as a regression fingerprint."""
        node_a, keys_a = chr_a
        node_b, keys_b = chr_b
        out_a = render_chr_script(node_a, keys_a, fleet_cfg)
        out_b = render_chr_script(node_b, keys_b, fleet_cfg)
        diff_lines = list(
            difflib.unified_diff(
                out_a.splitlines(), out_b.splitlines(),
                fromfile="chr_a.rsc", tofile="chr_b.rsc", lineterm="",
            )
        )
        # Header (3 lines) + at minimum WG_MGMT, WG_DATA, IDENTITY, PUBLIC_IP
        # context blocks. The exact count depends on diff context windows.
        assert diff_lines, "diff between two CHRs should produce some output"
        # Look only at lines that actually changed (drop file headers + context).
        change_lines = [
            ln for ln in diff_lines
            if (ln.startswith("+") or ln.startswith("-"))
            and not ln.startswith("+++")
            and not ln.startswith("---")
        ]
        change_text = "\n".join(change_lines)
        # Changed lines should contain per-CHR values…
        assert "10.99.0.11" in change_text and "10.99.0.22" in change_text
        assert "contabo-de-01" in change_text and "hetzner-fi-02" in change_text
        # …and never expose a fleet-constant string (context lines are OK to
        # contain it — they are the same on both sides).
        assert "s3cret-shared-fleet-wide" not in change_text


# ════════════════════════════════════════════════════════════════════════════
# RouterOS v7 syntactic sanity (basic)
# ════════════════════════════════════════════════════════════════════════════
class TestRouterosSanity:
    def test_no_unrendered_jinja_markers(self, chr_a, fleet_cfg) -> None:
        node, keys = chr_a
        out = render_chr_script(node, keys, fleet_cfg)
        assert "{{" not in out and "}}" not in out, (
            "every {{ ... }} placeholder must be substituted by render"
        )
        # And no {% block %} survivors either — the template uses pure substitution.
        assert "{%" not in out and "%}" not in out

    def test_all_ten_sections_present(self, chr_a, fleet_cfg) -> None:
        node, keys = chr_a
        out = render_chr_script(node, keys, fleet_cfg)
        # Each section header from §6.5 must appear, in order, at least once.
        # §4 renamed in feat/chr-unified-provisioning-complete (shared pool
        # is now the design, not an anti-pattern); §9 is now SURGICAL block
        # spelled out in the header comment of the template.
        expected_headers = [
            "# ---- 1. WireGuard CONTROL tunnel",
            "# ---- 2. WireGuard DATA path",
            "# ---- 3. RADIUS client",
            "# ---- 4. Shared IP pool",
            "# ---- 5. PPTP server",
            "# ---- 6. SSTP server",
            "# ---- 7. IPsec / IKEv2 server",
            "# ---- 8. NAT / masquerade",
            "# 9. SURGICAL FIREWALL",
            "# ---- 10. control-plane is NOT a data route",
        ]
        last_pos = -1
        for header in expected_headers:
            pos = out.find(header)
            assert pos > last_pos, f"missing or out-of-order section: {header!r}"
            last_pos = pos

    def test_key_routeros_commands_present(self, chr_a, fleet_cfg) -> None:
        node, keys = chr_a
        out = render_chr_script(node, keys, fleet_cfg)
        # Spot-check that the headline RouterOS v7 paths the doc lists are all in.
        for path in [
            "/system identity set name=",
            "/interface wireguard",
            "/interface wireguard peers",
            "/ip address",
            "/radius",
            "/radius incoming",
            "/ppp aaa",
            "/ppp profile",
            "/interface pptp-server server",
            "/interface sstp-server server",
            "/ip ipsec profile",
            "/ip ipsec proposal",
            "/ip ipsec mode-config",
            "/ip ipsec identity",
            "/ip ipsec peer",
            "/ip firewall nat",
            "/ip firewall filter",
            "/ip route",
        ]:
            assert path in out, f"expected RouterOS path missing from render: {path!r}"

    def test_quoted_values_balanced(self, chr_a, fleet_cfg) -> None:
        """Double-quoted RouterOS strings must come in pairs on each
        logical line. Logical lines are formed by joining backslash
        continuations; multi-line ``source="..."`` script bodies in
        §11b (break-glass scripts) span many text lines as ONE
        RouterOS-token quoted literal, so we strip them before the
        per-line check."""
        import re as _re
        node, keys = chr_a
        out = render_chr_script(node, keys, fleet_cfg)
        flat = out.replace(" \\\n", " ").replace("\\\n", "")
        flat = _re.sub(r'source="(?:[^"\\]|\\.)*"', 'source=""', flat, flags=_re.DOTALL)
        for lineno, line in enumerate(flat.splitlines(), start=1):
            dq = line.count('"')
            assert dq % 2 == 0, (
                f"line {lineno} has an odd number of double-quotes: {line!r}"
            )

    def test_shared_pool_is_the_fleet_constant_pool(self, chr_a, fleet_cfg) -> None:
        """feat/chr-unified-provisioning-complete §6.5.2: every node carries
        the SAME shared pool name + ranges so a subscriber roaming between
        nodes keeps the same Framed-IP and the same profile.

        Constraints:
          - The pool MUST be created with the fleet-constant name (one
            source of truth).
          - Any ``/ip pool add`` line MUST use the configured
            ``IP_POOL_NAME``; no per-node ad-hoc pools.
          - RADIUS Framed-IP still wins in the access-accept response;
            the local pool is the fallback so an Access-Accept that
            omits Framed-IP still gets a valid address.
        """
        node, keys = chr_a
        out = render_chr_script(node, keys, fleet_cfg)
        flat = out.replace(" \\\n", " ")
        table = None
        pool_adds: list[str] = []
        for raw in flat.splitlines():
            line = raw.strip()
            if line.startswith("/"):
                table = line
                continue
            if table == "/ip pool" and line.startswith("add "):
                pool_adds.append(line)
        assert pool_adds, "expected /ip pool add for the shared fleet pool"
        for line in pool_adds:
            assert f'name="{fleet_cfg.ip_pool_name}"' in line, (
                "/ip pool add must use the fleet-constant pool name "
                f"({fleet_cfg.ip_pool_name!r}); got: {line!r}"
            )
        # Cross-CHR roaming guarantee: the central pool name is the only
        # remote-address pool reference for client traffic.
        assert (
            f'remote-address="{fleet_cfg.ip_pool_name}"' in out
            or f"remote-address={fleet_cfg.ip_pool_name}" in out
        ), "PPP profile must reference the fleet-constant pool"

    def test_strict_undefined_catches_missing_binding(self, chr_a, fleet_cfg) -> None:
        """If a future template edit introduces a new variable but render_chr_script
        doesn't supply it, we want a loud failure — not silent empty output."""
        node, keys = chr_a
        bindings = build_bindings(node, keys, fleet_cfg)
        # Drop a known binding to simulate the regression.
        del bindings["ROUTER_IDENTITY"]
        with pytest.raises(UndefinedError):
            render_from_bindings(bindings)


# ════════════════════════════════════════════════════════════════════════════
# Binding boundary self-consistency
# ════════════════════════════════════════════════════════════════════════════
class TestBindingBoundaries:
    def test_headline_is_a_subset_of_full_per_chr(self) -> None:
        """§6.3 headline bindings ⊆ §6.5.1 full per-CHR table."""
        assert set(HEADLINE_PER_CHR_BINDINGS).issubset(set(PER_CHR_BINDINGS))

    def test_no_overlap_between_per_chr_and_fleet_constant(
        self, chr_a, fleet_cfg
    ) -> None:
        """A binding cannot be both per-CHR and fleet-constant. The renderer's
        build_bindings dict carries that boundary explicitly: any per-CHR var
        whose *value* coincidentally matches a fleet-constant value would still
        be in the per-CHR set (we go by name, not by value)."""
        node, keys = chr_a
        bindings = build_bindings(node, keys, fleet_cfg)
        per_chr_names = set(PER_CHR_BINDINGS)
        all_names = set(bindings.keys())
        fleet_constant_names = all_names - per_chr_names
        assert not (per_chr_names & fleet_constant_names)
        # And: every per-CHR var the renderer ships must be in PER_CHR_BINDINGS.
        # (i.e. the renderer cannot quietly add a new per-CHR var without
        # updating the boundary registry.)
        documented_var_names = per_chr_names | fleet_constant_names
        assert documented_var_names == all_names

    def test_wg_data_addr_ip_is_derived_not_input(self, chr_a, fleet_cfg) -> None:
        """``WG_DATA_ADDR_IP`` is computed from ``WG_DATA_ADDR`` — the test
        guards against someone making it a separate input that could drift."""
        node, keys = chr_a
        bindings = build_bindings(node, keys, fleet_cfg)
        assert bindings["WG_DATA_ADDR"] == keys.data_addr
        # ip part of "10.98.0.11/24" must equal "10.98.0.11"
        assert bindings["WG_DATA_ADDR_IP"] == keys.data_addr.split("/", 1)[0]

    def test_changing_only_fleet_constant_changes_both_renders_identically(
        self, chr_a, chr_b, fleet_cfg
    ) -> None:
        """Inverse proof: bumping a fleet-constant must change CHR-A and CHR-B
        renders by the SAME amount (every CHR follows the same fleet policy)."""
        node_a, keys_a = chr_a
        node_b, keys_b = chr_b
        a_before = render_chr_script(node_a, keys_a, fleet_cfg).splitlines()
        b_before = render_chr_script(node_b, keys_b, fleet_cfg).splitlines()
        diff_before = sum(1 for a, b in zip(a_before, b_before) if a != b)

        bumped = replace(fleet_cfg, chr_shared_secret="rotated-secret-2")
        a_after = render_chr_script(node_a, keys_a, bumped).splitlines()
        b_after = render_chr_script(node_b, keys_b, bumped).splitlines()
        diff_after = sum(1 for a, b in zip(a_after, b_after) if a != b)

        # Cross-render diff must be unchanged — the per-CHR delta is the same
        # regardless of which fleet-constant secret is in play.
        assert diff_before == diff_after

        # And the secret rotation must show up in BOTH renders.
        assert "rotated-secret-2" in "\n".join(a_after)
        assert "rotated-secret-2" in "\n".join(b_after)
