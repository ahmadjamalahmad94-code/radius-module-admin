"""fix/script-service-get-guard-foreach — /ip service get must use the
foreach-skip-dynamic resolver, never raw `find name=`.

REFINED root cause (owner's live diagnosis on chr-vpn-2):
  ``[find name=winbox]`` was NOT empty — it returned MULTIPLE items:
  the STATIC service row AND a DYNAMIC current-connection row (the
  operator was actively connected via WinBox at the moment of import,
  visible as ``15 D c name=winbox ... remote=...`` in ``/ip service
  print``). ``/ip service get`` against a multi-item ref raises
  «invalid internal item number» exactly like the empty-find case,
  and ``:do {} on-error={}`` does NOT catch it. So the previous
  ``[:len $ref] > 0`` guard is INSUFFICIENT — multi-match still halts
  the script.

RouterOS-safe pattern (the only correct shape for /ip service):
    :local svc ""
    :foreach s in=[/ip service find] do={
        :do {
            :if ([/ip service get $s name] = "winbox") do={
                :if ([:tostr [/ip service get $s dynamic]] != "true") do={
                    :set svc $s
                }
            }
        } on-error={}
    }
    :if ([:len [:tostr $svc]] > 0) do={
        :local addr [/ip service get $svc address]
        ... use it ...
    }

This test renders the full script + asserts:
  * NO ``/ip service get`` ever wraps a raw ``[find ...]`` expression
    (the multi-match landmine);
  * every ``/ip service get`` call binds to a foreach-loop variable
    (``$s``) or a foreach-captured static ref;
  * the foreach-skip-dynamic block IS present (so we can't accidentally
    delete the safety harness and still pass).

Wireguard ``find`` callers are pinned by sibling tests because they
target peers/interfaces, not /ip service (no dynamic connection rows
to multi-match against). The length-guard pattern remains correct
there.

See docs/fleet/CHR_PROVISIONING_SERVICE_LOOKUP_BUG.md.
"""
from __future__ import annotations

import re
from types import SimpleNamespace

import pytest

from fleet.registry.script_render import (
    ChrKeyMaterial,
    RouterosTemplateConfig,
    render_chr_script,
)


# ════════════════════════════════════════════════════════════════════════
# Helpers — mint a render-able fleet config + two CHRs
# ════════════════════════════════════════════════════════════════════════


def _fake_node(name: str, public_ip: str) -> SimpleNamespace:
    return SimpleNamespace(name=name, public_ip=public_ip)


@pytest.fixture()
def fleet_cfg() -> RouterosTemplateConfig:
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


def _keys(name_prefix: str) -> ChrKeyMaterial:
    return ChrKeyMaterial(
        mgmt_privkey=f"{name_prefix}_MGMT_PRIV_xxxxxxxxxxxxxxxxxxxxxxx",
        mgmt_addr="10.99.0.42/24",
        data_privkey=f"{name_prefix}_DATA_PRIV_yyyyyyyyyyyyyyyyyyyyyyy",
        data_addr="10.98.0.42/24",
        wan_iface="ether1",
    )


def _render(fleet_cfg: RouterosTemplateConfig) -> str:
    node = _fake_node("chr-guard-test", "203.0.113.42")
    return render_chr_script(node, _keys("CHR_GUARD"), fleet_cfg)


# ════════════════════════════════════════════════════════════════════════
# (1) THE HEADLINE — no `get [find ...]` survives in the rendered script
# ════════════════════════════════════════════════════════════════════════
class TestNoUnguardedGetFind:

    def test_rendered_script_has_no_get_find_pattern(self, fleet_cfg):
        """``get [find ...]`` is the EXACT shape that halted the live
        import. The guarded shape is ``find …`` into a local + a
        separate ``get $local`` guarded by ``[:len $local] > 0``."""
        script = _render(fleet_cfg)
        offenders = [
            (i + 1, line)
            for i, line in enumerate(script.splitlines())
            if re.search(r"get\s*\[\s*find\b", line)
        ]
        assert offenders == [], (
            "rendered script contains `get [find ...]` which halts "
            "RouterOS with «invalid internal item number» when the "
            "find returns empty (NOT catchable by :do on-error). "
            "Replace with a length-guarded `:local ref [... find ...]; "
            ":if ([:len $ref] > 0) do={ ... get $ref ... }` shape. "
            f"Offending lines:\n" + "\n".join(
                f"  L{n}: {l!r}" for n, l in offenders[:20]
            )
        )


# ════════════════════════════════════════════════════════════════════════
# (2) Defence-in-depth — every guarded site uses the documented shape
# ════════════════════════════════════════════════════════════════════════
class TestGuardShape:

    def test_no_get_wraps_raw_find_for_ip_service(self, fleet_cfg):
        """REFINED contract — /ip service get [find ...] must NEVER
        appear. That's the exact multi-match landmine that halted
        chr-vpn-2's import (static service row + dynamic connection
        row → multi-item ref → invalid internal item number)."""
        script = _render(fleet_cfg)
        offenders = [
            (i + 1, line)
            for i, line in enumerate(script.splitlines())
            if re.search(r"/ip service get \[\s*find\b", line)
        ]
        assert offenders == [], (
            "/ip service get [find ...] survives in the rendered script "
            "— this is the multi-match landmine. Replace with the "
            "foreach-skip-dynamic harness. Offending lines:\n"
            + "\n".join(f"  L{n}: {l!r}" for n, l in offenders[:20])
        )

    def test_foreach_skip_dynamic_resolver_present(self, fleet_cfg):
        """The walk over /ip service find filtering out dynamic
        connection rows MUST appear in the rendered script — without
        it any /ip service get becomes a multi-match landmine."""
        script = _render(fleet_cfg)
        assert ":foreach s in=[/ip service find] do=" in script, (
            "the foreach-skip-dynamic resolver for /ip service is "
            "missing from the rendered script"
        )
        assert "/ip service get $s dynamic" in script, (
            "the dynamic-skip predicate (`get $s dynamic` != true) is "
            "missing — the foreach without it doesn't solve multi-match"
        )

    def test_ip_service_get_only_binds_to_foreach_safe_refs(self, fleet_cfg):
        """Every /ip service get $var ... must bind to either the
        foreach iter var `$s` OR a static ref captured INSIDE that
        foreach via `:set <var> $s`."""
        script = _render(fleet_cfg)
        gets = re.findall(r"/ip service get \$(\w+)\s", script)
        assert gets, "no /ip service get $var calls — test is moot"
        captured = set(re.findall(r":set\s+(\w+)\s+\$s\b", script))
        captured.add("s")
        for var in set(gets):
            assert var in captured, (
                f"/ip service get ${var} doesn't bind to the foreach "
                f"iter var or a foreach-captured static ref. Allowed: "
                f"{sorted(captured)!r}"
            )

    def test_every_wg_peers_get_is_preceded_by_a_length_guard(self, fleet_cfg):
        """Same contract for `/interface wireguard peers get $var ...`."""
        script = _render(fleet_cfg)
        gets = re.findall(
            r"/interface wireguard peers get \$(\w+)\s", script,
        )
        if not gets:
            pytest.skip("no peer `get $var` calls in this render variant")
        for var in set(gets):
            guard = re.compile(r":len \$" + re.escape(var) + r"\] > 0")
            assert guard.search(script), (
                f"`/interface wireguard peers get ${var} ...` has no "
                f"`[:len ${var}] > 0` guard — empty peer ref halts the script"
            )

    def test_every_wg_interface_get_is_preceded_by_a_length_guard(self, fleet_cfg):
        """`/interface wireguard get $var public-key` for wg-mgmt /
        wg-users key log lines must be guarded too."""
        script = _render(fleet_cfg)
        gets = re.findall(
            r"/interface wireguard get \$(\w+)\s", script,
        )
        if not gets:
            pytest.skip("no interface `get $var` calls in this render variant")
        for var in set(gets):
            guard = re.compile(r":len \$" + re.escape(var) + r"\] > 0")
            assert guard.search(script), (
                f"`/interface wireguard get ${var} ...` has no "
                f"`[:len ${var}] > 0` guard — empty if-name halts the script"
            )


# ════════════════════════════════════════════════════════════════════════
# (3) Quoted service names — `find name="winbox"` not `find name=winbox`
# ════════════════════════════════════════════════════════════════════════
class TestQuotedServiceNames:

    def test_no_unquoted_ip_service_find_name(self, fleet_cfg):
        """Every `/ip service find name=...` must quote the value. The
        unquoted form is accepted by current RouterOS but the quoted
        form is the documented-stable shape (and the failing live line
        had `find name=winbox` unquoted)."""
        script = _render(fleet_cfg)
        unquoted = re.findall(
            r"/ip service find name=([^\"\s\]]+)", script,
        )
        assert unquoted == [], (
            "unquoted `/ip service find name=<x>` — quote the service "
            f"name like `find name=\"x\"`. Offenders: {unquoted!r}"
        )


# ════════════════════════════════════════════════════════════════════════
# (4) Regression pin — the literal §12 winbox check renders SAFELY
# ════════════════════════════════════════════════════════════════════════
class TestSection12WinboxCheckSafe:

    def test_winbox_addr_assignment_is_guarded(self, fleet_cfg):
        """The exact §12 line that halted the owner's import had to
        change shape. The new shape is `:local winboxAddr ""` + a
        `[:len $wbSvc] > 0` guarded `:set winboxAddr ...`."""
        script = _render(fleet_cfg)
        # The empty-string default initialiser must be present.
        assert ':local winboxAddr ""' in script, (
            "§12 winbox check no longer pre-initialises winboxAddr to "
            "an empty string — the guarded shape requires the local to "
            "exist before the conditional :set"
        )
        # No bare `:local winboxAddr [/ip service get ...]` line.
        bad = re.search(
            r":local\s+winboxAddr\s+\[/ip service get \[find",
            script,
        )
        assert bad is None, (
            "§12 still has the OLD shape `:local winboxAddr [/ip service "
            "get [find name=winbox] address]` — that's the line that "
            "halted chr-vpn-2's import. Use the guarded variant."
        )
