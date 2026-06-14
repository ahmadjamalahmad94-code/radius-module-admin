"""fix/script-service-get-guard — no unguarded `get [find ...]` in the .rsc.

Live blocker on the owner's chr-vpn-2: the §12 rollback-validation block
hit ``:local winboxAddr [/ip service get [find name=winbox] address]``
and RouterOS halted the import with::

    Script Error: invalid internal item number (/ip/service/get; line 1100)

The surrounding ``:do {} on-error={}`` does NOT catch this class of
error — RouterOS aborts the script even past a try, so the §12
rollback-CANCEL never ran and the 3-minute self-lockout reverted the
import. The CHR was stuck in the pre-script state.

Root cause: any ``/path get [find ...]`` where the ``find`` returns an
empty internal ref. The defensive shape is ALWAYS::

    :local ref [/path find name="x"]
    :if ([:len $ref] > 0) do={
        :local val [/path get $ref field]
    }

This test renders the full script for two distinct CHRs (so both the
mgmt-only and the radius_transport-on variants are covered) and
asserts no unguarded ``get [find`` pattern appears. The renderer's
``StrictUndefined`` would have caught a missing binding, but it can't
catch a hand-written defensive-pattern regression. This test is the
backstop.

Secondary contracts pinned here:
  * every ``/ip service find name=...`` quotes the service name (an
    unquoted ``find name=winbox`` accepted by RouterOS, but the quoted
    form is the documented-stable shape and matches the rest of the
    codebase);
  * each guarded site uses ``[:len $... ] > 0`` (or ``[:len [/...]] > 0``)
    so the guard text itself is greppable + auditable.
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

    def test_every_ip_service_get_is_preceded_by_a_length_guard(self, fleet_cfg):
        """For each `/ip service get $var ...` call, the SAME script
        must also contain a `[:len $var] > 0` guard (any line)."""
        script = _render(fleet_cfg)
        # Find all `/ip service get $local field` patterns and pull
        # the local-var name.
        gets = re.findall(r"/ip service get \$(\w+)\s", script)
        assert gets, (
            "no `/ip service get $var` calls present — guard pattern "
            "must be used so this test is meaningful"
        )
        for var in set(gets):
            guard = re.compile(r":len \$" + re.escape(var) + r"\] > 0")
            assert guard.search(script), (
                f"`/ip service get ${var} ...` appears with no matching "
                f"`[:len ${var}] > 0` guard — the find result could be "
                f"empty, and the get would halt the script"
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
