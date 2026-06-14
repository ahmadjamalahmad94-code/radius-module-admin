"""fix/chr-rollback-wgdata-rest — three live root causes on chr-vpn-2.

Drives the generator + panel fixes for the owner's authoritative
three-issue spec (RouterOS 7.21.x):

ISSUE 1 — rollback guard fired forever:
    The §0a scheduler ran `/system backup load name=hobe-fleet-pre-apply`
    which errors «missing value(s) of argument(s) password» in scheduler
    context, AND interval= made it RECURRING — it logged "rollback fired"
    + "executing script failed" every 3m ~20× and never self-removed.
    Redesign: one-shot, self-removing FIRST, password="" non-interactive,
    bounded (no retry on failure).

ISSUE 2 — wg-data no handshake (the real onboarding blocker):
    The CHR's local wg-data config was correct but the proxy had no peer
    for this CHR's wg-data pubkey. SMOKING GUN: the script logged the
    wg-mgmt + wg-users pubkeys but NEVER the wg-data pubkey. Fix: log the
    wg-data pubkey on the CHR + reclassify the §12 handshake checks (2)+(4)
    as REMOTE-PENDING (never rollback-gating — reverting would wipe correct
    local config). Panel-side preflight catches an un-publishable wg-data
    peer before export.

ISSUE 3 — "login failure for user hobe-panel via api":
    SMOKING GUN: the SET branch refreshed group but NOT password, so a
    pre-existing hobe-panel row kept a STALE password ≠ the panel's stored
    REST secret. Fix: set password= in BOTH the add AND set branches so
    the CHR password always converges to the panel-known secret.
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
# Render helpers
# ════════════════════════════════════════════════════════════════════════


def _fake_node(name: str, public_ip: str) -> SimpleNamespace:
    return SimpleNamespace(name=name, public_ip=public_ip)


@pytest.fixture()
def fleet_cfg() -> RouterosTemplateConfig:
    return RouterosTemplateConfig(
        panel_wg_pubkey="PANEL_PUBKEY_ABC123==",
        panel_wg_endpoint="panel.fleet.test",
        panel_wg_addr="10.99.0.1",
        proxy_wg_pubkey="8wYymFP7RuTHViBxcUrjDkbtzYiUk0hUDzWOOTGvXI=",
        proxy_wg_endpoint="proxy.hoberadius.com",
        proxy_wg_addr="10.98.0.1",
        chr_shared_secret="s3cret-shared-fleet-wide",
        sstp_cert_name="hobe-sstp-cert",
        ike_cert_name="hobe-ike-cert",
        client_supernet="10.0.0.0/8",
        dns_push="1.1.1.1,1.0.0.1",
        gw_local_addr="10.0.0.1",
        api_user="hobe-panel",
        api_password="panel-known-secret-xyz",
    )


def _render(fleet_cfg: RouterosTemplateConfig) -> str:
    node = _fake_node("chr-vpn-2", "203.0.113.12")
    keys = ChrKeyMaterial(
        mgmt_privkey="CHR_MGMT_PRIV_xxxxxxxxxxxxxxxxxxxxxxxxx",
        mgmt_addr="10.99.0.12/24",
        data_privkey="CHR_DATA_PRIV_yyyyyyyyyyyyyyyyyyyyyyyyy",
        data_addr="10.98.0.12/24",
        wan_iface="ether1",
    )
    return render_chr_script(node, keys, fleet_cfg)


# ════════════════════════════════════════════════════════════════════════
# ISSUE 1 — rollback guard is one-shot, valid, self-removing
# ════════════════════════════════════════════════════════════════════════
class TestRollbackRedesign:

    def test_scheduler_self_removes_before_restore(self, fleet_cfg):
        """The on-event's FIRST action must remove the scheduler so it
        can never fire twice (no infinite 3m loop)."""
        script = _render(fleet_cfg)
        # on-event is a single physical line ending with ` \`. Greedy
        # `.*` to the last `)` (the event string itself contains a
        # literal "(one-shot)" so a non-greedy match stops too early).
        m = re.search(r"on-event=\((.*)\)\s*\\", script)
        assert m, "rollback scheduler on-event not found"
        event = m.group(1)
        # The remove must appear BEFORE the backup load in the event body.
        remove_pos = event.find("/system scheduler remove [find name=hobe-fleet-rollback]")
        load_pos = event.find("/system backup load")
        assert remove_pos != -1, "on-event must self-remove the scheduler"
        assert load_pos != -1, "on-event must still attempt the restore"
        assert remove_pos < load_pos, (
            "self-remove must run BEFORE the restore so a failed/rebooting "
            "restore can never leave the scheduler re-firing every interval"
        )

    def test_backup_load_uses_password_arg(self, fleet_cfg):
        """The restore must pass password= (empty) — the missing arg was
        the «missing value(s) of argument(s) password» scheduler error."""
        script = _render(fleet_cfg)
        assert 'backup load name=hobe-fleet-pre-apply password=\\"\\"' in script, (
            "rollback restore must use the non-interactive password=\"\" "
            "form; the bare `backup load name=...` errors in scheduler ctx"
        )

    def test_restore_wrapped_in_on_error_bounded(self, fleet_cfg):
        """A failed restore must NOT loop — it's wrapped in :do/on-error
        and the scheduler already self-removed."""
        script = _render(fleet_cfg)
        m = re.search(r"on-event=\((.*)\)\s*\\", script)
        event = m.group(1)
        assert ":do {" in event and "on-error=" in event, (
            "restore must be wrapped in :do/on-error so a backup-load "
            "failure logs + stops instead of erroring every interval"
        )

    def test_scheduler_comment_marks_one_shot(self, fleet_cfg):
        script = _render(fleet_cfg)
        assert "one-shot self-removing" in script

    def test_cancel_block_uses_local_only_gate(self, fleet_cfg):
        """On success the rollback is cancelled based on LOCAL checks
        only; pending-remote handshake never blocks the cancel."""
        script = _render(fleet_cfg)
        assert ":if ($hobeRollbackOk) do={" in script
        gate = script.index(":if ($hobeRollbackOk) do={")
        body = script[gate:gate + 1500]
        assert '/system scheduler remove [find name="hobe-fleet-rollback"]' in body
        # Pending-remote is reported inside the success branch, not gating.
        assert "hobePendingRemote" in body


# ════════════════════════════════════════════════════════════════════════
# ISSUE 2 — wg-data pubkey logged + handshake checks are remote-pending
# ════════════════════════════════════════════════════════════════════════
class TestWgDataPubkeyAndPending:

    def test_wg_data_pubkey_is_logged(self, fleet_cfg):
        """SMOKING GUN #2: the script must log the CHR's wg-data pubkey
        (it logged wg-mgmt + wg-users but never wg-data), so the operator
        can confirm the key the proxy must peer."""
        script = _render(fleet_cfg)
        assert "this CHR wg-data pubkey" in script, (
            "wg-data pubkey log line missing — operator can't confirm the "
            "key the proxy must trust"
        )
        # It reads the live interface pubkey (length-guarded), like wg-mgmt.
        assert "get $hobeDataIf public-key" in script
        # And it names the allowed-ips the proxy must use.
        assert "10.98.0.12/32" in script

    def test_handshake_checks_do_not_gate_rollback(self, fleet_cfg):
        script = _render(fleet_cfg)
        assert ":global hobePendingRemote false" in script
        assert "(2) wg-mgmt local config OK but NO handshake" in script
        assert "(4) wg-data local config OK but NO handshake" in script
        assert "(2) wg-mgmt no handshake AND no ping" not in script
        assert "(4) wg-data no handshake AND no ping" not in script


# ════════════════════════════════════════════════════════════════════════
# ISSUE 3 — hobe-panel password set in BOTH add + set branches
# ════════════════════════════════════════════════════════════════════════
class TestHobePanelPasswordConverges:

    def test_set_branch_sets_password(self, fleet_cfg):
        """The SET branch (user already exists) must ALSO set password=
        so a stale pre-existing password converges to the panel secret —
        the cause of «login failure for user hobe-panel via api»."""
        script = _render(fleet_cfg)
        # Locate the managed-row /user set and grab the continuation
        # lines (each ends with ` \`) up to the closing comment.
        idx = script.index(
            '/user set [find name="hobe-panel" comment="hobe-fleet-api-managed"]'
        )
        block = script[idx:idx + 400]
        assert 'password="panel-known-secret-xyz"' in block, (
            "the /user set branch must set password= to the panel secret; "
            "leaving it stale was the via-api REST auth failure"
        )

    def test_add_branch_still_sets_password(self, fleet_cfg):
        script = _render(fleet_cfg)
        idx = script.index('/user add name="hobe-panel"')
        block = script[idx:idx + 400]
        assert 'password="panel-known-secret-xyz"' in block


# ════════════════════════════════════════════════════════════════════════
# Preflight (panel-side, acceptance item 7)
# ════════════════════════════════════════════════════════════════════════
class TestWgDataPreflight:

    def _provider(self):
        from app.extensions import db
        from fleet.registry.models_chr import FleetProvider
        p = FleetProvider.query.first()
        if p:
            return p
        p = FleetProvider(name="pf-prov", cost_model="open", price_per_tb=0,
                          overage_allowed=False, billing_cycle_day=1)
        db.session.add(p); db.session.commit()
        return p

    _IPSEQ = [50]

    def _node(self, **kw):
        from app.extensions import db
        from fleet.registry.models_chr import FleetChrNode
        self._IPSEQ[0] += 1
        seq = self._IPSEQ[0]
        base = dict(
            provider_id=self._provider().id,
            name=f"pf-node-{seq}", public_ip=f"203.0.113.{seq}",
            wg_mgmt_ip=f"10.99.0.{seq}", wg_mgmt_pubkey="m" * 44,
            wg_data_pubkey="d" * 44,
            max_sessions=500, link_speed_mbps=1000, weight=1.0,
            enabled=True, drain=False, status="up",
        )
        base.update(kw)
        n = FleetChrNode(**base)
        db.session.add(n); db.session.commit()
        return n

    def test_ok_when_pubkey_present_and_eligible(self, app):
        with app.app_context():
            from fleet.sync.preflight import preflight_wg_data
            n = self._node(name="pf-ok", wg_mgmt_ip="10.99.0.51")
            v = preflight_wg_data(n)
            assert v.state == "ok"
            assert v.will_publish is True
            assert v.allowed_ip == "10.98.0.51/32"

    def test_blocked_when_wg_data_pubkey_missing(self, app):
        with app.app_context():
            from fleet.sync.preflight import preflight_wg_data
            n = self._node(name="pf-nopub", wg_mgmt_ip="10.99.0.52",
                           wg_data_pubkey="")
            v = preflight_wg_data(n)
            assert v.state == "blocked"
            assert v.will_publish is False
            assert any("wg-data pubkey missing" in r for r in v.reasons)

    def test_allowed_ip_unique_across_distinct_nodes(self, app):
        """Distinct nodes derive distinct 10.98.0.X/32 (wg_mgmt_ip is
        unique + the derivation maps the full suffix), so uniqueness
        holds. The collision branch stays in the code as defense if the
        derivation ever changes; here we confirm the happy path is
        classified unique + ok."""
        with app.app_context():
            from fleet.sync.preflight import preflight_wg_data
            self._node(name="pf-a", wg_mgmt_ip="10.99.0.77")
            n2 = self._node(name="pf-b", wg_mgmt_ip="10.99.0.78")
            v = preflight_wg_data(n2)
            assert v.allowed_ip_unique is True
            assert v.state == "ok"
            assert v.allowed_ip == "10.98.0.78/32"

    def test_pending_when_drained(self, app):
        with app.app_context():
            from fleet.sync.preflight import preflight_wg_data
            n = self._node(name="pf-drain", wg_mgmt_ip="10.99.0.60",
                           drain=True)
            v = preflight_wg_data(n)
            assert v.state == "pending_remote"
            assert v.will_publish is False
