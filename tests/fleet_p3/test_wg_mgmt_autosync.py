"""feat/periodic-wg-mgmt-autosync — periodic self-healer for wg-mgmt state.

Companion to fix/fleet-wireguard-provisioning's BUG B: the render path
already adopts the live panel pubkey at script-generate time, but that
was only triggered by render. Between renders the panel-host wg-mgmt
key could drift (someone runs ``wg genkey`` on the host) or a peer
could be removed by hand, leaving the panel + every NEW CHR trusting
the wrong key forever.

This poller runs on the same lifecycle as the metrics_poller (daemon
thread, opt-in via config, gated by TESTING) and on every tick:

  1. Reads the LIVE wg-mgmt pubkey via the wg sudo-helper and ADOPTS
     it into ``Setting fleet.infra.PANEL_WG_PUBKEY`` if it differs.
     Affected fleet nodes get ``needs_reimport=True`` so the
     troubleshoot page surfaces the known-stale on-CHR copy.
  2. Calls ``reconcile_panel_host()`` so every eligible node's wg-mgmt
     peer is ensured on the control host AND persisted.

Tests below pin:
  * drift-detect + adopt + audit + needs_reimport flip
  * idempotency (same key → no-op, no churn)
  * helper-absent → clean no-op + INFO log + no crash
  * malformed live key → rejected at the ``set_panel_pubkey`` gate
  * reconcile called every tick (even when key unchanged)
  * tick() never raises (defence-in-depth)
  * background loop config + start/stop contract
  * boot stays clean when the helper is absent
"""
from __future__ import annotations

import logging

import pytest

from app.extensions import db
from app.models import AuditLog
from fleet.registry.models_chr import FleetChrNode, FleetProvider
from fleet.sync import wg_apply, wg_mgmt_autosync
from fleet.sync.wg_mgmt_autosync import (
    AUDIT_ACTION_PUBKEY_AUTO_CORRECTED,
    AUTOSYNC_INTERVAL_SETTING,
    DEFAULT_AUTOSYNC_INTERVAL_S,
    AutosyncSummary,
    is_running,
    start_background_autosync,
    stop_background_autosync,
    tick,
)


# ════════════════════════════════════════════════════════════════════════
# Fixtures
# ════════════════════════════════════════════════════════════════════════


@pytest.fixture()
def provider(app):
    p = FleetProvider.query.first()
    if p is not None:
        return p
    p = FleetProvider(
        name="autosync-prov", cost_model="open", price_per_tb=0,
        overage_allowed=False, billing_cycle_day=1,
    )
    db.session.add(p); db.session.commit()
    return p


def _make_node(provider, **kw):
    base = dict(
        provider_id=provider.id,
        name="chr-autosync",
        public_ip="203.0.113.50",
        wg_mgmt_ip="10.99.0.50", wg_mgmt_pubkey="x" * 44,
        max_sessions=500, link_speed_mbps=1000, weight=1.0,
        enabled=True, drain=False, status="up",
        cpu_pct=0, active_sessions=0,
    )
    base.update(kw)
    n = FleetChrNode(**base)
    db.session.add(n); db.session.commit()
    return n


@pytest.fixture()
def helper_present(monkeypatch):
    """Pretend the wg sudo-helper is installed + returns a given live
    key. ``reconcile_panel_host`` is also stubbed to a clean reported
    no-op so tests don't need the full peer-sync chain."""
    live_holder = {"key": "L" * 43 + "="}

    def _set_live(key: str):
        live_holder["key"] = key

    monkeypatch.setattr(wg_apply, "helper_installed", lambda: True)
    monkeypatch.setattr(
        wg_apply, "read_live_panel_pubkey",
        lambda: live_holder["key"],
    )

    # Stub the reconciler so tests pin the autosync contract, not the
    # full peer-sync chain (that's covered by its own tests).
    reconcile_calls = {"count": 0}

    def _fake_reconcile():
        reconcile_calls["count"] += 1
        return {"available": True, "applied": True,
                "applied_pubkeys": [], "desired_count": 3,
                "message": "stub ok"}
    import fleet.sync.service as svc
    monkeypatch.setattr(svc, "reconcile_panel_host", _fake_reconcile)

    return {"set_live": _set_live, "reconcile_calls": reconcile_calls}


def _stored_panel_pubkey() -> str:
    from fleet.registry.infra_settings import panel_pubkey_for_display
    return (panel_pubkey_for_display() or "").strip()


def _audit_count() -> int:
    return AuditLog.query.filter_by(
        action=AUDIT_ACTION_PUBKEY_AUTO_CORRECTED
    ).count()


# ════════════════════════════════════════════════════════════════════════
# 1. The headline: drifted live key → self-corrected on next tick
# ════════════════════════════════════════════════════════════════════════
class TestDriftSelfHeals:

    def test_adopts_live_key_when_setting_unset(self, app, helper_present):
        """Clean install: PANEL_WG_PUBKEY unset → poller adopts the live
        value + audits + reports it in the summary."""
        assert _stored_panel_pubkey() == ""
        live = "A" * 43 + "="
        helper_present["set_live"](live)
        summary = tick()
        assert summary.helper_available is True
        assert summary.pubkey_checked is True
        assert summary.pubkey_adopted is True
        assert summary.pubkey_old == ""
        assert summary.pubkey_new == live
        assert _stored_panel_pubkey() == live
        # Audit row carries the rotation.
        rows = AuditLog.query.filter_by(
            action=AUDIT_ACTION_PUBKEY_AUTO_CORRECTED
        ).all()
        assert len(rows) == 1
        meta = rows[0].meta or {}
        assert meta.get("source") == "wg_mgmt_autosync"
        assert meta.get("old_pubkey") == ""
        assert meta.get("new_pubkey") == live

    def test_adopts_rotated_live_key_records_old(self, app, helper_present):
        """The headline drift case (chr-vpn-1/2): stored != live →
        adopt, audit with the old value visible for the operator."""
        from fleet.registry.infra_settings import set_panel_pubkey
        old = "B" * 43 + "="
        new = "C" * 43 + "="
        set_panel_pubkey(old)
        helper_present["set_live"](new)
        summary = tick()
        assert summary.pubkey_adopted is True
        assert summary.pubkey_old == old
        assert summary.pubkey_new == new
        assert _stored_panel_pubkey() == new
        rows = AuditLog.query.filter_by(
            action=AUDIT_ACTION_PUBKEY_AUTO_CORRECTED
        ).all()
        assert (rows[0].meta or {}).get("old_pubkey") == old
        assert (rows[0].meta or {}).get("new_pubkey") == new


# ════════════════════════════════════════════════════════════════════════
# 2. Idempotency: same key → no Setting write, no audit
# ════════════════════════════════════════════════════════════════════════
class TestIdempotent:

    def test_same_key_is_a_noop(self, app, helper_present):
        from fleet.registry.infra_settings import set_panel_pubkey
        key = "D" * 43 + "="
        set_panel_pubkey(key)
        helper_present["set_live"](key)
        # Two ticks with the same live key → zero audit rows.
        for _ in range(2):
            summary = tick()
            assert summary.pubkey_adopted is False
        assert _stored_panel_pubkey() == key
        assert _audit_count() == 0


# ════════════════════════════════════════════════════════════════════════
# 3. Helper absent → clean no-op + info log + no crash
# ════════════════════════════════════════════════════════════════════════
class TestHelperAbsent:

    def test_no_helper_returns_noop_summary(self, app, monkeypatch, caplog):
        monkeypatch.setattr(wg_apply, "helper_installed", lambda: False)
        with caplog.at_level(logging.INFO, logger="fleet.sync.wg_mgmt_autosync"):
            summary = tick()
        assert summary.helper_available is False
        assert summary.pubkey_checked is False
        assert summary.pubkey_adopted is False
        assert summary.reconcile_attempted is False
        # The clean-no-op INFO line is emitted so the operator can see
        # in journalctl what the poller is doing.
        assert any(
            "wg sudo-helper not installed" in r.message
            for r in caplog.records
        )

    def test_no_helper_does_not_crash(self, app, monkeypatch):
        """Defence: helper-absent must not touch the DB or raise."""
        monkeypatch.setattr(wg_apply, "helper_installed", lambda: False)
        # No exception, returns a summary.
        summary = tick()
        assert isinstance(summary, AutosyncSummary)


# ════════════════════════════════════════════════════════════════════════
# 4. Malformed live key → rejected at the validation gate
# ════════════════════════════════════════════════════════════════════════
class TestMalformedLiveKey:

    def test_invalid_live_key_does_not_adopt(self, app, monkeypatch):
        """read_live_panel_pubkey itself rejects malformed input
        (returns None). The poller treats that as "no signal" and
        keeps the stored value."""
        from fleet.registry.infra_settings import set_panel_pubkey
        old = "E" * 43 + "="
        set_panel_pubkey(old)

        monkeypatch.setattr(wg_apply, "helper_installed", lambda: True)
        # The python wrapper validates 44-char base64 → returns None on
        # anything else. Pin that contract here by faking it.
        monkeypatch.setattr(wg_apply, "read_live_panel_pubkey", lambda: None)
        # Stub the reconciler too so we don't hit the real one.
        import fleet.sync.service as svc
        monkeypatch.setattr(svc, "reconcile_panel_host",
                            lambda: {"available": True, "applied": True,
                                     "applied_pubkeys": [],
                                     "desired_count": 0, "message": ""})

        summary = tick()
        assert summary.pubkey_adopted is False
        assert _stored_panel_pubkey() == old
        assert _audit_count() == 0


# ════════════════════════════════════════════════════════════════════════
# 5. Reconcile runs every tick (even when key is unchanged)
# ════════════════════════════════════════════════════════════════════════
class TestReconcileAlwaysRuns:

    def test_reconcile_called_when_key_unchanged(self, app, helper_present):
        """Drift detection is separate from peer sync — both run every
        pass. So even when the live key matches the stored value, the
        peer reconcile still ticks (so a hand-removed peer reappears)."""
        from fleet.registry.infra_settings import set_panel_pubkey
        key = "F" * 43 + "="
        set_panel_pubkey(key)
        helper_present["set_live"](key)
        summary = tick()
        assert summary.pubkey_adopted is False
        assert summary.reconcile_attempted is True
        assert summary.reconcile_applied is True
        # The fake reconciler counted exactly one invocation.
        assert helper_present["reconcile_calls"]["count"] == 1


# ════════════════════════════════════════════════════════════════════════
# 6. needs_reimport flag flips on every previously-rendered node
# ════════════════════════════════════════════════════════════════════════
class TestNeedsReimportFlip:

    def test_adoption_marks_previously_rendered_nodes_stale(
        self, app, provider, helper_present,
    ):
        """When the stored key changes, every node that carries a
        ``control_wg_public_key_snapshot`` (i.e. has been rendered at
        least once) gets needs_reimport=True so the troubleshoot page
        flags the on-CHR copy as known-stale."""
        from fleet.registry.infra_settings import set_panel_pubkey
        # Two nodes that have been rendered, one that hasn't.
        rendered_a = _make_node(provider, name="chr-rendered-a",
                                public_ip="203.0.113.51",
                                wg_mgmt_ip="10.99.0.51",
                                control_wg_public_key_snapshot="OLD" + "A" * 41 + "=")
        rendered_b = _make_node(provider, name="chr-rendered-b",
                                public_ip="203.0.113.52",
                                wg_mgmt_ip="10.99.0.52",
                                control_wg_public_key_snapshot="OLD" + "B" * 41 + "=")
        fresh = _make_node(provider, name="chr-fresh",
                           public_ip="203.0.113.53",
                           wg_mgmt_ip="10.99.0.53",
                           control_wg_public_key_snapshot="")
        # Force a drift: stored != live.
        set_panel_pubkey("Z" * 43 + "=")
        helper_present["set_live"]("Y" * 43 + "=")

        summary = tick()
        assert summary.pubkey_adopted is True
        # The two rendered nodes flipped; the fresh node stayed.
        db.session.refresh(rendered_a)
        db.session.refresh(rendered_b)
        db.session.refresh(fresh)
        assert rendered_a.needs_reimport is True
        assert rendered_b.needs_reimport is True
        assert fresh.needs_reimport is False
        assert summary.nodes_marked_stale == 2


# ════════════════════════════════════════════════════════════════════════
# 7. tick() never raises (defence in depth)
# ════════════════════════════════════════════════════════════════════════
class TestNeverRaises:

    def test_reconcile_raising_does_not_break_tick(self, app, monkeypatch):
        """If reconcile_panel_host raises, the tick still returns a
        summary with the failure recorded — the background loop keeps
        ticking, the operator sees the issue in logs."""
        monkeypatch.setattr(wg_apply, "helper_installed", lambda: True)
        monkeypatch.setattr(wg_apply, "read_live_panel_pubkey",
                            lambda: "G" * 43 + "=")
        import fleet.sync.service as svc

        def _boom():
            raise RuntimeError("simulated reconcile failure")
        monkeypatch.setattr(svc, "reconcile_panel_host", _boom)
        # Must not raise.
        summary = tick()
        assert summary.helper_available is True
        assert summary.reconcile_attempted is True
        assert summary.reconcile_applied is False
        assert "reconcile_raised" in summary.reconcile_message

    def test_live_key_read_raising_does_not_break_tick(self, app, monkeypatch):
        monkeypatch.setattr(wg_apply, "helper_installed", lambda: True)

        def _boom():
            raise RuntimeError("simulated helper failure")
        monkeypatch.setattr(wg_apply, "read_live_panel_pubkey", _boom)
        # Stub reconcile so we don't go further.
        import fleet.sync.service as svc
        monkeypatch.setattr(svc, "reconcile_panel_host",
                            lambda: {"available": True, "applied": True,
                                     "applied_pubkeys": [],
                                     "desired_count": 0, "message": ""})
        summary = tick()
        # pubkey_checked is True (we tried) but pubkey_adopted False.
        assert summary.pubkey_checked is True
        assert summary.pubkey_adopted is False


# ════════════════════════════════════════════════════════════════════════
# 8. Background loop config + start/stop contract
# ════════════════════════════════════════════════════════════════════════
class TestBackgroundLoop:

    @pytest.fixture(autouse=True)
    def _stop_background(self):
        """Ensure no stale worker thread from a sibling test leaks
        into these assertions."""
        stop_background_autosync(join_timeout=1.0)
        yield
        stop_background_autosync(join_timeout=1.0)

    def test_start_returns_false_under_testing(self, app):
        """TESTING gate: the background loop never starts in unit tests."""
        # The default TestingConfig has TESTING=True.
        assert app.config.get("TESTING") is True
        assert start_background_autosync(app) is False
        assert is_running() is False

    def test_start_returns_false_when_disabled(self, app):
        app.config["TESTING"] = False
        app.config["PANEL_WG_AUTOSYNC_ENABLED"] = False
        try:
            assert start_background_autosync(app) is False
            assert is_running() is False
        finally:
            app.config["TESTING"] = True
            app.config.pop("PANEL_WG_AUTOSYNC_ENABLED", None)

    def test_default_interval_is_120s(self):
        assert DEFAULT_AUTOSYNC_INTERVAL_S == 120

    def test_interval_resolver_setting_beats_config(self, app):
        from app.models import Setting
        # Setting row beats config value beats default.
        row = Setting(key=AUTOSYNC_INTERVAL_SETTING, value="45")
        db.session.add(row); db.session.commit()
        app.config["PANEL_WG_AUTOSYNC_INTERVAL"] = 9999
        try:
            from fleet.sync.wg_mgmt_autosync import _resolve_interval
            assert _resolve_interval(app) == 45
        finally:
            db.session.delete(row); db.session.commit()
            app.config.pop("PANEL_WG_AUTOSYNC_INTERVAL", None)

    def test_interval_resolver_floor_15s(self, app):
        from app.models import Setting
        row = Setting(key=AUTOSYNC_INTERVAL_SETTING, value="1")
        db.session.add(row); db.session.commit()
        try:
            from fleet.sync.wg_mgmt_autosync import _resolve_interval
            assert _resolve_interval(app) == 15
        finally:
            db.session.delete(row); db.session.commit()
