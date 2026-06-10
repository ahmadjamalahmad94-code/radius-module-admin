"""Regression: the dashboard «فحص الآن» button delegates to
``fleet.health.monitor.check_now`` and must return the **same** state
the background ``run_once`` would surface for that node.

Before the fix in this branch, the wrapper in
``fleet.ui.dashboard_data._try_delegate_to_monitor`` only special-cased
a ``dict`` return value. The real monitor returns a ``RunSummary``
dataclass, so the wrapper fell through to ``{"ok": True, "checked":
"monitor"}`` — no ``state`` field — and the dashboard JS read
``HEALTH_AR.unknown`` and toasted «الحالة الآن: غير معروفة عبر مراقب
الصحّة» even when the monitor had just marked the node ``up``.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.extensions import db
from fleet.health.models_health import FleetChrHealth
from fleet.health.monitor import PingResult, PingTarget
from fleet.registry.models_chr import FleetChrNode, FleetProvider
from fleet.ui.dashboard_data import check_now as ui_check_now


def _t(seconds: int) -> datetime:
    return datetime(2026, 6, 10, 0, 0, 0, tzinfo=timezone.utc).replace(tzinfo=None) + timedelta(seconds=seconds)


def _provider() -> FleetProvider:
    p = FleetProvider(name="acme-cn", cost_model="open")
    db.session.add(p); db.session.commit()
    return p


def _node(name: str = "chr-vpn-1") -> FleetChrNode:
    provider = FleetProvider.query.first() or _provider()
    n = FleetChrNode(
        provider_id=provider.id, name=name,
        public_ip="203.0.113.11",
        wg_mgmt_ip="10.99.0.11",
        wg_mgmt_pubkey="x" * 44,
        routeros_api_port=8729, coa_port=3799,
        max_sessions=500, link_speed_mbps=1000,
        weight=1.0, enabled=True, status="provisioning",
    )
    db.session.add(n); db.session.commit()
    return n


class _AlwaysOkPinger:
    """Mock the wg-mgmt ICMP success the operator just confirmed live."""

    def __init__(self):
        self.targets: list[PingTarget] = []

    def ping(self, target: PingTarget) -> PingResult:
        self.targets.append(target)
        return PingResult(ok=True, latency_ms=10.0)


def test_manual_check_now_returns_up_state_on_reachable_node(app, monkeypatch):
    """The live regression: manual check on a reachable node must surface
    ``state="up"`` (matching the background monitor) — not "unknown"."""
    node = _node()

    # Pin the monitor's pinger to the OK mock so the test exercises the
    # real production code path (resolve target → ping → evaluate →
    # commit) without any network.
    from fleet.health import monitor as _mon
    monkeypatch.setattr(_mon, "_default_pinger", lambda: _AlwaysOkPinger())

    result = ui_check_now(node.id, now=_t(0))

    assert result["ok"] is True, result
    assert result["checked"] == "monitor"
    assert result["state"] == "up", (
        f"manual check on a reachable node returned state={result.get('state')!r} — "
        "the dashboard toast would render «غير معروفة» again"
    )
    # The persisted health row matches the wrapper's response.
    health = db.session.get(FleetChrHealth, node.id)
    assert health is not None and health.state == "up"


def test_manual_check_now_probes_wg_mgmt_ip_not_public_ip(app, monkeypatch):
    """Same probe path as run_once: target is wg_mgmt_ip, never public_ip."""
    node = _node(name="chr-target")
    seen: list[PingTarget] = []

    class _Capture:
        def ping(self, target):
            seen.append(target)
            return PingResult(ok=True, latency_ms=12.5)

    from fleet.health import monitor as _mon
    monkeypatch.setattr(_mon, "_default_pinger", lambda: _Capture())

    ui_check_now(node.id, now=_t(0))
    assert seen, "monitor.check_now must have invoked the pinger"
    assert seen[0].host == "10.99.0.11"
    assert seen[0].host != "203.0.113.11"


def test_manual_check_now_state_matches_background_run(app, monkeypatch):
    """The headline invariant: manual «فحص الآن» and background run_once
    must produce the SAME state for the same node + probe outcome."""
    from fleet.health import monitor as _mon
    monkeypatch.setattr(_mon, "_default_pinger", lambda: _AlwaysOkPinger())
    node = _node(name="chr-consistency")

    manual = ui_check_now(node.id, now=_t(0))
    health_after_manual = db.session.get(FleetChrHealth, node.id)
    assert manual["state"] == health_after_manual.state

    # A second run_once over all enabled nodes (background path) must
    # agree with the manual snapshot.
    _mon.run_once(now=_t(60))
    health_after_run = db.session.get(FleetChrHealth, node.id)
    assert health_after_run.state == manual["state"] == "up"
