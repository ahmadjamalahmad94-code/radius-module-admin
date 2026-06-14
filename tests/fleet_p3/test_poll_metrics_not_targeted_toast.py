"""fix/poll-metrics-not-targeted-toast — on-demand poll reports only the target.

Live false alarm: with >1 CHR node, clicking «مقاييس» on chr-vpn-2 (which
read fine) showed a warning toast «العقدة «chr-vpn-2» — تعذّرت القراءة:
not_targeted».

Mechanism: the on-demand endpoint runs poll_all() over EVERY eligible
node with a `_solo_collector` that stamps every NON-target node with the
internal `not_targeted` sentinel (BUG L armour). poll_all appended those
sibling sentinels to summary.errors, so error_count>0 and the dashboard
JS surfaced summary.errors[0] (a sibling's sentinel) labelled with the
clicked node — even though the clicked node's REAL collect succeeded.

Fix: the route now reports ONLY the target node's outcome (checked=1,
errors filtered to node.name). `not_targeted` is an internal sentinel and
never operator-facing. The «فحص» button is unaffected (it calls
verify_node_wg_identity directly, never poll_all / not_targeted).
"""
from __future__ import annotations

import pytest

from app.extensions import db
from app.models import Admin
from fleet.registry.models_chr import FleetChrNode, FleetProvider


def _login_super(client):
    client.post("/login", data={"username": "admin", "password": "admin12345"})
    adm = Admin.query.first()
    if adm and not adm.is_super_admin:
        adm.is_super_admin = True
        db.session.commit()


def _provider() -> FleetProvider:
    p = FleetProvider.query.first()
    if p is not None:
        return p
    p = FleetProvider(name="nt-prov", cost_model="open", price_per_tb=0,
                      overage_allowed=False, billing_cycle_day=1)
    db.session.add(p); db.session.commit()
    return p


_SEQ = [80]


def _make_node(**kw) -> FleetChrNode:
    _SEQ[0] += 1
    base = dict(
        provider_id=_provider().id,
        name=f"chr-nt-{_SEQ[0]}",
        public_ip=f"203.0.113.{_SEQ[0]}",
        wg_mgmt_ip=f"10.99.0.{_SEQ[0]}", wg_mgmt_pubkey="x" * 44,
        max_sessions=500, link_speed_mbps=1000, weight=1.0,
        enabled=True, drain=False, status="up",
    )
    base.update(kw)
    n = FleetChrNode(**base)
    db.session.add(n); db.session.commit()
    from fleet.health.routeros_creds import set_credentials
    set_credentials(n, username="hobe-panel", password="pw")
    db.session.commit()
    return n


URL = "/admin/fleet/chr-nodes/{id}/poll-metrics-now"


def _stub_collect(monkeypatch, ok_for_id: int):
    """Make the REAL collector succeed only for ok_for_id; any other id
    would be a real collect too — but _solo_collector only calls the real
    collect for the target, so this only ever runs for the target."""
    from fleet.health import routeros_collector as rc

    def _fake(node, **kw):
        return rc.Sample(cpu_pct=5.0, mem_pct=10.0, active_sessions=0,
                         rx_bytes=1, tx_bytes=1, uptime="1h")
    monkeypatch.setattr(rc, "collect", _fake)


class TestSiblingSentinelNotSurfaced:

    def test_target_success_no_sibling_not_targeted_error(self, app, client, monkeypatch):
        """With a sibling present, polling the target returns error_count=0
        — the sibling's not_targeted sentinel must NOT leak into the
        operator-facing summary."""
        _login_super(client)
        target = _make_node(name="chr-vpn-2")
        _make_node(name="chr-sibling-1")  # the sibling that gets not_targeted
        _make_node(name="chr-sibling-2")
        _stub_collect(monkeypatch, target.id)

        r = client.post(URL.format(id=target.id))
        assert r.status_code == 200, r.data[:200]
        body = r.get_json()
        assert body["ok"] is True
        s = body["summary"]
        assert s["checked"] == 1, "on-demand poll is single-node"
        assert s["ok_count"] == 1
        assert s["error_count"] == 0, (
            "sibling not_targeted sentinels must not surface as errors "
            f"for the clicked node; got {s['errors']!r}"
        )
        assert s["errors"] == []
        # No 'not_targeted' anywhere in the operator-facing payload.
        assert "not_targeted" not in r.get_data(as_text=True)

    def test_real_target_error_is_still_reported(self, app, client, monkeypatch):
        """If the TARGET itself errors, that real error IS reported (we
        only filter sibling sentinels, never the target's outcome)."""
        _login_super(client)
        target = _make_node(name="chr-target-err")
        _make_node(name="chr-sib-err")
        from fleet.health import routeros_collector as rc
        def _fake(node, **kw):
            return rc.Sample(error="connect_failed",
                             error_detail="timeout")
        monkeypatch.setattr(rc, "collect", _fake)

        r = client.post(URL.format(id=target.id))
        body = r.get_json()
        s = body["summary"]
        assert s["error_count"] == 1
        assert s["errors"][0][0] == "chr-target-err"
        assert s["errors"][0][1] == "connect_failed"
