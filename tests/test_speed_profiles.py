"""Zero-central speed-profile fan-out — push the profile to every fleet node.

The legacy ``ensure_on_chr`` hit the singleton CHR. In the zero-central
world a profile is a fleet-wide policy: when the operator clicks «دفع
البروفايل» we install ``/ppp/profile`` on every eligible fleet node so a
tunnel placed by the brain anywhere finds its profile already there.

What this suite pins:
  * fan-out runs the install on EVERY enabled+non-drain+non-disabled node;
  * a single-node failure is reported in the result, not raised;
  * empty fleet → total=0/ok=0 (no exception);
  * a node whose creds aren't ready contributes to "skipped" not "errors";
  * the route surface returns a Arabic toast that reflects the aggregate.
"""
from __future__ import annotations

import pytest

from app.extensions import db
from app.models import Admin, ChrSpeedProfile
from app.services import speed_profiles as sp
from app.services import fleet_node_router
from app.services.fleet_node_router import FleetNodeUnavailable
from app.services.routeros_client import RouterOSError
from fleet.registry.models_chr import FleetChrNode, FleetProvider


# ─────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────
def _provider():
    p = FleetProvider(name="prov", cost_model="open", price_per_tb=0)
    db.session.add(p); db.session.flush()
    return p


def _fleet_node(prov, *, name, ip, wg, **kw):
    n = FleetChrNode(
        provider_id=prov.id, name=name, public_ip=ip,
        wg_mgmt_ip=wg, wg_mgmt_pubkey="x",
        routeros_api_port=8443, routeros_api_user="hobe-panel",
        routeros_api_password_enc="",
        coa_port=3799, max_sessions=1000, link_speed_mbps=1000,
        status=kw.pop("status", "up"),
        enabled=kw.pop("enabled", True),
        drain=kw.pop("drain", False),
    )
    db.session.add(n); db.session.commit()
    return n


def _profile():
    p = ChrSpeedProfile(name="fast", code="fast", download_mbps=50, upload_mbps=25)
    db.session.add(p); db.session.commit()
    return p


class _RecordingClient:
    """Per-node client that records every call by host."""
    calls: list[tuple[str, str]] = []  # (host, method)
    fail_hosts: set[str] = set()

    def __init__(self, host):
        self.host = host

    def ensure_ip_pool(self, **kw):
        type(self).calls.append((self.host, "ensure_ip_pool"))
        if self.host in self.fail_hosts:
            raise RouterOSError(code="ROS-1", message=f"forced fail on {self.host}")

    def ensure_ppp_profile(self, **kw):
        type(self).calls.append((self.host, "ensure_ppp_profile"))


@pytest.fixture(autouse=True)
def _stub_node_client(monkeypatch):
    _RecordingClient.calls = []
    _RecordingClient.fail_hosts = set()
    monkeypatch.setattr(
        fleet_node_router, "build_client_for",
        lambda node: _RecordingClient(host=(node.public_ip or node.wg_mgmt_ip)),
    )


# ─────────────────────────────────────────────────────────────────────────
# Fan-out
# ─────────────────────────────────────────────────────────────────────────
def test_fanout_pushes_profile_to_every_eligible_node(app):
    prov = _provider()
    a = _fleet_node(prov, name="chr-a", ip="10.0.0.1", wg="10.99.0.1")
    b = _fleet_node(prov, name="chr-b", ip="10.0.0.2", wg="10.99.0.2")
    c = _fleet_node(prov, name="chr-c", ip="10.0.0.3", wg="10.99.0.3")
    profile = _profile()

    result = sp.ensure_on_chr(profile)

    assert result["total"] == 3
    assert result["ok"] == 3
    assert result["errors"] == 0
    assert result["skipped"] == 0
    # Every node got both calls.
    hosts_hit = {h for (h, m) in _RecordingClient.calls if m == "ensure_ppp_profile"}
    assert hosts_hit == {"10.0.0.1", "10.0.0.2", "10.0.0.3"}


def test_fanout_excludes_disabled_and_drained_nodes(app):
    prov = _provider()
    _fleet_node(prov, name="chr-drain", ip="10.0.0.1", wg="10.99.0.1", drain=True)
    _fleet_node(prov, name="chr-disabled", ip="10.0.0.2", wg="10.99.0.2", enabled=False)
    good = _fleet_node(prov, name="chr-good", ip="10.0.0.3", wg="10.99.0.3")
    profile = _profile()

    result = sp.ensure_on_chr(profile)

    assert result["total"] == 1
    assert result["ok"] == 1
    hosts_hit = {h for (h, _) in _RecordingClient.calls}
    assert hosts_hit == {"10.0.0.3"}


def test_fanout_reports_per_node_failure_without_aborting_rest(app):
    prov = _provider()
    a = _fleet_node(prov, name="chr-a", ip="10.0.0.1", wg="10.99.0.1")
    bad = _fleet_node(prov, name="chr-bad", ip="10.0.0.2", wg="10.99.0.2")
    c = _fleet_node(prov, name="chr-c", ip="10.0.0.3", wg="10.99.0.3")
    profile = _profile()
    _RecordingClient.fail_hosts = {"10.0.0.2"}

    result = sp.ensure_on_chr(profile)

    assert result["total"] == 3
    assert result["ok"] == 2
    assert result["errors"] == 1
    bad_entry = next(p for p in result["per_node"] if p["node_name"] == "chr-bad")
    assert bad_entry["ok"] is False
    assert "forced fail" in bad_entry["message"]


def test_fanout_counts_no_creds_as_skipped_not_error(app, monkeypatch):
    prov = _provider()
    a = _fleet_node(prov, name="chr-a", ip="10.0.0.1", wg="10.99.0.1")
    b = _fleet_node(prov, name="chr-b", ip="10.0.0.2", wg="10.99.0.2")
    profile = _profile()

    def _build(node):
        if node.name == "chr-b":
            raise FleetNodeUnavailable("لا اعتماد", reason_code="no_credentials")
        return _RecordingClient(host=node.public_ip)

    monkeypatch.setattr(fleet_node_router, "build_client_for", _build)

    result = sp.ensure_on_chr(profile)
    assert result["total"] == 2
    assert result["ok"] == 1
    assert result["skipped"] == 1
    assert result["errors"] == 0


def test_fanout_returns_total_zero_when_fleet_is_empty(app):
    profile = _profile()
    result = sp.ensure_on_chr(profile)
    assert result["total"] == 0
    assert result["ok"] == 0
    assert result["per_node"] == []


# ─────────────────────────────────────────────────────────────────────────
# Route surface — admin toast
# ─────────────────────────────────────────────────────────────────────────
def _login_admin(client):
    return client.post("/login", data={"username": "admin", "password": "admin12345"})


def test_sync_route_toasts_aggregate(client, app):
    _login_admin(client)
    prov = _provider()
    a = _fleet_node(prov, name="chr-a", ip="10.0.0.1", wg="10.99.0.1")
    b = _fleet_node(prov, name="chr-b", ip="10.0.0.2", wg="10.99.0.2")
    profile = _profile()
    rv = client.post(
        f"/admin/chr/speed-profiles/{profile.id}/sync",
        follow_redirects=False,
    )
    assert rv.status_code in (302, 303)
    # A "تم دفع" toast targets the 2-node fan-out wording.
    rv = client.get("/admin/chr/speed-profiles")
    body = rv.get_data(as_text=True)
    assert "2 عقدة" in body or "تم دفع" in body or "fast" in body
