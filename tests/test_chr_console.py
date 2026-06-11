"""Zero-central CHR console — per-node selector + per-node mutations.

The legacy chr_settings singleton is gone; the console now operates on a
specific fleet node chosen from a picker or brain-auto-picked. This
suite pins:

  * /admin/chr/console renders the per-node picker when a fleet exists;
  * /admin/chr/console?node_id=<id> deep-links to that node (and the
    dropdown sticks even when the node is unreachable);
  * the service surface accepts a ``node_id`` and threads it to the
    underlying client; auto-pick (no node_id) hits the brain's best;
  * console.enabled() reflects fleet readiness (any eligible node);
  * settings#chr UI is gone (no tab, none of the legacy routes exist).
"""
from __future__ import annotations

import pytest

from app.extensions import db
from app.models import Admin
from app.services import chr_console, fleet_node_router
from fleet.registry.models_chr import FleetChrNode, FleetProvider


# ─────────────────────────────────────────────────────────────────────────
# Test helpers
# ─────────────────────────────────────────────────────────────────────────
def _login_admin(client):
    return client.post("/login", data={"username": "admin", "password": "admin12345"})


def _make_super_admin():
    adm = Admin.query.first()
    if adm and not adm.is_super_admin:
        adm.is_super_admin = True
        db.session.commit()


def _provider():
    p = FleetProvider(name="prov", cost_model="open", price_per_tb=0)
    db.session.add(p); db.session.flush()
    return p


def _fleet_node(prov, *, name="chr-1", public_ip="1.2.3.4", wg="10.99.0.11",
                status="up", enabled=True, drain=False):
    n = FleetChrNode(
        provider_id=prov.id, name=name, public_ip=public_ip,
        wg_mgmt_ip=wg, wg_mgmt_pubkey="x",
        routeros_api_port=8443, routeros_api_user="hobe-panel",
        routeros_api_password_enc="",
        coa_port=3799, max_sessions=1000, link_speed_mbps=1000,
        status=status, enabled=enabled, drain=drain,
    )
    db.session.add(n); db.session.commit()
    return n


class _StubClient:
    last_host: str = ""
    def __init__(self, **kw):
        type(self).last_host = kw.get("host", "")
    def test_connection(self): return {"reachable": True}
    def list_ppp_secrets(self): return []
    def list_ppp_active(self): return []
    def list_ipsec_users(self): return []
    def list_ipsec_identities(self): return []
    def list_ipsec_active_peers(self): return []
    def list_interfaces(self): return []
    def system_resource(self): return {"version": "7.10", "board-name": "CHR"}
    def system_identity(self): return {"name": "chr-1"}
    def set_ppp_secret_disabled(self, _id, _flag): return None
    def remove_ppp_secret(self, _id): return None
    def set_ipsec_user_disabled(self, _id, _flag): return None
    def remove_ipsec_user(self, _id): return None
    def reboot(self): return None


@pytest.fixture(autouse=True)
def _stub_client(monkeypatch):
    _StubClient.last_host = ""
    monkeypatch.setattr(
        fleet_node_router, "build_client_for",
        lambda node: _StubClient(host=(node.public_ip or node.wg_mgmt_ip)),
    )


# ─────────────────────────────────────────────────────────────────────────
# Readiness gate
# ─────────────────────────────────────────────────────────────────────────
def test_console_enabled_requires_a_fleet_node(app):
    # Empty fleet → not enabled.
    assert chr_console.enabled() is False
    _fleet_node(_provider())
    assert chr_console.enabled() is True


# ─────────────────────────────────────────────────────────────────────────
# Service surface — per-node
# ─────────────────────────────────────────────────────────────────────────
def test_overview_explicit_node_targets_that_node(app):
    prov = _provider()
    a = _fleet_node(prov, name="chr-a", public_ip="10.0.0.1", wg="10.99.0.1")
    b = _fleet_node(prov, name="chr-b", public_ip="10.0.0.2", wg="10.99.0.2")
    result = chr_console.overview(node_id=b.id)
    assert result["ok"] is True
    assert result["node_id"] == b.id
    assert result["node_name"] == "chr-b"
    assert _StubClient.last_host == b.public_ip


def test_overview_no_explicit_node_uses_brain_pick(app):
    prov = _provider()
    busy = _fleet_node(prov, name="chr-busy", public_ip="10.0.0.1",
                       wg="10.99.0.1")
    # Use the brain to fix the order — empty fleet would also be a
    # valid "no node" path but here we just verify ONE node + auto-pick.
    result = chr_console.overview()
    assert result["ok"] is True
    assert result["node_id"] == busy.id


def test_overview_returns_message_when_fleet_is_empty(app):
    result = chr_console.overview()
    assert result["ok"] is False
    assert "الأسطول" in result["message"]


def test_mutation_targets_picked_node(app):
    prov = _provider()
    a = _fleet_node(prov, name="chr-a", public_ip="10.0.0.1", wg="10.99.0.1")
    b = _fleet_node(prov, name="chr-b", public_ip="10.0.0.2", wg="10.99.0.2")
    res = chr_console.remove_ppp_secret("*A1", node_id=b.id)
    assert res["ok"] is True
    assert _StubClient.last_host == b.public_ip


# ─────────────────────────────────────────────────────────────────────────
# Route: dropdown + sticky deep-link
# ─────────────────────────────────────────────────────────────────────────
def test_console_page_renders_node_picker(client, app):
    _login_admin(client); _make_super_admin()
    prov = _provider()
    _fleet_node(prov, name="chr-mtl", public_ip="1.2.3.4", wg="10.99.0.4")
    _fleet_node(prov, name="chr-nyc", public_ip="5.6.7.8", wg="10.99.0.8")
    rv = client.get("/admin/chr/console")
    assert rv.status_code == 200
    body = rv.get_data(as_text=True)
    assert "على أي عقدة؟" in body
    assert "chr-mtl" in body
    assert "chr-nyc" in body


def test_console_deep_link_node_id_stays_selected(client, app):
    _login_admin(client); _make_super_admin()
    prov = _provider()
    _fleet_node(prov, name="chr-nyc", public_ip="5.6.7.8", wg="10.99.0.8")
    rv = client.get("/admin/chr/console?node_id=1")
    body = rv.get_data(as_text=True)
    assert 'value="1" selected' in body


# ─────────────────────────────────────────────────────────────────────────
# Settings#chr is gone
# ─────────────────────────────────────────────────────────────────────────
def test_settings_chr_tab_is_removed(client):
    _login_admin(client)
    body = client.get("/admin/settings").get_data(as_text=True)
    assert "data-tab=\"chr\"" not in body
    assert "MikroTik CHR — نمط الـCHR الواحد" not in body


def test_legacy_chr_settings_routes_404(client):
    _login_admin(client); _make_super_admin()
    for path in (
        "/admin/settings/chr",
        "/admin/settings/chr/lock",
        "/admin/settings/chr/unlock",
        "/admin/settings/chr/test",
        "/admin/settings/chr/reveal",
    ):
        rv = client.post(path)
        assert rv.status_code == 404, f"{path} should 404 — got {rv.status_code}"


def test_chr_settings_module_is_gone():
    """``app.services.chr_settings`` should not be importable."""
    import importlib
    with pytest.raises(ImportError):
        importlib.import_module("app.services.chr_settings")
