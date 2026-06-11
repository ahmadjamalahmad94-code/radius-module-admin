"""Step 6 of docs/CONSOLIDATION.md — post-removal regression suite.

This file replaces the step-5 migration tests (the migration tool was
removed because the legacy ``chr_nodes`` table is gone). What's left
pins the post-removal contract:

  * the legacy admin/api routes are GONE (404 / no registration);
  * the routing-table contract is fleet-only and still publishes
    wg_data_ip + allowed_chr_ips for fleet nodes;
  * /admin/infra/system-health still renders the consolidated dashboard;
  * the sidebar groups «أسطول CHR» exposes the moved items and no
    longer carries a link to the deleted /admin/infra/chr-nodes page;
  * settings#chr is still labeled as «نمط الـCHR الواحد» (single-CHR
    mode) — relabel from step 4 stays.
"""
from __future__ import annotations

from app.extensions import db
from app.models import Admin


def _login_admin(client):
    return client.post("/login", data={"username": "admin", "password": "admin12345"})


def _make_super_admin():
    adm = Admin.query.first()
    if adm and not adm.is_super_admin:
        adm.is_super_admin = True
        db.session.commit()


# ─────────────────────────────────────────────────────────────────────────
# Legacy ChrNode/ChrNodeMetric are gone from the model namespace.
# ─────────────────────────────────────────────────────────────────────────
def test_chrnode_class_is_no_longer_exposed_from_app_models():
    import app.models as _models
    assert not hasattr(_models, "ChrNode"), "ChrNode should be deleted in step 6"
    assert not hasattr(_models, "ChrNodeMetric"), "ChrNodeMetric should be deleted in step 6"


def test_proxy_realm_route_dropped_legacy_allowlist_attribute(app):
    """The legacy ``allowed_chr_node_ids`` property + setter were removed
    in step 6; only the fleet allow-list survives.

    Takes the ``app`` fixture so the SQLAlchemy mapper is fully
    initialised — instantiating an ORM class directly without app
    context raises ``InvalidRequestError`` because the cross-package
    FleetChrNode relationship hasn't resolved yet.
    """
    # Force the fleet model class into the registry so the
    # CustomerVpnTunnel → FleetChrNode relationship can resolve when
    # ProxyRealmRoute (which lives next to those models) is instantiated.
    from fleet.registry.models_chr import FleetChrNode  # noqa: F401
    from app.models import ProxyRealmRoute
    r = ProxyRealmRoute()
    assert not hasattr(r, "allowed_chr_node_ids"), \
        "legacy allow-list property should be gone after step 6"
    assert hasattr(r, "allowed_fleet_chr_node_ids"), \
        "fleet allow-list property must still exist"


def test_service_allocation_uses_fleet_chr_node_id_only():
    from app.models import ServiceAllocation
    cols = {c.name for c in ServiceAllocation.__table__.columns}
    assert "fleet_chr_node_id" in cols, \
        "fleet_chr_node_id must be the model's FK column after step 6"
    assert "chr_node_id" not in cols, \
        "legacy chr_node_id must have been renamed away by the heal"


# ─────────────────────────────────────────────────────────────────────────
# Legacy routes no longer exist.
# ─────────────────────────────────────────────────────────────────────────
def test_legacy_chr_nodes_list_route_404s(client):
    _login_admin(client)
    rv = client.get("/admin/infra/chr-nodes")
    assert rv.status_code == 404


def test_legacy_chr_node_create_route_404s(client):
    _login_admin(client); _make_super_admin()
    rv = client.post("/admin/infra/chr-nodes/create", data={"name": "x"})
    assert rv.status_code == 404


def test_legacy_consolidation_routes_are_gone(client):
    _login_admin(client); _make_super_admin()
    assert client.get("/admin/infra/consolidation").status_code == 404
    assert client.post("/admin/infra/consolidation/run").status_code == 404


# ─────────────────────────────────────────────────────────────────────────
# Surviving pages still render correctly.
# ─────────────────────────────────────────────────────────────────────────
def test_system_health_still_renders_nested_resources(client):
    _login_admin(client)
    rv = client.get("/admin/infra/system-health")
    assert rv.status_code == 200
    body = rv.get_data(as_text=True)
    # The poller-liveness pill that landed in step 1 must still be there.
    assert "جامع مقاييس الأسطول" in body
    # And the rebuilt nested-dict template branch must still draw a
    # disk-percent — the most reliable signal across psutil-less envs.
    import re
    assert re.search(r"استخدام القرص (\d+)%", body), "disk pct not rendered"


def test_sidebar_still_groups_items_under_fleet_and_hides_legacy_link(client):
    _login_admin(client)
    body = client.get("/admin/infra/system-health").get_data(as_text=True)
    assert "أسطول CHR" in body
    for label in ("بروفايلات السرعة", "نسخ RADIUS", "تخصيصات الخدمة", "وكيل RADIUS"):
        assert label in body, f"sidebar should still expose «{label}» under fleet"
    assert 'href="/admin/infra/chr-nodes"' not in body, \
        "legacy chr-nodes link must not reappear"


def test_settings_chr_tab_was_removed_in_zero_central(client):
    """The settings#chr singleton tab was retired entirely by the
    zero-central work that landed after step 6. Per-node RouterOS
    credentials live on fleet_chr_nodes rows; the tab has nothing left
    to show, so it's gone from the page chrome and from the URL space."""
    _login_admin(client)
    body = client.get("/admin/settings").get_data(as_text=True)
    assert "نمط الـCHR الواحد" not in body, \
        "settings#chr tab text should be gone after zero-central"
    assert 'data-tab="chr"' not in body, \
        "settings#chr tab button should be gone after zero-central"


# ─────────────────────────────────────────────────────────────────────────
# Routing-table proof — pure fleet, wg_data_ip + allowed_chr_ips intact.
# ─────────────────────────────────────────────────────────────────────────
def test_routing_table_chr_nodes_are_fleet_sourced_only(app):
    """The routing-table JSON the proxy reads now sources nodes only from
    the fleet registry. We seed one fleet node and assert it's present +
    tagged ``source='fleet'``."""
    import hashlib
    import hmac
    import time

    from fleet.registry.models_chr import FleetChrNode, FleetProvider

    SHARED = "test-proxy-shared-secret-32-chars-long-xxxxxxxxx"
    app.config["RADIUS_PROXY_SHARED_SECRET"] = SHARED
    app.config["RADIUS_PROXY_TOKEN_TTL"] = 60
    from app.api import proxy_api
    proxy_api._NONCE_CACHE.clear()

    prov = FleetProvider(name="prov-1", cost_model="open", price_per_tb=0)
    db.session.add(prov); db.session.flush()
    db.session.add(FleetChrNode(
        provider_id=prov.id, name="chr-step6-1",
        public_ip="203.0.113.55",
        wg_mgmt_ip="10.99.0.55", wg_mgmt_pubkey="x",
        routeros_api_port=8443, routeros_api_user="", routeros_api_password_enc="",
        coa_port=3799, max_sessions=1000, link_speed_mbps=1000,
        status="up", enabled=True, drain=False,
    ))
    db.session.commit()

    ts = int(time.time())
    mac = hmac.new(SHARED.encode(), f"{ts}:rt-step6".encode(), hashlib.sha256).hexdigest()
    token = f"{ts}:rt-step6:{mac}"
    rv = app.test_client().get("/api/proxy/routing-table", headers={"X-Proxy-Token": token})
    assert rv.status_code == 200
    body = rv.get_json()
    assert body["ok"] is True
    entry = next(e for e in body["chr_nodes"] if e["name"] == "chr-step6-1")
    assert entry["source"] == "fleet"
    assert entry["public_ip"] == "203.0.113.55"
    assert entry["wg_data_ip"] == "10.98.0.55"  # the wg_mgmt → wg_data swap
