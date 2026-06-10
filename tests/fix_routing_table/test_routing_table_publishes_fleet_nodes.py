"""Hotfix verification: GET /api/proxy/routing-table publishes fleet nodes.

Reproduces the live-deploy bug: a provisioned ``chr-vpn-1`` (the only node
on the deployment) was invisible to the proxy because the routing-table
handler read the LEGACY ``ChrNode`` table AND filtered to
``status == "active"``. The new ``fleet_chr_nodes`` table the onboarding
wizard writes to was never even queried.

The tests below assert:

  * A provisioned ``FleetChrNode`` (the exact shape the live deploy has:
    name=chr-vpn-1, public=178.105.244.112, wg_mgmt=10.99.0.11) appears
    in ``chr_nodes[]``.
  * Each fleet entry carries ``name``, ``public_ip``, ``wg_mgmt_ip``,
    ``wg_data_ip`` (derived 10.99.0.11 → 10.98.0.11), ``status``,
    ``enabled``, ``drain``, ``source=="fleet"``.
  * ``status`` filtering accepts ``provisioning``, ``up``, ``degraded`` —
    rejects ``down`` and ``disabled`` and ``drain=True``.
  * Legacy ``ChrNode`` entries (the pre-fleet CHR-console table) are
    still published for backward compatibility — kept filtered to
    ``status="active"`` per the Phase-4 contract.
  * ``realms_status`` summarises why ``routes[]`` is empty so the
    operator sees "1 draft, 0 active" in one read.
  * Debug logging is OFF by default; flipping the Setting row to "1"
    emits a single INFO line per endpoint hit, captured below via
    the standard ``caplog`` fixture.
"""
from __future__ import annotations

import hashlib
import hmac
import time

import pytest

from app.extensions import db
from app.models import ChrNode, Customer, Setting

from fleet.registry.models_chr import FleetChrNode, FleetProvider


SHARED_SECRET = "test-routing-table-hotfix-secret"
URL = "/api/proxy/routing-table"


# ════════════════════════════════════════════════════════════════════════
# Fixtures
# ════════════════════════════════════════════════════════════════════════


@pytest.fixture()
def proxy_app(app):
    app.config["RADIUS_PROXY_SHARED_SECRET"] = SHARED_SECRET
    app.config["RADIUS_PROXY_TOKEN_TTL"] = 60
    from app.api import proxy_api
    proxy_api._NONCE_CACHE.clear()
    return app


_NONCE_SEQ: list[int] = [0]


def _token() -> str:
    _NONCE_SEQ[0] += 1
    ts = int(time.time())
    nonce = f"hotfix-{ts}-{_NONCE_SEQ[0]}"
    mac = hmac.new(SHARED_SECRET.encode(), f"{ts}:{nonce}".encode(),
                   hashlib.sha256).hexdigest()
    return f"{ts}:{nonce}:{mac}"


def _provider() -> FleetProvider:
    p = FleetProvider.query.first()
    if p is not None:
        return p
    p = FleetProvider(
        name="hotfix-provider", cost_model="open", price_per_tb=0,
        overage_allowed=False, billing_cycle_day=1,
    )
    db.session.add(p); db.session.commit()
    return p


def _live_node(**overrides) -> FleetChrNode:
    """The EXACT shape the deployed chr-vpn-1 has."""
    base = dict(
        provider_id=_provider().id,
        name="chr-vpn-1",
        public_ip="178.105.244.112",
        wg_mgmt_ip="10.99.0.11",
        wg_mgmt_pubkey="x" * 44,
        max_sessions=500, link_speed_mbps=1000,
        weight=1.0,
        enabled=True, drain=False,
        status="provisioning",     # the LIVE deploy's status
        cpu_pct=10, active_sessions=0,
    )
    base.update(overrides)
    n = FleetChrNode(**base)
    db.session.add(n); db.session.commit()
    return n


# ════════════════════════════════════════════════════════════════════════
# 1. The headline live-deploy regression
# ════════════════════════════════════════════════════════════════════════


def test_provisioning_fleet_node_appears_in_routing_table(proxy_app, client):
    node = _live_node()
    r = client.get(URL, headers={"X-Proxy-Token": _token()})
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert body["ok"] is True
    entries = body["chr_nodes"]
    assert entries, "chr_nodes[] is EMPTY — the live bug regressed"
    entry = next(e for e in entries if e["name"] == "chr-vpn-1")
    # Critical proxy-facing fields.
    assert entry["public_ip"] == "178.105.244.112"
    assert entry["wg_mgmt_ip"] == "10.99.0.11"
    # The owner's headline ask: the wg-data IP IS the RADIUS source.
    assert entry["wg_data_ip"] == "10.98.0.11"
    assert entry["status"] == "provisioning"
    assert entry["enabled"] is True
    assert entry["drain"] is False
    assert entry["source"] == "fleet"


def test_up_and_degraded_nodes_also_publish(proxy_app, client):
    _live_node(name="chr-up", public_ip="178.105.244.113",
               wg_mgmt_ip="10.99.0.12", status="up")
    _live_node(name="chr-deg", public_ip="178.105.244.114",
               wg_mgmt_ip="10.99.0.13", status="degraded")
    r = client.get(URL, headers={"X-Proxy-Token": _token()})
    names = {e["name"] for e in r.get_json()["chr_nodes"]}
    assert {"chr-up", "chr-deg"}.issubset(names)


def test_down_node_is_PUBLISHED_disabled_and_drain_excluded(proxy_app, client):
    """Live-deploy catch-22 fix.

    Publication tracks DATA-plane + admin intent, not control-plane health.
    A node whose wg-mgmt ping fails (``status=down``) but whose wg-data
    tunnel still carries RADIUS MUST appear in the proxy's allowlist —
    otherwise the proxy rejects packets from a healthy data plane just
    because the panel can't ping the control plane.

    Admin intent / drain are the gates: ``enabled=False`` (admin off)
    and ``drain=True`` (no new placements; existing keep running) both
    remove a node from the allowlist; ``status='disabled'`` also drops
    it. Health-``down`` does NOT.

    The brain's :func:`fleet.brain.placement.rank` separately excludes
    ``down`` from NEW placements — see :func:`test_brain_rank_still_excludes_down_from_new_placements`
    below for the corresponding-side check.
    """
    _live_node(name="chr-down", public_ip="178.105.244.115",
               wg_mgmt_ip="10.99.0.14", status="down")
    _live_node(name="chr-off", public_ip="178.105.244.116",
               wg_mgmt_ip="10.99.0.15", status="up", enabled=False)
    _live_node(name="chr-drain", public_ip="178.105.244.117",
               wg_mgmt_ip="10.99.0.16", status="up", drain=True)
    _live_node(name="chr-disabled", public_ip="178.105.244.118",
               wg_mgmt_ip="10.99.0.17", status="disabled")
    _live_node(name="chr-survivor", public_ip="178.105.244.119",
               wg_mgmt_ip="10.99.0.18", status="up")
    r = client.get(URL, headers={"X-Proxy-Token": _token()})
    entries = r.get_json()["chr_nodes"]
    by_name = {e["name"]: e for e in entries}

    # The control-plane-down node IS published (the fix), with its
    # status string intact so the proxy / operator still sees it's
    # unhealthy.
    assert "chr-down" in by_name, (
        "control-plane DOWN node was filtered out — the catch-22 regressed"
    )
    assert by_name["chr-down"]["status"] == "down"
    assert by_name["chr-down"]["wg_data_ip"] == "10.98.0.14"
    assert by_name["chr-down"]["enabled"] is True
    assert by_name["chr-down"]["drain"] is False

    # The healthy survivor is in too.
    assert "chr-survivor" in by_name

    # Admin intent + drain still gate publication.
    assert "chr-off" not in by_name
    assert "chr-drain" not in by_name
    assert "chr-disabled" not in by_name


def test_brain_rank_still_excludes_down_from_new_placements(proxy_app):
    """Corresponding-side invariant: a ``down`` node IS published to the
    proxy allowlist but the brain MUST NOT pick it for new logins."""
    from fleet.brain.placement import rank
    from fleet.health.models_health import FleetChrHealth

    down = _live_node(name="chr-rank-down", public_ip="178.105.244.220",
                      wg_mgmt_ip="10.99.0.20", status="down")
    up = _live_node(name="chr-rank-up", public_ip="178.105.244.221",
                    wg_mgmt_ip="10.99.0.21", status="up")
    db.session.add_all([
        FleetChrHealth(chr_id=down.id, state="down"),
        FleetChrHealth(chr_id=up.id, state="up"),
    ])
    db.session.commit()

    ranked = {ns.name for ns in rank()}
    assert "chr-rank-up" in ranked
    assert "chr-rank-down" not in ranked, (
        "brain rank() must keep excluding down nodes from new placements"
    )


def test_wg_data_ip_empty_for_non_canonical_mgmt_pool(proxy_app, client):
    """A node whose wg-mgmt address is not in the 10.99/16 pool gets
    no derived wg-data IP — the proxy falls back to the legacy
    public-IP allowlist for it."""
    _live_node(name="chr-quirky", public_ip="178.105.244.250",
               wg_mgmt_ip="172.16.0.11", status="up")
    r = client.get(URL, headers={"X-Proxy-Token": _token()})
    entry = next(e for e in r.get_json()["chr_nodes"]
                 if e["name"] == "chr-quirky")
    assert entry["wg_data_ip"] == ""


# ════════════════════════════════════════════════════════════════════════
# 2. Legacy ChrNode still published (Phase-4 contract gap #1 unchanged)
# ════════════════════════════════════════════════════════════════════════


def test_legacy_chr_node_active_still_published(proxy_app, client):
    n = ChrNode(
        name="chr-legacy-01",
        public_ip="203.0.113.50",
        capacity_mbps=1000, max_reserved_mbps=800,
        status="active",
        management_ip="10.99.0.99",
    )
    db.session.add(n); db.session.commit()
    r = client.get(URL, headers={"X-Proxy-Token": _token()})
    entry = next(e for e in r.get_json()["chr_nodes"]
                 if e["name"] == "chr-legacy-01")
    assert entry["public_ip"] == "203.0.113.50"
    assert entry["source"] == "legacy"
    # Legacy fields kept for backward compat.
    assert entry.get("management_ip") == "10.99.0.99"
    # And wg-data is still derived from the legacy management_ip
    # (the proxy needs SOMETHING to allowlist).
    assert entry["wg_data_ip"] == "10.98.0.99"


def test_fleet_node_wins_over_legacy_with_same_name(proxy_app, client):
    """A fleet node + legacy node with the same name → fleet entry wins
    (the wizard is the post-Phase-2 source of truth)."""
    _live_node(name="chr-shared", public_ip="178.105.244.200",
               wg_mgmt_ip="10.99.0.7", status="up")
    db.session.add(ChrNode(
        name="chr-shared",
        public_ip="203.0.113.7",
        capacity_mbps=1000, max_reserved_mbps=800,
        status="active",
    )); db.session.commit()
    entries = client.get(URL, headers={"X-Proxy-Token": _token()}).get_json()["chr_nodes"]
    matches = [e for e in entries if e["name"] == "chr-shared"]
    assert len(matches) == 1
    assert matches[0]["source"] == "fleet"
    assert matches[0]["public_ip"] == "178.105.244.200"


# ════════════════════════════════════════════════════════════════════════
# 3. Realms diagnostic — why routes[] is empty
# ════════════════════════════════════════════════════════════════════════


def test_realms_status_reports_draft_count(proxy_app, client):
    """A draft ProxyRealmRoute → routes[]=0 + realms_status.draft=1 +
    hint pointing the owner to the right admin page."""
    from app.models import (
        Customer, CustomerRadiusInstance, ProxyRealmRoute,
    )
    cust = Customer.query.first()
    if cust is None:
        cust = Customer(
            company_name="acme", email="x@y.com",
            country_iso="PS", dial_code="970",
        )
        db.session.add(cust); db.session.commit()
    inst = CustomerRadiusInstance(
        customer_id=cust.id,
        instance_name="acme-radius",
        radius_auth_ip="10.200.0.2",
        mgmt_wg_ip="10.99.0.99",
        realm="acme",
    )
    db.session.add(inst); db.session.commit()
    db.session.add(ProxyRealmRoute(
        realm="acme", customer_id=cust.id,
        radius_instance_id=inst.id,
        target_radius_ip="10.200.0.2",
        status="draft",
    )); db.session.commit()
    body = client.get(URL, headers={"X-Proxy-Token": _token()}).get_json()
    assert body["routes"] == []
    assert body["realms_status"]["draft"] == 1
    assert body["realms_status"]["active"] == 0
    assert body["realms_status"]["total"] == 1
    assert body["realms_status"]["hint"]


def test_realms_status_empty_when_active(proxy_app, client):
    """No realms ⇒ both counts zero + a hint."""
    body = client.get(URL, headers={"X-Proxy-Token": _token()}).get_json()
    assert body["realms_status"]["total"] == 0
    assert body["realms_status"]["active"] == 0
    assert body["realms_status"]["hint"]


# ════════════════════════════════════════════════════════════════════════
# 4. Debug-logging switch
# ════════════════════════════════════════════════════════════════════════


def test_debug_logging_default_off_no_extra_log(proxy_app, client, caplog):
    _live_node()
    with caplog.at_level("INFO", logger="fleet.proxy_api"):
        client.get(URL, headers={"X-Proxy-Token": _token()})
    assert all("fleet.proxy_api routing-table" not in rec.message
               for rec in caplog.records)


def test_debug_logging_when_setting_enabled(proxy_app, client, caplog):
    _live_node()
    db.session.add(Setting(key="fleet.proxy_api.debug_logging", value="1"))
    db.session.commit()
    with caplog.at_level("INFO", logger="fleet.proxy_api"):
        client.get(URL, headers={"X-Proxy-Token": _token()})
    msgs = [r.message for r in caplog.records]
    assert any("fleet.proxy_api routing-table" in m for m in msgs)
    assert any("chr_nodes=1" in m for m in msgs)


def test_debug_logging_helper_set_and_read(proxy_app):
    from app.services.proxy_api_debug import (
        SETTING_KEY, is_debug_enabled, set_debug_enabled,
    )
    assert is_debug_enabled() is False
    set_debug_enabled(True)
    assert is_debug_enabled() is True
    row = db.session.get(Setting, SETTING_KEY)
    assert row is not None and row.value == "1"
    set_debug_enabled(False)
    assert is_debug_enabled() is False
