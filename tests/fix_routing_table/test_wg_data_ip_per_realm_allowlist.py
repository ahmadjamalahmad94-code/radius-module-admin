"""routes[].allowed_chr_ips MUST include wg_data_ip.

Live-deploy regression (2026-06): the proxy received a RADIUS Access-Request
from CHR ``chr-vpn-1`` over the wg-data tunnel and logged:

    Packet from unknown CHR IP 10.98.0.11 — dropped

Even though the panel's ``/api/proxy/routing-table`` published
``chr_nodes[0].wg_data_ip = "10.98.0.11"`` correctly, the per-realm
allowlist (``routes[].allowed_chr_ips``) on the same response only
carried the node's PUBLIC IP. A proxy that enforces the per-realm
allowlist before falling through to the global ``chr_nodes[]`` map
therefore drops the packet.

The fix: every fleet (and legacy) node listed in
``r.allowed_fleet_chr_node_ids`` / ``r.allowed_chr_node_ids`` publishes
BOTH its public_ip AND its derived wg_data_ip in ``allowed_chr_ips``.

These tests pin that behaviour:

  1. Realm references a FLEET node ⇒ allowed_chr_ips contains both IPs.
  2. Realm references a LEGACY node ⇒ same: public_ip + derived wg_data_ip
     (from the legacy ``management_ip`` column).
  3. The order is stable (public first, wg-data second) and there are no
     duplicates.
  4. A node whose wg_mgmt_ip is outside the canonical 10.99/24 pool
     emits an empty wg_data_ip — the per-realm allowlist falls back to
     the public_ip alone (no fabricated 10.98 address).
"""
from __future__ import annotations

import hashlib
import hmac
import time

import pytest

from app.extensions import db
from app.models import Customer, CustomerRadiusInstance, ProxyRealmRoute

from fleet.registry.models_chr import FleetChrNode, FleetProvider


SHARED_SECRET = "test-wg-data-allowlist-secret"
URL = "/api/proxy/routing-table"


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
    nonce = f"perrealm-{ts}-{_NONCE_SEQ[0]}"
    mac = hmac.new(SHARED_SECRET.encode(), f"{ts}:{nonce}".encode(),
                   hashlib.sha256).hexdigest()
    return f"{ts}:{nonce}:{mac}"


def _provider() -> FleetProvider:
    p = FleetProvider.query.first()
    if p is not None:
        return p
    p = FleetProvider(
        name="allow-prov", cost_model="open", price_per_tb=0,
        overage_allowed=False, billing_cycle_day=1,
    )
    db.session.add(p); db.session.commit()
    return p


def _customer() -> Customer:
    c = Customer.query.first()
    if c is not None:
        return c
    c = Customer(company_name="acme", email="x@y.com", country_iso="PS", dial_code="970")
    db.session.add(c); db.session.commit()
    return c


def _make_fleet_node(**kw) -> FleetChrNode:
    base = dict(
        provider_id=_provider().id,
        name="chr-vpn-1",
        public_ip="178.105.244.112",
        wg_mgmt_ip="10.99.0.11",
        wg_mgmt_pubkey="x" * 44,
        max_sessions=500, link_speed_mbps=1000,
        weight=1.0, enabled=True, drain=False,
        status="up", cpu_pct=10, active_sessions=0,
    )
    base.update(kw)
    n = FleetChrNode(**base)
    db.session.add(n); db.session.commit()
    return n


def _make_realm(*, fleet_ids=None) -> ProxyRealmRoute:
    """Build a per-realm route allow-listing the given fleet node ids.

    The legacy `allowed_chr_node_ids` allow-list was dropped in step 6 of
    docs/CONSOLIDATION.md; this helper now reflects the fleet-only world.
    """
    cust = _customer()
    inst = CustomerRadiusInstance(
        customer_id=cust.id,
        instance_name="r-inst",
        radius_auth_ip="10.200.0.2",
        mgmt_wg_ip="10.99.0.99",
        realm="acme",
    )
    db.session.add(inst); db.session.commit()
    r = ProxyRealmRoute(
        realm="acme", customer_id=cust.id,
        radius_instance_id=inst.id,
        target_radius_ip="10.200.0.2",
        status="active",
        allowed_fleet_chr_node_ids=list(fleet_ids or []),
    )
    db.session.add(r); db.session.commit()
    return r


# ════════════════════════════════════════════════════════════════════════
# 1. The headline live-deploy regression
# ════════════════════════════════════════════════════════════════════════


def test_fleet_node_realm_publishes_both_public_and_wg_data(proxy_app, client):
    """The live chr-vpn-1 shape: wg_mgmt 10.99.0.11 → wg-data 10.98.0.11.
    Both IPs must end up in the per-realm allowlist."""
    node = _make_fleet_node()
    _make_realm(fleet_ids=[node.id])
    body = client.get(URL, headers={"X-Proxy-Token": _token()}).get_json()
    assert body["ok"] is True
    assert len(body["routes"]) == 1
    allowed = body["routes"][0]["allowed_chr_ips"]
    assert "178.105.244.112" in allowed, "public_ip missing from realm allowlist"
    assert "10.98.0.11" in allowed, (
        "wg_data_ip missing from realm allowlist — the live `unknown CHR IP "
        "10.98.0.11 — dropped` regression"
    )
    # Order: public first, derived wg-data second — keeps the legacy proxy
    # (pre-wg-data) reading the public IP before the new shape lands.
    assert allowed.index("178.105.244.112") < allowed.index("10.98.0.11")


def test_quirky_mgmt_pool_falls_back_to_public_only(proxy_app, client):
    """A fleet node with wg_mgmt outside 10.99/16 has no derived wg-data IP.
    The per-realm allowlist falls back to the public IP only — we never
    fabricate a wg-data address."""
    node = _make_fleet_node(name="chr-quirky", public_ip="178.105.244.222",
                            wg_mgmt_ip="172.16.0.11")
    _make_realm(fleet_ids=[node.id])
    body = client.get(URL, headers={"X-Proxy-Token": _token()}).get_json()
    allowed = body["routes"][0]["allowed_chr_ips"]
    assert allowed == ["178.105.244.222"], (
        "fabricated a wg-data IP for a node outside the canonical pool"
    )


def test_no_duplicates_in_per_realm_allowlist(proxy_app, client):
    """The per-realm allowlist must not publish the same IP twice. With
    fleet-only sourcing (after step 6 of docs/CONSOLIDATION.md) the only
    way duplicates could appear would be a bug in the (public_ip, wg_data_ip)
    pair derivation — pin it explicitly."""
    fleet = _make_fleet_node(name="chr-fl", public_ip="203.0.113.40",
                             wg_mgmt_ip="10.99.0.40")
    _make_realm(fleet_ids=[fleet.id])
    body = client.get(URL, headers={"X-Proxy-Token": _token()}).get_json()
    allowed = body["routes"][0]["allowed_chr_ips"]
    assert sorted(allowed) == sorted(set(allowed)), f"duplicates: {allowed}"
    assert "203.0.113.40" in allowed
    assert "10.98.0.40" in allowed


def test_routing_table_live_exact_repro(proxy_app, client):
    """Pin the exact LIVE 2026-06 ``chr-vpn-1`` JSON shape — the contract
    the proxy agent will consume. If this snapshot changes, the proxy team
    needs a heads-up.
    """
    node = _make_fleet_node()  # exact live shape
    _make_realm(fleet_ids=[node.id])
    body = client.get(URL, headers={"X-Proxy-Token": _token()}).get_json()

    # chr_nodes[] contract (global allowlist + wg_data_ip mapping).
    entry = next(e for e in body["chr_nodes"] if e["name"] == "chr-vpn-1")
    assert entry["name"]        == "chr-vpn-1"
    assert entry["public_ip"]   == "178.105.244.112"
    assert entry["wg_mgmt_ip"]  == "10.99.0.11"
    assert entry["wg_data_ip"]  == "10.98.0.11"
    assert entry["status"]      == "up"
    assert entry["enabled"]     is True
    assert entry["drain"]       is False
    assert entry["source"]      == "fleet"

    # routes[] contract — per-realm allowlist now MUST include wg_data_ip.
    route = body["routes"][0]
    assert route["realm"] == "acme"
    assert "178.105.244.112" in route["allowed_chr_ips"]
    assert "10.98.0.11"      in route["allowed_chr_ips"]
