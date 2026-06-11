"""Phase-4 gate — contract gap #1: routing-table chr_nodes[] carries node name.

The proxy keys telemetry/placement by the registry node NAME, so every entry in
``GET /api/proxy/routing-table`` → ``chr_nodes[]`` must expose ``name`` (additive
to the pre-existing ``public_ip`` etc.). This asserts the field is present.
"""
from __future__ import annotations

import hashlib
import hmac
import time

import pytest

from app.extensions import db
from fleet.registry.models_chr import FleetChrNode, FleetProvider

SHARED_SECRET = "test-proxy-shared-secret-32-chars-long-xxxxxxxxx"
ROUTING_URL = "/api/proxy/routing-table"


@pytest.fixture()
def configured_app(app):
    app.config["RADIUS_PROXY_SHARED_SECRET"] = SHARED_SECRET
    app.config["RADIUS_PROXY_TOKEN_TTL"] = 60
    from app.api import proxy_api
    proxy_api._NONCE_CACHE.clear()
    return app


@pytest.fixture()
def active_chr(configured_app):
    """A live fleet CHR — post-step-6 the routing-table only reads the fleet."""
    prov = FleetProvider(name="p4-test", cost_model="open", price_per_tb=0)
    db.session.add(prov); db.session.flush()
    node = FleetChrNode(
        provider_id=prov.id,
        name="chr-exit-routing-01",
        public_ip="203.0.113.77",
        wg_mgmt_ip="10.99.0.77", wg_mgmt_pubkey="x",
        routeros_api_port=8443, routeros_api_user="", routeros_api_password_enc="",
        coa_port=3799,
        max_sessions=1000, link_speed_mbps=1000,
        status="up", enabled=True, drain=False,
    )
    db.session.add(node)
    db.session.commit()
    return node


def _sign_token(nonce: str = "rt1") -> str:
    ts = int(time.time())
    mac = hmac.new(SHARED_SECRET.encode(), f"{ts}:{nonce}".encode(), hashlib.sha256).hexdigest()
    return f"{ts}:{nonce}:{mac}"


def test_routing_table_chr_nodes_include_name(configured_app, client, active_chr):
    r = client.get(ROUTING_URL, headers={"X-Proxy-Token": _sign_token()})
    assert r.status_code == 200, r.get_data(as_text=True)
    body = r.get_json()
    assert body["ok"] is True
    chr_nodes = body["chr_nodes"]
    assert chr_nodes, "expected at least one active CHR in the routing table"
    entry = next(e for e in chr_nodes if e.get("name") == "chr-exit-routing-01")
    # gap-1: name is present (additive — public_ip still there too).
    assert entry["name"] == "chr-exit-routing-01"
    assert entry["public_ip"] == "203.0.113.77"
