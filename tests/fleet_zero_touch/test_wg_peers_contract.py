"""The proxy wg-peers contract: auth, exact JSON shape, eligibility, and the
wg_data_pubkey backfill that feeds it."""
from __future__ import annotations

import hashlib
import hmac
import time

import pytest

from app.extensions import db

from tests.fleet_zero_touch.conftest import _pk, make_node, make_provider

SECRET = "zero-touch-wg-peers-secret"
URL = "/api/proxy/wg-peers"


@pytest.fixture()
def proxy_app(app):
    app.config["RADIUS_PROXY_SHARED_SECRET"] = SECRET
    app.config["RADIUS_PROXY_TOKEN_TTL"] = 60
    from app.api import proxy_api
    proxy_api._NONCE_CACHE.clear()
    return app


_SEQ = [0]


def _token() -> str:
    _SEQ[0] += 1
    ts = int(time.time())
    nonce = f"zt-{ts}-{_SEQ[0]}"
    mac = hmac.new(SECRET.encode(), f"{ts}:{nonce}".encode(), hashlib.sha256).hexdigest()
    return f"{ts}:{nonce}:{mac}"


def test_requires_token(proxy_app, client):
    assert client.get(URL).status_code == 401


def test_publishes_eligible_peers_with_exact_shape(proxy_app, client):
    from fleet.registry import infra_settings as ifs
    ifs.set_panel_pubkey(_pk("panel"))
    prov = make_provider()
    make_node(prov, "chr-1", octet=11)
    make_node(prov, "drained", octet=12, drain=True)
    db.session.commit()

    r = client.get(URL, headers={"X-Proxy-Token": _token()})
    assert r.status_code == 200
    body = r.get_json()
    assert body["ok"] is True
    assert body["interface"] == "wg-data"
    assert body["listen_port"] == 51821
    assert body["panel_wg_pubkey"] == _pk("panel")
    assert body["peer_count"] == 1
    # The proxy reconciler reads data["peers"] and expects a TOP-LEVEL list.
    assert "peers" in body, "response must carry a top-level 'peers' field"
    assert isinstance(body["peers"], list), "'peers' must be a JSON list"
    assert "wg_data_peers" not in body, "the legacy key must be gone (single source)"
    peer = body["peers"][0]
    assert peer["name"] == "chr-1"
    assert peer["allowed_ips"] == ["10.98.0.11/32"]
    assert peer["public_key"] == _pk("d11")
    assert peer["endpoint"] is None  # proxy is the listener — CHRs dial in
    # exact key set the proxy parses (frozen contract)
    assert set(peer.keys()) == {"name", "public_key", "allowed_ips", "endpoint"}


def test_empty_fleet_returns_empty_peers_list(proxy_app, client):
    """No nodes → peers is an empty LIST, never missing/null (so the proxy's
    `data["peers"]` is always iterable — this is the bug that logged
    'peers not a list')."""
    r = client.get(URL, headers={"X-Proxy-Token": _token()})
    body = r.get_json()
    assert body["peers"] == []
    assert isinstance(body["peers"], list)
    assert body["peer_count"] == 0


def test_node_without_data_pubkey_omitted(proxy_app, client):
    prov = make_provider()
    make_node(prov, "no-data", octet=11, data_pub="")
    db.session.commit()
    r = client.get(URL, headers={"X-Proxy-Token": _token()})
    body = r.get_json()
    assert body["peer_count"] == 0
    assert body["peers"] == []


def test_backfill_populates_wg_data_pubkey_from_job(app):
    """A node created before the column existed gets its wg-data pubkey healed
    from the onboarding job refs (no key re-mint)."""
    import json
    from fleet.registry.models_onboarding import OnboardingJob

    prov = make_provider()
    node = make_node(prov, "legacy", octet=11, data_pub="")  # simulate pre-column row
    job = OnboardingJob(status="active")
    job.chr_id = node.id
    job.wg_keypair_ref = json.dumps({"mgmt_pubkey": _pk("m11"), "data_pubkey": _pk("d11")})
    db.session.add(job)
    db.session.commit()

    from fleet.sync.backfill import backfill_wg_data_pubkeys
    n = backfill_wg_data_pubkeys()
    assert n == 1
    db.session.refresh(node)
    assert node.wg_data_pubkey == _pk("d11")
    # idempotent: a second run touches nothing.
    assert backfill_wg_data_pubkeys() == 0
