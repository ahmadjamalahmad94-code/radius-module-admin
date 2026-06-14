"""fix/wg-data-peer-publish-pipeline — panel publishes the wg-data peer.

Live blocker: chr-vpn-2's wg-data peer shows rx=0 / no handshake / ping
10.98.0.1 timeout → the PROXY never added this CHR's wg-data peer
(pubkey QyVOMA0/…, allowed-ips 10.98.0.12/32).

VERDICT these tests pin: the panel MINTS the wg-data keypair
(panel-mints-panel-knows — see onboarding_service.generate_keys; the
script bakes private-key="{{ WG_DATA_PRIVKEY }}", so the CHR never
self-generates it), persists the pubkey on the node row, and PUBLISHES
it at GET /api/proxy/wg-peers. So:
  * it is NOT a "panel can't learn the key" gap (no REST read needed →
    the `not allowed (9)` permission bug is irrelevant to publishing);
  * it is NOT a panel-publish gap when the row carries the pubkey;
  * the remaining gap is the PROXY polling + applying the published set.

These tests prove the panel side end-to-end so a live rx=0 with a GREEN
publish row points squarely at a proxy deploy/poll gap.
"""
from __future__ import annotations

import hashlib
import hmac
import time

import pytest

from app.extensions import db
from fleet.registry.models_chr import FleetChrNode, FleetProvider

SHARED_SECRET = "test-proxy-secret"
CHR_VPN2_PUBKEY = "QyVOMA0/nByaNl9D85VD60xuMFFui90sS1W0IdOuuFE="


@pytest.fixture()
def proxy_app(app):
    app.config["RADIUS_PROXY_SHARED_SECRET"] = SHARED_SECRET
    return app


def _token() -> str:
    ts = int(time.time())
    nonce = "n-" + str(ts)
    mac = hmac.new(
        SHARED_SECRET.encode(), f"{ts}:{nonce}".encode(), hashlib.sha256,
    ).hexdigest()
    return f"{ts}:{nonce}:{mac}"


def _provider() -> FleetProvider:
    p = FleetProvider.query.first()
    if p is not None:
        return p
    p = FleetProvider(name="pp-prov", cost_model="open", price_per_tb=0,
                      overage_allowed=False, billing_cycle_day=1)
    db.session.add(p); db.session.commit()
    return p


_SEQ = [10]


def _node(**kw) -> FleetChrNode:
    _SEQ[0] += 1
    base = dict(
        provider_id=_provider().id,
        name=f"chr-pp-{_SEQ[0]}",
        public_ip=f"178.105.180.{_SEQ[0]}",
        wg_mgmt_ip=f"10.99.0.{_SEQ[0]}", wg_mgmt_pubkey="V" * 44,
        wg_data_pubkey="d" * 44,
        max_sessions=500, link_speed_mbps=1000, weight=1.0,
        enabled=True, drain=False, status="provisioning",
    )
    base.update(kw)
    n = FleetChrNode(**base)
    db.session.add(n); db.session.commit()
    return n


# ════════════════════════════════════════════════════════════════════════
# (1) desired_proxy_peers includes a provisioning node w/ its wg-data key
# ════════════════════════════════════════════════════════════════════════
class TestDesiredProxyPeers:

    def test_node_with_pubkey_is_published(self, app):
        with app.app_context():
            n = _node(name="chr-vpn-2", wg_mgmt_ip="10.99.0.12",
                      wg_data_pubkey=CHR_VPN2_PUBKEY)
            from fleet.sync.peers import desired_proxy_peers
            mine = [p for p in desired_proxy_peers() if p.name == "chr-vpn-2"]
            assert mine, "a provisioning node with a wg-data pubkey must publish"
            assert mine[0].public_key == CHR_VPN2_PUBKEY
            assert mine[0].allowed_ips == ["10.98.0.12/32"]

    def test_node_without_pubkey_is_not_published(self, app):
        with app.app_context():
            _node(name="chr-nopub", wg_mgmt_ip="10.99.0.30", wg_data_pubkey="")
            from fleet.sync.peers import desired_proxy_peers
            assert not any(p.name == "chr-nopub" for p in desired_proxy_peers())

    def test_disabled_node_is_not_published(self, app):
        with app.app_context():
            _node(name="chr-off", wg_mgmt_ip="10.99.0.31", status="disabled")
            from fleet.sync.peers import desired_proxy_peers
            assert not any(p.name == "chr-off" for p in desired_proxy_peers())


# ════════════════════════════════════════════════════════════════════════
# (2) GET /api/proxy/wg-peers serves the peer (what the proxy polls)
# ════════════════════════════════════════════════════════════════════════
class TestWgPeersEndpoint:

    def test_endpoint_publishes_chr_vpn2(self, proxy_app, client):
        with proxy_app.app_context():
            _node(name="chr-vpn-2-ep", wg_mgmt_ip="10.99.0.12",
                  wg_data_pubkey=CHR_VPN2_PUBKEY)
        r = client.get("/api/proxy/wg-peers", headers={"X-Proxy-Token": _token()})
        assert r.status_code == 200, r.data[:200]
        body = r.get_json()
        assert body["interface"] == "wg-data"
        assert body["listen_port"] == 51821
        mine = [p for p in body["peers"] if p["public_key"] == CHR_VPN2_PUBKEY]
        assert mine, "wg-peers must publish chr-vpn-2's wg-data pubkey"
        assert mine[0]["allowed_ips"] == ["10.98.0.12/32"]
        assert mine[0]["endpoint"] is None  # proxy is the listener

    def test_endpoint_requires_auth(self, proxy_app, client):
        r = client.get("/api/proxy/wg-peers")  # no token
        assert r.status_code == 401


# ════════════════════════════════════════════════════════════════════════
# (3) Troubleshoot view surfaces the publish state (operator-visible)
# ════════════════════════════════════════════════════════════════════════
class TestTroubleshootPublishRow:

    def test_publish_row_green_when_publishable(self, app):
        with app.app_context():
            n = _node(name="chr-pub-ok", wg_mgmt_ip="10.99.0.40",
                      wg_data_pubkey=CHR_VPN2_PUBKEY)
            from fleet.ui.troubleshoot_view import build_view
            view = build_view(n)
            row = next(r for r in view.rows if r.key == "wg_data_peer_publish")
            assert row.ok is True
            assert "10.98.0.40/32" in row.value
            # The green-but-no-handshake hint points at the proxy.
            # (detail is empty when ok; the proxy guidance lives in docs)

    def test_publish_row_red_when_pubkey_missing(self, app):
        with app.app_context():
            n = _node(name="chr-pub-bad", wg_mgmt_ip="10.99.0.41",
                      wg_data_pubkey="")
            from fleet.ui.troubleshoot_view import build_view
            view = build_view(n)
            row = next(r for r in view.rows if r.key == "wg_data_peer_publish")
            assert row.ok is False
            assert row.severity == "error"
            assert "wg_data_peer_not_publishable" in view.blockers
