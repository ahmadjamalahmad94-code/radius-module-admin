"""Customer RADIUS ↔ proxy tunnel — panel-side tests (Agent A).

Pins the design's headline guarantees from
``docs/CUSTOMER_RADIUS_TUNNEL_DESIGN.md``:

* §1 IP allocator deterministic + overflow guard
* §3 heartbeat round-trip is idempotent (same input → same fingerprint)
* §4.1 ``GET /api/proxy/radius-peers`` shape + auth
* §6.1 ``chr_shared_secret`` lands in the authenticated routing-table
  response AND never lands in the logs
* §6.4 fingerprint compare → badge state transitions + 3-cycle P9 alarm
* Tunnel provision is idempotent (no side effect when payload unchanged)
"""
from __future__ import annotations

import logging

import pytest

from app.extensions import db
from app.models import CustomerRadiusInstance, ProxyRealmRoute, Setting
from app.services.customer_radius_tunnel import (
    DRIFT_ALARM_AFTER,
    IpAllocatorError,
    allocate_radius_wg_ip,
    build_radius_peers_payload,
    build_tunnel_config,
    compute_fingerprint,
    ingest_wg_radius_report,
    sync_badge_for,
)
from fleet.registry.infra_settings import (
    get_chr_shared_secret_plaintext,
    set_chr_shared_secret,
    set_proxy_radius_endpoint,
    set_proxy_radius_pubkey,
    set_proxy_radius_tunnel_ip,
)

from .conftest import proxy_token


PROXY_PUBKEY_B64 = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
PROXY_ENDPOINT = "proxy.hoberadius.com:51822"
PROXY_TUNNEL_IP = "10.200.0.1"


# ════════════════════════════════════════════════════════════════════════
# §1 — IP allocator
# ════════════════════════════════════════════════════════════════════════
class TestIpAllocator:
    def test_deterministic_simple_cases(self):
        # The doc's exact example: customer 5 → 10.200.5.2
        assert allocate_radius_wg_ip(5) == "10.200.5.2"
        assert allocate_radius_wg_ip(1) == "10.200.1.2"
        assert allocate_radius_wg_ip(254) == "10.200.254.2"

    def test_overflow_rejected_loudly(self):
        with pytest.raises(IpAllocatorError):
            allocate_radius_wg_ip(70000)
        with pytest.raises(IpAllocatorError):
            allocate_radius_wg_ip(0)
        with pytest.raises(IpAllocatorError):
            allocate_radius_wg_ip(-3)

    def test_same_call_same_result(self):
        a = allocate_radius_wg_ip(42)
        b = allocate_radius_wg_ip(42)
        assert a == b


# ════════════════════════════════════════════════════════════════════════
# §6.1 — chr_shared_secret in the authenticated routing-table response
# ════════════════════════════════════════════════════════════════════════
class TestChrSharedSecretInRoutingTable:
    URL = "/api/proxy/routing-table"
    SECRET = "u8QkUUtfZjXrYpLn7P9aZWuQbN2pXKv6"

    def test_secret_present_when_set(self, proxy_app, client, caplog):
        set_chr_shared_secret(self.SECRET)
        with caplog.at_level(logging.DEBUG):
            r = client.get(self.URL, headers={"X-Proxy-Token": proxy_token()})
        assert r.status_code == 200, r.get_data(as_text=True)
        body = r.get_json()
        assert "chr_shared_secret" in body, "design §6.1 requires the field"
        assert body["chr_shared_secret"] == self.SECRET
        # §security invariant — plaintext secret must NEVER end up in a log
        # record. We allow the fingerprint (sha256 prefix) to appear; the
        # actual plaintext must not.
        joined_logs = "\n".join(rec.getMessage() for rec in caplog.records)
        assert self.SECRET not in joined_logs, (
            "design §6 + security: chr_shared_secret must never appear in logs"
        )

    def test_secret_empty_when_unset(self, proxy_app, client):
        # No secret minted on this app — published field is ""
        r = client.get(self.URL, headers={"X-Proxy-Token": proxy_token()})
        body = r.get_json()
        assert body["chr_shared_secret"] == ""

    def test_routing_table_requires_auth(self, proxy_app, client):
        # Missing X-Proxy-Token → 401, the existing contract.
        r = client.get(self.URL)
        assert r.status_code == 401


# ════════════════════════════════════════════════════════════════════════
# §4.1 — GET /api/proxy/radius-peers
# ════════════════════════════════════════════════════════════════════════
class TestRadiusPeersEndpoint:
    URL = "/api/proxy/radius-peers"

    def test_requires_x_proxy_token(self, proxy_app, client):
        r = client.get(self.URL)
        assert r.status_code == 401

    def test_empty_set_when_no_qualifying_instance(self, proxy_app, client):
        r = client.get(self.URL, headers={"X-Proxy-Token": proxy_token()})
        body = r.get_json()
        assert body["ok"] is True
        assert body["interface"] == "wg-radius"
        assert body["listen_port"] == 51822
        assert body["peer_count"] == 0
        assert body["peers"] == []
        # Stable panel pubkey is minted on first call — non-empty wg key.
        assert isinstance(body["panel_wg_pubkey"], str) and len(body["panel_wg_pubkey"]) >= 40

    def test_qualifying_instances_appear(self, proxy_app, client, customer_factory):
        _, inst5 = customer_factory(
            customer_id=5,
            wg_public_key=PROXY_PUBKEY_B64,
            instance_name="client5-radius",
        )
        # An instance without a reported pubkey must be excluded.
        customer_factory(customer_id=7, wg_public_key="")

        r = client.get(self.URL, headers={"X-Proxy-Token": proxy_token()})
        body = r.get_json()
        names = [p["name"] for p in body["peers"]]
        assert "client5-radius" in names
        assert len([p for p in body["peers"] if p["name"] == "client5-radius"]) == 1
        client5 = next(p for p in body["peers"] if p["name"] == "client5-radius")
        assert client5["allowed_ips"] == ["10.200.5.2/32"]
        assert client5["endpoint"] is None
        assert client5["public_key"] == PROXY_PUBKEY_B64
        # Excluded instance does NOT appear.
        assert not any("client7" in p["name"] for p in body["peers"])

    def test_disabled_instance_is_excluded(self, proxy_app, client, customer_factory):
        customer_factory(
            customer_id=9, wg_public_key=PROXY_PUBKEY_B64, status="disabled",
        )
        r = client.get(self.URL, headers={"X-Proxy-Token": proxy_token()})
        body = r.get_json()
        names = [p["name"] for p in body["peers"]]
        assert not any("client9" in n for n in names)

    def test_panel_pubkey_is_stable_across_calls(self, proxy_app, client):
        a = client.get(self.URL, headers={"X-Proxy-Token": proxy_token()}).get_json()
        b = client.get(self.URL, headers={"X-Proxy-Token": proxy_token()}).get_json()
        assert a["panel_wg_pubkey"] == b["panel_wg_pubkey"], (
            "stable-slot invariant: panel wg-radius key must not regenerate"
        )


# ════════════════════════════════════════════════════════════════════════
# §3 + §6.4 — heartbeat round-trip + fingerprint reconcile
# ════════════════════════════════════════════════════════════════════════
class TestTunnelConfigBuilder:
    def _seed_proxy_settings(self):
        set_proxy_radius_pubkey(PROXY_PUBKEY_B64)
        set_proxy_radius_endpoint(PROXY_ENDPOINT)
        set_proxy_radius_tunnel_ip(PROXY_TUNNEL_IP)

    def _seed_route_secret(self, instance: CustomerRadiusInstance, secret: str) -> None:
        ref = f"radius_secret.customer.{instance.customer_id}"
        db.session.add(Setting(key=ref, value=secret))
        route = ProxyRealmRoute(
            customer_id=instance.customer_id,
            realm=instance.realm,
            radius_instance_id=instance.id,
            target_radius_ip=instance.radius_auth_ip,
            secret_vault_ref=ref,
            status="active",
        )
        db.session.add(route)
        db.session.commit()

    def test_payload_shape_matches_design(self, proxy_app, customer_factory):
        self._seed_proxy_settings()
        _, inst = customer_factory(customer_id=5)
        self._seed_route_secret(inst, "rR7Hsh-very-long-test-secret-K2m")

        tc = build_tunnel_config(inst)
        payload = tc.as_payload()
        assert payload["tunnel_ip"] == "10.200.5.2"
        assert payload["tunnel_cidr"] == 16
        assert payload["proxy_public_key"] == PROXY_PUBKEY_B64
        assert payload["proxy_endpoint"] == PROXY_ENDPOINT
        assert payload["proxy_tunnel_ip"] == PROXY_TUNNEL_IP
        assert payload["allowed_ips"] == ["10.200.0.1/32"]
        assert payload["persistent_keepalive"] == 25
        assert payload["radius_secret"] == "rR7Hsh-very-long-test-secret-K2m"
        assert payload["listen_ports"] == {"auth": 1812, "acct": 1813}
        assert payload["fingerprint"].startswith("sha256:")
        assert payload["enabled"] is True

    def test_disabled_when_proxy_not_configured(self, proxy_app, customer_factory):
        # No proxy settings minted → enabled=False, but the rest of the
        # block still computes (tunnel_ip, allowed_ips=[] because
        # proxy_tunnel_ip is "").
        _, inst = customer_factory(customer_id=11)
        tc = build_tunnel_config(inst)
        assert tc.enabled is False
        assert tc.tunnel_ip == "10.200.11.2"

    def test_idempotent_same_state_same_fingerprint(self, proxy_app, customer_factory):
        """Idempotency requirement (§3 idempotent provision): repeated
        heartbeats with the same panel + instance state produce the same
        fingerprint, so the customer side does not rewrite local config."""
        self._seed_proxy_settings()
        _, inst = customer_factory(customer_id=42)
        self._seed_route_secret(inst, "stable-route-secret-32-chars-yyyyy")

        first = build_tunnel_config(inst)
        second = build_tunnel_config(inst)
        third = build_tunnel_config(inst)
        assert first.fingerprint == second.fingerprint == third.fingerprint


class TestHeartbeatFingerprintReconcile:
    def _setup(self, customer_factory):
        set_proxy_radius_pubkey(PROXY_PUBKEY_B64)
        set_proxy_radius_endpoint(PROXY_ENDPOINT)
        set_proxy_radius_tunnel_ip(PROXY_TUNNEL_IP)
        _, inst = customer_factory(customer_id=5)
        return inst

    def test_matched_fingerprint_flips_badge_to_in_sync(self, proxy_app, customer_factory):
        inst = self._setup(customer_factory)
        tc = build_tunnel_config(inst)
        # Pretend the customer just applied the exact same config.
        summary = ingest_wg_radius_report(
            inst,
            {
                "public_key": PROXY_PUBKEY_B64,
                "config_fingerprint": tc.fingerprint,
                "last_handshake_age_s": 12,
            },
            published_fingerprint=tc.fingerprint,
        )
        assert summary["drift_action"] == "matched"
        badge = sync_badge_for(inst)
        assert badge["state"] == "in_sync"
        assert "متزامن" in badge["label_ar"]

    def test_three_cycle_drift_alarms(self, proxy_app, customer_factory, caplog):
        inst = self._setup(customer_factory)
        tc = build_tunnel_config(inst)
        wrong_fp = "sha256:" + ("d" * 64)
        last_summary = None
        with caplog.at_level(logging.WARNING):
            for cycle in range(DRIFT_ALARM_AFTER):
                last_summary = ingest_wg_radius_report(
                    inst,
                    {
                        "public_key": PROXY_PUBKEY_B64,
                        "config_fingerprint": wrong_fp,
                    },
                    published_fingerprint=tc.fingerprint,
                )
        assert last_summary["drift_action"] == "alarm"
        assert inst.drift_cycles >= DRIFT_ALARM_AFTER
        badge = sync_badge_for(inst)
        assert badge["state"] == "alarm"

    def test_pubkey_change_audited_via_summary(self, proxy_app, customer_factory):
        inst = self._setup(customer_factory)
        tc = build_tunnel_config(inst)
        first = ingest_wg_radius_report(
            inst,
            {"public_key": PROXY_PUBKEY_B64, "config_fingerprint": tc.fingerprint},
            published_fingerprint=tc.fingerprint,
        )
        assert first["pubkey_changed"] is True

        # Second pass with the SAME pubkey → no change report.
        second = ingest_wg_radius_report(
            inst,
            {"public_key": PROXY_PUBKEY_B64, "config_fingerprint": tc.fingerprint},
            published_fingerprint=tc.fingerprint,
        )
        assert second["pubkey_changed"] is False

    def test_no_report_block_still_stages_published_fingerprint(
        self, proxy_app, customer_factory,
    ):
        """When the customer's heartbeat omits the wg_radius block (older
        client / first contact), we still stage the published fingerprint
        for the NEXT cycle to compare against."""
        inst = self._setup(customer_factory)
        tc = build_tunnel_config(inst)
        summary = ingest_wg_radius_report(
            inst, None, published_fingerprint=tc.fingerprint,
        )
        assert summary["drift_action"] == ""
        assert inst.last_published_fingerprint == tc.fingerprint


# ════════════════════════════════════════════════════════════════════════
# Heartbeat HTTP integration — round-trip exercises the same path the
# real bridge will hit
# ════════════════════════════════════════════════════════════════════════
class TestHeartbeatHttpIntegration:
    URL = "/api/integration/hoberadius/instance-ops/heartbeat"

    def _set_signing(self, proxy_app):
        # Unsigned integration is allowed when LICENSE_CHECK_SIGNATURE_REQUIRED
        # is unset (matching how the bridge code paths run in dev). The
        # signature helper accepts that mode in tests already; we just
        # ensure the relevant flag is False so the heartbeat exercises
        # the full route handler.
        proxy_app.config.setdefault("LICENSE_CHECK_SIGNATURE_REQUIRED", False)

    def test_heartbeat_returns_radius_tunnel_block(
        self, proxy_app, client, customer_factory,
    ):
        from app.models import License, Plan
        from datetime import datetime, timedelta

        self._set_signing(proxy_app)
        set_proxy_radius_pubkey(PROXY_PUBKEY_B64)
        set_proxy_radius_endpoint(PROXY_ENDPOINT)
        set_proxy_radius_tunnel_ip(PROXY_TUNNEL_IP)
        cust, inst = customer_factory(customer_id=5)

        plan = Plan(name="default", slug="default", monthly_price=0)
        db.session.add(plan); db.session.flush()
        lic = License(
            customer_id=cust.id, plan_id=plan.id,
            license_key="HBR-TUNNEL-TEST-KEY",
            status="active",
            starts_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(days=30),
        )
        db.session.add(lic); db.session.commit()

        body = {
            "license_key": "HBR-TUNNEL-TEST-KEY",
            "server_fingerprint": "fp-test",
            "realm": inst.realm,
            "wg_radius": {
                "public_key": PROXY_PUBKEY_B64,
                "interface_up": True,
                "tunnel_ip": "10.200.5.2",
                "last_handshake_age_s": 35,
                "freeradius_proxy_client_present": True,
                "config_fingerprint": "sha256:" + ("0" * 64),
            },
        }
        r = client.post(self.URL, json=body)
        assert r.status_code == 200, r.get_data(as_text=True)
        payload = r.get_json()
        assert "radius_tunnel" in payload, "heartbeat response must carry §3.2 block"
        rt = payload["radius_tunnel"]
        assert rt["enabled"] is True
        assert rt["tunnel_ip"] == "10.200.5.2"
        assert rt["proxy_public_key"] == PROXY_PUBKEY_B64
        assert rt["fingerprint"].startswith("sha256:")
        # Pubkey persisted onto the instance row.
        db.session.refresh(inst)
        assert inst.wg_public_key == PROXY_PUBKEY_B64
