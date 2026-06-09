"""Tests for the Phase-4-B telemetry ingest endpoint and service.

Covers:
  * Auth — missing token, bad HMAC, expired timestamp, replay → 401.
  * Validation — non-JSON body, missing fields, wrong types, out-of-range,
    bad sampled_at, unknown node → 400/404 per the contract envelope.
  * Happy path — valid payload persists one ``fleet_chr_metrics`` row with
    correct contract→column mapping; response carries health + directives.
  * Query helpers — ``latest_metrics()`` returns the most recent sample;
    ``rolling_window(n)`` averages exactly the last N samples (no leakage).
  * Shed directive flips when ``cpu_util`` crosses the configured threshold.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from datetime import datetime, timezone

import pytest

from app.extensions import db
from fleet.config import FLEET
from fleet.health.models_health import FleetChrMetric
from fleet.health.telemetry_ingest import (
    TelemetrySample,
    TelemetryValidationError,
    UnknownNodeError,
    ingest_payload,
    latest_metrics,
    rolling_window,
    validate,
)
from fleet.registry.models_chr import FleetChrNode, FleetProvider


SHARED_SECRET = "test-proxy-shared-secret-32-chars-long-xxxxxxxxx"
TELEMETRY_URL = "/api/proxy/telemetry"


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────
@pytest.fixture()
def configured_app(app):
    """Ensure the proxy auth secret is set for the duration of each test."""
    app.config["RADIUS_PROXY_SHARED_SECRET"] = SHARED_SECRET
    app.config["RADIUS_PROXY_TOKEN_TTL"] = 60
    # Each test starts with a fresh nonce cache so replay tests are deterministic.
    from app.api import proxy_api
    proxy_api._NONCE_CACHE.clear()
    return app


@pytest.fixture()
def enrolled_node(configured_app):
    """A registry node the proxy can target by name."""
    prov = FleetProvider(name="Contabo", cost_model="open", price_per_tb=0)
    db.session.add(prov)
    db.session.flush()
    node = FleetChrNode(
        provider_id=prov.id,
        name="chr-exit-01",
        public_ip="203.0.113.11",
        wg_mgmt_ip="10.99.0.11",
        wg_mgmt_pubkey="PUBKEY_AAA===",
        max_sessions=4000,
        link_speed_mbps=1000,
        status="up",
        enabled=True,
        drain=False,
    )
    db.session.add(node)
    db.session.commit()
    return node


def _sign_token(secret: str = SHARED_SECRET, ts: int | None = None, nonce: str = "n1") -> str:
    if ts is None:
        ts = int(time.time())
    msg = f"{ts}:{nonce}".encode()
    mac = hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()
    return f"{ts}:{nonce}:{mac}"


def _valid_payload(node: str = "chr-exit-01", *, cpu: float = 0.62, sessions: int = 1280) -> dict:
    return {
        "node": node,
        "sampled_at": "2026-06-09T19:40:00Z",
        "metrics": {
            "cpu_util": cpu,
            "mem_util": 0.41,
            "active_sessions": sessions,
            "session_capacity": 4000,
            "latency_ms": 18.4,
            "egress_gbps": 0.74,
            "egress_gb_period": 512.0,
            "uptime_seconds": 86400,
        },
        "agent_version": "1.0.0",
    }


# ════════════════════════════════════════════════════════════════════════════
# Auth — the contract §0 promise
# ════════════════════════════════════════════════════════════════════════════
class TestAuth:
    def test_missing_token_is_401(self, configured_app, client, enrolled_node):
        r = client.post(TELEMETRY_URL, json=_valid_payload())
        assert r.status_code == 401
        assert r.get_json() == {"ok": False, "error": "unauthorized"}

    def test_bad_hmac_is_401(self, configured_app, client, enrolled_node):
        ts = int(time.time())
        bad_token = f"{ts}:n2:{'0' * 64}"
        r = client.post(TELEMETRY_URL, json=_valid_payload(),
                        headers={"X-Proxy-Token": bad_token})
        assert r.status_code == 401

    def test_expired_timestamp_is_401(self, configured_app, client, enrolled_node):
        old_ts = int(time.time()) - 600  # 10 min ago, TTL is 60s
        r = client.post(
            TELEMETRY_URL, json=_valid_payload(),
            headers={"X-Proxy-Token": _sign_token(ts=old_ts, nonce="exp1")},
        )
        assert r.status_code == 401

    def test_replay_is_rejected(self, configured_app, client, enrolled_node):
        token = _sign_token(nonce="replay1")
        ok = client.post(TELEMETRY_URL, json=_valid_payload(),
                         headers={"X-Proxy-Token": token})
        assert ok.status_code == 200
        again = client.post(TELEMETRY_URL, json=_valid_payload(),
                            headers={"X-Proxy-Token": token})
        assert again.status_code == 401

    def test_empty_shared_secret_denies_all(self, configured_app, client, enrolled_node):
        configured_app.config["RADIUS_PROXY_SHARED_SECRET"] = ""
        r = client.post(TELEMETRY_URL, json=_valid_payload(),
                        headers={"X-Proxy-Token": _sign_token(nonce="empty-secret")})
        assert r.status_code == 401


# ════════════════════════════════════════════════════════════════════════════
# Validation — every malformed shape maps to 400 (never 500)
# ════════════════════════════════════════════════════════════════════════════
class TestValidation:
    def _post(self, client, body, nonce="v1"):
        return client.post(
            TELEMETRY_URL, json=body,
            headers={"X-Proxy-Token": _sign_token(nonce=nonce)},
        )

    def test_non_json_body_is_400(self, configured_app, client, enrolled_node):
        r = client.post(
            TELEMETRY_URL, data="not-json",
            content_type="text/plain",
            headers={"X-Proxy-Token": _sign_token(nonce="nj1")},
        )
        assert r.status_code == 400
        assert r.get_json()["error"] == "bad_request"

    def test_missing_top_level_field_is_400(self, configured_app, client, enrolled_node):
        body = _valid_payload()
        body.pop("metrics")
        r = self._post(client, body, nonce="miss1")
        assert r.status_code == 400
        assert r.get_json()["error"] == "bad_request"
        assert "metrics" in r.get_json()["detail"]

    def test_metrics_not_object_is_400(self, configured_app, client, enrolled_node):
        body = _valid_payload(); body["metrics"] = "string"
        r = self._post(client, body, nonce="nob1")
        assert r.status_code == 400

    def test_cpu_util_out_of_range_is_400(self, configured_app, client, enrolled_node):
        body = _valid_payload(); body["metrics"]["cpu_util"] = 1.5
        r = self._post(client, body, nonce="cpu1")
        assert r.status_code == 400
        assert "cpu_util" in r.get_json()["detail"]

    def test_active_sessions_negative_is_400(self, configured_app, client, enrolled_node):
        body = _valid_payload(); body["metrics"]["active_sessions"] = -5
        r = self._post(client, body, nonce="neg1")
        assert r.status_code == 400

    def test_active_sessions_not_int_is_400(self, configured_app, client, enrolled_node):
        body = _valid_payload(); body["metrics"]["active_sessions"] = 12.7
        r = self._post(client, body, nonce="ni1")
        assert r.status_code == 400

    def test_boolean_metric_is_400(self, configured_app, client, enrolled_node):
        body = _valid_payload(); body["metrics"]["cpu_util"] = True
        r = self._post(client, body, nonce="bool1")
        assert r.status_code == 400

    def test_sampled_at_without_tz_is_400(self, configured_app, client, enrolled_node):
        body = _valid_payload(); body["sampled_at"] = "2026-06-09T19:40:00"
        r = self._post(client, body, nonce="tz1")
        assert r.status_code == 400

    def test_sampled_at_garbage_is_400(self, configured_app, client, enrolled_node):
        body = _valid_payload(); body["sampled_at"] = "yesterday"
        r = self._post(client, body, nonce="gb1")
        assert r.status_code == 400

    def test_unknown_node_is_404(self, configured_app, client, enrolled_node):
        body = _valid_payload(node="ghost-node")
        r = self._post(client, body, nonce="ghost1")
        assert r.status_code == 404
        assert r.get_json()["error"] == "unknown_node"

    def test_unknown_metric_key_is_tolerated(self, configured_app, client, enrolled_node):
        """Forward-compat: unknown keys ignored, request still succeeds."""
        body = _valid_payload()
        body["metrics"]["future_metric"] = 42
        r = self._post(client, body, nonce="fwd1")
        assert r.status_code == 200


# ════════════════════════════════════════════════════════════════════════════
# Happy path — full round-trip
# ════════════════════════════════════════════════════════════════════════════
class TestHappyPath:
    def test_valid_payload_persists_one_row_and_returns_contract_shape(
        self, configured_app, client, enrolled_node
    ):
        # Sanity: no metrics yet
        assert FleetChrMetric.query.count() == 0

        r = client.post(
            TELEMETRY_URL, json=_valid_payload(),
            headers={"X-Proxy-Token": _sign_token(nonce="happy1")},
        )
        assert r.status_code == 200, r.get_data(as_text=True)
        body = r.get_json()
        assert body["ok"] is True
        assert body["node"] == "chr-exit-01"
        assert body["accepted_at"] == "2026-06-09T19:40:00Z"
        assert body["health"] == "up"
        assert body["directives"] == {"shed": False, "drain": False}

        # Exactly one row, source='proxy', correct mapping.
        rows = FleetChrMetric.query.all()
        assert len(rows) == 1
        row = rows[0]
        assert row.chr_id == enrolled_node.id
        assert row.source == "proxy"
        assert float(row.cpu_pct) == pytest.approx(62.0)   # 0.62 → 62.00
        assert float(row.mem_pct) == pytest.approx(41.0)
        assert row.active_sessions == 1280
        assert float(row.ping_rtt_ms) == pytest.approx(18.4)
        # 512 GB → 512 * 1e9 bytes
        assert row.tx_bytes == 512 * 1_000_000_000
        # Sampled-at parsed and stored as naive UTC.
        assert row.ts == datetime(2026, 6, 9, 19, 40, 0)

    def test_shed_flips_when_cpu_above_threshold(self, configured_app, client, enrolled_node):
        threshold_ratio = FLEET.health.cpu_shed_threshold_pct / 100.0
        # Just above threshold → shedding.
        body = _valid_payload(cpu=threshold_ratio + 0.01)
        r = client.post(TELEMETRY_URL, json=body,
                        headers={"X-Proxy-Token": _sign_token(nonce="shed1")})
        body_r = r.get_json()
        assert r.status_code == 200
        assert body_r["directives"]["shed"] is True
        assert body_r["health"] == "shedding"

    def test_drain_directive_reflects_node_row(self, configured_app, client, enrolled_node):
        enrolled_node.drain = True
        db.session.commit()
        r = client.post(
            TELEMETRY_URL, json=_valid_payload(),
            headers={"X-Proxy-Token": _sign_token(nonce="drain1")},
        )
        assert r.status_code == 200
        assert r.get_json()["directives"]["drain"] is True

    def test_optional_metrics_may_be_omitted(self, configured_app, client, enrolled_node):
        body = _valid_payload()
        body["metrics"] = {"cpu_util": 0.5}  # bare minimum
        r = client.post(TELEMETRY_URL, json=body,
                        headers={"X-Proxy-Token": _sign_token(nonce="opt1")})
        assert r.status_code == 200
        row = FleetChrMetric.query.first()
        assert float(row.cpu_pct) == pytest.approx(50.0)
        assert row.mem_pct is None
        assert row.active_sessions is None
        assert row.tx_bytes is None


# ════════════════════════════════════════════════════════════════════════════
# Health seam — telemetry defers to the monitor's authoritative hysteresis state
# (Phase-4 gate: fleet.health.monitor.state_of(name) is the single source of truth)
# ════════════════════════════════════════════════════════════════════════════
class TestHealthSeam:
    def test_health_reflects_monitor_down_state(self, configured_app, client, enrolled_node):
        """A healthy sample must NOT report 'up' when the monitor has the node
        flap-damped to 'down' — telemetry defers to monitor.state_of()."""
        from fleet.health.models_health import FleetChrHealth

        db.session.add(FleetChrHealth(chr_id=enrolled_node.id, state="down"))
        db.session.commit()

        # Low CPU → telemetry's own logic would say 'up'; the monitor overrides.
        r = client.post(TELEMETRY_URL, json=_valid_payload(cpu=0.10),
                        headers={"X-Proxy-Token": _sign_token(nonce="seam-down")})
        assert r.status_code == 200
        assert r.get_json()["health"] == "down"

    def test_health_up_when_monitor_says_up(self, configured_app, client, enrolled_node):
        from fleet.health.models_health import FleetChrHealth

        db.session.add(FleetChrHealth(chr_id=enrolled_node.id, state="up"))
        db.session.commit()
        r = client.post(TELEMETRY_URL, json=_valid_payload(cpu=0.10),
                        headers={"X-Proxy-Token": _sign_token(nonce="seam-up")})
        assert r.status_code == 200
        assert r.get_json()["health"] == "up"

    def test_health_falls_back_when_no_monitor_row(self, configured_app, client, enrolled_node):
        """No FleetChrHealth row yet (node never probed) → state_of() is None and
        telemetry uses its own best-effort sample-based answer."""
        r = client.post(TELEMETRY_URL, json=_valid_payload(cpu=0.10),
                        headers={"X-Proxy-Token": _sign_token(nonce="seam-fallback")})
        assert r.status_code == 200
        assert r.get_json()["health"] == "up"


# ════════════════════════════════════════════════════════════════════════════
# Query helpers — dashboard + scoring brain
# ════════════════════════════════════════════════════════════════════════════
class TestQueryHelpers:
    def _seed_samples(self, enrolled_node, samples):
        """samples = list of (cpu_pct, sessions, latency_ms, ts)."""
        for cpu, sess, lat, ts in samples:
            db.session.add(FleetChrMetric(
                chr_id=enrolled_node.id, ts=ts, source="proxy",
                cpu_pct=cpu, mem_pct=None,
                active_sessions=sess, ping_rtt_ms=lat,
                rx_bytes=None, tx_bytes=None, ping_loss_pct=None,
            ))
        db.session.commit()

    def test_latest_metrics_returns_most_recent(self, configured_app, enrolled_node):
        self._seed_samples(enrolled_node, [
            (50.0, 100, 10.0, datetime(2026, 6, 9, 19, 0, 0)),
            (60.0, 150, 12.0, datetime(2026, 6, 9, 19, 5, 0)),
            (55.0, 130, 11.0, datetime(2026, 6, 9, 19, 3, 0)),
        ])
        # By id
        latest = latest_metrics(enrolled_node.id)
        assert latest is not None and float(latest.cpu_pct) == 60.0
        # By name — same answer
        by_name = latest_metrics("chr-exit-01")
        assert by_name is not None and by_name.id == latest.id

    def test_latest_metrics_unknown_node_is_none(self, configured_app):
        assert latest_metrics("ghost") is None
        assert latest_metrics(999_999) is None

    def test_rolling_window_averages_only_last_n(self, configured_app, enrolled_node):
        # 5 samples at 1-min intervals; window of 3 must only see the newest 3.
        samples = [
            (10.0, 100, 1.0, datetime(2026, 6, 9, 19, 0, 0)),
            (20.0, 200, 2.0, datetime(2026, 6, 9, 19, 1, 0)),
            (30.0, 300, 3.0, datetime(2026, 6, 9, 19, 2, 0)),
            (40.0, 400, 4.0, datetime(2026, 6, 9, 19, 3, 0)),
            (50.0, 500, 5.0, datetime(2026, 6, 9, 19, 4, 0)),
        ]
        self._seed_samples(enrolled_node, samples)
        w = rolling_window(enrolled_node.id, n=3)
        assert w["samples"] == 3
        assert w["avg_cpu_pct"] == pytest.approx((30.0 + 40.0 + 50.0) / 3)
        assert w["avg_active_sessions"] == pytest.approx((300 + 400 + 500) / 3)
        assert w["avg_latency_ms"] == pytest.approx((3.0 + 4.0 + 5.0) / 3)
        assert w["last_active_sessions"] == 500
        assert w["last_ts"] == datetime(2026, 6, 9, 19, 4, 0)
        # mem was None in every sample
        assert w["avg_mem_pct"] is None

    def test_rolling_window_no_samples_yields_zero_count(self, configured_app, enrolled_node):
        w = rolling_window(enrolled_node.id, n=5)
        assert w["samples"] == 0
        assert w["avg_cpu_pct"] is None and w["last_ts"] is None

    def test_rolling_window_rejects_zero_n(self, configured_app, enrolled_node):
        with pytest.raises(ValueError):
            rolling_window(enrolled_node.id, n=0)


# ════════════════════════════════════════════════════════════════════════════
# Service module direct calls (no HTTP)
# ════════════════════════════════════════════════════════════════════════════
class TestServiceModule:
    def test_validate_returns_typed_sample(self):
        sample = validate(_valid_payload())
        assert isinstance(sample, TelemetrySample)
        assert sample.node == "chr-exit-01"
        assert sample.metrics["cpu_util"] == 0.62
        assert sample.agent_version == "1.0.0"

    def test_ingest_payload_raises_unknown_node(self, configured_app):
        body = _valid_payload(node="no-such-node")
        with pytest.raises(UnknownNodeError):
            ingest_payload(body)

    def test_ingest_payload_raises_validation_error_for_missing_node(self, configured_app):
        body = _valid_payload(); body.pop("node")
        with pytest.raises(TelemetryValidationError) as exc:
            ingest_payload(body)
        assert exc.value.code == "bad_request"
