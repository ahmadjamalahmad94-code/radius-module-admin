"""Tests for the Phase-5-B placement-decision read endpoint and service.

Covers:
  * Auth — missing/bad token, expired ts, replay → 401.
  * Validation — bad realm chars, n out of range → 400.
  * Decision computed by the local stub adapter:
      - returns headline node + ordered top_n by score.
      - empty when no eligible node (decision=null, top_n=[]).
      - drain/disabled/non-up nodes excluded.
  * Audit — every served response inserts one fleet_placement_decisions
    row (kind='new', outcome='pending') with full reason snapshot.
  * Real-brain seam — when ``fleet.brain.best_node``/``top_n`` exist, the
    adapter uses them and the endpoint returns those values verbatim;
    the wire shape stays identical.
"""

from __future__ import annotations

import hashlib
import hmac
import time
import importlib

import pytest

from app.extensions import db
from fleet.brain import brain_adapter
from fleet.brain.brain_adapter import NodeScore, best_node, top_n
from fleet.brain.models_session import PlacementDecision
from fleet.brain.placement_query import (
    PlacementQueryError,
    _clean_n,
    _clean_realm,
    serve_decision,
)
from fleet.registry.models_chr import FleetChrNode, FleetProvider


SHARED_SECRET = "test-proxy-shared-secret-32-chars-long-xxxxxxxxx"
URL = "/api/proxy/placement-decision"


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────
@pytest.fixture()
def configured_app(app):
    app.config["RADIUS_PROXY_SHARED_SECRET"] = SHARED_SECRET
    app.config["RADIUS_PROXY_TOKEN_TTL"] = 60
    from app.api import proxy_api
    proxy_api._NONCE_CACHE.clear()
    return app


def _sign_token(secret: str = SHARED_SECRET, ts: int | None = None, nonce: str = "n1") -> str:
    if ts is None:
        ts = int(time.time())
    mac = hmac.new(secret.encode(), f"{ts}:{nonce}".encode(), hashlib.sha256).hexdigest()
    return f"{ts}:{nonce}:{mac}"


def _provider() -> FleetProvider:
    prov = FleetProvider(name="Contabo", cost_model="open", price_per_tb=0)
    db.session.add(prov)
    db.session.flush()
    return prov


def _node(
    name: str,
    *,
    public_ip: str,
    wg_mgmt_ip: str,
    score: float | None = 0.5,
    status: str = "up",
    enabled: bool = True,
    drain: bool = False,
) -> FleetChrNode:
    prov = FleetProvider.query.first() or _provider()
    n = FleetChrNode(
        provider_id=prov.id,
        name=name,
        public_ip=public_ip,
        wg_mgmt_ip=wg_mgmt_ip,
        wg_mgmt_pubkey=f"PUBKEY_{name}",
        max_sessions=1000,
        link_speed_mbps=500,
        status=status,
        enabled=enabled,
        drain=drain,
        score=score,
    )
    db.session.add(n)
    return n


@pytest.fixture()
def fleet_three(configured_app):
    """Three nodes with distinct scores so order is deterministic."""
    _provider()
    _node("chr-exit-01", public_ip="203.0.113.1",  wg_mgmt_ip="10.99.0.1", score=0.50)
    _node("chr-exit-02", public_ip="203.0.113.2",  wg_mgmt_ip="10.99.0.2", score=0.91)
    _node("chr-exit-03", public_ip="203.0.113.3",  wg_mgmt_ip="10.99.0.3", score=0.78)
    db.session.commit()


@pytest.fixture()
def fleet_with_excluded(configured_app):
    """Some nodes the stub MUST drop: drain, disabled, non-UP."""
    _provider()
    _node("good-1",     public_ip="203.0.113.10", wg_mgmt_ip="10.99.0.10", score=0.80)
    _node("good-2",     public_ip="203.0.113.11", wg_mgmt_ip="10.99.0.11", score=0.60)
    _node("draining",   public_ip="203.0.113.12", wg_mgmt_ip="10.99.0.12", score=0.99, drain=True)
    _node("disabled",   public_ip="203.0.113.13", wg_mgmt_ip="10.99.0.13", score=0.99, enabled=False)
    _node("degraded",   public_ip="203.0.113.14", wg_mgmt_ip="10.99.0.14", score=0.99, status="degraded")
    _node("down",       public_ip="203.0.113.15", wg_mgmt_ip="10.99.0.15", score=0.99, status="down")
    db.session.commit()


# ════════════════════════════════════════════════════════════════════════════
# Auth — contract §0
# ════════════════════════════════════════════════════════════════════════════
class TestAuth:
    def test_missing_token_is_401(self, configured_app, client, fleet_three):
        r = client.get(URL)
        assert r.status_code == 401
        assert r.get_json() == {"ok": False, "error": "unauthorized"}

    def test_bad_hmac_is_401(self, configured_app, client, fleet_three):
        ts = int(time.time())
        bad = f"{ts}:n2:{'0' * 64}"
        r = client.get(URL, headers={"X-Proxy-Token": bad})
        assert r.status_code == 401

    def test_expired_ts_is_401(self, configured_app, client, fleet_three):
        r = client.get(URL, headers={
            "X-Proxy-Token": _sign_token(ts=int(time.time()) - 600, nonce="exp1"),
        })
        assert r.status_code == 401

    def test_replay_is_rejected(self, configured_app, client, fleet_three):
        tok = _sign_token(nonce="rp1")
        ok = client.get(URL, headers={"X-Proxy-Token": tok})
        assert ok.status_code == 200
        again = client.get(URL, headers={"X-Proxy-Token": tok})
        assert again.status_code == 401


# ════════════════════════════════════════════════════════════════════════════
# Validation — malformed query params → 400 (never 500)
# ════════════════════════════════════════════════════════════════════════════
class TestValidation:
    def _get(self, client, qs, nonce):
        return client.get(URL + qs, headers={"X-Proxy-Token": _sign_token(nonce=nonce)})

    def test_bad_realm_char_is_400(self, configured_app, client, fleet_three):
        r = self._get(client, "?realm=client/5", "vr1")
        assert r.status_code == 400
        assert r.get_json()["error"] == "bad_request"

    def test_realm_too_long_is_400(self, configured_app, client, fleet_three):
        r = self._get(client, "?realm=" + "a" * 81, "vr2")
        assert r.status_code == 400

    def test_n_non_integer_is_400(self, configured_app, client, fleet_three):
        r = self._get(client, "?n=foo", "vn1")
        assert r.status_code == 400
        assert "integer" in r.get_json()["detail"]

    def test_n_too_small_is_400(self, configured_app, client, fleet_three):
        r = self._get(client, "?n=0", "vn2")
        assert r.status_code == 400

    def test_n_too_large_is_400(self, configured_app, client, fleet_three):
        r = self._get(client, "?n=99", "vn3")
        assert r.status_code == 400

    def test_empty_realm_is_treated_as_global(self, configured_app, client, fleet_three):
        # Empty realm is NOT malformed; it just means "no constraint".
        r = self._get(client, "?realm=", "ve1")
        assert r.status_code == 200
        assert r.get_json()["decision"] == "chr-exit-02"


# ════════════════════════════════════════════════════════════════════════════
# Happy path — decision matches the best-scored eligible node
# ════════════════════════════════════════════════════════════════════════════
class TestDecisionHappyPath:
    def test_decision_is_top_scored_node(self, configured_app, client, fleet_three):
        r = client.get(URL, headers={"X-Proxy-Token": _sign_token(nonce="hp1")})
        assert r.status_code == 200
        body = r.get_json()
        assert body["ok"] is True
        assert body["decision"] == "chr-exit-02"   # score 0.91
        # top_n default is 3
        names = [x["node"] for x in body["top_n"]]
        assert names == ["chr-exit-02", "chr-exit-03", "chr-exit-01"]
        # Score order is strictly descending
        scores = [x["score"] for x in body["top_n"]]
        assert scores == sorted(scores, reverse=True)
        # reasons carries the stub marker
        for entry in body["top_n"]:
            assert entry["reasons"]["source"] == "stub"
            assert "rank" in entry["reasons"]

    def test_n_clips_top_n_length(self, configured_app, client, fleet_three):
        r = client.get(URL + "?n=2", headers={"X-Proxy-Token": _sign_token(nonce="n2")})
        body = r.get_json()
        assert body["decision"] == "chr-exit-02"
        assert [x["node"] for x in body["top_n"]] == ["chr-exit-02", "chr-exit-03"]

    def test_excludes_drain_disabled_and_non_up(
        self, configured_app, client, fleet_with_excluded
    ):
        r = client.get(URL, headers={"X-Proxy-Token": _sign_token(nonce="excl1")})
        body = r.get_json()
        assert body["decision"] == "good-1"
        assert [x["node"] for x in body["top_n"]] == ["good-1", "good-2"]
        # The excluded set must not leak.
        leaked = {"draining", "disabled", "degraded", "down"}
        assert not (leaked & {x["node"] for x in body["top_n"]})


# ════════════════════════════════════════════════════════════════════════════
# No eligible node — empty contract envelope, still 200
# ════════════════════════════════════════════════════════════════════════════
class TestNoEligible:
    def test_empty_fleet_yields_empty_decision(self, configured_app, client):
        r = client.get(URL, headers={"X-Proxy-Token": _sign_token(nonce="emp1")})
        assert r.status_code == 200
        assert r.get_json() == {"ok": True, "decision": None, "top_n": []}

    def test_all_draining_yields_empty(self, configured_app, client):
        _provider()
        _node("d1", public_ip="203.0.113.30", wg_mgmt_ip="10.99.0.30", score=0.9, drain=True)
        _node("d2", public_ip="203.0.113.31", wg_mgmt_ip="10.99.0.31", score=0.9, drain=True)
        db.session.commit()
        r = client.get(URL, headers={"X-Proxy-Token": _sign_token(nonce="emp2")})
        body = r.get_json()
        assert body == {"ok": True, "decision": None, "top_n": []}


# ════════════════════════════════════════════════════════════════════════════
# Audit row — every served response inserts one fleet_placement_decisions row
# ════════════════════════════════════════════════════════════════════════════
class TestAuditPersistence:
    def test_records_decision_with_full_reason_snapshot(
        self, configured_app, client, fleet_three
    ):
        before = PlacementDecision.query.count()
        r = client.get(
            URL + "?realm=client5&current_node=chr-exit-01&n=2",
            headers={"X-Proxy-Token": _sign_token(nonce="aud1")},
        )
        assert r.status_code == 200
        after = PlacementDecision.query.count()
        assert after == before + 1

        row: PlacementDecision = PlacementDecision.query.order_by(PlacementDecision.id.desc()).first()
        assert row.kind == "new"
        assert row.outcome == "pending"
        assert row.username == "realm:client5"
        # from_chr_id resolves current_node; to_chr_id resolves decision
        from_node = FleetChrNode.query.filter_by(name="chr-exit-01").first()
        to_node = FleetChrNode.query.filter_by(name="chr-exit-02").first()
        assert row.from_chr_id == from_node.id
        assert row.to_chr_id == to_node.id

        # Reason snapshot
        reason = row.reason
        assert reason["realm"] == "client5"
        assert reason["current_node"] == "chr-exit-01"
        assert reason["decision"]["name"] == "chr-exit-02"
        assert [c["name"] for c in reason["top_n"]] == ["chr-exit-02", "chr-exit-03"]

    def test_no_eligible_still_records_audit_row(self, configured_app, client):
        before = PlacementDecision.query.count()
        r = client.get(URL, headers={"X-Proxy-Token": _sign_token(nonce="aud2")})
        assert r.status_code == 200
        assert PlacementDecision.query.count() == before + 1
        row = PlacementDecision.query.order_by(PlacementDecision.id.desc()).first()
        # Decision is None ⇒ to_chr_id is None
        assert row.to_chr_id is None
        assert row.reason["decision"] is None
        assert row.reason["top_n"] == []
        assert row.username == "__proxy_realm_query__"

    def test_unknown_current_node_leaves_from_chr_id_null(
        self, configured_app, client, fleet_three
    ):
        r = client.get(
            URL + "?current_node=ghost-node",
            headers={"X-Proxy-Token": _sign_token(nonce="aud3")},
        )
        assert r.status_code == 200
        row = PlacementDecision.query.order_by(PlacementDecision.id.desc()).first()
        assert row.from_chr_id is None
        assert row.reason["current_node"] == "ghost-node"  # still in the snapshot


# ════════════════════════════════════════════════════════════════════════════
# Service module direct calls (no HTTP)
# ════════════════════════════════════════════════════════════════════════════
class TestServiceLayer:
    def test_serve_decision_without_record(self, configured_app, fleet_three):
        before = PlacementDecision.query.count()
        result = serve_decision(realm="client5", n=2, record=False)
        assert result.decision.name == "chr-exit-02"
        assert [c.name for c in result.candidates] == ["chr-exit-02", "chr-exit-03"]
        assert PlacementDecision.query.count() == before  # no row written

    def test_clean_realm_accepts_valid_chars(self):
        assert _clean_realm("user@client5") == "user@client5"
        assert _clean_realm("client-5_v2.test") == "client-5_v2.test"
        assert _clean_realm("") is None
        assert _clean_realm(None) is None

    def test_clean_realm_rejects_invalid_chars(self):
        with pytest.raises(PlacementQueryError):
            _clean_realm("client 5")  # space
        with pytest.raises(PlacementQueryError):
            _clean_realm("foo;bar")
        with pytest.raises(PlacementQueryError):
            _clean_realm("x" * 81)

    def test_clean_n_validates_range(self):
        assert _clean_n(None) == 3
        assert _clean_n("") == 3
        assert _clean_n("5") == 5
        with pytest.raises(PlacementQueryError):
            _clean_n("0")
        with pytest.raises(PlacementQueryError):
            _clean_n("33")
        with pytest.raises(PlacementQueryError):
            _clean_n("foo")


# ════════════════════════════════════════════════════════════════════════════
# Brain adapter — stub backend default + real-brain seam
# ════════════════════════════════════════════════════════════════════════════
class TestBrainAdapter:
    def test_stub_is_default_backend(self, configured_app, fleet_three):
        # Force a re-resolve and call.
        best = best_node()
        assert best is not None and best.name == "chr-exit-02"
        # After a call, the backend marker is set.
        assert brain_adapter.BRAIN_BACKEND in {"stub", "real"}

    def test_top_n_size_zero_returns_empty(self, configured_app, fleet_three):
        assert top_n(n=0) == []

    def test_top_n_preserves_score_order(self, configured_app, fleet_three):
        ranked = top_n(n=5)
        assert [r.name for r in ranked] == ["chr-exit-02", "chr-exit-03", "chr-exit-01"]
        assert [r.score for r in ranked] == sorted(
            [r.score for r in ranked], reverse=True
        )

    def test_real_brain_seam_replaces_stub(self, configured_app, fleet_three, monkeypatch):
        """If fleet.brain exposes best_node + top_n, the adapter uses them.

        We monkey-patch ``fleet.brain.best_node`` / ``top_n`` on the module
        for the duration of this test to simulate the parallel-built brain
        landing — the wire response must change to whatever the real brain
        returned, and BRAIN_BACKEND must flip to "real".
        """
        import fleet.brain as _brain

        # Fake brain that prefers chr-exit-01 (the lowest-scored eligible)
        # to prove the adapter is delegating, not running its own ranking.
        class FakeNS:
            def __init__(self, name, score, reasons):
                self.name = name; self.score = score; self.reasons = reasons

        def fake_best(realm=None):
            return FakeNS("chr-exit-01", 9.99, {"source": "real", "rationale": "fake"})

        def fake_top(realm=None, n=3):
            return [
                FakeNS("chr-exit-01", 9.99, {"source": "real"}),
                FakeNS("chr-exit-03", 1.0,  {"source": "real"}),
            ][:n]

        monkeypatch.setattr(_brain, "best_node", fake_best, raising=False)
        monkeypatch.setattr(_brain, "top_n",     fake_top,  raising=False)

        decision = best_node()
        assert decision is not None and decision.name == "chr-exit-01"
        ranked = top_n(n=3)
        assert [r.name for r in ranked] == ["chr-exit-01", "chr-exit-03"]
        # All return values are coerced into the adapter's NodeScore dataclass.
        assert all(isinstance(r, NodeScore) for r in ranked)
        assert brain_adapter.BRAIN_BACKEND == "real"

    def test_adapter_rejects_broken_brain_return(self, configured_app, monkeypatch):
        """A future brain that returns objects without ``.name`` is a bug —
        the adapter raises rather than emit a half-rendered wire shape."""
        import fleet.brain as _brain

        class NoName:
            score = 1.0
            reasons = {}

        monkeypatch.setattr(_brain, "best_node", lambda realm=None: NoName(), raising=False)
        monkeypatch.setattr(_brain, "top_n", lambda realm=None, n=3: [], raising=False)
        with pytest.raises(TypeError):
            best_node()


# ════════════════════════════════════════════════════════════════════════════
# Self-consistency: serve_decision keeps decision == top_n[0]
# ════════════════════════════════════════════════════════════════════════════
class TestSelfConsistency:
    def test_decision_leads_top_n_even_with_inconsistent_brain(
        self, configured_app, fleet_three, monkeypatch
    ):
        """If the brain's best_node and top_n disagree on the headline,
        serve_decision rewrites top_n's head so the response is internally
        consistent."""
        import fleet.brain as _brain

        class NS:
            def __init__(self, name, score):
                self.name = name; self.score = score; self.reasons = {}

        monkeypatch.setattr(_brain, "best_node", lambda realm=None: NS("chr-exit-01", 1.0), raising=False)
        monkeypatch.setattr(_brain, "top_n",
                            lambda realm=None, n=3: [NS("chr-exit-02", 2.0), NS("chr-exit-03", 1.5)],
                            raising=False)
        result = serve_decision(realm="any", n=3, record=False)
        assert result.decision.name == "chr-exit-01"
        assert result.candidates[0].name == "chr-exit-01"
        # The other candidates are preserved
        assert {c.name for c in result.candidates} >= {"chr-exit-01", "chr-exit-02", "chr-exit-03"}
