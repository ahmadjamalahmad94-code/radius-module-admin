"""Tests for the Phase-6-B DNS reconciler.

Covers the policy boundary: desired-state computation, weight
normalisation, the flap guard, the empty-set black-hole guard, the
preview-vs-apply split, and the audit-row side effects.

Brain + monitor + driver are all mocked through dependency injection
(``rank_fn``, ``state_of``, the in-process driver fake exposed by
``fleet.dns.driver_adapter``). That way the tests pin the reconciler's
behaviour deterministically — independent of whether the real Phase-5
brain DB seeding works in the SQLite test DB, and independent of any
Cloudflare creds the driver might need.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Iterable

import pytest

from app.extensions import db
from app.models import utcnow

from fleet.brain.scoring import NodeScore
from fleet.config import FLEET
from fleet.dns import driver_adapter
from fleet.dns.driver_adapter import (
    ApplyResult,
    DRIVER_MODES,
    NodeRecord,
    reset_fake_calls,
)
from fleet.dns.models_dns import DnsRecordState
from fleet.dns.reconcile import (
    DesiredState,
    ReconcileConfig,
    compute_desired,
    normalize_weights,
    preview,
    reconcile_now,
)
from fleet.notify.models_alert import Event
from fleet.registry.models_chr import FleetChrNode, FleetProvider


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────
@pytest.fixture(autouse=True)
def _reset_driver_calls(app):
    """Each test starts with a clean driver-adapter call log."""
    reset_fake_calls()
    yield
    reset_fake_calls()


@pytest.fixture()
def fleet_three(app):
    """Three enrolled nodes with distinct public IPs."""
    prov = FleetProvider(name="Contabo", cost_model="open", price_per_tb=0)
    db.session.add(prov)
    db.session.flush()
    for name, ip, mgmt in (
        ("chr-eu-1", "203.0.113.11", "10.99.0.11"),
        ("chr-eu-2", "203.0.113.12", "10.99.0.12"),
        ("chr-eu-3", "203.0.113.13", "10.99.0.13"),
    ):
        db.session.add(FleetChrNode(
            provider_id=prov.id, name=name,
            public_ip=ip, wg_mgmt_ip=mgmt, wg_mgmt_pubkey=f"PUB_{name}",
            max_sessions=1000, link_speed_mbps=500,
            status="up", enabled=True, drain=False,
        ))
    db.session.commit()


def _scored(name: str, score: float, eligible: bool = True) -> NodeScore:
    """Build a synthetic brain NodeScore."""
    return NodeScore(
        node_id=hash(name) & 0x7FFFFFFF,
        name=name,
        eligible=eligible,
        score=score,
        reasons={"synthetic": True, "score": score},
    )


def _all_healthy(_name: str) -> str:
    return "up"


def _none_healthy(_name: str) -> str:
    return "down"


# ════════════════════════════════════════════════════════════════════════════
# Weight normalisation — pure function
# ════════════════════════════════════════════════════════════════════════════
class TestNormalizeWeights:
    def test_empty(self):
        assert normalize_weights([]) == []

    def test_single_score_uses_median(self):
        # One node, no spread — middle weight (not the maximum).
        assert normalize_weights([42.0]) == [50]

    def test_all_equal_uses_median(self):
        assert normalize_weights([5.0, 5.0, 5.0]) == [50, 50, 50]

    def test_linear_top_and_bottom_pin(self):
        weights = normalize_weights([1.0, 5.0, 10.0])
        assert weights[0] == 1            # bottom of the range
        assert weights[-1] == 100         # top of the range
        assert weights[1] == 45           # linear: (5-1)/(10-1) ≈ 0.444

    def test_monotone_in_input(self):
        scores = [0.1, 0.5, 0.5, 2.0, 4.7, 4.7]
        weights = normalize_weights(scores)
        for s_pair, w_pair in zip(zip(scores, scores[1:]), zip(weights, weights[1:]), strict=True):
            if s_pair[0] < s_pair[1]:
                assert w_pair[0] <= w_pair[1]
            elif s_pair[0] == s_pair[1]:
                assert w_pair[0] == w_pair[1]

    def test_negative_scores_shift_up(self):
        # The worst still becomes weight_min, not 0 (some providers treat 0
        # as "do not include").
        weights = normalize_weights([-10.0, 0.0, 10.0])
        assert weights[0] == 1
        assert weights[-1] == 100
        assert weights[1] == 50

    def test_custom_bounds(self):
        w = normalize_weights([1.0, 2.0, 3.0], weight_min=10, weight_max=20)
        assert w[0] == 10 and w[-1] == 20 and w[1] == 15

    def test_invalid_bounds_raise(self):
        with pytest.raises(ValueError):
            normalize_weights([1.0, 2.0], weight_min=0)
        with pytest.raises(ValueError):
            normalize_weights([1.0, 2.0], weight_min=5, weight_max=3)


# ════════════════════════════════════════════════════════════════════════════
# Desired-state computation
# ════════════════════════════════════════════════════════════════════════════
class TestComputeDesired:
    def test_basic_three_nodes_all_healthy(self, fleet_three):
        ranking = [
            _scored("chr-eu-1", 0.50),
            _scored("chr-eu-2", 0.91),  # best
            _scored("chr-eu-3", 0.70),
        ]
        # Brain returns best-first; reconciler trusts that order for weights.
        ranking.sort(key=lambda ns: -ns.score)
        desired: DesiredState = compute_desired(
            cfg=ReconcileConfig(fqdn="vpn.example.com"),
            rank_fn=lambda: ranking,
            state_of=_all_healthy,
        )
        publishable = desired.publishable
        assert [r.node for r in publishable] == ["chr-eu-2", "chr-eu-3", "chr-eu-1"]
        # Top-ranked gets the max weight; bottom-ranked the min.
        assert publishable[0].weight == 100
        assert publishable[-1].weight == 1
        # All three IPs in the publish list, sorted.
        assert desired.publish_ips == sorted(["203.0.113.11", "203.0.113.12", "203.0.113.13"])
        # No exclusions.
        assert desired.excluded_reasons == {}

    def test_down_node_is_excluded(self, fleet_three):
        ranking = [_scored("chr-eu-1", 0.9), _scored("chr-eu-2", 0.8)]

        def health(name: str) -> str:
            return "down" if name == "chr-eu-1" else "up"

        desired = compute_desired(
            cfg=ReconcileConfig(), rank_fn=lambda: ranking, state_of=health,
        )
        names = {r.node for r in desired.publishable}
        assert names == {"chr-eu-2"}
        assert desired.excluded_reasons.get("chr-eu-1", "").startswith("health_")

    def test_unknown_health_is_excluded(self, fleet_three):
        ranking = [_scored("chr-eu-1", 0.9), _scored("chr-eu-2", 0.5)]
        desired = compute_desired(
            cfg=ReconcileConfig(), rank_fn=lambda: ranking,
            state_of=lambda name: None,  # never been probed
        )
        assert desired.publishable == []
        # Both nodes recorded as excluded so the audit can show why.
        assert set(desired.excluded_reasons.keys()) == {"chr-eu-1", "chr-eu-2"}

    def test_draining_node_is_excluded_even_if_brain_returns_it(self, fleet_three):
        # Flip chr-eu-2 into drain after the fixtures.
        node = FleetChrNode.query.filter_by(name="chr-eu-2").first()
        node.drain = True
        db.session.commit()

        ranking = [_scored("chr-eu-2", 0.99), _scored("chr-eu-1", 0.50)]
        desired = compute_desired(rank_fn=lambda: ranking, state_of=_all_healthy)
        assert [r.node for r in desired.publishable] == ["chr-eu-1"]
        assert desired.excluded_reasons["chr-eu-2"] == "draining"

    def test_node_with_no_public_ip_is_excluded(self, fleet_three):
        node = FleetChrNode.query.filter_by(name="chr-eu-1").first()
        # Workaround: ``public_ip`` is NOT NULL. We override the lookup
        # path by removing the node from the registry.
        db.session.delete(node)
        db.session.commit()

        ranking = [_scored("chr-eu-1", 0.9), _scored("chr-eu-2", 0.8)]
        desired = compute_desired(rank_fn=lambda: ranking, state_of=_all_healthy)
        assert "chr-eu-1" in desired.excluded_reasons
        assert desired.excluded_reasons["chr-eu-1"] == "no_node_row"

    def test_top_n_cap_clips_publishable(self, fleet_three, monkeypatch):
        # Force top_n_cap down to 2 via a config override.
        from fleet.config import FleetConfig, DnsConfig
        tight = FleetConfig(dns=DnsConfig(ttl=30, top_n_cap=2, min_healthy=1))
        ranking = [
            _scored("chr-eu-1", 0.50),
            _scored("chr-eu-2", 0.91),
            _scored("chr-eu-3", 0.70),
        ]
        ranking.sort(key=lambda ns: -ns.score)
        desired = compute_desired(
            fleet_cfg=tight, rank_fn=lambda: ranking, state_of=_all_healthy,
        )
        assert len(desired.publishable) == 2
        assert [r.node for r in desired.publishable] == ["chr-eu-2", "chr-eu-3"]

    def test_empty_ranking_yields_empty_desired(self, fleet_three):
        desired = compute_desired(rank_fn=lambda: [], state_of=_all_healthy)
        assert desired.publishable == []
        assert desired.publish_ips == []
        assert desired.excluded_reasons == {}


# ════════════════════════════════════════════════════════════════════════════
# Preview — no side effects
# ════════════════════════════════════════════════════════════════════════════
class TestPreview:
    def test_preview_does_not_write_or_call_driver(self, fleet_three):
        ranking = [_scored("chr-eu-1", 0.9), _scored("chr-eu-2", 0.5)]
        before_events = Event.query.count()
        before_state = DnsRecordState.query.count()

        result = preview(rank_fn=lambda: ranking, state_of=_all_healthy)
        assert isinstance(result, DesiredState)
        assert len(result.publishable) == 2
        # No DB writes
        assert Event.query.count() == before_events
        assert DnsRecordState.query.count() == before_state
        # No driver calls
        assert driver_adapter.FAKE_CALLS == []


# ════════════════════════════════════════════════════════════════════════════
# reconcile_now — full apply path
# ════════════════════════════════════════════════════════════════════════════
class TestReconcileApply:
    def test_first_reconcile_applies_and_persists(self, fleet_three):
        ranking = [_scored("chr-eu-1", 0.91), _scored("chr-eu-2", 0.50)]
        result = reconcile_now(
            cfg=ReconcileConfig(fqdn="vpn.example.com"),
            rank_fn=lambda: ranking,
            state_of=_all_healthy,
        )
        # Applied via the fake driver
        assert result.applied is True
        assert result.changed is True
        assert result.reason == "applied"
        assert result.apply is not None and result.apply.applied is True

        # Driver was called with the right shape
        assert len(driver_adapter.FAKE_CALLS) == 1
        call = driver_adapter.FAKE_CALLS[0]
        assert call["mode"] == "WEIGHTED_ROUND_ROBIN"
        assert call["dry_run"] is False
        assert call["published_ips"] == sorted(["203.0.113.11", "203.0.113.12"])

        # DnsRecordState upserted
        row = DnsRecordState.get("vpn.example.com", "A")
        assert row is not None
        assert row.published_ips == sorted(["203.0.113.11", "203.0.113.12"])
        assert row.ttl == FLEET.dns.ttl
        assert row.last_change_reason == "reconcile"

        # One Event(kind='dns_update')
        ev = Event.query.filter_by(kind="dns_update").order_by(Event.id.desc()).first()
        assert ev is not None
        assert ev.detail["fqdn"] == "vpn.example.com"
        assert ev.detail["desired_ips"] == sorted(["203.0.113.11", "203.0.113.12"])
        # Weights snapshot
        weights = {w["node"]: w["weight"] for w in ev.detail["weights"]}
        assert weights["chr-eu-1"] == 100 and weights["chr-eu-2"] == 1


# ════════════════════════════════════════════════════════════════════════════
# Flap guard — no thrash when set unchanged
# ════════════════════════════════════════════════════════════════════════════
class TestFlapGuard:
    def _seed_published(self, ips, when=None):
        DnsRecordState.upsert("vpn.example.com", "A", ips, ttl=30, reason="seed")
        db.session.commit()
        if when is not None:
            row = DnsRecordState.get("vpn.example.com", "A")
            row.updated_at = when
            db.session.commit()

    def test_unchanged_set_within_min_interval_is_no_op(self, fleet_three):
        # Seed the previous state to exactly the set the desired ranking will produce.
        self._seed_published(["203.0.113.11", "203.0.113.12"], when=utcnow())

        ranking = [_scored("chr-eu-1", 0.91), _scored("chr-eu-2", 0.50)]
        result = reconcile_now(
            cfg=ReconcileConfig(fqdn="vpn.example.com",
                                min_reapply_interval_seconds=60),
            rank_fn=lambda: ranking,
            state_of=_all_healthy,
        )
        assert result.applied is False
        assert result.changed is False
        assert result.suppressed is False
        assert result.reason == "set_unchanged_within_min_interval"
        # Driver never called
        assert driver_adapter.FAKE_CALLS == []
        # Audit shows the no-change
        ev = Event.query.filter_by(kind="dns_no_change").order_by(Event.id.desc()).first()
        assert ev is not None
        assert ev.detail["reason"] == "set_unchanged_within_min_interval"

    def test_changed_set_applies_even_within_window(self, fleet_three):
        # Previous publish = chr-eu-1 only; brain now wants both.
        self._seed_published(["203.0.113.11"], when=utcnow())
        ranking = [_scored("chr-eu-1", 0.91), _scored("chr-eu-2", 0.50)]
        result = reconcile_now(
            cfg=ReconcileConfig(fqdn="vpn.example.com",
                                min_reapply_interval_seconds=300),
            rank_fn=lambda: ranking, state_of=_all_healthy,
        )
        assert result.applied is True
        assert result.changed is True
        row = DnsRecordState.get("vpn.example.com", "A")
        assert row.published_ips == sorted(["203.0.113.11", "203.0.113.12"])

    def test_unchanged_past_window_records_heartbeat_no_change(self, fleet_three):
        # Previous publish is old enough that the flap window has passed.
        self._seed_published(["203.0.113.11", "203.0.113.12"],
                             when=utcnow() - timedelta(seconds=600))
        ranking = [_scored("chr-eu-1", 0.91), _scored("chr-eu-2", 0.50)]
        result = reconcile_now(
            cfg=ReconcileConfig(fqdn="vpn.example.com",
                                min_reapply_interval_seconds=60),
            rank_fn=lambda: ranking, state_of=_all_healthy,
        )
        # Set is unchanged → driver still NOT called, but heartbeat upsert
        # refreshes updated_at so the next window starts now.
        assert result.applied is False
        assert result.changed is False
        assert result.reason == "set_unchanged"
        assert driver_adapter.FAKE_CALLS == []
        row = DnsRecordState.get("vpn.example.com", "A")
        assert row.last_change_reason == "heartbeat"


# ════════════════════════════════════════════════════════════════════════════
# Empty-set black-hole guard
# ════════════════════════════════════════════════════════════════════════════
class TestEmptySetGuard:
    def test_empty_fleet_first_reconcile_is_no_change(self, app):
        result = reconcile_now(rank_fn=lambda: [], state_of=_none_healthy)
        assert result.applied is False
        assert result.changed is False
        assert result.suppressed is False
        assert result.reason == "fleet_empty"
        assert driver_adapter.FAKE_CALLS == []
        ev = Event.query.filter_by(kind="dns_no_change").order_by(Event.id.desc()).first()
        assert ev is not None and ev.detail["reason"] == "fleet_empty"

    def test_all_down_with_prior_publish_suppresses(self, fleet_three):
        DnsRecordState.upsert(
            "vpn.hoberadius.com", "A",
            ["203.0.113.11", "203.0.113.12"], ttl=30, reason="seed",
        )
        db.session.commit()
        ranking = [_scored("chr-eu-1", 0.9), _scored("chr-eu-2", 0.8)]
        result = reconcile_now(
            rank_fn=lambda: ranking,
            state_of=_none_healthy,   # everything down per the monitor
        )
        assert result.applied is False
        assert result.suppressed is True
        assert result.reason == "publishable_set_empty"
        # Previous published set untouched
        row = DnsRecordState.get("vpn.hoberadius.com", "A")
        assert row.published_ips == sorted(["203.0.113.11", "203.0.113.12"])
        # Audit reflects suppression
        ev = Event.query.filter_by(kind="dns_suppressed").order_by(Event.id.desc()).first()
        assert ev is not None
        assert ev.detail["reason"] == "publishable_set_empty"
        assert ev.detail["previous_ips"] == sorted(["203.0.113.11", "203.0.113.12"])


# ════════════════════════════════════════════════════════════════════════════
# Dry-run mode and per-call settings
# ════════════════════════════════════════════════════════════════════════════
class TestDryRun:
    def test_dry_run_records_event_but_does_not_apply(self, fleet_three):
        ranking = [_scored("chr-eu-1", 0.9), _scored("chr-eu-2", 0.5)]
        result = reconcile_now(
            cfg=ReconcileConfig(fqdn="vpn.example.com", dry_run=True),
            rank_fn=lambda: ranking, state_of=_all_healthy,
        )
        assert result.applied is False
        assert result.reason == "dry_run"
        # Driver still called, but with dry_run=True
        assert len(driver_adapter.FAKE_CALLS) == 1
        assert driver_adapter.FAKE_CALLS[0]["dry_run"] is True
        # No DnsRecordState row was upserted
        assert DnsRecordState.get("vpn.example.com", "A") is None
        # Event recorded
        ev = Event.query.filter_by(kind="dns_dry_run").order_by(Event.id.desc()).first()
        assert ev is not None

    def test_mode_is_validated(self):
        with pytest.raises(ValueError):
            ReconcileConfig(mode="GARBAGE_MODE")

    def test_min_interval_negative_is_rejected(self):
        with pytest.raises(ValueError):
            ReconcileConfig(min_reapply_interval_seconds=-1)


# ════════════════════════════════════════════════════════════════════════════
# Driver adapter — backend selection
# ════════════════════════════════════════════════════════════════════════════
class TestDriverAdapter:
    def test_apply_validates_mode(self):
        from fleet.dns.driver_adapter import apply_desired_state
        with pytest.raises(ValueError):
            apply_desired_state([], mode="MADE_UP", dry_run=False)

    def test_apply_with_fake_default(self, app):
        from fleet.dns.driver_adapter import apply_desired_state, DRIVER_BACKEND
        result = apply_desired_state(
            [NodeRecord("chr-a", "1.2.3.4", 50, True)],
            mode="WEIGHTED_ROUND_ROBIN", dry_run=False,
        )
        assert isinstance(result, ApplyResult)
        assert result.published_ips == ["1.2.3.4"]
        assert driver_adapter.DRIVER_BACKEND == "fake"

    def test_real_driver_seam_replaces_fake(self, app, monkeypatch):
        """When ``fleet.dns.driver`` exposes ``apply_desired_state``, the
        adapter delegates to it and ``DRIVER_BACKEND`` flips to "real"."""
        import sys, types
        fake_module = types.ModuleType("fleet.dns.driver")

        def fake_apply(desired, *, mode, dry_run):
            return ApplyResult(
                applied=True, changed=True,
                published_ips=[r.ip for r in desired if r.included],
                message="real driver pretend",
                mode=mode, dry_run=dry_run, raw={"backend": "real"},
            )
        fake_module.apply_desired_state = fake_apply
        monkeypatch.setitem(sys.modules, "fleet.dns.driver", fake_module)

        from fleet.dns.driver_adapter import apply_desired_state
        from fleet.dns import driver_adapter as da
        result = apply_desired_state(
            [NodeRecord("chr-a", "1.2.3.4", 100, True)],
            mode="ROUND_ROBIN", dry_run=False,
        )
        assert result.message == "real driver pretend"
        assert da.DRIVER_BACKEND == "real"
