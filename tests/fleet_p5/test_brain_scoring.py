"""CHR Fleet Phase 5 — scoring engine verification.

Two layers:

* **Pure** — :func:`fleet.brain.scoring.score_node` and
  :func:`fleet.brain.scoring.should_move` are exercised against in-memory
  fixtures so every per-factor curve, the eligibility filter, and the
  movement hysteresis are checked without the DB.

* **DB-bound** — :func:`fleet.brain.placement.rank`,
  :func:`~fleet.brain.placement.best_node`, and
  :func:`~fleet.brain.placement.top_n` are exercised on a real fixture
  fleet under the panel's test app, asserting:

    - 'down' health excludes (rank never returns it; best_node never picks it).
    - cpu > 70 (default shed threshold) penalises the node so a
      similarly-loaded fresh peer beats it.
    - Unlimited (open provider) always out-ranks metered at low load.
    - Metered penalty escalates monotonically toward the cap.
    - At/over the drain ratio the metered node becomes ineligible.
    - Capacity ordering: more free sessions → higher rank.
    - **Fill-unlimited-first**: while ANY unlimited node has capacity
      headroom, no metered node ever beats it.
    - ``should_move`` honours the sustain window AND the cooldown.
"""
from __future__ import annotations

import dataclasses
from datetime import datetime, timedelta

import pytest

from app.extensions import db

from fleet.brain.placement import best_node, rank, top_n
from fleet.brain.scoring import NodeScore, UserSessionState, score_node, should_move
from fleet.config import FLEET, BrainConfig, FleetConfig, ScoringWeights
from fleet.health.models_health import FleetChrHealth, FleetChrMetric
from fleet.registry.models_chr import FleetChrNode, FleetProvider


# ════════════════════════════════════════════════════════════════════════
# Lightweight in-memory shapes for the PURE tests (no DB needed)
# ════════════════════════════════════════════════════════════════════════


@dataclasses.dataclass
class _Node:
    id: int = 1
    name: str = "n"
    enabled: bool = True
    drain: bool = False
    status: str = "up"
    max_sessions: int = 1000
    active_sessions: int = 0
    cpu_pct: float | None = None
    used_tb_cycle: float = 0.0
    bandwidth_cap_tb: float | None = None
    weight: float = 1.0


@dataclasses.dataclass
class _Health:
    state: str = "up"


@dataclasses.dataclass
class _Metric:
    cpu_pct: float | None = None
    active_sessions: int | None = None


@dataclasses.dataclass
class _Provider:
    cost_model: str = "open"
    monthly_cap_tb: float | None = None


def _cfg() -> FleetConfig:
    return FleetConfig()  # production defaults — same as FLEET


# ════════════════════════════════════════════════════════════════════════
# 1. PURE — eligibility filter
# ════════════════════════════════════════════════════════════════════════


def test_down_health_is_excluded():
    s = score_node(_Node(), _Health(state="down"), None, _Provider(), _cfg())
    assert s.eligible is False
    assert s.score == 0.0
    assert s.reasons["ineligible_reason"] == "down"


def test_disabled_node_is_excluded():
    s = score_node(_Node(enabled=False), _Health(state="up"), None, _Provider(), _cfg())
    assert s.eligible is False
    assert s.reasons["ineligible_reason"] == "disabled"


def test_draining_node_is_excluded():
    s = score_node(_Node(drain=True), _Health(state="up"), None, _Provider(), _cfg())
    assert s.eligible is False
    assert s.reasons["ineligible_reason"] == "draining"


def test_metered_over_cap_is_excluded():
    # used 11 TB out of 10 TB cap → over the drain ratio of 1.0
    node = _Node(bandwidth_cap_tb=10.0, used_tb_cycle=11.0)
    prov = _Provider(cost_model="metered", monthly_cap_tb=10.0)
    s = score_node(node, _Health(), None, prov, _cfg())
    assert s.eligible is False
    assert s.reasons["ineligible_reason"] == "over_cap"


# ════════════════════════════════════════════════════════════════════════
# 2. PURE — CPU penalty
# ════════════════════════════════════════════════════════════════════════


def test_low_cpu_outranks_high_cpu_below_shed():
    a = score_node(_Node(id=1), _Health(), _Metric(cpu_pct=20), _Provider(), _cfg())
    b = score_node(_Node(id=2), _Health(), _Metric(cpu_pct=60), _Provider(), _cfg())
    assert a.score > b.score
    assert a.reasons["shedding"] is False
    assert b.reasons["shedding"] is False


def test_cpu_above_shed_triggers_heavy_penalty():
    """A node at 75% CPU (above the 70% shed threshold) must score
    materially below a peer at 65% — even though raw headroom only
    differs by 10 pts, the heavy step multiplier dominates."""
    healthy_load = score_node(
        _Node(id=1), _Health(), _Metric(cpu_pct=65), _Provider(), _cfg()
    )
    over_shed = score_node(
        _Node(id=2), _Health(), _Metric(cpu_pct=75), _Provider(), _cfg()
    )
    assert healthy_load.reasons["shedding"] is False
    assert over_shed.reasons["shedding"] is True
    # The over-shed node's CPU contribution must be a small fraction of the
    # healthy peer's; with default cpu_shed_penalty=0.85 it's roughly 15%.
    assert over_shed.reasons["cpu"] < healthy_load.reasons["cpu"] * 0.5


def test_cpu_at_exactly_shed_threshold_is_already_shedding():
    """Shed kicks in at the threshold (>=), not strictly above."""
    s = score_node(_Node(), _Health(), _Metric(cpu_pct=70.0), _Provider(), _cfg())
    assert s.reasons["shedding"] is True


def test_missing_cpu_metric_is_neutral_not_punitive():
    """If neither the metric nor the denormalized node carries a CPU
    sample, scoring stays alive (factor=0.5) rather than collapsing to
    zero — we never silently drop a node for missing telemetry."""
    s = score_node(_Node(cpu_pct=None), _Health(), None, _Provider(), _cfg())
    assert s.eligible is True
    assert s.reasons["cpu"] > 0


# ════════════════════════════════════════════════════════════════════════
# 3. PURE — cost factor (open vs metered, escalation)
# ════════════════════════════════════════════════════════════════════════


def test_open_provider_always_beats_metered_at_zero_load():
    """Identical CPU / capacity; only cost_model differs."""
    open_s = score_node(
        _Node(id=1), _Health(), _Metric(cpu_pct=10, active_sessions=10),
        _Provider(cost_model="open"), _cfg(),
    )
    metered_s = score_node(
        _Node(id=2, bandwidth_cap_tb=10.0, used_tb_cycle=0.0),
        _Health(), _Metric(cpu_pct=10, active_sessions=10),
        _Provider(cost_model="metered", monthly_cap_tb=10.0), _cfg(),
    )
    assert open_s.reasons["cost"] > metered_s.reasons["cost"]
    assert open_s.score > metered_s.score


def test_metered_cost_penalty_escalates_toward_cap():
    """Score the same metered node at four points along the curve.
    Cost contribution must be monotonically non-increasing."""
    prov = _Provider(cost_model="metered", monthly_cap_tb=10.0)
    cost_at = []
    for used_tb in (0.0, 4.0, 7.5, 9.5):  # ratios: 0, 0.4, 0.75, 0.95
        s = score_node(
            _Node(bandwidth_cap_tb=10.0, used_tb_cycle=used_tb),
            _Health(), None, prov, _cfg(),
        )
        cost_at.append(s.reasons["cost"])
    # Strictly decreasing — each step is a step further into the curve.
    assert cost_at == sorted(cost_at, reverse=True)
    assert cost_at[0] > cost_at[-1]
    # The 75% point is flagged near_cap (warn ratio = 0.5 by default).
    near_cap_score = score_node(
        _Node(bandwidth_cap_tb=10.0, used_tb_cycle=7.5),
        _Health(), None, prov, _cfg(),
    )
    assert near_cap_score.reasons["near_cap"] is True


def test_metered_drain_boundary_is_inclusive():
    """At exactly the drain ratio (1.0), the node is ineligible."""
    s = score_node(
        _Node(bandwidth_cap_tb=10.0, used_tb_cycle=10.0),
        _Health(),
        None,
        _Provider(cost_model="metered", monthly_cap_tb=10.0),
        _cfg(),
    )
    assert s.eligible is False
    assert s.reasons["ineligible_reason"] == "over_cap"


# ════════════════════════════════════════════════════════════════════════
# 4. PURE — capacity ordering
# ════════════════════════════════════════════════════════════════════════


def test_more_free_capacity_outranks_less():
    spacious = score_node(
        _Node(id=1, max_sessions=1000, active_sessions=100),
        _Health(), None, _Provider(), _cfg(),
    )
    crowded = score_node(
        _Node(id=2, max_sessions=1000, active_sessions=900),
        _Health(), None, _Provider(), _cfg(),
    )
    assert spacious.score > crowded.score
    assert spacious.reasons["capacity"] > crowded.reasons["capacity"]


def test_capacity_zero_when_at_full():
    s = score_node(
        _Node(max_sessions=100, active_sessions=100),
        _Health(), None, _Provider(), _cfg(),
    )
    # Still eligible at the wire — capacity hits 0 but health/cost may
    # carry it. The capacity contribution itself collapses.
    assert s.reasons["capacity"] == 0.0


# ════════════════════════════════════════════════════════════════════════
# 5. PURE — node weight multiplier + reasons dict shape
# ════════════════════════════════════════════════════════════════════════


def test_node_weight_scales_final_score_not_factors():
    """node.weight is a final multiplier — operator override knob.
    Doubling it doubles ``score`` but leaves the per-factor contributions
    in ``reasons`` untouched (so the audit trail still makes sense)."""
    base = score_node(
        _Node(weight=1.0), _Health(), _Metric(cpu_pct=10), _Provider(), _cfg()
    )
    boosted = score_node(
        _Node(weight=2.0), _Health(), _Metric(cpu_pct=10), _Provider(), _cfg()
    )
    assert pytest.approx(base.score * 2.0) == boosted.score
    assert base.reasons["cpu"] == boosted.reasons["cpu"]
    assert base.reasons["weight"] == 1.0
    assert boosted.reasons["weight"] == 2.0


def test_reasons_dict_carries_every_documented_key():
    s = score_node(_Node(), _Health(), _Metric(cpu_pct=10), _Provider(), _cfg())
    required = {
        "health", "cpu", "capacity", "cost", "weight",
        "shedding", "near_cap", "usage_ratio", "tier",
    }
    assert required.issubset(s.reasons.keys())


# ════════════════════════════════════════════════════════════════════════
# 6. PURE — should_move hysteresis
# ════════════════════════════════════════════════════════════════════════


def _t(s: int) -> datetime:
    return datetime(2026, 6, 10, 12, 0, 0) + timedelta(seconds=s)


def test_should_move_false_when_not_over_threshold():
    st = UserSessionState(
        user="alice", current_chr_id=1,
        over_threshold_since=None, last_moved_at=None, now=_t(0),
    )
    assert should_move(st, _cfg()) is False


def test_should_move_false_before_sustain_window():
    # Default sustain = 180 s. At 179 s, must not signal.
    st = UserSessionState(
        user="alice", current_chr_id=1,
        over_threshold_since=_t(0), last_moved_at=None, now=_t(179),
    )
    assert should_move(st, _cfg()) is False


def test_should_move_true_at_sustain_window_boundary():
    st = UserSessionState(
        user="alice", current_chr_id=1,
        over_threshold_since=_t(0), last_moved_at=None, now=_t(180),
    )
    assert should_move(st, _cfg()) is True


def test_should_move_blocked_by_cooldown_after_recent_move():
    # User was moved 300 s ago — under default 600 s cooldown.
    st = UserSessionState(
        user="alice", current_chr_id=1,
        over_threshold_since=_t(0), last_moved_at=_t(0 - 300), now=_t(180),
    )
    assert should_move(st, _cfg()) is False


def test_should_move_true_once_cooldown_elapsed():
    # 600 s since last move, AND sustain window has elapsed.
    st = UserSessionState(
        user="alice", current_chr_id=1,
        over_threshold_since=_t(0), last_moved_at=_t(0 - 600), now=_t(180),
    )
    assert should_move(st, _cfg()) is True


# ════════════════════════════════════════════════════════════════════════
# 7. DB-bound fixture helpers
# ════════════════════════════════════════════════════════════════════════


def _provider(name: str, *, cost_model: str = "open", cap_tb: float | None = None,
              ) -> FleetProvider:
    p = FleetProvider(
        name=name, cost_model=cost_model,
        price_per_tb=5.0 if cost_model == "metered" else 0,
        monthly_cap_tb=cap_tb, overage_allowed=False,
        billing_cycle_day=1,
    )
    db.session.add(p)
    db.session.commit()
    return p


_NODE_SEQ: list[int] = [0]


def _node(
    *, name: str, provider: FleetProvider,
    max_sessions: int = 1000, active: int = 0,
    enabled: bool = True, drain: bool = False, status: str = "up",
    cpu_pct: float | None = 20.0, used_tb: float = 0.0,
    bandwidth_cap_tb: float | None = None,
    weight: float = 1.0,
) -> FleetChrNode:
    # Counter, not hash() — hash collisions on the IP suffix made the
    # spill-to-metered test flake.
    _NODE_SEQ[0] += 1
    h = _NODE_SEQ[0]
    n = FleetChrNode(
        provider_id=provider.id, name=name,
        public_ip=f"203.0.113.{h}",
        wg_mgmt_ip=f"10.99.0.{h}",
        wg_mgmt_pubkey="x" * 44,
        max_sessions=max_sessions, link_speed_mbps=1000,
        bandwidth_cap_tb=bandwidth_cap_tb,
        cost_model="inherit",
        weight=weight, enabled=enabled, drain=drain, status=status,
        cpu_pct=cpu_pct, active_sessions=active, used_tb_cycle=used_tb,
    )
    db.session.add(n)
    db.session.commit()
    return n


def _health(node: FleetChrNode, state: str) -> None:
    h = FleetChrHealth(
        chr_id=node.id, state=state, state_since=datetime(2026, 6, 10),
    )
    db.session.add(h)
    db.session.commit()


def _metric(node: FleetChrNode, *, cpu: float, active: int) -> None:
    m = FleetChrMetric(
        chr_id=node.id, cpu_pct=cpu, active_sessions=active, source="control",
    )
    db.session.add(m)
    db.session.commit()


# ════════════════════════════════════════════════════════════════════════
# 8. DB-bound — rank / best_node / top_n
# ════════════════════════════════════════════════════════════════════════


def test_rank_excludes_down_nodes(app):
    p = _provider("acme-1")
    healthy = _node(name="alive", provider=p)
    sick = _node(name="dead", provider=p)
    _health(healthy, "up")
    _health(sick, "down")

    results = rank()
    names = [s.name for s in results]
    assert "alive" in names
    assert "dead" not in names


def test_best_node_picks_unlimited_over_metered_at_equal_load(app):
    unlimited_p = _provider("open-host", cost_model="open")
    metered_p = _provider("metered-host", cost_model="metered", cap_tb=10.0)
    a = _node(name="open-A", provider=unlimited_p, max_sessions=1000, active=100)
    b = _node(name="metered-B", provider=metered_p,
              max_sessions=1000, active=100, bandwidth_cap_tb=10.0, used_tb=0.0)
    _health(a, "up"); _health(b, "up")

    best = best_node()
    assert best is not None
    assert best.name == "open-A"


def test_fill_unlimited_first_holds_even_when_metered_is_fresher(app):
    """The headline two-tier guarantee: while any unlimited node has
    headroom, a metered node — even a brand-new metered node at 0 TB
    used and lower CPU — can never out-rank it."""
    unlimited_p = _provider("open-1", cost_model="open")
    metered_p = _provider("met-1", cost_model="metered", cap_tb=10.0)

    # Unlimited node is moderately loaded but well below the spill
    # headroom threshold (70% free required by default = 30% used max).
    busy_open = _node(
        name="open-busy", provider=unlimited_p,
        max_sessions=1000, active=200, cpu_pct=55,
    )
    # Metered node is pristine.
    fresh_metered = _node(
        name="met-fresh", provider=metered_p,
        max_sessions=1000, active=0, cpu_pct=5,
        bandwidth_cap_tb=10.0, used_tb=0.0,
    )
    _health(busy_open, "up"); _health(fresh_metered, "up")

    results = rank()
    assert [s.name for s in results][0] == "open-busy"
    # The Tier 0 / Tier 1 markers are stamped on the reasons dict.
    by_name = {s.name: s for s in results}
    assert by_name["open-busy"].reasons["tier"] == 0
    assert by_name["met-fresh"].reasons["tier"] == 1


def test_spill_to_metered_when_all_unlimited_are_full(app):
    """Once every unlimited node falls below the spill headroom threshold
    (default: less than 30% free), the metered node moves back into
    Tier 0 contention by virtue of all unlimited nodes dropping to
    Tier 1. Within Tier 1 it's pure score-desc, and an idle metered
    node CAN beat a packed unlimited node."""
    unlimited_p = _provider("open-1", cost_model="open")
    metered_p = _provider("met-1", cost_model="metered", cap_tb=10.0)

    # Unlimited: 950 / 1000 sessions → only 5% free, below the 30% spill
    # headroom → falls to Tier 1.
    packed = _node(
        name="open-packed", provider=unlimited_p,
        max_sessions=1000, active=950, cpu_pct=60,
    )
    # Metered: 100 / 1000 sessions, 0 TB used.
    spill = _node(
        name="met-spill", provider=metered_p,
        max_sessions=1000, active=100, cpu_pct=10,
        bandwidth_cap_tb=10.0, used_tb=0.0,
    )
    _health(packed, "up"); _health(spill, "up")

    results = rank()
    by_name = {s.name: s for s in results}
    # Both are in Tier 1 (no unlimited had headroom).
    assert by_name["open-packed"].reasons["tier"] == 1
    assert by_name["met-spill"].reasons["tier"] == 1
    # And the idle metered node wins on pure score.
    assert results[0].name == "met-spill"


def test_cpu_over_70_drops_rank_below_fresh_peer(app):
    p = _provider("acme")
    a = _node(name="cool", provider=p, cpu_pct=20, active=100)
    b = _node(name="hot", provider=p, cpu_pct=80, active=100)
    _health(a, "up"); _health(b, "up")

    results = rank()
    cool_idx = next(i for i, s in enumerate(results) if s.name == "cool")
    hot_idx = next(i for i, s in enumerate(results) if s.name == "hot")
    assert cool_idx < hot_idx
    # And the hot one is flagged as shedding.
    assert next(s for s in results if s.name == "hot").reasons["shedding"] is True


def test_top_n_respects_n_and_caps_at_dns_top_n(app):
    p = _provider("acme")
    for i in range(5):
        n = _node(name=f"n-{i}", provider=p, active=i * 10)
        _health(n, "up")
    assert len(top_n(n=2)) == 2
    assert len(top_n(n=99)) <= FLEET.dns.top_n_cap


def test_top_n_zero_returns_empty(app):
    p = _provider("acme")
    n = _node(name="x", provider=p); _health(n, "up")
    assert top_n(n=0) == []


def test_rank_uses_latest_metric_over_denormalized_snapshot(app):
    """When a recent FleetChrMetric exists its cpu_pct beats the
    denormalised cpu_pct on the node row — so the brain reacts to live
    telemetry, not stale snapshots."""
    p = _provider("acme")
    # Node row says cpu=10 (denormalised); the live metric says cpu=85.
    n = _node(name="live", provider=p, cpu_pct=10)
    _health(n, "up")
    _metric(n, cpu=85, active=200)

    [scored] = rank()
    assert scored.reasons["shedding"] is True


def test_metered_node_skipped_when_over_cap(app):
    p = _provider("met", cost_model="metered", cap_tb=10.0)
    n = _node(name="overflow", provider=p,
              bandwidth_cap_tb=10.0, used_tb=10.0)
    _health(n, "up")
    assert rank() == []
    assert best_node() is None


# ════════════════════════════════════════════════════════════════════════
# 9. create_app smoke
# ════════════════════════════════════════════════════════════════════════


def test_create_app_boots(app):
    from sqlalchemy import inspect
    tables = set(inspect(db.engine).get_table_names())
    assert {"fleet_chr_nodes", "fleet_chr_health", "fleet_chr_metrics",
            "fleet_providers"}.issubset(tables)
