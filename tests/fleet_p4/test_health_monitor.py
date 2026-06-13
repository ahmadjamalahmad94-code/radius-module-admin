"""CHR Fleet Phase 4 — health monitor verification.

Covers:

* The hysteresis core (:func:`fleet.health.monitor.evaluate_transition`) —
  pure-function tests with a controlled clock + cfg, asserting the
  exact 300 s windows down and up.
* The DB-bound :func:`run_once` driving end-to-end:
    - up→down→up across a single replayed timeline with a fake pinger,
      asserting the transitions fire on (and only on) the exact second
      they should;
    - ``fleet_chr_metrics`` rows accumulate per probe;
    - on transition, a ``fleet_events`` row is appended with the right
      kind / severity / chr_id;
    - ``fleet_chr_nodes.status`` is mirrored to the new state;
    - a single OK in the middle of a near-down streak RESETS the streak
      (no flip).
* :func:`check_now` with ``node_id=None`` and a single id, including the
  unknown-id no-op path.
* The pinger is honoured for ``enabled=False`` nodes only via the
  explicit ``check_now(node_id=...)`` override (per spec: enabled-only on
  the cron path).
* Pinger-side exceptions are treated as a failed probe, not a crash.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Iterable

import pytest
from sqlalchemy import desc

from app.extensions import db

from fleet.config import HealthConfig
from fleet.health.models_health import FleetChrHealth, FleetChrMetric
from fleet.health.monitor import (
    NodeOutcome,
    PingResult,
    PingTarget,
    RunSummary,
    Transition,
    check_now,
    evaluate_transition,
    run_once,
)
from fleet.notify.models_alert import Event
from fleet.registry.models_chr import FleetChrNode, FleetProvider


# ════════════════════════════════════════════════════════════════════════
# Helpers / fixtures
# ════════════════════════════════════════════════════════════════════════


def _t(seconds: int) -> datetime:
    """A naive UTC clock used for tests (matches utcnow() shape)."""
    base = datetime(2026, 6, 9, 12, 0, 0)
    return base + timedelta(seconds=seconds)


@dataclass
class _FakePinger:
    """Deterministic pinger driven by a scripted dictionary or default.

    ``script``: mapping ``chr_id → bool`` (or callable ``(target) → bool``).
    Defaults to OK for every node. ``raise_for_chr_id`` injects an
    exception for the safety-net test.
    """

    script: dict[int, object] = field(default_factory=dict)
    raise_for_chr_id: int | None = None
    seen: list[PingTarget] = field(default_factory=list)

    def ping(self, target: PingTarget) -> PingResult:
        self.seen.append(target)
        if self.raise_for_chr_id == target.chr_id:
            raise RuntimeError("simulated pinger fault")
        rule = self.script.get(target.chr_id, True)
        ok = bool(rule(target)) if callable(rule) else bool(rule)
        return PingResult(
            ok=ok, latency_ms=4.2 if ok else None,
            error="" if ok else "timeout",
        )


def _provider() -> FleetProvider:
    p = FleetProvider(name="acme-test", cost_model="open")
    db.session.add(p)
    db.session.commit()
    return p


def _make_node(name: str, *, enabled: bool = True) -> FleetChrNode:
    provider = FleetProvider.query.first() or _provider()
    n = FleetChrNode(
        provider_id=provider.id, name=name,
        public_ip=f"203.0.113.{(hash(name) % 200) + 10}",
        wg_mgmt_ip=f"10.99.0.{(hash(name) % 200) + 10}",
        wg_mgmt_pubkey="x" * 44,
        routeros_api_port=8729, coa_port=3799,
        max_sessions=500, link_speed_mbps=1000,
        weight=1.0, enabled=enabled, status="provisioning",
    )
    db.session.add(n)
    db.session.commit()
    return n


def _cfg() -> HealthConfig:
    # Use the production defaults so the test asserts the real 5-min window.
    return HealthConfig()


# ════════════════════════════════════════════════════════════════════════
# 1. evaluate_transition — pure function tests
# ════════════════════════════════════════════════════════════════════════


def test_single_fail_does_not_flip_to_down():
    """A blip does not move state — the whole point of hysteresis."""
    h = FleetChrHealth(chr_id=1, state="up", state_since=_t(0),
                       consecutive_fail=0, consecutive_ok=10, flap_count_1h=0)
    t = evaluate_transition(h, ping_ok=False, now=_t(60),
                            last_fail_ts=None, cfg=_cfg())
    assert t is None
    assert h.state == "up"
    assert h.consecutive_fail == 1
    assert h.first_fail_at == _t(60)


def test_continuous_fails_under_300s_do_not_flip():
    """Even 299 s of continuous fail is below the threshold."""
    h = FleetChrHealth(chr_id=1, state="up", state_since=_t(0),
                       consecutive_fail=0, consecutive_ok=0, flap_count_1h=0)
    # First fail at t=60s.
    evaluate_transition(h, ping_ok=False, now=_t(60), last_fail_ts=None, cfg=_cfg())
    # Continuing failures right up to 359s = 299s into the streak.
    t = evaluate_transition(h, ping_ok=False, now=_t(60 + 299),
                            last_fail_ts=_t(60), cfg=_cfg())
    assert t is None
    assert h.state == "up"


def test_fail_streak_at_exactly_300s_flips_to_down():
    """At the 300-second mark, the down edge fires (>= on purpose)."""
    h = FleetChrHealth(chr_id=1, state="up", state_since=_t(0),
                       consecutive_fail=0, consecutive_ok=0, flap_count_1h=0)
    evaluate_transition(h, ping_ok=False, now=_t(60), last_fail_ts=None, cfg=_cfg())
    t = evaluate_transition(h, ping_ok=False, now=_t(60 + 300),
                            last_fail_ts=_t(60 + 299), cfg=_cfg())
    assert t is not None
    assert t.from_state == "up" and t.to_state == "down"
    assert h.state == "down"
    assert h.state_since == _t(60 + 300)
    assert h.last_transition == "up->down"


def test_one_ok_in_streak_resets_the_clock():
    """A single success in the middle of a streak resets first_fail_at."""
    h = FleetChrHealth(chr_id=1, state="up", state_since=_t(0),
                       consecutive_fail=0, consecutive_ok=0, flap_count_1h=0)
    # First failure.
    evaluate_transition(h, ping_ok=False, now=_t(60), last_fail_ts=None, cfg=_cfg())
    assert h.first_fail_at == _t(60)
    # 250 s of fails, then a single recovery, then more fails.
    evaluate_transition(h, ping_ok=False, now=_t(60 + 250),
                        last_fail_ts=_t(60), cfg=_cfg())
    evaluate_transition(h, ping_ok=True, now=_t(60 + 260),
                        last_fail_ts=_t(60 + 250), cfg=_cfg())
    assert h.first_fail_at is None
    assert h.consecutive_fail == 0
    # New streak starts; we need ANOTHER 300 s of continuous fails to flip.
    evaluate_transition(h, ping_ok=False, now=_t(60 + 270),
                        last_fail_ts=None, cfg=_cfg())
    # 299 s into the new streak — still up.
    t = evaluate_transition(h, ping_ok=False, now=_t(60 + 270 + 299),
                            last_fail_ts=_t(60 + 270), cfg=_cfg())
    assert t is None and h.state == "up"


def test_recovery_under_300s_does_not_flip_back_up():
    """A 100-second OK streak is not enough to leave the down state."""
    h = FleetChrHealth(chr_id=1, state="down", state_since=_t(0),
                       consecutive_fail=0, consecutive_ok=0, flap_count_1h=1,
                       first_fail_at=None)
    # last_fail_ts captured at t=10s — only 100 s of recovery so far.
    t = evaluate_transition(h, ping_ok=True, now=_t(110),
                            last_fail_ts=_t(10), cfg=_cfg())
    assert t is None
    assert h.state == "down"
    assert h.consecutive_ok == 1


def test_recovery_at_exactly_300s_flips_back_to_up():
    h = FleetChrHealth(chr_id=1, state="down", state_since=_t(0),
                       consecutive_fail=0, consecutive_ok=0, flap_count_1h=1)
    t = evaluate_transition(h, ping_ok=True, now=_t(310),
                            last_fail_ts=_t(10), cfg=_cfg())
    assert t is not None
    assert t.from_state == "down" and t.to_state == "up"
    assert h.state == "up"
    assert h.last_transition == "down->up"


def test_unknown_state_seeds_up_on_first_ok():
    """A brand-new node with no history should be ``up`` on first contact."""
    h = FleetChrHealth(chr_id=1, state="unknown", state_since=_t(0),
                       consecutive_fail=0, consecutive_ok=0, flap_count_1h=0)
    t = evaluate_transition(h, ping_ok=True, now=_t(0),
                            last_fail_ts=None, cfg=_cfg())
    assert t is not None and t.to_state == "up"
    assert h.state == "up"


# ════════════════════════════════════════════════════════════════════════
# 2. run_once — DB-bound end-to-end
# ════════════════════════════════════════════════════════════════════════


def test_run_once_persists_metric_per_node(app):
    n1 = _make_node("chr-A")
    n2 = _make_node("chr-B")
    fake = _FakePinger(script={n1.id: True, n2.id: False})

    summary = run_once(pinger=fake, now=_t(0))

    assert summary.checked == 2
    assert summary.ok_count == 1
    assert summary.fail_count == 1
    # One metric row per node, with the matching ping fields.
    metrics = FleetChrMetric.query.order_by(FleetChrMetric.chr_id).all()
    assert {m.chr_id for m in metrics} == {n1.id, n2.id}
    by_chr = {m.chr_id: m for m in metrics}
    assert by_chr[n1.id].ping_loss_pct == 0
    assert by_chr[n1.id].ping_rtt_ms is not None
    assert by_chr[n2.id].ping_loss_pct == 100
    assert by_chr[n2.id].ping_rtt_ms is None


def test_run_once_skips_disabled_nodes_on_cron_path(app):
    enabled = _make_node("chr-enabled", enabled=True)
    disabled = _make_node("chr-disabled", enabled=False)
    fake = _FakePinger()

    summary = run_once(pinger=fake, now=_t(0))
    assert summary.checked == 1
    assert fake.seen[0].chr_id == enabled.id


def test_probe_targets_wg_mgmt_ip_not_public_and_marks_up(app):
    """Decision: health rides the CONTROL PLANE (wg-mgmt), never the public IP.

    A node with both IPs set is probed at its ``wg_mgmt_ip`` (10.99.0.11) over
    the panel's wg-mgmt tunnel — the public IP is never touched (probing it
    would be insecure + firewall-blocked). A reachable node flips unknown→up.
    """
    node = _make_node("chr-vpn-1")
    node.public_ip = "178.105.244.112"   # the real chr-vpn-1 front door
    node.wg_mgmt_ip = "10.99.0.11"       # the control-plane address
    db.session.commit()

    fake = _FakePinger()  # default OK == a reachable CHR over the tunnel
    run_once(pinger=fake, now=_t(0))

    # The probe went to the wg-mgmt IP, and NEVER to the public IP.
    assert fake.seen, "the node must have been probed"
    assert fake.seen[0].host == "10.99.0.11"
    assert all(t.host != "178.105.244.112" for t in fake.seen)

    # unknown → up on the first successful probe; node.status mirrored.
    health = db.session.get(FleetChrHealth, node.id)
    assert health.state == "up"
    assert db.session.get(FleetChrNode, node.id).status == "up"


def test_probe_falls_back_to_public_ip_only_when_mgmt_ip_empty(app):
    """The public IP is a LAST-RESORT fallback — used only when there is no
    wg-mgmt IP (e.g. a legacy/pre-fleet row), never in preference to it."""
    node = _make_node("legacy-node")
    node.public_ip = "5.6.7.8"
    node.wg_mgmt_ip = ""
    db.session.commit()

    fake = _FakePinger()
    run_once(pinger=fake, now=_t(0))
    assert fake.seen and fake.seen[0].host == "5.6.7.8"


def test_full_up_to_down_to_up_replay_with_hysteresis(app):
    """The headline test: replay a real timeline, assert each transition
    fires on exactly the expected second."""
    node = _make_node("chr-headline")

    # Phase A — node is up. One healthy probe at t=0 seeds it.
    fake = _FakePinger(script={node.id: True})
    run_once(pinger=fake, now=_t(0))
    health = db.session.get(FleetChrHealth, node.id)
    assert health.state == "up"

    # Phase B — failures begin at t=60s and continue. Up to t=60+299 we
    # must NOT have flipped to down.
    fake = _FakePinger(script={node.id: False})
    run_once(pinger=fake, now=_t(60))            # first fail
    run_once(pinger=fake, now=_t(60 + 100))      # streak grows
    run_once(pinger=fake, now=_t(60 + 200))
    summary = run_once(pinger=fake, now=_t(60 + 299))
    health = db.session.get(FleetChrHealth, node.id)
    assert health.state == "up", "must not flip at 299 s"
    assert all(t.to_state != "down" for t in summary.transitions)

    # At t=60+300, the down edge fires.
    summary = run_once(pinger=fake, now=_t(60 + 300))
    health = db.session.get(FleetChrHealth, node.id)
    assert health.state == "down"
    assert len(summary.transitions) == 1
    tr = summary.transitions[0]
    assert tr.from_state == "up" and tr.to_state == "down"
    assert tr.at == _t(60 + 300)

    # ``fleet_chr_nodes.status`` was mirrored.
    fresh_node = db.session.get(FleetChrNode, node.id)
    assert fresh_node.status == "down"

    # ``fleet_events`` row materialised with kind=health_down, severity=crit.
    ev = (
        Event.query
        .filter_by(chr_id=node.id, kind="health_down")
        .order_by(desc(Event.id))
        .first()
    )
    assert ev is not None
    assert ev.severity == "crit"
    assert ev.detail["from_state"] == "up"
    assert ev.detail["to_state"] == "down"

    # Phase C — recovery. The DOWN was recorded at t=60+300 (=360); that
    # tick wrote a FAIL metric, so ``last_fail_ts`` for the recovery
    # window calculation is 360. Recovery requires ``up_after`` (300 s)
    # of continuous OK measured from that timestamp → boundary at t=660.
    fake = _FakePinger(script={node.id: True})
    run_once(pinger=fake, now=_t(60 + 400))         # t=460 (100 s in)
    run_once(pinger=fake, now=_t(60 + 540))         # t=600 (240 s in)
    summary = run_once(pinger=fake, now=_t(60 + 599))  # t=659 (299 s)
    health = db.session.get(FleetChrHealth, node.id)
    assert health.state == "down", "299 s of recovery is not enough"
    assert all(t.to_state != "up" for t in summary.transitions)

    # At t=60+600=660 we hit exactly 300 s after last_fail_ts → flip to up.
    summary = run_once(pinger=fake, now=_t(60 + 600))
    health = db.session.get(FleetChrHealth, node.id)
    assert health.state == "up"
    assert any(t.to_state == "up" for t in summary.transitions)
    fresh_node = db.session.get(FleetChrNode, node.id)
    assert fresh_node.status == "up"

    # A health_up event was emitted.
    up_ev = (
        Event.query
        .filter_by(chr_id=node.id, kind="health_up")
        .order_by(desc(Event.id))
        .first()
    )
    assert up_ev is not None
    assert up_ev.severity == "info"


def test_recovery_window_uses_persisted_last_fail(app):
    """The down→up boundary is anchored on the persisted last_fail metric,
    not on consecutive_ok counts (so an operator can run the monitor
    sparingly without distorting the window)."""
    node = _make_node("chr-window")

    # Seed up.
    run_once(pinger=_FakePinger(script={node.id: True}), now=_t(0))
    # Fail streak → down at t=300.
    fake_fail = _FakePinger(script={node.id: False})
    run_once(pinger=fake_fail, now=_t(0))
    run_once(pinger=fake_fail, now=_t(150))
    summary = run_once(pinger=fake_fail, now=_t(300))
    assert any(t.to_state == "down" for t in summary.transitions)

    # Single OK at t=300+299 — must NOT flip.
    fake_ok = _FakePinger(script={node.id: True})
    summary = run_once(pinger=fake_ok, now=_t(300 + 299))
    assert all(t.to_state != "up" for t in summary.transitions)
    health = db.session.get(FleetChrHealth, node.id)
    assert health.state == "down"

    # One more OK at t=300+300 — must flip.
    summary = run_once(pinger=fake_ok, now=_t(300 + 300))
    health = db.session.get(FleetChrHealth, node.id)
    assert health.state == "up"


# ════════════════════════════════════════════════════════════════════════
# 3. check_now
# ════════════════════════════════════════════════════════════════════════


def test_check_now_with_no_id_probes_every_enabled_node(app):
    a = _make_node("chr-now-A")
    b = _make_node("chr-now-B")
    fake = _FakePinger()
    summary = check_now(pinger=fake, now=_t(0))
    assert summary.checked == 2
    assert {t.chr_id for t in fake.seen} == {a.id, b.id}


def test_check_now_with_id_probes_only_that_node_even_if_disabled(app):
    on = _make_node("chr-on")
    off = _make_node("chr-off", enabled=False)
    fake = _FakePinger()
    summary = check_now(node_id=off.id, pinger=fake, now=_t(0))
    assert summary.checked == 1
    assert fake.seen and fake.seen[0].chr_id == off.id


def test_check_now_with_unknown_id_is_a_no_op(app):
    _make_node("chr-other")
    fake = _FakePinger()
    summary = check_now(node_id=99999, pinger=fake, now=_t(0))
    assert summary.checked == 0
    assert summary.ok_count == 0 and summary.fail_count == 0
    assert fake.seen == []


# ════════════════════════════════════════════════════════════════════════
# 4. Safety net: pinger exceptions don't break the pass
# ════════════════════════════════════════════════════════════════════════


def test_pinger_exception_is_treated_as_fail(app):
    n = _make_node("chr-bomb")
    fake = _FakePinger(raise_for_chr_id=n.id)
    summary = run_once(pinger=fake, now=_t(0))
    assert summary.checked == 1
    assert summary.fail_count == 1
    # A metric row was still recorded so the next pass has continuity.
    m = FleetChrMetric.query.filter_by(chr_id=n.id).one()
    assert m.ping_loss_pct == 100


# ════════════════════════════════════════════════════════════════════════
# 5. create_app smoke
# ════════════════════════════════════════════════════════════════════════


def test_create_app_boots(app):
    """If the ``app`` fixture handed us a context, create_app() returned."""
    # Sanity: the monitor's tables exist on this DB.
    from sqlalchemy import inspect
    tables = set(inspect(db.engine).get_table_names())
    assert {"fleet_chr_nodes", "fleet_chr_health", "fleet_chr_metrics",
            "fleet_events"}.issubset(tables)
