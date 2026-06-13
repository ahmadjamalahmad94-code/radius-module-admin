"""fleet.health.monitor — Phase 4 task A (ping-based health monitor).

Iterates every ENABLED row in ``fleet_chr_nodes``, pings each, persists a
``fleet_chr_metrics`` sample (with ``source='ping'``), and updates the rolling
``fleet_chr_health`` state with **hysteresis** so a single blip never flips
a node down:

* A node is marked **DOWN** only after it has failed ping CONTINUOUSLY for
  ``HealthConfig.down_after`` seconds (default **300s = 5 min**, configurable
  via :mod:`fleet.config`).
* A previously-DOWN node is marked **UP** again only after it has succeeded
  CONTINUOUSLY for ``HealthConfig.up_after`` seconds (default 300s) — same
  damping in reverse.
* On a real transition we append a row to ``fleet_events`` (kind
  ``health_down`` or ``health_up``) so the Phase-9 notifier has something to
  consume. THIS module does NOT send any notifications yet — that wiring
  belongs to P9-T1 (the TODO is marked in :func:`_notify_hook`).

The pinger is a small interface (:class:`Pinger`) so the same monitor body
runs with the real TCP-connect probe in production and a deterministic fake
in the test suite — no real network in CI.

Phase-4 scope (per the gate spec) is **pure health sensing + recording**:
no DNS reshuffle, no CoA, no failover. Those wire up in later phases via
the events log this module emits.
"""
from __future__ import annotations

import dataclasses
import logging
import platform
import shutil
import socket
import subprocess
import time
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from typing import Protocol

from sqlalchemy import desc

from app.extensions import db
from app.models import utcnow

from fleet.config import FLEET, HealthConfig
from fleet.health.models_health import FleetChrHealth, FleetChrMetric
from fleet.notify.models_alert import Event
from fleet.registry.models_chr import FleetChrNode


logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════════
# Pinger interface
# ════════════════════════════════════════════════════════════════════════


@dataclasses.dataclass(frozen=True)
class PingTarget:
    """Where to ping a CHR node.

    ``host`` is the panel's preferred reach over the **control plane**
    (``wg_mgmt_ip``, e.g. ``10.99.0.11``); ``public_ip`` is only used as
    a last-resort fallback when ``wg_mgmt_ip`` is empty. Probing the
    public IP for liveness is wrong in two ways: the operator's CHR
    firewall blocks RouterOS api-ssl on the WAN (so the probe always
    fails and the node looks down), and it exposes the control port to
    the internet if it ever stops being blocked. ``wg-mgmt`` is the
    documented control plane and the only place the panel should reach
    the CHR for health.

    ``port`` is the RouterOS control endpoint (``routeros_api_port``);
    ICMP pingers ignore it. The default :class:`IcmpPinger` does an
    ICMP echo to ``host`` and treats a reply as "the CHR is up" — that
    is the documented control-plane liveness contract (the CHR firewall
    accepts ICMP on wg-mgmt; api-ssl/cert are not needed to know it's
    alive).
    """

    chr_id: int
    name: str
    host: str
    port: int = 8729           # RouterOS api-ssl default; ICMP pingers ignore this.


@dataclasses.dataclass(frozen=True)
class PingResult:
    """Outcome of a single probe.

    ``ok``           True iff the probe succeeded.
    ``latency_ms``   wall-clock latency of the probe; None when ok=False.
    ``error``        short machine-readable cause when ok=False
                     (``"timeout"`` / ``"refused"`` / ``"unreachable"``).
    """

    ok: bool
    latency_ms: float | None = None
    error: str = ""


class Pinger(Protocol):
    """Pluggable probe transport.

    Production wiring registers a real implementation
    (:class:`TcpConnectPinger`). Tests pass a deterministic fake that
    yields exact transitions on a controlled clock.
    """

    def ping(self, target: PingTarget) -> PingResult:  # noqa: D401 - protocol
        """Probe ``target`` once and return what we observed."""


class TcpConnectPinger:
    """Legacy probe: TCP connect to ``target.host:target.port``.

    Kept for back-compat and as a deliberate override (some operators
    want to probe a specific TCP port). Production now defaults to
    :class:`IcmpPinger` (see the rationale on ``_resolve_target``): the
    CHR's control plane is ``wg-mgmt``, and that interface accepts ICMP
    without any cert/api-ssl handshake — ICMP is the most honest "is
    this box reachable over the control plane" signal we can get.
    """

    def __init__(self, timeout_s: float = 3.0):
        self._timeout = timeout_s

    def ping(self, target: PingTarget) -> PingResult:
        sock = None
        start = time.perf_counter()
        try:
            sock = socket.create_connection((target.host, target.port), timeout=self._timeout)
            latency = (time.perf_counter() - start) * 1000.0
            return PingResult(ok=True, latency_ms=round(latency, 2))
        except socket.timeout:
            return PingResult(ok=False, error="timeout")
        except ConnectionRefusedError:
            return PingResult(ok=False, error="refused")
        except OSError as exc:
            # "Network is unreachable", "Host unreachable", DNS errors, …
            return PingResult(ok=False, error=getattr(exc, "strerror", str(exc)) or "os_error")
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:  # pragma: no cover - best-effort cleanup
                    pass


class IcmpPinger:
    """Production probe: ICMP echo to ``target.host`` over the control plane.

    Why ICMP and not TCP-connect-8729:
      * The previous default tried TCP to RouterOS api-ssl on port 8729
        over the **public IP**, which is firewall-blocked on WAN (and
        ought to be — exposing api-ssl is a footgun). Result: a perfectly
        healthy CHR always read as ``down`` until the operator manually
        flipped its status. This was the live blocker driving this fix.
      * ``wg-mgmt`` accepts ICMP on the panel-side firewall (it's the
        control plane — that's the whole point). The moment the tunnel
        is up, ``ping 10.99.0.11`` works; the moment it goes down, it
        stops. That is exactly the liveness signal the monitor needs.
      * No raw sockets / no privileges required: we shell out to the
        system ``ping`` binary which is on every Linux / Windows host
        the panel runs on. If the binary somehow isn't there, the probe
        falls back to a single TCP-connect to ``target.port`` so the
        monitor degrades to the legacy behaviour rather than reporting
        every node down.

    Cross-platform invocation:
      * **Linux**: ``ping -c 1 -W <seconds> <host>``
      * **Windows**: ``ping -n 1 -w <milliseconds> <host>``
      * **macOS**: ``ping -c 1 -W <milliseconds> <host>`` (macOS uses ms
        for ``-W``); same flag spelling as Linux happens to work.

    A non-zero return code OR a "100% packet loss" line counts as fail.
    """

    def __init__(self, timeout_s: float = 3.0):
        self._timeout = timeout_s

    def _build_argv(self, host: str) -> list[str]:
        sysname = platform.system().lower()
        if sysname == "windows":
            timeout_ms = max(1, int(self._timeout * 1000))
            return ["ping", "-n", "1", "-w", str(timeout_ms), host]
        # Linux + macOS
        timeout_s = max(1, int(round(self._timeout)))
        return ["ping", "-c", "1", "-W", str(timeout_s), host]

    def ping(self, target: PingTarget) -> PingResult:
        host = (target.host or "").strip()
        if not host:
            return PingResult(ok=False, error="no_host")
        if shutil.which("ping") is None:
            # Degraded fallback: legacy TCP-connect so the monitor still
            # runs on a stripped container missing the ping binary.
            return TcpConnectPinger(timeout_s=self._timeout).ping(target)

        argv = self._build_argv(host)
        start = time.perf_counter()
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=self._timeout + 2.0,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return PingResult(ok=False, error="timeout")
        except OSError as exc:  # pragma: no cover - exotic spawn failure
            return PingResult(ok=False, error=getattr(exc, "strerror", str(exc)) or "spawn_error")
        latency_ms = round((time.perf_counter() - start) * 1000.0, 2)

        # ``ping`` returns 0 only when at least one reply was received.
        # On Windows it can return 0 even with "Destination host
        # unreachable" so we also scan the output for the loss line.
        text = (proc.stdout or "") + (proc.stderr or "")
        lost_all = "100% packet loss" in text or "100% loss" in text
        if proc.returncode == 0 and not lost_all:
            return PingResult(ok=True, latency_ms=latency_ms)
        if "Destination Host Unreachable" in text or "unreachable" in text.lower():
            return PingResult(ok=False, error="unreachable")
        return PingResult(ok=False, error="timeout" if lost_all else f"rc{proc.returncode}")


# ════════════════════════════════════════════════════════════════════════
# Public result shapes
# ════════════════════════════════════════════════════════════════════════


@dataclasses.dataclass(frozen=True)
class Transition:
    """A health-state edge that just fired."""

    chr_id: int
    from_state: str
    to_state: str
    at: datetime


@dataclasses.dataclass(frozen=True)
class NodeOutcome:
    """One node's outcome from a single monitor pass."""

    chr_id: int
    name: str
    ok: bool
    latency_ms: float | None
    state: str
    transition: Transition | None = None


@dataclasses.dataclass(frozen=True)
class RunSummary:
    """Top-level summary returned by :func:`run_once` / :func:`check_now`."""

    started_at: datetime
    finished_at: datetime
    checked: int
    ok_count: int
    fail_count: int
    transitions: tuple[Transition, ...]
    outcomes: tuple[NodeOutcome, ...]


# ════════════════════════════════════════════════════════════════════════
# Hysteresis core (pure function — no DB I/O, easy to unit-test)
# ════════════════════════════════════════════════════════════════════════


def evaluate_transition(
    health: FleetChrHealth,
    *,
    ping_ok: bool,
    now: datetime,
    last_fail_ts: datetime | None,
    cfg: HealthConfig,
) -> Transition | None:
    """Apply ONE probe outcome to ``health`` in place; return a transition iff fired.

    Logic
    -----
    * **OK probe**
      * ``consecutive_ok += 1``; ``consecutive_fail = 0``; ``first_fail_at = None``.
      * If current state is **down**, we are recovering. The down→up edge
        fires only when the elapsed time since the *last failed probe*
        (``last_fail_ts``) is ≥ ``cfg.up_after`` — i.e. continuous OK for
        that whole window. If ``last_fail_ts`` is None the recovery started
        before any persisted fail, so we accept right away.
      * If current state is **unknown/degraded**, a single OK is enough
        to seed it ``up`` (we have no evidence to keep penalising).
      * If current state is already **up**, this is a no-op.

    * **FAIL probe**
      * ``consecutive_fail += 1``; ``consecutive_ok = 0``.
      * If ``first_fail_at`` is None (this is the start of a streak), set
        it to ``now``. Otherwise leave it alone — the streak is ongoing.
      * If current state is anything BUT down and the streak length
        (``now - first_fail_at``) is ≥ ``cfg.down_after``, flip to ``down``.

    * On every transition we bump ``flap_count_1h``; the dampening rule
      itself (suppress flips while ``flap_count_1h`` is high) is delegated
      to the Phase-9 notifier rule matrix (P9-T3), so the data is captured
      here even though no decision is made off it yet.

    The function mutates ``health`` in place. Caller is responsible for
    flushing/committing.
    """
    if ping_ok:
        health.consecutive_ok = (health.consecutive_ok or 0) + 1
        health.consecutive_fail = 0
        health.first_fail_at = None

        if health.state == "down":
            # Recovery window: continuous OK for ``up_after`` seconds.
            if last_fail_ts is None:
                elapsed = float("inf")
            else:
                # last_fail_ts is captured BEFORE this OK was recorded.
                elapsed = (now - last_fail_ts).total_seconds()
            if elapsed >= cfg.up_after:
                return _do_transition(health, "up", now)
            return None

        if health.state in ("unknown", "degraded"):
            return _do_transition(health, "up", now)

        # Already up — nothing to do.
        return None

    # FAIL path.
    health.consecutive_fail = (health.consecutive_fail or 0) + 1
    health.consecutive_ok = 0
    if health.first_fail_at is None:
        health.first_fail_at = now

    if health.state == "down":
        # Already down; just keep accumulating the streak.
        return None

    # Hard rule (added after the live "provisioning-marked-down" debug):
    # a node that has NEVER been verified up must not be flipped to down
    # by the monitor. Health rows start at state="unknown" on first
    # contact, and a node freshly enrolled by the wizard sits in
    # ``provisioning`` until its wg-mgmt tunnel comes up and the first
    # ping succeeds. While we are still in "unknown", a failing ping
    # means "we cannot reach it YET" — that's the same as
    # provisioning, not a real outage. Only nodes that have already
    # been seen up (``up`` / ``degraded``) can transition to ``down``.
    # This breaks the catch-22 where the monitor would mark a fresh CHR
    # ``down`` before it ever had a chance to come up, and the routing
    # table (which excludes ``down`` nodes by default) would then never
    # publish it. See: fleet/registry/models_chr.py NODE_STATUSES.
    if health.state not in ("up", "degraded"):
        return None

    streak_s = (now - health.first_fail_at).total_seconds()
    if streak_s >= cfg.down_after:
        return _do_transition(health, "down", now)
    return None


def _do_transition(health: FleetChrHealth, to_state: str, now: datetime) -> Transition:
    """Mutate ``health`` for a confirmed transition and return the record."""
    from_state = health.state
    health.last_transition = f"{from_state}->{to_state}"
    health.state = to_state
    health.state_since = now
    health.flap_count_1h = (health.flap_count_1h or 0) + 1
    if to_state == "up":
        # Down-streak is over; clear the start-of-streak marker.
        health.first_fail_at = None
    return Transition(chr_id=health.chr_id, from_state=from_state, to_state=to_state, at=now)


# ════════════════════════════════════════════════════════════════════════
# DB-bound helpers
# ════════════════════════════════════════════════════════════════════════


def _resolve_target(node: FleetChrNode) -> PingTarget:
    """Pick the reach for a node — **control plane first**, public IP fallback.

    The monitor's job is "is the CHR alive?" — and the CHR's control
    plane IS ``wg-mgmt``. The public IP is for end-user VPN traffic; the
    operator's firewall correctly blocks RouterOS api-ssl on the WAN, so
    probing the public IP for control liveness always failed and made
    even a healthy CHR look down (the live deployment debug this fix
    came out of). The fix is to send every probe over ``wg_mgmt_ip``
    (e.g. ``10.99.0.11``), the way the rest of the panel reaches CHRs.

    ``public_ip`` is kept only as a last-resort fallback for a node
    whose ``wg_mgmt_ip`` was somehow never populated — that should be
    impossible after onboarding but we don't want a single bad row to
    silently turn off health for the whole fleet. When that fallback
    fires, the probe still uses ICMP (see :class:`IcmpPinger`) so it
    doesn't expose any control port externally.
    """
    host = (node.wg_mgmt_ip or "").strip() or (node.public_ip or "").strip()
    return PingTarget(
        chr_id=int(node.id),
        name=node.name or "",
        host=host,
        # fix/api-service-port-consistency — fallback is 8443 (REST over
        # www-ssl), NEVER 8729 (binary api-ssl, which the unified script
        # explicitly disables). The 8729 literal here was vestigial —
        # the monitor's primary probe is ICMP (no TCP dial), but the
        # misleading default invited drift between the script-enabled
        # transport and the panel's dial port. Keep every fallback 8443.
        port=int(node.routeros_api_port or 8443),
    )


def _get_or_create_health(chr_id: int, now: datetime) -> FleetChrHealth:
    """Lazy-init a health row on first contact (state=unknown)."""
    row = db.session.get(FleetChrHealth, chr_id)
    if row is None:
        row = FleetChrHealth(
            chr_id=chr_id, state="unknown", state_since=now,
            consecutive_fail=0, consecutive_ok=0, flap_count_1h=0,
        )
        db.session.add(row)
    return row


def _last_fail_ts(chr_id: int, *, before: datetime) -> datetime | None:
    """Timestamp of the most recent FAILED ping metric BEFORE ``before``.

    Used to gate the down→up recovery window. We treat ``ping_loss_pct
    >= 100`` as "failed probe" — that is the value :func:`run_once`
    writes when ``ping_ok=False``.
    """
    row = (
        db.session.query(FleetChrMetric.ts)
        .filter(FleetChrMetric.chr_id == chr_id)
        .filter(FleetChrMetric.source == "ping")
        .filter(FleetChrMetric.ping_loss_pct >= 100)
        .filter(FleetChrMetric.ts < before)
        .order_by(desc(FleetChrMetric.ts))
        .first()
    )
    return row[0] if row is not None else None


def _persist_metric(
    chr_id: int, *, ok: bool, latency_ms: float | None, now: datetime,
) -> None:
    """Append one ``fleet_chr_metrics`` row for this probe."""
    db.session.add(FleetChrMetric(
        chr_id=chr_id,
        ts=now,
        ping_rtt_ms=latency_ms if ok else None,
        ping_loss_pct=0 if ok else 100,
        source="ping",
    ))


def _emit_event(transition: Transition, node_name: str, *, latency_ms: float | None) -> None:
    """Write a ``fleet_events`` row for a state edge.

    Only down/up edges produce an event — unknown/degraded intermediates
    are not interesting for the operator. Severity follows the doc's
    catalog (see fleet.notify.models_alert): ``health_down`` is ``crit``,
    ``health_up`` is ``info``.

    TODO(P9-T1, fleet.notify): the notifier should consume rows of this
    kind and materialise an ``Alert`` with a stable dedupe_key (e.g.
    ``f"chr:{chr_id}:{kind}"``). We deliberately don't queue any alert
    from here — the Phase-9 task owns that wiring.
    """
    if transition.to_state == "down":
        kind = "health_down"
        severity = "crit"
    elif transition.to_state == "up":
        kind = "health_up"
        severity = "info"
    else:
        return  # not an operator-facing edge
    ev = Event(
        chr_id=transition.chr_id,
        ts=transition.at,
        kind=kind,
        severity=severity,
    )
    ev.detail = {
        "node_name": node_name,
        "from_state": transition.from_state,
        "to_state": transition.to_state,
        "latency_ms": latency_ms,
        "at": transition.at.isoformat() + "Z",
    }
    db.session.add(ev)
    _notify_hook(ev)


def _notify_hook(event: Event) -> None:
    """Fan a health transition out to BOTH downstream consumers (union of P8+P9).

    * **Phase 9 notifier** (``fleet.notify.notifier.dispatch_event``) — runs the
      alert rule matrix; disabled kinds / unconfigured channels are a no-op.
    * **Phase 8 orchestrator** (``fleet.brain.rebalance.on_monitor_event``) — a
      ``health_down`` event auto-invokes the rebalance orchestrator, which records
      a forced-evacuation plan (advisory when ``live_apply_enabled`` is OFF; the
      proxy enforces it via CoA when ON). Other kinds are ignored by it.

    Each consumer is wrapped in its own try/except so neither can break the probe
    loop — the monitor MUST keep recording metrics regardless. Dropping either
    would silently disable notifications or auto-failover.
    """
    try:
        from fleet.notify.notifier import dispatch_event
        dispatch_event(event)
    except Exception:  # never let alerting break the health cycle
        logger.exception("fleet.notify dispatch failed for kind=%s", event.kind)
    logger.debug(
        "fleet.health: event %s for chr_id=%s fanned out to notifier + orchestrator",
        event.kind, event.chr_id,
    )
    try:
        from fleet.brain.rebalance import on_monitor_event as _on_monitor_event
        _on_monitor_event(event)
    except Exception:  # noqa: BLE001 — sensor must never crash on the hook
        logger.exception(
            "fleet.health: orchestrator hook raised for event %s/chr_id=%s",
            event.kind, event.chr_id,
        )


def _denormalize_node_status(node: FleetChrNode, transition: Transition, now: datetime) -> None:
    """Mirror the new state onto the denormalised ``fleet_chr_nodes`` snapshot.

    The brain reads ``fleet_chr_nodes.status`` for fast eligibility checks
    (its hot index ``idx_fleet_chr_status``). We keep that in sync with
    ``fleet_chr_health.state`` so the brain never has to JOIN. The check
    constraint on ``status`` accepts our values.

    Operator-set states are protected: ``disabled`` is never overwritten
    by a probe (the operator turned the node off — health probes do not
    re-enable it). ``drain`` is independent (separate boolean column)
    and is left alone here.
    """
    if node.status == "disabled":
        # Operator has the node off; the monitor does not flip it back on.
        if transition.to_state == "up":
            node.last_ping_ok_at = now
        return
    if transition.to_state == "up":
        node.status = "up"
        node.last_ping_ok_at = now
    elif transition.to_state == "down":
        node.status = "down"


def _reconcile_node_status(node: FleetChrNode, health: "FleetChrHealth", *, ok_now: bool, now: datetime) -> None:
    """Make ``node.status`` consistent with ``health.state`` on EVERY probe.

    Without this reconcile, a node can get stuck in ``provisioning``
    forever: ``_denormalize_node_status`` only fires on a *new*
    transition, so once ``health.state`` is already ``up`` (e.g. from a
    prior pass) the node's registry status is never touched again. This
    was the live regression — wg-mgmt handshake, ICMP, and health all
    showed up; the dashboard kept saying ``provisioning``; the
    routing-table publisher treated the row inconsistently.

    Rules (each protects an operator intent):

    * ``disabled``      — never overwritten. The operator turned the
                          node off; a successful probe does not turn it
                          back on. ``last_ping_ok_at`` is still bumped
                          so the dashboard shows liveness.
    * ``up`` health     — promote ``provisioning``/``down``/empty
                          registry status to ``up``. This is the
                          headline promotion: a CHR whose wg-mgmt is
                          live AND ICMP is replying AND hysteresis says
                          up MUST be ``status='up'`` so the routing
                          table publishes it and the brain ranks it.
    * ``down`` health   — registry follows. Already covered by
                          ``_denormalize_node_status`` on the
                          transition; this is the no-transition tail
                          (consecutive down probes after the initial
                          flip) where we keep the snapshot in sync.
    * ``unknown``       — leave registry alone. ``provisioning`` stays
                          ``provisioning`` until the FIRST verified up.
    * ``degraded``      — leave registry as ``up`` (degraded is a
                          shedding state, not an outage) unless the
                          operator explicitly set something else.
    """
    if node.status == "disabled":
        if ok_now:
            node.last_ping_ok_at = now
        return
    state = (health.state or "unknown")
    if state == "up":
        # Promote provisioning / down / empty / mismatched-up to up.
        if node.status != "up":
            node.status = "up"
        if ok_now:
            node.last_ping_ok_at = now
    elif state == "down":
        if node.status != "down":
            node.status = "down"
    # state in {"unknown", "degraded"} → don't touch node.status.
    # An unknown health is the "we don't know yet" state; a provisioning
    # node must stay provisioning until verified up at least once.


# ════════════════════════════════════════════════════════════════════════
# Public entry-points
# ════════════════════════════════════════════════════════════════════════


def _default_pinger() -> Pinger:
    """ICMP over wg-mgmt is the documented control-plane liveness check
    — see :class:`IcmpPinger` for the rationale. The TCP pinger is still
    importable for callers that want to test a specific TCP port."""
    return IcmpPinger()


def run_once(
    *,
    pinger: Pinger | None = None,
    now: datetime | None = None,
    cfg: HealthConfig | None = None,
) -> RunSummary:
    """Probe EVERY enabled node once. Idempotent, cron-friendly.

    Returns a :class:`RunSummary` so callers (the CLI, a test, a future
    scheduler) can react without re-querying the DB. The function commits
    once at the end so a crash mid-loop leaves the DB unchanged.

    Parameters
    ----------
    pinger
        Pluggable probe transport. Defaults to :class:`TcpConnectPinger`.
        Tests inject a deterministic fake.
    now
        Override the wall clock — used by the test suite to simulate the
        5-minute hysteresis window without sleeping. Defaults to
        :func:`app.models.utcnow`.
    cfg
        Override the health tunables. Defaults to ``FLEET.health``.
    """
    return _run(
        nodes=list(_enabled_nodes()),
        pinger=pinger or _default_pinger(),
        now=now or utcnow(),
        cfg=cfg or FLEET.health,
    )


def check_now(
    node_id: int | None = None,
    *,
    pinger: Pinger | None = None,
    now: datetime | None = None,
    cfg: HealthConfig | None = None,
) -> RunSummary:
    """On-demand health check.

    With ``node_id=None`` this is equivalent to :func:`run_once` — handy
    for the future "Health · Probe everything now" admin button.

    With a specific ``node_id`` it probes that one node, even if its
    ``enabled`` flag is False (operators sometimes want to test a
    disabled/draining node before re-enabling it).
    """
    if node_id is None:
        return run_once(pinger=pinger, now=now, cfg=cfg)
    node = db.session.get(FleetChrNode, node_id)
    if node is None:
        return RunSummary(
            started_at=now or utcnow(), finished_at=now or utcnow(),
            checked=0, ok_count=0, fail_count=0,
            transitions=(), outcomes=(),
        )
    return _run(
        nodes=[node],
        pinger=pinger or _default_pinger(),
        now=now or utcnow(),
        cfg=cfg or FLEET.health,
    )


# ════════════════════════════════════════════════════════════════════════
# Internal driver
# ════════════════════════════════════════════════════════════════════════


def _enabled_nodes() -> Iterable[FleetChrNode]:
    return (
        db.session.query(FleetChrNode)
        .filter(FleetChrNode.enabled.is_(True))
        .order_by(FleetChrNode.id.asc())
        .all()
    )


def _run(
    *,
    nodes: list[FleetChrNode],
    pinger: Pinger,
    now: datetime,
    cfg: HealthConfig,
) -> RunSummary:
    started = now
    outcomes: list[NodeOutcome] = []
    transitions: list[Transition] = []
    ok_count = 0
    fail_count = 0

    for node in nodes:
        target = _resolve_target(node)
        result = _safe_ping(pinger, target)
        ok_count += int(bool(result.ok))
        fail_count += int(not result.ok)

        # 1. Capture the metric BEFORE we mutate health (so the recovery
        # window calculation uses the pre-existing failure record).
        last_fail = (
            _last_fail_ts(target.chr_id, before=now)
            if not result.ok or _is_currently_down(target.chr_id)
            else None
        )
        _persist_metric(target.chr_id, ok=result.ok, latency_ms=result.latency_ms, now=now)

        # 2. Update / create the rolling health row.
        health = _get_or_create_health(target.chr_id, now)
        transition = evaluate_transition(
            health,
            ping_ok=result.ok,
            now=now,
            last_fail_ts=last_fail,
            cfg=cfg,
        )

        # 3. On a real transition, mirror onto the node snapshot + log an event.
        if transition is not None:
            transitions.append(transition)
            _denormalize_node_status(node, transition, now)
            _emit_event(transition, node_name=target.name, latency_ms=result.latency_ms)

        # 3b. ALWAYS reconcile the registry snapshot with the rolling
        # health row — even when no transition fired. Without this, a
        # node whose health was already ``up`` (from a prior pass) but
        # whose ``fleet_chr_nodes.status`` is still ``provisioning``
        # never gets promoted, and the dashboard / routing-table
        # publisher / brain ranking all see the stale value. The
        # reconciler respects operator intent (``disabled`` is never
        # overwritten; ``drain`` is a separate column and untouched).
        _reconcile_node_status(node, health, ok_now=bool(result.ok), now=now)

        outcomes.append(NodeOutcome(
            chr_id=target.chr_id,
            name=target.name,
            ok=result.ok,
            latency_ms=result.latency_ms,
            state=health.state,
            transition=transition,
        ))

    db.session.commit()
    return RunSummary(
        started_at=started,
        finished_at=now,
        checked=len(nodes),
        ok_count=ok_count,
        fail_count=fail_count,
        transitions=tuple(transitions),
        outcomes=tuple(outcomes),
    )


def _is_currently_down(chr_id: int) -> bool:
    row = db.session.get(FleetChrHealth, chr_id)
    return bool(row is not None and row.state == "down")


def state_for_chr(chr_id: int) -> str | None:
    """Authoritative hysteresis state for a node id.

    Returns one of ``'unknown' | 'up' | 'degraded' | 'down'`` (FleetChrHealth.state),
    or ``None`` if no health row exists yet (node never probed).
    """
    row = db.session.get(FleetChrHealth, chr_id)
    return row.state if row is not None else None


def state_of(name: str) -> str | None:
    """Authoritative hysteresis state for the node named ``name``.

    ``name`` is the registry node name that telemetry/placement key by. This is
    the public seam other modules (e.g. telemetry ingest) read so the monitor's
    flap-damped state is the single source of truth for up/down. Returns the
    state string, or ``None`` if the node or its health row does not exist yet
    (callers should fall back to their own best-effort signal).
    """
    node = FleetChrNode.query.filter_by(name=name).one_or_none()
    if node is None:
        return None
    return state_for_chr(node.id)


def _safe_ping(pinger: Pinger, target: PingTarget) -> PingResult:
    """Pinger faults are treated as a failed probe, never a service crash.

    A buggy custom pinger should not take the whole monitor pass down.
    The exception is logged once with the chr_id so the operator can
    chase it; the metric is recorded as a fail so hysteresis still
    progresses correctly.
    """
    try:
        return pinger.ping(target)
    except Exception:  # noqa: BLE001 — pinger-agnostic safety net
        logger.exception(
            "fleet.health: pinger raised for chr_id=%s — treating as fail",
            target.chr_id,
        )
        return PingResult(ok=False, error="pinger_exception")


# ════════════════════════════════════════════════════════════════════════
# CLI entry-point — `python -m fleet.health.monitor`
# ════════════════════════════════════════════════════════════════════════


def _cli(argv: list[str] | None = None) -> int:
    """Run a single monitor pass under a real Flask app context.

    Wired through ``__main__.py`` so cron / systemd can simply call
    ``python -m fleet.health.monitor``. Idempotent: each invocation is
    one full pass; running it twice in a row is safe and adds two
    metric rows per node.

    Exit code is 0 on success. A crash inside the pass propagates up so
    cron's mail-on-error path triggers — we deliberately do not swallow
    fatal exceptions here.
    """
    import argparse

    parser = argparse.ArgumentParser(
        prog="python -m fleet.health.monitor",
        description="CHR fleet ping-based health monitor — one pass and exit.",
    )
    parser.add_argument(
        "--node-id", type=int, default=None,
        help="Probe a single node by id (default: every enabled node).",
    )
    parser.add_argument(
        "--quiet", action="store_true",
        help="Suppress the per-node summary; print only the totals line.",
    )
    args = parser.parse_args(argv)

    # Build the app on demand so the CLI works regardless of how the
    # process was started (cron, systemd, a developer shell).
    from app import create_app  # local import — avoid a Flask import at module load
    app = create_app()
    with app.app_context():
        summary = check_now(node_id=args.node_id) if args.node_id else run_once()

    if not args.quiet:
        for o in summary.outcomes:
            status = "OK " if o.ok else "FAIL"
            rtt = f"{o.latency_ms:.1f}ms" if o.latency_ms is not None else "—"
            trans = (
                f"  TRANSITION {o.transition.from_state}->{o.transition.to_state}"
                if o.transition is not None else ""
            )
            print(f"[{status}] #{o.chr_id} {o.name:<24} {rtt:<10} state={o.state}{trans}")
    print(
        f"fleet.health.monitor: checked={summary.checked} "
        f"ok={summary.ok_count} fail={summary.fail_count} "
        f"transitions={len(summary.transitions)}"
    )
    return 0


__all__ = [
    "Pinger",
    "PingResult",
    "PingTarget",
    "IcmpPinger",
    "TcpConnectPinger",
    "Transition",
    "NodeOutcome",
    "RunSummary",
    "evaluate_transition",
    "run_once",
    "check_now",
    "state_of",
    "state_for_chr",
]


if __name__ == "__main__":  # pragma: no cover - exercised via python -m
    raise SystemExit(_cli())
