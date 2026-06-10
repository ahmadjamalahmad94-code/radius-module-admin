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
import socket
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

    ``host`` is the panel's preferred reach (``public_ip``; the
    ``wg_mgmt_ip`` is used as a fallback when public IP is blank).
    ``port`` is the RouterOS control endpoint (``routeros_api_port``).
    A pinger MAY ignore the port (e.g. an ICMP pinger), but the TCP
    pinger uses it as its connect target — a successful TCP handshake to
    the api-ssl port is a strong "node is reachable AND its control plane
    is alive" signal in one probe.
    """

    chr_id: int
    name: str
    host: str
    port: int = 8729           # RouterOS api-ssl default; see fleet_chr_nodes.routeros_api_port


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
    """Default probe: TCP connect to ``target.host:target.port``.

    Chosen over raw-ICMP because:

    * It requires no privileged sockets (works as a normal user / inside
      a Docker container / on Windows where ICMP needs admin).
    * A successful handshake to the RouterOS api-ssl port confirms both
      reachability AND that the control plane is up (ICMP can succeed
      while RouterOS is wedged).
    * "ICMP or TCP-connect" is explicitly allowed by the Phase-4 spec.

    The connect socket is closed in a ``finally`` block so a failed probe
    never leaks a half-open fd.
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
    """Pick the best reach for a node — public IP first, mgmt IP as fallback."""
    host = (node.public_ip or "").strip() or (node.wg_mgmt_ip or "").strip()
    return PingTarget(
        chr_id=int(node.id),
        name=node.name or "",
        host=host,
        port=int(node.routeros_api_port or 8729),
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
    """Hand ``event`` to the Phase-9 alert rule matrix.

    The notifier is best-effort: never raises, never blocks the health
    cycle. Disabled kinds and unconfigured channels are a no-op.
    """
    try:
        from fleet.notify.notifier import dispatch_event
        dispatch_event(event)
    except Exception:  # never let alerting break the health cycle
        logger.exception("fleet.notify dispatch failed for kind=%s", event.kind)
    logger.debug(
        "fleet.health: event %s for chr_id=%s queued for future notifier",
        event.kind, event.chr_id,
    )


def _denormalize_node_status(node: FleetChrNode, transition: Transition, now: datetime) -> None:
    """Mirror the new state onto the denormalised ``fleet_chr_nodes`` snapshot.

    The brain reads ``fleet_chr_nodes.status`` for fast eligibility checks
    (its hot index ``idx_fleet_chr_status``). We keep that in sync with
    ``fleet_chr_health.state`` so the brain never has to JOIN. The check
    constraint on ``status`` accepts our values.
    """
    if transition.to_state == "up":
        node.status = "up"
        node.last_ping_ok_at = now
    elif transition.to_state == "down":
        node.status = "down"


# ════════════════════════════════════════════════════════════════════════
# Public entry-points
# ════════════════════════════════════════════════════════════════════════


def _default_pinger() -> Pinger:
    return TcpConnectPinger()


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
