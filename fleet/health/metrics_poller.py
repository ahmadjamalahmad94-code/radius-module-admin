"""fleet.health.metrics_poller — RouterOS control-plane metrics poller.

The panel reaches every onboarded CHR over its wg-mgmt control tunnel.
This module turns that connectivity into a steady stream of
``fleet_chr_metrics`` rows with ``source='control'`` so the dashboard
can render real CPU, active sessions, RX/TX bandwidth + the brain can
score nodes against live load.

Two callers:

* :func:`poll_all` — one synchronous pass over every eligible node.
  Idempotent and crash-proof; tests + the on-demand «اقرأ القياسات
  الآن» button both call this directly.
* :func:`start_background_poller` — wired into the app start-up hook
  in :mod:`app._fleet_workers`. Spawns ONE daemon thread that loops
  :func:`poll_all` every ``cfg.metrics_interval_s`` (default 60s).
  Refuses to start a second one in the same process.

Eligibility: a node is polled when ``enabled=True`` AND ``drain=False``
AND ``credentials_for(node)`` returns non-None. ``status='down'`` is
NOT a gate (data-plane vs control-plane principle — see the routing-
table fix). A node whose api-ssl isn't reachable gets one polled
attempt per cycle that returns ``error='connect_failed'``; the worker
records that and moves on.
"""
from __future__ import annotations

import dataclasses
import logging
import threading
import time
from datetime import datetime
from typing import Callable, Iterable

from app.extensions import db
from app.models import utcnow

from fleet.health.models_health import FleetChrMetric
from fleet.health.routeros_collector import Sample, collect
from fleet.health.routeros_creds import credentials_for
from fleet.registry.models_chr import FleetChrNode


logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════════
# Config
# ════════════════════════════════════════════════════════════════════════

#: Setting key for the poll interval (seconds). Falls back to the default
#: below. Re-read on every loop iteration so the operator can adjust
#: cadence without restarting the panel.
POLL_INTERVAL_SETTING = "fleet.metrics.poll_interval_s"

#: Hard default — 60s. A balance between dashboard freshness and putting
#: load on the CHR. The brain's scoring tick runs at ~30s; we stay under
#: 2× that so two consecutive scoring passes always have new data.
DEFAULT_POLL_INTERVAL_S = 60

#: How many samples a single thread writes per pass before it commits.
#: We batch so a 50-node fleet writes one COMMIT, not 50.
_COMMIT_BATCH = 50


# ════════════════════════════════════════════════════════════════════════
# Result shape
# ════════════════════════════════════════════════════════════════════════


@dataclasses.dataclass(frozen=True)
class PollSummary:
    """Per-pass outcome — used by tests + the on-demand button."""

    started_at: datetime
    finished_at: datetime
    checked: int
    ok_count: int
    skipped_count: int
    error_count: int
    errors: tuple[tuple[str, str], ...] = ()  # (node_name, error_code)


# ════════════════════════════════════════════════════════════════════════
# Synchronous pass — the single source of truth for "poll the fleet"
# ════════════════════════════════════════════════════════════════════════


def poll_all(
    *,
    collector: Callable[[FleetChrNode], Sample] | None = None,
    now: datetime | None = None,
) -> PollSummary:
    """Run ONE pass over every eligible node.

    ``collector`` is the test seam: production code passes ``None`` and
    the function calls :func:`fleet.health.routeros_collector.collect`
    directly. Tests pass a stub that returns scripted :class:`Sample`
    objects per node.

    Idempotent: each pass appends one ``fleet_chr_metrics`` row per
    successful poll. Re-running has no destructive effect.
    """
    started = now or utcnow()
    collector = collector or (lambda n: collect(n))
    summary_errors: list[tuple[str, str]] = []
    ok = 0
    skipped = 0
    err = 0
    pending: list[FleetChrMetric] = []

    nodes = _eligible_nodes()
    for node in nodes:
        if credentials_for(node) is None:
            skipped += 1
            continue
        try:
            sample = collector(node)
        except Exception as exc:  # noqa: BLE001 — defensive: must not crash a pass
            logger.exception("metrics_poller: collector raised on %s", node.name)
            err += 1
            summary_errors.append((node.name, exc.__class__.__name__))
            continue

        if not sample.ok:
            err += 1
            summary_errors.append((node.name, sample.error or "unknown"))
            # Still record an empty metric row so the dashboard sees we
            # tried — operator can see "polled, all None" instead of
            # nothing at all. We tag source='control' so it still
            # routes through the same path.
            pending.append(_to_metric(node.id, sample, ts=started))
            continue

        ok += 1
        pending.append(_to_metric(node.id, sample, ts=started))

        if len(pending) >= _COMMIT_BATCH:
            _flush(pending)
            pending = []

    if pending:
        _flush(pending)

    finished = utcnow()
    return PollSummary(
        started_at=started, finished_at=finished,
        checked=len(nodes), ok_count=ok,
        skipped_count=skipped, error_count=err,
        errors=tuple(summary_errors),
    )


def _eligible_nodes() -> list[FleetChrNode]:
    return (
        FleetChrNode.query
        .filter(FleetChrNode.enabled.is_(True))
        .filter(FleetChrNode.drain.is_(False))
        .order_by(FleetChrNode.id.asc())
        .all()
    )


def _to_metric(chr_id: int, sample: Sample, *, ts: datetime) -> FleetChrMetric:
    return FleetChrMetric(
        chr_id=chr_id, ts=ts,
        cpu_pct=sample.cpu_pct,
        mem_pct=sample.mem_pct,
        active_sessions=sample.active_sessions,
        rx_bytes=sample.rx_bytes,
        tx_bytes=sample.tx_bytes,
        ping_rtt_ms=None,            # this is the control-plane path
        ping_loss_pct=None,          # ICMP loss lives in the monitor's source='ping'
        source="control",
    )


def _flush(rows: Iterable[FleetChrMetric]) -> None:
    db.session.add_all(list(rows))
    try:
        db.session.commit()
    except Exception:  # noqa: BLE001 — defensive
        db.session.rollback()
        logger.exception("metrics_poller: commit failed")


# ════════════════════════════════════════════════════════════════════════
# Background worker — one daemon thread per process
# ════════════════════════════════════════════════════════════════════════


_worker_lock = threading.Lock()
_worker_thread: threading.Thread | None = None
_worker_stop = threading.Event()


def start_background_poller(app) -> bool:
    """Start the background poller thread. Returns True iff a NEW
    thread was launched (False if one already runs OR config disables it).

    The poller is opt-in via ``FLEET_METRICS_POLLER_ENABLED`` (default
    True in production, False in TESTING / when ``AUTO_INIT_DB`` is off
    so unit tests + CLI commands aren't surprised by a background
    thread).
    """
    global _worker_thread
    cfg = app.config
    if cfg.get("TESTING"):
        return False
    if not cfg.get("FLEET_METRICS_POLLER_ENABLED", True):
        return False

    with _worker_lock:
        if _worker_thread is not None and _worker_thread.is_alive():
            return False
        _worker_stop.clear()

        def _loop():
            logger.info("fleet.metrics_poller: background worker started")
            while not _worker_stop.is_set():
                interval = _resolve_interval(app)
                try:
                    with app.app_context():
                        poll_all()
                except Exception:  # noqa: BLE001 — never exit on a bad pass
                    logger.exception("metrics_poller: pass raised; will retry")
                # ``wait`` honours an Event signal, so a process-shutdown
                # request wakes the thread immediately.
                _worker_stop.wait(timeout=max(5, interval))
            logger.info("fleet.metrics_poller: background worker stopped")

        thread = threading.Thread(
            target=_loop, name="fleet-metrics-poller", daemon=True,
        )
        thread.start()
        _worker_thread = thread
        return True


def stop_background_poller(*, join_timeout: float = 5.0) -> None:
    """Cooperative stop — used by tests + graceful shutdown handlers."""
    global _worker_thread
    with _worker_lock:
        _worker_stop.set()
        t = _worker_thread
    if t is not None:
        t.join(timeout=join_timeout)
    with _worker_lock:
        _worker_thread = None


def _resolve_interval(app) -> int:
    """Per-cycle interval lookup. Setting row wins over app config wins
    over the documented default."""
    try:
        from app.models import Setting
        row = db.session.get(Setting, POLL_INTERVAL_SETTING)
        if row and (row.value or "").strip().isdigit():
            return max(5, int(row.value))
    except Exception:  # noqa: BLE001 — never crash the loop on a settings read
        pass
    return int(app.config.get("FLEET_METRICS_POLL_INTERVAL_S",
                              DEFAULT_POLL_INTERVAL_S))


__all__ = [
    "POLL_INTERVAL_SETTING",
    "DEFAULT_POLL_INTERVAL_S",
    "PollSummary",
    "poll_all",
    "start_background_poller",
    "stop_background_poller",
]
