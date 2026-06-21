"""Monthly sweep for the «full IP change» service (licensing side).

On a schedule (or via a hook the scheduler calls) this:
  * marks IP-change entitlements EXPIRED when their monthly term ends, and
  * EMITS an expiry event into the fleet notification backbone (``fleet_events``)
    so the notifier/customer side can revert + warn;
  * exposes a queryable 7/3/1-day COUNTDOWN the notification backbone consumes.

The expiry date + state live on ``CustomerVpnEntitlement`` (expires_at/status),
so they're directly queryable; this module adds the term-end transition + the
event emission + the countdown query. The actual customer-side revert and the
reminder messages are owned elsewhere (this just makes the signal available).
"""
from __future__ import annotations

import threading
from typing import Optional

from ..extensions import db
from ..models import CustomerVpnEntitlement, utcnow

import logging

logger = logging.getLogger("ip_change.sweep")

#: Default countdown thresholds (days before expiry) the notifier reminds on.
COUNTDOWN_THRESHOLDS = (7, 3, 1)

EVENT_EXPIRED = "ip_change_expired"
EVENT_EXPIRING = "ip_change_expiring"


# ── event emission (fleet notification backbone) ─────────────────────────────
def _emit_event(kind: str, severity: str, detail: dict, *, chr_id: Optional[int] = None) -> None:
    """Append a row to the fleet event log (the notifier consumes these). Never
    raises — a telemetry failure must not abort the sweep."""
    try:
        from fleet.notify.models_alert import Event
        ev = Event(kind=kind, severity=severity if severity in ("info", "warn", "crit") else "info",
                   chr_id=chr_id)
        ev.detail = detail or {}
        db.session.add(ev)
    except Exception:  # noqa: BLE001
        logger.exception("ip_change.sweep: failed to emit %s", kind)


def _assigned_server_ip(customer_id: int) -> str:
    """The customer's current SSTP egress (assigned CHR public IP), if any."""
    try:
        from ..models import CustomerVpnTunnel
        t = (CustomerVpnTunnel.query
             .filter_by(customer_id=customer_id, tunnel_type="sstp")
             .filter(CustomerVpnTunnel.status == "active")
             .order_by(CustomerVpnTunnel.id.desc())
             .first())
        if t is not None and t.fleet_chr_node is not None:
            return t.fleet_chr_node.public_ip or ""
    except Exception:  # noqa: BLE001
        return ""
    return ""


def _days_left(expires_at, now) -> int:
    return int((expires_at - now).total_seconds() // 86400)


# ── the sweep (the schedulable hook) ─────────────────────────────────────────
def sweep_expired_ip_change(*, commit: bool = True) -> dict:
    """Mark every past-term IP-change entitlement EXPIRED and emit an
    ``ip_change_expired`` event for each newly-expired one. Idempotent: an
    already-expired entitlement is skipped (so re-running doesn't re-emit).
    Returns ``{"expired": [customer_id, …], "count": N}``.
    """
    now = utcnow()
    due = (CustomerVpnEntitlement.query
           .filter(CustomerVpnEntitlement.expires_at.isnot(None))
           .filter(CustomerVpnEntitlement.expires_at < now)
           .filter(CustomerVpnEntitlement.status != "expired")
           .all())
    expired_ids: list[int] = []
    for ent in due:
        ent.status = "expired"
        ent.enabled = False
        db.session.add(ent)
        _emit_event(EVENT_EXPIRED, "warn", {
            "customer_id": ent.customer_id,
            "expires_at": ent.expires_at.replace(microsecond=0).isoformat() + "Z",
            "server_ip": _assigned_server_ip(ent.customer_id),
            "reason": "monthly_term_ended",
        }, chr_id=None)
        expired_ids.append(ent.customer_id)
    if commit and expired_ids:
        db.session.commit()
    elif not commit:
        db.session.flush()
    if expired_ids:
        logger.info("ip_change.sweep: expired %d entitlement(s): %s", len(expired_ids), expired_ids)
    return {"expired": expired_ids, "count": len(expired_ids)}


# ── countdown (queryable + optionally emitted) ───────────────────────────────
def ip_change_countdown(thresholds=COUNTDOWN_THRESHOLDS, *, emit: bool = False) -> list[dict]:
    """Active IP-change entitlements approaching expiry, oldest-first. Returns
    ``[{customer_id, expires_at, days_left, server_ip}, …]`` for entitlements
    expiring within ``max(thresholds)`` days — the 7/3/1-day reminder source the
    notification backbone consumes. When ``emit`` is set, also drops an
    ``ip_change_expiring`` event for each one whose ``days_left`` hits a threshold.
    """
    now = utcnow()
    horizon = max(thresholds) if thresholds else 7
    rows = (CustomerVpnEntitlement.query
            .filter(CustomerVpnEntitlement.expires_at.isnot(None))
            .filter(CustomerVpnEntitlement.status == "active")
            .order_by(CustomerVpnEntitlement.expires_at.asc())
            .all())
    out: list[dict] = []
    for ent in rows:
        dleft = _days_left(ent.expires_at, now)
        if dleft < 0 or dleft > horizon:
            continue
        item = {
            "customer_id": ent.customer_id,
            "expires_at": ent.expires_at.replace(microsecond=0).isoformat() + "Z",
            "days_left": dleft,
            "server_ip": _assigned_server_ip(ent.customer_id),
        }
        out.append(item)
        if emit and dleft in tuple(thresholds):
            _emit_event(EVENT_EXPIRING, "info" if dleft > 1 else "warn",
                        {**item, "threshold": dleft})
    if emit:
        db.session.commit()
    return out


# ── background worker (mirrors fleet.health.metrics_poller) ──────────────────
_thread: Optional[threading.Thread] = None
_lock = threading.Lock()
_stop = threading.Event()


def start_background_sweep(app) -> bool:
    """Start the daily IP-change expiry sweep thread. Opt-in via
    ``IP_CHANGE_SWEEP_ENABLED`` (default True in prod, off in TESTING). Returns
    True iff a NEW thread launched."""
    global _thread
    cfg = app.config
    if cfg.get("TESTING"):
        return False
    if not cfg.get("IP_CHANGE_SWEEP_ENABLED", True):
        return False
    with _lock:
        if _thread is not None and _thread.is_alive():
            return False
        _stop.clear()
        interval = int(cfg.get("IP_CHANGE_SWEEP_INTERVAL_S", 3600))  # hourly

        def _loop():
            logger.info("ip_change.sweep: background worker started")
            while not _stop.is_set():
                try:
                    with app.app_context():
                        sweep_expired_ip_change()
                        ip_change_countdown(emit=True)
                except Exception:  # noqa: BLE001 — never exit on a bad pass
                    logger.exception("ip_change.sweep: pass raised; will retry")
                _stop.wait(timeout=max(60, interval))
            logger.info("ip_change.sweep: background worker stopped")

        t = threading.Thread(target=_loop, name="ip-change-sweep", daemon=True)
        t.start()
        _thread = t
        return True


def stop_background_sweep(*, join_timeout: float = 5.0) -> None:
    """Cooperative stop (tests + graceful shutdown)."""
    global _thread
    with _lock:
        _stop.set()
        t = _thread
    if t is not None:
        t.join(timeout=join_timeout)
    with _lock:
        _thread = None


__all__ = [
    "COUNTDOWN_THRESHOLDS", "EVENT_EXPIRED", "EVENT_EXPIRING",
    "sweep_expired_ip_change", "ip_change_countdown",
    "start_background_sweep", "stop_background_sweep",
]
