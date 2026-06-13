"""fleet.sync.wg_mgmt_autosync — periodic panel-host wg-mgmt self-healer.

The control-plane key-and-peer state on the panel host has to stay in
lock-step with the panel's Setting rows + every CHR's stored pubkey
forever, not just at script-render time. Without this poller a key
rotation on the panel host (e.g. someone re-ran ``wg genkey``) or a
peer that was removed by hand silently drifts the panel into the
chr-vpn-1 / chr-vpn-2 failure class:

  * stored ``Setting fleet.infra.PANEL_WG_PUBKEY`` ≠ live ``wg show
    wg-mgmt public-key`` ⇒ every NEW CHR script trusts a key the panel
    no longer presents ⇒ permanent wg-mgmt handshake failure;
  * a node that exists in the panel DB but whose wg-mgmt peer is
    missing on the control host ⇒ the CHR dials in, the server rejects
    the unknown pubkey, no handshake ⇒ REST forever unreachable.

This module IS the control-plane equivalent of what the proxy already
does for the data-plane:

  * proxy publishes its live wg-data pubkey in every heartbeat → the
    panel's ``_adopt_proxy_wg_pubkey_from_heartbeat`` adopts it on
    drift (see app/api/proxy_api.py), so every NEW CHR script trusts
    the live proxy key automatically.
  * proxy reconciles its wg-data peers periodically by polling
    ``GET /api/proxy/wg-peers``.

Both control-plane halves of that contract now live here:

  1. ``tick()`` reads the LIVE panel pubkey via the wg sudo-helper
     and adopts it into ``Setting fleet.infra.PANEL_WG_PUBKEY`` when
     it differs from the stored value. Affected nodes get
     ``needs_reimport=True`` so the troubleshoot page shows the
     known-stale state and the operator knows to re-import the
     script the panel will now render with the corrected key.
  2. ``tick()`` calls ``reconcile_panel_host()`` so any peer that
     should exist on the control host is ``wg set ... peer`` + saved
     to ``/etc/wireguard/wg-mgmt.conf``. A peer that was removed by
     hand reappears within ONE interval.

Safe by default everywhere:

  * The wg sudo-helper is absent on dev / CI / a host that hasn't run
    ``install_wg_helper.sh`` yet — ``tick()`` logs ONE INFO line per
    pass and returns a no-op summary. No crashes, no DB writes.
  * Any failure inside a pass is caught, logged, and the next pass
    runs as normal. The poller never dies on a bad tick.
  * Opt-in via ``PANEL_WG_AUTOSYNC_ENABLED`` (default ON in prod, OFF
    in tests + TESTING). Interval lives at ``PANEL_WG_AUTOSYNC_INTERVAL``
    (default ``DEFAULT_AUTOSYNC_INTERVAL_S`` seconds).
"""
from __future__ import annotations

import dataclasses
import logging
import threading
from datetime import datetime

from app.extensions import db
from app.models import utcnow


logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════════
# Config
# ════════════════════════════════════════════════════════════════════════

#: Setting key for the autosync interval (seconds). Setting row beats
#: the app-config default so the operator can adjust cadence without
#: restarting the panel.
AUTOSYNC_INTERVAL_SETTING = "fleet.wg_autosync.interval_s"

#: Hard default — 120 seconds. Doubled vs metrics_poller because the
#: control-plane state changes orders of magnitude less often (a key
#: rotation is a rare event; a peer add happens on operator action)
#: AND because the helper invocation is privileged: we don't want to
#: hammer ``sudo`` more than necessary. Two minutes still detects
#: drift well within the operator's mental "did it self-heal yet?"
#: window.
DEFAULT_AUTOSYNC_INTERVAL_S = 120

#: Audit action name for an auto-adoption of a drifted live pubkey.
AUDIT_ACTION_PUBKEY_AUTO_CORRECTED = "panel_wg_pubkey_auto_corrected"


# ════════════════════════════════════════════════════════════════════════
# Result shape
# ════════════════════════════════════════════════════════════════════════


@dataclasses.dataclass(frozen=True)
class AutosyncSummary:
    """Per-pass outcome — used by tests + a future admin-button trigger."""

    started_at: datetime
    finished_at: datetime
    helper_available: bool
    pubkey_checked: bool
    pubkey_adopted: bool
    pubkey_old: str = ""
    pubkey_new: str = ""
    nodes_marked_stale: int = 0
    reconcile_attempted: bool = False
    reconcile_applied: bool = False
    reconcile_desired_count: int = 0
    reconcile_message: str = ""
    error: str = ""


# ════════════════════════════════════════════════════════════════════════
# Synchronous pass — the single source of truth for "self-heal once"
# ════════════════════════════════════════════════════════════════════════


def tick(*, now: datetime | None = None) -> AutosyncSummary:
    """Run ONE pass of the autosync.

    Steps:
      1. Helper-availability probe — bail with a clean no-op when the
         wg sudo-helper isn't installed (dev / CI / pre-install host).
      2. Read the live panel wg-mgmt public key. If it differs from
         the Setting row, adopt the live value + audit + flag every
         eligible CHR node with ``needs_reimport=True`` so the
         troubleshoot page reflects the now-known-stale on-CHR copy.
      3. Reconcile peers via ``reconcile_panel_host()``: every
         eligible node's wg-mgmt peer is ensured on the control host
         AND persisted to /etc/wireguard/wg-mgmt.conf (idempotent).

    Returns the :class:`AutosyncSummary` for callers (tests + the
    background loop's structured log line).

    Never raises — any internal failure is caught and recorded in
    ``summary.error`` so the background loop can keep ticking.
    """
    started = now or utcnow()

    try:
        from fleet.sync.wg_apply import (
            helper_installed,
            read_live_panel_pubkey,
        )
        from fleet.sync.service import reconcile_panel_host
    except Exception as exc:  # noqa: BLE001 — branch w/o fleet.sync
        return AutosyncSummary(
            started_at=started, finished_at=utcnow(),
            helper_available=False, pubkey_checked=False,
            pubkey_adopted=False,
            error=f"import_failed: {exc.__class__.__name__}",
        )

    if not helper_installed():
        logger.info(
            "fleet.wg_mgmt_autosync: wg sudo-helper not installed — "
            "skipping pass (run deploy/zero_touch/install_wg_helper.sh "
            "on the panel host to enable auto-correct + auto-reconcile)"
        )
        return AutosyncSummary(
            started_at=started, finished_at=utcnow(),
            helper_available=False, pubkey_checked=False,
            pubkey_adopted=False,
        )

    pubkey_adopted = False
    pubkey_old = ""
    pubkey_new = ""
    nodes_marked = 0
    pubkey_checked = False

    # ── 1. Live-key adoption ──────────────────────────────────────────
    # ``pubkey_checked`` reflects "we attempted the read", set BEFORE
    # the call so a raise mid-read still records the attempt (the
    # adoption gate below decides what to do with a None result).
    pubkey_checked = True
    try:
        live = read_live_panel_pubkey()
    except Exception as exc:  # noqa: BLE001 — never crash the tick
        logger.warning(
            "fleet.wg_mgmt_autosync: live-key read raised (%s); "
            "skipping adoption this pass",
            exc.__class__.__name__,
        )
        live = None

    if live:
        try:
            adopted, old = _adopt_if_drifted(live)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "fleet.wg_mgmt_autosync: adoption raised (%s); "
                "keeping stored key for this pass",
                exc.__class__.__name__,
            )
            adopted = False
            old = ""
        if adopted:
            pubkey_adopted = True
            pubkey_old = old
            pubkey_new = live
            try:
                nodes_marked = _flag_affected_nodes_stale()
            except Exception:  # noqa: BLE001
                logger.exception(
                    "fleet.wg_mgmt_autosync: needs_reimport flag failed"
                )

    # ── 2. Peer reconcile (always, even when key is unchanged) ───────
    reconcile_attempted = False
    reconcile_applied = False
    reconcile_count = 0
    reconcile_msg = ""
    try:
        reconcile_attempted = True
        result = reconcile_panel_host()
        reconcile_applied = bool(result.get("applied"))
        reconcile_count = int(result.get("desired_count") or 0)
        reconcile_msg = str(result.get("message") or "")[:200]
    except Exception as exc:  # noqa: BLE001
        reconcile_msg = f"reconcile_raised: {exc.__class__.__name__}"
        logger.warning(
            "fleet.wg_mgmt_autosync: reconcile_panel_host raised (%s)",
            exc.__class__.__name__,
        )

    finished = utcnow()
    summary = AutosyncSummary(
        started_at=started, finished_at=finished,
        helper_available=True,
        pubkey_checked=pubkey_checked,
        pubkey_adopted=pubkey_adopted,
        pubkey_old=pubkey_old, pubkey_new=pubkey_new,
        nodes_marked_stale=nodes_marked,
        reconcile_attempted=reconcile_attempted,
        reconcile_applied=reconcile_applied,
        reconcile_desired_count=reconcile_count,
        reconcile_message=reconcile_msg,
    )

    # One structured INFO line per pass — easy to grep in journalctl.
    logger.info(
        "fleet.wg_mgmt_autosync: tick complete helper=%s pubkey_checked=%s "
        "pubkey_adopted=%s nodes_marked_stale=%s reconcile_applied=%s "
        "desired=%s",
        summary.helper_available,
        summary.pubkey_checked,
        summary.pubkey_adopted,
        summary.nodes_marked_stale,
        summary.reconcile_applied,
        summary.reconcile_desired_count,
    )
    return summary


def _adopt_if_drifted(live_key: str) -> tuple[bool, str]:
    """Adopt ``live_key`` into Setting fleet.infra.PANEL_WG_PUBKEY when
    it differs from the stored value. Returns (adopted, old_value).

    Same writer the manual UI uses (``set_panel_pubkey``) → identical
    validation, identical Setting row, identical readers. Plus an
    audit row so the rotation is visible in /admin/audit.
    """
    from fleet.registry.infra_settings import (
        panel_pubkey_for_display,
        set_panel_pubkey,
    )
    stored = (panel_pubkey_for_display() or "").strip()
    if stored == live_key:
        return (False, stored)

    # set_panel_pubkey validates the shape (44-char base64) and writes
    # the Setting row. We pass the value through the same gate as the
    # manual «حفظ المفتاح العام» button so a malformed live key (the
    # helper returns one of those only if RouterOS itself is broken)
    # can't poison the DB.
    set_panel_pubkey(live_key)

    # Audit — non-secret (wg PUBLIC keys are designed to be shared).
    # We write the AuditLog row DIRECTLY (not via app.auth.routes.audit)
    # because the poller runs in a background thread / outside any
    # request context, and the helper there reads ``session.get`` which
    # raises RuntimeError out-of-request. actor_admin_id=None is
    # explicitly nullable on the model.
    try:
        from app.models import AuditLog
        row = AuditLog(
            actor_admin_id=None,
            action=AUDIT_ACTION_PUBKEY_AUTO_CORRECTED,
            entity_type="fleet_infra",
            entity_id="PANEL_WG_PUBKEY",
            summary=(
                f"تصحيح ذاتي لمفتاح اللوحة العام (wg-mgmt) من المُلتقَط "
                f"الحيّ على المضيف: {(stored or '<unset>')} → {live_key}"
            ),
        )
        row.meta = {
            "source": "wg_mgmt_autosync",
            "old_pubkey": stored,
            "new_pubkey": live_key,
        }
        db.session.add(row)
        db.session.commit()
    except Exception:  # noqa: BLE001 — audit is best-effort
        db.session.rollback()

    logger.warning(
        "fleet.wg_mgmt_autosync: adopted live wg-mgmt pubkey "
        "old=%s… new=%s… (Setting fleet.infra.PANEL_WG_PUBKEY updated)",
        (stored[:8] if stored else "<unset>"),
        live_key[:8],
    )
    return (True, stored)


def _flag_affected_nodes_stale() -> int:
    """When the stored key changes, every CHR that has previously been
    rendered now carries a script trusting the OLD key. Flip
    ``needs_reimport=True`` on every fleet node that has at least one
    rendered script (proxied by ``control_wg_public_key_snapshot`` being
    non-empty, written by ``OnboardingService._build_bindings``). The
    troubleshoot page reads this flag.

    Returns the count of nodes flipped this pass.
    """
    from fleet.registry.models_chr import FleetChrNode
    rows = (
        FleetChrNode.query
        .filter(FleetChrNode.control_wg_public_key_snapshot != "")
        .filter(FleetChrNode.needs_reimport.is_(False))
        .all()
    )
    flipped = 0
    for n in rows:
        n.needs_reimport = True
        db.session.add(n)
        flipped += 1
    if flipped:
        try:
            db.session.commit()
        except Exception:  # noqa: BLE001
            db.session.rollback()
            return 0
    return flipped


# ════════════════════════════════════════════════════════════════════════
# Background worker — one daemon thread per process
# ════════════════════════════════════════════════════════════════════════


_worker_lock = threading.Lock()
_worker_thread: threading.Thread | None = None
_worker_stop = threading.Event()


def start_background_autosync(app) -> bool:
    """Start the background autosync thread. Returns True iff a NEW
    thread was launched (False if one already runs OR config disables it).

    Opt-in via ``PANEL_WG_AUTOSYNC_ENABLED`` (default True in
    production). Gated by ``TESTING`` so unit tests never get
    surprised by a background thread they didn't ask for. Errors
    during start-up are logged + swallowed — a misconfig MUST NOT
    keep the app from booting.
    """
    global _worker_thread
    cfg = app.config
    if cfg.get("TESTING"):
        return False
    if not cfg.get("PANEL_WG_AUTOSYNC_ENABLED", True):
        return False

    with _worker_lock:
        if _worker_thread is not None and _worker_thread.is_alive():
            return False
        _worker_stop.clear()

        def _loop():
            logger.info("fleet.wg_mgmt_autosync: background worker started")
            while not _worker_stop.is_set():
                interval = _resolve_interval(app)
                try:
                    with app.app_context():
                        tick()
                except Exception:  # noqa: BLE001 — never exit on a bad pass
                    logger.exception(
                        "fleet.wg_mgmt_autosync: pass raised; will retry"
                    )
                _worker_stop.wait(timeout=max(15, interval))
            logger.info("fleet.wg_mgmt_autosync: background worker stopped")

        thread = threading.Thread(
            target=_loop, name="fleet-wg-mgmt-autosync", daemon=True,
        )
        thread.start()
        _worker_thread = thread
        return True


def stop_background_autosync(*, join_timeout: float = 5.0) -> None:
    """Cooperative stop — used by tests + graceful shutdown handlers."""
    global _worker_thread
    with _worker_lock:
        _worker_stop.set()
        t = _worker_thread
    if t is not None:
        t.join(timeout=join_timeout)
    with _worker_lock:
        _worker_thread = None


def is_running() -> bool:
    """True iff the background worker thread is alive."""
    with _worker_lock:
        return _worker_thread is not None and _worker_thread.is_alive()


def _resolve_interval(app) -> int:
    """Per-cycle interval lookup. Setting row beats app config beats
    the documented default. Floor of 15s — anything tighter just
    burns sudo calls without giving the operator more signal."""
    try:
        from app.models import Setting
        row = db.session.get(Setting, AUTOSYNC_INTERVAL_SETTING)
        if row and (row.value or "").strip().isdigit():
            return max(15, int(row.value))
    except Exception:  # noqa: BLE001 — never crash the loop on a settings read
        pass
    return int(app.config.get("PANEL_WG_AUTOSYNC_INTERVAL",
                              DEFAULT_AUTOSYNC_INTERVAL_S))


__all__ = [
    "AUTOSYNC_INTERVAL_SETTING",
    "DEFAULT_AUTOSYNC_INTERVAL_S",
    "AUDIT_ACTION_PUBKEY_AUTO_CORRECTED",
    "AutosyncSummary",
    "tick",
    "start_background_autosync",
    "stop_background_autosync",
    "is_running",
]
