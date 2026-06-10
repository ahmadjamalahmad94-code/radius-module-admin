"""fleet.ui.routes_p8 — Phase-8 admin page (rebalance + forced failover).

Mounts under ``/admin/fleet/p8``:

* ``GET  /admin/fleet/p8/``                           dashboard
* ``POST /admin/fleet/p8/rebalance-now``              manual rebalance
* ``POST /admin/fleet/p8/chr-nodes/<id>/evacuate``    forced failover of one node

All POSTs go through the orchestrator adapter (real engine if available,
stub fallback otherwise — the wire/contract shape stays identical). Every
mutation flashes a hub-style toast on success and records an audit row.
No native ``alert()`` / ``confirm()`` in the page — destructive intents
render the design-system confirm modal.
"""

from __future__ import annotations

import logging

from flask import Blueprint, flash, redirect, render_template, request, url_for

from app.auth.routes import audit, current_admin, login_required
from app.extensions import db

from fleet.brain.orchestrator_adapter import (
    backend_label,
    execute_rebalance,
    is_available as orchestrator_available,
    plan_forced_failover,
    plan_rebalance,
)
from fleet.control.live_apply_settings import (
    is_enabled as live_apply_is_enabled,
    load_view as live_apply_load_view,
)
from fleet.registry.models_chr import FleetChrNode
from fleet.ui.p8_view import (
    all_headrooms,
    fleet_capacity,
    recent_events,
    recent_plans,
)


logger = logging.getLogger(__name__)

bp = Blueprint("fleet_p8", __name__, url_prefix="/admin/fleet/p8")


# ════════════════════════════════════════════════════════════════════════
# Dashboard
# ════════════════════════════════════════════════════════════════════════
@bp.get("/")
@login_required
def dashboard():
    """Render the rebalance + failover view.

    Panels:

    1. **Fleet headroom** — KPI card with totals + a "can absorb biggest
       node" verdict that turns red when the fleet has no spare capacity
       to take the busiest node's load.
    2. **Per-node headroom** — sorted table with one bar per CHR showing
       used vs free sessions. Each row gets an «إخلاء» button that
       triggers a forced-failover plan for that node.
    3. **Recent plans** — last 50 placement_decisions grouped by their
       recorded ``plan_id``; each plan row shows attempted/applied/
       failed/pending counts + a kind label (إعادة توازن / إخلاء قسري /
       يدوي).
    4. **Recent events** — last 30 ``rebalance_*`` / ``failover_*``
       events with severity colour.

    The honest "live-apply gate" banner sits at the top — when live-apply
    is OFF the page makes it clear that plans here are advisory only and
    no session is actually moved.
    """
    headrooms = all_headrooms()
    capacity = fleet_capacity(headrooms)
    plans = recent_plans(limit=50)
    events = recent_events(limit=30)
    live_apply = live_apply_load_view()
    orchestrator_ready = orchestrator_available()
    return render_template(
        "admin/fleet/p8_dashboard.html",
        headrooms=headrooms,
        capacity=capacity,
        plans=plans,
        events=events,
        live_apply=live_apply,
        live_apply_on=live_apply_is_enabled(),
        orchestrator_ready=orchestrator_ready,
        orchestrator_backend=backend_label(),
    )


# ════════════════════════════════════════════════════════════════════════
# Manual triggers
# ════════════════════════════════════════════════════════════════════════
def _audit(action: str, summary: str, meta: dict) -> None:
    """Best-effort audit. Never blocks the operator's action."""
    try:
        admin = current_admin()
        meta = {**meta, "actor": admin.username if admin else ""}
        audit(action, "fleet_brain", "", summary, meta)
    except Exception:  # noqa: BLE001 — auditing must not break ops
        logger.exception("fleet_p8: audit row failed for action=%s", action)


@bp.post("/rebalance-now")
@login_required
def rebalance_now():
    """Operator-triggered global rebalance — equivalent to the
    orchestrator's "manual" scheduler tick.

    Flow:
      1. ``plan_rebalance("manual")`` via the adapter.
      2. ``execute_rebalance(plan)`` via the adapter.
      3. Audit both calls + flash the result.

    When live-apply is OFF (default), ``execute_rebalance`` returns
    ``applied=False`` and the toast says so honestly — no sessions
    were moved. The plan still lands in the audit table for review.
    """
    plan = plan_rebalance("manual")
    _audit(
        "fleet_rebalance_planned",
        f"خطة إعادة توازن يدوية ({len(plan.moves)} حركات)",
        {"plan_id": plan.plan_id, "trigger": plan.trigger, "kind": plan.kind,
         "moves": len(plan.moves), "backend": backend_label()},
    )
    if not orchestrator_available():
        flash(
            "المُنسِّق غير مرتبط بعد — تم تسجيل النية فقط، لا يوجد تنفيذ فعلي. "
            "(تشغيل برنامج Phase-8 task A سيُكمل الحلقة).",
            "warning",
        )
        db.session.commit()
        return redirect(url_for("fleet_p8.dashboard"))

    result = execute_rebalance(plan)
    _audit(
        "fleet_rebalance_executed",
        f"تنفيذ خطة {plan.plan_id} — مطبق={result.moves_applied}/فشل={result.moves_failed}",
        {"plan_id": plan.plan_id, "applied": result.applied,
         "moves_attempted": result.moves_attempted,
         "moves_applied": result.moves_applied,
         "moves_failed": result.moves_failed,
         "moves_skipped": result.moves_skipped},
    )
    db.session.commit()

    if not live_apply_is_enabled():
        flash(
            "خطة الإعادة جُهِّزت لكن «التطبيق الحي» مغلق — "
            "لم تُنفَّذ أي حركة (استشاري فقط).",
            "warning",
        )
    elif result.moves_failed and not result.moves_applied:
        flash(f"فشل التنفيذ — {result.message or 'لا توجد رسالة من المُنسِّق'}.", "error")
    elif result.moves_failed:
        flash(
            f"اكتمل جزئياً — {result.moves_applied} نُفِّذت، {result.moves_failed} فشلت.",
            "warning",
        )
    elif result.moves_applied:
        flash(f"تم تنفيذ {result.moves_applied} حركة بنجاح.", "success")
    else:
        flash("لا توجد حركات مقترحة في الوقت الحالي — الأسطول متوازن.", "info")
    return redirect(url_for("fleet_p8.dashboard"))


@bp.post("/chr-nodes/<int:node_id>/evacuate")
@login_required
def evacuate_node(node_id: int):
    """Forced-failover for ONE node — operator marks it bad and asks the
    orchestrator to move every session off it.

    Calls ``plan_forced_failover(node_name)`` then ``execute_rebalance``.
    Same live-apply honesty as ``rebalance_now``.
    """
    node = db.session.get(FleetChrNode, node_id)
    if node is None:
        flash("لم يتم العثور على هذا الـCHR.", "error")
        return redirect(url_for("fleet_p8.dashboard"))

    plan = plan_forced_failover(node.name)
    _audit(
        "fleet_failover_planned",
        f"إخلاء قسري للعقدة {node.name} ({len(plan.moves)} حركات مقترحة)",
        {"plan_id": plan.plan_id, "source_node": node.name,
         "moves": len(plan.moves), "backend": backend_label()},
    )
    if not orchestrator_available():
        flash(
            f"المُنسِّق غير مرتبط — تم تسجيل النية لإخلاء «{node.name}» فقط، لا يوجد تنفيذ.",
            "warning",
        )
        db.session.commit()
        return redirect(url_for("fleet_p8.dashboard"))

    result = execute_rebalance(plan)
    _audit(
        "fleet_failover_executed",
        f"تنفيذ إخلاء {node.name} — مطبق={result.moves_applied}/فشل={result.moves_failed}",
        {"plan_id": plan.plan_id, "source_node": node.name,
         "applied": result.applied,
         "moves_attempted": result.moves_attempted,
         "moves_applied": result.moves_applied,
         "moves_failed": result.moves_failed,
         "moves_skipped": result.moves_skipped},
    )
    db.session.commit()

    if not live_apply_is_enabled():
        flash(
            f"تم تجهيز خطة إخلاء لـ«{node.name}» لكن «التطبيق الحي» مغلق — لم تُنفَّذ أي حركة.",
            "warning",
        )
    elif result.moves_failed and not result.moves_applied:
        flash(f"فشل إخلاء «{node.name}» — {result.message or 'لا توجد تفاصيل'}.", "error")
    elif result.moves_failed:
        flash(
            f"إخلاء «{node.name}» اكتمل جزئياً — "
            f"{result.moves_applied} نُفِّذت، {result.moves_failed} فشلت.",
            "warning",
        )
    elif result.moves_applied:
        flash(f"تم إخلاء «{node.name}» — نُقلت {result.moves_applied} جلسة.", "success")
    else:
        flash(f"لا توجد جلسات على «{node.name}» لإخلائها.", "info")
    return redirect(url_for("fleet_p8.dashboard"))


__all__ = ["bp"]
