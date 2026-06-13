"""fleet.sync.routes — admin endpoints driving the live progress UI.

Blueprint ``fleet_sync`` at ``/admin/fleet/sync``. No background workers: the
browser creates a job, then polls ``/tick`` on an interval; each tick runs ONE
real stage and returns the full job state. That keeps progress genuinely live
(the bar moves only on real state changes) and the whole flow synchronous +
testable.

Endpoints
---------
* ``GET  /``                    standalone progress page (+ «إعادة مزامنة الأسطول»).
* ``POST /jobs``                create a job (scope=fleet | node + node_id).
* ``GET  /jobs/<id>.json``      current job state.
* ``POST /jobs/<id>/tick``      advance one stage, return job state.
"""
from __future__ import annotations

from flask import Blueprint, jsonify, render_template, request

from app.auth.routes import login_required
from app.extensions import db
from fleet.sync import service
from fleet.sync.models import SyncJob

bp = Blueprint("fleet_sync", __name__, url_prefix="/admin/fleet/sync")


@bp.get("/")
@login_required
def sync_index():
    """Standalone live progress page. Optionally auto-resumes ``?job=<id>``."""
    latest = SyncJob.query.order_by(SyncJob.id.desc()).first()
    return render_template(
        "admin/fleet/sync_progress.html",
        latest_job_id=(latest.id if latest else None),
    )


@bp.post("/jobs")
@login_required
def create_sync_job():
    body = request.get_json(silent=True) or {}
    scope = (body.get("scope") or "fleet").strip()
    node_ids = None
    if scope == "node":
        raw = body.get("node_id") or body.get("node_ids")
        if isinstance(raw, list):
            node_ids = [int(x) for x in raw if str(x).strip().isdigit()]
        elif str(raw).strip().isdigit():
            node_ids = [int(raw)]
        if not node_ids:
            return jsonify({"ok": False, "error": "bad_request",
                            "message": "scope=node يتطلب node_id."}), 400
    try:
        job = service.create_job(scope=scope, node_ids=node_ids)
    except Exception as exc:  # noqa: BLE001
        return jsonify({"ok": False, "error": "internal_error",
                        "message": f"تعذّر إنشاء مهمة المزامنة: {exc}"}), 500
    return jsonify({"ok": True, "job": service.to_dict(job)})


@bp.get("/jobs/<int:job_id>.json")
@login_required
def get_sync_job(job_id: int):
    job = db.session.get(SyncJob, job_id)
    if job is None:
        return jsonify({"ok": False, "error": "not_found"}), 404
    return jsonify({"ok": True, "job": service.to_dict(job)})


@bp.post("/jobs/<int:job_id>/tick")
@login_required
def tick_sync_job(job_id: int):
    job = db.session.get(SyncJob, job_id)
    if job is None:
        return jsonify({"ok": False, "error": "not_found"}), 404
    try:
        service.tick(job)
    except Exception as exc:  # noqa: BLE001 — surface, never 500-crash the poll loop
        return jsonify({"ok": False, "error": "tick_failed",
                        "message": f"تعذّر تنفيذ خطوة المزامنة: {exc}"}), 500
    return jsonify({"ok": True, "job": service.to_dict(job)})


@bp.post("/server-peers/resync")
@login_required
def resync_server_peers():
    """Fast-path: reconcile the wg-mgmt peer set on the panel host NOW.

    fix/fleet-wireguard-provisioning (BUG C+D): «إعادة مزامنة peers
    الخادم». A node added in the DB/UI was sometimes never matched by
    a server-side ``wg set wg-mgmt peer ...`` — so the CHR's wg-mgmt
    dial-in was rejected and REST stayed unreachable. The full
    fleet-resync covers this as a side effect, but the operator
    also needs a fast, focused «just-add-the-peer» button without
    spinning a full pipeline (and the «إعادة مزامنة الأسطول»
    button on the dashboard calls THIS too, so the same peer-add
    runs without waiting for every check stage).

    Returns the ApplyResult shape from
    :func:`fleet.sync.wg_apply.apply_panel_peers` — the front-end
    flashes the Arabic message verbatim.
    """
    try:
        result = service.reconcile_panel_host()
    except Exception as exc:  # noqa: BLE001 — surface, never crash the call
        return jsonify({
            "ok": False, "error": "internal_error",
            "message": f"تعذّر إعادة مزامنة نظراء الخادم: {exc}",
        }), 500
    return jsonify({"ok": True, "result": result})


__all__ = ["bp"]
