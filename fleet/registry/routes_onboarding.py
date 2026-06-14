"""fleet.registry.routes_onboarding — admin JSON API for the CHR onboarding wizard.

Phase 3 / P3-T1. Blueprint ``admin_fleet_onboarding`` (url_prefix
``/admin/fleet/onboarding``). Each endpoint advances one step of the §6.2 state
machine via :class:`fleet.registry.onboarding_service.OnboardingService`.

The build steps (keys/script/push) depend on sibling Phase-3 modules
(P3-T2/T3/T4). Until they land, those calls raise ``OnboardingDependencyError``
which we surface as HTTP 503 (endpoint is wired, dependency not yet available).
The rendered script — which embeds private keys — is NEVER returned in a
response; only its content hash is exposed.

Not registered here (the phase-gate integrator wires the blueprint); tests
register it onto a throwaway app and monkeypatch :func:`build_service` to inject
in-memory collaborator fakes.
"""
from __future__ import annotations

from flask import (
    Blueprint,
    Response,
    current_app,
    jsonify,
    render_template,
    request,
    url_for,
)

from app.auth.routes import audit, login_required, super_admin_required
from app.extensions import db
from fleet.registry.models_chr import FleetChrNode
from fleet.registry.models_onboarding import OnboardingJob
from fleet.registry.onboarding_service import (
    OnboardingDependencyError,
    OnboardingError,
    OnboardingService,
    job_to_dict,
)

bp = Blueprint("admin_fleet_onboarding", __name__, url_prefix="/admin/fleet/onboarding")


def build_service() -> OnboardingService:
    """Factory the routes use to obtain a service. Tests monkeypatch this to
    inject fake key/vault/renderer/pusher collaborators."""
    return OnboardingService()


def _body() -> dict:
    return request.get_json(silent=True) or {}


def _job_or_404(job_id: int) -> OnboardingJob | None:
    return db.session.get(OnboardingJob, int(job_id))


def _run(job_id: int, fn, action: str, summary: str):
    """Shared wrapper: load job, run ``fn(service, job)``, audit, map errors."""
    job = _job_or_404(job_id)
    if job is None:
        return jsonify({"ok": False, "error": "not_found",
                        "message": "مهمة التسجيل غير موجودة."}), 404
    service = build_service()
    try:
        result = fn(service, job)
    except OnboardingDependencyError as exc:
        return jsonify({"ok": False, "error": "dependency_unavailable",
                        "message": str(exc)}), 503
    except OnboardingError as exc:
        return jsonify({"ok": False, "error": "onboarding_error",
                        "message": str(exc)}), 400
    audit(action, "fleet_onboarding", str(job.id), summary)
    db.session.commit()
    return jsonify({"ok": True, "job": job_to_dict(job), **(result or {})})


@bp.post("/jobs")
@login_required
def create_draft():
    # URL is /admin/fleet/onboarding/jobs — the address the wizard UI (P3-T5)
    # posts the form to (data-onboarding-url default).
    service = build_service()
    try:
        job = service.create_draft(_body())
    except OnboardingError as exc:
        return jsonify({"ok": False, "error": "onboarding_error",
                        "message": str(exc)}), 400
    audit("fleet_onboarding_draft", "fleet_onboarding", str(job.id),
          f"بدء تسجيل CHR «{job.form_input.get('name', '')}»")
    db.session.commit()
    return jsonify({"ok": True, "job": job_to_dict(job)}), 201


@bp.get("/<int:job_id>")
@login_required
def get_job(job_id: int):
    job = _job_or_404(job_id)
    if job is None:
        return jsonify({"ok": False, "error": "not_found"}), 404
    return jsonify({"ok": True, "job": job_to_dict(job)})


@bp.post("/<int:job_id>/generate-keys")
@login_required
def generate_keys(job_id: int):
    return _run(job_id, lambda s, j: s.generate_keys(j) and None,
                "fleet_onboarding_keys", "توليد مفاتيح wg-mgmt/wg-data")


@bp.post("/<int:job_id>/render-script")
@login_required
def render_script(job_id: int):
    # The script body (with private keys) is NOT returned — only its hash.
    return _run(job_id, lambda s, j: (s.render_script(j), None)[1],
                "fleet_onboarding_render", "توليد سكربت RouterOS الموحّد")


@bp.post("/<int:job_id>/push")
@login_required
def push(job_id: int):
    reach = _body().get("reach") or {}
    return _run(job_id, lambda s, j: s.push(j, reach) and None,
                "fleet_onboarding_push", "دفع السكربت عبر قناة الإقلاع")


@bp.post("/<int:job_id>/retry")
@login_required
def retry(job_id: int):
    return _run(job_id, lambda s, j: s.retry(j) and None,
                "fleet_onboarding_retry", "إعادة محاولة بعد فشل")


# ════════════════════════════════════════════════════════════════════════════
# fix/fleet-onboarding-actions — per-job ACTIONS for the dashboard
#
# When the auto-advance landed for `create_draft` it only helped NEW
# submissions. Jobs that were already stuck in `draft` (the owner had four
# duplicate `chr-vpn-1` rows from before the auto-advance fix) had no
# actionable control on the dashboard. These two endpoints fix that:
#
#   POST /admin/fleet/onboarding/jobs/<id>/advance
#       drive a job FORWARD as far as we can safely go without external
#       network — draft→keys_generated→script_generated. Anything beyond
#       (push to CHR / verify) needs the bootstrap reach which only the
#       wizard's last step collects, so we deliberately stop there.
#
#   POST /admin/fleet/onboarding/jobs/<id>/delete
#       Remove a stuck or duplicate job. If the job already created a
#       provisioning FleetChrNode (chr_id is set) and the operator
#       confirms, the node is removed too — discarding the in-flight
#       attempt entirely. Active/terminal-success jobs are not removed
#       via this path (delete a real, live node by other means).
#
# Both require @super_admin_required + audit (per the urgent brief —
# day-to-day operators must not be able to delete drafts / advance
# state-machine rows behind the operator's back).
# ════════════════════════════════════════════════════════════════════════════


#: Statuses we will NOT advance from. ``active`` is terminal-success;
#: ``failed`` has its own dedicated /retry endpoint and we don't want
#: ``advance`` to silently overlap.
_ADVANCE_REFUSE_FROM = ("active", "failed")

#: Auto-advance ceiling. Beyond ``script_generated`` the next step is
#: ``pushed`` which requires a ``reach`` dict (host:port + creds) that
#: only the wizard's last step collects.
_ADVANCE_CEILING = "script_generated"


@bp.post("/jobs/<int:job_id>/advance")
@super_admin_required
def advance(job_id: int):
    """Drive an in-flight onboarding job forward up to ``script_generated``.

    Returns the post-advance ``status`` + ``chr_id`` so the dashboard JS can
    decide whether to refresh the node table.

    Idempotent: if the job is already at/above ``_ADVANCE_CEILING`` we return
    its current state with ``advanced=False`` — calling /advance twice in a
    row is harmless.

    On a step failure we stamp ``form_input.last_error`` on the job and
    return the specific Arabic reason in ``message``, mirroring the
    create_draft auto-advance fallback so the dashboard never loses the why.
    """
    job = _job_or_404(job_id)
    if job is None:
        return jsonify({"ok": False, "error": "not_found",
                        "message": "مهمة التسجيل غير موجودة."}), 404
    if job.status in _ADVANCE_REFUSE_FROM:
        ar_label = {"active": "نشطة", "failed": "فشلت"}[job.status]
        return jsonify({
            "ok": False, "error": "advance_refused",
            "message": (
                f"الجوب في حالة «{ar_label}» — لا يمكن دفعه من هذه الواجهة. "
                f"استخدم «إعادة المحاولة» للجوبات الفاشلة، أو احذفها."),
        }), 409

    service = build_service()
    initial_status = job.status
    initial_chr_id = job.chr_id
    last_error: str | None = None

    # Walk the safe edges: draft → keys_generated → script_generated.
    while job.status != _ADVANCE_CEILING and job.status not in _ADVANCE_REFUSE_FROM:
        try:
            if job.status == "draft":
                service.generate_keys(job)
            elif job.status == "keys_generated":
                service.render_script(job)
            else:  # defensive — unknown intermediate state
                break
        except OnboardingDependencyError as exc:
            last_error = (
                f"تعذّر متابعة الجوب: الاعتماد الخارجي غير متوفّر بعد ({exc})"
            )
            _stamp_job_error(job, last_error)
            return jsonify({
                "ok": False, "error": "dependency_unavailable",
                "message": last_error,
                "status": job.status, "chr_id": job.chr_id,
            }), 503
        except OnboardingError as exc:
            last_error = str(exc)
            _stamp_job_error(job, last_error)
            return jsonify({
                "ok": False, "error": "onboarding_error",
                "message": last_error,
                "status": job.status, "chr_id": job.chr_id,
            }), 400
        except Exception as exc:  # noqa: BLE001 — never crash the dashboard
            last_error = f"خطأ غير متوقّع: {exc}"
            _stamp_job_error(job, last_error)
            return jsonify({
                "ok": False, "error": "internal_error",
                "message": last_error,
                "status": job.status, "chr_id": job.chr_id,
            }), 500

    advanced = (job.status != initial_status) or (job.chr_id != initial_chr_id)
    audit(
        "fleet_onboarding_advance",
        "fleet_onboarding",
        str(job.id),
        f"دفع جوب التسجيل «{(job.form_input or {}).get('name', '#'+str(job.id))}» "
        f"من «{initial_status}» إلى «{job.status}»",
        metadata={"from": initial_status, "to": job.status,
                  "chr_id": job.chr_id, "advanced": advanced},
    )
    db.session.commit()
    return jsonify({
        "ok": True,
        "advanced": advanced,
        "status": job.status,
        "chr_id": job.chr_id,
        "job": job_to_dict(job),
    })


@bp.post("/jobs/<int:job_id>/delete")
@super_admin_required
def delete_job(job_id: int):
    """Delete a stuck or duplicate onboarding job. If the job created a
    provisioning ``FleetChrNode`` (``chr_id`` is set), the operator can opt
    in to remove it too via ``{"remove_node": true}`` — by default we keep
    the node so an operator clicking «حذف» on a half-finished but visible
    node doesn't accidentally wipe it.

    Active jobs cannot be deleted via this path. Use the dedicated lifecycle
    endpoints once they exist; for now the only legitimate cleanup target is
    pre-active job rows."""
    job = _job_or_404(job_id)
    if job is None:
        return jsonify({"ok": False, "error": "not_found",
                        "message": "مهمة التسجيل غير موجودة."}), 404
    if job.status == "active":
        return jsonify({
            "ok": False, "error": "delete_refused",
            "message": (
                "لا يمكن حذف جوب «نشطة» من هذه الواجهة — العقدة فعّالة. "
                "استخدم إجراءات إدارة العقد بدلاً من ذلك."),
        }), 409

    remove_node = bool(_body().get("remove_node", True))
    teardown_report = None
    if remove_node and job.chr_id is not None:
        # fix/fleet-delete-complete-teardown — route through the
        # centralised teardown so the cascade is COMPLETE (proxy
        # route scrub + CoA queue drop + sessions + pinned refs +
        # panel-host wg-mgmt reconcile). The previous handler just
        # called ``db.session.delete(node)`` which left every one
        # of those surfaces stale until the operator clicked
        # another button.
        from fleet.registry.teardown import teardown_node
        report = teardown_node(job.chr_id)
        teardown_report = report.as_dict()

    summary_name = (job.form_input or {}).get("name", f"#{job.id}")
    node_removed = bool(teardown_report and teardown_report.get("node_row_deleted"))
    audit(
        "fleet_onboarding_delete",
        "fleet_onboarding",
        str(job.id),
        f"حذف جوب تسجيل «{summary_name}» (الحالة: {job.status})"
        + (f" + إزالة العقدة #{job.chr_id}" if node_removed else ""),
        metadata={
            "status": job.status, "chr_id": job.chr_id,
            "node_removed": node_removed,
            "teardown": teardown_report or {},
        },
    )
    db.session.delete(job)
    db.session.commit()
    return jsonify({
        "ok": True,
        "deleted": True,
        "node_removed": node_removed,
        "job_id": job_id,
        "teardown": teardown_report or {},
    })


# ════════════════════════════════════════════════════════════════════════
# fix/fleet-delete-complete-teardown — orphan cleanup surfaces
# ════════════════════════════════════════════════════════════════════════

@bp.post("/nodes/<int:node_id>/delete")
@super_admin_required
def delete_orphan_node(node_id: int):
    """Delete a fleet_chr_nodes row directly — used to clean up nodes
    that no longer have an active OnboardingJob pointing at them.

    Previously the only delete path was through the job-delete handler;
    a node left behind by ``remove_node=False`` or by a manual API
    insertion was invisible from the wizard tab and unreachable for
    cleanup. This endpoint plugs that gap. Runs the same centralised
    teardown cascade as the job-delete path.

    Refuses to delete a node that's still pointed at by a NON-failed,
    NON-active job — the operator should delete the job (or advance
    it past failure) before reaching for direct node deletion. This
    keeps the «one wizard job ↔ one node row» invariant intact for
    the normal flow.
    """
    node = db.session.get(FleetChrNode, node_id)
    if node is None:
        return jsonify({
            "ok": False, "error": "not_found",
            "message": "عقدة الأسطول غير موجودة.",
        }), 404
    # Refuse if a live (non-failed, non-active) job is still pointing here.
    blocking_states = (
        "draft", "keys_generated", "script_generated",
        "pushed", "verifying",
    )
    blocking = (
        OnboardingJob.query
        .filter(OnboardingJob.chr_id == node_id)
        .filter(OnboardingJob.status.in_(blocking_states))
        .first()
    )
    if blocking is not None:
        return jsonify({
            "ok": False, "error": "delete_refused",
            "message": (
                f"العقدة مرتبطة بمهمة تسجيل قيد التنفيذ #{blocking.id} "
                f"(الحالة: {blocking.status}). احذف المهمة أولاً، أو ادفعها "
                "حتى تنتهي ثم احذف العقدة."),
        }), 409

    from fleet.registry.teardown import teardown_node
    report = teardown_node(node)
    audit(
        "fleet_node_delete",
        "fleet_chr_node",
        str(node_id),
        f"حذف عقدة الأسطول «{report.node_name}» (المعرّف #{node_id}) "
        f"مع التنظيف الكامل.",
        metadata={"teardown": report.as_dict()},
    )
    db.session.commit()
    return jsonify({
        "ok": True,
        "deleted": True,
        "node_id": node_id,
        "teardown": report.as_dict(),
    })


@bp.get("/orphans")
@super_admin_required
def survey_orphans():
    """Read-only survey of dangling refs — the «معاينة المهملات» panel
    shows this so the operator can preview before purging."""
    from fleet.registry.teardown import find_orphans
    return jsonify({"ok": True, "survey": find_orphans().as_dict()})


@bp.post("/orphans/purge")
@super_admin_required
def purge_orphans_route():
    """Run the full orphan sweep + commit. Audits exactly what was
    found and what was removed."""
    from fleet.registry.teardown import purge_orphans
    report = purge_orphans()
    audit(
        "fleet_orphan_purge", "fleet_onboarding", "*",
        (
            f"تنظيف المهملات: "
            f"{len(report.survey_before.orphan_node_ids)} عقدة + "
            f"{report.orphan_jobs_deleted} مهمة + "
            f"{len(report.survey_before.stale_route_node_ids)} مسار + "
            f"{len(report.survey_before.stale_coa_node_ids)} CoA"
        ),
        metadata=report.as_dict(),
    )
    db.session.commit()
    return jsonify({"ok": True, "report": report.as_dict()})


def _stamp_job_error(job: OnboardingJob, message: str) -> None:
    """Mirror onboarding_service._stamp_job_error so a /advance failure
    leaves the same breadcrumb on the dashboard's pending card."""
    data = dict(job.form_input or {})
    data["last_error"] = (message or "")[:500]
    job.form_input = data
    db.session.add(job)
    db.session.commit()


# ════════════════════════════════════════════════════════════════════════════
# fix/fleet-script-view-instructions — view + download the rendered .rsc
#
# Owner pain: after «تم توليد السكربت» there was no way to SEE/COPY/DOWNLOAD
# the actual RouterOS script. The MikroTik admin needs the bytes to install
# the node manually (until the bootstrap-push channel auto-pushes them).
#
# Security & vault discipline:
#   * The script EMBEDS WireGuard private keys (wg-mgmt/wg-data). The
#     persistent column ``generated_script_ref`` is a SHA-256 hash only —
#     not the script body. We re-render on demand using the same renderer
#     used by the auto-advance path; the bytes only ever live on the
#     active stack frame.
#   * Endpoint is @super_admin_required + audited. The audit log records
#     "operator X viewed the script for job N (chr-vpn-1)" — not the body.
#   * The handler never logs the body, never writes it to disk, and never
#     surfaces it in an error response (we trap exceptions and return the
#     Arabic reason only).
#
# Statuses where this is meaningful:
#   * script_generated, pushed, verifying, active  — the script exists
#   * keys_generated                                — we can render fresh
#   * draft / failed (no chr_id)                    — refused
# ════════════════════════════════════════════════════════════════════════════


_SCRIPT_VIEW_OK_STATUSES = (
    "keys_generated", "script_generated", "pushed", "verifying", "active",
)


def _safe_filename(name: str) -> str:
    """Sanitise the node name for use as a .rsc filename. RouterOS file
    operations dislike spaces + most punctuation; lowercase ASCII + hyphens
    + underscores + digits + dots is the safe alphabet."""
    import re as _re
    cleaned = _re.sub(r"[^A-Za-z0-9._-]+", "-", str(name or "")).strip("-.")
    return (cleaned or f"chr-job-{0}").lower()


def _render_job_to_response_payload(job: OnboardingJob):
    """Shared render pipeline used by both the job-keyed view_script and
    the new node-keyed view_node_script.

    Runs the same path as the original view_script:
      * status-gate against _SCRIPT_VIEW_OK_STATUSES + chr_id check;
      * build bindings (errors propagate as the right HTTP code);
      * defence-in-depth bindings_check;
      * render via the configured renderer.

    Returns either a `(jsonify(...), status_code)` tuple to short-circuit
    OR a dict `{"job": job, "script": str, "bindings": dict, "node_name": str,
    "filename": str}` for the caller to wrap. The caller decides the
    final JSON shape (job-keyed adds `job_id`; node-keyed adds `node_id`)
    so the two routes stay distinct + auditable.
    """
    if job.status not in _SCRIPT_VIEW_OK_STATUSES:
        return jsonify({
            "ok": False, "error": "script_unavailable",
            "message": (
                f"السكربت غير متاح بعد — الحالة الحالية «{job.status}». "
                f"اضغط «متابعة» على البطاقة لدفع الجوب حتى مرحلة توليد "
                f"السكربت ثم أعد المحاولة."),
        }), 400
    if not job.chr_id:
        return jsonify({
            "ok": False, "error": "script_unavailable",
            "message": (
                "لا توجد عقدة CHR مرتبطة بهذه المهمة بعد، فلا يمكن توليد "
                "السكربت. ادفع الجوب أولاً عبر «متابعة»."),
        }), 400
    service = build_service()
    try:
        bindings = service._build_bindings(job)
    except OnboardingDependencyError as exc:
        return jsonify({"ok": False, "error": "dependency_unavailable",
                        "message": str(exc)}), 503
    except OnboardingError as exc:
        return jsonify({"ok": False, "error": "onboarding_error",
                        "message": str(exc)}), 400
    from fleet.registry.script_bindings_check import check_bindings, summary_ar
    missing = check_bindings(bindings)
    if missing:
        return jsonify({
            "ok": False,
            "error": "bindings_incomplete",
            "message": summary_ar(missing),
            "missing": [
                {"key": m.key, "label_ar": m.label_ar, "setup_hint_ar": m.setup_hint_ar}
                for m in missing
            ],
        }), 412
    try:
        script = service.renderer.render(bindings)
    except Exception as exc:  # noqa: BLE001 — never leak the body in errors
        return jsonify({"ok": False, "error": "internal_error",
                        "message": f"تعذّر توليد السكربت: {exc}"}), 500
    node_name = (job.form_input or {}).get("name") or f"chr-job-{job.id}"
    filename = f"{_safe_filename(node_name)}.rsc"
    # Successful render → clear any stale «بانتظار» error on the job.
    service._clear_job_error(job)
    return {
        "job": job,
        "script": script,
        "bindings": bindings,
        "node_name": node_name,
        "filename": filename,
    }


@bp.get("/jobs/<int:job_id>/script")
@super_admin_required
def view_script(job_id: int):
    """Re-render the per-CHR .rsc and return it in JSON.

    Response on success:
        {ok: true,
         job_id, node_name, status,
         filename:  "chr-vpn-1.rsc",
         script:    "<rendered RouterOS bytes>",
         sha256:    "<the stored generated_script_ref>"}

    Response on refusal:
        400 {ok:false, error:"script_unavailable", message:"<Arabic reason>"}

    fix/view-script-404-orphan — robust resolver:
      1. Try ``OnboardingJob(job_id)`` directly (normal path).
      2. If absent, try ``FleetChrNode(job_id)`` and find ANY
         OnboardingJob whose ``chr_id`` matches that node's id in a
         renderable state — covers the "operator clicked a stale
         button whose underlying job id was deleted but the node id
         lives on" race + the legacy chrome where the dashboard URL
         happens to carry a node id that collides with a deleted
         job id.
      3. If neither resolves, return 410 GONE (not bare 404) with a
         clear actionable message: refresh the dashboard / run «نظّف
         المهملات» / re-add via the wizard.
    """
    job = _job_or_404(job_id)
    if job is None:
        # Fallback A: maybe the id refers to a FleetChrNode whose
        # OnboardingJob got deleted (orphan card). Look up a renderable
        # job by chr_id so the operator can still SEE the script.
        from fleet.registry.models_chr import FleetChrNode
        node = db.session.get(FleetChrNode, int(job_id))
        if node is not None:
            sibling_job = (
                OnboardingJob.query
                .filter(OnboardingJob.chr_id == node.id)
                .filter(OnboardingJob.status.in_(_SCRIPT_VIEW_OK_STATUSES))
                .order_by(OnboardingJob.id.desc())
                .first()
            )
            if sibling_job is not None:
                current_app.logger.info(
                    "view_script: id=%s resolved via FleetChrNode(%s) -> "
                    "OnboardingJob(%s) (stale-button fallback)",
                    job_id, node.id, sibling_job.id,
                )
                job = sibling_job
            else:
                return jsonify({
                    "ok": False,
                    "error": "orphan_node",
                    "message": (
                        f"العقدة #{node.id} «{node.name}» موجودة لكن لا توجد "
                        f"مهمة تسجيل قابلة للعرض مرتبطة بها — على الأرجح "
                        f"حُذفت المهمة لاحقاً. شغّل «نظّف المهملات» لإزالة "
                        f"العقدة المعزولة ثم أضِفها من جديد عبر المعالج."
                    ),
                    "node_id": node.id,
                    "node_name": node.name,
                }), 410   # Gone — the resource existed but is no longer available
        if job is None:
            return jsonify({
                "ok": False,
                "error": "not_found",
                "message": (
                    "مهمة التسجيل غير موجودة — على الأرجح حُذفت بعد فتح "
                    "هذه الصفحة. أعد تحميل اللوحة لمشاهدة الحالة الحالية، "
                    "أو شغّل «نظّف المهملات» إن بقيت بطاقات وهمية."
                ),
                "job_id": job_id,
            }), 404
    result = _render_job_to_response_payload(job)
    if isinstance(result, tuple):
        return result   # short-circuit response from the helper
    audit(
        "fleet_onboarding_script_view",
        "fleet_onboarding",
        str(result["job"].id),
        f"تم عرض سكربت RouterOS للعقدة «{result['node_name']}» (الجوب #{result['job'].id})",
        metadata={"chr_id": result["job"].chr_id, "status": result["job"].status,
                  "script_sha256": result["job"].generated_script_ref},
    )
    db.session.commit()
    return jsonify({
        "ok": True,
        "job_id": result["job"].id,
        "node_name": result["node_name"],
        "status": result["job"].status,
        "filename": result["filename"],
        "script": result["script"],
        "sha256": result["job"].generated_script_ref,
    })


@bp.get("/chr-nodes/<int:node_id>/script")
@super_admin_required
def view_node_script(node_id: int):
    """Re-render the per-CHR .rsc keyed by NODE id (not job id).

    feat/active-node-view-script-reimport — the original
    ``view_script`` is job-keyed, so once a node leaves the pending
    tab («نشطة») the operator has no way to re-view + re-import the
    script. That's the missing piece for the key-rotation flow: the
    periodic wg-mgmt autosync (fleet/sync/wg_mgmt_autosync.py) flips
    ``needs_reimport=True`` on active nodes when the panel key drifts,
    but there was no UI to fetch the freshly-rendered script with the
    corrected key.

    Resolution:
      * load FleetChrNode(node_id);
      * find the latest renderable OnboardingJob with chr_id=node.id
        (includes status='active' — that's exactly the case the
        owner needs);
      * render via the shared pipeline + return the same JSON shape
        as ``view_script`` plus a ``node_id`` echo so the front-end
        can disambiguate the two callers.
    """
    from fleet.registry.models_chr import FleetChrNode
    node = db.session.get(FleetChrNode, int(node_id))
    if node is None:
        return jsonify({
            "ok": False, "error": "not_found",
            "message": (
                "العقدة غير موجودة — على الأرجح حُذفت بعد فتح الصفحة. "
                "أعد تحميل اللوحة لمشاهدة الحالة الحالية."
            ),
            "node_id": node_id,
        }), 404
    sibling_job = (
        OnboardingJob.query
        .filter(OnboardingJob.chr_id == node.id)
        .filter(OnboardingJob.status.in_(_SCRIPT_VIEW_OK_STATUSES))
        .order_by(OnboardingJob.id.desc())
        .first()
    )
    if sibling_job is None:
        return jsonify({
            "ok": False, "error": "orphan_node",
            "message": (
                f"العقدة #{node.id} «{node.name}» موجودة لكن لا توجد "
                f"مهمة تسجيل قابلة للعرض مرتبطة بها — على الأرجح "
                f"حُذفت المهمة لاحقاً. شغّل «نظّف المهملات» لإزالة "
                f"العقدة المعزولة ثم أضِفها من جديد عبر المعالج."
            ),
            "node_id": node.id, "node_name": node.name,
        }), 410
    result = _render_job_to_response_payload(sibling_job)
    if isinstance(result, tuple):
        return result
    audit(
        "fleet_node_script_view",
        "fleet_chr_node",
        str(node.id),
        f"تم عرض سكربت RouterOS للعقدة «{node.name}» (عقدة #{node.id})",
        metadata={
            "chr_id": node.id,
            "job_id": result["job"].id,
            "status": result["job"].status,
            "script_sha256": result["job"].generated_script_ref,
            "needs_reimport_before": bool(node.needs_reimport),
        },
    )
    db.session.commit()
    return jsonify({
        "ok": True,
        "node_id": node.id,
        "job_id": result["job"].id,
        "node_name": result["node_name"],
        "status": result["job"].status,
        "filename": result["filename"],
        "script": result["script"],
        "sha256": result["job"].generated_script_ref,
        # Surface the re-import flag so the modal can show a banner
        # if the operator opened the script because of an autosync
        # key-drift event. We DO NOT auto-clear it here — clearance
        # waits for the next autosync handshake confirmation.
        "needs_reimport": bool(node.needs_reimport),
    })


@bp.get("/chr-nodes/<int:node_id>/script.rsc")
@super_admin_required
def download_node_script(node_id: int):
    """Direct file download of the per-CHR .rsc — no JSON, no modal, no JS.

    fix/direct-script-download-and-freeze — the JSON+modal path
    (``view_node_script``) was live-blocked: Chrome's renderer froze
    while the ~900-line / ~61KB script `<pre>` was open + the dashboard
    poll competed for the main thread, so the operator could not click
    «نسخ» / «تنزيل .rsc».

    This route bypasses the entire modal pipeline: a plain HTTP GET
    on a normal anchor with the ``download`` attribute streams the
    file straight to disk. Cannot freeze. Cannot rely on a
    JavaScript handler. Cannot be killed by a live-poll tick.

    Resolution path is the SAME as ``view_node_script`` (find latest
    renderable OnboardingJob for the node, render via the shared
    pipeline), but the response is ``text/plain`` with
    ``Content-Disposition: attachment`` so the browser saves the file.

    Error envelope: we still need to return SOMETHING readable when
    the renderer can't produce a script — falling back to a
    short-text .txt download with the Arabic reason in the body so
    the operator's File Saved dialog shows the failure cause without
    requiring JS or a modal.
    """
    node = db.session.get(FleetChrNode, int(node_id))
    if node is None:
        return jsonify({
            "ok": False, "error": "not_found",
            "message": "العقدة غير موجودة.", "node_id": node_id,
        }), 404
    sibling_job = (
        OnboardingJob.query
        .filter(OnboardingJob.chr_id == node.id)
        .filter(OnboardingJob.status.in_(_SCRIPT_VIEW_OK_STATUSES))
        .order_by(OnboardingJob.id.desc())
        .first()
    )
    if sibling_job is None:
        return jsonify({
            "ok": False, "error": "orphan_node",
            "message": (
                f"العقدة #{node.id} «{node.name}» موجودة لكن لا توجد "
                f"مهمة تسجيل قابلة للعرض مرتبطة بها."
            ),
            "node_id": node.id, "node_name": node.name,
        }), 410

    # fix/script-service-get-guard — best-effort retry once on
    # OnboardingDependencyError. Both this route and view_node_script
    # share the same _render_job_to_response_payload pipeline; the
    # owner saw the JSON route return 200 while this route returned
    # 503 milliseconds later — symptom of a TRANSIENT sibling-module
    # import flicker (the only path that raises OnboardingDepError).
    # A second attempt re-enters with the imports now warm in
    # sys.modules and almost always succeeds.
    result = _render_job_to_response_payload(sibling_job)
    if isinstance(result, tuple):
        _resp, _status = result
        if _status == 503:
            current_app.logger.warning(
                "download_node_script(node=%s): 503 on first attempt — "
                "retrying once (likely transient sibling-import flicker)",
                node.id,
            )
            result = _render_job_to_response_payload(sibling_job)
    if isinstance(result, tuple):
        # Still failed after retry — surface a TEXT/PLAIN attachment
        # with the Arabic reason in the body so the operator's Save
        # dialog produces a human-readable .rsc.txt rather than a
        # JSON blob shoved into a .rsc filename.
        _resp, _status = result
        body = _resp.get_json() or {}
        msg = body.get("message") or body.get("error") or "تعذّر توليد السكربت."
        text = (
            f"# تعذّر توليد سكربت RouterOS للعقدة "
            f"«{node.name}» (#{node.id})\n"
            f"# السبب: {msg}\n"
            f"# error_code: {body.get('error', 'unknown')}\n"
            f"# HTTP status: {_status}\n"
            f"#\n"
            f"# هذه ليست عملية تنزيل ناجحة — لا تستورد هذا الملف.\n"
            f"# أعد المحاولة بعد دقائق، أو افتح صفحة العقدة لمزيد من التفاصيل.\n"
        )
        return Response(
            text,
            status=_status,
            mimetype="text/plain; charset=utf-8",
            headers={
                "Content-Disposition": (
                    f'attachment; filename="{_safe_filename(node.name)}.error.txt"'
                ),
                "Cache-Control": "no-store, no-cache, must-revalidate, private",
                "Pragma": "no-cache",
            },
        )

    script_bytes = result["script"]
    filename = result["filename"]  # safe, already sanitised
    # Audit — record the DOWNLOAD (not the body).
    audit(
        "fleet_node_script_download",
        "fleet_chr_node",
        str(node.id),
        f"تم تنزيل سكربت RouterOS للعقدة «{node.name}» (مباشر)",
        metadata={
            "chr_id": node.id,
            "job_id": result["job"].id,
            "status": result["job"].status,
            "script_sha256": result["job"].generated_script_ref,
            "needs_reimport_before": bool(node.needs_reimport),
            "transport": "direct_download",
        },
    )
    db.session.commit()

    resp = Response(
        script_bytes,
        mimetype="text/plain; charset=utf-8",
        headers={
            # filename is `<node>.rsc`; the `attachment` disposition
            # forces a Save-As dialog rather than rendering the body.
            "Content-Disposition": f'attachment; filename="{filename}"',
            # Defence: never let any proxy / browser cache the script
            # body (it carries plaintext private keys).
            "Cache-Control": "no-store, no-cache, must-revalidate, private",
            "Pragma": "no-cache",
        },
    )
    return resp


# ════════════════════════════════════════════════════════════════════════════
# fix/view-script-dedicated-page — standalone full-page script viewer
# ════════════════════════════════════════════════════════════════════════════
# The floating «عرض السكربت» modal kept failing for the owner despite a
# string of fixes (event delegation, pause-poll, page-level modal,
# textarea). We stop fighting the modal-vs-live-poll renderer entirely:
# «عرض السكربت» now opens a DEDICATED full page in a NEW TAB that renders
# the script as plain readable text — its own minimal template (NOT the
# dashboard layout) so there is NO live_poll.js, NO polling, NO heavy
# modal CSS. It cannot be broken by the dashboard renderer/poll.
#
# Same render path as the .rsc download (_render_job_to_response_payload)
# so viewed == downloaded == imported. Orphan / missing node / render-
# dependency failures degrade GRACEFULLY: the page shows the error text
# instead of a 500/503.


def _script_view_page(node, sibling_job, *, download_url: str) -> Response:
    """Render the standalone script-view page for a resolved node+job.

    Always returns 200 with a human page — render failures are shown
    inline (the operator opened a tab to READ something; a blank
    500/503 helps nobody). The HTTP status stays 200 so the new tab
    always shows content; the page body carries the precise reason.
    """
    node_name = getattr(node, "name", "") or f"node-{getattr(node, 'id', '?')}"
    result = _render_job_to_response_payload(sibling_job)
    if isinstance(result, tuple):
        # (jsonify(...), status) error from the shared pipeline — show
        # the Arabic reason on the page instead of crashing the tab.
        _resp, _status = result
        body = _resp.get_json() or {}
        msg = body.get("message") or body.get("error") or "تعذّر توليد السكربت."
        html = render_template(
            "admin/fleet/script_view_page.html",
            node_name=node_name,
            script=None,
            error_message=msg,
            error_code=body.get("error", "unknown"),
            http_status=_status,
            download_url=download_url,
            filename="",
        )
        return Response(
            html, status=200, mimetype="text/html; charset=utf-8",
            headers={"Cache-Control": "no-store, no-cache, must-revalidate, private"},
        )

    # Audit the view (distinct from the JSON modal action + the download).
    try:
        audit(
            "fleet_node_script_view_page",
            "fleet_chr_node",
            str(getattr(node, "id", "") or ""),
            f"عرض صفحة سكربت RouterOS للعقدة «{node_name}» (صفحة مستقلة)",
            metadata={
                "chr_id": getattr(node, "id", None),
                "job_id": result["job"].id,
                "status": result["job"].status,
            },
        )
        db.session.commit()
    except Exception:  # noqa: BLE001 — audit must never break the viewer
        db.session.rollback()

    html = render_template(
        "admin/fleet/script_view_page.html",
        node_name=result["node_name"],
        script=result["script"],
        error_message=None,
        error_code=None,
        http_status=200,
        download_url=download_url,
        filename=result["filename"],
    )
    return Response(
        html, status=200, mimetype="text/html; charset=utf-8",
        headers={"Cache-Control": "no-store, no-cache, must-revalidate, private"},
    )


@bp.get("/chr-nodes/<int:node_id>/script/view")
@super_admin_required
def view_node_script_page(node_id: int):
    """Standalone full-page script viewer keyed by NODE id (active cards)."""
    node = db.session.get(FleetChrNode, int(node_id))
    if node is None:
        html = render_template(
            "admin/fleet/script_view_page.html",
            node_name=f"#{node_id}", script=None,
            error_message=(
                "العقدة غير موجودة — على الأرجح حُذفت بعد فتح اللوحة. "
                "أعد تحميل اللوحة."
            ),
            error_code="not_found", http_status=404,
            download_url="", filename="",
        )
        return Response(html, status=404, mimetype="text/html; charset=utf-8")
    sibling_job = (
        OnboardingJob.query
        .filter(OnboardingJob.chr_id == node.id)
        .filter(OnboardingJob.status.in_(_SCRIPT_VIEW_OK_STATUSES))
        .order_by(OnboardingJob.id.desc())
        .first()
    )
    if sibling_job is None:
        html = render_template(
            "admin/fleet/script_view_page.html",
            node_name=node.name, script=None,
            error_message=(
                f"العقدة #{node.id} «{node.name}» موجودة لكن لا توجد مهمة "
                f"تسجيل قابلة للعرض مرتبطة بها — على الأرجح حُذفت المهمة. "
                f"شغّل «نظّف المهملات» ثم أعِد الإضافة عبر المعالج."
            ),
            error_code="orphan_node", http_status=410,
            download_url="", filename="",
        )
        return Response(html, status=410, mimetype="text/html; charset=utf-8")
    download_url = url_for(
        "admin_fleet_onboarding.download_node_script", node_id=node.id
    )
    return _script_view_page(node, sibling_job, download_url=download_url)


@bp.get("/jobs/<int:job_id>/script/view")
@super_admin_required
def view_job_script_page(job_id: int):
    """Standalone full-page script viewer keyed by JOB id (pending cards).

    Resolves the same way as the JSON ``view_script``: try the job
    directly, then fall back to a FleetChrNode whose id collides (stale
    button). The download link prefers the node-keyed .rsc route when a
    chr_id is known, else the job is shown without a download anchor.
    """
    job = db.session.get(OnboardingJob, int(job_id))
    node = None
    if job is None:
        # Fallback: the id might be a FleetChrNode id (stale pending card).
        node = db.session.get(FleetChrNode, int(job_id))
        if node is not None:
            job = (
                OnboardingJob.query
                .filter(OnboardingJob.chr_id == node.id)
                .filter(OnboardingJob.status.in_(_SCRIPT_VIEW_OK_STATUSES))
                .order_by(OnboardingJob.id.desc())
                .first()
            )
    if job is None:
        html = render_template(
            "admin/fleet/script_view_page.html",
            node_name=f"#{job_id}", script=None,
            error_message=(
                "المهمة غير موجودة — على الأرجح اكتملت أو حُذفت. أعد تحميل "
                "اللوحة لمشاهدة الحالة الحالية."
            ),
            error_code="job_not_found", http_status=404,
            download_url="", filename="",
        )
        return Response(html, status=404, mimetype="text/html; charset=utf-8")
    if node is None and job.chr_id:
        node = db.session.get(FleetChrNode, job.chr_id)
    download_url = ""
    if node is not None:
        download_url = url_for(
            "admin_fleet_onboarding.download_node_script", node_id=node.id
        )
    # The viewer only needs a name for the header; synthesize one if the
    # job has no linked node yet.
    view_node = node or _SimpleNode(
        id=job.chr_id or 0,
        name=(job.form_input or {}).get("name") or f"job-{job.id}",
    )
    return _script_view_page(view_node, job, download_url=download_url)


class _SimpleNode:
    """Tiny stand-in so _script_view_page can render a job with no
    linked FleetChrNode row (name + id are all it reads)."""

    def __init__(self, *, id: int, name: str) -> None:
        self.id = id
        self.name = name


# ════════════════════════════════════════════════════════════════════════════
# fix/chr-script-syntax-355 owner review #5 — secret rotation scaffold
# ════════════════════════════════════════════════════════════════════════════
# The owner's review flagged that the rendered script embeds plaintext:
#
#   * WireGuard PRIVATE keys (wg-mgmt + wg-data, per-node).
#   * The RADIUS shared secret (`CHR_SHARED_SECRET`, fleet-constant).
#   * The IPsec PSK (`hobe-mc` peer secret, currently the same as
#     `CHR_SHARED_SECRET` — fleet-constant by design).
#   * The panel poller user password (`API_PASSWORD`, per-fleet default
#     or per-node override).
#
# Rotating these in-place requires touching FOUR distinct surfaces:
#
#   (a) Fleet vault (per-node WG keypairs → re-mint + re-store ciphertext).
#   (b) Settings (`fleet.infra.CHR_SHARED_SECRET` → re-generate +
#       Fernet-encrypt + commit).
#   (c) Per-node row (`routeros_api_password_enc` → re-encrypt new
#       password).
#   (d) Distributed convergence (the routing-table / secret-sync
#       channel must publish the new secret to the proxy BEFORE the
#       CHR re-imports, otherwise RADIUS auth fails mid-rotation).
#
# The full sequencer (rotate → re-render → push → verify → reconcile-
# on-proxy) is non-trivial and out of scope for this fix branch. The
# panel ALREADY has the building blocks (`generate_chr_shared_secret`
# in infra_settings.py, the wg_keys minter in fleet/registry/wg_keys.py,
# the secret-sync channel in fleet/sync/) — the missing piece is the
# orchestration + the proxy-side replay-safe convergence test.
#
# What ships in THIS branch: a stub endpoint that responds 501 Not
# Implemented with a clear Arabic message explaining the deferred
# scope, so the UI button can be wired up without serving a 404. The
# audit log records the operator's request, so we can size the real
# rotation work from the access pattern.


@bp.post("/jobs/<int:job_id>/rotate-secrets")
@super_admin_required
def rotate_secrets(job_id: int):
    """Stub for the per-node secret rotation flow (deferred).

    Audited even though we don't perform the rotation yet — operator
    intent is the signal we need to size the real work."""
    job = _job_or_404(job_id)
    if job is None:
        return jsonify({"ok": False, "error": "not_found",
                        "message": "مهمة التسجيل غير موجودة."}), 404
    node_name = (job.form_input or {}).get("name") or f"chr-job-{job.id}"
    audit(
        "fleet_onboarding_script_rotate_requested",
        "fleet_onboarding",
        str(job.id),
        f"طُلب تدوير أسرار العقدة «{node_name}» (الجوب #{job.id}) — مؤجَّل (501).",
        metadata={"chr_id": job.chr_id, "status": job.status},
    )
    db.session.commit()
    return jsonify({
        "ok": False,
        "error": "rotate_not_implemented_yet",
        "message": (
            "تدوير الأسرار غير مفعَّل في هذه النسخة بعد. الأجزاء الجاهزة في "
            "اللوحة: توليد مفاتيح WireGuard جديدة، توليد سرّ RADIUS مشترك "
            "جديد، إعادة تشفير كلمة المستخدم على الخادم. الجزء الناقص: "
            "تنسيق التدوير عبر الـRADIUS proxy (نشر السرّ الجديد قبل "
            "إعادة الاستيراد على الـCHR) لتجنّب فشل المصادقة في منتصف "
            "العملية. سيُشحَن في فرع منفصل."
        ),
        "deferred_components": {
            "wg_keys":       "generator ready (fleet/registry/wg_keys.py); orchestrator missing",
            "radius_secret": "generator ready (infra_settings.generate_chr_shared_secret); proxy-side replay-safe push missing",
            "ipsec_psk":     "shares CHR_SHARED_SECRET by design; rotates together",
            "api_password":  "per-node row column ready; minter + re-encryption + onboarding-state machine glue missing",
        },
    }), 501


__all__ = ["bp", "build_service"]
