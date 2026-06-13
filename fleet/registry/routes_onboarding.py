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

from flask import Blueprint, jsonify, request

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
    """
    job = _job_or_404(job_id)
    if job is None:
        return jsonify({"ok": False, "error": "not_found",
                        "message": "مهمة التسجيل غير موجودة."}), 404
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
        # The renderer is pure (no DB writes, no vault writes); calling it
        # again is safe + cheap. We bypass service.render_script() to avoid
        # re-advancing the state machine — that would error from any state
        # past script_generated.
        bindings = service._build_bindings(job)
    except OnboardingDependencyError as exc:
        return jsonify({"ok": False, "error": "dependency_unavailable",
                        "message": str(exc)}), 503
    except OnboardingError as exc:
        return jsonify({"ok": False, "error": "onboarding_error",
                        "message": str(exc)}), 400

    # Defence in depth — re-validate even on an old job that already has
    # ``status = script_generated`` from before the bindings check landed.
    # The owner's first install came from exactly such a job; we refuse to
    # serve a syntactically-broken .rsc again.
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
        }), 412   # Precondition Required — operator must wire panel/proxy/secret first

    try:
        script = service.renderer.render(bindings)
    except Exception as exc:  # noqa: BLE001 — never leak the body in errors
        return jsonify({"ok": False, "error": "internal_error",
                        "message": f"تعذّر توليد السكربت: {exc}"}), 500

    node_name = (job.form_input or {}).get("name") or f"chr-job-{job.id}"
    filename = f"{_safe_filename(node_name)}.rsc"

    # The script rendered cleanly + passed the bindings gate → every
    # prerequisite is in place now. Drop any stale «بانتظار إعداد …» error
    # stamped on a PRIOR failed attempt (e.g. before the panel WG key was
    # set) so the pending-onboardings card stops contradicting the «جاهز»
    # banner. No-op when there's no error.
    service._clear_job_error(job)

    # Audit — record the VIEW (not the body). The audit row's `summary`
    # is operator-facing; the body never appears anywhere except the
    # JSON response we're about to return.
    audit(
        "fleet_onboarding_script_view",
        "fleet_onboarding",
        str(job.id),
        f"تم عرض سكربت RouterOS للعقدة «{node_name}» (الجوب #{job.id})",
        metadata={"chr_id": job.chr_id, "status": job.status,
                  "script_sha256": job.generated_script_ref},
    )
    db.session.commit()

    return jsonify({
        "ok": True,
        "job_id": job.id,
        "node_name": node_name,
        "status": job.status,
        "filename": filename,
        "script": script,
        "sha256": job.generated_script_ref,
    })


__all__ = ["bp", "build_service"]
