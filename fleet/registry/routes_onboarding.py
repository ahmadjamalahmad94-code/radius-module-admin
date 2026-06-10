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
    node_removed = False
    if remove_node and job.chr_id is not None:
        node = db.session.get(FleetChrNode, job.chr_id)
        if node is not None:
            # Surface the node id in the audit summary so the operation is
            # auditable even after the rows are gone.
            db.session.delete(node)
            node_removed = True

    summary_name = (job.form_input or {}).get("name", f"#{job.id}")
    audit(
        "fleet_onboarding_delete",
        "fleet_onboarding",
        str(job.id),
        f"حذف جوب تسجيل «{summary_name}» (الحالة: {job.status})"
        + (f" + إزالة العقدة #{job.chr_id}" if node_removed else ""),
        metadata={"status": job.status, "chr_id": job.chr_id,
                  "node_removed": node_removed},
    )
    db.session.delete(job)
    db.session.commit()
    return jsonify({
        "ok": True,
        "deleted": True,
        "node_removed": node_removed,
        "job_id": job_id,
    })


def _stamp_job_error(job: OnboardingJob, message: str) -> None:
    """Mirror onboarding_service._stamp_job_error so a /advance failure
    leaves the same breadcrumb on the dashboard's pending card."""
    data = dict(job.form_input or {})
    data["last_error"] = (message or "")[:500]
    job.form_input = data
    db.session.add(job)
    db.session.commit()


__all__ = ["bp", "build_service"]
