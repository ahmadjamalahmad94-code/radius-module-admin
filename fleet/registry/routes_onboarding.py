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

from app.auth.routes import audit, login_required
from app.extensions import db
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


__all__ = ["bp", "build_service"]
