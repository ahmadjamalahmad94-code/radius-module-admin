"""fleet.registry.routes_provider — admin JSON API for fleet provider CRUD.

Phase 3 / P3-T6. Blueprint ``admin_fleet_provider`` (url_prefix
``/admin/fleet/providers``). Thin layer: parse request → call
:mod:`fleet.registry.provider_service` → ``jsonify``. All mutations are audited.

The blueprint is intentionally NOT registered here — the phase-gate integrator
wires it into ``app/__init__.py`` (so parallel Phase-3 agents never edit that
shared file). Tests register it onto a throwaway app.
"""
from __future__ import annotations

from flask import Blueprint, jsonify, request

from app.auth.routes import audit, login_required
from app.extensions import db
from fleet.registry import provider_service as svc

bp = Blueprint("admin_fleet_provider", __name__, url_prefix="/admin/fleet/providers")


def _error(exc: svc.ProviderError):
    """Map a ProviderError subclass to (json, http_status)."""
    if isinstance(exc, svc.ProviderNotFound):
        status = 404
    elif isinstance(exc, (svc.ProviderNameTaken, svc.ProviderInUse)):
        status = 409
    else:
        status = 400
    return jsonify({"ok": False, "error": type(exc).__name__, "message": str(exc)}), status


def _body() -> dict:
    return request.get_json(silent=True) or {}


@bp.get("")
@login_required
def list_providers():
    return jsonify({
        "ok": True,
        "providers": [svc.to_dict(p) for p in svc.list_providers()],
    })


@bp.get("/<int:provider_id>")
@login_required
def get_provider(provider_id: int):
    try:
        prov = svc.get_provider_or_404(provider_id)
    except svc.ProviderError as exc:
        return _error(exc)
    return jsonify({"ok": True, "provider": svc.to_dict(prov)})


@bp.post("")
@login_required
def create_provider():
    data = _body()
    try:
        prov = svc.create_provider(
            name=data.get("name"),
            cost_model=data.get("cost_model"),
            price_per_tb=data.get("price_per_tb", 0),
            monthly_cap_tb=data.get("monthly_cap_tb"),
            overage_allowed=data.get("overage_allowed", False),
            overage_price_per_tb=data.get("overage_price_per_tb"),
            billing_cycle_day=data.get("billing_cycle_day", 1),
            api_creds_ref=data.get("api_creds_ref"),
        )
    except svc.ProviderError as exc:
        return _error(exc)
    audit("fleet_provider_create", "fleet_provider", str(prov.id),
          f"إنشاء مزوّد «{prov.name}» ({prov.cost_model})")
    db.session.commit()
    return jsonify({"ok": True, "provider": svc.to_dict(prov)}), 201


@bp.post("/<int:provider_id>")
@login_required
def update_provider(provider_id: int):
    data = _body()
    # Only forward keys the caller actually sent (partial update).
    allowed = {
        "name", "cost_model", "price_per_tb", "monthly_cap_tb",
        "overage_allowed", "overage_price_per_tb", "billing_cycle_day",
        "api_creds_ref",
    }
    fields = {k: v for k, v in data.items() if k in allowed}
    try:
        prov = svc.update_provider(provider_id, **fields)
    except svc.ProviderError as exc:
        return _error(exc)
    audit("fleet_provider_update", "fleet_provider", str(prov.id),
          f"تعديل مزوّد «{prov.name}»", {"fields": sorted(fields.keys())})
    db.session.commit()
    return jsonify({"ok": True, "provider": svc.to_dict(prov)})


@bp.post("/<int:provider_id>/delete")
@login_required
def delete_provider(provider_id: int):
    try:
        prov = svc.get_provider_or_404(provider_id)
        name = prov.name
        svc.delete_provider(provider_id)
    except svc.ProviderError as exc:
        return _error(exc)
    audit("fleet_provider_delete", "fleet_provider", str(provider_id),
          f"حذف مزوّد «{name}»")
    db.session.commit()
    return jsonify({"ok": True, "deleted": provider_id})


__all__ = ["bp"]
