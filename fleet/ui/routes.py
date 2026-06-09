"""fleet.ui.routes — admin pages for the CHR Fleet (dashboard + onboarding wizard).

Blueprint ``fleet_ui`` rooted at ``/admin/fleet``. Pages here render Jinja
templates that live under ``app/templates/admin/fleet/`` and reuse the existing
hub/uds design tokens from ``admin/base_new.html`` — visual parity with the rest
of the admin app is the point.

Endpoints
---------
* ``GET /admin/fleet/``                       fleet dashboard (list + KPIs).
* ``GET /admin/fleet/onboarding/new``        the multi-step onboarding wizard.

The wizard is server-rendered HTML; its multi-step UX is driven by
``app/static/js/admin_fleet_wizard.js``. When the user clicks the final
"إرسال" the JS POSTS the collected form (JSON) to the onboarding state-
machine endpoint owned by the sibling agent
(``POST {{ONBOARDING_URL}}`` — default ``/admin/fleet/onboarding/jobs``).
"""

from __future__ import annotations

from flask import Blueprint, current_app, render_template

from app.auth.routes import login_required
from app.extensions import db
from fleet.registry.models_chr import (
    NODE_COST_MODELS,
    FleetChrNode,
    FleetProvider,
)


bp = Blueprint(
    "fleet_ui",
    __name__,
    url_prefix="/admin/fleet",
)


@bp.get("/")
@login_required
def fleet_dashboard():
    """Top-level dashboard for the CHR fleet.

    Pulls a compact roll-up from the registry (counts by status) and the latest
    nodes so the operator lands on something meaningful even before metrics
    flow. Heavy charts/scoring views land in a later phase.
    """
    nodes = (
        FleetChrNode.query
        .order_by(FleetChrNode.status.asc(), FleetChrNode.name.asc())
        .limit(50)
        .all()
    )
    providers = FleetProvider.query.order_by(FleetProvider.name.asc()).all()
    by_status = {s: 0 for s in ("up", "degraded", "down", "disabled", "provisioning")}
    for n in nodes:
        by_status[n.status] = by_status.get(n.status, 0) + 1
    return render_template(
        "admin/fleet/dashboard.html",
        nodes=nodes,
        providers=providers,
        by_status=by_status,
        total_nodes=FleetChrNode.query.count(),
        total_providers=len(providers),
    )


@bp.get("/onboarding/new")
@login_required
def onboarding_wizard():
    """Render the onboarding wizard. All required option lists are passed in
    so the JS doesn't have to make a second round-trip just to render the
    provider dropdown."""
    providers = FleetProvider.query.order_by(FleetProvider.name.asc()).all()
    return render_template(
        "admin/fleet/onboarding_wizard.html",
        providers=providers,
        cost_models=NODE_COST_MODELS,
        # The sibling agent's onboarding-API endpoint. Centralised here so a
        # rename on their side is a one-line change in template/JS, never a
        # scatter across the codebase.
        onboarding_api_url=current_app.config.get(
            "FLEET_ONBOARDING_API_URL", "/admin/fleet/onboarding/jobs"
        ),
        providers_api_url="/admin/fleet/providers",
    )


__all__ = ["bp"]
