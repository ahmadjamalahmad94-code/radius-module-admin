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

from flask import Blueprint, current_app, jsonify, render_template

from app.auth.routes import login_required
from app.extensions import db
from fleet.registry.models_chr import (
    NODE_COST_MODELS,
    FleetChrNode,
    FleetProvider,
)
from fleet.ui.dashboard_data import (
    build_node_views,
    check_now,
    get_node_view,
    health_state_counts,
)
from fleet.ui.brain_view import brain_available, ranked_view_for


bp = Blueprint(
    "fleet_ui",
    __name__,
    url_prefix="/admin/fleet",
)


@bp.get("/")
@login_required
def fleet_dashboard():
    """Top-level dashboard for the CHR fleet.

    Phase-4 / task C: each row now carries health (state, last_transition,
    state_since) + the latest telemetry sample (cpu, mem, sessions, RX/TX,
    ping). The per-row payload is composed by ``dashboard_data.build_node_views``
    so the template stays declarative and the data layer can be swapped to
    Phase-4 A/B's proper query helpers without touching this file.
    """
    nodes = (
        FleetChrNode.query
        .order_by(FleetChrNode.status.asc(), FleetChrNode.name.asc())
        .limit(50)
        .all()
    )
    providers = FleetProvider.query.order_by(FleetProvider.name.asc()).all()

    node_views = build_node_views(nodes)
    # Registry lifecycle counts (existing KPIs) — kept so disabled/provisioning
    # remain visible at-a-glance.
    by_status = {s: 0 for s in ("up", "degraded", "down", "disabled", "provisioning")}
    for n in nodes:
        by_status[n.status] = by_status.get(n.status, 0) + 1
    # Phase-4 addition: health-dimension counts (unknown/up/degraded/down).
    by_health = health_state_counts(node_views)

    # Phase-5 task C: explainable ranking. Prefer the real brain
    # (fleet.brain.rank) when importable, otherwise fall back to a local
    # computation that mirrors fleet.config.ScoringWeights so the dashboard
    # is meaningful on every branch of the parallel build matrix.
    ranking, ranking_source = ranked_view_for(node_views)
    eligible_count = sum(1 for r in ranking if r.eligible)

    return render_template(
        "admin/fleet/dashboard.html",
        nodes=nodes,                  # kept for backwards-compat refs
        node_views=node_views,
        providers=providers,
        by_status=by_status,
        by_health=by_health,
        ranking=ranking,
        ranking_source=ranking_source,
        ranking_eligible=eligible_count,
        brain_imported=brain_available(),
        total_nodes=FleetChrNode.query.count(),
        total_providers=len(providers),
    )


# ────────────────────────────────────────────────────────────────────────────
# Manual health-check triggers (P4 task C).
#
# Both endpoints return JSON so the dashboard JS can refresh affected rows
# without a full page reload. The work itself is delegated to
# ``fleet.ui.dashboard_data.check_now``, which prefers the proper monitor
# (``fleet.health.monitor.check_now`` once Phase-4 A/B lands) and falls back
# to a deterministic re-evaluation against the latest metric row.
# ────────────────────────────────────────────────────────────────────────────


@bp.post("/chr-nodes/<int:node_id>/check-now")
@login_required
def chr_node_check_now(node_id: int):
    """Re-evaluate ONE node's health and return the fresh row payload."""
    node = db.session.get(FleetChrNode, node_id)
    if node is None:
        return jsonify({"ok": False, "error": "not_found"}), 404
    result = check_now(node_id)
    # Build the row payload the dashboard JS plugs back into the table cell.
    row = _node_view_to_payload(get_node_view(node))
    return jsonify({"ok": True, "result": result, "row": row})


@bp.post("/chr-nodes/check-all")
@login_required
def chr_nodes_check_all():
    """Re-evaluate EVERY node. Returns per-id results + the full table dataset
    so the dashboard can rebuild rows in one render pass."""
    nodes = FleetChrNode.query.order_by(FleetChrNode.name.asc()).all()
    per_node: list[dict] = []
    for node in nodes:
        per_node.append({"id": node.id, "name": node.name, "result": check_now(node.id)})
    rows = [_node_view_to_payload(v) for v in build_node_views(nodes)]
    return jsonify({"ok": True, "count": len(nodes), "results": per_node, "rows": rows})


def _node_view_to_payload(view) -> dict:
    """Compact JSON payload for AJAX row refreshes — mirrors the template's
    row layout so the JS can swap fields by data-cell key without re-rendering
    HTML on the client."""
    n = view.node
    h = view.health
    m = view.metric
    return {
        "id": n.id,
        "name": n.name,
        "public_ip": n.public_ip,
        "provider_name": n.provider.name if n.provider else None,
        "status": n.status,
        "drain": bool(n.drain),
        "score": str(n.score) if n.score is not None else None,
        "cost_model": n.cost_model,
        "link_speed_mbps": n.link_speed_mbps,
        "max_sessions": n.max_sessions,
        "health": {
            "state": h.state,
            "state_since": h.state_since.isoformat() + "Z" if h.state_since else None,
            "last_transition": h.last_transition,
            "consecutive_fail": h.consecutive_fail,
            "consecutive_ok": h.consecutive_ok,
        },
        "metric": {
            "ts": m.ts.isoformat() + "Z" if m.ts else None,
            "cpu_pct": m.cpu_pct,
            "mem_pct": m.mem_pct,
            "active_sessions": m.active_sessions,
            "rx_bytes": m.rx_bytes,
            "tx_bytes": m.tx_bytes,
            "ping_rtt_ms": m.ping_rtt_ms,
            "ping_loss_pct": m.ping_loss_pct,
            "source": m.source,
        },
    }


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
