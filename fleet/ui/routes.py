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

from flask import Blueprint, current_app, flash, jsonify, redirect, render_template, request, url_for

from app.auth.routes import audit, login_required, super_admin_required
from app.extensions import db
from app.services.whatsapp.crypto import WhatsAppCryptoError
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
from fleet.dns.settings_store import (
    MODE_LABELS_AR,
    MODE_VALUES,
    clear_token,
    load_view as load_frontdoor_view,
    save_mode,
    save_token,
)
from fleet.ui.dns_reconciler_view import (
    preview as dns_preview,
    reconcile_now as dns_reconcile_now,
    reconciler_available,
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

    # fix/fleet-onboarding-visibility: surface in-flight onboarding jobs on
    # the dashboard. Without this card, a job whose auto-advance failed
    # (e.g. vault key missing) is invisible — the owner clicks «إرسال» and
    # sees nothing. We expose every non-terminal job (everything except
    # ``active`` — terminal-success — and pure failure rows that have
    # already been retried) ordered newest-first.
    from fleet.registry.models_onboarding import OnboardingJob
    pending_states = ("draft", "keys_generated", "script_generated",
                      "pushed", "verifying", "failed")
    pending_jobs = (
        OnboardingJob.query
        .filter(OnboardingJob.status.in_(pending_states))
        .order_by(OnboardingJob.id.desc())
        .limit(20)
        .all()
    )
    # A job whose linked CHR node is already connected/live has, from the
    # operator's point of view, FINISHED onboarding — the node already shows
    # under «العقد» and «الترتيب». Keep it out of «قيد التنفيذ» so a working,
    # connected node never keeps nagging as "in-progress". This is a
    # presentation-only filter: the job row stays in the DB for audit, and we
    # never force an illegal state-machine jump (script_generated→active).
    live_node_ids = {
        v.node.id for v in node_views if v.health.state in ("up", "degraded")
    }
    pending_job_views = [
        _onboarding_job_view(j)
        for j in pending_jobs
        if not (j.chr_id and j.chr_id in live_node_ids)
    ]

    # ── Overview aggregates (read-only, derived from the same node_views) ──
    # Power the redesigned overview tab: a health-distribution bar + a
    # capacity/sessions panel that fill the space the bare KPI strip left
    # empty. Pure presentation roll-ups — no new queries, no model changes.
    ov_sessions = 0
    ov_capacity = 0
    for v in node_views:
        s = v.metric.active_sessions
        if s is None:
            s = v.node.active_sessions or 0
        ov_sessions += int(s or 0)
        ov_capacity += int(v.node.max_sessions or 0)
    ov_views = len(node_views)
    overview_stats = {
        "sessions": ov_sessions,
        "capacity": ov_capacity,
        "util_pct": round(ov_sessions * 100 / ov_capacity) if ov_capacity else 0,
        "eligible": eligible_count,
        "online_pct": round(by_health.get("up", 0) * 100 / ov_views) if ov_views else 0,
    }
    best_rank = ranking[0] if ranking and ranking[0].eligible else None

    # The settings#chr singleton cross-reference banner is gone — the
    # singleton itself was retired in the zero-central work; there's no
    # longer "another place" the same CHR could be configured. The
    # template still reads ``singleton_chr_match`` (it just renders
    # nothing) so we keep the variable but always set None.
    singleton_match = None

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
        pending_jobs=pending_job_views,
        pending_jobs_count=len(pending_job_views),
        overview_stats=overview_stats,
        best_rank=best_rank,
        singleton_chr_match=singleton_match,
    )


# Arabic labels + "what does this status MEAN" + "what's the next step?".
# Kept here (not in models_onboarding) so the model stays decoupled from UI
# strings. Both fields used by fix/fleet-script-view-instructions to make
# the pending card transparent — no more opaque states for the owner.
_ONBOARDING_STATUS_AR = {
    "draft":            "مسودة",
    "keys_generated":   "تم توليد المفاتيح",
    "script_generated": "تم توليد السكربت",
    "pushed":           "تم الدفع للعقدة",
    "verifying":        "قيد التحقّق",
    "active":           "نشطة",
    "failed":           "فشلت",
}

_ONBOARDING_STATUS_MEANING_AR = {
    "draft":            "سجلت اللوحة بياناتك ولم تبدأ بعد بتوليد المفاتيح.",
    "keys_generated":   "أُنشئت مفاتيح WireGuard على اللوحة، والعقدة جاهزة لتوليد السكربت.",
    "script_generated": "السكربت الكامل لـ RouterOS جاهز للتطبيق على المايكروتيك.",
    "pushed":           "دُفع السكربت إلى المايكروتيك عبر قناة الإقلاع لمرّة واحدة.",
    "verifying":        "تتحقق اللوحة من أن العقدة تتصل عبر wg-mgmt وأن RADIUS يعمل.",
    "active":           "العقدة فعّالة ضمن الأسطول وتستقبل جلسات RADIUS عبر الجسر.",
    "failed":           "فشلت إحدى مراحل الإعداد — راجع سبب الخطأ أدناه ثم أعد المحاولة.",
}

_ONBOARDING_NEXT_STEP_AR = {
    "draft":            "اضغط «متابعة» لتوليد المفاتيح وعقدة CHR الأولية.",
    "keys_generated":   "اضغط «متابعة» لتوليد السكربت ثم «عرض السكربت» لتثبيته على المايكروتيك.",
    "script_generated": "اضغط «عرض السكربت» لنسخه/تنزيله وتثبيته على المايكروتيك.",
    "pushed":           "اللوحة تتابع — لا حاجة لإجراء يدوي.",
    "verifying":        "في انتظار اتصال wg-mgmt من العقدة. تأكّد أن السكربت يعمل عليها.",
    "active":           "كل شيء يعمل — العقدة فعّالة.",
    "failed":           "اضغط «إعادة المحاولة» بعد إصلاح السبب، أو «حذف» للإلغاء.",
}


# Statuses where «عرض السكربت» can be shown on the row (the renderer needs a
# linked chr_id and at least a WireGuard keypair to work). Mirrors
# ``_SCRIPT_VIEW_OK_STATUSES`` in fleet/registry/routes_onboarding.py.
_STATUSES_WITH_SCRIPT = frozenset({
    "keys_generated", "script_generated", "pushed", "verifying", "active",
})

# Ordinal position of each status along the onboarding pipeline, used by the
# dashboard's «قيد التنفيذ» stepper to light up completed vs upcoming stages.
# ``failed`` has no position (rendered as its own red state).
_STATUS_STEP_INDEX = {
    "draft":            0,
    "keys_generated":   1,
    "script_generated": 2,
    "pushed":           3,
    "verifying":        4,
    "active":           5,
}


def _onboarding_job_view(job) -> dict:
    """Plain-dict view of an OnboardingJob for the dashboard template."""
    form = job.form_input or {}
    status = job.status
    has_script = bool(job.chr_id) and status in _STATUSES_WITH_SCRIPT
    # Suppress a stale «بانتظار إعداد …» error once the script has actually
    # generated: a successful render proves every prerequisite (panel WG key,
    # endpoints, secret) is in place, so the old waiting-message would only
    # contradict the «جاهز» banner. Real, non-waiting errors still show.
    last_error = form.get("last_error")
    if last_error and has_script and "بانتظار" in last_error:
        last_error = None
    return {
        "id": job.id,
        "status": status,
        "status_label": _ONBOARDING_STATUS_AR.get(status, status),
        "status_meaning": _ONBOARDING_STATUS_MEANING_AR.get(status, ""),
        "next_step": _ONBOARDING_NEXT_STEP_AR.get(status, ""),
        "step_index": _STATUS_STEP_INDEX.get(status, 0),
        "is_failed": status == "failed",
        "has_script": has_script,
        "chr_id": job.chr_id,
        "provider": form.get("provider") or "—",
        "name": form.get("name") or f"#{job.id}",
        "public_ip": form.get("public_ip") or "—",
        "last_error": last_error,
        "created_at": job.created_at.isoformat() + "Z" if getattr(job, "created_at", None) else None,
    }


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


@bp.get("/troubleshoot")
@login_required
def fleet_troubleshoot_index():
    """Per-CHR troubleshooter — every node side-by-side.

    Answers the four end-to-end checks the operator needs after adding a
    CHR from the wizard:

      * wg-mgmt IP / derived wg-data IP
      * Proxy recognition (chr_nodes[].wg_data_ip published?)
      * PPP pool not colliding with the reserved /24s
      * RADIUS reachability hint (Reject vs timeout)

    The page is read-only (no actions); each row links to the node-detail
    page for fixes.
    """
    from fleet.ui.troubleshoot_view import build_all_views
    views = build_all_views()
    return render_template(
        "admin/fleet/troubleshoot.html",
        views=views,
        any_blockers=any(not v.all_green for v in views),
    )


@bp.get("/troubleshoot/<int:node_id>.json")
@login_required
def fleet_troubleshoot_node_json(node_id: int):
    """JSON view for the dashboard JS auto-refresh."""
    from fleet.ui.troubleshoot_view import build_view
    node = db.session.get(FleetChrNode, node_id)
    if node is None:
        return jsonify({"ok": False, "error": "not_found"}), 404
    return jsonify({"ok": True, "view": build_view(node).to_dict()})


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


# ════════════════════════════════════════════════════════════════════════════
# Phase 6 / task C — Front-door (Cloudflare DNS) settings page.
#
# SECURITY:
#   * The Cloudflare API token is encrypted at rest with the existing
#     WHATSAPP_FERNET_KEY (see fleet.dns.settings_store).
#   * The plaintext token is ONLY accepted from the POST form; it is read into
#     a local, handed to ``save_token`` (which encrypts and writes), and the
#     reference is dropped on function return. It is NEVER:
#       - logged (no current_app.logger calls in this path);
#       - echoed in the response (the redirect target is the same form page,
#         which re-renders from ``load_view`` and therefore only ever shows
#         the masked ciphertext);
#       - included in a URL (POST-redirect-GET pattern).
#   * The "تغيير" flow does a clear-then-redirect so the operator's next view
#     shows the empty input + the «لم يُضبط» banner.
# ════════════════════════════════════════════════════════════════════════════


@bp.get("/dns/")
@login_required
def dns_frontdoor():
    """Render the front-door settings page (masked token + mode switch)."""
    view = load_frontdoor_view()
    return render_template(
        "admin/fleet/frontdoor.html",
        view=view,
        mode_choices=[(v, MODE_LABELS_AR[v]) for v in MODE_VALUES],
        reconciler_imported=reconciler_available(),
    )


@bp.post("/dns/token")
@login_required
def dns_frontdoor_token_save():
    """Accept a new token (POST-redirect-GET)."""
    # We deliberately do NOT log request.form here, ever.
    plaintext = (request.form.get("cloudflare_api_token") or "").strip()
    if not plaintext:
        flash("الرجاء لصق توكن Cloudflare قبل الحفظ.", "error")
        return redirect(url_for("fleet_ui.dns_frontdoor"))
    try:
        save_token(plaintext)
    except WhatsAppCryptoError:
        flash("لم يُضبط مفتاح التشفير على الخادم — راجع إعداد WHATSAPP_FERNET_KEY.", "error")
        return redirect(url_for("fleet_ui.dns_frontdoor"))
    except Exception:  # noqa: BLE001 - never reveal what failed in token paths
        flash("تعذّر حفظ التوكن — تحقق من اللوحة وأعد المحاولة.", "error")
        return redirect(url_for("fleet_ui.dns_frontdoor"))
    finally:
        # Drop the local reference. CPython has no secure-erase primitive but
        # keeping the binding alive after the redirect serves no purpose.
        plaintext = ""
    flash("تم حفظ توكن Cloudflare بشكل مُشفّر. لا يظهر النص الأصلي في أي مكان.", "success")
    return redirect(url_for("fleet_ui.dns_frontdoor"))


@bp.post("/dns/token/clear")
@login_required
def dns_frontdoor_token_clear():
    """Wipe the stored token (used by the «تغيير» button)."""
    clear_token()
    flash("تم مسح التوكن. أدخِل توكناً جديداً للمتابعة.", "warning")
    return redirect(url_for("fleet_ui.dns_frontdoor"))


@bp.post("/dns/mode")
@login_required
def dns_frontdoor_mode_save():
    """Persist the free/paid mode."""
    mode = (request.form.get("mode") or "").strip().lower()
    if mode not in MODE_VALUES:
        flash("قيمة الوضع غير صحيحة.", "error")
        return redirect(url_for("fleet_ui.dns_frontdoor"))
    save_mode(mode)
    flash(f"تم تعديل وضع التشغيل: {MODE_LABELS_AR[mode]}.", "success")
    return redirect(url_for("fleet_ui.dns_frontdoor"))


@bp.post("/dns/preview")
@login_required
def dns_frontdoor_preview():
    """Dry-run — never touches Cloudflare. Returns JSON for the page JS."""
    return jsonify({"ok": True, "preview": dns_preview()})


@bp.post("/dns/apply")
@login_required
def dns_frontdoor_apply():
    """Ask the reconciler to publish. Returns JSON for the page JS."""
    return jsonify({"ok": True, "result": dns_reconcile_now()})


# ════════════════════════════════════════════════════════════════════════════
# feat/fleet-infrastructure-settings — «إعدادات بنية الأسطول»
#
# The page the «بانتظار إعداد» pending-card error message points to. Captures
# the five required fleet-constants (panel + proxy WireGuard, RADIUS secret)
# and the two optional cert names, writes them to ``Setting`` rows, which
# ``OnboardingService._const`` reads BEFORE app.config / defaults. Once all
# five required values are stored, the validator's «بانتظار» clears and
# render_script succeeds without any other code change.
#
# Auth: super_admin_required across the board (these settings affect every
# CHR in the fleet). Every mutator is audited.
# ════════════════════════════════════════════════════════════════════════════


def _infra_redirect():
    return redirect(url_for("fleet_ui.fleet_infrastructure"))


@bp.get("/infrastructure")
@super_admin_required
def fleet_infrastructure():
    """Render the «إعدادات بنية الأسطول» page."""
    from fleet.registry import infra_settings as svc
    from fleet.health.routeros_creds import fleet_default_view
    return render_template(
        "admin/fleet/infrastructure.html",
        view=svc.view_all(),
        ready=svc.is_fleet_ready(),
        missing=svc.missing_required(),
        panel_pubkey=svc.panel_pubkey_for_display(),
        panel_pubkey_is_set=svc.panel_pubkey_is_set(),
        metrics_creds=fleet_default_view(),
        panel_privkey_on_server=svc.panel_privkey_is_on_server(),
    )


@bp.post("/infrastructure/panel-keypair")
@super_admin_required
def fleet_infra_generate_panel_keypair():
    """Mint a new wg-mgmt keypair on the panel. Stores the private side
    encrypted; returns only the public side for the UI flash."""
    from fleet.registry import infra_settings as svc
    try:
        result = svc.generate_panel_wg_keypair()
    except svc.InfraSettingsError as exc:
        flash(str(exc), "error")
        return _infra_redirect()
    except WhatsAppCryptoError:
        flash("لم يُضبط مفتاح التشفير على الخادم — راجع إعداد WHATSAPP_FERNET_KEY.", "error")
        return _infra_redirect()
    audit(
        "fleet_infra_panel_keypair_generated", "fleet_infra", "PANEL_WG_PUBKEY",
        "تم توليد زوج مفاتيح wg-mgmt للوحة"
        + (" — أُعيد التوليد (السكربتات السابقة لم تعد صالحة)" if result["regenerated"] else ""),
        metadata={"regenerated": result["regenerated"]},
    )
    db.session.commit()
    if result["regenerated"]:
        # KEY DRIFT CASCADE (feat/fleet-zero-touch-sync): the panel key is the
        # single stable source of truth; a deliberate regen MUST trigger a fleet
        # re-push. Flag every node needs_reimport and kick off a re-sync job so
        # the owner sees live staged progress instead of silent drift.
        flagged = _cascade_panel_key_change()
        flash(
            "تم توليد زوج مفاتيح اللوحة الجديد. ⚠ السكربتات الصادرة سابقاً "
            f"للعقد لم تعد صالحة — وُسِمت {len(flagged)} عقدة لإعادة الاستيراد "
            "وبدأت «إعادة مزامنة الأسطول». أعد إنشاء سكربت كل عقدة من «عرض السكربت».",
            "warning",
        )
    else:
        flash("تم توليد زوج مفاتيح اللوحة بنجاح.", "success")
    return _infra_redirect()


def _cascade_panel_key_change() -> list[str]:
    """Panel wg-mgmt key changed → flag every node stale + start a re-sync job.

    Idempotent + defensive: never lets a cascade failure break the key-change
    response (the flag is the durable signal; the job is a convenience)."""
    flagged: list[str] = []
    try:
        from fleet.sync.keys import flag_fleet_needs_reimport
        flagged = flag_fleet_needs_reimport()
    except Exception:  # noqa: BLE001
        db.session.rollback()
    try:
        from fleet.sync.service import create_job
        create_job(scope="fleet")
    except Exception:  # noqa: BLE001 — job is best-effort; flag already persisted
        db.session.rollback()
    return flagged


@bp.post("/infrastructure/panel-pubkey")
@super_admin_required
def fleet_infra_save_panel_pubkey():
    """Accept a panel WG public key the operator pasted in from the host
    where they ran ``wg genkey | wg pubkey``. Preferred over the server-side
    «توليد» path because the private key never leaves the host.

    If the server previously minted a keypair (private side encrypted in DB),
    this also wipes that ciphertext row — the host's privkey is now the only
    authoritative copy."""
    from fleet.registry import infra_settings as svc
    try:
        result = svc.set_panel_pubkey(request.form.get("panel_pubkey") or "")
    except svc.InfraSettingsError as exc:
        flash(str(exc), "error")
        return _infra_redirect()
    audit(
        "fleet_infra_panel_pubkey_pasted", "fleet_infra", "PANEL_WG_PUBKEY",
        "تم لصق المفتاح العام للوحة يدوياً"
        + (" — تم حذف المفتاح الخاص الذي وُلِّد سابقاً على الخادم" if result["cleared_server_privkey"] else ""),
        metadata=result,
    )
    db.session.commit()
    if result["cleared_server_privkey"]:
        flash(
            "تم حفظ المفتاح العام، وأُزيل المفتاح الخاص الذي وُلِّد سابقاً على الخادم. "
            "المفتاح الخاص الآن هو الذي لديك على المضيف فقط.",
            "success",
        )
    elif result["replaced"]:
        flagged = _cascade_panel_key_change()
        flash(
            "⚠ تم استبدال المفتاح العام للوحة — السكربتات السابقة للعقد لم تعد صالحة. "
            f"وُسِمت {len(flagged)} عقدة لإعادة الاستيراد وبدأت «إعادة مزامنة الأسطول».",
            "warning",
        )
    else:
        flash("تم حفظ المفتاح العام للوحة.", "success")
    return _infra_redirect()


@bp.post("/infrastructure/panel-privkey/reveal")
@super_admin_required
def fleet_infra_reveal_panel_privkey():
    """ONE-TIME reveal of the server-stored panel WG private key so the
    operator can install it in ``/etc/wireguard/wg-mgmt.conf`` on the panel
    host. Audited loudly: this is the single legitimate moment the private
    side ever leaves the vault. Re-clicking simply reveals it again — the
    audit row records every reveal so an unexpected one is traceable."""
    from fleet.registry import infra_settings as svc
    from fleet.health.routeros_creds import fleet_default_view as _fleet_default_view
    try:
        privkey = svc.get_panel_wg_private_key_decrypted()
    except svc.InfraSettingsError as exc:
        flash(str(exc), "error")
        return _infra_redirect()
    except WhatsAppCryptoError:
        flash("لم يُضبط مفتاح التشفير على الخادم — تعذّر فكّ مفتاح اللوحة الخاص.", "error")
        return _infra_redirect()
    audit(
        "fleet_infra_panel_privkey_revealed", "fleet_infra", "PANEL_WG_PRIVKEY",
        "كُشف المفتاح الخاص للوحة لمستخدم super-admin (نسخه ولصقه على مضيف اللوحة)",
        metadata={"reason": "operator install on panel host"},
    )
    db.session.commit()
    # The private key goes back to the page via a one-shot flash — the
    # template wraps it in a copy-then-clear modal so it doesn't linger on
    # screen or in browser history (page is super-admin only anyway).
    return render_template(
        "admin/fleet/infrastructure.html",
        view=svc.view_all(),
        ready=svc.is_fleet_ready(),
        missing=svc.missing_required(),
        panel_pubkey=svc.panel_pubkey_for_display(),
        panel_pubkey_is_set=svc.panel_pubkey_is_set(),
        panel_privkey_on_server=svc.panel_privkey_is_on_server(),
        revealed_panel_privkey=privkey,
        # The metrics-credentials card is part of this page (live-metrics
        # feature); pass its view so the reveal re-render isn't missing it.
        metrics_creds=_fleet_default_view(),
    )


@bp.post("/infrastructure/panel-endpoint")
@super_admin_required
def fleet_infra_save_panel_endpoint():
    from fleet.registry import infra_settings as svc
    try:
        svc.set_panel_endpoint(request.form.get("panel_endpoint") or "")
    except svc.InfraSettingsError as exc:
        flash(str(exc), "error")
        return _infra_redirect()
    audit("fleet_infra_panel_endpoint_set", "fleet_infra", "PANEL_WG_ENDPOINT",
          "تم حفظ نقطة وصول اللوحة")
    db.session.commit()
    flash("تم حفظ نقطة وصول اللوحة.", "success")
    return _infra_redirect()


@bp.post("/infrastructure/proxy-pubkey")
@super_admin_required
def fleet_infra_save_proxy_pubkey():
    from fleet.registry import infra_settings as svc
    try:
        svc.set_proxy_pubkey(request.form.get("proxy_pubkey") or "")
    except svc.InfraSettingsError as exc:
        flash(str(exc), "error")
        return _infra_redirect()
    audit("fleet_infra_proxy_pubkey_set", "fleet_infra", "PROXY_WG_PUBKEY",
          "تم حفظ مفتاح وكيل RADIUS العام")
    db.session.commit()
    flash("تم حفظ مفتاح الوكيل العام.", "success")
    return _infra_redirect()


@bp.post("/infrastructure/proxy-endpoint")
@super_admin_required
def fleet_infra_save_proxy_endpoint():
    from fleet.registry import infra_settings as svc
    try:
        svc.set_proxy_endpoint(request.form.get("proxy_endpoint") or "")
    except svc.InfraSettingsError as exc:
        flash(str(exc), "error")
        return _infra_redirect()
    audit("fleet_infra_proxy_endpoint_set", "fleet_infra", "PROXY_WG_ENDPOINT",
          "تم حفظ نقطة وصول الوكيل")
    db.session.commit()
    flash("تم حفظ نقطة وصول الوكيل.", "success")
    return _infra_redirect()


@bp.post("/infrastructure/radius-secret")
@super_admin_required
def fleet_infra_save_radius_secret():
    from fleet.registry import infra_settings as svc
    form_value = (request.form.get("chr_shared_secret") or "").strip()
    auto = bool(request.form.get("auto_generate"))
    try:
        if auto:
            svc.generate_chr_shared_secret()
            audit("fleet_infra_radius_secret_generated", "fleet_infra", "CHR_SHARED_SECRET",
                  "تم توليد السر المشترك لـ RADIUS تلقائياً")
            db.session.commit()
            flash("تم توليد سرّ قوي وحفظه مشفّراً.", "success")
        else:
            svc.set_chr_shared_secret(form_value)
            audit("fleet_infra_radius_secret_set", "fleet_infra", "CHR_SHARED_SECRET",
                  "تم تحديث السر المشترك لـ RADIUS")
            db.session.commit()
            flash(
                "تم حفظ السرّ مشفّراً. تذكّر أن تضبط القيمة نفسها على الوكيل "
                "(PROXY_CHR_SECRET).",
                "success",
            )
    except svc.InfraSettingsError as exc:
        flash(str(exc), "error")
    except WhatsAppCryptoError:
        flash("لم يُضبط مفتاح التشفير على الخادم — راجع إعداد WHATSAPP_FERNET_KEY.", "error")
    return _infra_redirect()


@bp.post("/infrastructure/cert-names")
@super_admin_required
def fleet_infra_save_cert_names():
    from fleet.registry import infra_settings as svc
    try:
        svc.set_cert_name("SSTP_CERT_NAME", request.form.get("sstp_cert_name") or "")
        svc.set_cert_name("IKE_CERT_NAME", request.form.get("ike_cert_name") or "")
    except svc.InfraSettingsError as exc:
        flash(str(exc), "error")
        return _infra_redirect()
    audit("fleet_infra_cert_names_set", "fleet_infra", "CERTS",
          "تم تحديث أسماء شهادات SSTP/IKEv2")
    db.session.commit()
    flash("تم حفظ أسماء الشهادات. (اتركها فارغة لتخطّي SSTP/IPsec في السكربت.)", "success")
    return _infra_redirect()


# ════════════════════════════════════════════════════════════════════════
# Live-metrics credentials — fleet defaults + per-node overrides + poll-now
# ════════════════════════════════════════════════════════════════════════
#
# These three routes complete the live-metrics UI loop: the operator can
# enter the read-only RouterOS API username + password from the panel
# (no terminal), per-node or fleet-wide, then click «اقرأ المقاييس الآن»
# to verify before the 60-second background pass.

@bp.post("/infrastructure/metrics-creds")
@super_admin_required
def fleet_infra_save_metrics_creds():
    """Save the fleet-default API user + password for the live-metrics poller.

    The plaintext password is read from the form, written through
    :mod:`fleet.health.routeros_creds` (Fernet-encrypted at rest), and
    flashed back as a masked chip. Empty password keeps the existing
    value — same convention as every other password form on the panel.
    """
    from fleet.health.routeros_creds import (
        get_default_password_plaintext,
        set_default_password,
        set_default_user,
    )
    user = (request.form.get("api_user") or "").strip()
    password = request.form.get("api_password") or ""
    if not user:
        flash("اسم المستخدم مطلوب — اتركه «hobe-panel» إن أردت الافتراضي.", "error")
        return _infra_redirect()
    try:
        set_default_user(user)
        if password:
            set_default_password(password)
    except WhatsAppCryptoError:
        flash("لم يُضبط مفتاح التشفير على الخادم — راجع WHATSAPP_FERNET_KEY.", "error")
        return _infra_redirect()
    audit(
        "fleet_metrics_creds_set", "fleet_infra", "METRICS_CREDS",
        "تم حفظ بيانات اعتماد قراءة المقاييس الافتراضية",
        metadata={"user": user, "password_changed": bool(password)},
    )
    db.session.commit()
    has_pwd = bool(get_default_password_plaintext())
    if has_pwd:
        flash(
            "تم حفظ بيانات اعتماد قراءة المقاييس. أعد توليد سكربت كل عقدة "
            "حتى يُنشَأ المستخدم القارئ على CHR.",
            "success",
        )
    else:
        flash(
            "تم حفظ اسم المستخدم — لم تُضبط كلمة المرور بعد، فستظل المقاييس "
            "الحيّة معطّلة حتى تُدخلها هنا.",
            "warning",
        )
    return _infra_redirect()


@bp.post("/chr-nodes/<int:node_id>/metrics-creds")
@super_admin_required
def fleet_chr_node_save_metrics_creds(node_id: int):
    """Save per-node API credentials override OR clear them.

    The form has two modes:

    * ``mode="set"`` (default) — write the supplied user + password
      (encrypted) onto the FleetChrNode row. Empty password is rejected
      so an accidental submit doesn't erase a working override.
    * ``mode="clear"`` — wipe the override so the node falls back to the
      fleet default again.

    Returns a JSON envelope so the dashboard's inline form can flash a
    toast without a full reload.
    """
    from fleet.health.routeros_creds import (
        clear_credentials,
        credentials_for,
        node_creds_view,
        set_credentials,
    )
    from fleet.registry.models_chr import FleetChrNode

    node = db.session.get(FleetChrNode, node_id)
    if node is None:
        return jsonify({"ok": False, "error": "not_found"}), 404

    mode = (request.form.get("mode") or "set").lower()
    if mode == "clear":
        clear_credentials(node)
        audit(
            "fleet_metrics_creds_node_cleared", "fleet_chr_node", str(node_id),
            f"تم حذف بيانات اعتماد المقاييس الخاصة بـ {node.name}",
            metadata={"node": node.name},
        )
        db.session.commit()
        return jsonify({"ok": True, "view": node_creds_view(node)})

    user = (request.form.get("api_user") or "").strip()
    password = request.form.get("api_password") or ""
    port_raw = (request.form.get("api_port") or "").strip()

    if not user or not password:
        return jsonify({
            "ok": False, "error": "missing_credentials",
            "detail": "اسم المستخدم وكلمة المرور مطلوبان.",
        }), 400
    try:
        if port_raw:
            node.routeros_api_port = max(1, min(65535, int(port_raw)))
    except ValueError:
        return jsonify({
            "ok": False, "error": "bad_port",
            "detail": "المنفذ يجب أن يكون رقماً بين 1 و65535.",
        }), 400
    try:
        set_credentials(node, username=user, password=password)
    except WhatsAppCryptoError:
        return jsonify({
            "ok": False, "error": "crypto_unavailable",
            "detail": "لم يُضبط مفتاح التشفير على الخادم — راجع WHATSAPP_FERNET_KEY.",
        }), 500
    audit(
        "fleet_metrics_creds_node_set", "fleet_chr_node", str(node_id),
        f"تم تحديث بيانات اعتماد المقاييس لـ {node.name}",
        metadata={"node": node.name, "user": user, "port": node.routeros_api_port},
    )
    db.session.commit()
    return jsonify({
        "ok": True, "view": node_creds_view(node),
        "effective_ready": credentials_for(node) is not None,
    })


@bp.post("/chr-nodes/<int:node_id>/verify-wg")
@super_admin_required
def fleet_chr_node_verify_wg(node_id: int):
    """Both-directions WireGuard key verification (panel ↔ CHR) over REST.

    Field-incident armour: a wrong panel pubkey on the CHR's wg-mgmt peer
    used to be invisible until everything downstream failed. This endpoint
    answers «هل المفاتيح متطابقة؟» in one click, with both keys echoed so
    the operator can eyeball the diff. JSON for the dashboard JS toast.
    """
    from fleet.health.wg_verify import verify_node_wg_identity
    from fleet.registry.models_chr import FleetChrNode

    node = db.session.get(FleetChrNode, node_id)
    if node is None:
        return jsonify({"ok": False, "error": "not_found"}), 404
    result = verify_node_wg_identity(node)
    status = 200 if result.ok else 409
    return jsonify(result.to_dict()), status


@bp.post("/chr-nodes/<int:node_id>/poll-metrics-now")
@super_admin_required
def fleet_chr_node_poll_metrics_now(node_id: int):
    """On-demand single-node poll. Bypasses the 60-second worker cycle.

    Returns the resulting :class:`PollSummary` + a refreshed
    :class:`NodeView` for the dashboard JS to splice into the row.
    """
    from fleet.health.metrics_poller import poll_all
    from fleet.health.routeros_creds import credentials_diagnostics, credentials_for
    from fleet.registry.models_chr import FleetChrNode

    node = db.session.get(FleetChrNode, node_id)
    if node is None:
        return jsonify({"ok": False, "error": "not_found"}), 404
    if credentials_for(node) is None:
        # Precise per-source verdict — «which credential source is broken»
        # was the field gap: a Fernet decrypt failure looked identical to
        # "never configured" and sent the operator to the wrong screen.
        diag = credentials_diagnostics(node)
        return jsonify({
            "ok": False, "error": "no_credentials",
            "reason_code": diag["reason_code"],
            "detail": diag["message_ar"],
            "node_password_state": diag["node_password_state"],
            "fleet_password_state": diag["fleet_password_state"],
        }), 409

    # Restrict the pass to this one node by skipping siblings without
    # creds AT the poll_all layer — but we already filter on credentials,
    # so to keep the on-demand button cheap we directly target the node
    # via a one-shot eligibility filter override.
    target_id = node.id

    def _solo_collector(n):
        if n.id != target_id:
            from fleet.health.routeros_collector import Sample
            return Sample(error="not_targeted")
        from fleet.health.routeros_collector import collect as _real
        return _real(n)

    summary = poll_all(collector=_solo_collector)
    row = _node_view_to_payload(get_node_view(node))
    return jsonify({
        "ok": True,
        "summary": {
            "checked": summary.checked,
            "ok_count": summary.ok_count,
            "error_count": summary.error_count,
            "errors": [list(t) for t in summary.errors],
        },
        "row": row,
    })


__all__ = ["bp"]
