"""fleet.notify.ui_routes — admin pages for the Phase-9 alerts feature.

Blueprint ``fleet_notify_ui`` rooted at ``/admin/fleet/alerts``:

* ``GET /admin/fleet/alerts/``         recent alerts feed + KPI strip
* ``POST /admin/fleet/alerts/<id>/ack`` mark a single alert as
  acknowledged (sets ``status='suppressed'`` so the dedupe slot frees up
  AND the row drops out of the active list).
* ``GET /admin/fleet/alerts/settings`` per-kind enable/disable + channel
  selection.
* ``POST /admin/fleet/alerts/settings`` save form.

The pages reuse the existing admin design tokens (``base_new.html``); no
native ``alert``/``confirm`` is used — acks go through a form POST and
flash a toast, the same pattern other admin pages follow.
"""
from __future__ import annotations

from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)

from app.auth.routes import login_required
from app.extensions import db
from app.models import utcnow

from .models_alert import Alert, Event
from .rules import KIND_LABELS
from .settings_store import (
    FLEET_CHANNELS,
    get_channels,
    get_kind_states,
    set_channels,
    set_kind_enabled,
)

bp = Blueprint(
    "fleet_notify_ui",
    __name__,
    url_prefix="/admin/fleet/alerts",
)


# ── helpers ───────────────────────────────────────────────────────────────

_SEVERITY_BY_KIND = {  # tiny dup so we don't run a rule for each row
    "health_down": "crit",
    "cap_breach": "crit",
    "failover_start": "warn",
    "cap_warn": "warn",
    "dns_suppressed": "warn",
    "move_fail": "warn",
    "onboard_fail": "warn",
    "flap_suppressed": "warn",
    "cost_cap_nearing": "warn",
}


def _severity(event_kind: str) -> str:
    return _SEVERITY_BY_KIND.get(event_kind, "info")


def _alert_view(row: Alert, event: Event | None) -> dict:
    kind = (event.kind if event else "")
    return {
        "id": row.id,
        "created_at": row.created_at.strftime("%Y-%m-%d %H:%M") if row.created_at else "",
        "channel": row.channel,
        "recipient": row.recipient,
        "status": row.status,
        "body": row.body,
        "dedupe_key": row.dedupe_key or "",
        "retries": row.retries or 0,
        "event_id": row.event_id,
        "event_kind": kind,
        "event_kind_label": KIND_LABELS.get(kind, kind or "—"),
        "severity": _severity(kind),
    }


# ── pages ─────────────────────────────────────────────────────────────────

@bp.get("/")
@login_required
def alerts_list():
    """Recent alerts + simple KPIs.

    Pulls the latest 100 rows. Joining each alert to its event lets the
    template show the event kind label / severity without N+1 queries —
    SQLAlchemy resolves the ``Event`` lookup against the identity map
    after one IN-list fetch.
    """
    rows = (
        Alert.query
        .order_by(Alert.created_at.desc())
        .limit(100)
        .all()
    )
    event_ids = {r.event_id for r in rows if r.event_id is not None}
    events_by_id: dict[int, Event] = {}
    if event_ids:
        for ev in Event.query.filter(Event.id.in_(event_ids)).all():
            events_by_id[ev.id] = ev

    alert_views = [_alert_view(r, events_by_id.get(r.event_id)) for r in rows]

    kpis = {
        "total":       len(alert_views),
        "queued":      sum(1 for a in alert_views if a["status"] == "queued"),
        "sent":        sum(1 for a in alert_views if a["status"] == "sent"),
        "failed":      sum(1 for a in alert_views if a["status"] == "failed"),
        "suppressed":  sum(1 for a in alert_views if a["status"] == "suppressed"),
        "crit":        sum(1 for a in alert_views if a["severity"] == "crit"),
    }

    return render_template(
        "admin/fleet/alerts_list.html",
        alerts=alert_views, kpis=kpis,
    )


@bp.post("/<int:alert_id>/ack")
@login_required
def alert_ack(alert_id: int):
    """Acknowledge an alert: drops it out of the active set so a new
    occurrence of the same dedupe_key can fire again.

    No native confirm() — the page renders an inline form button; the
    operator decides whether the situation warrants the slot reopening.
    """
    row = db.session.get(Alert, alert_id)
    if row is None:
        flash("التنبيه غير موجود.", "error")
        return redirect(url_for("fleet_notify_ui.alerts_list"))
    if row.status in ("sent", "queued"):
        row.status = "suppressed"
        row.sent_at = row.sent_at or utcnow()
        db.session.add(row)
        db.session.commit()
        flash("تم تأكيد قراءة التنبيه.", "success")
    else:
        flash("التنبيه ليس بحاجة لتأكيد إضافي.", "info")
    return redirect(url_for("fleet_notify_ui.alerts_list"))


@bp.get("/settings")
@login_required
def alerts_settings():
    return render_template(
        "admin/fleet/alerts_settings.html",
        kinds=get_kind_states(),
        channels=list(FLEET_CHANNELS),
        active_channels=set(get_channels()),
    )


@bp.post("/settings")
@login_required
def alerts_settings_save():
    enabled_kinds = set(request.form.getlist("enabled_kinds"))
    for kind in KIND_LABELS:
        set_kind_enabled(kind, kind in enabled_kinds)
    set_channels(request.form.getlist("channels"))
    db.session.commit()
    flash("تم حفظ تفضيلات التنبيهات.", "success")
    return redirect(url_for("fleet_notify_ui.alerts_settings"))


__all__ = ["bp"]
