"""fleet.ui.routes_p7 — Phase-7 admin page (live-apply + movable users).

A separate blueprint so the existing ``fleet_ui`` package doesn't grow
sideways for every new admin surface. Mounts under ``/admin/fleet/p7``:

* ``GET  /admin/fleet/p7/``                  dashboard (live-apply card,
                                             recent enforcement events,
                                             per-user movable table)
* ``POST /admin/fleet/p7/live-apply``        flip the flag (audited)
* ``POST /admin/fleet/p7/users/<id>/movable``  toggle per-user movable
* ``POST /admin/fleet/p7/users``             upsert/seed a fleet user row

All POSTs flash a hub-style toast on success, render the
design-system confirm modal on destructive intents, and never use
native ``alert()`` / ``confirm()``. The Arabic UI is RTL by inheritance
from ``admin/base_new.html``.
"""
from __future__ import annotations

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from sqlalchemy import desc

from app.auth.routes import audit, current_admin, login_required
from app.extensions import db

from fleet.brain.models_session import PlacementDecision, UserFleet
from fleet.control.live_apply_settings import (
    SETTING_KEY as LIVE_APPLY_KEY,
    is_enabled as live_apply_is_enabled,
    load_view as live_apply_load_view,
    set_enabled as live_apply_set_enabled,
)
from fleet.notify.models_alert import Event
from fleet.registry.models_chr import FleetChrNode


bp = Blueprint("fleet_p7", __name__, url_prefix="/admin/fleet/p7")


# ════════════════════════════════════════════════════════════════════════
# Page
# ════════════════════════════════════════════════════════════════════════


@bp.get("/")
@login_required
def dashboard():
    """Render the Phase-7 dashboard.

    Three panels:

    * **Live-apply state** — current ON/OFF + last setter (best-effort
      via audit table once the integrator wires it).
    * **Recent enforcement** — last 20 ``coa_sent`` / ``move_ok`` /
      ``move_fail`` events joined to their node so the row can show
      "chr-exit-02 ← bob@client5: applied".
    * **Per-user movable flags** — every ``fleet_users`` row with the
      toggle + a tooltip note that an OUTAGE move forces regardless.
    """
    live_apply = live_apply_load_view()

    # Recent enforcement events — only ones the proxy emits via the
    # enforcement endpoint or the panel mints from a direct CoA.
    recent_events = (
        Event.query
        .filter(Event.kind.in_(("coa_sent", "move_ok", "move_fail")))
        .order_by(desc(Event.ts))
        .limit(20)
        .all()
    )
    node_by_id = {n.id: n for n in FleetChrNode.query.all()}
    event_rows = [
        {
            "id": ev.id,
            "ts": ev.ts,
            "kind": ev.kind,
            "severity": ev.severity,
            "node_name": (node_by_id[ev.chr_id].name
                          if ev.chr_id in node_by_id else "—"),
            "user": ev.detail.get("user", "") or "—",
            "action": ev.detail.get("action", "—"),
            "result": ev.detail.get("result", "—"),
            "previous_node": ev.detail.get("previous_node", "") or "",
            "reason": ev.detail.get("reason", "") or "—",
        }
        for ev in recent_events
    ]

    # Recent decisions — show last 10 placement decisions for context.
    recent_decisions = (
        PlacementDecision.query
        .order_by(desc(PlacementDecision.decided_at))
        .limit(10)
        .all()
    )
    decisions_rows = [
        {
            "id": d.id,
            "username": d.username,
            "decided_at": d.decided_at,
            "kind": d.kind,
            "outcome": d.outcome,
            "from": (node_by_id[d.from_chr_id].name
                     if d.from_chr_id in node_by_id else "—"),
            "to": (node_by_id[d.to_chr_id].name
                   if d.to_chr_id in node_by_id else "—"),
        }
        for d in recent_decisions
    ]

    users = (
        UserFleet.query
        .order_by(UserFleet.movable.desc(), UserFleet.username.asc())
        .limit(100)
        .all()
    )

    return render_template(
        "admin/fleet/p7_dashboard.html",
        live_apply=live_apply,
        live_apply_key=LIVE_APPLY_KEY,
        event_rows=event_rows,
        decisions_rows=decisions_rows,
        users=users,
        user_count=UserFleet.query.count(),
        movable_count=UserFleet.query.filter(UserFleet.movable.is_(True)).count(),
    )


# ════════════════════════════════════════════════════════════════════════
# Live-apply toggle
# ════════════════════════════════════════════════════════════════════════


@bp.post("/live-apply")
@login_required
def toggle_live_apply():
    """Flip the live-apply flag. UI-only entry point (no API).

    The form posts ``desired`` = "on" | "off". The route audits every
    flip — see :func:`fleet.control.live_apply_settings.set_enabled` —
    and flashes an Arabic toast back to the dashboard.
    """
    desired_raw = (request.form.get("desired") or "").strip().lower()
    if desired_raw not in ("on", "off"):
        flash("قيمة غير صالحة للتطبيق الحي.", "error")
        return redirect(url_for("fleet_p7.dashboard"))
    desired = desired_raw == "on"
    admin = current_admin()
    new_state = live_apply_set_enabled(
        desired,
        actor_audit=audit,
        actor_label=(admin.username if admin else ""),
    )
    msg = (
        "تم تفعيل «التطبيق الحي للأسطول» — سيبدأ الوكيل بتنفيذ قرارات الفلوت."
        if new_state else
        "تم إيقاف «التطبيق الحي للأسطول» — قرارات الفلوت استشارية فقط الآن."
    )
    flash(msg, "success" if not new_state else "warning")
    return redirect(url_for("fleet_p7.dashboard"))


# ════════════════════════════════════════════════════════════════════════
# Movable flag CRUD
# ════════════════════════════════════════════════════════════════════════


@bp.post("/users/<int:user_id>/movable")
@login_required
def toggle_movable(user_id: int):
    """Flip ``fleet_users.movable`` for one user. POST-only, audited."""
    user = db.session.get(UserFleet, user_id)
    if user is None:
        abort(404)
    desired_raw = (request.form.get("desired") or "").strip().lower()
    if desired_raw not in ("on", "off"):
        flash("قيمة غير صالحة لخيار النقل.", "error")
        return redirect(url_for("fleet_p7.dashboard"))
    desired = desired_raw == "on"
    previous = bool(user.movable)
    user.movable = desired
    db.session.add(user)
    try:
        admin = current_admin()
        audit(
            "fleet_user_movable_toggled",
            "fleet_users", str(user.id),
            f"المستخدم {user.username} → {'قابل للنقل' if desired else 'غير قابل للنقل'}",
            {
                "username": user.username,
                "from": previous, "to": desired,
                "actor": admin.username if admin else "",
            },
        )
    except Exception:  # noqa: BLE001 — audit best-effort
        pass
    db.session.commit()
    flash(
        f"تم تحديث «قابل للنقل» للمستخدم {user.username}.",
        "success",
    )
    return redirect(url_for("fleet_p7.dashboard"))


@bp.post("/users")
@login_required
def seed_user():
    """Create a fleet_users row. Used to seed the table from the UI
    before any RADIUS traffic exists for a customer (typically Phase-3+
    will populate this automatically on Acct-Start).

    Form fields: ``username`` (required), ``realm`` (required),
    ``customer_id`` (required int), ``movable`` ("on"/"off").
    """
    username = (request.form.get("username") or "").strip().lower()
    realm = (request.form.get("realm") or "").strip().lower()
    customer_id_raw = (request.form.get("customer_id") or "").strip()
    movable = (request.form.get("movable") or "").strip().lower() == "on"

    if not username or not realm or not customer_id_raw:
        flash("الحقول (المستخدم، النطاق، العميل) مطلوبة جميعها.", "error")
        return redirect(url_for("fleet_p7.dashboard"))
    try:
        customer_id = int(customer_id_raw)
    except ValueError:
        flash("معرّف العميل يجب أن يكون رقمًا.", "error")
        return redirect(url_for("fleet_p7.dashboard"))

    existing = UserFleet.query.filter_by(username=username).one_or_none()
    if existing is not None:
        existing.movable = movable
        existing.realm = realm
        existing.customer_id = customer_id
        db.session.add(existing)
        flash(f"تم تحديث المستخدم {username}.", "success")
    else:
        row = UserFleet(
            customer_id=customer_id, realm=realm,
            username=username, movable=movable,
        )
        db.session.add(row)
        flash(f"تمت إضافة المستخدم {username}.", "success")
    db.session.commit()
    return redirect(url_for("fleet_p7.dashboard"))


__all__ = ["bp"]
