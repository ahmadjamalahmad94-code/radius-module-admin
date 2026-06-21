"""Admin notification-center routes + the bell unread-count API."""
from __future__ import annotations

from flask import Blueprint, jsonify, redirect, render_template, request, url_for

from app.auth.routes import login_required
from app.extensions import db

from . import service
from .models import Notification

bp = Blueprint("admin_notifications", __name__, url_prefix="/admin/notifications")

_TYPE_LABELS = {
    "license_expiry": "انتهاء الاشتراك",
    "ip_change_expiry": "انتهاء خدمة تغيير IP",
    "trial_expiry": "انتهاء التجربة",
    "message_package_low": "اقتراب نفاد الرسائل",
    "message_package_empty": "نفاد الرسائل",
    "invoice_new": "فاتورة جديدة",
    "payment_received": "استلام دفعة",
    "payment_overdue": "دفعة متأخرة",
}


@bp.get("/")
@login_required
def center():
    """The notification center — recent notifications + filters."""
    unread_only = request.args.get("unread") in ("1", "true", "on")
    type_filter = (request.args.get("type") or "").strip() or None
    severity = (request.args.get("severity") or "").strip() or None
    items = service.recent(limit=200, unread_only=unread_only,
                           type=type_filter, severity=severity)
    return render_template(
        "admin/notifications/center.html",
        items=items,
        unread_count=service.unread_count(),
        type_labels=_TYPE_LABELS,
        unread_only=unread_only,
        type_filter=type_filter,
        severity_filter=severity,
    )


@bp.post("/<int:notification_id>/read")
@login_required
def mark_read(notification_id: int):
    ok = service.mark_read(notification_id)
    db.session.commit()
    if request.headers.get("X-Requested-With") == "XMLHttpRequest" \
            or "application/json" in (request.headers.get("Accept") or ""):
        return jsonify({"ok": ok, "unread_count": service.unread_count()})
    return redirect(url_for("admin_notifications.center"))


@bp.post("/read-all")
@login_required
def mark_all_read():
    n = service.mark_all_read()
    db.session.commit()
    if request.headers.get("X-Requested-With") == "XMLHttpRequest" \
            or "application/json" in (request.headers.get("Accept") or ""):
        return jsonify({"ok": True, "marked": n, "unread_count": 0})
    return redirect(url_for("admin_notifications.center"))


@bp.get("/unread-count")
@login_required
def unread_count():
    """Lightweight JSON for the sidebar bell badge poll."""
    return jsonify({"ok": True, "count": service.unread_count()})
