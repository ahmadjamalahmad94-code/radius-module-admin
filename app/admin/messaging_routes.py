"""قنوات التواصل والإشعارات — admin routes (blueprint: ``admin_messaging``).

Dedicated settings sub-page for the unified messaging system. Lets the admin:

* Enable/disable + configure the SMS, WhatsApp, and Telegram channels.
* Pick which channels the panel uses to notify the OWNER, and which event
  types are routed.
* Fire a one-off test send per channel.

All business logic lives in :mod:`app.services.messaging`. These routes only
do request parsing → service call → flash/redirect (or JSON for AJAX).
"""
from __future__ import annotations

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for

from ..auth.routes import audit, login_required
from ..extensions import db
from ..services import messaging
from ..services.messaging.channels import CHANNELS, CHANNEL_LABELS, OWNER_EVENTS, OWNER_EVENT_LABELS

bp = Blueprint("admin_messaging", __name__, url_prefix="/admin/messaging")


def _redirect():
    return redirect(url_for("admin_messaging.settings"))


def _state() -> dict:
    return {
        "channels": [messaging.get_channel_state(c) for c in CHANNELS],
        "channel_labels": CHANNEL_LABELS,
        "owner_prefs": messaging.get_owner_prefs(),
        "owner_events": OWNER_EVENTS,
        "owner_event_labels": OWNER_EVENT_LABELS,
    }


@bp.get("/settings")
@login_required
def settings():
    return render_template("admin/settings/messaging_new.html", **_state())


@bp.post("/settings/channel/<channel>")
@login_required
def settings_save_channel(channel: str):
    if channel not in CHANNELS:
        flash("قناة غير معروفة.", "error")
        return _redirect()
    try:
        messaging.save_channel(channel, request.form, actor_audit=audit)
    except messaging.ChannelSettingsError as exc:
        db.session.rollback()
        flash(str(exc), "error")
        return _redirect()
    db.session.commit()
    flash(f"تم حفظ إعدادات قناة {CHANNEL_LABELS.get(channel, channel)}.", "success")
    return _redirect()


@bp.post("/settings/owner-prefs")
@login_required
def settings_save_owner_prefs():
    try:
        messaging.save_owner_prefs(request.form, actor_audit=audit)
    except messaging.ChannelSettingsError as exc:
        db.session.rollback()
        flash(str(exc), "error")
        return _redirect()
    db.session.commit()
    flash("تم حفظ تفضيلات إشعارات المالك.", "success")
    return _redirect()


@bp.post("/settings/channel/<channel>/test")
@login_required
def settings_test_channel(channel: str):
    if channel not in CHANNELS:
        return jsonify({"ok": False, "code": "unknown_channel",
                        "message": "قناة غير معروفة."}), 400
    recipient = (request.form.get("recipient") or request.json and request.json.get("recipient") or "").strip()
    result = messaging.test_send(channel, recipient, actor_audit=audit)
    db.session.commit()
    return jsonify(result)
