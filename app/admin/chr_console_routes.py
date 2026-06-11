"""وحدة تحكّم CHR — مسارات المسؤول (blueprint: admin_chr).

Zero-central edition: the console now operates on a SPECIFIC fleet node
chosen by the operator from a dropdown («على أي عقدة؟»). When the operator
hasn't picked one yet the brain's best-eligible node is used as the
default, matching the access-connections page's UX.

Every mutating endpoint accepts ``node_id`` in the form so the operator
can act on a specific CHR even when they have many. The viewer (GET)
accepts ``node_id`` as a query parameter so a deep-link is shareable.
الحماية: الوحدة كلها محروسة بـ :func:`chr_console_required`. القراءة آمنة
(لا ترفع، لا تنهار). التعديلات تتطلّب تأكيدًا صريحًا للإجراءات غير القابلة
للتراجع وتُدقَّق جميعها. لا تُعرض ولا تُسجَّل أي أسرار CHR.
"""
from __future__ import annotations

from flask import Blueprint, flash, redirect, render_template, request, url_for

from ..auth.routes import audit, chr_console_required
from ..extensions import db
from ..services import chr_console, fleet_node_router

bp = Blueprint("admin_chr", __name__, url_prefix="/admin/chr")


def _safe_int(value):
    try:
        return int(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _redirect(node_id=None):
    """Bounce back to the console — preserve the picked node across redirects."""
    if node_id:
        return redirect(url_for("admin_chr.console", node_id=int(node_id)))
    return redirect(url_for("admin_chr.console"))


def _enabled_guard():
    """يعيد None إن كانت الوحدة مفعّلة؛ وإلا redirect إلى الإعدادات."""
    if not chr_console.enabled():
        flash(
            "وحدة تحكّم CHR غير مفعّلة. أضف عقدة CHR إلى الأسطول من «معالج إضافة CHR» أولًا.",
            "error",
        )
        return redirect(url_for("fleet_ui.onboarding_wizard"))
    return None


@bp.get("/console")
@chr_console_required
def console():
    blocked = _enabled_guard()
    if blocked:
        return blocked
    node_id = _safe_int(request.args.get("node_id"))
    data = chr_console.overview(node_id=node_id)
    fleet_nodes = fleet_node_router.available_nodes()
    # Prefer the requested id even when the overview couldn't be built (so
    # the dropdown stays sticky on a wedged node); fall back to whatever
    # the brain picked once we have it.
    selected_node_id = node_id or data.get("node_id")
    selected_node_name = data.get("node_name") or ""
    if selected_node_id and not selected_node_name:
        # Drop the friendly label from the fleet list when the node didn't
        # come back from overview (e.g. unreachable).
        for n in fleet_nodes:
            if n.id == selected_node_id:
                selected_node_name = n.name
                break
    return render_template(
        "admin/chr_console.html",
        data=data,
        fleet_nodes=fleet_nodes,
        selected_node_id=selected_node_id,
        selected_node_name=selected_node_name,
    )


# ───────────────────────── PPP secrets (tunnel users) ─────────────────────────

@bp.post("/console/ppp/toggle")
@chr_console_required
def ppp_toggle():
    blocked = _enabled_guard()
    if blocked:
        return blocked
    node_id = _safe_int(request.form.get("node_id"))
    secret_id = (request.form.get("secret_id") or "").strip()
    name = (request.form.get("name") or "").strip()
    disable = (request.form.get("action") or "").strip().lower() == "disable"
    if not secret_id:
        flash("معرّف الحساب مفقود.", "error")
        return _redirect(node_id)
    result = chr_console.set_ppp_secret_disabled(secret_id, disable, node_id=node_id)
    if result.get("ok"):
        audit("chr_console_ppp_toggle", "chr_console", secret_id,
              f"{'تعطيل' if disable else 'تفعيل'} حساب نفق {name or secret_id} على CHR",
              {"secret_id": secret_id, "name": name, "disabled": disable, "node_id": node_id})
        db.session.commit()
        flash(f"تم {'تعطيل' if disable else 'تفعيل'} الحساب {name or secret_id}.", "success")
    else:
        flash("تعذّر تنفيذ الإجراء على CHR: " + (result.get("message") or "—"), "error")
    return _redirect(node_id)


@bp.post("/console/ppp/remove")
@chr_console_required
def ppp_remove():
    blocked = _enabled_guard()
    if blocked:
        return blocked
    node_id = _safe_int(request.form.get("node_id"))
    secret_id = (request.form.get("secret_id") or "").strip()
    name = (request.form.get("name") or "").strip()
    if (request.form.get("confirm") or "").strip().lower() != "yes":
        flash("الحذف يتطلّب تأكيدًا صريحًا.", "error")
        return _redirect(node_id)
    if not secret_id:
        flash("معرّف الحساب مفقود.", "error")
        return _redirect(node_id)
    result = chr_console.remove_ppp_secret(secret_id, node_id=node_id)
    if result.get("ok"):
        audit("chr_console_ppp_removed", "chr_console", secret_id,
              f"حذف حساب نفق {name or secret_id} من CHR",
              {"secret_id": secret_id, "name": name, "node_id": node_id})
        db.session.commit()
        flash(f"تم حذف الحساب {name or secret_id} من CHR.", "success")
    else:
        flash("تعذّر الحذف من CHR: " + (result.get("message") or "—"), "error")
    return _redirect(node_id)


# ───────────────────────── IPsec users ─────────────────────────

@bp.post("/console/ipsec/toggle")
@chr_console_required
def ipsec_toggle():
    blocked = _enabled_guard()
    if blocked:
        return blocked
    node_id = _safe_int(request.form.get("node_id"))
    user_id = (request.form.get("user_id") or "").strip()
    name = (request.form.get("name") or "").strip()
    disable = (request.form.get("action") or "").strip().lower() == "disable"
    if not user_id:
        flash("معرّف مستخدم IPsec مفقود.", "error")
        return _redirect(node_id)
    result = chr_console.set_ipsec_user_disabled(user_id, disable, node_id=node_id)
    if result.get("ok"):
        audit("chr_console_ipsec_toggle", "chr_console", user_id,
              f"{'تعطيل' if disable else 'تفعيل'} مستخدم IPsec {name or user_id} على CHR",
              {"user_id": user_id, "name": name, "disabled": disable, "node_id": node_id})
        db.session.commit()
        flash(f"تم {'تعطيل' if disable else 'تفعيل'} مستخدم IPsec {name or user_id}.", "success")
    else:
        flash("تعذّر تنفيذ الإجراء على CHR: " + (result.get("message") or "—"), "error")
    return _redirect(node_id)


@bp.post("/console/ipsec/remove")
@chr_console_required
def ipsec_remove():
    blocked = _enabled_guard()
    if blocked:
        return blocked
    node_id = _safe_int(request.form.get("node_id"))
    user_id = (request.form.get("user_id") or "").strip()
    name = (request.form.get("name") or "").strip()
    if (request.form.get("confirm") or "").strip().lower() != "yes":
        flash("الحذف يتطلّب تأكيدًا صريحًا.", "error")
        return _redirect(node_id)
    if not user_id:
        flash("معرّف مستخدم IPsec مفقود.", "error")
        return _redirect(node_id)
    result = chr_console.remove_ipsec_user(user_id, node_id=node_id)
    if result.get("ok"):
        audit("chr_console_ipsec_removed", "chr_console", user_id,
              f"حذف مستخدم IPsec {name or user_id} من CHR",
              {"user_id": user_id, "name": name, "node_id": node_id})
        db.session.commit()
        flash(f"تم حذف مستخدم IPsec {name or user_id} من CHR.", "success")
    else:
        flash("تعذّر الحذف من CHR: " + (result.get("message") or "—"), "error")
    return _redirect(node_id)


# ───────────────────────── admin action (destructive) ─────────────────────────

@bp.post("/console/reboot")
@chr_console_required
def reboot():
    blocked = _enabled_guard()
    if blocked:
        return blocked
    node_id = _safe_int(request.form.get("node_id"))
    if (request.form.get("confirm") or "").strip().lower() != "yes":
        flash("إعادة تشغيل CHR تتطلّب تأكيدًا صريحًا.", "error")
        return _redirect(node_id)
    result = chr_console.reboot(node_id=node_id)
    if result.get("ok"):
        audit("chr_console_reboot", "chr_console", str(node_id or "auto"),
              f"إعادة تشغيل CHR من وحدة التحكّم", {"node_id": node_id})
        db.session.commit()
        flash("أُرسل أمر إعادة تشغيل CHR. قد ينقطع الاتصال مؤقتًا.", "success")
    else:
        flash("تعذّر إرسال أمر إعادة التشغيل: " + (result.get("message") or "—"), "error")
    return _redirect(node_id)
