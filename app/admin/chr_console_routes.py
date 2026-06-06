"""وحدة تحكّم CHR المركزية — مسارات المسؤول (blueprint: admin_chr).

تحكّم كامل في CHR المملوك مركزيًا هنا عبر RouterOS REST: عرض حالة النظام والجلسات
النشطة والواجهات، وإدارة مستخدمي الأنفاق (``/ppp/secret``) ومستخدمي IPsec
(تعطيل/تفعيل/حذف)، وإجراء إداري حسّاس (إعادة تشغيل CHR).

الحماية: الوحدة كلها محروسة بـ :func:`chr_console_required` (صلاحية ``chr_console``؛
المسؤول العام دائمًا مسموح). القراءة أولًا: الصفحة GET لا تغيّر شيئًا ولا تنهار عند
تعذّر الوصول. التعديلات POST مع تأكيد صريح للإجراءات غير القابلة للتراجع (حذف/إعادة
تشغيل) وتُدقَّق جميعها. لا تُعرض ولا تُسجَّل أي أسرار CHR.
"""
from __future__ import annotations

from flask import Blueprint, flash, redirect, render_template, request, url_for

from ..auth.routes import audit, chr_console_required
from ..extensions import db
from ..services import chr_console

bp = Blueprint("admin_chr", __name__, url_prefix="/admin/chr")


def _redirect():
    return redirect(url_for("admin_chr.console"))


def _enabled_guard():
    """يعيد None إن كانت الوحدة مفعّلة؛ وإلا redirect إلى الإعدادات."""
    if not chr_console.enabled():
        flash("وحدة تحكّم CHR غير مُفعّلة (فعّل CHR_CONSOLE_ENABLED وأكمل إعداد CHR).", "error")
        return redirect(url_for("admin.settings_page") + "#chr-settings")
    return None


@bp.get("/console")
@chr_console_required
def console():
    blocked = _enabled_guard()
    if blocked:
        return blocked
    data = chr_console.overview()
    return render_template("admin/chr_console.html", data=data)


# ───────────────────────── PPP secrets (tunnel users) ─────────────────────────

@bp.post("/console/ppp/toggle")
@chr_console_required
def ppp_toggle():
    blocked = _enabled_guard()
    if blocked:
        return blocked
    secret_id = (request.form.get("secret_id") or "").strip()
    name = (request.form.get("name") or "").strip()
    disable = (request.form.get("action") or "").strip().lower() == "disable"
    if not secret_id:
        flash("معرّف الحساب مفقود.", "error")
        return _redirect()
    result = chr_console.set_ppp_secret_disabled(secret_id, disable)
    if result.get("ok"):
        audit("chr_console_ppp_toggle", "chr_console", secret_id,
              f"{'تعطيل' if disable else 'تفعيل'} حساب نفق {name or secret_id} على CHR",
              {"secret_id": secret_id, "name": name, "disabled": disable})
        db.session.commit()
        flash(f"تم {'تعطيل' if disable else 'تفعيل'} الحساب {name or secret_id}.", "success")
    else:
        flash("تعذّر تنفيذ الإجراء على CHR: " + (result.get("message") or "—"), "error")
    return _redirect()


@bp.post("/console/ppp/remove")
@chr_console_required
def ppp_remove():
    blocked = _enabled_guard()
    if blocked:
        return blocked
    secret_id = (request.form.get("secret_id") or "").strip()
    name = (request.form.get("name") or "").strip()
    if (request.form.get("confirm") or "").strip().lower() != "yes":
        flash("الحذف يتطلّب تأكيدًا صريحًا.", "error")
        return _redirect()
    if not secret_id:
        flash("معرّف الحساب مفقود.", "error")
        return _redirect()
    result = chr_console.remove_ppp_secret(secret_id)
    if result.get("ok"):
        audit("chr_console_ppp_removed", "chr_console", secret_id,
              f"حذف حساب نفق {name or secret_id} من CHR", {"secret_id": secret_id, "name": name})
        db.session.commit()
        flash(f"تم حذف الحساب {name or secret_id} من CHR.", "success")
    else:
        flash("تعذّر الحذف من CHR: " + (result.get("message") or "—"), "error")
    return _redirect()


# ───────────────────────── IPsec users ─────────────────────────

@bp.post("/console/ipsec/toggle")
@chr_console_required
def ipsec_toggle():
    blocked = _enabled_guard()
    if blocked:
        return blocked
    user_id = (request.form.get("user_id") or "").strip()
    name = (request.form.get("name") or "").strip()
    disable = (request.form.get("action") or "").strip().lower() == "disable"
    if not user_id:
        flash("معرّف مستخدم IPsec مفقود.", "error")
        return _redirect()
    result = chr_console.set_ipsec_user_disabled(user_id, disable)
    if result.get("ok"):
        audit("chr_console_ipsec_toggle", "chr_console", user_id,
              f"{'تعطيل' if disable else 'تفعيل'} مستخدم IPsec {name or user_id} على CHR",
              {"user_id": user_id, "name": name, "disabled": disable})
        db.session.commit()
        flash(f"تم {'تعطيل' if disable else 'تفعيل'} مستخدم IPsec {name or user_id}.", "success")
    else:
        flash("تعذّر تنفيذ الإجراء على CHR: " + (result.get("message") or "—"), "error")
    return _redirect()


@bp.post("/console/ipsec/remove")
@chr_console_required
def ipsec_remove():
    blocked = _enabled_guard()
    if blocked:
        return blocked
    user_id = (request.form.get("user_id") or "").strip()
    name = (request.form.get("name") or "").strip()
    if (request.form.get("confirm") or "").strip().lower() != "yes":
        flash("الحذف يتطلّب تأكيدًا صريحًا.", "error")
        return _redirect()
    if not user_id:
        flash("معرّف مستخدم IPsec مفقود.", "error")
        return _redirect()
    result = chr_console.remove_ipsec_user(user_id)
    if result.get("ok"):
        audit("chr_console_ipsec_removed", "chr_console", user_id,
              f"حذف مستخدم IPsec {name or user_id} من CHR", {"user_id": user_id, "name": name})
        db.session.commit()
        flash(f"تم حذف مستخدم IPsec {name or user_id} من CHR.", "success")
    else:
        flash("تعذّر الحذف من CHR: " + (result.get("message") or "—"), "error")
    return _redirect()


# ───────────────────────── admin action (destructive) ─────────────────────────

@bp.post("/console/reboot")
@chr_console_required
def reboot():
    blocked = _enabled_guard()
    if blocked:
        return blocked
    if (request.form.get("confirm") or "").strip().lower() != "yes":
        flash("إعادة تشغيل CHR تتطلّب تأكيدًا صريحًا.", "error")
        return _redirect()
    result = chr_console.reboot()
    if result.get("ok"):
        audit("chr_console_reboot", "chr_console", "global", "إعادة تشغيل CHR من وحدة التحكّم", {})
        db.session.commit()
        flash("أُرسل أمر إعادة تشغيل CHR. قد ينقطع الاتصال مؤقتًا.", "success")
    else:
        flash("تعذّر إرسال أمر إعادة التشغيل: " + (result.get("message") or "—"), "error")
    return _redirect()
