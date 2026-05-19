from __future__ import annotations

from functools import wraps

from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for

from ..extensions import db
from ..models import Admin, AuditLog, utcnow

bp = Blueprint("auth", __name__)


def current_admin() -> Admin | None:
    admin_id = session.get("admin_id")
    if not admin_id:
        return None
    return db.session.get(Admin, int(admin_id))


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        admin = current_admin()
        if not admin or not admin.active:
            session.clear()
            flash("سجل الدخول للمتابعة.", "warning")
            return redirect(url_for("auth.login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


def audit(action: str, entity_type: str, entity_id: str = "", summary: str = "", metadata=None) -> None:
    admin_id = session.get("admin_id")
    row = AuditLog(
        actor_admin_id=admin_id,
        action=action,
        entity_type=entity_type,
        entity_id=str(entity_id or ""),
        summary=summary,
    )
    row.meta = metadata or {}
    db.session.add(row)


def safe_next_url(target: str | None) -> str:
    target = (target or "").strip()
    if target.startswith("/") and not target.startswith("//"):
        return target
    return url_for("admin.dashboard")


@bp.get("/login")
def login():
    return render_template("auth/login.html")


@bp.post("/login")
def login_post():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    admin = Admin.query.filter_by(username=username).first()
    if not admin or not admin.active or not admin.check_password(password):
        flash("بيانات الدخول غير صحيحة.", "error")
        return render_template("auth/login.html", username=username), 401

    admin.last_login_at = utcnow()
    db.session.add(admin)
    session.clear()
    session.permanent = True
    session["admin_id"] = admin.id
    session["admin_name"] = admin.full_name or admin.username
    audit("login", "admin", str(admin.id), f"Admin {admin.username} logged in")
    db.session.commit()
    current_app.logger.info("Admin login succeeded for %s", admin.username)
    flash("تم تسجيل الدخول بنجاح.", "success")
    return redirect(safe_next_url(request.args.get("next")))


@bp.post("/logout")
@login_required
def logout():
    admin = current_admin()
    audit("logout", "admin", str(admin.id if admin else ""), "Admin logged out")
    db.session.commit()
    session.clear()
    flash("تم تسجيل الخروج.", "info")
    return redirect(url_for("auth.login"))
