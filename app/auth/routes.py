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


def super_admin_required(view):
    """Gate sensitive actions (e.g. revealing/managing vault secrets) to super admins.
    Denials are audited and return JSON 403 for XHR or a flash+redirect otherwise."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        admin = current_admin()
        if not admin or not admin.active:
            session.clear()
            flash("سجل الدخول للمتابعة.", "warning")
            return redirect(url_for("auth.login", next=request.path))
        if not getattr(admin, "is_super_admin", False):
            from flask import jsonify
            audit("vault_permission_denied", "vault", "",
                  f"رُفض وصول {admin.username} لإجراء يتطلب مسؤولًا عامًا",
                  {"path": request.path})
            db.session.commit()
            wants_json = (request.headers.get("X-Requested-With") == "XMLHttpRequest"
                          or "application/json" in (request.headers.get("Accept") or ""))
            if wants_json:
                return jsonify({"ok": False, "error": "forbidden",
                                "message": "هذا الإجراء يتطلب صلاحية مسؤول عام."}), 403
            flash("هذا الإجراء يتطلب صلاحية مسؤول عام (super admin).", "error")
            return redirect(request.referrer or url_for("admin.dashboard"))
        return view(*args, **kwargs)

    return wrapped


def chr_console_required(view):
    """يحرس وحدة تحكّم CHR المركزية بالصلاحية ``chr_console``.

    المشروع لا يملك أدوارًا دقيقة للمدراء (فقط ``Admin.is_super_admin``)، لذا تُمنح
    هذه الصلاحية حاليًا للمسؤول العام دائمًا — وهي المصدر الوحيد لحراسة الوحدة كلها،
    فإن أُضيف محرّر أدوار لاحقًا يكفي توسيع هذا الموضع. الرفض يُدقَّق ويُرجِع JSON 403
    للطلبات اللاإمتزامنة أو flash+redirect لغيرها."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        admin = current_admin()
        if not admin or not admin.active:
            session.clear()
            flash("سجل الدخول للمتابعة.", "warning")
            return redirect(url_for("auth.login", next=request.path))
        if not getattr(admin, "is_super_admin", False):
            from flask import jsonify
            audit("chr_console_permission_denied", "chr_console", "",
                  f"رُفض وصول {admin.username} لوحدة تحكّم CHR (يتطلب صلاحية chr_console)",
                  {"path": request.path})
            db.session.commit()
            wants_json = (request.headers.get("X-Requested-With") == "XMLHttpRequest"
                          or "application/json" in (request.headers.get("Accept") or ""))
            if wants_json:
                return jsonify({"ok": False, "error": "forbidden",
                                "message": "وحدة تحكّم CHR تتطلب صلاحية مسؤول عام."}), 403
            flash("وحدة تحكّم CHR تتطلب صلاحية مسؤول عام (super admin).", "error")
            return redirect(request.referrer or url_for("admin.dashboard"))
        return view(*args, **kwargs)

    return wrapped


def enforce_admin_blueprint(blueprint, exempt_endpoints: frozenset[str] | set[str] = frozenset()) -> None:
    """حارس على مستوى الـ blueprint بأكمله (دفاع في العمق).

    كل مسارات لوحة الإدارة محمية بـ ``@login_required`` فرديًا، لكن مسارًا
    جديدًا يُنسى عليه الـ decorator كان سيصبح عامًا بصمت. هذا الحارس يجعل
    الافتراض «مغلق»: أي طلب لمسار ضمن الـ blueprint بلا جلسة مدير نشطة
    يُعاد لتسجيل الدخول (أو 401 JSON للطلبات اللاإمتزامنة).
    """
    # idempotent: الـ blueprints كائنات وحيدة على مستوى الموديول بينما
    # create_app() قد تُستدعى عدة مرات (الاختبارات) — Flask يمنع إضافة
    # before_request بعد أول تسجيل، لذا نثبّت الحارس مرة واحدة فقط.
    if getattr(blueprint, "_hb_admin_guard_installed", False):
        return
    blueprint._hb_admin_guard_installed = True

    @blueprint.before_request
    def _require_admin_session():  # pragma: no cover - trivial glue
        if request.endpoint in exempt_endpoints:
            return None
        admin = current_admin()
        wants_json = (request.headers.get("X-Requested-With") == "XMLHttpRequest"
                      or "application/json" in (request.headers.get("Accept") or "")
                      or request.path.startswith("/admin/api/"))
        # (1) مصادقة — لا نمسح الجلسة هنا كي لا نُتلف مصافحة 2FA المؤقتة
        # (pending_2fa_admin)؛ تسجيل الدخول الناجح يمسحها بنفسه.
        if admin is None or not admin.active:
            if wants_json:
                from flask import jsonify
                return jsonify({"ok": False, "error": "unauthorized",
                                "message": "سجل الدخول للمتابعة."}), 401
            flash("سجل الدخول للمتابعة.", "warning")
            return redirect(url_for("auth.login", next=request.path))
        # (2) RBAC — القدرة المطلوبة لهذه (endpoint, method) مقابل دور المدير.
        from ..services import rbac
        needed = rbac.required_capability(request.endpoint or "", request.method)
        if not rbac.can(admin, needed):
            audit("rbac_denied", "admin", str(admin.id),
                  f"رُفض {admin.username} ({rbac.role_of(admin)}) — يتطلب {needed}",
                  {"endpoint": request.endpoint, "method": request.method})
            db.session.commit()
            if wants_json:
                from flask import jsonify
                return jsonify({"ok": False, "error": "forbidden",
                                "message": "ليس لديك صلاحية لهذا الإجراء."}), 403
            flash("ليس لديك صلاحية لتنفيذ هذا الإجراء بدورك الحالي.", "error")
            return redirect(request.referrer or url_for("admin.dashboard"))
        return None


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


def _complete_login(admin, next_url: str | None):
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
    return redirect(safe_next_url(next_url))


@bp.post("/login")
def login_post():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    next_url = request.args.get("next")
    admin = Admin.query.filter_by(username=username).first()
    if not admin or not admin.active or not admin.check_password(password):
        flash("بيانات الدخول غير صحيحة.", "error")
        return render_template("auth/login.html", username=username), 401

    # 2FA: كلمة المرور صحيحة لكن المدير فعّل TOTP → مرحلة ثانية.
    if getattr(admin, "totp_enabled", False) and getattr(admin, "totp_secret", ""):
        # هوية مؤقتة موقّعة في الجلسة حتى يجتاز الرمز (لا admin_id بعد).
        session["pending_2fa_admin"] = admin.id
        session["pending_2fa_next"] = next_url or ""
        return redirect(url_for("auth.two_factor"))

    return _complete_login(admin, next_url)


@bp.get("/login/2fa")
def two_factor():
    if not session.get("pending_2fa_admin"):
        return redirect(url_for("auth.login"))
    return render_template("auth/two_factor.html")


@bp.post("/login/2fa")
def two_factor_post():
    from ..services import two_factor as tf
    admin_id = session.get("pending_2fa_admin")
    if not admin_id:
        return redirect(url_for("auth.login"))
    admin = db.session.get(Admin, int(admin_id))
    code = request.form.get("code") or ""
    if not admin or not admin.active or not tf.verify(admin.totp_secret, code):
        audit("login_2fa_failed", "admin", str(admin_id), "رمز التحقق الثنائي غير صحيح")
        db.session.commit()
        flash("رمز التحقق غير صحيح — حاول مجددًا.", "error")
        return render_template("auth/two_factor.html"), 401
    next_url = session.get("pending_2fa_next") or None
    session.pop("pending_2fa_admin", None)
    session.pop("pending_2fa_next", None)
    return _complete_login(admin, next_url)


@bp.post("/logout")
@login_required
def logout():
    admin = current_admin()
    audit("logout", "admin", str(admin.id if admin else ""), "Admin logged out")
    db.session.commit()
    session.clear()
    flash("تم تسجيل الخروج.", "info")
    return redirect(url_for("auth.login"))
