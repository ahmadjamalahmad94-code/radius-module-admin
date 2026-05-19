from __future__ import annotations

from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, abort, redirect, request, session, url_for
from markupsafe import Markup, escape

from .config import Config, TestingConfig
from .extensions import db
from .models import Admin, Plan, Setting, utcnow


def create_app(config_object=None, **overrides) -> Flask:
    load_dotenv()
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(config_object or Config)
    app.config.update(overrides)
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    db.init_app(app)
    _install_csrf(app)
    _install_template_helpers(app)

    from .auth.routes import bp as auth_bp
    from .admin.routes import bp as admin_bp
    from .api.routes import bp as api_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(api_bp)

    @app.get("/")
    def root():
        return redirect(url_for("admin.dashboard"))

    if app.config.get("AUTO_INIT_DB"):
        with app.app_context():
            init_database(app)

    return app


def init_database(app: Flask) -> None:
    db.create_all()
    seed_defaults(app)


def seed_defaults(app: Flask) -> None:
    if not Admin.query.filter_by(username=app.config["ADMIN_USERNAME"]).first():
        admin = Admin(
            username=app.config["ADMIN_USERNAME"],
            full_name="License Admin",
            email=app.config["ADMIN_EMAIL"],
            active=True,
        )
        admin.set_password(app.config["ADMIN_PASSWORD"])
        db.session.add(admin)

    sample_plans = [
        ("Starter", "starter", Decimal("29.00"), 300, 2, 1, 1, {
            "cards": True,
            "mikrotik": True,
            "reports": False,
            "api_access": False,
            "multi_admin": False,
            "backups": False,
            "advanced_logs": False,
        }),
        ("Pro", "pro", Decimal("79.00"), 3000, 10, 5, 2, {
            "cards": True,
            "mikrotik": True,
            "reports": True,
            "api_access": True,
            "multi_admin": True,
            "backups": True,
            "advanced_logs": True,
        }),
        ("Enterprise", "enterprise", Decimal("199.00"), 20000, 50, 20, 5, {
            "cards": True,
            "mikrotik": True,
            "reports": True,
            "api_access": True,
            "multi_admin": True,
            "backups": True,
            "advanced_logs": True,
        }),
    ]
    for name, slug, price, users, nas, admins, devices, features in sample_plans:
        if Plan.query.filter_by(slug=slug).first():
            continue
        plan = Plan(
            name=name,
            slug=slug,
            monthly_price=price,
            currency=app.config["DEFAULT_CURRENCY"],
            max_users=users,
            max_nas=nas,
            max_admins=admins,
            max_devices=devices,
            status="active",
        )
        plan.features = features
        db.session.add(plan)

    defaults = {
        "product_name": "HobeRadius License Panel",
        "license_api_base_url": "http://127.0.0.1:5055",
        "default_grace_days": str(app.config["DEFAULT_GRACE_DAYS"]),
        "default_currency": app.config["DEFAULT_CURRENCY"],
        "support_email": app.config["SUPPORT_EMAIL"],
        "support_phone": app.config["SUPPORT_PHONE"],
        "check_interval_recommendation": "Every 6 hours",
        "environment_label": app.config["LICENSE_PANEL_ENV"],
    }
    for key, value in defaults.items():
        if not db.session.get(Setting, key):
            db.session.add(Setting(key=key, value=value))

    db.session.commit()


def _install_csrf(app: Flask) -> None:
    def csrf_token() -> str:
        import secrets

        token = session.get("_csrf_token")
        if not token:
            token = secrets.token_urlsafe(32)
            session["_csrf_token"] = token
        return token

    def csrf_input() -> Markup:
        token = escape(csrf_token())
        return Markup(f'<input type="hidden" name="_csrf_token" value="{token}">')

    app.jinja_env.globals["csrf_token"] = csrf_token
    app.jinja_env.globals["csrf_input"] = csrf_input

    @app.before_request
    def check_csrf():
        if not app.config.get("WTF_CSRF_ENABLED", True):
            return None
        if request.method in {"GET", "HEAD", "OPTIONS"}:
            return None
        if request.path.startswith("/api/"):
            return None
        sent = request.form.get("_csrf_token") or request.headers.get("X-CSRFToken")
        expected = session.get("_csrf_token")
        if not expected or sent != expected:
            abort(400, "CSRF token is invalid")
        return None


def _install_template_helpers(app: Flask) -> None:
    @app.template_filter("dt")
    def dt_filter(value):
        if not value:
            return "-"
        if isinstance(value, str):
            return value
        return value.strftime("%Y-%m-%d %H:%M")

    @app.template_filter("date")
    def date_filter(value):
        if not value:
            return "-"
        if isinstance(value, str):
            return value
        return value.strftime("%Y-%m-%d")

    @app.template_filter("money")
    def money_filter(value):
        if value is None:
            return "0.00"
        return f"{Decimal(value):,.2f}"

    @app.template_filter("status_label")
    def status_label(value):
        return {
            "active": "نشط",
            "inactive": "غير نشط",
            "blocked": "محظور",
            "expired": "منتهي",
            "suspended": "معلق",
            "revoked": "ملغي",
            "trial": "تجريبي",
            "grace": "مهلة سماح",
            "paid": "مدفوع",
            "unpaid": "غير مدفوع",
            "waived": "معفى",
        }.get(str(value), value)

    @app.template_filter("badge_class")
    def badge_class(value):
        return {
            "active": "badge-green",
            "trial": "badge-blue",
            "grace": "badge-amber",
            "expired": "badge-orange",
            "suspended": "badge-red",
            "revoked": "badge-gray",
            "blocked": "badge-red",
            "inactive": "badge-gray",
            "paid": "badge-green",
            "unpaid": "badge-orange",
            "waived": "badge-blue",
            "fingerprint_denied": "badge-red",
            "not_found": "badge-gray",
        }.get(str(value), "badge-gray")

    @app.context_processor
    def inject_now():
        return {"now": utcnow(), "timedelta": timedelta}
