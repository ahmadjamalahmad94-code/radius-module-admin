from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, abort, flash, jsonify, make_response, redirect, render_template, request, session, url_for
from markupsafe import Markup, escape
from sqlalchemy import inspect, text
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from .bootstrap import BootstrapError, bootstrap_admin_from_config
from .config import Config, TestingConfig
from .extensions import db
from .models import Plan, Setting, VpnServicePlan, utcnow
from .services.customer_control import seed_service_catalog
from .security import client_ip


def create_app(config_object=None, **overrides) -> Flask:
    load_dotenv()
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(config_object or Config)
    app.config.update(overrides)
    _configure_logging(app)
    _validate_production_config(app)
    _install_proxy_fix(app)
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    db.init_app(app)
    _install_rate_limits(app)
    _install_csrf(app)
    _install_security_headers(app)
    _install_error_handlers(app)
    _install_template_helpers(app)

    from .auth.routes import bp as auth_bp
    from .admin.routes import bp as admin_bp
    from .admin.vault_routes import bp as admin_vault_bp
    from .api.routes import bp as api_bp
    from .public.routes import bp as public_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(admin_vault_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(public_bp)

    @app.get("/")
    def root():
        from flask import session as flask_session
        if flask_session.get("admin_id"):
            return redirect(url_for("admin.dashboard"))
        if flask_session.get("customer_user_id"):
            return redirect(url_for("public.customer_portal_dashboard"))
        return render_template("public/landing.html")

    _register_cli_commands(app)

    if app.config.get("AUTO_INIT_DB"):
        with app.app_context():
            init_database(app)

    return app


def _configure_logging(app: Flask) -> None:
    level_name = str(app.config.get("LOG_LEVEL", "INFO")).upper()
    level = getattr(logging, level_name, logging.INFO)
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s [%(name)s] %(message)s")
    app.logger.setLevel(level)


def _validate_production_config(app: Flask) -> None:
    if app.config.get("TESTING"):
        return
    env = str(app.config.get("LICENSE_PANEL_ENV", "")).strip().lower()
    bootstrap_mode = _is_bootstrap_mode(app)
    production_mode = env in {"prod", "production"} and not bootstrap_mode
    if not production_mode and not bootstrap_mode:
        return

    if os.environ.get("FLASK_DEBUG", "").strip().lower() in {"1", "true", "yes", "on"} or app.config.get("DEBUG"):
        raise RuntimeError("Production/bootstrap deployment requires FLASK_DEBUG=0.")
    weak_passwords = {
        "",
        Config.DEFAULT_ADMIN_PASSWORD,
        "change-this-password",
        "admin",
        "password",
        "replace-with-a-strong-unique-password",
        "replace-with-a-strong-unique-admin-password",
    }
    weak_secrets = {
        "",
        Config.DEFAULT_SECRET_KEY,
        "change-this-secret",
        "change-this-password",
        "replace-with-a-long-random-secret-at-least-32-bytes",
        "replace-with-a-long-random-flask-secret",
    }
    if str(app.config.get("SECRET_KEY", "")) in weak_secrets:
        raise RuntimeError("Production/bootstrap deployment requires a non-default FLASK_SECRET.")
    if str(app.config.get("ADMIN_PASSWORD", "")) in weak_passwords:
        raise RuntimeError("Production/bootstrap deployment requires a non-default LICENSE_ADMIN_PASSWORD.")
    if app.config.get("SQLALCHEMY_DATABASE_URI") == Config.DEFAULT_DATABASE_URI:
        raise RuntimeError("Production/bootstrap deployment requires an explicit DATABASE_URL.")
    if not app.config.get("RATE_LIMITS_ENABLED", True):
        raise RuntimeError("Production/bootstrap deployment requires RATE_LIMITS_ENABLED=1.")
    if production_mode and not app.config.get("SESSION_COOKIE_SECURE", False):
        raise RuntimeError("Production requires SESSION_COOKIE_SECURE=1.")
    if app.config.get("LICENSE_CHECK_ALLOW_UNSIGNED", False):
        raise RuntimeError("Production/bootstrap deployment requires LICENSE_CHECK_ALLOW_UNSIGNED=0.")
    if not app.config.get("LICENSE_CHECK_SIGNATURE_REQUIRED", False):
        raise RuntimeError("Production/bootstrap deployment requires LICENSE_CHECK_SIGNATURE_REQUIRED=1.")
    hmac_secret = str(app.config.get("LICENSE_CHECK_HMAC_SECRET") or "")
    if len(hmac_secret) < 32 or hmac_secret.startswith("replace-with-"):
        raise RuntimeError("Production/bootstrap deployment requires a strong LICENSE_CHECK_HMAC_SECRET.")


def _is_bootstrap_mode(app: Flask) -> bool:
    return (
        str(app.config.get("LICENSE_PANEL_ENV", "")).strip().lower() == "bootstrap"
        or bool(app.config.get("BOOTSTRAP_MODE"))
    )


def _install_proxy_fix(app: Flask) -> None:
    if app.config.get("TRUST_PROXY_HEADERS"):
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)


def _install_rate_limits(app: Flask) -> None:
    buckets: dict[str, tuple[float, int]] = {}

    def retry_after_for(key: str, max_attempts: int, window_seconds: int) -> int | None:
        now = time.monotonic()
        start, count = buckets.get(key, (now, 0))
        if now - start >= window_seconds:
            start, count = now, 0
        count += 1
        buckets[key] = (start, count)
        if count <= max_attempts:
            return None
        return max(1, int(window_seconds - (now - start)))

    def rate_limited_response(retry_after: int):
        if request.path.startswith("/api/"):
            response = jsonify({
                "active": False,
                "status": "rate_limited",
                "mode": "denied",
                "message": "محاولات كثيرة خلال وقت قصير. الرجاء إعادة المحاولة لاحقًا.",
            })
        else:
            flash("محاولات كثيرة خلال وقت قصير. حاول مرة أخرى لاحقًا.", "error")
            response = make_response(render_template("auth/login.html", username=request.form.get("username", "")))
        response.status_code = 429
        response.headers["Retry-After"] = str(retry_after)
        return response

    @app.before_request
    def check_rate_limit():
        if not app.config.get("RATE_LIMITS_ENABLED", True):
            return None
        if request.endpoint == "auth.login_post":
            retry_after = retry_after_for(
                f"login:{client_ip(app.config.get('TRUST_PROXY_HEADERS', False))}",
                int(app.config.get("LOGIN_RATE_LIMIT_MAX", 10)),
                int(app.config.get("LOGIN_RATE_LIMIT_WINDOW_SECONDS", 900)),
            )
            if retry_after:
                return rate_limited_response(retry_after)
        if request.endpoint == "api.license_check":
            body = request.get_json(silent=True) or {}
            license_key = str(body.get("license_key") or "").strip().upper()
            retry_after = retry_after_for(
                f"license-check-ip:{client_ip(app.config.get('TRUST_PROXY_HEADERS', False))}",
                int(app.config.get("LICENSE_CHECK_RATE_LIMIT_MAX", 120)),
                int(app.config.get("LICENSE_CHECK_RATE_LIMIT_WINDOW_SECONDS", 60)),
            )
            if retry_after:
                return rate_limited_response(retry_after)
            if license_key:
                retry_after = retry_after_for(
                    f"license-check-key:{license_key}",
                    int(app.config.get("LICENSE_KEY_RATE_LIMIT_MAX", 600)),
                    int(app.config.get("LICENSE_KEY_RATE_LIMIT_WINDOW_SECONDS", 300)),
                )
                if retry_after:
                    return rate_limited_response(retry_after)
        return None


def _install_security_headers(app: Flask) -> None:
    @app.after_request
    def set_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
            "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
            "img-src 'self' data:; "
            "script-src 'self'; "
            "frame-ancestors 'none'",
        )
        if app.config.get("SESSION_COOKIE_SECURE"):
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response


def _install_error_handlers(app: Flask) -> None:
    @app.errorhandler(HTTPException)
    def handle_http_error(error):
        if request.path.startswith("/api/"):
            return jsonify({
                "error": error.name.lower().replace(" ", "_"),
                "message": error.description,
            }), error.code
        return error

    @app.errorhandler(Exception)
    def handle_unexpected_error(error):
        if app.config.get("TESTING"):
            raise error
        app.logger.exception("Unhandled request error")
        if request.path.startswith("/api/"):
            return jsonify({
                "error": "internal_server_error",
                "message": "حدث خطأ داخلي في الخادم.",
            }), 500
        return "حدث خطأ داخلي في الخادم.", 500


def init_database(app: Flask) -> None:
    db.create_all()
    ensure_schema_compatibility(app)
    seed_defaults(app)


def ensure_schema_compatibility(app: Flask) -> None:
    if db.engine.dialect.name not in {"sqlite", "postgresql"}:
        return
    inspector = inspect(db.engine)
    tables = set(inspector.get_table_names())
    if "customers" in tables:
        _add_columns_if_missing("customers", {
            "runtime_url": "VARCHAR(255) NOT NULL DEFAULT ''",
            "portal_config_json": "TEXT NOT NULL DEFAULT '{}'",
            "currency": "VARCHAR(12) NOT NULL DEFAULT 'USD'",
        })
    # Customer Secure Vault: elevated-admin flag on existing admins tables.
    # The 3 vault tables themselves are created fresh by db.create_all().
    if "admins" in tables:
        _add_columns_if_missing("admins", {
            "is_super_admin": "BOOLEAN NOT NULL DEFAULT 0"
            if db.engine.dialect.name == "sqlite"
            else "BOOLEAN NOT NULL DEFAULT FALSE",
        })
    if "license_payment_requests" in tables:
        datetime_type = "TIMESTAMP" if db.engine.dialect.name == "postgresql" else "DATETIME"
        _add_columns_if_missing("license_payment_requests", {
            "access_token": "VARCHAR(96) NOT NULL DEFAULT ''",
            "applied_at": datetime_type,
            "applied_action": "VARCHAR(60) NOT NULL DEFAULT ''",
            "applied_result_json": "TEXT NOT NULL DEFAULT '{}'",
        })
    # Raise fingerprint floor on all existing licenses that still have the
    # old default of 1.  Silently no-ops if the column doesn't exist yet
    # or if there are no rows to update.
    if "licenses" in tables:
        try:
            db.session.execute(
                text("UPDATE licenses SET max_fingerprints = 3 WHERE max_fingerprints < 3")
            )
            db.session.commit()
        except Exception:
            db.session.rollback()

    if "provisioning_orders" in tables:
        datetime_type = "TIMESTAMP" if db.engine.dialect.name == "postgresql" else "DATETIME"
        _add_columns_if_missing("provisioning_orders", {
            "license_payment_request_id": "INTEGER",
            "target_plan_id": "INTEGER",
            "requested_at": datetime_type,
            "paid_at": datetime_type,
            "provisioning_started_at": datetime_type,
            "ready_at": datetime_type,
            "assigned_operator": "VARCHAR(160) NOT NULL DEFAULT ''",
        })

    # WhatsApp Gateway tables are created fresh by db.create_all(); the guarded
    # blocks below only matter for live DBs created before a column was added,
    # so they mirror the pattern above and stay intentionally minimal.
    if "whatsapp_message_queue" in tables:
        datetime_type = "TIMESTAMP" if db.engine.dialect.name == "postgresql" else "DATETIME"
        _add_columns_if_missing("whatsapp_message_queue", {
            "provider_message_id": "VARCHAR(190)",
            "next_attempt_at": datetime_type,
            "error_code": "VARCHAR(60)",
            "error_message": "TEXT",
        })

    if "whatsapp_tenant_accounts" in tables:
        datetime_type = "TIMESTAMP" if db.engine.dialect.name == "postgresql" else "DATETIME"
        _add_columns_if_missing("whatsapp_tenant_accounts", {
            "quality_rating": "VARCHAR(20)",
            "messaging_limit_tier": "VARCHAR(40)",
            "last_health_check_at": datetime_type,
            "last_error_code": "VARCHAR(60)",
        })


def _add_columns_if_missing(table_name: str, columns: dict[str, str]) -> None:
    inspector = inspect(db.engine)
    existing = {column["name"] for column in inspector.get_columns(table_name)}
    for column_name, definition in columns.items():
        if column_name in existing:
            continue
        db.session.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}"))
    db.session.commit()


def seed_defaults(app: Flask) -> None:
    bootstrap_admin_from_config(app, fail_if_exists=False)
    seed_service_catalog()

    # Customer Secure Vault: the primary/bootstrap admin is elevated to super_admin
    # so the owner can manage & reveal secrets out of the box. Other admins stay
    # non-super (can view metadata/records but not reveal) until promoted.
    try:
        from .models import Admin as _Admin
        _primary = _Admin.query.filter_by(username=app.config.get("ADMIN_USERNAME", "admin")).first()
        if _primary is None:
            _primary = _Admin.query.order_by(_Admin.id.asc()).first()
        if _primary is not None and not _primary.is_super_admin:
            _primary.is_super_admin = True
            db.session.commit()
    except Exception:
        db.session.rollback()

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

    vpn_plans = [
        ("شبكة خاصة 10 ميجابت", "vpn_10m", "خدمة تغيير العنوان والشبكة الخاصة بسرعة 10 ميجابت/ثانية", 10, 10, 25, 1, Decimal("10.00")),
        ("شبكة خاصة 50 ميجابت", "vpn_50m", "خدمة تغيير العنوان والشبكة الخاصة بسرعة 50 ميجابت/ثانية", 50, 50, 100, 1, Decimal("35.00")),
        ("شبكة خاصة 100 ميجابت", "vpn_100m", "خدمة تغيير العنوان والشبكة الخاصة بسرعة 100 ميجابت/ثانية", 100, 100, 250, 1, Decimal("65.00")),
    ]
    for name, code, description, download, upload, users, locations, price in vpn_plans:
        if VpnServicePlan.query.filter_by(code=code).first():
            continue
        db.session.add(VpnServicePlan(
            name=name,
            code=code,
            description=description,
            download_mbps=download,
            upload_mbps=upload,
            max_vpn_users=users,
            max_locations=locations,
            price_monthly=price,
            is_active=True,
        ))

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


def _register_cli_commands(app: Flask) -> None:
    import click

    @app.cli.command("init-db")
    def init_db_command():
        """Create tables and seed default data if missing."""
        with app.app_context():
            init_database(app)
        click.echo("Database initialized.")

    @app.cli.command("bootstrap-admin")
    def bootstrap_admin_command():
        """Create the first admin from LICENSE_ADMIN_* environment values."""
        with app.app_context():
            db.create_all()
            try:
                admin = bootstrap_admin_from_config(app, fail_if_exists=True)
            except BootstrapError as exc:
                raise click.ClickException(str(exc)) from exc
            username = admin.username
            db.session.commit()
        click.echo(f"Admin '{username}' created.")

    @app.cli.command("whatsapp-drain")
    @click.option("--batch-size", type=int, default=None, help="Max messages to process this run.")
    def whatsapp_drain_command(batch_size):
        """Drain one batch of queued WhatsApp messages.

        The panel has no resident worker; this is invoked by a systemd timer
        (see deploy/systemd) every couple of minutes. Sends due ``queued``
        messages through the provider and prints a one-line summary.
        """
        from .services.whatsapp.worker import drain_once

        with app.app_context():
            summary = drain_once(batch_size)
        click.echo(
            "whatsapp-drain: "
            f"claimed={summary['claimed']} sent={summary['sent']} "
            f"retried={summary['retried']} failed={summary['failed']} "
            f"skipped={summary['skipped']}"
        )


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

    @app.context_processor
    def _inject_admin_flags():
        # Exposes `is_super_admin` to all templates so elevated-only UI (e.g. the
        # Customer Secure Vault entry) can be hidden from non-super admins.
        from .auth.routes import current_admin
        admin = current_admin()
        return {"is_super_admin": bool(admin and getattr(admin, "is_super_admin", False))}

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

    @app.template_filter("dt_local")
    def dt_local_filter(value):
        """Format a (UTC) datetime in the portal's local timezone.

        received_at is stored as naive UTC; this shifts it by
        PORTAL_TZ_OFFSET_HOURS (default +3) so customer-facing times line up
        with the radius's local timestamps. Strings are passed through.
        """
        if not value:
            return "-"
        if isinstance(value, str):
            return value
        import os
        from datetime import timedelta
        try:
            offset = float(os.environ.get("PORTAL_TZ_OFFSET_HOURS", "3"))
        except (TypeError, ValueError):
            offset = 3.0
        return (value + timedelta(hours=offset)).strftime("%Y-%m-%d %H:%M")

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

    @app.template_filter("role_label")
    def role_label_filter(value):
        from .services.customer_control import role_label

        return role_label(str(value or ""))

    @app.template_filter("service_key_label")
    def service_key_label_filter(value):
        from .services.customer_control import service_label

        return service_label(str(value or ""))

    @app.template_filter("request_type_label")
    def request_type_label_filter(value):
        from .services.customer_control import service_request_type_label

        return service_request_type_label(str(value or ""))

    @app.template_filter("service_request_status_label")
    def service_request_status_label_filter(value):
        from .services.customer_control import service_request_status_label

        return service_request_status_label(str(value or ""))

    @app.template_filter("payment_purpose_label")
    def payment_purpose_label_filter(value):
        from .services.customer_control import payment_purpose_label

        return payment_purpose_label(str(value or ""))

    @app.template_filter("audit_action_label")
    def audit_action_label_filter(value):
        from .services.customer_control import audit_action_label

        return audit_action_label(str(value or ""))

    @app.template_filter("audit_summary_label")
    def audit_summary_label_filter(value):
        from .services.customer_control import audit_summary_label

        return audit_summary_label(str(value or ""))

    @app.template_filter("entity_type_label")
    def entity_type_label_filter(value):
        from .services.customer_control import entity_type_label

        return entity_type_label(str(value or ""))

    @app.template_filter("status_label")
    def status_label(value):
        return {
            "active": "نشط",
            "inactive": "غير نشط",
            "blocked": "محظور",
            "expired": "منتهي",
            "suspended": "معلق",
            "revoked": "ملغي",
            "disabled": "معطلة",
            "trial": "تجريبي",
            "grace": "مهلة سماح",
            "paid": "مدفوع",
            "unpaid": "غير مدفوع",
            "waived": "معفى",
            "pending": "بانتظار الدفع",
            "not_required": "غير مطلوب",
            "approved": "موافق عليه",
            "completed": "مكتمل",
            "trial_active": "تجربة مفعلة",
            "proof_submitted": "بانتظار المراجعة",
            "under_review": "قيد المراجعة",
            "rejected": "مرفوض",
            "cancelled": "ملغي",
            "failed": "فشل",
            "payment_pending": "بانتظار الدفع",
            "provisioning_pending": "قيد التجهيز",
            "provisioning_in_progress": "التجهيز جار",
            "testing": "قيد الفحص",
            "ready": "جاهز",
            "delivered": "تم التسليم",
            "needs_manual_review": "يحتاج مراجعة",
            "not_found": "غير موجود",
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
            "disabled": "badge-gray",
            "blocked": "badge-red",
            "inactive": "badge-gray",
            "paid": "badge-green",
            "unpaid": "badge-orange",
            "waived": "badge-blue",
            "pending": "badge-amber",
            "not_required": "badge-gray",
            "approved": "badge-green",
            "completed": "badge-green",
            "trial_active": "badge-blue",
            "proof_submitted": "badge-blue",
            "under_review": "badge-blue",
            "rejected": "badge-red",
            "cancelled": "badge-gray",
            "failed": "badge-red",
            "payment_pending": "badge-amber",
            "provisioning_pending": "badge-blue",
            "provisioning_in_progress": "badge-blue",
            "testing": "badge-amber",
            "ready": "badge-green",
            "delivered": "badge-green",
            "needs_manual_review": "badge-orange",
            "fingerprint_denied": "badge-red",
            "not_found": "badge-gray",
        }.get(str(value), "badge-gray")

    @app.context_processor
    def inject_now():
        return {
            "now": utcnow(),
            "timedelta": timedelta,
            "bootstrap_mode": _is_bootstrap_mode(app),
        }
