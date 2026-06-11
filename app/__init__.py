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

    # Reject any DATABASE_URL that would re-introduce the SQLite
    # split-brain (relative paths resolved against cwd). Canonical-path
    # diagnostics + legacy-sibling warning are logged here so the
    # operator sees them on every boot, including under systemd.
    _validate_and_log_db_path(app)

    db.init_app(app)
    _install_rate_limits(app)
    _install_csrf(app)
    _install_security_headers(app)
    _install_error_handlers(app)
    _install_template_helpers(app)

    # i18n / l10n. Must run BEFORE blueprints register so the Jinja
    # globals (``_`` / ``gettext``) are available for templates loaded
    # during route registration.
    from .i18n import init_app as init_i18n
    init_i18n(app)

    from .auth.routes import bp as auth_bp
    from .admin.routes import bp as admin_bp
    from .admin.vault_routes import bp as admin_vault_bp
    from .admin.chr_console_routes import bp as admin_chr_bp
    from .admin.landing_routes import bp as admin_landing_bp
    from .admin.infra_routes import bp as admin_infra_bp
    from .admin.messaging_routes import bp as admin_messaging_bp
    # «اتصالات الوصول» — لوحة موحَّدة لإضافة/إدارة PPTP/SSTP/IPsec/WireGuard
    # على CHR المركزي. تستورد الـORM الجديد (WireguardPeer) قبل db.create_all().
    from .admin.access_connections_routes import bp as admin_access_bp
    from .models import WireguardPeer  # noqa: F401 — model registration
    from .i18n.routes import bp as i18n_bp
    from .api.routes import bp as api_bp
    from .api.proxy_api import bp as proxy_api_bp
    from .public.routes import bp as public_bp
    # NOTE — the rotatable «bridge token» surface was retired together with
    # the legacy linking-auth removal (the only way to authenticate the bridge
    # is now the license-key bearer; nothing to rotate, nothing to sync). The
    # blueprints + the ``BridgeTokenState`` model are gone. The
    # ``bridge_token_states`` table on older DBs is left alone — it carries
    # no auth meaning anymore.
    # CHR Fleet (Phase 3): registry/onboarding/provider APIs + admin UI.
    # Importing the modules also pulls in their ORM models so the fleet tables
    # land in db.metadata for db.create_all(). The P3-gate integrator wires all
    # four sub-teams here: routes_chr (T5 CHR-node CRUD), routes_provider (T6),
    # routes_onboarding (T1 wizard API), fleet.ui (T5 pages). secrets_vault is
    # imported so its ChrSecret model (fleet_chr_secrets) is created.
    from fleet.registry import secrets_vault as _fleet_secrets_vault  # noqa: F401 (model registration)
    from fleet.registry.routes_chr import bp as fleet_registry_api_bp
    from fleet.registry.routes_onboarding import bp as fleet_onboarding_bp
    from fleet.registry.routes_provider import bp as fleet_provider_bp
    from fleet.ui.routes import bp as fleet_ui_bp
    # P4-B: per-CHR telemetry ingest (POST /api/proxy/telemetry, see
    # docs/contracts/fleet_api.md §1). Reuses the existing X-Proxy-Token
    # HMAC; persists into fleet_chr_metrics.
    from fleet.health.routes_telemetry import bp as fleet_telemetry_bp
    # P5-B: proxy-facing placement-decision read endpoint
    # (GET /api/proxy/placement-decision, contract §6). Same X-Proxy-Token
    # auth; delegates ranking to fleet.brain (real impl) or local stub
    # adapter; audits each served decision into fleet_placement_decisions.
    from fleet.brain.routes_placement_decision import bp as fleet_placement_decision_bp
    # Phase 7 panel: enforcement-outcome ingest + UI dashboard.
    from fleet.control.routes_enforcement import bp as fleet_p7_enforcement_bp
    from fleet.ui.routes_p7 import bp as fleet_p7_ui_bp
    # P8-B: rebalance + forced-failover dashboard (/admin/fleet/p8/).
    # Uses fleet.brain.orchestrator_adapter — real engine when Task A's
    # plan_rebalance / execute_rebalance are importable, stub otherwise.
    from fleet.ui.routes_p8 import bp as fleet_p8_ui_bp
    # Phase 9 owner alerts (recent alerts + per-kind settings).
    from fleet.notify.ui_routes import bp as fleet_p9_alerts_bp
    # feat/fleet-zero-touch-sync: live staged sync/onboarding progress + the
    # SyncJob model (importing the routes pulls in fleet.sync.models so the
    # fleet_sync_jobs table lands in db.metadata for db.create_all()).
    from fleet.sync.routes import bp as fleet_sync_bp
    # Register the remaining Phase-2 fleet ORM models so db.create_all() builds
    # ALL fleet tables. The route imports above only pull in the P3-referenced
    # models (providers, chr_nodes, onboarding_jobs, chr_secrets); these four
    # modules carry the rest (metrics/health, users/sessions/placement,
    # events/alerts, dns_records_state). Without this, a fresh prod DB would be
    # missing those tables.
    from fleet.health import models_health as _fleet_models_health    # noqa: F401
    from fleet.brain import models_session as _fleet_models_session   # noqa: F401
    from fleet.notify import models_alert as _fleet_models_alert      # noqa: F401
    from fleet.dns import models_dns as _fleet_models_dns             # noqa: F401

    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    # bridge-token blueprints retired with the linking-auth cleanup.
    app.register_blueprint(admin_vault_bp)
    app.register_blueprint(admin_chr_bp)
    app.register_blueprint(admin_landing_bp)
    app.register_blueprint(admin_infra_bp)
    app.register_blueprint(admin_messaging_bp)
    app.register_blueprint(admin_access_bp)
    app.register_blueprint(i18n_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(proxy_api_bp)
    app.register_blueprint(public_bp)
    app.register_blueprint(fleet_registry_api_bp)
    app.register_blueprint(fleet_provider_bp)
    app.register_blueprint(fleet_onboarding_bp)
    app.register_blueprint(fleet_ui_bp)
    app.register_blueprint(fleet_telemetry_bp)
    app.register_blueprint(fleet_placement_decision_bp)
    app.register_blueprint(fleet_p7_enforcement_bp)
    app.register_blueprint(fleet_p7_ui_bp)
    app.register_blueprint(fleet_p8_ui_bp)
    app.register_blueprint(fleet_p9_alerts_bp)
    app.register_blueprint(fleet_sync_bp)

    @app.get("/")
    def root():
        # The landing page is shown to EVERYONE (including logged-in users).
        # Navigation into the dashboard/portal is via the context-aware "دخول"
        # button in the landing navbar, not an automatic redirect.
        from .services.landing_cms import get_published_homepage, build_public_context
        page = get_published_homepage()
        ctx = build_public_context(page) if page else {
            "page": None, "sections": [], "social_links": [],
            "contact_methods": [], "status_badge_class": {},
        }
        return render_template("public/landing.html", **ctx)

    _register_cli_commands(app)

    if app.config.get("AUTO_INIT_DB"):
        with app.app_context():
            init_database(app)

    _start_workers(app)

    return app


def _start_workers(app: Flask) -> None:
    """Spawn fleet background workers (daemon threads).

    Currently:
      * ``fleet.health.metrics_poller`` — polls RouterOS over wg-mgmt and
        writes ``fleet_chr_metrics`` rows with ``source='control'`` so
        the dashboard renders real CPU / sessions / bandwidth.

    Every worker is opt-in via a config flag and gated by ``TESTING`` so
    unit tests + the CLI never spawn background threads they didn't ask
    for. Errors during start-up are logged and swallowed: a worker
    misconfig must NOT keep the app from booting.
    """
    try:
        from fleet.health.metrics_poller import start_background_poller
        start_background_poller(app)
    except Exception:  # noqa: BLE001 — never fail app boot on a worker
        app.logger.exception("fleet metrics poller failed to start")


def _configure_logging(app: Flask) -> None:
    level_name = str(app.config.get("LOG_LEVEL", "INFO")).upper()
    level = getattr(logging, level_name, logging.INFO)
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s [%(name)s] %(message)s")
    app.logger.setLevel(level)


def _validate_and_log_db_path(app: Flask) -> None:
    """Reject relative sqlite:/// URIs at boot + police the legacy sibling.

    The historical split-brain (license_panel.db vs license_panel.sqlite3)
    came from cwd-dependent path resolution. We refuse to start with a
    config that would re-create the same trap, and we log the resolved
    on-disk path so the operator can verify it in journalctl.

    Legacy-sibling policy (field-hardened):
    * ``license_panel.db`` as a SYMLINK/hardlink to the canonical
      ``.sqlite3`` → silent OK. This is the owner's sanctioned aliasing
      so stray tooling that still references the old name hits the same
      physical database. No warning noise.
    * ``license_panel.db`` as a SEPARATE REAL FILE → **refuse to boot**
      when this process is actually using the file-backed canonical DB.
      Booting in that state is how the original incident silently grew:
      writes landed in a file the running app never reads. Failing
      loudly at start-up forces reconciliation while the divergence is
      still small. In-memory / PostgreSQL deployments skip the check —
      the sibling is irrelevant to them.
    """
    from .db_path import (
        LEGACY_CONFLICT,
        DatabaseURIError,
        classify_legacy_sibling,
        resolved_sqlite_path_for,
        validate_database_uri,
    )

    uri = str(app.config.get("SQLALCHEMY_DATABASE_URI", ""))
    try:
        validate_database_uri(uri)
    except DatabaseURIError as exc:
        # Hard-fail: this is the exact misconfig the field report
        # uncovered. Better to refuse than open a stray file.
        raise RuntimeError(str(exc)) from exc

    resolved = resolved_sqlite_path_for(uri)
    if resolved is not None:
        app.logger.info("SQLite database resolved to: %s", resolved)
    from .db_path import canonical_sqlite_path
    state, sibling = classify_legacy_sibling()
    if state == LEGACY_CONFLICT:
        if resolved is not None and resolved == canonical_sqlite_path():
            # This process runs ON the canonical file AND a divergent
            # twin exists → refuse. The operator must consolidate (or
            # symlink) BEFORE the panel writes another row that the
            # other file will never see.
            raise RuntimeError(
                f"SQLite split-brain detected: {sibling} is a SEPARATE real "
                "database file next to the canonical license_panel.sqlite3. "
                "Refusing to boot so the divergence cannot grow. Reconcile "
                "per docs/DB_PATH_FIX_RUNBOOK.md (merge what you need, then "
                "delete the legacy file or replace it with a symlink to the "
                "canonical file)."
            )
        # Not running on the file-backed canonical DB (tests / Postgres):
        # the sibling can't bite this process, but tell the operator.
        app.logger.warning(
            "Legacy SQLite sibling present (separate real file): %s. This "
            "process is not using the canonical SQLite file so it is not "
            "affected, but reconcile per docs/DB_PATH_FIX_RUNBOOK.md before "
            "any SQLite-backed deployment starts.",
            sibling,
        )


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
    # "Explicit DATABASE_URL" means the OPERATOR set one — i.e. the env
    # var exists — NOT that its value differs from the built-in default.
    # The previous string-equality check (`uri == DEFAULT_DATABASE_URI`)
    # rejected a perfectly explicit env URL whenever it happened to spell
    # the same canonical path the default computes (which is exactly what
    # a correct prod env file does: it points at
    # /opt/.../instance/license_panel.sqlite3). That false rejection is
    # what forced the run_panel.sh wrapper workaround in the field —
    # the wrapper "fixed" boot only because it exported a DIFFERENT
    # string (the legacy .db symlink path). Presence-of-env is the real
    # contract; the URI's own validity is enforced separately by
    # _validate_and_log_db_path / validate_database_uri.
    if not (os.environ.get("DATABASE_URL") or "").strip():
        raise RuntimeError(
            "Production/bootstrap deployment requires an explicit DATABASE_URL "
            "environment variable (set it in /etc/hoberadius-license-panel/"
            "license-panel.env; systemd EnvironmentFile= delivers it)."
        )
    if not app.config.get("RATE_LIMITS_ENABLED", True):
        raise RuntimeError("Production/bootstrap deployment requires RATE_LIMITS_ENABLED=1.")
    if production_mode and not app.config.get("SESSION_COOKIE_SECURE", False):
        raise RuntimeError("Production requires SESSION_COOKIE_SECURE=1.")
    # Legacy strict-signature gates removed alongside the bearer-only
    # link contract (docs/SIMPLE_LINK_CONTRACT.md). Production now only
    # requires DATABASE_URL + RATE_LIMITS_ENABLED + SESSION_COOKIE_SECURE,
    # all checked above.


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
        # Read rate-limit knobs through the platform_settings resolver so the
        # owner can tune them live from /admin/settings/platform without a
        # restart. The resolver chain is: Setting row -> app.config -> default.
        from .services import platform_settings as ps
        if not ps.get_bool("RATE_LIMITS_ENABLED"):
            return None
        if request.endpoint == "auth.login_post":
            retry_after = retry_after_for(
                f"login:{client_ip(app.config.get('TRUST_PROXY_HEADERS', False))}",
                ps.get_int("LOGIN_RATE_LIMIT_MAX"),
                ps.get_int("LOGIN_RATE_LIMIT_WINDOW_SECONDS"),
            )
            if retry_after:
                return rate_limited_response(retry_after)
        if request.endpoint == "api.license_check":
            body = request.get_json(silent=True) or {}
            license_key = str(body.get("license_key") or "").strip().upper()
            retry_after = retry_after_for(
                f"license-check-ip:{client_ip(app.config.get('TRUST_PROXY_HEADERS', False))}",
                ps.get_int("LICENSE_CHECK_RATE_LIMIT_MAX"),
                ps.get_int("LICENSE_CHECK_RATE_LIMIT_WINDOW_SECONDS"),
            )
            if retry_after:
                return rate_limited_response(retry_after)
            if license_key:
                retry_after = retry_after_for(
                    f"license-check-key:{license_key}",
                    ps.get_int("LICENSE_KEY_RATE_LIMIT_MAX"),
                    ps.get_int("LICENSE_KEY_RATE_LIMIT_WINDOW_SECONDS"),
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
            # السكربتات المضمّنة (inline) ومعالِجات onclick في قوالب اللوحة المُعاد
            # تصميمها كانت محجوبة بـ'self' فقط → السايدبار والأزرار لا تعمل. السماح
            # بـ'unsafe-inline' للسكربتات يعيد تشغيل واجهة اللوحة (أداة إدارية خلف
            # مصادقة، قوالبها كلها داخلية). الأنسب أمنيًا لاحقًا: نقل السكربتات لملفات
            # خارجية أو استخدام nonce لكل <script> وإزالة onclick.
            "script-src 'self' 'unsafe-inline'; "
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
            # ISO-3166 alpha-2 country key + E.164 dial-code, added with the
            # country/city picker on the add-customer page.
            "country_iso": "VARCHAR(2) NOT NULL DEFAULT ''",
            "dial_code": "VARCHAR(8) NOT NULL DEFAULT ''",
        })
    # Customer Secure Vault: elevated-admin flag on existing admins tables.
    # The 3 vault tables themselves are created fresh by db.create_all().
    if "admins" in tables:
        _add_columns_if_missing("admins", {
            "is_super_admin": "BOOLEAN NOT NULL DEFAULT 0"
            if db.engine.dialect.name == "sqlite"
            else "BOOLEAN NOT NULL DEFAULT FALSE",
        })
    # سوبر يوزر صريح على مستخدمي العميل. العمود يُنشأ تلقائياً عبر db.create_all()
    # على القواعد الجديدة؛ هذا البلوك المحمي يداوي العمود الإضافي على القواعد القائمة
    # فقط (idempotent: يتجاهل إن كان موجوداً).
    if "customer_users" in tables:
        _add_columns_if_missing("customer_users", {
            "is_super": "BOOLEAN NOT NULL DEFAULT 0"
            if db.engine.dialect.name == "sqlite"
            else "BOOLEAN NOT NULL DEFAULT FALSE",
        })
    # لقطة أدمن الراديوس: الجدول يُنشأ عبر db.create_all() على القواعد الجديدة؛
    # هذا البلوك يداوي العمود الإضافي is_primary على القواعد القائمة (idempotent).
    if "customer_radius_admins" in tables:
        _add_columns_if_missing("customer_radius_admins", {
            "is_primary": "BOOLEAN NOT NULL DEFAULT 0"
            if db.engine.dialect.name == "sqlite"
            else "BOOLEAN NOT NULL DEFAULT FALSE",
        })
    # حقائق جهاز RouterOS على عقد CHR (نسخة/لوحة/uptime…) تُلتقط مع كل استطلاع
    # ناجح. القواعد الجديدة تنشئ العمود عبر db.create_all()؛ هذا يداوي القائمة.
    if "chr_nodes" in tables:
        _add_columns_if_missing("chr_nodes", {
            "device_facts_json": "TEXT NOT NULL DEFAULT '{}'",
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

    # Central CHR tunnel accounts. The table + its unique username constraint are
    # created fresh by db.create_all() on new DBs; this guarded block only heals
    # additive columns on a pre-existing table, mirroring the pattern above.
    if "customer_vpn_tunnels" in tables:
        datetime_type = "TIMESTAMP" if db.engine.dialect.name == "postgresql" else "DATETIME"
        bool_default_false = (
            "BOOLEAN NOT NULL DEFAULT 0"
            if db.engine.dialect.name == "sqlite"
            else "BOOLEAN NOT NULL DEFAULT FALSE"
        )
        _add_columns_if_missing("customer_vpn_tunnels", {
            "license_id": "INTEGER",
            "password_hint": "VARCHAR(40) NOT NULL DEFAULT ''",
            "profile": "VARCHAR(80) NOT NULL DEFAULT 'default'",
            "max_connections": "INTEGER NOT NULL DEFAULT 1",
            # Speed control columns (feat/chr-speed-profiles).
            "speed_profile_id": "INTEGER",
            "download_mbps": "INTEGER",
            "upload_mbps": "INTEGER",
            "rate_limit": "VARCHAR(80) NOT NULL DEFAULT ''",
            # Monthly quota + throttle-on-exhaust (feat/chr-monthly-quota).
            "monthly_quota_gb": "INTEGER",
            "throttle_down_mbps": "INTEGER",
            "throttle_up_mbps": "INTEGER",
            "quota_period": "VARCHAR(7) NOT NULL DEFAULT ''",
            "quota_bytes_used": "BIGINT NOT NULL DEFAULT 0",
            "quota_sample_bytes": "BIGINT NOT NULL DEFAULT 0",
            "is_throttled": bool_default_false,
            "provisioning": "VARCHAR(20) NOT NULL DEFAULT 'auto'",
            "source": "VARCHAR(30) NOT NULL DEFAULT 'bridge_request'",
            "chr_provisioned": bool_default_false,
            "chr_secret_id": "VARCHAR(40) NOT NULL DEFAULT ''",
            "chr_host": "VARCHAR(255) NOT NULL DEFAULT ''",
            "remote_address": "VARCHAR(64) NOT NULL DEFAULT ''",
            "delivery_status": "VARCHAR(20) NOT NULL DEFAULT 'pending'",
            "delivered_at": datetime_type,
            "requested_by_user_id": "INTEGER",
            "created_by_admin_id": "INTEGER",
            "last_error": "VARCHAR(255) NOT NULL DEFAULT ''",
            "notes": "TEXT NOT NULL DEFAULT ''",
        })

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
            "last_error_message": "TEXT",
            # Meta Embedded Signup (P1): onboarding path + granted scopes + sync time.
            "onboarding_method": "VARCHAR(20)",
            "scopes": "TEXT",
            "last_sync_at": datetime_type,
        })

    # Meta Embedded Signup onboarding attempts (state/nonce sessions). The table
    # itself + its PK and the unique state_hash constraint are created fresh by
    # db.create_all() on both new and live DBs; this guarded block only heals the
    # additive/nullable columns on a pre-existing table, mirroring the pattern above.
    if "whatsapp_embedded_signup_attempts" in tables:
        datetime_type = "TIMESTAMP" if db.engine.dialect.name == "postgresql" else "DATETIME"
        _add_columns_if_missing("whatsapp_embedded_signup_attempts", {
            "license_id": "INTEGER",
            "nonce_hash": "VARCHAR(128)",
            "status": "VARCHAR(20)",
            "error_code": "VARCHAR(60)",
            "error_message": "TEXT",
            "initiated_by": "INTEGER",
            "expires_at": datetime_type,
            "completed_at": datetime_type,
        })
    # FleetChrNode — per-CHR RouterOS API credentials for the live-metrics
    # poller. The columns are NEW (added on this branch) so on a fresh
    # db.create_all() they're already present; this heal exists for the
    # LIVE deployment where the table predates this branch.
    if "fleet_chr_nodes" in tables:
        bool_false = (
            "BOOLEAN NOT NULL DEFAULT 0"
            if db.engine.dialect.name == "sqlite"
            else "BOOLEAN NOT NULL DEFAULT FALSE"
        )
        _add_columns_if_missing("fleet_chr_nodes", {
            "routeros_api_user": "VARCHAR(80) NOT NULL DEFAULT ''",
            "routeros_api_password_enc": "TEXT NOT NULL DEFAULT ''",
            # Anchors the idempotent legacy→fleet migration (services/fleet_consolidation.py).
            # Nullable on purpose: only rows imported FROM the legacy chr_nodes
            # table carry a value; native fleet rows leave it NULL.
            "legacy_chr_node_id": "INTEGER",
            # feat/fleet-zero-touch-sync: CHR wg-data pubkey (proxy peer) +
            # the stale-script flag flipped on panel-key drift.
            "wg_data_pubkey": "TEXT NOT NULL DEFAULT ''",
            "needs_reimport": bool_false,
        })
        # Backfill wg_data_pubkey from the onboarding job refs for rows that
        # predate the column. Best-effort + idempotent: only touches rows that
        # are still empty and whose job carried a data_pubkey. Never raises.
        try:
            from fleet.sync.backfill import backfill_wg_data_pubkeys
            backfill_wg_data_pubkeys()
        except Exception:  # noqa: BLE001 — schema heal must never crash boot
            db.session.rollback()

    # ProxyRealmRoute — fleet allow-list column. (Pre-step-6 schemas had a
    # separate ``allowed_chr_node_ids_json`` for the legacy chr_nodes table;
    # that column is dropped a few lines below.)
    if "proxy_realm_routes" in tables:
        _add_columns_if_missing("proxy_realm_routes", {
            "allowed_fleet_chr_node_ids_json": "TEXT NOT NULL DEFAULT '[]'",
        })

    # Zero-central: each customer tunnel + WG peer carries the fleet node it
    # was provisioned on. Backfill is handled below — column add first.
    if "customer_vpn_tunnels" in tables:
        _add_columns_if_missing("customer_vpn_tunnels", {
            "fleet_chr_node_id": "INTEGER",
        })
    if "customer_wireguard_peers" in tables:
        _add_columns_if_missing("customer_wireguard_peers", {
            "fleet_chr_node_id": "INTEGER",
        })

    # ════════════════════════════════════════════════════════════════════
    # Step 6 of docs/CONSOLIDATION.md — DESTRUCTIVE removal of the legacy
    # ``chr_nodes`` registry. Owner decision: the whole legacy system is
    # gone and the fleet is canonical, so we drop the tables and migrate
    # service_allocations.chr_node_id → fleet_chr_node_id.
    #
    # All operations below are GUARDED + IDEMPOTENT — a fresh DB created
    # by db.create_all() never has the legacy tables/columns in the first
    # place, so every block is a quiet no-op.
    # ════════════════════════════════════════════════════════════════════

    # ── 6.A: service_allocations.chr_node_id → fleet_chr_node_id.
    # The model now FKs into fleet_chr_nodes(id); the old FK pointed at
    # ``chr_nodes(id)`` which we drop below. Since the data is explicitly
    # experimental, we ZERO-OUT the column (NULL) before renaming so any
    # stale legacy id can never accidentally collide with an unrelated
    # fleet id. SQLite ≥ 3.25 and PostgreSQL both support RENAME COLUMN.
    if "service_allocations" in tables:
        sa_cols = {c["name"] for c in inspect(db.engine).get_columns("service_allocations")}
        if "chr_node_id" in sa_cols and "fleet_chr_node_id" not in sa_cols:
            db.session.execute(text("UPDATE service_allocations SET chr_node_id = NULL"))
            db.session.execute(text(
                "ALTER TABLE service_allocations RENAME COLUMN chr_node_id TO fleet_chr_node_id"
            ))
            db.session.commit()
        elif "chr_node_id" in sa_cols and "fleet_chr_node_id" in sa_cols:
            # Belt-and-braces: both columns somehow coexist (manual edit?). Drop
            # the dead legacy column so it can't drift further.
            try:
                db.session.execute(text("ALTER TABLE service_allocations DROP COLUMN chr_node_id"))
                db.session.commit()
            except Exception:
                db.session.rollback()

    # ── 6.B: proxy_realm_routes.allowed_chr_node_ids_json — drop. The
    # column is no longer referenced by Python; the fleet allow-list lives
    # in ``allowed_fleet_chr_node_ids_json`` (created/healed above).
    if "proxy_realm_routes" in tables:
        prr_cols = {c["name"] for c in inspect(db.engine).get_columns("proxy_realm_routes")}
        if "allowed_chr_node_ids_json" in prr_cols:
            try:
                db.session.execute(text(
                    "ALTER TABLE proxy_realm_routes DROP COLUMN allowed_chr_node_ids_json"
                ))
                db.session.commit()
            except Exception:
                # Older SQLite (< 3.35) — leave the column in place; the
                # Python model doesn't read or write it, so it stays inert.
                db.session.rollback()

    # ── 6.C: drop the legacy tables themselves. Order matters because the
    # legacy chr_node_metrics.chr_node_id FKs into chr_nodes. We re-read the
    # table list after the SA rename so the inspector sees fresh schema.
    tables_now = set(inspect(db.engine).get_table_names())
    if "chr_node_metrics" in tables_now:
        try:
            db.session.execute(text("DROP TABLE chr_node_metrics"))
            db.session.commit()
        except Exception:
            db.session.rollback()
    if "chr_nodes" in tables_now:
        try:
            db.session.execute(text("DROP TABLE chr_nodes"))
            db.session.commit()
        except Exception:
            # PostgreSQL may need CASCADE when an FK that we couldn't drop
            # earlier is still hanging on. Try once more with cascade.
            db.session.rollback()
            try:
                db.session.execute(text("DROP TABLE chr_nodes CASCADE"))
                db.session.commit()
            except Exception:
                db.session.rollback()

    # ── Zero-central backfill: stamp the fleet node onto pre-zero-central
    # tunnel + WG-peer rows by matching the legacy ``chr_host`` column
    # against ``fleet_chr_nodes.public_ip``. Idempotent: a row that already
    # has fleet_chr_node_id stays untouched. Best-effort: failures collapse
    # to "leave the row alone" (the provisioning service will pick a node
    # at the next ``provision_*`` call).
    tables_now = set(inspect(db.engine).get_table_names())
    if {"customer_vpn_tunnels", "fleet_chr_nodes"}.issubset(tables_now):
        try:
            db.session.execute(text(
                "UPDATE customer_vpn_tunnels "
                "SET fleet_chr_node_id = (SELECT id FROM fleet_chr_nodes "
                "                          WHERE public_ip = customer_vpn_tunnels.chr_host) "
                "WHERE fleet_chr_node_id IS NULL AND chr_host <> ''"
            ))
            db.session.commit()
        except Exception:
            db.session.rollback()
    if {"customer_wireguard_peers", "fleet_chr_nodes"}.issubset(tables_now):
        try:
            db.session.execute(text(
                "UPDATE customer_wireguard_peers "
                "SET fleet_chr_node_id = (SELECT id FROM fleet_chr_nodes "
                "                          WHERE public_ip = customer_wireguard_peers.chr_host) "
                "WHERE fleet_chr_node_id IS NULL AND chr_host <> ''"
            ))
            db.session.commit()
        except Exception:
            db.session.rollback()

    # ``instance_activation_tokens`` table was retired with the activation-code
    # mechanism (legacy linking auth). The table is left alone on older DBs;
    # the panel never reads/writes it. No model, no heal.


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

    # CHR speed profiles (central rate-limit presets). Idempotent by code.
    from .models import ChrSpeedProfile as _ChrSpeedProfile
    speed_presets = [
        ("سرعة 10 ميجابت", "10m", 10, 10),
        ("سرعة 50 ميجابت", "50m", 50, 50),
        ("سرعة 100 ميجابت", "100m", 100, 100),
    ]
    for sp_name, sp_code, sp_down, sp_up in speed_presets:
        if _ChrSpeedProfile.query.filter_by(code=sp_code).first():
            continue
        db.session.add(_ChrSpeedProfile(
            name=sp_name, code=sp_code, download_mbps=sp_down, upload_mbps=sp_up, active=True,
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

    # Landing Page CMS — seed default editable homepage content (idempotent).
    try:
        from .services.landing_cms import seed_landing_defaults
        seed_landing_defaults()
    except Exception:  # pragma: no cover - seeding must never block startup
        app.logger.exception("landing CMS seed failed")
        db.session.rollback()


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

    @app.cli.command("vpn-quota-sync")
    def vpn_quota_sync_command():
        """Sample CHR VPN-tunnel usage; throttle tunnels over their monthly GB
        quota and restore/reset at month start. Run by a systemd timer every few
        minutes (the panel has no resident worker).
        """
        from .services.vpn_quota import run_once

        with app.app_context():
            summary = run_once()
        click.echo(
            "vpn-quota-sync: "
            f"checked={summary.get('checked', 0)} "
            f"throttled={summary.get('throttled', 0)} "
            f"restored={summary.get('restored', 0)} "
            f"errors={summary.get('errors', 0)}"
            + (f" fatal={summary['fatal']}" if summary.get("fatal") else "")
        )

    @app.cli.command("collect-chr-metrics")
    def collect_chr_metrics_command():
        """Poll all active CHR nodes via RouterOS REST and record ChrNodeMetric rows.
        Run by a systemd timer every 5 minutes.
        """
        from .services.chr_metrics import collect_all_nodes

        with app.app_context():
            summary = collect_all_nodes()
        click.echo(
            "collect-chr-metrics: "
            f"polled={summary.get('polled', 0)} "
            f"ok={summary.get('ok', 0)} "
            f"skipped={summary.get('skipped', 0)} "
            f"errors={summary.get('errors', 0)}"
        )

    @app.cli.command("enforce-allocations")
    @click.option(
        "--dry-run/--apply",
        default=True,
        help=(
            "--dry-run (default): اقرأ فقط — اعرض ما سيتغيّر دون كتابة. "
            "--apply: طبِّق التغييرات فعليًا."
        ),
    )
    @click.option(
        "--customer-id",
        default=None,
        type=int,
        help="حدِّد النطاق لعميل واحد فقط (للمراجعة أو الإصلاح اليدوي).",
    )
    def enforce_allocations_command(
        dry_run: bool = True,
        customer_id: int | None = None,
    ) -> None:
        """يُعيَّر ServiceAllocations المنتهية تلقائيًا ويُدقّق كل تغيير.

        الافتراضي: dry-run (لا يكتب شيئًا).
        شغّله مع --apply عبر systemd timer كل 15 دقيقة.
        """
        from .services.allocation_enforcer import run

        with app.app_context():
            result = run(dry_run=dry_run, customer_id=customer_id)

        mode = "DRY-RUN" if dry_run else "APPLY"
        if "error" in result:
            click.echo(
                f"enforce-allocations [{mode}] ERROR: {result['error']} | "
                f"expired={result.get('allocations_expired', 0)}",
                err=True,
            )
        else:
            scope = f" customer_id={customer_id}" if customer_id is not None else ""
            click.echo(
                f"enforce-allocations [{mode}] OK: "
                f"allocations_expired={result.get('allocations_expired', 0)}"
                f"{scope}"
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
        # Also exposes `hidden_sections` for sidebar visibility control.
        from .auth.routes import current_admin
        from .admin.section_visibility import get_hidden_sections
        admin = current_admin()
        return {
            "is_super_admin": bool(admin and getattr(admin, "is_super_admin", False)),
            "hidden_sections": get_hidden_sections(),
        }

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
            # Safe diagnostic: presence flags + lengths only, never token values.
            app.logger.error(
                "CSRF fail path=%s form_tok=%s hdr_tok=%s session_tok=%s sent_len=%s exp_len=%s match=%s",
                request.path,
                bool(request.form.get("_csrf_token")),
                bool(request.headers.get("X-CSRFToken")),
                bool(expected),
                len(sent or ""),
                len(expected or ""),
                (sent == expected),
            )
            abort(400, "CSRF token is invalid")
        return None


def _install_template_helpers(app: Flask) -> None:
    # Per-direction-symmetric speed helpers — wired as Jinja globals so every
    # template that shows a Mbps value can render it as «X↓ / Y↑ ميجابت» without
    # the route having to pass the helper in by hand. See
    # app/services/speed_profiles.py for the per-direction contract.
    from .services.speed_profiles import (
        per_direction_label as _per_direction_label,
        rate_limit_string as _rate_limit_string,
        symmetric_rate_limit as _symmetric_rate_limit,
    )
    app.jinja_env.globals["per_direction_label"] = _per_direction_label
    app.jinja_env.globals["rate_limit_string"] = _rate_limit_string
    app.jinja_env.globals["symmetric_rate_limit"] = _symmetric_rate_limit

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

    @app.template_filter("datetimeformat")
    def datetimeformat_filter(value, fmt="%Y-%m-%d %H:%M"):
        """تنسيق تاريخ/وقت (UTC→محلي مثل dt_local) — اسم تستخدمه القوالب المُعاد
        تصميمها. النصوص تمرّ كما هي، والأخطاء تُرجِع القيمة الخام بلا كسر."""
        if not value:
            return "—"
        if isinstance(value, str):
            return value
        import os
        from datetime import timedelta
        try:
            offset = float(os.environ.get("PORTAL_TZ_OFFSET_HOURS", "3"))
        except (TypeError, ValueError):
            offset = 3.0
        try:
            return (value + timedelta(hours=offset)).strftime(fmt)
        except Exception:  # noqa: BLE001 — التنسيق لا يجب أن يكسر صفحة
            return str(value)

    # ── حل جذري لمنع التكرار: فلتر مفقود يجب ألا يكسر الصفحة (500) ──
    # القوالب المُعاد تصميمها قد تشير أحيانًا إلى فلتر غير مسجَّل بعد (صفحة/خدمة
    # جديدة بمساعد جديد) → Jinja يرفع TemplateRuntimeError فتسقط الصفحة كاملة.
    # نجعل أي فلتر غير مسجَّل يتحوّل إلى تمرير القيمة كما هي (passthrough) مع تحذير
    # في السجل، فلا يُسقِط فلترٌ واحد مفقود صفحةً كاملة بعد الآن.
    class _FallbackFilterDict(dict):
        def __missing__(self, key):
            import logging
            logging.getLogger(__name__).warning(
                "Jinja filter '%s' غير مسجَّل — استخدام تمرير احتياطي", key)
            return lambda value, *a, **k: value

    app.jinja_env.filters = _FallbackFilterDict(app.jinja_env.filters)

    # ── حل جذري (الجزء الثاني): متغيّر سياق مفقود يجب ألا يكسر الصفحة ──
    # القوالب المُعاد تصميمها قد تشير لمتغيّر لا يمرّره الراوت (مثل `usage` في
    # licenses/detail_new) → Jinja الافتراضي يرفع UndefinedError فتسقط الصفحة 500.
    # ChainableUndefined يسمح بسلسلة الوصول (usage.users.foo) دون رفع، ويُعرَض فارغًا،
    # و|default(x) يلتقطه فيعطي البديل. فالصفحة تفتح (بقيم فارغة/افتراضية) بدل الكسر.
    from jinja2 import ChainableUndefined
    app.jinja_env.undefined = ChainableUndefined

    # ── حل جذري (الجزء الثالث): url_for لـendpoint غير موجود يجب ألا يكسر الصفحة ──
    # القوالب المُعاد تصميمها قد تشير إلى endpoint لم يُسجَّل بعد (مثل
    # admin_infra.proxy_routes_reload) → Flask يرمي BuildError فتسقط الصفحة 500.
    # نغلّف url_for في القوالب: عند فشل البناء نُعيد '#' (رابط آمن) + تحذير في السجل،
    # فالصفحة تفتح ويظهر الزر/الرابط معطّلاً بدل أن تنكسر الصفحة كاملة.
    from flask import url_for as _flask_url_for
    from werkzeug.routing.exceptions import BuildError as _BuildError

    def _safe_url_for(endpoint, **values):
        try:
            return _flask_url_for(endpoint, **values)
        except _BuildError:
            import logging
            logging.getLogger(__name__).warning(
                "url_for: endpoint '%s' غير موجود — رابط احتياطي '#'", endpoint)
            return "#"

    app.jinja_env.globals["url_for"] = _safe_url_for

    # ── Static asset cache-busting ────────────────────────────────────────
    # Append ?v=<file-mtime> to every static URL so a deploy that changes a
    # CSS/JS file automatically invalidates the browser (and any CDN) cache.
    # Without this, fixes to admin_design_sweep.js / *.css kept showing the
    # OLD behaviour after a deploy until the operator did a manual hard
    # refresh — the source of repeated "I fixed it but it's still broken"
    # confusion (e.g. the confirm-modal fixes). mtime changes on every git
    # checkout/deploy, so the param self-updates with zero template edits.
    _static_version_cache: dict[str, int] = {}

    @app.url_defaults
    def _add_static_version(endpoint, values):
        if endpoint != "static" or not values.get("filename"):
            return
        filename = values["filename"]
        ver = _static_version_cache.get(filename)
        if ver is None:
            try:
                static_root = app.static_folder or ""
                ver = int(os.stat(os.path.join(static_root, filename)).st_mtime)
            except OSError:
                ver = 0
            # Cache only in non-debug so dev edits always re-stat; prod is
            # stable per process (a deploy restarts the process anyway).
            if not app.debug:
                _static_version_cache[filename] = ver
        if ver:
            values.setdefault("v", ver)

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
