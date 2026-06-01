from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DATABASE_URI = f"sqlite:///{BASE_DIR / 'instance' / 'license_panel.sqlite3'}"


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer.") from exc


def _is_production_env() -> bool:
    return os.environ.get("LICENSE_PANEL_ENV", "local").strip().lower() in {"prod", "production"}


def _is_bootstrap_env() -> bool:
    return (
        os.environ.get("LICENSE_PANEL_ENV", "local").strip().lower() == "bootstrap"
        or _env_bool("LICENSE_PANEL_BOOTSTRAP_MODE", False)
    )


def _is_strict_deployment_env() -> bool:
    return _is_production_env() or _is_bootstrap_env()


class Config:
    DEFAULT_SECRET_KEY = "dev-secret-change-me"
    DEFAULT_ADMIN_PASSWORD = "admin12345"
    DEFAULT_DATABASE_URI = DEFAULT_DATABASE_URI

    SECRET_KEY = os.environ.get("FLASK_SECRET", DEFAULT_SECRET_KEY)
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", DEFAULT_DATABASE_URI)
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    LICENSE_PANEL_ENV = os.environ.get("LICENSE_PANEL_ENV", "local")
    BOOTSTRAP_MODE = _is_bootstrap_env()
    DEFAULT_GRACE_DAYS = _env_int("DEFAULT_GRACE_DAYS", 7)
    DEFAULT_CURRENCY = os.environ.get("DEFAULT_CURRENCY", "USD")
    SUPPORT_EMAIL = os.environ.get("SUPPORT_EMAIL", "support@example.com")
    SUPPORT_PHONE = os.environ.get("SUPPORT_PHONE", "")
    ADMIN_USERNAME = os.environ.get("LICENSE_ADMIN_USERNAME", "admin")
    ADMIN_PASSWORD = os.environ.get("LICENSE_ADMIN_PASSWORD", DEFAULT_ADMIN_PASSWORD)
    ADMIN_EMAIL = os.environ.get("LICENSE_ADMIN_EMAIL", "admin@example.com")
    AUTO_INIT_DB = _env_bool("AUTO_INIT_DB", True)
    WTF_CSRF_ENABLED = True
    RATE_LIMITS_ENABLED = _env_bool("RATE_LIMITS_ENABLED", True)
    LOGIN_RATE_LIMIT_MAX = _env_int("LOGIN_RATE_LIMIT_MAX", 10)
    LOGIN_RATE_LIMIT_WINDOW_SECONDS = _env_int("LOGIN_RATE_LIMIT_WINDOW_SECONDS", 900)
    LICENSE_CHECK_RATE_LIMIT_MAX = _env_int("LICENSE_CHECK_RATE_LIMIT_MAX", 120)
    LICENSE_CHECK_RATE_LIMIT_WINDOW_SECONDS = _env_int("LICENSE_CHECK_RATE_LIMIT_WINDOW_SECONDS", 60)
    LICENSE_KEY_RATE_LIMIT_MAX = _env_int("LICENSE_KEY_RATE_LIMIT_MAX", 600)
    LICENSE_KEY_RATE_LIMIT_WINDOW_SECONDS = _env_int("LICENSE_KEY_RATE_LIMIT_WINDOW_SECONDS", 300)
    LICENSE_CHECK_HMAC_SECRET = os.environ.get("LICENSE_CHECK_HMAC_SECRET", "")
    LICENSE_CHECK_SIGNATURE_REQUIRED = _env_bool("LICENSE_CHECK_SIGNATURE_REQUIRED", _is_strict_deployment_env())
    LICENSE_CHECK_ALLOW_UNSIGNED = _env_bool("LICENSE_CHECK_ALLOW_UNSIGNED", not _is_strict_deployment_env())
    LICENSE_CHECK_MAX_CLOCK_SKEW_SECONDS = _env_int("LICENSE_CHECK_MAX_CLOCK_SKEW_SECONDS", 300)
    LICENSE_CHECK_REPLAY_WINDOW_SECONDS = _env_int("LICENSE_CHECK_REPLAY_WINDOW_SECONDS", 600)
    LICENSE_CHECK_NONCE_CACHE_MAX = _env_int("LICENSE_CHECK_NONCE_CACHE_MAX", 5000)
    TRUST_PROXY_HEADERS = _env_bool("TRUST_PROXY_HEADERS", False)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = os.environ.get("SESSION_COOKIE_SAMESITE", "Lax")
    SESSION_COOKIE_SECURE = _env_bool("SESSION_COOKIE_SECURE", _is_production_env())
    SESSION_LIFETIME_SECONDS = _env_int("SESSION_LIFETIME_SECONDS", 43200)
    PERMANENT_SESSION_LIFETIME = SESSION_LIFETIME_SECONDS
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
    WHATSAPP_GATEWAY_ENABLED = _env_bool("WHATSAPP_GATEWAY_ENABLED", True)
    WHATSAPP_FERNET_KEY = os.environ.get("WHATSAPP_FERNET_KEY", "")
    WHATSAPP_GRAPH_API_VERSION = os.environ.get("WHATSAPP_GRAPH_API_VERSION", "v21.0")
    WHATSAPP_GRAPH_BASE = os.environ.get("WHATSAPP_GRAPH_BASE", "https://graph.facebook.com")
    WHATSAPP_HTTP_TIMEOUT_SECONDS = _env_int("WHATSAPP_HTTP_TIMEOUT_SECONDS", 15)
    WHATSAPP_DRAIN_BATCH_SIZE = _env_int("WHATSAPP_DRAIN_BATCH_SIZE", 50)
    WHATSAPP_MAX_ATTEMPTS = _env_int("WHATSAPP_MAX_ATTEMPTS", 3)
    WHATSAPP_DEFAULT_TIMEZONE = os.environ.get("WHATSAPP_DEFAULT_TIMEZONE", "Asia/Hebron")
    WHATSAPP_DEFAULT_COUNTRY = os.environ.get("WHATSAPP_DEFAULT_COUNTRY", "PS")


class TestingConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False
    RATE_LIMITS_ENABLED = False
    AUTO_INIT_DB = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    # Fixed valid 32-byte urlsafe-base64 Fernet key so WhatsApp crypto works
    # deterministically under tests. Test-only; never used in deployment.
    WHATSAPP_FERNET_KEY = "t7Hk9w0Qd2cQ3pYy5sFv8nJzZbR1mLxWtUe4aGhKpD0="
