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

    # Customer Secure Vault — Fernet key for encrypting per-customer secrets at rest.
    # Comes from the environment ONLY; never stored in the DB, never committed.
    # If empty, the vault UI works but creating/revealing secrets is blocked.
    CUSTOMER_VAULT_ENCRYPTION_KEY = os.environ.get("CUSTOMER_VAULT_ENCRYPTION_KEY", "")

    # ── Meta WhatsApp Embedded Signup ──────────────────────────────────────
    # Self-service onboarding via Meta's Embedded Signup (replaces manual token
    # paste as the primary path). All values come from the environment ONLY —
    # never hardcoded, never committed. When the App ID / Config ID are absent
    # (or the flag is off) the embedded-signup CTA is hidden and the manual
    # "advanced" path remains available, so nothing breaks before creds exist.
    META_EMBEDDED_SIGNUP_ENABLED = _env_bool("META_EMBEDDED_SIGNUP_ENABLED", True)
    META_APP_ID = os.environ.get("META_APP_ID", "")
    META_APP_SECRET = os.environ.get("META_APP_SECRET", "")
    META_CONFIG_ID = os.environ.get("META_CONFIG_ID", "")  # Embedded Signup configuration id
    META_GRAPH_VERSION = os.environ.get("META_GRAPH_VERSION", WHATSAPP_GRAPH_API_VERSION)
    # Optional explicit OAuth redirect override (else derived from url_for).
    META_OAUTH_REDIRECT_URI = os.environ.get("META_OAUTH_REDIRECT_URI", "")
    # Lifetime (seconds) of a server-issued embedded-signup state/nonce session
    # before it expires; the completion callback must arrive within this window.
    META_EMBEDDED_ATTEMPT_TTL_SECONDS = _env_int("META_EMBEDDED_ATTEMPT_TTL_SECONDS", 600)
    # When True, the completion callback MUST carry a valid server-issued state
    # (no legacy/no-state path). Default False so a missing/legacy flow degrades
    # safely; the callback still enforces state whenever the frontend supplies it.
    META_EMBEDDED_REQUIRE_STATE = _env_bool("META_EMBEDDED_REQUIRE_STATE", False)

    # ── MikroTik CHR central tunnel provisioning (SSTP/PPTP/L2TP) ──────────
    # The owner connects ONE central CHR (RouterOS v7) here; the panel creates
    # /ppp/secret accounts on it via the RouterOS REST API and delivers the
    # credentials to customer panels over the signed bridge. The CHR host/port/
    # user/password are entered by the OWNER in panel settings (stored in the
    # `settings` table; the password ENCRYPTED via CUSTOMER_VAULT_ENCRYPTION_KEY)
    # — never hardcoded. Env vars below are only operational toggles/defaults,
    # not credentials.
    CHR_PROVISIONING_ENABLED = _env_bool("CHR_PROVISIONING_ENABLED", True)
    # RouterOS REST API runs over HTTPS; CHR ships a self-signed cert, so TLS
    # verification defaults OFF. Set CHR_TLS_VERIFY=1 once a trusted cert exists.
    CHR_TLS_VERIFY = _env_bool("CHR_TLS_VERIFY", False)
    CHR_HTTP_TIMEOUT_SECONDS = _env_int("CHR_HTTP_TIMEOUT_SECONDS", 15)
    # Fallback ceiling for how many simultaneous tunnel accounts one customer may
    # hold when their VPN entitlement does not specify max_vpn_users.
    CHR_DEFAULT_MAX_TUNNELS = _env_int("CHR_DEFAULT_MAX_TUNNELS", 5)
    # Default RouterOS /ppp/profile applied to provisioned secrets.
    CHR_DEFAULT_PPP_PROFILE = os.environ.get("CHR_DEFAULT_PPP_PROFILE", "default")

    # ── WhatsApp Cloud API settings panel (admin-managed credentials) ──────
    # Lets an admin store/manage the house Meta Cloud API credentials in the
    # panel settings (encrypted) instead of editing env. When disabled, the
    # section is hidden. Env vars below act as a FALLBACK when no DB value is
    # saved (DB overrides env only when explicitly saved).
    WHATSAPP_CLOUD_SETTINGS_ENABLED = _env_bool("WHATSAPP_CLOUD_SETTINGS_ENABLED", True)
    WHATSAPP_ACCESS_TOKEN = os.environ.get("WHATSAPP_ACCESS_TOKEN", "")
    WHATSAPP_PHONE_NUMBER_ID = os.environ.get("WHATSAPP_PHONE_NUMBER_ID", "")
    WHATSAPP_BUSINESS_ACCOUNT_ID = os.environ.get("WHATSAPP_BUSINESS_ACCOUNT_ID", "")


class TestingConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False
    RATE_LIMITS_ENABLED = False
    AUTO_INIT_DB = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    # Fixed valid 32-byte urlsafe-base64 Fernet keys so crypto works
    # deterministically under tests. Test-only; never used in deployment.
    WHATSAPP_FERNET_KEY = "t7Hk9w0Qd2cQ3pYy5sFv8nJzZbR1mLxWtUe4aGhKpD0="
    CUSTOMER_VAULT_ENCRYPTION_KEY = "e1R4rJoOuYz751w-g5Xd1HzPIUPuIWwXdI8bD8Zty_8="
    # Deterministic Meta Embedded Signup creds for tests (mocked network calls).
    META_EMBEDDED_SIGNUP_ENABLED = True
    META_APP_ID = "test-app-id"
    META_APP_SECRET = "test-app-secret"
    META_CONFIG_ID = "test-config-id"
