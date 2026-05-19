from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


class Config:
    DEFAULT_SECRET_KEY = "dev-secret-change-me"
    DEFAULT_ADMIN_PASSWORD = "admin12345"

    SECRET_KEY = os.environ.get("FLASK_SECRET", DEFAULT_SECRET_KEY)
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        f"sqlite:///{BASE_DIR / 'instance' / 'license_panel.sqlite3'}",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    LICENSE_PANEL_ENV = os.environ.get("LICENSE_PANEL_ENV", "local")
    DEFAULT_GRACE_DAYS = int(os.environ.get("DEFAULT_GRACE_DAYS", "7"))
    DEFAULT_CURRENCY = os.environ.get("DEFAULT_CURRENCY", "USD")
    SUPPORT_EMAIL = os.environ.get("SUPPORT_EMAIL", "support@example.com")
    SUPPORT_PHONE = os.environ.get("SUPPORT_PHONE", "")
    ADMIN_USERNAME = os.environ.get("LICENSE_ADMIN_USERNAME", "admin")
    ADMIN_PASSWORD = os.environ.get("LICENSE_ADMIN_PASSWORD", DEFAULT_ADMIN_PASSWORD)
    ADMIN_EMAIL = os.environ.get("LICENSE_ADMIN_EMAIL", "admin@example.com")
    AUTO_INIT_DB = os.environ.get("AUTO_INIT_DB", "1") == "1"
    WTF_CSRF_ENABLED = True
    RATE_LIMITS_ENABLED = os.environ.get("RATE_LIMITS_ENABLED", "1") == "1"
    LOGIN_RATE_LIMIT_MAX = int(os.environ.get("LOGIN_RATE_LIMIT_MAX", "10"))
    LOGIN_RATE_LIMIT_WINDOW_SECONDS = int(os.environ.get("LOGIN_RATE_LIMIT_WINDOW_SECONDS", "900"))
    LICENSE_CHECK_RATE_LIMIT_MAX = int(os.environ.get("LICENSE_CHECK_RATE_LIMIT_MAX", "120"))
    LICENSE_CHECK_RATE_LIMIT_WINDOW_SECONDS = int(os.environ.get("LICENSE_CHECK_RATE_LIMIT_WINDOW_SECONDS", "60"))


class TestingConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False
    RATE_LIMITS_ENABLED = False
    AUTO_INIT_DB = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
