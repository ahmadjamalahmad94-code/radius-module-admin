"""SEC M7 — default credentials never boot silently.

The strong-credential gate in _validate_production_config only fires for an
explicitly-declared prod/bootstrap env. A production deploy that forgets
LICENSE_PANEL_ENV skips that gate entirely and boots on dev-secret-change-me /
admin12345 with no signal. We can't force prod behaviour (it would break local
dev), but the fail-open must be LOUD: a warning fires whenever default
credentials are in use outside a declared prod env — and it never leaks the
actual secret/password values.
"""
from __future__ import annotations

import logging

from app import create_app, _validate_production_config
from app.config import Config, TestingConfig


def _app_with(**overrides):
    app = create_app(TestingConfig, **overrides)
    # Exercise the real (non-testing) validation path.
    app.config["TESTING"] = False
    app.config["LICENSE_PANEL_ENV"] = "local"   # env not declared prod
    return app


def test_default_creds_emit_loud_warning(caplog):
    app = _app_with(ADMIN_PASSWORD=Config.DEFAULT_ADMIN_PASSWORD)
    app.config["SECRET_KEY"] = Config.DEFAULT_SECRET_KEY
    with caplog.at_level(logging.WARNING):
        _validate_production_config(app)
    assert "INSECURE BOOT" in caplog.text
    # The warning names WHICH credential, but never the value itself.
    assert Config.DEFAULT_ADMIN_PASSWORD not in caplog.text
    assert Config.DEFAULT_SECRET_KEY not in caplog.text


def test_strong_creds_boot_quietly(caplog):
    app = _app_with(ADMIN_PASSWORD="a-strong-unique-local-password")
    app.config["SECRET_KEY"] = "a-strong-random-flask-secret-32bytes-xx"
    with caplog.at_level(logging.WARNING):
        _validate_production_config(app)
    assert "INSECURE BOOT" not in caplog.text


def test_warning_does_not_raise(caplog):
    """The M7 net only warns — it must never turn a local dev boot into a hard
    failure (that's what the declared-prod gate is for)."""
    app = _app_with(ADMIN_PASSWORD=Config.DEFAULT_ADMIN_PASSWORD)
    app.config["SECRET_KEY"] = Config.DEFAULT_SECRET_KEY
    # Should return None without raising.
    assert _validate_production_config(app) is None
