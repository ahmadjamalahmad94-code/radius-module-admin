from __future__ import annotations

import logging

import pytest

from app import create_app, seed_defaults
from app.bootstrap import BootstrapError, bootstrap_admin_from_config
from app.config import Config, TestingConfig
from app.extensions import db
from app.models import Admin, Plan


def test_empty_db_bootstrap_creates_first_admin():
    app = create_app(TestingConfig)
    with app.app_context():
        db.create_all()
        admin = bootstrap_admin_from_config(app, fail_if_exists=True)
        db.session.commit()

        assert admin.username == "admin"
        assert Admin.query.count() == 1
        assert Admin.query.first().password_hash != "admin12345"
        assert Admin.query.first().check_password("admin12345")


def test_existing_admin_prevents_rebootstrap():
    app = create_app(TestingConfig)
    with app.app_context():
        db.create_all()
        bootstrap_admin_from_config(app, fail_if_exists=True)
        db.session.commit()

        with pytest.raises(BootstrapError, match="already exists"):
            bootstrap_admin_from_config(app, fail_if_exists=True)

        assert Admin.query.count() == 1


def test_seed_defaults_is_idempotent_when_admin_exists(app):
    seed_defaults(app)
    seed_defaults(app)

    assert Admin.query.count() == 1
    assert Plan.query.filter_by(slug="pro").count() == 1


def test_production_bootstrap_refuses_default_password_without_leaking_secret(caplog):
    app = create_app(
        TestingConfig,
        LICENSE_PANEL_ENV="production",
        ADMIN_PASSWORD=Config.DEFAULT_ADMIN_PASSWORD,
    )
    with app.app_context(), caplog.at_level(logging.INFO):
        db.create_all()
        with pytest.raises(BootstrapError) as exc:
            bootstrap_admin_from_config(app, fail_if_exists=True)

    assert Config.DEFAULT_ADMIN_PASSWORD not in str(exc.value)
    assert Config.DEFAULT_ADMIN_PASSWORD not in caplog.text


def test_bootstrap_admin_cli_creates_first_admin():
    app = create_app(
        TestingConfig,
        ADMIN_USERNAME="ops-admin",
        ADMIN_PASSWORD="strong-local-password",
        ADMIN_EMAIL="ops@example.test",
    )
    with app.app_context():
        db.create_all()

    result = app.test_cli_runner().invoke(args=["bootstrap-admin"])

    assert result.exit_code == 0
    assert "ops-admin" in result.output
    assert "strong-local-password" not in result.output
    with app.app_context():
        admin = Admin.query.filter_by(username="ops-admin").first()
        assert admin is not None
        assert admin.check_password("strong-local-password")


def test_bootstrap_admin_cli_refuses_existing_admin():
    app = create_app(TestingConfig, ADMIN_PASSWORD="strong-local-password")
    with app.app_context():
        db.create_all()
        bootstrap_admin_from_config(app, fail_if_exists=True)
        db.session.commit()

    result = app.test_cli_runner().invoke(args=["bootstrap-admin"])

    assert result.exit_code != 0
    assert "already exists" in result.output
    assert "strong-local-password" not in result.output
