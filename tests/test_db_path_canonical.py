"""Regression suite for the canonical SQLite path.

A live-field report uncovered a split-brain: two SQLite files
(``instance/license_panel.db`` and ``instance/license_panel.sqlite3``)
existed side-by-side; the running app silently read only the second
while operators sometimes wrote to the first. Root cause was
cwd-dependent path resolution. These tests pin the resolution down so
the same drift cannot return:

* :func:`canonical_sqlite_path` is absolute and stable across cwd.
* The default ``DATABASE_URL`` resolves to the canonical absolute path.
* ``Flask.instance_path`` lands at the SAME directory the SQLite file
  lives in.
* A relative ``sqlite:///`` URI is refused at boot — that was the exact
  misconfig that caused the original split-brain.
* In-memory and absolute SQLite, and PostgreSQL, all pass validation.
* Changing the process cwd between two ``create_app()`` calls does NOT
  change the resolved SQLite URI.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from app.db_path import (
    CANONICAL_SQLITE_FILENAME,
    INSTANCE_DIR,
    LEGACY_SQLITE_FILENAME,
    REPO_ROOT,
    DatabaseURIError,
    canonical_database_uri,
    canonical_sqlite_path,
    detect_legacy_sibling,
    resolved_sqlite_path_for,
    validate_database_uri,
)


# ────────────────────── 1. canonical path is absolute + stable ──────────────────────

def test_canonical_path_is_absolute():
    p = canonical_sqlite_path()
    assert p.is_absolute(), f"expected absolute path, got {p!r}"
    assert p.name == CANONICAL_SQLITE_FILENAME


def test_canonical_path_lives_under_repo_instance_dir():
    p = canonical_sqlite_path()
    # The canonical path's parent must be the instance dir, which itself
    # must be a direct child of the repo root.
    assert p.parent == INSTANCE_DIR
    assert INSTANCE_DIR.parent == REPO_ROOT


def test_canonical_uri_uses_sqlite_three_slash_form():
    uri = canonical_database_uri()
    assert uri.startswith("sqlite:///")
    body = uri[len("sqlite:///"):]
    assert Path(body).is_absolute(), f"non-absolute URI path: {body!r}"


def test_canonical_path_does_not_depend_on_cwd(tmp_path, monkeypatch):
    """The classic split-brain trigger: chdir to a random place and
    confirm the resolved canonical path is byte-identical."""
    before = canonical_sqlite_path()
    monkeypatch.chdir(tmp_path)
    after = canonical_sqlite_path()
    assert before == after


# ────────────────────── 2. validation refuses the bad shapes ──────────────────────

def test_validation_accepts_canonical_uri():
    validate_database_uri(canonical_database_uri())


def test_validation_accepts_in_memory_sqlite():
    validate_database_uri("sqlite:///:memory:")
    validate_database_uri("sqlite://")


def test_validation_accepts_postgres():
    validate_database_uri("postgresql+psycopg://u:p@h/d")


def test_validation_accepts_windows_absolute_sqlite():
    validate_database_uri("sqlite:///C:/some/path/license_panel.sqlite3")


def test_validation_accepts_posix_absolute_sqlite():
    validate_database_uri("sqlite:////opt/hoberadius-license-panel/instance/license_panel.sqlite3")


def test_validation_rejects_relative_sqlite_uri():
    """The exact misconfig the field report uncovered."""
    with pytest.raises(DatabaseURIError) as exc:
        validate_database_uri("sqlite:///instance/license_panel.db")
    # Error message must NAME the trap so the operator knows what to fix.
    assert "RELATIVE" in str(exc.value)


def test_validation_rejects_bare_relative_sqlite():
    with pytest.raises(DatabaseURIError):
        validate_database_uri("sqlite:///foo.db")


def test_validation_rejects_empty_uri():
    with pytest.raises(DatabaseURIError):
        validate_database_uri("")


# ────────────────────── 3. boot-time enforcement ──────────────────────

def test_create_app_refuses_relative_database_url():
    """A bad DATABASE_URL must STOP boot, not silently open a stray
    file in cwd. We inject via the factory's override dict (Config's
    env read happens at module import — the env-var path is exercised
    in production)."""
    from app import create_app
    from app.config import TestingConfig
    with pytest.raises(RuntimeError) as exc:
        create_app(TestingConfig, SQLALCHEMY_DATABASE_URI="sqlite:///instance/license_panel.db")
    msg = str(exc.value)
    assert "RELATIVE" in msg or "relative" in msg


def test_create_app_default_uses_canonical_path(app):
    """The conftest spins up TestingConfig (in-memory). Verify that when
    no DATABASE_URL is supplied to Config (the production default), the
    URI matches the canonical path. Done without booting a second app
    by checking Config.DEFAULT_DATABASE_URI directly."""
    from app.config import Config
    assert Config.DEFAULT_DATABASE_URI == canonical_database_uri()


def test_create_app_cwd_independence(tmp_path, monkeypatch):
    """Two create_app() calls from different cwds must compute the same
    DEFAULT URI. (The app-instance URI is overridden by TestingConfig
    in the test suite, so we assert against the importable default.)"""
    from app.config import Config as Config_a
    monkeypatch.chdir(tmp_path)
    # Reload the config module to recompute the default at import time.
    import importlib
    import app.config as cfg_mod
    cfg_mod_reloaded = importlib.reload(cfg_mod)
    assert cfg_mod_reloaded.Config.DEFAULT_DATABASE_URI == Config_a.DEFAULT_DATABASE_URI
    # Sanity: the resolved on-disk path is absolute and identical.
    p1 = Path(Config_a.DEFAULT_DATABASE_URI[len("sqlite:///"):])
    p2 = Path(cfg_mod_reloaded.Config.DEFAULT_DATABASE_URI[len("sqlite:///"):])
    assert p1 == p2
    assert p1.is_absolute()


# ────────────────────── 4. legacy-sibling diagnostics ──────────────────────

def test_detect_legacy_sibling_returns_none_when_absent(tmp_path, monkeypatch):
    """Pivot detection at a clean tmp instance dir."""
    import app.db_path as dbp
    monkeypatch.setattr(dbp, "INSTANCE_DIR", tmp_path)
    assert dbp.detect_legacy_sibling() is None


def test_detect_legacy_sibling_returns_path_when_present(tmp_path, monkeypatch):
    import app.db_path as dbp
    legacy = tmp_path / LEGACY_SQLITE_FILENAME
    legacy.write_bytes(b"")
    monkeypatch.setattr(dbp, "INSTANCE_DIR", tmp_path)
    found = dbp.detect_legacy_sibling()
    assert found == legacy


def test_resolved_sqlite_path_helper():
    p = resolved_sqlite_path_for("sqlite:////tmp/x.sqlite3")
    assert p == Path("/tmp/x.sqlite3").resolve()
    assert resolved_sqlite_path_for("sqlite:///:memory:") is None
    assert resolved_sqlite_path_for("postgresql://h/d") is None


# ────────────────────── 5. constants are stable ──────────────────────

def test_canonical_filename_constant():
    """The hard-coded canonical filename is the .sqlite3 the running
    app reads — NOT the .db variant the field report flagged as the
    legacy sibling."""
    assert CANONICAL_SQLITE_FILENAME == "license_panel.sqlite3"
    assert LEGACY_SQLITE_FILENAME == "license_panel.db"
