"""DB sibling policy + DATABASE_URL explicitness — field-session regressions.

Three behaviours pinned down (fix/fleet-deterministic-onboarding):

1. ``license_panel.db`` as a SYMLINK to the canonical ``.sqlite3`` is the
   owner's sanctioned aliasing — classify ``symlink_ok``, no boot warning.
2. ``license_panel.db`` as a SEPARATE REAL file is the split-brain hazard
   — classify ``conflict``; the app REFUSES to boot when it is actually
   running on the file-backed canonical DB.
3. "Explicit DATABASE_URL" means the env var EXISTS — not that its value
   differs from the built-in default string. The old string-equality
   check rejected a perfectly explicit prod env URL whenever it spelled
   the same canonical path the default computes (which a correct prod
   env file does), forcing the fragile run_panel.sh wrapper in the field.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

import app.db_path as dbp
from app.db_path import (
    LEGACY_ABSENT,
    LEGACY_CONFLICT,
    LEGACY_SYMLINK_OK,
    classify_legacy_sibling,
    detect_legacy_sibling,
)


def _make_canonical(tmp_path: Path) -> Path:
    canonical = tmp_path / "license_panel.sqlite3"
    canonical.write_bytes(b"canonical")
    return canonical


def _try_symlink(link: Path, target: Path) -> bool:
    """Windows needs admin/dev-mode for symlinks — skip gracefully if denied."""
    try:
        link.symlink_to(target)
        return True
    except (OSError, NotImplementedError):
        return False


# ── classification unit tests ───────────────────────────────────────────


def test_absent_when_no_legacy_file(tmp_path, monkeypatch):
    monkeypatch.setattr(dbp, "INSTANCE_DIR", tmp_path)
    _make_canonical(tmp_path)
    state, path = classify_legacy_sibling()
    assert state == LEGACY_ABSENT and path is None
    assert detect_legacy_sibling() is None


def test_symlink_to_canonical_is_ok_not_conflict(tmp_path, monkeypatch):
    monkeypatch.setattr(dbp, "INSTANCE_DIR", tmp_path)
    canonical = _make_canonical(tmp_path)
    legacy = tmp_path / "license_panel.db"
    if not _try_symlink(legacy, canonical):
        pytest.skip("symlink creation not permitted on this host")
    state, path = classify_legacy_sibling()
    assert state == LEGACY_SYMLINK_OK
    assert path == legacy
    # Back-compat shim: symlink is NOT reported as a sibling hazard.
    assert detect_legacy_sibling() is None


def test_hardlink_to_canonical_is_ok(tmp_path, monkeypatch):
    monkeypatch.setattr(dbp, "INSTANCE_DIR", tmp_path)
    canonical = _make_canonical(tmp_path)
    legacy = tmp_path / "license_panel.db"
    try:
        os.link(canonical, legacy)
    except (OSError, NotImplementedError):
        pytest.skip("hardlink creation not permitted on this host")
    state, _ = classify_legacy_sibling()
    assert state == LEGACY_SYMLINK_OK


def test_separate_real_file_is_conflict(tmp_path, monkeypatch):
    monkeypatch.setattr(dbp, "INSTANCE_DIR", tmp_path)
    _make_canonical(tmp_path)
    legacy = tmp_path / "license_panel.db"
    legacy.write_bytes(b"divergent twin")
    state, path = classify_legacy_sibling()
    assert state == LEGACY_CONFLICT
    assert path == legacy
    assert detect_legacy_sibling() == legacy


def test_dangling_symlink_is_harmless(tmp_path, monkeypatch):
    monkeypatch.setattr(dbp, "INSTANCE_DIR", tmp_path)
    _make_canonical(tmp_path)
    legacy = tmp_path / "license_panel.db"
    if not _try_symlink(legacy, tmp_path / "gone.sqlite3"):
        pytest.skip("symlink creation not permitted on this host")
    state, _ = classify_legacy_sibling()
    # A dangling link opens nothing → cannot split-brain.
    assert state == LEGACY_SYMLINK_OK


# ── boot policy ─────────────────────────────────────────────────────────


def test_boot_refuses_on_canonical_db_with_conflicting_twin(tmp_path, monkeypatch):
    """File-backed canonical DB + separate real legacy file → RuntimeError
    at create_app (the divergence must not be allowed to grow)."""
    monkeypatch.setattr(dbp, "INSTANCE_DIR", tmp_path)
    canonical = _make_canonical(tmp_path)
    (tmp_path / "license_panel.db").write_bytes(b"divergent twin")

    from app import create_app
    from app.config import TestingConfig
    uri = "sqlite:///" + canonical.resolve().as_posix()
    with pytest.raises(RuntimeError) as exc:
        create_app(TestingConfig, SQLALCHEMY_DATABASE_URI=uri)
    assert "split-brain" in str(exc.value)


def test_boot_clean_with_symlink_twin_no_warning(tmp_path, monkeypatch, caplog):
    """Symlink twin → boots, and NO legacy-sibling warning in the log."""
    monkeypatch.setattr(dbp, "INSTANCE_DIR", tmp_path)
    canonical = _make_canonical(tmp_path)
    legacy = tmp_path / "license_panel.db"
    if not _try_symlink(legacy, canonical):
        pytest.skip("symlink creation not permitted on this host")

    from app import create_app
    from app.config import TestingConfig
    uri = "sqlite:///" + canonical.resolve().as_posix()
    import logging
    with caplog.at_level(logging.WARNING):
        app_obj = create_app(TestingConfig, SQLALCHEMY_DATABASE_URI=uri)
    assert app_obj is not None
    assert not any(
        "Legacy SQLite sibling" in rec.getMessage() or "split-brain" in rec.getMessage()
        for rec in caplog.records
    )


def test_boot_in_memory_ignores_conflict_with_warning_only(tmp_path, monkeypatch, caplog):
    """A test/Postgres process (not on the canonical file) must still boot —
    the twin can't bite it — but the operator gets a warning."""
    monkeypatch.setattr(dbp, "INSTANCE_DIR", tmp_path)
    _make_canonical(tmp_path)
    (tmp_path / "license_panel.db").write_bytes(b"divergent twin")

    from app import create_app
    from app.config import TestingConfig
    import logging
    with caplog.at_level(logging.WARNING):
        app_obj = create_app(TestingConfig)  # in-memory sqlite
    assert app_obj is not None
    assert any("separate real file" in rec.getMessage() for rec in caplog.records)


# ── DATABASE_URL explicitness (the systemd incident) ────────────────────


def test_explicit_env_url_equal_to_default_is_accepted(monkeypatch):
    """THE regression: env DATABASE_URL whose value equals the built-in
    default string must count as explicit. The old string-equality check
    rejected exactly this (a correct prod env file pointing at the
    canonical path) and forced the run_panel.sh wrapper."""
    from app import _validate_production_config
    from app.config import Config

    monkeypatch.setenv("DATABASE_URL", Config.DEFAULT_DATABASE_URI)

    class _FakeApp:
        config = {
            "TESTING": False,
            "LICENSE_PANEL_ENV": "production",
            "BOOTSTRAP_MODE": False,
            "DEBUG": False,
            "SECRET_KEY": "a-strong-unique-secret-key-of-decent-length!!",
            "ADMIN_PASSWORD": "a-strong-unique-admin-password!",
            "SQLALCHEMY_DATABASE_URI": Config.DEFAULT_DATABASE_URI,
            "RATE_LIMITS_ENABLED": True,
            "SESSION_COOKIE_SECURE": True,
        }
    monkeypatch.delenv("FLASK_DEBUG", raising=False)
    # Must NOT raise — the env var exists, so the URL is explicit.
    _validate_production_config(_FakeApp())


def test_missing_env_url_is_rejected_in_production(monkeypatch):
    from app import _validate_production_config
    from app.config import Config

    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("FLASK_DEBUG", raising=False)

    class _FakeApp:
        config = {
            "TESTING": False,
            "LICENSE_PANEL_ENV": "production",
            "BOOTSTRAP_MODE": False,
            "DEBUG": False,
            "SECRET_KEY": "a-strong-unique-secret-key-of-decent-length!!",
            "ADMIN_PASSWORD": "a-strong-unique-admin-password!",
            "SQLALCHEMY_DATABASE_URI": Config.DEFAULT_DATABASE_URI,
            "RATE_LIMITS_ENABLED": True,
            "SESSION_COOKIE_SECURE": True,
        }
    with pytest.raises(RuntimeError) as exc:
        _validate_production_config(_FakeApp())
    assert "DATABASE_URL" in str(exc.value)
