"""Canonical SQLite path resolution for the panel.

ONE place that knows where the panel's SQLite file lives, anchored
absolutely at the repository's ``instance/`` directory and independent
of the process working directory or the launch method.

Background — why this module exists
-----------------------------------
A live-field report uncovered a split-brain: two SQLite files
(``instance/license_panel.sqlite3`` and ``instance/license_panel.db``)
existed side-by-side. The running service was reading the ``.sqlite3``
file (per ``config.py``), while some interactive sessions / scripts had
been writing to ``.db``. Result: data the operator "saved" appeared to
have vanished from the panel.

The source code path resolution was already absolute. The split came
from operational drift — most likely a relative ``DATABASE_URL`` (e.g.
``sqlite:///instance/license_panel.db``) set in a ``.env`` file or shell
session, which resolves against the launching process's cwd. Different
launch methods → different physical files.

Hardening contract
------------------
1. :data:`CANONICAL_SQLITE_FILENAME` is fixed: ``license_panel.sqlite3``.
2. :func:`canonical_sqlite_path` returns the absolute on-disk path
   resolved from this package's location, NOT cwd.
3. :func:`canonical_database_uri` wraps it as a SQLAlchemy URI.
4. :func:`validate_database_uri` REFUSES at boot to start with a
   *relative* ``sqlite:///`` URI: the most common cause of the
   split-brain. Postgres / in-memory / absolute sqlite all pass.
5. :func:`detect_legacy_sibling` returns the path of a legacy
   ``license_panel.db`` next to the canonical file (if any) so the boot
   log can warn the operator to reconcile.
"""
from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse

#: The package directory — ``<repo>/app``. Used so that even if the working
#: directory is wildly different at launch (e.g. systemd starts from
#: ``WorkingDirectory=/opt/hoberadius-license-panel`` but a maintenance
#: script ``cd``-s elsewhere), the path resolution stays identical.
_APP_DIR = Path(__file__).resolve().parent

#: The repository root — ``<repo>``. This is the SAME root the Flask app
#: factory used when it set ``instance_relative_config=True`` so the
#: derived ``instance_path`` ends up here too.
REPO_ROOT: Path = _APP_DIR.parent

#: The on-disk directory that holds the SQLite file + the customer-backups
#: subtree. Mirrors Flask's auto-derived ``app.instance_path``.
INSTANCE_DIR: Path = REPO_ROOT / "instance"

#: The CANONICAL filename. Hard-coded so a stale env var pointing at the
#: ``.db`` variant can be detected unambiguously by
#: :func:`detect_legacy_sibling`.
CANONICAL_SQLITE_FILENAME: str = "license_panel.sqlite3"

#: The legacy filename the field report found. Kept for the boot-time
#: warning so the operator knows precisely which sibling to reconcile.
LEGACY_SQLITE_FILENAME: str = "license_panel.db"


def canonical_sqlite_path() -> Path:
    """Absolute path to the panel's canonical SQLite file.

    Computed from the package directory, so the result is identical
    regardless of the caller's working directory.
    """
    return (INSTANCE_DIR / CANONICAL_SQLITE_FILENAME).resolve()


def canonical_database_uri() -> str:
    """SQLAlchemy URI for the canonical SQLite file (absolute form)."""
    return _sqlite_uri_for(canonical_sqlite_path())


def _sqlite_uri_for(path: Path) -> str:
    """Build a SQLAlchemy SQLite URI for ``path``.

    SQLAlchemy's SQLite URL convention: ``sqlite:///absolute/posix/path``
    (three slashes + leading slash on POSIX) and
    ``sqlite:///C:/...`` on Windows. We always emit POSIX-style separators
    so the URI is stable across platforms.
    """
    p = path.resolve()
    return "sqlite:///" + p.as_posix()


# ── validation ──────────────────────────────────────────────────────────

class DatabaseURIError(RuntimeError):
    """Raised when a configured DATABASE_URL would re-introduce the
    split-brain (e.g. a relative ``sqlite:///`` URI)."""


def validate_database_uri(uri: str) -> None:
    """Reject configurations that could silently fall through to a second
    physical SQLite file.

    Specifically: a ``sqlite:///`` URI whose path is *relative*. Relative
    paths resolve against cwd, which is exactly how the live-field issue
    happened — different launch methods produced different physical
    files. Absolute sqlite, in-memory sqlite, PostgreSQL, and any
    non-sqlite dialect all pass.

    Raises :class:`DatabaseURIError` so the app factory can surface a
    clear message rather than silently opening a stray file.
    """
    if not uri:
        raise DatabaseURIError("DATABASE_URL is empty.")
    if not uri.startswith("sqlite"):
        # PostgreSQL / MySQL / etc — assume the DBA knows what they want.
        return
    # In-memory variants (sqlite:///:memory:, sqlite://) — fine for tests.
    if "memory" in uri or uri == "sqlite://":
        return

    # SQLAlchemy SQLite URIs come in two shapes:
    #   sqlite:///absolute/path           (POSIX absolute)
    #   sqlite:///C:/abs/path             (Windows absolute, drive letter)
    #   sqlite:///relative/path           (relative — REJECT)
    # The leading 'sqlite:///' is always present for a file-backed DB.
    if not uri.startswith("sqlite:///"):
        # sqlite://hostname/relative — anything else is non-standard.
        raise DatabaseURIError(
            f"DATABASE_URL has an unsupported SQLite URI shape: {uri!r}. "
            "Use sqlite:///<absolute-path> only."
        )
    body = uri[len("sqlite:///"):]
    if not body:
        raise DatabaseURIError(
            "DATABASE_URL points at an empty SQLite path. "
            "Use sqlite:///<absolute-path>."
        )
    # Windows: a drive-letter prefix (C:/, D:/, …) is absolute.
    if re.match(r"^[A-Za-z]:[\\/]", body):
        return
    # POSIX: must start with /
    if body.startswith("/"):
        return

    raise DatabaseURIError(
        "DATABASE_URL uses a RELATIVE SQLite path "
        f"({uri!r}). Relative paths resolve against the process working "
        "directory and were the cause of the historical split-brain "
        "(license_panel.db vs license_panel.sqlite3). "
        "Use sqlite:///" + str(canonical_sqlite_path()) + " or set "
        "DATABASE_URL to an explicit absolute path."
    )


# ── operator diagnostics ────────────────────────────────────────────────

def detect_legacy_sibling() -> Path | None:
    """Return the path of a legacy ``license_panel.db`` sibling if one
    exists next to the canonical SQLite file, else ``None``.

    The app factory calls this at boot. When a sibling is detected, the
    operator gets a single warning log line pointing at the
    reconciliation runbook — never an automatic move/delete (the field
    report's whole point is that the panel CANNOT pick which file is
    authoritative; only the operator can).
    """
    legacy = INSTANCE_DIR / LEGACY_SQLITE_FILENAME
    return legacy if legacy.exists() else None


def resolved_sqlite_path_for(uri: str) -> Path | None:
    """Return the absolute on-disk file that a ``sqlite:///`` URI opens.

    Returns ``None`` for in-memory or non-sqlite URIs. For a relative
    sqlite URI (which :func:`validate_database_uri` rejects), this still
    returns the cwd-resolved path so test output and logs can show
    *what* would have been opened. Useful for the boot diagnostic line.
    """
    if not uri.startswith("sqlite:///"):
        return None
    if "memory" in uri:
        return None
    body = uri[len("sqlite:///"):]
    if not body:
        return None
    return Path(body).resolve()


__all__ = [
    "CANONICAL_SQLITE_FILENAME",
    "DatabaseURIError",
    "INSTANCE_DIR",
    "LEGACY_SQLITE_FILENAME",
    "REPO_ROOT",
    "canonical_database_uri",
    "canonical_sqlite_path",
    "detect_legacy_sibling",
    "resolved_sqlite_path_for",
    "validate_database_uri",
]
