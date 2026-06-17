"""Migration 007 — app_releases.download_url (external-URL releases).

Adds the optional ``download_url`` column so a release can link to an external
asset (e.g. a GitHub release) instead of a panel-hosted file — for binaries too
large to upload through the panel.

Idempotent: only adds the column when it's absent (matches the boot-time
``ensure_schema_compatibility`` heal, which is the path that actually runs on
deploy). Fresh DBs already get the column from the model via ``db.create_all``.
"""
from __future__ import annotations

from sqlalchemy import inspect, text

from app.extensions import db

_TABLE = "app_releases"
_COLUMN = "download_url"
_DEF = "VARCHAR(600) NOT NULL DEFAULT ''"


def _has_column() -> bool:
    insp = inspect(db.engine)
    if _TABLE not in set(insp.get_table_names()):
        return True  # table absent ⇒ create_all/006 will build it WITH the column
    return _COLUMN in {c["name"] for c in insp.get_columns(_TABLE)}


def upgrade() -> None:
    if _has_column():
        return
    db.session.execute(text(f"ALTER TABLE {_TABLE} ADD COLUMN {_COLUMN} {_DEF}"))
    db.session.commit()


def downgrade() -> None:
    # SQLite can't easily drop columns; this is a no-op (the column is additive
    # and harmless). Postgres could DROP COLUMN, but we keep it reversible-safe.
    return
