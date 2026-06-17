"""Migration 006 — app_products + app_releases.

Tables backing the public landing "Downloads" section and the admin
app-uploads workflow. Binaries live on disk under
``instance_path/app_releases/<slug>/<platform>/<channel>/`` — only metadata
is in the DB.

Idempotent: ``db.create_all(..., checkfirst=True)`` is a no-op when the
tables already exist (fresh ``db.create_all()`` boots also build them).
"""
from __future__ import annotations

from app.extensions import db
from app.models import AppProduct, AppRelease

_TABLES = [AppProduct.__table__, AppRelease.__table__]


def upgrade() -> None:
    db.metadata.create_all(bind=db.engine, tables=_TABLES, checkfirst=True)


def downgrade() -> None:
    # release rows reference products via FK — drop releases first.
    db.metadata.drop_all(bind=db.engine, tables=[AppRelease.__table__], checkfirst=True)
    db.metadata.drop_all(bind=db.engine, tables=[AppProduct.__table__], checkfirst=True)
