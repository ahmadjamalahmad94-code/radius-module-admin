"""Migration 009 — module_releases.

Per-customer OPT-IN self-update feed for the customer RADIUS module: the
provider publishes an available version (semver + Arabic changelog + mandatory/
min_version + optional targeting); customer instances poll
``GET /api/integration/hoberadius/update/latest`` and their own panel decides
whether to install. This is NOT the landing mobile-app downloads (``app_releases``).

Idempotent: ``create_all(..., checkfirst=True)`` is a no-op when the table
already exists (fresh ``db.create_all()`` boots also build it).
"""
from __future__ import annotations

from app.extensions import db
from app.models import ModuleRelease

_TABLES = [ModuleRelease.__table__]


def upgrade() -> None:
    db.metadata.create_all(bind=db.engine, tables=_TABLES, checkfirst=True)


def downgrade() -> None:
    db.metadata.drop_all(bind=db.engine, tables=_TABLES, checkfirst=True)
