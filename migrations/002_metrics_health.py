"""Migration 002 — chr_metrics + chr_health.

Phase 2 / P2-T2. Schema: docs/chr_fleet/02_DATA_MODEL.md §2.4, §2.5.

Depends on migration 001 (both tables FK ``chr_nodes.id``); importing the health
models pulls in the registry models too, so chr_nodes is registered on the shared
metadata before these tables are created. Idempotent, dialect-aware, app-context
required. TimescaleDB ``create_hypertable`` on chr_metrics is intentionally skipped
(optional/prod-only) — the ``(chr_id, ts)`` index covers locality everywhere.
"""
from __future__ import annotations

from app.extensions import db
from fleet.health.models_health import FleetChrHealth, FleetChrMetric

# Order matters on drop (children first); on create, create_all sorts by FK deps.
_TABLES = [FleetChrMetric.__table__, FleetChrHealth.__table__]


def upgrade() -> None:
    """Create chr_metrics and chr_health. Idempotent (checkfirst)."""
    db.metadata.create_all(bind=db.engine, tables=_TABLES, checkfirst=True)


def downgrade() -> None:
    """Drop chr_metrics and chr_health. Idempotent."""
    db.metadata.drop_all(bind=db.engine, tables=_TABLES, checkfirst=True)


if __name__ == "__main__":  # pragma: no cover - manual apply helper
    from app import create_app

    app = create_app()
    with app.app_context():
        upgrade()
        print("migration 002_metrics_health: upgrade OK")
