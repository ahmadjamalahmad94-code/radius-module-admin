"""Migration 001 — providers + chr_nodes (+ chr_effective view).

Phase 2 / P2-T1. Schema: docs/chr_fleet/02_DATA_MODEL.md §2.2, §2.3.

Idempotent, dialect-aware (SQLite tests, PostgreSQL prod). Must run inside a Flask
app context. Creates the two registry tables from their ORM models (checkfirst, so
re-running is a no-op) plus the ``chr_effective`` resolution view, which the brain
reads to get each node's effective cost/cap (node override else provider default).
"""
from __future__ import annotations

from app.extensions import db
from fleet.registry.models_chr import FleetChrNode, FleetProvider

# Effective cost/cap resolution view (doc §2.3). COALESCE + NULLIF are portable
# across SQLite and PostgreSQL; only the CREATE form differs per dialect. Table
# names carry the fleet_ prefix (see fleet.registry.models_chr for why).
_VIEW_NAME = "fleet_chr_effective"
_VIEW_SELECT = """
SELECT n.*,
  COALESCE(NULLIF(n.cost_model, 'inherit'), p.cost_model) AS eff_cost_model,
  COALESCE(n.price_per_tb,    p.price_per_tb)             AS eff_price_per_tb,
  COALESCE(n.bandwidth_cap_tb, p.monthly_cap_tb)         AS eff_cap_tb,
  COALESCE(n.overage_allowed, p.overage_allowed)         AS eff_overage_allowed
FROM fleet_chr_nodes n JOIN fleet_providers p ON p.id = n.provider_id
""".strip()

_TABLES = [FleetProvider.__table__, FleetChrNode.__table__]


def _create_view() -> None:
    dialect = db.engine.dialect.name
    if dialect == "postgresql":
        db.session.execute(db.text(f"CREATE OR REPLACE VIEW {_VIEW_NAME} AS {_VIEW_SELECT}"))
    elif dialect == "sqlite":
        db.session.execute(db.text(f"CREATE VIEW IF NOT EXISTS {_VIEW_NAME} AS {_VIEW_SELECT}"))
    else:  # best-effort for other engines: drop-then-create
        db.session.execute(db.text(f"DROP VIEW IF EXISTS {_VIEW_NAME}"))
        db.session.execute(db.text(f"CREATE VIEW {_VIEW_NAME} AS {_VIEW_SELECT}"))
    db.session.commit()


def upgrade() -> None:
    """Create providers, chr_nodes, and the chr_effective view. Idempotent."""
    db.metadata.create_all(bind=db.engine, tables=_TABLES, checkfirst=True)
    _create_view()


def downgrade() -> None:
    """Drop the view then the two tables. Idempotent."""
    db.session.execute(db.text(f"DROP VIEW IF EXISTS {_VIEW_NAME}"))
    db.session.commit()
    db.metadata.drop_all(bind=db.engine, tables=list(reversed(_TABLES)), checkfirst=True)


if __name__ == "__main__":  # pragma: no cover - manual apply helper
    from app import create_app

    app = create_app()
    with app.app_context():
        upgrade()
        print("migration 001_providers_chr_nodes: upgrade OK")
