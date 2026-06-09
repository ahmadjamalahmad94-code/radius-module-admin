"""Phase 2 / group 1 (P2-T1 + P2-T2) — fleet registry & health schema.

Verifies the two idempotent migrations apply cleanly on a FRESH in-memory DB, the
ORM models do real CRUD, the chr_effective view resolves inherit-vs-override cost,
and the doc's dedupe/unique + CHECK constraints are enforced.
"""
from __future__ import annotations

import importlib.util
from decimal import Decimal
from pathlib import Path

import pytest
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError

from app import create_app
from app.config import TestingConfig
from app.extensions import db

# Importing the models registers them on db.metadata (and pulls registry into
# health via its import), so create_all/inspect see the fleet tables.
from fleet.registry.models_chr import FleetChrNode, FleetProvider
from fleet.health.models_health import FleetChrHealth, FleetChrMetric

_MIG_DIR = Path(__file__).resolve().parents[1] / "migrations"


def _load(filename: str):
    """Load a digit-prefixed migration module by path (not importable by name)."""
    spec = importlib.util.spec_from_file_location(filename[:-3], _MIG_DIR / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def app_ctx():
    # TestingConfig => sqlite :memory:, AUTO_INIT_DB=False => no tables yet (fresh DB).
    app = create_app(TestingConfig)
    with app.app_context():
        yield app
        db.session.remove()


def _apply_migrations():
    _load("001_providers_chr_nodes.py").upgrade()
    _load("002_metrics_health.py").upgrade()


_FLEET_TABLES = {"fleet_providers", "fleet_chr_nodes", "fleet_chr_metrics", "fleet_chr_health"}


def test_migrations_apply_clean_on_fresh_db(app_ctx):
    insp = inspect(db.engine)
    assert "fleet_chr_nodes" not in insp.get_table_names()  # genuinely fresh

    _apply_migrations()

    insp = inspect(db.engine)
    tables = set(insp.get_table_names())
    assert _FLEET_TABLES <= tables
    assert "fleet_chr_effective" in set(insp.get_view_names())

    # Idempotent: re-running upgrade() must be a clean no-op.
    _apply_migrations()


def test_crud_view_and_constraints(app_ctx):
    _apply_migrations()

    prov = FleetProvider(
        name="Contabo",
        cost_model="metered",
        price_per_tb=Decimal("2.50"),
        monthly_cap_tb=Decimal("30.000"),
        overage_allowed=True,
    )
    db.session.add(prov)
    db.session.commit()

    # Node A inherits provider cost; Node B overrides to 'open'.
    node_a = FleetChrNode(
        provider_id=prov.id, name="chr-01",
        public_ip="1.2.3.4", wg_mgmt_ip="10.99.0.1", wg_mgmt_pubkey="pubA",
        max_sessions=4000, link_speed_mbps=1000,  # cost_model defaults to 'inherit'
    )
    node_b = FleetChrNode(
        provider_id=prov.id, name="chr-02",
        public_ip="5.6.7.8", wg_mgmt_ip="10.99.0.2", wg_mgmt_pubkey="pubB",
        max_sessions=2000, link_speed_mbps=500, cost_model="open",
    )
    db.session.add_all([node_a, node_b])
    db.session.commit()

    db.session.add(FleetChrMetric(chr_id=node_a.id, cpu_pct=Decimal("12.50"),
                                  active_sessions=10, rx_bytes=1000, tx_bytes=2000, source="control"))
    db.session.add(FleetChrHealth(chr_id=node_a.id, state="up", consecutive_ok=3))
    db.session.commit()

    # Read-back across the relationship + child tables.
    assert FleetChrNode.query.filter_by(name="chr-01").one().provider.name == "Contabo"
    assert FleetChrMetric.query.filter_by(chr_id=node_a.id).count() == 1
    assert db.session.get(FleetChrHealth, node_a.id).state == "up"

    # chr_effective resolves inherit -> provider, and honours the node override.
    eff = {
        r.id: r.eff_cost_model
        for r in db.session.execute(db.text("SELECT id, eff_cost_model FROM fleet_chr_effective")).all()
    }
    assert eff[node_a.id] == "metered"   # inherited from provider
    assert eff[node_b.id] == "open"      # node override wins

    # Dedupe (G2 / §2.3): duplicate (provider_id, name) rejected.
    db.session.add(FleetChrNode(provider_id=prov.id, name="chr-01",
                           public_ip="9.9.9.9", wg_mgmt_ip="10.99.0.9", wg_mgmt_pubkey="x",
                           max_sessions=1, link_speed_mbps=1))
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()

    # Dedupe: duplicate public_ip rejected (unique front-door identity).
    db.session.add(FleetChrNode(provider_id=prov.id, name="chr-03",
                           public_ip="1.2.3.4", wg_mgmt_ip="10.99.0.3", wg_mgmt_pubkey="y",
                           max_sessions=1, link_speed_mbps=1))
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()

    # CHECK constraint: invalid status value rejected.
    db.session.add(FleetChrNode(provider_id=prov.id, name="chr-04",
                           public_ip="2.2.2.2", wg_mgmt_ip="10.99.0.4", wg_mgmt_pubkey="z",
                           max_sessions=1, link_speed_mbps=1, status="bogus"))
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()


def test_downgrade_drops_everything(app_ctx):
    _apply_migrations()
    _load("002_metrics_health.py").downgrade()
    _load("001_providers_chr_nodes.py").downgrade()

    insp = inspect(db.engine)
    remaining = set(insp.get_table_names())
    assert not (_FLEET_TABLES & remaining)
    assert "fleet_chr_effective" not in set(insp.get_view_names())
