"""CHR Fleet Phase 2 — P2-T3 + P2-T4 verification.

Covers:

* The Phase-2 SQL migrations (003_users_sessions.sql, 004_events_alerts.sql)
  are well-formed: each ``CREATE TABLE`` carries ``IF NOT EXISTS`` and a
  matching ``CREATE INDEX`` set. Static check — no DB engine required.
* Importing :mod:`fleet.brain.models_session` and
  :mod:`fleet.notify.models_alert` registers the five new tables
  (``users_fleet``, ``sessions``, ``placement_decisions``, ``events``,
  ``alerts``) on the shared ``db.metadata`` and ``db.create_all()``
  produces them on the test SQLite DB.
* CRUD smoke-tests for each new model.
* The brain's two single-survivor invariants are enforced at the DB
  level: one active session per username (``uq_active_session_per_user``)
  and one active ``framed_ip`` fleet-wide (``uq_active_ip``).
* The notifier's storm-suppression invariant (``uq_alert_dedupe``) is
  enforced: a second queued alert with the same ``dedupe_key`` fails.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError

from app.extensions import db

# Importing the models registers them on db.metadata.
from fleet.brain.models_session import (
    DECISION_KINDS,
    DECISION_OUTCOMES,
    PlacementDecision,
    SESSION_STATES,
    Session,
    UserFleet,
)
from fleet.notify.models_alert import (
    ALERT_CHANNELS,
    ALERT_STATUSES,
    Alert,
    EVENT_KINDS,
    Event,
)


MIGRATIONS_DIR = Path(__file__).resolve().parents[1] / "migrations"


# ───────────────────────── migrations: static well-formed check ────────────

def test_migration_003_is_idempotent_and_complete():
    """Every CREATE in 003 uses IF NOT EXISTS and the three target tables
    appear, so re-applying the migration on a partially-migrated DB is safe."""
    sql = (MIGRATIONS_DIR / "003_users_sessions.sql").read_text(encoding="utf-8")
    text = sql.lower()
    # All CREATE TABLE statements must be idempotent.
    assert text.count("create table ") == text.count("create table if not exists "), (
        "non-idempotent CREATE TABLE in 003_users_sessions.sql"
    )
    # The three Phase-2-T3 tables must exist in the file.
    for table in ("users_fleet", "sessions", "placement_decisions"):
        assert f"create table if not exists {table}" in text, (
            f"missing CREATE TABLE for {table} in 003_users_sessions.sql"
        )
    # The two safety invariants (G2 + single-active-session) appear as
    # partial-unique indexes.
    assert "uq_active_session_per_user" in text
    assert "uq_active_ip" in text


def test_migration_004_is_idempotent_and_complete():
    """Every CREATE in 004 uses IF NOT EXISTS and the two target tables
    appear, with the dedupe partial-unique index in place."""
    sql = (MIGRATIONS_DIR / "004_events_alerts.sql").read_text(encoding="utf-8")
    text = sql.lower()
    assert text.count("create table ") == text.count("create table if not exists "), (
        "non-idempotent CREATE TABLE in 004_events_alerts.sql"
    )
    for table in ("events", "alerts"):
        assert f"create table if not exists {table}" in text, (
            f"missing CREATE TABLE for {table} in 004_events_alerts.sql"
        )
    assert "uq_alert_dedupe" in text


# ───────────────────────── tables exist after create_all() ────────────────

def test_create_all_emits_p2_t3_t4_tables(app):
    """``db.create_all()`` (the panel's SQLite migration path) must
    materialize all five Phase-2-T3+T4 tables once the models are
    imported."""
    tables = set(inspect(db.engine).get_table_names())
    assert {
        "users_fleet",
        "sessions",
        "placement_decisions",
        "events",
        "alerts",
    }.issubset(tables)


def test_p2_t3_t4_indexes_exist(app):
    """The brain + notifier single-survivor invariants live as
    partial-unique indexes. Verify they were emitted by SQLAlchemy."""
    insp = inspect(db.engine)

    sessions_idx = {ix["name"] for ix in insp.get_indexes("sessions")}
    assert "uq_active_session_per_user" in sessions_idx
    assert "uq_active_ip" in sessions_idx

    alerts_idx = {ix["name"] for ix in insp.get_indexes("alerts")}
    assert "uq_alert_dedupe" in alerts_idx

    users_idx = {ix["name"] for ix in insp.get_indexes("users_fleet")}
    assert "idx_users_movable" in users_idx


# ───────────────────────── CRUD smoke tests ────────────────────────────────

def _make_chr_node(name: str) -> int:
    """Insert a minimal ChrNode row and return its id (needed for FKs)."""
    from app.models import ChrNode

    node = ChrNode(
        name=name,
        public_ip="203.0.113.1",
        capacity_mbps=1000,
        max_reserved_mbps=800,
        status="active",
    )
    db.session.add(node)
    db.session.commit()
    return node.id


def test_user_fleet_crud_and_movable_default_false(app):
    user = UserFleet(
        customer_id=42,
        realm="example.com",
        username="alice@example.com",
        fixed_ip="10.20.30.40",
    )
    db.session.add(user)
    db.session.commit()

    loaded = UserFleet.query.filter_by(username="alice@example.com").one()
    assert loaded.movable is False  # field default
    assert loaded.customer_id == 42
    assert loaded.fixed_ip == "10.20.30.40"

    # The uniqueness on username is enforced at the DB layer.
    db.session.add(UserFleet(
        customer_id=42, realm="example.com", username="alice@example.com",
    ))
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()


def test_session_active_uniques_enforced(app):
    chr1 = _make_chr_node("chr-p2-t3-1")
    chr2 = _make_chr_node("chr-p2-t3-2")

    s1 = Session(
        username="bob@example.com", realm="example.com", chr_id=chr1,
        framed_ip="10.0.0.1", acct_session_id="s-1",
    )
    db.session.add(s1)
    db.session.commit()

    # Same username active on a different CHR → blocked (G1 single-survivor).
    db.session.add(Session(
        username="bob@example.com", realm="example.com", chr_id=chr2,
        framed_ip="10.0.0.2", acct_session_id="s-2",
    ))
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()

    # Same framed_ip active for a different user → blocked (G2 no-dup-IP).
    db.session.add(Session(
        username="carol@example.com", realm="example.com", chr_id=chr2,
        framed_ip="10.0.0.1", acct_session_id="s-3",
    ))
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()

    # Once the first session closes, a new placement is accepted.
    s1.state = "closed"
    s1.closed_at = db.func.now()
    db.session.add(s1)
    db.session.commit()

    db.session.add(Session(
        username="bob@example.com", realm="example.com", chr_id=chr2,
        framed_ip="10.0.0.1", acct_session_id="s-4",
    ))
    db.session.commit()
    assert Session.query.filter_by(state="active").count() == 1


def test_placement_decision_reason_roundtrips(app):
    chr1 = _make_chr_node("chr-p2-t3-pd1")
    chr2 = _make_chr_node("chr-p2-t3-pd2")

    decision = PlacementDecision(
        username="dora@example.com",
        kind="rebalance",
        from_chr_id=chr1,
        to_chr_id=chr2,
        outcome="applied",
    )
    decision.reason = {"cpu": 0.82, "cost_penalty": 0.7, "winner": "chr-2"}
    db.session.add(decision)
    db.session.commit()

    fresh = PlacementDecision.query.filter_by(username="dora@example.com").one()
    assert fresh.kind in DECISION_KINDS
    assert fresh.outcome in DECISION_OUTCOMES
    # JSON column round-trips intact.
    assert fresh.reason == {"cpu": 0.82, "cost_penalty": 0.7, "winner": "chr-2"}


def test_event_and_alert_basic_roundtrip(app):
    chr1 = _make_chr_node("chr-p2-t4-1")

    ev = Event(chr_id=chr1, kind="health_down", severity="crit")
    ev.detail = {"consecutive_fail": 5, "rtt_ms": None}
    db.session.add(ev)
    db.session.commit()

    assert ev.kind in EVENT_KINDS
    assert ev.detail == {"consecutive_fail": 5, "rtt_ms": None}

    alert = Alert(
        event_id=ev.id,
        channel="sms",
        recipient="+970599000000",
        body=f"CHR-{chr1} down",
        dedupe_key=f"chr:{chr1}:down",
    )
    db.session.add(alert)
    db.session.commit()
    assert alert.channel in ALERT_CHANNELS
    assert alert.status in ALERT_STATUSES
    assert alert.status == "queued"


def test_alert_dedupe_storm_is_suppressed(app):
    chr1 = _make_chr_node("chr-p2-t4-dedupe")
    ev = Event(chr_id=chr1, kind="health_down", severity="crit")
    db.session.add(ev)
    db.session.commit()

    key = f"chr:{chr1}:down"
    a1 = Alert(event_id=ev.id, channel="whatsapp",
               recipient="+970599000001", body="down 1", dedupe_key=key)
    db.session.add(a1)
    db.session.commit()

    # Second alert with the SAME dedupe_key while a1 is still queued → blocked.
    db.session.add(Alert(event_id=ev.id, channel="whatsapp",
                         recipient="+970599000001", body="down 2",
                         dedupe_key=key))
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()

    # Marking the first one "suppressed" (or any non-active status) frees
    # the slot, so a re-occurrence later is queueable again.
    a1.status = "suppressed"
    db.session.add(a1)
    db.session.commit()

    db.session.add(Alert(event_id=ev.id, channel="whatsapp",
                         recipient="+970599000001", body="down again",
                         dedupe_key=key))
    db.session.commit()
    assert Alert.query.filter_by(dedupe_key=key, status="queued").count() == 1


def test_session_state_check_constraint(app):
    """The CHECK on sessions.state rejects unknown values fleet-wide."""
    chr1 = _make_chr_node("chr-p2-t3-check")
    db.session.add(Session(
        username="eve@example.com", realm="example.com", chr_id=chr1,
        framed_ip="10.0.0.99", acct_session_id="s-eve", state="bogus",
    ))
    # SQLite honours the CHECK; insertion fails at commit.
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()
    # And the documented enumeration is the source of truth.
    assert set(SESSION_STATES) == {"active", "closing", "closed"}
