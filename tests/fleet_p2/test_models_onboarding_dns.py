"""Unit tests for Phase-2 task T5 models.

Covers:
  * ``fleet.registry.models_onboarding.OnboardingJob`` — schema CRUD round-trip,
    JSON property sugar, state-machine guards (legal vs illegal transitions),
    and the retry edge ``failed → script_generated``.
  * ``fleet.dns.models_dns.DnsRecordState`` — upsert idempotency,
    ``(fqdn, record_type)`` uniqueness, sort-then-store canonicalisation that
    makes diff-checks deterministic, and IP-version validation against the
    record type.

These run against the SQLite ``TestingConfig`` DB created by the shared
``app`` fixture in ``tests/conftest.py``. The models import is the only thing
that wires them into ``db.metadata`` for ``create_all()``.
"""

from __future__ import annotations

import pytest

# Importing the model modules registers them with the shared
# ``app.extensions.db`` metadata; the ``app`` fixture's ``db.create_all()``
# then creates the corresponding tables in the SQLite test DB.
from fleet.registry.models_onboarding import (
    ONBOARDING_STATUSES,
    OnboardingJob,
    can_transition,
)
from fleet.dns.models_dns import DnsRecordState

from app.extensions import db


# ════════════════════════════════════════════════════════════════════════════
# State-machine helpers (pure, no DB)
# ════════════════════════════════════════════════════════════════════════════
class TestOnboardingStateMachine:
    def test_documented_states_present(self) -> None:
        """All seven states from 06_ONBOARDING_WIZARD §6.2 are declared."""
        assert set(ONBOARDING_STATUSES) == {
            "draft", "keys_generated", "script_generated",
            "pushed", "verifying", "active", "failed",
        }

    @pytest.mark.parametrize(
        ("src", "dst"),
        [
            ("draft", "keys_generated"),
            ("keys_generated", "script_generated"),
            ("script_generated", "pushed"),
            ("pushed", "verifying"),
            ("verifying", "active"),
            ("verifying", "failed"),
            ("failed", "script_generated"),  # retry edge
        ],
    )
    def test_legal_transitions(self, src: str, dst: str) -> None:
        assert can_transition(src, dst), f"{src} → {dst} should be legal"

    @pytest.mark.parametrize(
        ("src", "dst"),
        [
            ("draft", "active"),       # skipping the pipeline
            ("active", "failed"),      # terminal-success can't fail later
            ("pushed", "active"),      # must go through verifying
            ("keys_generated", "pushed"),
        ],
    )
    def test_illegal_transitions(self, src: str, dst: str) -> None:
        assert not can_transition(src, dst), f"{src} → {dst} should be illegal"


# ════════════════════════════════════════════════════════════════════════════
# OnboardingJob — schema + JSON sugar + advance() guard
# ════════════════════════════════════════════════════════════════════════════
class TestOnboardingJobCRUD:
    def test_create_with_defaults(self, app) -> None:
        job = OnboardingJob(form_input={"provider": "Contabo", "name": "chr-eu-3"})
        db.session.add(job)
        db.session.commit()

        fetched = db.session.get(OnboardingJob, job.id)
        assert fetched is not None
        assert fetched.status == "draft"
        assert fetched.form_input == {"provider": "Contabo", "name": "chr-eu-3"}
        assert fetched.verify_report is None
        assert fetched.chr_id is None
        assert fetched.created_at is not None
        assert fetched.updated_at is not None
        assert fetched.wg_keypair_ref is None

    def test_full_state_walk_persists(self, app) -> None:
        job = OnboardingJob(form_input={"name": "chr-us-1"})
        db.session.add(job)
        db.session.commit()

        # Walk the happy path
        for nxt in ("keys_generated", "script_generated", "pushed", "verifying", "active"):
            job.advance(nxt)
            db.session.commit()

        assert db.session.get(OnboardingJob, job.id).status == "active"

    def test_advance_rejects_illegal_jump(self, app) -> None:
        job = OnboardingJob(form_input={"name": "chr-x"})
        db.session.add(job)
        db.session.commit()

        with pytest.raises(ValueError, match="illegal onboarding transition"):
            job.advance("active")          # draft → active is illegal
        with pytest.raises(ValueError, match="unknown onboarding status"):
            job.advance("garbage")
        # Bad calls leave state untouched
        assert job.status == "draft"

    def test_retry_edge_from_failed(self, app) -> None:
        job = OnboardingJob(form_input={"name": "chr-retry"})
        db.session.add(job); db.session.commit()
        for nxt in ("keys_generated", "script_generated", "pushed", "verifying", "failed"):
            job.advance(nxt)
        db.session.commit()
        # Owner-fix retry path documented in §6.2
        job.advance("script_generated")
        assert job.status == "script_generated"

    def test_verify_report_round_trip_and_null(self, app) -> None:
        job = OnboardingJob(form_input={"name": "chr-v"})
        db.session.add(job); db.session.commit()

        assert job.verify_report is None
        job.verify_report = {"wg_mgmt": "ok", "radius_probe": "ok", "ports": [8729, 3799]}
        db.session.commit()

        fresh = db.session.get(OnboardingJob, job.id)
        assert fresh.verify_report == {"wg_mgmt": "ok", "radius_probe": "ok", "ports": [8729, 3799]}

        fresh.verify_report = None
        db.session.commit()
        assert db.session.get(OnboardingJob, job.id).verify_report is None


# ════════════════════════════════════════════════════════════════════════════
# DnsRecordState — upsert / uniqueness / canonicalisation / validation
# ════════════════════════════════════════════════════════════════════════════
class TestDnsRecordState:
    def test_upsert_creates_then_updates_same_row(self, app) -> None:
        row = DnsRecordState.upsert(
            "vpn.hoberadius.com", "A",
            ["3.3.3.3", "1.1.1.1", "2.2.2.2"],
            ttl=60, provider_zone_id="zone-abc", reason="initial_publish",
        )
        db.session.commit()
        first_id = row.id

        # Same key, different set: should land in the same row
        row2 = DnsRecordState.upsert(
            "vpn.hoberadius.com", "A",
            ["4.4.4.4", "1.1.1.1"],
            ttl=30, reason="health_change",
        )
        db.session.commit()
        assert row2.id == first_id
        assert row2.ttl == 30
        assert row2.published_ips == ["1.1.1.1", "4.4.4.4"]
        assert row2.last_change_reason == "health_change"
        # provider_zone_id is preserved when not passed
        assert row2.provider_zone_id == "zone-abc"

    def test_ips_are_sorted_for_deterministic_diffs(self, app) -> None:
        """published_ips must be sort-stable so ``prev == new`` short-circuits the publish."""
        row = DnsRecordState.upsert(
            "vpn.example.com", "A", ["10.0.0.5", "10.0.0.1", "10.0.0.2"], ttl=120,
        )
        db.session.commit()
        assert row.published_ips == ["10.0.0.1", "10.0.0.2", "10.0.0.5"]

    def test_fqdn_record_type_uniqueness(self, app) -> None:
        """Two rows with the same (fqdn, record_type) violate uq_dns_fqdn_type."""
        DnsRecordState.upsert("vpn.example.com", "A", ["1.1.1.1"], ttl=60)
        db.session.commit()

        rogue = DnsRecordState(
            fqdn="vpn.example.com", record_type="A", ttl=60,
            published_ips_json='["1.1.1.1"]',
        )
        db.session.add(rogue)
        with pytest.raises(Exception):  # IntegrityError on SQLite + Postgres
            db.session.commit()
        db.session.rollback()

    def test_a_and_aaaa_for_same_fqdn_coexist(self, app) -> None:
        a = DnsRecordState.upsert("vpn.example.com", "A", ["1.2.3.4"], ttl=60)
        aaaa = DnsRecordState.upsert("vpn.example.com", "AAAA", ["2001:db8::1"], ttl=60)
        db.session.commit()
        assert a.id != aaaa.id
        # Confirm round-trip via .get
        assert DnsRecordState.get("vpn.example.com", "A").published_ips == ["1.2.3.4"]
        assert DnsRecordState.get("vpn.example.com", "AAAA").published_ips == ["2001:db8::1"]

    def test_record_type_validates_ip_version(self, app) -> None:
        with pytest.raises(ValueError, match="A record requires IPv4"):
            DnsRecordState.upsert("vpn.example.com", "A", ["2001:db8::1"], ttl=60)
        with pytest.raises(ValueError, match="AAAA record requires IPv6"):
            DnsRecordState.upsert("vpn.example.com", "AAAA", ["1.2.3.4"], ttl=60)
        with pytest.raises(ValueError, match="not a valid IP literal"):
            DnsRecordState.upsert("vpn.example.com", "A", ["totally-not-an-ip"], ttl=60)

    def test_upsert_rejects_bad_record_type_and_ttl(self, app) -> None:
        with pytest.raises(ValueError, match="record_type must be one of"):
            DnsRecordState.upsert("vpn.example.com", "CNAME", ["1.1.1.1"], ttl=60)
        with pytest.raises(ValueError, match="ttl must be a positive integer"):
            DnsRecordState.upsert("vpn.example.com", "A", ["1.1.1.1"], ttl=0)
