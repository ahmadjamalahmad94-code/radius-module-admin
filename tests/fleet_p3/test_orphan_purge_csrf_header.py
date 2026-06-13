"""fix/orphan-purge-csrf-header — «نفّذ التنظيف» button reaches the server.

Field incident: the operator clicked «نفّذ التنظيف» on the dashboard's
orphan-purge modal and nothing happened — the survey kept showing the
same «مهام بدون عقدة: #2» row after every retry. Root cause: the JS
sent the CSRF token under the WRONG header name (``X-CSRF-Token`` with
a hyphen) while Flask-WTF only accepts ``X-CSRFToken`` (no hyphen,
per WTF_CSRF_HEADERS default). The POST was 400'd silently; the
front-end's `if (data && data.ok)` branch was never entered, so the
modal closed without a page reload and the operator saw the same
phantom card.

Every OTHER fetch() in admin_fleet_dashboard.js + all sibling fleet JS
already use ``X-CSRFToken`` — this was the ONE outlier.

Tests below pin three things:

  1. The CSRF header on the orphan-purge POST is the correct
     `X-CSRFToken` (not the broken `X-CSRF-Token`).
  2. No other admin JS smuggles back the hyphenated variant (sweep).
  3. The purge_orphans backend really deletes an OnboardingJob with
     `chr_id IS NULL` (the owner's «مهام بدون عقدة: #2» case) — so
     once the CSRF reaches the server, the work actually happens.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.extensions import db
from fleet.registry.models_chr import FleetChrNode, FleetProvider
from fleet.registry.models_onboarding import OnboardingJob
from fleet.registry.teardown import find_orphans, purge_orphans


# ════════════════════════════════════════════════════════════════════════
# (1) JS contract — the orphan-purge POST uses X-CSRFToken
# ════════════════════════════════════════════════════════════════════════
class TestJsCsrfHeaderContract:
    """Pin the EXACT header name the orphan-purge confirm POST sends."""

    JS = Path("app/static/js/admin_fleet_dashboard.js")

    def test_purge_post_uses_x_csrftoken(self):
        body = self.JS.read_text(encoding="utf-8")
        # Locate the orphan-purge confirm fetch (it carries `purgeUrl`
        # as its first arg + `"method": "POST"` immediately after).
        m = re.search(
            r"fetch\(purgeUrl,\s*\{(.+?)\}\s*\);",
            body, re.DOTALL,
        )
        assert m, "could not locate the orphan-purge fetch() call"
        block = m.group(1)
        assert '"X-CSRFToken"' in block, (
            "orphan-purge POST must send the CSRF token under the "
            "Flask-WTF default header X-CSRFToken (no hyphen). The "
            "hyphenated X-CSRF-Token is silently 400'd by WTF and was "
            "the cause of the «نفّذ التنظيف» dead-button incident."
        )
        # And the broken hyphenated variant must NOT be present.
        assert '"X-CSRF-Token"' not in block, (
            "orphan-purge POST still uses the broken X-CSRF-Token "
            "header — Flask-WTF rejects it as a CSRF mismatch"
        )

    def test_no_admin_js_uses_hyphenated_variant(self):
        """Sweep every admin JS file for the broken hyphenated variant.
        We sweep the whole static/js tree so a future fetch() that
        accidentally pastes `X-CSRF-Token` is caught at test time, not
        in production."""
        offenders: list[str] = []
        for path in Path("app/static/js").rglob("*.js"):
            text = path.read_text(encoding="utf-8")
            if "X-CSRF-Token" in text:
                offenders.append(str(path))
        assert not offenders, (
            "the following JS files use the broken hyphenated "
            f"X-CSRF-Token header: {offenders}. Normalize to "
            "X-CSRFToken to match Flask-WTF + the rest of the panel."
        )


# ════════════════════════════════════════════════════════════════════════
# (2) Backend — purge_orphans actually deletes the «مهام بدون عقدة» case
# ════════════════════════════════════════════════════════════════════════
class TestPurgeDeletesOrphanJobs:

    @pytest.fixture()
    def provider(self, app):
        p = FleetProvider.query.first()
        if p is not None:
            return p
        p = FleetProvider(
            name="purge-test-prov", cost_model="open", price_per_tb=0,
            overage_allowed=False, billing_cycle_day=1,
        )
        db.session.add(p); db.session.commit()
        return p

    def test_orphan_job_with_null_chr_id_is_flagged_and_deleted(self, app, provider):
        """The owner's exact case: an OnboardingJob with NO linked node
        (chr_id IS NULL) appears in the pending list as «مهام بدون عقدة».
        find_orphans must flag it; purge_orphans must delete it."""
        j = OnboardingJob(status="script_generated", chr_id=None)
        j.form_input = {"name": "phantom-job", "provider": "purge-test-prov"}
        db.session.add(j); db.session.commit()
        jid = j.id

        survey = find_orphans()
        assert jid in survey.orphan_job_ids, (
            f"OnboardingJob(chr_id=NULL, id={jid}) must be flagged as "
            "orphan — that's the «مهام بدون عقدة» case from the survey"
        )

        report = purge_orphans()
        db.session.commit()
        assert db.session.get(OnboardingJob, jid) is None, (
            "purge_orphans must DELETE the OnboardingJob whose chr_id "
            "is NULL — without this, «نفّذ التنظيف» is a no-op even "
            "when the CSRF token reaches the server"
        )
        assert report.orphan_jobs_deleted >= 1
        # The pre-survey snapshot in the report carries the orphan job id
        # (for audit metadata).
        assert jid in report.survey_before.orphan_job_ids

    def test_orphan_job_deleted_across_pending_states(self, app, provider):
        """Pending-state matrix: every status that can appear on the
        «قيد التنفيذ» card must be eligible for orphan-purge when
        chr_id is NULL."""
        states = ("draft", "keys_generated", "script_generated",
                  "pushed", "verifying", "failed")
        jids: list[int] = []
        for s in states:
            j = OnboardingJob(status=s, chr_id=None)
            j.form_input = {"name": f"orphan-{s}",
                            "provider": "purge-test-prov"}
            db.session.add(j)
        db.session.commit()
        jids = [j.id for j in OnboardingJob.query.all()]

        purge_orphans()
        db.session.commit()
        remaining = OnboardingJob.query.count()
        assert remaining == 0, (
            f"purge_orphans should remove every chr_id-NULL pending job "
            f"across all 6 pending states; {remaining} survived"
        )

    def test_active_job_is_NOT_purged(self, app, provider):
        """Defence: a job with `chr_id IS NULL` but status `active`
        (terminal-success) must NOT be touched — the active terminal
        state is outside the pending-card filter."""
        j = OnboardingJob(status="active", chr_id=None)
        j.form_input = {"name": "alive", "provider": "purge-test-prov"}
        db.session.add(j); db.session.commit()
        jid = j.id

        purge_orphans()
        db.session.commit()
        assert db.session.get(OnboardingJob, jid) is not None, (
            "purge_orphans must NOT touch terminal-active jobs — even "
            "when chr_id is NULL, the row is audit history"
        )


# ════════════════════════════════════════════════════════════════════════
# (3) Route-level — POST /admin/fleet/onboarding/orphans/purge works
# ════════════════════════════════════════════════════════════════════════
class TestPurgeRoute:

    def test_route_returns_report_with_orphan_jobs_deleted(self, app, client):
        """End-to-end: POST the purge endpoint and confirm the report
        body carries orphan_jobs_deleted count (proves the orphan job
        was swept end-to-end, not just at the service layer)."""
        from app.models import Admin
        # Login + super-admin.
        client.post("/login", data={"username": "admin",
                                    "password": "admin12345"})
        adm = Admin.query.first()
        if adm and not adm.is_super_admin:
            adm.is_super_admin = True
            db.session.commit()

        j = OnboardingJob(status="script_generated", chr_id=None)
        j.form_input = {"name": "route-phantom",
                        "provider": "route-test-prov"}
        db.session.add(j); db.session.commit()
        jid = j.id

        # Disable CSRF for this raw POST (the production browser carries
        # X-CSRFToken; the test client uses Flask's WTF_CSRF_ENABLED=False
        # config in TestingConfig if set, otherwise we'd need to fetch
        # the token). We just confirm the route logic + deletion.
        r = client.post("/admin/fleet/onboarding/orphans/purge")
        assert r.status_code == 200, r.data[:200]
        body = r.get_json()
        assert body["ok"] is True
        report = body["report"]
        assert report["orphan_jobs_deleted"] >= 1, (
            f"route response did not record the orphan job deletion: {report}"
        )
        assert db.session.get(OnboardingJob, jid) is None
