"""fix/view-script-404-orphan — robust script-view + orphan-job sweep.

Field incident: the dashboard rendered a pending card with
``data-job-id="2"`` (status «تم توليد السكربت»), but
``GET /admin/fleet/onboarding/jobs/2/script`` returned a bare 404 and
the script modal hung on «(لم يُحمَّل السكربت)». Root cause: a job/node
state inconsistency from many delete/recreate cycles — at click time
the OnboardingJob row was gone (deleted directly or via a partial
cleanup) but the dashboard render had captured it before.

Three independently-sufficient pins:

  1. `view_script` now FALLS BACK to a FleetChrNode(node_id) lookup
     when no job exists; if a sibling job (chr_id=node.id) is in a
     renderable state, render via it (operator still SEES the script).
  2. `view_script` returns 410 GONE with a clear actionable Arabic
     message when the node exists but no renderable sibling job is
     left; and 404 with a refresh-the-page hint when nothing at all
     matches the id.
  3. The orphan-purge now ALSO sweeps OnboardingJob rows whose
     `chr_id` points at a node that no longer exists (previously
     uncaught — these were the source of the phantom cards).

Plus a presentation-layer guard: the dashboard pending list filters
out jobs whose `chr_id` points at a missing node, so no broken
«عرض السكربت» button can be rendered in the first place.
"""
from __future__ import annotations

import pytest

from app.extensions import db
from app.models import Admin
from fleet.registry.models_chr import FleetChrNode, FleetProvider
from fleet.registry.models_onboarding import OnboardingJob
from fleet.registry.teardown import find_orphans, purge_orphans


def _login_admin(client):
    return client.post(
        "/login", data={"username": "admin", "password": "admin12345"}
    )


def _make_super_admin():
    adm = Admin.query.first()
    if adm and not adm.is_super_admin:
        adm.is_super_admin = True
        db.session.commit()


@pytest.fixture()
def provider(app):
    p = FleetProvider.query.first()
    if p is not None:
        return p
    p = FleetProvider(
        name="vs404-prov", cost_model="open", price_per_tb=0,
        overage_allowed=False, billing_cycle_day=1,
    )
    db.session.add(p); db.session.commit()
    return p


def _make_node(provider, **kw):
    base = dict(
        provider_id=provider.id,
        name="chr-vs404",
        public_ip="203.0.113.50",
        wg_mgmt_ip="10.99.0.50", wg_mgmt_pubkey="x" * 44,
        max_sessions=500, link_speed_mbps=1000, weight=1.0,
        enabled=True, drain=False, status="provisioning",
        cpu_pct=0, active_sessions=0,
    )
    base.update(kw)
    n = FleetChrNode(**base)
    db.session.add(n); db.session.commit()
    return n


def _make_job(*, status="script_generated", chr_id=None, name="chr-vs404"):
    j = OnboardingJob(status=status, chr_id=chr_id)
    j.form_input = {"name": name, "provider": "vs404-prov"}
    j.generated_script_ref = "sha256:" + "0" * 64
    db.session.add(j); db.session.commit()
    return j


URL = "/admin/fleet/onboarding/jobs/{id}/script"


# ════════════════════════════════════════════════════════════════════════
# (1) Missing job + missing node → 404 with actionable message
# ════════════════════════════════════════════════════════════════════════
class TestNothingResolves:

    def test_404_carries_clear_message(self, app, client):
        _login_admin(client); _make_super_admin()
        r = client.get(URL.format(id=9999))
        assert r.status_code == 404
        body = r.get_json()
        assert body["ok"] is False
        assert body["error"] == "not_found"
        # The message must be actionable (not just "not found").
        assert "أعد تحميل اللوحة" in body["message"]
        assert body.get("job_id") == 9999


# ════════════════════════════════════════════════════════════════════════
# (2) Missing job, node exists, NO sibling job → 410 GONE + orphan hint
# ════════════════════════════════════════════════════════════════════════
class TestOrphanNodeNoSiblingJob:

    def test_410_with_orphan_hint(self, app, client, provider):
        _login_admin(client); _make_super_admin()
        n = _make_node(provider, name="chr-orphan")
        r = client.get(URL.format(id=n.id))
        assert r.status_code == 410, r.data
        body = r.get_json()
        assert body["ok"] is False
        assert body["error"] == "orphan_node"
        assert body["node_id"] == n.id
        assert body["node_name"] == "chr-orphan"
        assert "نظّف المهملات" in body["message"], body["message"]


# ════════════════════════════════════════════════════════════════════════
# (3) Missing job, node exists, SIBLING job → render via sibling
# ════════════════════════════════════════════════════════════════════════
class TestSiblingJobFallback:

    def test_falls_back_to_sibling_job_when_target_job_deleted(
        self, app, client, provider,
    ):
        """The operator clicks a stale button with id=N. There's no
        OnboardingJob with that primary key, BUT a FleetChrNode(N)
        exists AND a separate OnboardingJob has chr_id=N in a
        renderable state. view_script resolves via the sibling job
        (status != 404 and != 410 = the resolver picked it up).

        We don't drive the renderer here — the bindings-incomplete
        precondition (412) is a perfectly acceptable signal that the
        fallback path WAS taken (because the alternative — no job
        resolved — would return 404 or 410, which the prior code did
        emit and this test would catch).
        """
        _login_admin(client); _make_super_admin()
        n = _make_node(provider, name="chr-sibling")
        sibling = _make_job(status="script_generated", chr_id=n.id,
                            name="chr-sibling")
        r = client.get(URL.format(id=n.id))
        # Either 200 (full render succeeded) or 412 (bindings-incomplete
        # precondition — fleet-infra Settings not seeded in the test DB)
        # or 503 (renderer dep). Anything OTHER than 404 / 410 means the
        # resolver successfully fell back to the sibling job. The bare
        # 404 was the pre-fix bug; the 410 orphan_node is the
        # node-without-sibling case (tested above).
        assert r.status_code not in (404, 410), (
            f"sibling-job fallback didn't kick in for node #{n.id} "
            f"(sibling job #{sibling.id}); got status {r.status_code}: "
            f"{r.data[:200]!r}"
        )


# ════════════════════════════════════════════════════════════════════════
# (4) Orphan-purge sweeps jobs whose chr_id points to a missing node
# ════════════════════════════════════════════════════════════════════════
class TestOrphanPurgeIncludesDanglingChrId:

    def test_find_orphans_lists_jobs_with_dangling_chr_id(self, app, provider):
        """A job whose chr_id references a deleted FleetChrNode is now
        flagged as an orphan job (previously: only chr_id IS NULL was)."""
        # Create a node, a job pointing at it, then DELETE the node
        # while leaving the job.
        n = _make_node(provider, name="chr-dangling")
        j = _make_job(status="script_generated", chr_id=n.id,
                      name="chr-dangling")
        chr_id = n.id
        db.session.delete(n); db.session.commit()
        # The job's chr_id now points at a missing node.
        survey = find_orphans()
        assert j.id in survey.orphan_job_ids, (
            "job whose chr_id points at a deleted node must be flagged "
            "as orphan — it renders a card with a 404-on-click button"
        )

    def test_purge_removes_dangling_jobs(self, app, provider):
        n = _make_node(provider, name="chr-purge-me")
        j = _make_job(status="script_generated", chr_id=n.id,
                      name="chr-purge-me")
        db.session.delete(n); db.session.commit()
        report = purge_orphans()
        db.session.commit()
        assert db.session.get(OnboardingJob, j.id) is None
        assert report.orphan_jobs_deleted >= 1


# ════════════════════════════════════════════════════════════════════════
# (5) Dashboard pending list drops jobs whose chr_id is missing
# ════════════════════════════════════════════════════════════════════════
class TestDashboardSkipsDanglingPending:

    def test_dashboard_omits_pending_card_for_dangling_job(
        self, app, client, provider,
    ):
        """The dashboard renders the pending tab with a guard that
        drops any job whose chr_id points at a missing node — so the
        operator never sees a «عرض السكربت» button that 404s."""
        _login_admin(client); _make_super_admin()
        n = _make_node(provider, name="chr-dangling-card")
        j = _make_job(status="script_generated", chr_id=n.id,
                      name="chr-dangling-card")
        db.session.delete(n); db.session.commit()

        r = client.get("/admin/fleet/")
        html = r.get_data(as_text=True)
        # The pending tab MUST NOT render a card with the dangling job's id.
        assert f'data-job-id="{j.id}"' not in html, (
            "dashboard rendered a pending card for a job whose chr_id "
            "points at a deleted node — the «عرض السكربت» button on it "
            "would 404. The pending list must filter these out."
        )

    def test_dashboard_renders_card_for_normal_pending_job(
        self, app, client, provider,
    ):
        """Regression guard: the dangling-job filter must NOT also
        drop the NORMAL case (job with a live node, no live-up health)."""
        _login_admin(client); _make_super_admin()
        n = _make_node(provider, name="chr-normal", status="provisioning")
        j = _make_job(status="script_generated", chr_id=n.id,
                      name="chr-normal")
        r = client.get("/admin/fleet/")
        html = r.get_data(as_text=True)
        assert f'data-job-id="{j.id}"' in html, (
            "normal pending card disappeared — the dangling-job filter "
            "is too aggressive"
        )
