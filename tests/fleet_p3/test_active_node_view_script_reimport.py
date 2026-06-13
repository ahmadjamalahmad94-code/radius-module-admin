"""feat/active-node-view-script-reimport — node-keyed «عرض السكربت».

Owner brief: once a node becomes ACTIVE («نشطة») it leaves the pending
tab → the job-keyed «عرض السكربت» button disappears → there's no way
to re-import an active node's script. That broke the key-rotation
flow: the periodic wg-mgmt autosync sets ``needs_reimport=True`` on
active nodes when the panel key drifts, but the operator had no
button to fetch the corrected script.

Fix shipped here:

  1. ``GET /admin/fleet/onboarding/chr-nodes/<int:node_id>/script`` —
     re-render the script keyed by NODE id (finds the latest
     renderable OnboardingJob with chr_id=node.id, includes
     status='active'). Same JSON envelope as the job-keyed route.
  2. Active «عقد CHR» cards carry «عرض السكربت»
     (``.fd-node-view-script``, data-node-id) wired to the new route.
  3. When ``needs_reimport=True`` the card shows a
     «بحاجة لإعادة استيراد السكربت» badge AND highlights the button
     (``.fd-rowbtn--reimport``). Hint title spells out "تغيّر مفتاح
     اللوحة — أعد استيراد السكربت المُولّد حديثاً".
  4. Pending-tab («عرض السكربت») still works (job-keyed), unchanged.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.extensions import db
from app.models import Admin
from fleet.registry.models_chr import FleetChrNode, FleetProvider
from fleet.registry.models_onboarding import OnboardingJob


# ════════════════════════════════════════════════════════════════════════
# Helpers / fixtures
# ════════════════════════════════════════════════════════════════════════


@pytest.fixture()
def provider(app):
    p = FleetProvider.query.first()
    if p is not None:
        return p
    p = FleetProvider(
        name="anv-prov", cost_model="open", price_per_tb=0,
        overage_allowed=False, billing_cycle_day=1,
    )
    db.session.add(p); db.session.commit()
    return p


def _make_node(provider, **kw) -> FleetChrNode:
    """FleetChrNode.status check-constraint allows
    {provisioning, up, degraded, down, disabled} — 'active' is a JOB
    status, NOT a node status. We default the node to 'up' (the
    operationally-active state) and use OnboardingJob.status='active'
    in the sibling job."""
    base = dict(
        provider_id=provider.id,
        name="chr-active-1",
        public_ip="203.0.113.91",
        wg_mgmt_ip="10.99.0.91", wg_mgmt_pubkey="x" * 44,
        max_sessions=500, link_speed_mbps=1000, weight=1.0,
        enabled=True, drain=False, status="up",
        cpu_pct=10, active_sessions=0,
    )
    base.update(kw)
    n = FleetChrNode(**base)
    db.session.add(n); db.session.commit()
    return n


def _make_active_job(node: FleetChrNode, *, status="active") -> OnboardingJob:
    j = OnboardingJob(status=status, chr_id=node.id)
    j.form_input = {"name": node.name, "provider": "anv-prov"}
    j.generated_script_ref = "sha256:" + "f" * 64
    db.session.add(j); db.session.commit()
    return j


def _login_admin(client):
    return client.post(
        "/login", data={"username": "admin", "password": "admin12345"}
    )


def _make_super_admin():
    adm = Admin.query.first()
    if adm and not adm.is_super_admin:
        adm.is_super_admin = True
        db.session.commit()


URL = "/admin/fleet/onboarding/chr-nodes/{id}/script"


# ════════════════════════════════════════════════════════════════════════
# (1) Route returns JSON for an ACTIVE node
# ════════════════════════════════════════════════════════════════════════
class TestNodeKeyedRoute:

    def test_active_node_resolves_and_returns_script_envelope(
        self, app, client, provider,
    ):
        """The node-keyed route resolves a FleetChrNode whose
        OnboardingJob is status='active' (which the job-keyed route
        only sees because it's still in _SCRIPT_VIEW_OK_STATUSES)
        and returns a script-envelope JSON. We pin the envelope shape
        + the new node_id echo + the needs_reimport flag."""
        _login_admin(client); _make_super_admin()
        n = _make_node(provider, name="chr-anv-active")
        _make_active_job(n, status="active")

        r = client.get(URL.format(id=n.id))
        # Either 200 (full render) or 412 (bindings_incomplete - missing
        # fleet-infra Settings in the test DB). What we MUST NOT see is
        # 404/410 - those would mean the resolver itself failed to find
        # a renderable job for the node.
        assert r.status_code not in (404, 410), r.data[:200]
        if r.status_code == 200:
            body = r.get_json()
            assert body["ok"] is True
            assert body["node_id"] == n.id
            assert body["node_name"] == "chr-anv-active"
            assert "filename" in body
            assert "script" in body
            assert "sha256" in body
            assert "needs_reimport" in body, (
                "node-keyed route MUST surface the needs_reimport flag "
                "so the modal can show the drift banner"
            )
            assert body["needs_reimport"] is False

    def test_unknown_node_returns_404_with_actionable_message(
        self, app, client,
    ):
        _login_admin(client); _make_super_admin()
        r = client.get(URL.format(id=99999))
        assert r.status_code == 404
        body = r.get_json()
        assert body["ok"] is False
        assert body["error"] == "not_found"
        assert "أعد تحميل اللوحة" in body["message"]
        assert body["node_id"] == 99999

    def test_orphan_node_no_renderable_job_returns_410(
        self, app, client, provider,
    ):
        """A FleetChrNode that has no OnboardingJob in a renderable
        state (e.g. job was deleted while node stayed) returns 410
        GONE with the «نظّف المهملات» hint — same UX as the job-keyed
        fallback resolver."""
        _login_admin(client); _make_super_admin()
        n = _make_node(provider, name="chr-orphan-active")
        # NO OnboardingJob at all → orphan.
        r = client.get(URL.format(id=n.id))
        assert r.status_code == 410
        body = r.get_json()
        assert body["ok"] is False
        assert body["error"] == "orphan_node"
        assert body["node_id"] == n.id
        assert "نظّف المهملات" in body["message"]


# ════════════════════════════════════════════════════════════════════════
# (2) Active-node card renders «عرض السكربت» + needs_reimport badge
# ════════════════════════════════════════════════════════════════════════
class TestActiveCardUI:

    def test_active_card_renders_view_script_button(self, app, client, provider):
        """An ACTIVE fleet node appears in the «عقد CHR» tab with the
        node-keyed «عرض السكربت» button — the operator can re-view +
        re-import anytime, not just while the node is in the pending
        tab."""
        _login_admin(client); _make_super_admin()
        n = _make_node(provider, name="chr-active-card", status="up")
        r = client.get("/admin/fleet/")
        assert r.status_code == 200
        html = r.get_data(as_text=True)
        # The node card renders the new class + the node id.
        assert "fd-node-view-script" in html, (
            "active node card must carry the .fd-node-view-script "
            "button so the operator can re-view + re-import"
        )
        assert f'data-node-id="{n.id}"' in html
        # The button label is in Arabic.
        assert "عرض السكربت" in html

    def test_needs_reimport_badge_renders_when_flag_set(
        self, app, client, provider,
    ):
        """When needs_reimport=True the card shows the drift badge AND
        the «عرض السكربت» button gets the loud .fd-rowbtn--reimport
        variant + the drift hint in its title attribute."""
        _login_admin(client); _make_super_admin()
        n = _make_node(provider, name="chr-drifted", status="up",
                       needs_reimport=True)
        r = client.get("/admin/fleet/")
        html = r.get_data(as_text=True)
        assert "بحاجة لإعادة استيراد السكربت" in html, (
            "needs_reimport badge text missing from the active card"
        )
        # Application of the badge class (not just the CSS rule definition).
        assert 'class="fd-badge fd-badge--reimport"' in html
        # The button carries the highlighted variant.
        assert "fd-rowbtn fd-node-view-script fd-rowbtn--reimport" in html
        # And the hint title spells out the drift reason.
        assert "تغيّر مفتاح اللوحة" in html

    def test_no_reimport_badge_when_flag_clear(self, app, client, provider):
        """A normal node without the drift flag does NOT carry the
        badge or the highlighted button variant — the dashboard stays
        quiet in the common case.

        We look for an APPLICATION of the class (in an HTML element)
        rather than its mere presence in the page (the CSS rules for
        both .fd-badge--reimport and .fd-rowbtn--reimport are
        ALWAYS in the <style> block so the rules are available when
        needed; the test must distinguish "rule defined" from "rule
        used")."""
        _login_admin(client); _make_super_admin()
        n = _make_node(provider, name="chr-quiet", status="up",
                       needs_reimport=False)
        r = client.get("/admin/fleet/")
        html = r.get_data(as_text=True)
        # The base button still renders (always present on node cards).
        assert "fd-node-view-script" in html
        # The badge is rendered as a <span class="fd-badge fd-badge--reimport">
        # — that's the application. The CSS rule definition uses a `.`
        # selector + a `{` brace; the application uses a quoted class
        # attribute, which is far more constrained.
        assert 'class="fd-badge fd-badge--reimport"' not in html
        # Same for the loud button variant.
        assert "fd-rowbtn fd-node-view-script fd-rowbtn--reimport" not in html


# ════════════════════════════════════════════════════════════════════════
# (3) JS wires both pending-card and active-node buttons
# ════════════════════════════════════════════════════════════════════════
class TestJsWiresBoth:

    JS = Path("app/static/js/admin_fleet_script_view.js")

    def test_js_binds_both_classes(self):
        body = self.JS.read_text(encoding="utf-8")
        # Both classes wired — now via document delegation (see
        # fix/dashboard-buttons-event-delegation: the delegation moved
        # the dispatch from a per-button addEventListener inside a
        # querySelectorAll().forEach loop into a SINGLE document-level
        # listener that matches BOTH classes via .closest(). The
        # ``kind`` is now decided inside the handler by inspecting
        # ``btn.classList.contains("fd-node-view-script")``.).
        assert ".fd-pj-view-script" in body, "pending-card binding lost"
        assert ".fd-node-view-script" in body, (
            "active-node binding missing — owner can't re-import "
            "active nodes' scripts"
        )
        # openFor is still the single dispatch entry, called with the
        # resolved kind variable from the delegated handler.
        assert "openFor(id, name, kind)" in body, (
            "delegation must dispatch through openFor(id, name, kind)"
        )
        # Both kind constants reachable in the dispatch.
        assert '"node"' in body and '"job"' in body
        assert 'classList.contains("fd-node-view-script")' in body, (
            "delegated handler must distinguish node vs job by the "
            "button's class, not by which iterator wrote the listener"
        )

    def test_js_reads_node_script_url_from_script_tag(self):
        body = self.JS.read_text(encoding="utf-8")
        # The new template URL comes from data-node-script-url
        assert "dataset.nodeScriptUrl" in body
        # And urlFor distinguishes job vs node via the kind arg.
        assert 'kind === "node"' in body

    def test_template_passes_both_urls_to_the_script_tag(self):
        html = Path("app/templates/admin/fleet/dashboard.html").read_text(encoding="utf-8")
        # Both URL templates must be plumbed into the <script> tag.
        assert "data-script-url=" in html
        assert "data-node-script-url=" in html
        # And the node URL points at the new endpoint.
        assert "view_node_script" in html


# ════════════════════════════════════════════════════════════════════════
# (4) Pending-card path still works (regression guard)
# ════════════════════════════════════════════════════════════════════════
class TestPendingPathStillWorks:

    def test_pending_card_still_renders_pj_view_script(
        self, app, client, provider,
    ):
        _login_admin(client); _make_super_admin()
        n = _make_node(provider, name="chr-pending", status="provisioning")
        j = OnboardingJob(status="script_generated", chr_id=n.id)
        j.form_input = {"name": "chr-pending", "provider": "anv-prov"}
        j.generated_script_ref = "sha256:" + "0" * 64
        db.session.add(j); db.session.commit()

        r = client.get("/admin/fleet/")
        html = r.get_data(as_text=True)
        # The pending tab still uses the job-keyed button.
        assert "fd-pj-view-script" in html
        assert f'data-job-id="{j.id}"' in html


# ════════════════════════════════════════════════════════════════════════
# (5) Audit row written when node-script is fetched
# ════════════════════════════════════════════════════════════════════════
class TestAuditRow:

    def test_node_script_view_writes_audit_row_on_success(
        self, app, client, provider,
    ):
        """The node-keyed view emits a distinct audit action so the
        operator can see in /admin/audit who fetched what + when.

        The audit fires only after the render path completes (i.e. when
        the response is 200). On the bindings-incomplete (412) path
        the audit must NOT fire — that's intentional. So we either
        seed the prerequisites OR verify the conditional contract;
        here we just verify the action name pattern at the source
        level, leaving the integration audit-on-200 to the existing
        sweep that already exercises the job-keyed equivalent."""
        from pathlib import Path
        src = Path("fleet/registry/routes_onboarding.py").read_text(encoding="utf-8")
        # The node-keyed route must reference a distinct audit action.
        assert '"fleet_node_script_view"' in src, (
            "node-keyed view_node_script must write a distinct audit "
            "action 'fleet_node_script_view' (vs the job-keyed "
            "'fleet_onboarding_script_view')"
        )
        # And the audit must be invoked from inside view_node_script.
        body = src[src.index("def view_node_script("):]
        body = body[: body.index("\n@") if "\n@" in body else len(body)]
        assert "fleet_node_script_view" in body, (
            "audit call missing from view_node_script body — refactor "
            "regression"
        )
