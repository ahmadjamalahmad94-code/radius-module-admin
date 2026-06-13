"""fix/dashboard-buttons-event-delegation — dynamic-button click survival.

Field incident: «عرض السكربت» on ACTIVE node cards did nothing —
clicks silently dropped, no console error. Other buttons like
«فحص» / «مقاييس» / «متابعة» / «حذف» suffered the same class of
bug whenever the dashboard re-rendered their containing markup
(tab switch / live-poll `data-live-rows` replace).

Root cause: the JS bound click handlers per-button at init via
``document.querySelectorAll(...).forEach(addEventListener)``.
Buttons created or replaced AFTER init were never bound.

Fix: convert every such binding to EVENT DELEGATION at document
level using ``e.target.closest(selector)``. One listener at
``document`` survives every DOM rewrite and catches every present
+ future button.

These tests pin the contract at the SOURCE level — a structural
guarantee that future edits don't regress to per-button binding.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest


JS_DIR = Path("app/static/js")
SCRIPT_VIEW = JS_DIR / "admin_fleet_script_view.js"
PENDING_ACTIONS = JS_DIR / "admin_fleet_pending_actions.js"
DASHBOARD = JS_DIR / "admin_fleet_dashboard.js"


# ════════════════════════════════════════════════════════════════════════
# (1) admin_fleet_script_view.js — view-script delegation (the live bug)
# ════════════════════════════════════════════════════════════════════════
class TestScriptViewDelegation:

    def test_no_per_button_binding_at_init(self):
        """The previous broken pattern was
        ``document.querySelectorAll('.fd-node-view-script').forEach(btn => btn.addEventListener)``.
        Pin its absence so the future regression that the owner just
        survived doesn't sneak back."""
        body = SCRIPT_VIEW.read_text(encoding="utf-8")
        # We allow the SELECTOR to appear inside the delegated handler's
        # .closest() check — that's the GOOD shape. We disallow the
        # forEach(addEventListener) shape.
        bad = re.search(
            r"querySelectorAll\([\"'][^\"']*\.fd-(node|pj)-view-script[^\"']*[\"']\)\s*\.forEach",
            body,
        )
        assert bad is None, (
            "view-script handler still uses per-button querySelectorAll().forEach() "
            "binding — late-rendered buttons (tab switch / live-poll row replace) "
            "will silently die on click. Use document.addEventListener('click', ...) "
            "+ e.target.closest('.fd-node-view-script, .fd-pj-view-script') instead."
        )

    def test_uses_document_delegation_with_closest(self):
        body = SCRIPT_VIEW.read_text(encoding="utf-8")
        # The good shape: ONE document-level click listener that matches
        # both classes via .closest().
        assert 'document.addEventListener("click"' in body, (
            "view-script JS must register the click handler at document "
            "level so dynamically-rendered buttons are caught"
        )
        # The closest() match covers BOTH the pending-card and the
        # active-node buttons in one selector.
        m = re.search(
            r"\.closest\(\s*[\"'][^\"']*\.fd-pj-view-script[^\"']*"
            r"\.fd-node-view-script[^\"']*[\"']\s*\)",
            body,
        )
        # Allow either order: ".fd-pj-view-script, .fd-node-view-script"
        # or ".fd-node-view-script, .fd-pj-view-script". Both are fine.
        m2 = re.search(
            r"\.closest\(\s*[\"'][^\"']*"
            r"(\.fd-pj-view-script[^\"']*\.fd-node-view-script"
            r"|\.fd-node-view-script[^\"']*\.fd-pj-view-script)"
            r"[^\"']*[\"']\s*\)",
            body,
        )
        assert m or m2, (
            "view-script delegation must match BOTH .fd-pj-view-script "
            "AND .fd-node-view-script in one .closest() selector"
        )

    def test_kind_dispatch_preserved(self):
        """The delegated handler must still dispatch by kind so the
        node-keyed route is hit for active nodes and the job-keyed
        route is hit for pending cards."""
        body = SCRIPT_VIEW.read_text(encoding="utf-8")
        assert 'openFor(' in body
        assert '"node"' in body and '"job"' in body
        # And it must read the right dataset key per kind.
        assert "dataset.nodeId" in body
        assert "dataset.jobId" in body


# ════════════════════════════════════════════════════════════════════════
# (2) admin_fleet_pending_actions.js — advance/delete delegation
# ════════════════════════════════════════════════════════════════════════
class TestPendingActionsDelegation:

    def test_no_per_button_binding_at_init(self):
        body = PENDING_ACTIONS.read_text(encoding="utf-8")
        bad_adv = re.search(
            r"querySelectorAll\([\"'][^\"']*\.fd-pj-advance[^\"']*[\"']\)\s*\.forEach",
            body,
        )
        bad_del = re.search(
            r"querySelectorAll\([\"'][^\"']*\.fd-pj-delete[^\"']*[\"']\)\s*\.forEach",
            body,
        )
        assert bad_adv is None, (
            "pending-actions .fd-pj-advance is still bound per-button at "
            "init — dynamic re-renders will kill the «متابعة» button"
        )
        assert bad_del is None, (
            "pending-actions .fd-pj-delete is still bound per-button at "
            "init — dynamic re-renders will kill the «حذف» button"
        )

    def test_uses_document_delegation(self):
        body = PENDING_ACTIONS.read_text(encoding="utf-8")
        assert 'document.addEventListener("click"' in body
        # Delegation matches both classes via .closest() (separately is fine).
        assert ".closest(\".fd-pj-advance\")" in body
        assert ".closest(\".fd-pj-delete\")" in body


# ════════════════════════════════════════════════════════════════════════
# (3) admin_fleet_dashboard.js — fd-check-one / fd-poll-metrics delegation
# ════════════════════════════════════════════════════════════════════════
class TestDashboardActionDelegation:

    def test_no_per_button_binding_at_init_for_check_one(self):
        body = DASHBOARD.read_text(encoding="utf-8")
        bad = re.search(
            r"querySelectorAll\([\"'][^\"']*\.fd-check-one[^\"']*[\"']\)\s*\.forEach",
            body,
        )
        assert bad is None, (
            "fd-check-one is still bound per-button at init — re-rendered "
            "node cards will lose the «فحص» button"
        )

    def test_no_per_button_binding_at_init_for_poll_metrics(self):
        body = DASHBOARD.read_text(encoding="utf-8")
        bad = re.search(
            r"querySelectorAll\([\"'][^\"']*\.fd-poll-metrics[^\"']*[\"']\)\s*\.forEach",
            body,
        )
        assert bad is None, (
            "fd-poll-metrics is still bound per-button at init — re-rendered "
            "node cards will lose the «مقاييس» button"
        )

    def test_uses_document_delegation_for_dynamic_buttons(self):
        body = DASHBOARD.read_text(encoding="utf-8")
        # The handler is the entry point for click. We don't assert ONE
        # listener (the file has multiple unrelated click listeners) —
        # we assert each dynamic button class is matched via .closest()
        # inside SOME click handler.
        assert ".closest(\".fd-check-one\")" in body
        assert ".closest(\".fd-poll-metrics\")" in body


# ════════════════════════════════════════════════════════════════════════
# (4) Modal markup + JS load at page level — RENDER-TIME test
#
# fix/script-modal-js-page-level — the previous source-level test
# FALSE-PASSED: it confirmed the modal markup existed somewhere
# inside {% block content %} but did NOT prove it was actually
# emitted by GET /admin/fleet/. The modal + the two <script> tags
# sat inside `{% if pending_jobs %}` so they vanished whenever the
# operator had no pending onboarding jobs (the chr-vpn-1/2 active
# state). Active-node «عرض السكربت» buttons opened a modal that
# wasn't in the DOM + ran a handler that wasn't loaded.
#
# These tests render the dashboard via the test client and grep the
# RESPONSE HTML — the only check that catches the conditional-
# rendering trap. Two scenarios: empty fleet + active-node-only.
# ════════════════════════════════════════════════════════════════════════
class TestModalAndJsRenderedAtPageLevel:

    @staticmethod
    def _login_super(client):
        from app.extensions import db
        from app.models import Admin
        client.post("/login", data={"username": "admin",
                                    "password": "admin12345"})
        adm = Admin.query.first()
        if adm and not adm.is_super_admin:
            adm.is_super_admin = True
            db.session.commit()

    def test_render_with_no_pending_jobs_still_has_modal_and_js(
        self, app, client,
    ):
        """The exact live state the owner hit: chr-vpn-1/2 are ACTIVE
        (no pending OnboardingJob rows), so {% if pending_jobs %} is
        FALSE. Modal + both script tags MUST still render."""
        self._login_super(client)
        # No pending jobs, no nodes — pure empty state.
        html = client.get("/admin/fleet/").get_data(as_text=True)
        assert 'id="fd-script-modal"' in html, (
            "modal element missing from render with no pending jobs — "
            "the «عرض السكربت» button on any future active-node card "
            "would open a modal that isn't in the DOM"
        )
        assert "admin_fleet_script_view.js" in html, (
            "script-view JS bundle missing from render — the button "
            "click handler would never load"
        )
        assert "admin_fleet_pending_actions.js" in html, (
            "pending-actions JS bundle missing from render — the "
            "advance/delete handlers for any future pending card "
            "wouldn't load either"
        )

    def test_render_with_active_node_and_no_pending_has_button_and_js(
        self, app, client,
    ):
        """The active-node card renders the .fd-node-view-script
        button AND the script tag + modal that wire it up — all in
        the SAME response, so the page is self-consistent."""
        from app.extensions import db
        from fleet.registry.models_chr import FleetChrNode, FleetProvider
        self._login_super(client)
        p = FleetProvider.query.first() or FleetProvider(
            name="rt", cost_model="open", price_per_tb=0,
            overage_allowed=False, billing_cycle_day=1,
        )
        if p.id is None:
            db.session.add(p); db.session.commit()
        n = FleetChrNode(
            provider_id=p.id, name="chr-vpn-active",
            public_ip="203.0.113.11",
            wg_mgmt_ip="10.99.0.11", wg_mgmt_pubkey="x" * 44,
            max_sessions=500, link_speed_mbps=1000, weight=1.0,
            enabled=True, drain=False, status="up",
            cpu_pct=0, active_sessions=0,
        )
        db.session.add(n); db.session.commit()

        html = client.get("/admin/fleet/").get_data(as_text=True)
        # The button is there.
        assert "fd-node-view-script" in html
        assert f'data-node-id="{n.id}"' in html
        # AND the modal + JS are there in the SAME response — so
        # clicking the button actually does something.
        assert 'id="fd-script-modal"' in html
        assert "admin_fleet_script_view.js" in html
        assert "admin_fleet_pending_actions.js" in html
        # The script-view tag also carries BOTH URL templates so the
        # delegation handler can dispatch node-keyed vs job-keyed.
        assert "data-script-url=" in html
        assert "data-node-script-url=" in html

    def test_modal_subtree_not_live_replace_target(self):
        """Defence-in-depth: confirm the modal subtree is not marked
        as a live-poll replace target. If it were, every poll tick
        would destroy + re-create the modal — which would also wipe
        any open state. Read template source for this pin (the live-
        poll subtree marker would survive across renders)."""
        html = Path("app/templates/admin/fleet/dashboard.html").read_text(encoding="utf-8")
        modal_idx = html.index('id="fd-script-modal"')
        modal_block = html[modal_idx:modal_idx + 800]
        assert "data-live-replace" not in modal_block, (
            "modal subtree must NOT be a live-replace target — that "
            "would destroy the modal element on every live-poll tick"
        )


# ════════════════════════════════════════════════════════════════════════
# (5) End-to-end shape — both pending AND active-node buttons resolve
#     through the SAME delegated path
# ════════════════════════════════════════════════════════════════════════
class TestBothButtonClassesShareOnePath:

    def test_one_delegated_handler_for_both_view_script_classes(self):
        """The script-view file has ONE click handler at document
        scope that catches both the pending-card and the active-node
        buttons — they share the modal, so they share the click path."""
        body = SCRIPT_VIEW.read_text(encoding="utf-8")
        listeners = re.findall(r'document\.addEventListener\(\s*"click"', body)
        # We allow more than one (there could be unrelated future
        # listeners), but we require at least one + it must cover both
        # button classes.
        assert len(listeners) >= 1
        # And we still have a single source of truth for the URL
        # template + dispatch — no fork into two code paths.
        assert body.count("function openFor(") == 1
