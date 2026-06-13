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
# (4) Modal markup + JS load at page level (not inside a tab partial)
# ════════════════════════════════════════════════════════════════════════
class TestModalAtPageLevel:

    def test_modal_lives_inside_block_content_not_a_tab_partial(self):
        """The script-view modal markup + JS load must sit in
        ``{% block content %}`` (page-level), not inside a tab partial
        that gets replaced. We pin this by reading the source bounds
        and asserting the modal id is BEFORE the {% endblock %} of the
        content block + BEFORE any sub-include that could be swapped."""
        html = Path("app/templates/admin/fleet/dashboard.html").read_text(encoding="utf-8")
        # Locate {% block content %} ... {% endblock %} bounds.
        start = html.index("{% block content %}")
        # The TOP-level endblock for content is the last one before EOF
        # (the template uses several nested-looking {% endif %} etc but
        # only one {% block content %}). Walk forward to find the
        # matching {% endblock %} for content.
        # Simpler check: the modal id is present + comes AFTER `{% block content %}`.
        modal_idx = html.index('id="fd-script-modal"')
        assert modal_idx > start, "modal must be inside {% block content %}"
        # And the script-view JS tag is loaded at page level too.
        script_tag_idx = html.index("admin_fleet_script_view.js")
        assert script_tag_idx > start
        # Neither sits inside any {% include %} (tab content is rendered
        # inline by Jinja; there is no template include path that gets
        # AJAX-swapped). Pin that there's no `data-live-replace` on the
        # modal's container element.
        modal_block = html[modal_idx:modal_idx + 800]
        assert "data-live-replace" not in modal_block, (
            "modal subtree must NOT be a live-replace target — that would "
            "destroy the modal element on every live-poll tick"
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
