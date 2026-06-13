"""fix/script-modal-buttons-reachable — modal copy/download stay reachable.

Field incident: the install-instructions ``<details>`` block in the
script-view modal was OPEN by default and very tall (sensitivity
banner + WebFig warning + 5-step ordered list + success banner).
Combined with the modal's ``max-height:calc(100vh - 48px); overflow:
hidden`` flex column, the body bar carrying «نسخ» + «تنزيل .rsc»
was pushed below the fold. Operators couldn't reach the buttons
without scrolling INSIDE the modal — which the flex column blocks.

These tests pin three independently-sufficient fixes:

  1. Header copy + download buttons (always visible above the fold).
  2. Body copy + download buttons (legacy bottom position) kept.
  3. The install ``<details>`` is CLOSED by default; the operator
     expands it only on demand.

Together: even if the modal height shrinks to nothing, at least one
button pair is reachable.

NOTE: the script-view modal is rendered inside the dashboard's
``{% if pending_jobs %}`` block (it only shows when there IS a job
whose script can be viewed). The tests below check the TEMPLATE
SOURCE directly so they don't depend on DB seed state; plus one
integration test that creates a pending job to exercise the full
render path.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.extensions import db
from app.models import Admin


_DASHBOARD_TEMPLATE = Path("app/templates/admin/fleet/dashboard.html")


def _login_admin(client):
    return client.post(
        "/login", data={"username": "admin", "password": "admin12345"}
    )


def _make_super_admin():
    adm = Admin.query.first()
    if adm and not adm.is_super_admin:
        adm.is_super_admin = True
        db.session.commit()


def _modal_template_source() -> str:
    """Return only the `#fd-script-modal` block from the template source.

    The modal is conditional on ``{% if pending_jobs %}`` so a full
    render needs DB scaffolding. For shape assertions we read the
    template directly; the integration test below covers the route.
    """
    src = _DASHBOARD_TEMPLATE.read_text(encoding="utf-8")
    start = src.index('id="fd-script-modal"')
    # The modal is its own top-level `<div ...>...</div>` — find its
    # closing tag by counting siblings is overkill; just slice forward
    # a generous chunk that covers the entire dialog. The dialog ends
    # before the final `{% endblock %}`.
    end_marker = "{% endblock %}"
    end = src.index(end_marker, start)
    return src[start:end]


# ════════════════════════════════════════════════════════════════════════
# (1) Header copy + download buttons render
# ════════════════════════════════════════════════════════════════════════
class TestHeaderButtonsRender:

    def test_header_copy_button_present(self):
        modal = _modal_template_source()
        assert 'id="fd-sm-copy-top"' in modal, (
            "header copy button missing - operator can't reach copy "
            "when the install instructions push the body bar off-screen"
        )

    def test_header_download_button_present(self):
        modal = _modal_template_source()
        assert 'id="fd-sm-download-top"' in modal, (
            "header download button missing - operator can't reach "
            "download when the body bar is below the fold"
        )

    def test_header_button_ids_are_unique(self):
        """No duplicate IDs in the modal (prior incident:
        fix/confirm-duplicate-ids). The top buttons MUST carry the
        new -top suffixed ids, not the bare ids."""
        modal = _modal_template_source()
        for the_id in ("fd-sm-copy-top", "fd-sm-download-top",
                       "fd-sm-copy", "fd-sm-download"):
            count = len(re.findall(
                rf'\bid="{re.escape(the_id)}"', modal,
            ))
            assert count == 1, (
                f'expected exactly one element with id="{the_id}"; got {count}'
            )

    def test_header_buttons_render_before_install_details(self):
        """The header copy/download MUST appear in source order BEFORE
        the `<details>` block, otherwise they're still affected by the
        instructions block growing and pushing them down on first paint."""
        modal = _modal_template_source()
        idx_copy_top = modal.index('id="fd-sm-copy-top"')
        idx_details = modal.index("<details")
        assert idx_copy_top < idx_details, (
            "header copy button must appear BEFORE the install "
            "<details> block"
        )


# ════════════════════════════════════════════════════════════════════════
# (2) Body buttons still render (no regression on the legacy position)
# ════════════════════════════════════════════════════════════════════════
class TestBodyButtonsStillRender:

    def test_body_copy_button_present(self):
        modal = _modal_template_source()
        assert 'id="fd-sm-copy"' in modal, (
            "body copy button removed - broke the «نسخ أعلاه» reference "
            "in the install instructions"
        )

    def test_body_download_button_present(self):
        modal = _modal_template_source()
        assert 'id="fd-sm-download"' in modal


# ════════════════════════════════════════════════════════════════════════
# (3) Install instructions <details> is CLOSED by default
# ════════════════════════════════════════════════════════════════════════
class TestInstructionsCollapsedByDefault:

    def test_install_details_is_not_open_by_default(self):
        modal = _modal_template_source()
        # Find the install instructions <details> by its Jinja comment
        # marker, then assert the following `<details` tag has no
        # `open` attribute.
        marker = "Install instructions"
        idx = modal.find(marker)
        assert idx >= 0, "could not locate install instructions block"
        following = modal[idx:idx + 1200]
        m = re.search(r"<details(\s[^>]*)?>", following)
        assert m, "no <details> tag follows the install instructions marker"
        attrs = m.group(1) or ""
        assert " open" not in attrs.lower(), (
            f"install <details> renders with `open` ({attrs!r}) — the "
            "tall instructions block pushes copy/download off-screen on "
            "first open. Close it by default; operator expands on demand."
        )

    def test_install_summary_still_present(self):
        """Close-by-default must NOT hide the summary — the operator
        must still see what they can expand."""
        modal = _modal_template_source()
        assert "كيف أُثبّت السكربت على المايكروتيك؟" in modal


# ════════════════════════════════════════════════════════════════════════
# (3b) Integration — full dashboard render with a pending job present
# ════════════════════════════════════════════════════════════════════════
class TestIntegrationFullDashboardRender:

    def test_modal_renders_with_both_button_pairs_when_pending_job_exists(self, app, client):
        """End-to-end: the script modal lives inside
        ``{% if pending_jobs %}``. Create a pending job + a CHR node so
        the dashboard renders the conditional block, then assert all
        four button ids are reachable in the response HTML.
        """
        _login_admin(client); _make_super_admin()
        from fleet.registry.models_chr import FleetChrNode, FleetProvider
        from fleet.registry.models_onboarding import OnboardingJob

        prov = FleetProvider.query.first() or FleetProvider(
            name="modal-prov", cost_model="open", price_per_tb=0,
            overage_allowed=False, billing_cycle_day=1,
        )
        if prov.id is None:
            db.session.add(prov); db.session.commit()
        n = FleetChrNode(
            provider_id=prov.id, name="chr-modal-1",
            public_ip="203.0.113.99",
            wg_mgmt_ip="10.99.0.99", wg_mgmt_pubkey="X" * 44,
            max_sessions=500, link_speed_mbps=1000, weight=1.0,
            enabled=True, drain=False, status="provisioning",
            cpu_pct=0, active_sessions=0,
        )
        db.session.add(n); db.session.commit()
        job = OnboardingJob(
            status="script_generated",
            form_input={"name": "chr-modal-1"},
            chr_id=n.id,
            generated_script_ref="sha256:" + "0" * 64,
        )
        db.session.add(job); db.session.commit()

        r = client.get("/admin/fleet/")
        assert r.status_code == 200
        html = r.get_data(as_text=True)
        # Modal renders.
        assert 'id="fd-script-modal"' in html
        # Both button pairs are reachable in the response HTML.
        assert 'id="fd-sm-copy-top"' in html
        assert 'id="fd-sm-download-top"' in html
        assert 'id="fd-sm-copy"' in html
        assert 'id="fd-sm-download"' in html
        # And the install <details> has no `open` (full-render check).
        marker_idx = html.find("Install instructions")
        if marker_idx >= 0:
            window = html[marker_idx:marker_idx + 800]
            m = re.search(r"<details(\s[^>]*)?>", window)
            assert m, "no <details> after the Install instructions marker"
            attrs = m.group(1) or ""
            assert " open" not in attrs.lower()


# ════════════════════════════════════════════════════════════════════════
# (4) The JS wires BOTH button pairs (sister handlers)
# ════════════════════════════════════════════════════════════════════════
class TestJsWiresBothButtonPairs:

    def test_js_collects_both_copy_buttons(self):
        from pathlib import Path
        js = Path("app/static/js/admin_fleet_script_view.js").read_text(encoding="utf-8")
        # The handler must reference BOTH ids.
        assert '"fd-sm-copy"' in js
        assert '"fd-sm-copy-top"' in js
        # And iterate (forEach) so they share the same click handler.
        assert "copyBtns.forEach" in js, (
            "copy handler must iterate copyBtns — without forEach only "
            "the first button gets the click listener"
        )

    def test_js_collects_both_download_buttons(self):
        from pathlib import Path
        js = Path("app/static/js/admin_fleet_script_view.js").read_text(encoding="utf-8")
        assert '"fd-sm-download"' in js
        assert '"fd-sm-download-top"' in js
        # setDownload + reset both iterate dlBtns.
        assert "dlBtns.forEach" in js
