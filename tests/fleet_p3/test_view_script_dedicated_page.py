"""fix/view-script-dedicated-page — standalone full-page script viewer.

The floating «عرض السكربت» modal kept failing for the owner despite a
string of fixes (event delegation, pause-poll, page-level modal,
textarea). Radical root solution: «عرض السكربت» now opens a DEDICATED
full page in a NEW TAB rendering the script as plain text — its own
minimal template (no live_poll.js, no polling, no modal CSS) so the
dashboard renderer/poll can never break it.

These tests pin:
  * both routes registered (node-keyed + job-keyed);
  * a successful view returns a standalone HTML page (NOT extending the
    dashboard) with a <textarea readonly> carrying the rendered script
    + a download link;
  * orphan / unknown / render-dependency failures degrade GRACEFULLY to
    a readable error page (never a bare 500/503);
  * the dashboard buttons are target=_blank anchors to the new routes.
"""
from __future__ import annotations

import re

import pytest

from app.extensions import db
from app.models import Admin
from fleet.registry.models_chr import FleetChrNode, FleetProvider
from fleet.registry.models_onboarding import OnboardingJob


def _login_super(client):
    client.post("/login", data={"username": "admin", "password": "admin12345"})
    adm = Admin.query.first()
    if adm and not adm.is_super_admin:
        adm.is_super_admin = True
        db.session.commit()


def _provider() -> FleetProvider:
    p = FleetProvider.query.first()
    if p is not None:
        return p
    p = FleetProvider(name="vsp-prov", cost_model="open", price_per_tb=0,
                      overage_allowed=False, billing_cycle_day=1)
    db.session.add(p); db.session.commit()
    return p


_SEQ = [70]


def _make_node(**kw) -> FleetChrNode:
    _SEQ[0] += 1
    base = dict(
        provider_id=_provider().id,
        name=f"chr-vsp-{_SEQ[0]}",
        public_ip=f"203.0.113.{_SEQ[0]}",
        wg_mgmt_ip=f"10.99.0.{_SEQ[0]}", wg_mgmt_pubkey="x" * 44,
        max_sessions=500, link_speed_mbps=1000, weight=1.0,
        enabled=True, drain=False, status="up",
    )
    base.update(kw)
    n = FleetChrNode(**base)
    db.session.add(n); db.session.commit()
    return n


def _make_active_job(n: FleetChrNode) -> OnboardingJob:
    j = OnboardingJob(status="active", chr_id=n.id)
    j.form_input = {"name": n.name, "provider": "vsp-prov"}
    j.generated_script_ref = "sha256:" + "f" * 64
    db.session.add(j); db.session.commit()
    return j


NODE_URL = "/admin/fleet/onboarding/chr-nodes/{id}/script/view"
JOB_URL = "/admin/fleet/onboarding/jobs/{id}/script/view"


# ════════════════════════════════════════════════════════════════════════
# (1) Routes registered
# ════════════════════════════════════════════════════════════════════════
class TestRoutesRegistered:

    def test_node_view_route(self, app):
        rules = {str(r.rule) for r in app.url_map.iter_rules()}
        assert "/admin/fleet/onboarding/chr-nodes/<int:node_id>/script/view" in rules

    def test_job_view_route(self, app):
        rules = {str(r.rule) for r in app.url_map.iter_rules()}
        assert "/admin/fleet/onboarding/jobs/<int:job_id>/script/view" in rules


# ════════════════════════════════════════════════════════════════════════
# (2) Successful render → standalone page, textarea, script, download link
# ════════════════════════════════════════════════════════════════════════
class TestSuccessfulView:

    def test_node_view_renders_standalone_page(self, app, client, monkeypatch):
        _login_super(client)
        n = _make_node(name="chr-vsp-ok")
        _make_active_job(n)
        from fleet.registry import routes_onboarding as ro
        monkeypatch.setattr(
            ro, "_render_job_to_response_payload",
            lambda job: {
                "job": job,
                "script": "# pretend RouterOS script\n/system identity set name=ok\n",
                "bindings": {}, "node_name": "chr-vsp-ok",
                "filename": "chr-vsp-ok.rsc",
            },
        )
        r = client.get(NODE_URL.format(id=n.id))
        assert r.status_code == 200
        assert r.mimetype == "text/html"
        html = r.get_data(as_text=True)
        # Standalone page — NOT the dashboard layout (no live_poll.js).
        assert "live_poll.js" not in html
        assert "<!DOCTYPE html>" in html
        # The readonly textarea carries the rendered script verbatim.
        m = re.search(r'<textarea[^>]*id="script"[^>]*>', html)
        assert m, "standalone viewer must use a <textarea id=script>"
        assert "readonly" in m.group(0)
        assert "/system identity set name=ok" in html
        # The direct download link is present (points at the .rsc route).
        assert f"/admin/fleet/onboarding/chr-nodes/{n.id}/script.rsc" in html
        # No-store so the plaintext-key body isn't cached.
        assert "no-store" in r.headers.get("Cache-Control", "")

    def test_job_view_renders_standalone_page(self, app, client, monkeypatch):
        _login_super(client)
        n = _make_node(name="chr-vsp-job")
        j = _make_active_job(n)
        from fleet.registry import routes_onboarding as ro
        monkeypatch.setattr(
            ro, "_render_job_to_response_payload",
            lambda job: {
                "job": job, "script": "/ip x\n", "bindings": {},
                "node_name": "chr-vsp-job", "filename": "chr-vsp-job.rsc",
            },
        )
        r = client.get(JOB_URL.format(id=j.id))
        assert r.status_code == 200
        html = r.get_data(as_text=True)
        assert "<textarea" in html
        assert "/ip x" in html


# ════════════════════════════════════════════════════════════════════════
# (3) Graceful degradation — no bare 500/503
# ════════════════════════════════════════════════════════════════════════
class TestGracefulErrors:

    def test_unknown_node_shows_error_page_not_500(self, app, client):
        _login_super(client)
        r = client.get(NODE_URL.format(id=999999))
        assert r.status_code == 404
        assert r.mimetype == "text/html"
        html = r.get_data(as_text=True)
        assert "تعذّر عرض السكربت" in html
        assert "<textarea" not in html  # no script area on the error page

    def test_orphan_node_shows_error_page(self, app, client):
        _login_super(client)
        n = _make_node(name="chr-vsp-orphan")  # node, no job
        r = client.get(NODE_URL.format(id=n.id))
        assert r.status_code == 410
        html = r.get_data(as_text=True)
        assert "تعذّر عرض السكربت" in html
        assert "orphan_node" in html

    def test_render_dependency_failure_shows_error_inline(
        self, app, client, monkeypatch,
    ):
        """If the shared render pipeline returns a (json, 503) error,
        the page shows the reason inline at HTTP 200 (the tab always
        shows something) — NOT a blank 503."""
        _login_super(client)
        n = _make_node(name="chr-vsp-dep")
        _make_active_job(n)
        from flask import jsonify
        from fleet.registry import routes_onboarding as ro
        monkeypatch.setattr(
            ro, "_render_job_to_response_payload",
            lambda job: (jsonify({
                "ok": False, "error": "dependency_unavailable",
                "message": "وحدة Phase-3 غير متوفرة بعد.",
            }), 503),
        )
        r = client.get(NODE_URL.format(id=n.id))
        assert r.status_code == 200  # the tab shows the reason, not a blank 503
        html = r.get_data(as_text=True)
        assert "تعذّر عرض السكربت" in html
        assert "dependency_unavailable" in html
        assert "وحدة Phase-3 غير متوفرة بعد." in html

    def test_unknown_job_shows_error_page(self, app, client):
        _login_super(client)
        r = client.get(JOB_URL.format(id=888888))
        assert r.status_code == 404
        html = r.get_data(as_text=True)
        assert "تعذّر عرض السكربت" in html


# ════════════════════════════════════════════════════════════════════════
# (4) Dashboard buttons are new-tab anchors to the new routes
# ════════════════════════════════════════════════════════════════════════
class TestDashboardButtonsAreAnchors:

    def test_active_node_button_is_blank_anchor(self, app, client):
        _login_super(client)
        n = _make_node(name="chr-vsp-anchor")
        html = client.get("/admin/fleet/").get_data(as_text=True)
        m = re.search(
            r'<a[^>]*class="[^"]*fd-node-view-script[^"]*"[^>]*>',
            html,
        )
        assert m, "active-node «عرض السكربت» must be an <a>, not a <button>"
        tag = m.group(0)
        assert 'target="_blank"' in tag
        assert "noopener" in tag
        assert f"/admin/fleet/onboarding/chr-nodes/{n.id}/script/view" in html

    def test_view_script_button_is_not_a_modal_button(self, app, client):
        """The old <button> modal opener must be gone for active nodes."""
        _login_super(client)
        _make_node(name="chr-vsp-nomodal")
        html = client.get("/admin/fleet/").get_data(as_text=True)
        assert not re.search(
            r'<button[^>]*fd-node-view-script', html
        ), "active-node view-script must no longer be a modal <button>"
