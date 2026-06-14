"""fix/direct-script-download-and-freeze — freeze-proof download path.

Live blocker confirmed on the owner's panel: the script-view modal +
the live-poll competing for the main thread froze Chrome's renderer
even with the `pausePoll()` flag fix in place. The owner couldn't
copy or download the script. Two-pronged fix:

PRIMARY — a direct file-download route + an HTML anchor on every
node card. Zero JS, zero modal, zero live-poll involvement → cannot
freeze. The operator clicks ↓ تنزيل .rsc and the browser saves the
file. This is the reliable path.

SECONDARY — make the modal-based path also safe:
  * live_poll.js's isExternalPaused() ALSO reads the modal's
    display directly (belt-and-braces; doesn't rely on the
    window flag being set).
  * The 900-line <pre> was switched to a <textarea readonly>:
    native scroll, flat layout cost, native select-all, no
    per-line layout storm.
  * schedule() short-circuits when paused so a freshly-finished
    in-flight tick doesn't re-arm a timer behind an open modal.
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
# Helpers
# ════════════════════════════════════════════════════════════════════════


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
    p = FleetProvider(
        name="dl-prov", cost_model="open", price_per_tb=0,
        overage_allowed=False, billing_cycle_day=1,
    )
    db.session.add(p); db.session.commit()
    return p


_SEQ = [20]


def _make_node(**kw) -> FleetChrNode:
    _SEQ[0] += 1
    base = dict(
        provider_id=_provider().id,
        name=f"chr-dl-{_SEQ[0]}",
        public_ip=f"203.0.113.{_SEQ[0]}",
        wg_mgmt_ip=f"10.99.0.{_SEQ[0]}", wg_mgmt_pubkey="x" * 44,
        max_sessions=500, link_speed_mbps=1000, weight=1.0,
        enabled=True, drain=False, status="up",
        cpu_pct=0, active_sessions=0,
    )
    base.update(kw)
    n = FleetChrNode(**base)
    db.session.add(n); db.session.commit()
    return n


def _make_active_job(n: FleetChrNode) -> OnboardingJob:
    j = OnboardingJob(status="active", chr_id=n.id)
    j.form_input = {"name": n.name, "provider": "dl-prov"}
    j.generated_script_ref = "sha256:" + "f" * 64
    db.session.add(j); db.session.commit()
    return j


URL_TPL = "/admin/fleet/onboarding/chr-nodes/{id}/script.rsc"


# ════════════════════════════════════════════════════════════════════════
# (1) Direct-download route exists + returns the right shape
# ════════════════════════════════════════════════════════════════════════
class TestDownloadRoute:

    def test_route_registered(self, app):
        rules = {str(r.rule) for r in app.url_map.iter_rules()}
        assert "/admin/fleet/onboarding/chr-nodes/<int:node_id>/script.rsc" in rules

    def test_unknown_node_returns_404(self, app, client):
        _login_super(client)
        r = client.get(URL_TPL.format(id=999999))
        assert r.status_code == 404

    def test_orphan_node_returns_410(self, app, client):
        """Node exists but no renderable OnboardingJob — same 410
        contract as view_node_script. Operator's «Save File» dialog
        shows the JSON error body so the failure is debuggable."""
        _login_super(client)
        n = _make_node(name="chr-dl-orphan")
        r = client.get(URL_TPL.format(id=n.id))
        assert r.status_code == 410
        body = r.get_json()
        assert body["ok"] is False
        assert body["error"] == "orphan_node"

    def test_successful_download_serves_attachment(
        self, app, client, monkeypatch,
    ):
        """Stub the renderer so we can prove the response shape
        without booting the vault + wg-keys chain. The contract: a
        plain-text body + Content-Disposition: attachment."""
        _login_super(client)
        n = _make_node(name="chr-dl-ok")
        _make_active_job(n)
        # Stub the shared render helper to bypass bindings_check.
        from fleet.registry import routes_onboarding as ro
        def _fake_render(job):
            return {
                "job": job,
                "script": "# pretend RouterOS script\n/system identity set name=ok\n",
                "bindings": {},
                "node_name": "chr-dl-ok",
                "filename": "chr-dl-ok.rsc",
            }
        monkeypatch.setattr(ro, "_render_job_to_response_payload", _fake_render)
        r = client.get(URL_TPL.format(id=n.id))
        assert r.status_code == 200, r.data[:200]
        assert r.mimetype == "text/plain"
        # Content-Disposition forces a Save-As dialog with the right name.
        disp = r.headers.get("Content-Disposition", "")
        assert "attachment" in disp
        assert 'filename="chr-dl-ok.rsc"' in disp
        # Cache-Control prevents proxies caching plaintext keys.
        assert "no-store" in r.headers.get("Cache-Control", "")
        # The body is the rendered script verbatim.
        body = r.get_data(as_text=True)
        assert "/system identity set name=ok" in body

    def test_route_writes_audit_row(self, app, client, monkeypatch):
        """Distinct audit action so the download flow is greppable in
        /admin/audit (separate from the JSON view action)."""
        _login_super(client)
        n = _make_node(name="chr-dl-audit")
        _make_active_job(n)
        from fleet.registry import routes_onboarding as ro
        monkeypatch.setattr(
            ro, "_render_job_to_response_payload",
            lambda job: {
                "job": job, "script": "ok", "bindings": {},
                "node_name": n.name, "filename": f"{n.name}.rsc",
            },
        )
        client.get(URL_TPL.format(id=n.id))
        from app.models import AuditLog
        rows = AuditLog.query.filter_by(
            action="fleet_node_script_download"
        ).all()
        assert any(r.entity_id == str(n.id) for r in rows), (
            "direct-download must write a distinct fleet_node_script_download "
            "audit row (vs fleet_node_script_view) so the path is auditable"
        )


# ════════════════════════════════════════════════════════════════════════
# (2) Dashboard renders the direct-download anchor on every node card
# ════════════════════════════════════════════════════════════════════════
class TestDirectDownloadAnchor:

    def test_anchor_renders_on_active_node_card(self, app, client):
        _login_super(client)
        n = _make_node(name="chr-anchor-1")
        html = client.get("/admin/fleet/").get_data(as_text=True)
        assert "fd-node-download-script" in html, (
            "every node card must carry the direct-download anchor — "
            "no JS, no modal, cannot freeze the renderer"
        )
        # The href points at the new route.
        expected_href = f"/admin/fleet/onboarding/chr-nodes/{n.id}/script.rsc"
        assert expected_href in html
        # And it's a real `<a download>` (not a JS button).
        m = re.search(
            r'<a[^>]*class="[^"]*fd-node-download-script[^"]*"[^>]*>',
            html,
        )
        assert m, "download element must be an <a> tag, not a <button>"
        # The download attribute is present so the browser saves the
        # file instead of trying to render text/plain inline.
        assert "download" in m.group(0)

    def test_anchor_highlighted_when_needs_reimport(self, app, client):
        """A node with needs_reimport=True picks up the loud variant
        so the operator sees the drift call-to-action even on the
        direct-download path (without opening the modal)."""
        _login_super(client)
        n = _make_node(name="chr-anchor-stale", needs_reimport=True)
        html = client.get("/admin/fleet/").get_data(as_text=True)
        # Look for the class APPLIED on the anchor tag (not the rule
        # definition in <style>).
        m = re.search(
            r'<a[^>]*class="[^"]*fd-node-download-script[^"]*fd-rowbtn--reimport[^"]*"[^>]*>',
            html,
        )
        assert m, (
            "needs_reimport=True must paint the download anchor with "
            "the loud .fd-rowbtn--reimport variant"
        )


# ════════════════════════════════════════════════════════════════════════
# (3) Belt-and-braces — live_poll pauses on modal display directly
# ════════════════════════════════════════════════════════════════════════
class TestLivePollDomBasedPause:

    JS = Path("app/static/js/live_poll.js")

    def test_isExternalPaused_reads_modal_display(self):
        body = self.JS.read_text(encoding="utf-8")
        # The DOM-based pause must look at #fd-script-modal directly so
        # an open modal pauses the poll regardless of the flag-set
        # path. Pin the selector list.
        assert "#fd-script-modal" in body, (
            "isExternalPaused must inspect #fd-script-modal display "
            "as a belt-and-braces fallback when the window flag isn't "
            "set (which was the live failure on the owner's panel)"
        )
        # And the function reads style.display + falls back to
        # getComputedStyle.
        assert "el.style && el.style.display" in body
        assert "window.getComputedStyle" in body

    def test_schedule_short_circuits_when_paused(self):
        body = self.JS.read_text(encoding="utf-8")
        # The schedule() guard now also rejects when external-paused,
        # so a freshly-finished tick doesn't re-arm a timer behind an
        # open modal.
        m = re.search(
            r"schedule\(ms\)\s*\{[^}]*if\s*\(\s*isExternalPaused\(\)\s*\)",
            body, re.DOTALL,
        )
        assert m, (
            "schedule() must respect isExternalPaused() so the timer "
            "isn't re-armed underneath an open modal"
        )


# ════════════════════════════════════════════════════════════════════════
# (4) Modal body switched from <pre> to <textarea readonly>
# ════════════════════════════════════════════════════════════════════════
class TestModalBodyIsTextarea:

    HTML = Path("app/templates/admin/fleet/dashboard.html")

    def test_modal_body_is_textarea(self):
        body = self.HTML.read_text(encoding="utf-8")
        # The element with id fd-sm-script is now a <textarea>.
        m = re.search(
            r'<textarea[^>]*id="fd-sm-script"[^>]*>',
            body,
        )
        assert m, (
            "modal body must be a <textarea readonly> — the previous "
            "<pre> caused a layout-per-line storm on 900-line scripts "
            "that froze the renderer"
        )
        tag = m.group(0)
        assert "readonly" in tag, (
            "textarea must be readonly so the operator can't accidentally "
            "edit the script in-place"
        )
        # wrap=off so a long line doesn't soft-wrap (the script's
        # comment lines run long).
        assert 'wrap="off"' in tag

    def test_modal_body_is_not_pre(self):
        body = self.HTML.read_text(encoding="utf-8")
        # The old <pre id="fd-sm-script"> must be gone.
        assert re.search(r'<pre[^>]*id="fd-sm-script"', body) is None, (
            "old <pre id=fd-sm-script> still present — the layout "
            "storm regression is back"
        )

    def test_js_writes_via_value_not_textContent(self):
        body = Path("app/static/js/admin_fleet_script_view.js").read_text(encoding="utf-8")
        # The setScriptText helper writes to .value first (textarea
        # path); .textContent is the legacy fallback.
        assert "function setScriptText(value)" in body
        assert '"value" in scriptEl' in body
        # And the live writes go through setScriptText, not
        # scriptEl.textContent directly.
        assert "scriptEl.textContent = currentScript" not in body, (
            "live writes must go through setScriptText(currentScript) "
            "so a textarea sees .value (not .textContent)"
        )

    def test_copy_fallback_uses_select_on_textarea(self):
        body = Path("app/static/js/admin_fleet_script_view.js").read_text(encoding="utf-8")
        # The execCommand-copy fallback prefers the textarea's native
        # .select() over the Range/Selection dance (faster + iOS-safe).
        assert "scriptEl.select()" in body, (
            "copy fallback must use scriptEl.select() — the Range/"
            "Selection path is the slower legacy fallback"
        )
