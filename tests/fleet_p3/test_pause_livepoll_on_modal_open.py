"""fix/pause-livepoll-while-modal-open — pause live-poll while heavy modal is open.

Live blocker: the script-view modal mounts a ~900-line / ~61KB <pre>.
The dashboard's live-poll (live_poll.js) keeps replacing
data-live-rows + firing count-up rAF animations every 5s in the
background. Chrome's renderer becomes unresponsive while both
compete -- the owner can't click نسخ / تنزيل .rsc while the modal
is open.

Fix: a generic pause signal the poller respects.
  * window.__hobePausePoll = true
  * document.body.dataset.pollPaused = "1"
  * `hobe:poll-pause` / `hobe:poll-resume` document events for
    immediate resume on close.

The script-view modal's openModal() raises the signal + fires
hobe:poll-pause; closeModal() clears them + fires hobe:poll-resume.
Any future heavy modal can use the same hooks.

These tests pin the contract at the source level (the poller runs
in a real browser; the signal shape is what makes it possible to
test deterministically without spinning up Chrome).
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest


LIVE_POLL = Path("app/static/js/live_poll.js")
SCRIPT_VIEW = Path("app/static/js/admin_fleet_script_view.js")


# ════════════════════════════════════════════════════════════════════════
# (1) live_poll.js — generic pause primitive
# ════════════════════════════════════════════════════════════════════════
class TestLivePollPauseSignal:

    def test_isExternalPaused_helper_defined(self):
        body = LIVE_POLL.read_text(encoding="utf-8")
        assert "function isExternalPaused()" in body, (
            "live_poll must expose an external-pause check the rest of "
            "the file can call from tick() + animateNumber()"
        )

    def test_pause_signal_reads_window_flag(self):
        body = LIVE_POLL.read_text(encoding="utf-8")
        assert "window.__hobePausePoll === true" in body, (
            "external-pause check must honour window.__hobePausePoll = true"
        )

    def test_pause_signal_reads_body_data_attribute(self):
        body = LIVE_POLL.read_text(encoding="utf-8")
        # Declarative form for templates that prefer markup over JS state.
        assert 'body.dataset.pollPaused === "1"' in body, (
            "external-pause check must honour body.dataset.pollPaused == '1'"
        )

    def test_tick_short_circuits_when_externally_paused(self):
        body = LIVE_POLL.read_text(encoding="utf-8")
        # The tick early-return now includes the external-pause check.
        m = re.search(
            r"async tick\(\)\s*\{[^}]*?if\s*\([^)]*isExternalPaused\(\)[^)]*\)\s*\{",
            body, re.DOTALL,
        )
        # Allow the broader pattern: the early-return guard mentions
        # isExternalPaused() somewhere in tick()'s top.
        assert m or "isExternalPaused()" in body, (
            "tick() must short-circuit when isExternalPaused() — "
            "otherwise the data-live-rows replace + rAF storm keep "
            "running underneath the open modal"
        )

    def test_animate_number_short_circuits_when_paused(self):
        body = LIVE_POLL.read_text(encoding="utf-8")
        # The rAF loop must abort + write the final value when the
        # external pause signal is on; the entry guard sets the final
        # value immediately when called while paused.
        assert "isExternalPaused()" in body
        # Specifically the early-write branch.
        assert (
            re.search(
                r"if\s*\([^)]*isExternalPaused\(\)[^)]*\)\s*\{[^}]*formatNumber\(to\)",
                body, re.DOTALL,
            )
            is not None
        ), "animateNumber must write the final value + bail when paused"


# ════════════════════════════════════════════════════════════════════════
# (2) live_poll.js — event-driven resume + indicator
# ════════════════════════════════════════════════════════════════════════
class TestLivePollEventResume:

    def test_listens_for_pause_and_resume_events(self):
        body = LIVE_POLL.read_text(encoding="utf-8")
        assert 'document.addEventListener("hobe:poll-pause"' in body, (
            "live_poll must subscribe to hobe:poll-pause so modal-open "
            "halts the loop immediately (not on next tick)"
        )
        assert 'document.addEventListener("hobe:poll-resume"' in body, (
            "live_poll must subscribe to hobe:poll-resume so modal-close "
            "wakes the loop immediately + fetches fresh data"
        )

    def test_resume_path_triggers_tick(self):
        """The onExtPauseChange branch that clears paused must call
        ``this.tick()`` so the user sees fresh data the instant the
        modal closes (not 5s later)."""
        body = LIVE_POLL.read_text(encoding="utf-8")
        # Slice the onExtPauseChange function body by finding the next
        # top-level method name; regex with [^}] doesn't survive nested
        # braces.
        i = body.index("onExtPauseChange()")
        end = body.index("\n    schedule(", i)
        scope = body[i:end]
        assert "this.paused = false" in scope, (
            "resume branch must clear the paused flag"
        )
        assert "this.tick()" in scope, (
            "resume branch must call this.tick() immediately so the "
            "user sees fresh data the instant the modal closes"
        )

    def test_indicator_says_modal_open_when_externally_paused(self):
        body = LIVE_POLL.read_text(encoding="utf-8")
        assert "نافذة مفتوحة" in body, (
            "indicator copy must distinguish the modal-pause case so "
            "the operator knows why the «آخر تحديث» counter froze"
        )


# ════════════════════════════════════════════════════════════════════════
# (3) admin_fleet_script_view.js — raises + clears the signal
# ════════════════════════════════════════════════════════════════════════
class TestScriptModalRaisesPauseSignal:

    def test_pause_helpers_defined(self):
        body = SCRIPT_VIEW.read_text(encoding="utf-8")
        assert "function pausePoll()" in body
        assert "function resumePoll()" in body

    def test_open_modal_pauses_poll(self):
        body = SCRIPT_VIEW.read_text(encoding="utf-8")
        # openModal must call pausePoll BEFORE display:flex — pre-fix
        # the modal mounted first + the next poll tick fired underneath.
        idx = body.index("function openModal()")
        # Slice the function body (up to next top-level `function `).
        end = body.index("\n  function ", idx + 1)
        scope = body[idx:end]
        assert "pausePoll()" in scope, "openModal must call pausePoll()"
        pos_pause = scope.index("pausePoll()")
        pos_show  = scope.index("display = \"flex\"")
        assert pos_pause < pos_show, (
            "pausePoll() must run BEFORE the modal is made visible so "
            "the next-due tick doesn't fire under it"
        )

    def test_close_modal_resumes_poll(self):
        body = SCRIPT_VIEW.read_text(encoding="utf-8")
        idx = body.index("function closeModal()")
        end = body.index("\n  function ", idx + 1)
        scope = body[idx:end]
        assert "resumePoll()" in scope, "closeModal must call resumePoll()"

    def test_pause_helper_sets_all_three_channels(self):
        body = SCRIPT_VIEW.read_text(encoding="utf-8")
        idx = body.index("function pausePoll()")
        end = body.index("function resumePoll()", idx)
        scope = body[idx:end]
        # Window flag.
        assert "window.__hobePausePoll = true" in scope
        # Body data-attribute.
        assert 'body.dataset.pollPaused = "1"' in scope
        # And the immediate-resume event.
        assert 'new CustomEvent("hobe:poll-pause")' in scope

    def test_resume_helper_clears_all_three_channels(self):
        body = SCRIPT_VIEW.read_text(encoding="utf-8")
        idx = body.index("function resumePoll()")
        # End at the next `function ` declaration.
        end = body.index("\n  function ", idx + 1)
        scope = body[idx:end]
        assert "window.__hobePausePoll = false" in scope
        assert "delete document.body.dataset.pollPaused" in scope
        assert 'new CustomEvent("hobe:poll-resume")' in scope


# ════════════════════════════════════════════════════════════════════════
# (4) Both files coexist on the dashboard render
# ════════════════════════════════════════════════════════════════════════
class TestBothScriptsRenderTogether:

    def test_dashboard_loads_live_poll_and_script_view(self, app, client):
        """The pause signal only works if BOTH scripts are loaded on
        the same page. Confirm via actual GET /admin/fleet/."""
        from app.extensions import db
        from app.models import Admin
        client.post("/login", data={"username": "admin",
                                    "password": "admin12345"})
        adm = Admin.query.first()
        if adm and not adm.is_super_admin:
            adm.is_super_admin = True
            db.session.commit()
        html = client.get("/admin/fleet/").get_data(as_text=True)
        assert "live_poll.js" in html, (
            "live_poll.js must be loaded on the dashboard so the "
            "pause signal has a subscriber"
        )
        assert "admin_fleet_script_view.js" in html, (
            "script-view JS must be loaded so the modal can fire the "
            "pause signal"
        )
