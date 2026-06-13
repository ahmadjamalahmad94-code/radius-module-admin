"""fix/chr-script-remove-break — the rendered RouterOS script must
contain ZERO ``:break`` and ZERO ``:continue`` statements on any
EXECUTABLE line. Comments (lines starting with ``#``) are inert and
ignored by the RouterOS importer; the words may legitimately appear
in commentary documenting why we avoid them.

Live incident (chr-vpn-3):
    Script Error: bad command name break (line 469 column 28)

Root cause: ``:break`` inside a nested ``:if do={}`` block is
rejected by RouterOS («bad command name break»). The construct is
unreliable across v7 builds and we deliberately avoid it. The
cert-poll-wait loop was rewritten as a flag-gated pattern that
runs all 15 iterations but skips work + the delay once the cert is
ready.
"""
from __future__ import annotations

import pytest

from app.extensions import db
from fleet.registry.models_chr import FleetProvider
from fleet.registry.onboarding_service import OnboardingService


_BASE_CFG = {
    "PANEL_WG_PUBKEY": "PANEL_PUBKEY_BASE64_xxxxxxxxxxxxxxxxxxxxxxxx=",
    "PANEL_WG_ENDPOINT": "panel.example.com:51820",
    "PROXY_WG_PUBKEY": "PROXY_PUBKEY_BASE64_xxxxxxxxxxxxxxxxxxxxxxxx=",
    "PROXY_WG_ENDPOINT": "proxy.example.com:51821",
    "CHR_SHARED_SECRET": "central-shared-secret-from-panel-xxxxxxxx",
}


def _form() -> dict:
    return dict(
        name="chr-vpn-3", provider="contabo-de", cost_model="open",
        public_ip="1.1.1.3", max_sessions=500, link_speed_mbps=1000,
        router_username="admin", router_password="admin12345",
    )


@pytest.fixture()
def provider_app(app):
    p = FleetProvider(name="contabo-de", cost_model="open", price_per_tb=0)
    db.session.add(p); db.session.commit()
    return app


def _render(provider_app) -> str:
    svc = OnboardingService(config=dict(_BASE_CFG))
    job = svc.create_draft(_form(), auto_advance=False)
    svc.generate_keys(job)
    _, script = svc.render_script(job)
    return script


def _executable_lines(script: str) -> list[tuple[int, str]]:
    """Return ``(line_no, line)`` pairs for every NON-comment line.
    A line is treated as a comment when its first non-whitespace
    character is ``#`` (matching RouterOS comment syntax)."""
    out: list[tuple[int, str]] = []
    for i, ln in enumerate(script.splitlines(), start=1):
        if ln.lstrip().startswith("#"):
            continue
        out.append((i, ln))
    return out


class TestNoBreakOrContinue:

    def test_no_break_on_executable_line(self, provider_app):
        offenders = [
            (n, l) for n, l in _executable_lines(_render(provider_app))
            if ":break" in l
        ]
        assert not offenders, (
            "RouterOS rejects `:break` inside nested :if do={} blocks "
            "(«bad command name break»). The cert-poll-wait loop uses a "
            "flag-gated pattern instead. Offending lines:\n  "
            + "\n  ".join(f"L{n}: {l!r}" for n, l in offenders)
        )

    def test_no_continue_on_executable_line(self, provider_app):
        offenders = [
            (n, l) for n, l in _executable_lines(_render(provider_app))
            if ":continue" in l
        ]
        assert not offenders, (
            "`:continue` has the same v7 reliability issues as `:break`; "
            "use a flag-gated pattern. Offending lines:\n  "
            + "\n  ".join(f"L{n}: {l!r}" for n, l in offenders)
        )

    def test_loop_uses_flag_gated_pattern(self, provider_app):
        """The new cert-poll-wait shape: a counter loop where every
        iteration's body is gated on ``!$certReady`` so it spins to
        completion without `:break`. Asserting the structural tokens
        catches a regression where someone re-introduces `:break`."""
        script = _render(provider_app)
        # Counter loop still bounded at 15 iterations.
        assert ":for i from=1 to=15 do={" in script
        # Body gated on the flag — this is the no-break idiom.
        assert ":if (!$certReady) do={" in script
        # The success flag is what the timeout :log error checks too.
        assert ":local certReady false" in script
        assert ":if ($certReady = false) do={" in script
        # And the loop's outer body still contains the delay (just now
        # inside a second flag-gate so it skips once ready).
        assert ":delay 1s" in script

    def test_poll_wait_still_precedes_set_www_ssl(self, provider_app):
        """The whole point of the loop is to land BEFORE www-ssl is
        configured. Defence-in-depth: re-confirm after the rewrite."""
        script = _render(provider_app)
        poll_idx = script.index(":local certReady false")
        www_idx = script.index("set www-ssl disabled=no")
        assert poll_idx < www_idx

    def test_timeout_logs_error(self, provider_app):
        """If the cert never readies, we still get the log line so the
        operator can see WHY www-ssl is down on re-import."""
        script = _render(provider_app)
        assert "hobe-fleet-api-cert not ready after 15s" in script
