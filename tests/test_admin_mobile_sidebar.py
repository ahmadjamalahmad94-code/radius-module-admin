"""Admin panel mobile sidebar/drawer — regression guard (no browser in CI).

The bug: on a phone, tapping the burger showed only the dimmed backdrop; the
drawer never slid in. Root cause was CSS specificity — the closed dir-rule
``html[dir="rtl"] .adm-side`` (0,0,2,1) out-specified the open rule
``.adm-side.is-drawer-open`` (0,0,2,0), so adding ``is-drawer-open`` never
overrode the parked ``translateX(100%)``. These tests assert the fix shape so it
can't silently regress.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CSS = (ROOT / "app" / "static" / "css" / "admin_base.css").read_text(encoding="utf-8")
BASE = (ROOT / "app" / "templates" / "admin" / "base_new.html").read_text(encoding="utf-8")


def _mobile_block() -> str:
    """The `@media (max-width: 900px)` block text."""
    i = CSS.find("@media (max-width: 900px)")
    assert i != -1, "mobile breakpoint missing"
    # capture to the next top-level @media (good enough for substring checks)
    j = CSS.find("@media", i + 10)
    return CSS[i: j if j != -1 else len(CSS)]


def test_open_rule_outspecifies_closed_dir_rule():
    block = _mobile_block()
    # The open rule MUST be dir-qualified so it out-specifies the closed dir-rule.
    assert 'html[dir="rtl"] .adm-side.is-drawer-open' in block
    assert 'html:not([dir="rtl"]) .adm-side.is-drawer-open' in block


def test_open_rule_slides_in():
    block = _mobile_block()
    # the open selectors set translateX(0) (slide in)
    m = re.search(r"\.adm-side\.is-drawer-open[^{]*\{\s*transform:\s*translateX\(0\)", block)
    assert m, "open drawer must transform: translateX(0)"


def test_no_dir_closed_rule_without_matching_open_rule():
    """Regression guard for the exact bug: a dir-qualified CLOSED rule may exist
    only if the dir-qualified OPEN rule also exists (so open still wins)."""
    block = _mobile_block()
    if 'html[dir="rtl"] .adm-side {' in block or 'html[dir="rtl"] .adm-side{' in block:
        assert 'html[dir="rtl"] .adm-side.is-drawer-open' in block


def test_drawer_above_overlay():
    # drawer z-index (50) must sit ABOVE the backdrop overlay (39).
    assert ".adm-side-overlay" in CSS
    assert re.search(r"\.adm-side-overlay\s*\{[^}]*z-index:\s*39", CSS)
    assert "z-index: 50;" in _mobile_block()  # the drawer in the mobile block


def test_menu_button_is_44px_tap_target():
    block = _mobile_block()
    m = re.search(r"\.adm-menu-btn\s*\{[^}]*44px", block)
    assert m, "burger must be a >=44px tap target on mobile"


# ── template wiring (burger → drawer + dismissible backdrop) ──────────────────
def test_template_has_drawer_scaffolding():
    assert 'id="adm-menu-btn"' in BASE       # burger
    assert 'id="adm-side"' in BASE           # drawer
    assert 'id="adm-overlay"' in BASE        # backdrop


def test_template_js_toggles_drawer_and_overlay():
    # burger toggles the drawer class + the overlay; backdrop click closes both.
    assert "is-drawer-open" in BASE
    assert "is-visible" in BASE
    assert "overlay.addEventListener('click'" in BASE
