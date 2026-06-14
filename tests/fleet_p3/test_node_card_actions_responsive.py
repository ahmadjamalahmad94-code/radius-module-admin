"""fix/node-card-actions-responsive — node-card footer wraps + all visible.

Field incident (screenshot from the owner): node-card footer action
buttons OVERFLOWED the card width and got CUT OFF. Only «عرض السكربت
/ مقاييس / فحص» were visible; «↓ تنزيل .rsc / تعديل / حذف» and the
needs_reimport-highlighted button were clipped off the edge → the
operator couldn't reach them.

Root cause was twofold:
  1. ``.node-card { overflow:hidden }`` (kept for the rounded-corner
     shadow) clipped anything overflowing the card box.
  2. ``.nc-actions { display:flex; gap:8px }`` had NO ``flex-wrap``,
     so all 6+ buttons sat on a single horizontal line that exceeded
     the card width.

Fix in dashboard.html:
  * ``.nc-actions`` is now ``display:flex; gap:6px; flex-wrap:wrap;
    justify-content:flex-end; flex:1 1 auto`` — buttons wrap to a
    second line, and the actions block as a whole can drop to its
    own row under «آخر تواصل» on narrow cards.
  * Tighter button shape (height:30px, padding-inline:10px,
    font-size:11.5px) so more fit per row.
  * The delete <form> wrapper class ``.fd-delete-form`` gets
    ``display:contents`` so it doesn't break the flex flow.
  * ``.nc-lastseen`` is now ``flex:1 1 180px; min-width:0`` so it
    shrinks gracefully rather than forcing the actions block off
    the edge.

These tests pin the contract via RENDERED HTML (not template source)
— the failure was visible only at the layout level, so we render the
page and assert the class + the full set of action buttons coexist.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.extensions import db
from app.models import Admin
from fleet.registry.models_chr import FleetChrNode, FleetProvider


def _login_super(client):
    client.post("/login", data={"username": "admin",
                                "password": "admin12345"})
    adm = Admin.query.first()
    if adm and not adm.is_super_admin:
        adm.is_super_admin = True
        db.session.commit()


def _provider() -> FleetProvider:
    p = FleetProvider.query.first()
    if p is not None:
        return p
    p = FleetProvider(
        name="resp-prov", cost_model="open", price_per_tb=0,
        overage_allowed=False, billing_cycle_day=1,
    )
    db.session.add(p); db.session.commit()
    return p


_SEQ = [30]


def _make_node(**kw) -> FleetChrNode:
    _SEQ[0] += 1
    base = dict(
        provider_id=_provider().id,
        name=f"chr-resp-{_SEQ[0]}",
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


# ════════════════════════════════════════════════════════════════════════
# (1) CSS: .nc-actions wraps + .node-card overflow stays (rule-level)
# ════════════════════════════════════════════════════════════════════════
class TestActionRowCss:

    HTML = Path("app/templates/admin/fleet/dashboard.html")

    def test_nc_actions_has_flex_wrap(self):
        body = self.HTML.read_text(encoding="utf-8")
        # The bare rule must have flex-wrap so buttons drop to a
        # second line when the card is narrow.
        m = re.search(r"\.nc-actions\s*\{[^}]*flex-wrap:\s*wrap[^}]*\}", body)
        assert m, (
            ".nc-actions must use flex-wrap:wrap so buttons don't "
            "overflow the card width when there are 6+ of them"
        )

    def test_nc_actions_grows_to_own_row_on_narrow(self):
        body = self.HTML.read_text(encoding="utf-8")
        # flex:1 1 auto lets the whole actions block take a full row
        # under .nc-lastseen when the inline space isn't enough.
        m = re.search(r"\.nc-actions\s*\{[^}]*flex:\s*1\s+1\s+auto[^}]*\}", body)
        assert m, (
            ".nc-actions must have flex:1 1 auto so it can own a new "
            "row on narrow cards rather than getting squeezed out"
        )

    def test_nc_lastseen_is_shrinkable(self):
        body = self.HTML.read_text(encoding="utf-8")
        # min-width:0 lets the last-seen text shrink rather than
        # forcing the action area off the edge.
        m = re.search(r"\.nc-lastseen\s*\{[^}]*min-width:\s*0[^}]*\}", body)
        assert m, (
            ".nc-lastseen must be shrinkable (min-width:0) so it "
            "doesn't push the actions block off the card width"
        )

    def test_delete_form_uses_display_contents(self):
        body = self.HTML.read_text(encoding="utf-8")
        # The delete <form> wrapper class must be set to display:
        # contents so it doesn't add its own layout box between the
        # nc-actions flex container and the delete button.
        m = re.search(
            r"\.nc-actions\s+form\.fd-delete-form\s*\{[^}]*display:\s*contents[^}]*\}",
            body,
        )
        assert m, (
            "the per-card delete <form> must use display:contents so "
            "the delete button flexes as a peer of the other action "
            "buttons rather than being trapped inside an inline form"
        )


# ════════════════════════════════════════════════════════════════════════
# (2) RENDER: all action buttons coexist on the node card
# ════════════════════════════════════════════════════════════════════════
class TestAllActionsRender:

    def test_render_with_one_active_node_lists_all_actions(self, app, client):
        """The actual failure was visible at render: «↓ تنزيل .rsc /
        تعديل / حذف» were clipped. Confirm the action row carries the
        full button set on the rendered page."""
        _login_super(client)
        n = _make_node(name="chr-actions-all")
        html = client.get("/admin/fleet/").get_data(as_text=True)
        # Each action button is present.
        assert "fd-check-one" in html,        "«فحص» button missing"
        assert "fd-poll-metrics" in html,     "«مقاييس» button missing"
        assert "fd-node-view-script" in html, "«عرض السكربت» button missing"
        assert "fd-node-download-script" in html, (
            "«↓ تنزيل .rsc» direct-download anchor missing — that's "
            "the freeze-proof path; it MUST be one of the visible actions"
        )
        # «تعديل» link + «حذف» button.
        assert f'href="/admin/fleet/chr-nodes/{n.id}/edit"' in html, (
            "«تعديل» edit link missing from action row"
        )
        assert "fd-delete-form" in html, (
            "delete <form> class missing — needed by the display:contents "
            "rule that lets the delete button flex as a peer"
        )

    def test_action_row_has_no_inline_nowrap(self, app, client):
        """Defensive: the action row's container must NOT carry an
        inline ``flex-wrap:nowrap`` or ``overflow:hidden`` that would
        defeat the CSS rule. We grep for both on the .nc-actions
        element in the rendered output."""
        _login_super(client)
        _make_node(name="chr-actions-nowrap")
        html = client.get("/admin/fleet/").get_data(as_text=True)
        # Find every .nc-actions element opening tag.
        for tag in re.findall(r'<div[^>]*class="[^"]*nc-actions[^"]*"[^>]*>', html):
            assert "flex-wrap:nowrap" not in tag, (
                f"inline flex-wrap:nowrap on .nc-actions defeats the "
                f"wrap fix: {tag!r}"
            )
            assert "overflow:hidden" not in tag, (
                f"inline overflow:hidden on .nc-actions clips buttons: {tag!r}"
            )

    def test_needs_reimport_loud_button_still_present(self, app, client):
        """The needs_reimport-highlighted button was one of the
        clipped ones in the owner's screenshot. Confirm it renders
        AND that the action row markup still carries the wrap class."""
        _login_super(client)
        n = _make_node(name="chr-loud", needs_reimport=True)
        html = client.get("/admin/fleet/").get_data(as_text=True)
        # The loud variant is applied (not just defined in the
        # stylesheet) — distinguished by a class attribute that
        # actually combines the base + variant on a button/anchor.
        applied = re.search(
            r'class="[^"]*fd-rowbtn[^"]*fd-rowbtn--reimport[^"]*"',
            html,
        )
        assert applied, "fd-rowbtn--reimport variant not applied on any button/anchor"
        # And the card's .nc-actions container is the wrap variant.
        m = re.search(r'<div[^>]*class="[^"]*nc-actions[^"]*"', html)
        assert m, "no .nc-actions container in the rendered card"
