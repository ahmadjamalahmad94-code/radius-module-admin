"""Admin mobile horizontal-overflow guard (Customer 360 + panel-wide).

Bug: on a ~360px phone the Customer-360 page was shifted right with dead space
on the left and content clipped off the right. Root cause: the off-canvas
sidebar (`position:fixed; transform:translateX(±100%)`) extends the document
width with no root overflow clip, and the detail grids used `minmax(280px,1fr)`
tracks wider than a phone content column. These tests pin the fix shape.
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CSS = (ROOT / "app" / "static" / "css" / "admin_base.css").read_text(encoding="utf-8")
DETAIL = (ROOT / "app" / "templates" / "admin" / "customers" / "detail_new.html").read_text(encoding="utf-8")


def _mobile_block() -> str:
    i = CSS.find("@media (max-width: 900px)")
    assert i != -1
    j = CSS.find("@media", i + 10)
    return CSS[i: j if j != -1 else len(CSS)]


def test_root_overflow_guard_in_mobile_block():
    block = _mobile_block()
    assert "html, body { overflow-x: hidden" in block        # clip the parked drawer
    assert ".adm-shell, .adm-main, .adm-page" in block        # shrink, don't force width
    assert "min-width: 0" in block


def test_admin_base_css_braces_balanced():
    assert CSS.count("{") == CSS.count("}")


def test_customer360_grids_stack_on_phone():
    # the 280/220px minmax tracks collapse to one column ≤640px
    assert "@media (max-width: 640px)" in DETAIL
    assert ".cd-grid, .cd-grid-3 { grid-template-columns: 1fr; }" in DETAIL
    # KPI strip: 2-up on phone, 1-up on very small
    assert "repeat(2, minmax(0, 1fr))" in DETAIL
    assert "@media (max-width: 420px)" in DETAIL


def test_customer360_renders(app, client):
    from app.extensions import db
    from app.models import Admin, Customer
    with app.app_context():
        c = Customer.query.first()
        if c is None:
            c = Customer(company_name="شركتي", email="s360@x.com", status="active")
            db.session.add(c)
            db.session.commit()
        cid = c.id
        aid = Admin.query.first().id
    with client.session_transaction() as s:
        s["admin_id"] = aid
    r = client.get(f"/admin/customers/{cid}", follow_redirects=True)
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "admin_base.css" in body
    assert "max-width: 640px" in body          # the page's own stacking media query
