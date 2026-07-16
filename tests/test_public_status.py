"""صفحة الحالة العامّة — آمنة للخصوصية ومتاحة بلا تسجيل دخول."""
from __future__ import annotations

from app.services import public_status as ps


def test_aggregate_logic():
    assert ps._aggregate_from_counts(0, 0, 0, 0) == ps.UNKNOWN
    assert ps._aggregate_from_counts(4, 0, 0, 4) == ps.OK
    assert ps._aggregate_from_counts(3, 1, 0, 4) == ps.DEGRADED
    assert ps._aggregate_from_counts(0, 0, 4, 4) == ps.DOWN


def test_summary_never_raises_without_fleet(app):
    with app.app_context():
        s = ps.status_summary()
    assert s["overall"] in (ps.OK, ps.DEGRADED, ps.DOWN, ps.UNKNOWN)
    assert any(c["key"] == "panel" for c in s["components"])


def test_status_page_public_no_login(client):
    r = client.get("/status")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "حالة الخدمة" in body


def test_status_json_public(client):
    r = client.get("/status.json")
    assert r.status_code == 200
    data = r.get_json()
    assert "overall" in data and "components" in data


def test_status_leaks_no_internal_data(client):
    """لا أسماء عُقد ولا IP في الصفحة العامّة."""
    body = client.get("/status").get_data(as_text=True)
    # لا يظهر أي IP رباعي
    import re
    assert not re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", body)
