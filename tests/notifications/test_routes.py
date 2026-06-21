"""Notification-center routes + bell unread-count API."""
from __future__ import annotations

from app.extensions import db
from app.notifications import service

from .conftest import seed_customer


def test_center_requires_login(client):
    r = client.get("/admin/notifications/")
    assert r.status_code in (301, 302)
    assert "login" in (r.headers.get("Location") or "")


def test_center_renders_for_admin(auth_client):
    service.create(type="license_expiry", title="عنوان الإشعار",
                   body="جسم الإشعار", severity="warning", emit=False)
    db.session.commit()
    r = auth_client.get("/admin/notifications/")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "مركز الإشعارات" in body
    assert "عنوان الإشعار" in body


def test_unread_count_api(auth_client):
    service.create(type="t", title="a", dedupe_key="a", emit=False)
    service.create(type="t", title="b", dedupe_key="b", emit=False)
    db.session.commit()
    r = auth_client.get("/admin/notifications/unread-count")
    assert r.status_code == 200
    data = r.get_json()
    assert data["ok"] is True and data["count"] == 2


def test_mark_read_via_xhr(auth_client):
    note = service.create(type="t", title="a", dedupe_key="a", emit=False)
    db.session.commit()
    r = auth_client.post(f"/admin/notifications/{note.id}/read",
                         headers={"X-Requested-With": "XMLHttpRequest"})
    assert r.status_code == 200
    data = r.get_json()
    assert data["ok"] is True and data["unread_count"] == 0


def test_mark_all_read(auth_client):
    for i in range(3):
        service.create(type="t", title=f"n{i}", dedupe_key=f"d{i}", emit=False)
    db.session.commit()
    r = auth_client.post("/admin/notifications/read-all",
                         headers={"X-Requested-With": "XMLHttpRequest"})
    assert r.status_code == 200
    assert r.get_json()["unread_count"] == 0


def test_center_unread_filter(auth_client):
    a = service.create(type="t", title="STILLNEW", dedupe_key="a", emit=False)
    b = service.create(type="t", title="ALREADYSEEN", dedupe_key="b", emit=False)
    db.session.commit()
    service.mark_read(b.id)
    db.session.commit()
    r = auth_client.get("/admin/notifications/?unread=1")
    body = r.get_data(as_text=True)
    assert "STILLNEW" in body
    assert "ALREADYSEEN" not in body
