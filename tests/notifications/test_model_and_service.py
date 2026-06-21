"""Notification model CRUD + read-state + idempotent dedupe."""
from __future__ import annotations

from app.extensions import db
from app.notifications import service
from app.notifications.models import Notification

from .conftest import seed_customer


def test_create_owner_notification_and_read_state(app):
    note = service.create(type="license_expiry", title="عنوان", body="نص",
                          severity="warning", emit=False)
    db.session.commit()
    assert note.id is not None
    assert note.is_read is False
    assert note.severity == "warning"
    assert note.channels == ["web"]  # owner default

    assert service.unread_count() == 1
    assert service.mark_read(note.id) is True
    db.session.commit()
    assert note.is_read is True
    assert service.unread_count() == 0


def test_dedupe_is_idempotent(app):
    a = service.create(type="t", title="x", dedupe_key="k1", emit=False)
    db.session.commit()
    b = service.create(type="t", title="y", dedupe_key="k1", emit=False)
    db.session.commit()
    assert a.id == b.id  # same row returned
    assert Notification.query.filter_by(dedupe_key="k1").count() == 1
    assert b.title == "x"  # not overwritten


def test_channels_json_roundtrip(app):
    note = service.create(type="t", title="x", channels=["web", "panel", "telegram"],
                          emit=False)
    db.session.commit()
    fresh = db.session.get(Notification, note.id)
    assert fresh.channels == ["web", "panel", "telegram"]
    assert fresh.to_dict()["channels"] == ["web", "panel", "telegram"]


def test_mark_all_read(app):
    for i in range(3):
        service.create(type="t", title=f"n{i}", dedupe_key=f"d{i}", emit=False)
    db.session.commit()
    assert service.unread_count() == 3
    n = service.mark_all_read()
    db.session.commit()
    assert n == 3
    assert service.unread_count() == 0


def test_recent_filters(app):
    service.create(type="invoice_new", title="a", severity="info", dedupe_key="a", emit=False)
    service.create(type="license_expiry", title="b", severity="critical", dedupe_key="b", emit=False)
    db.session.commit()
    assert len(service.recent(type="invoice_new")) == 1
    assert len(service.recent(severity="critical")) == 1
    assert len(service.recent()) == 2
