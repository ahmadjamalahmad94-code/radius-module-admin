"""Tests for external-URL app releases (downloads that link off-site).

Covers: create_url_release + validation, the public landing rendering an
external link (target=_blank rel=noopener), the /downloads/<id> redirect for
URL releases, the admin add-by-URL route, idempotent seeding of the two shipped
apps, and that the file-upload path still works unchanged.
"""
from __future__ import annotations

import io

import pytest

from app.extensions import db
from app.models import Admin, AppProduct, AppRelease
from app.services import app_releases as ar


def _login(client):
    admin = Admin.query.first()
    with client.session_transaction() as sess:
        sess["admin_id"] = admin.id
    return admin


def _product(name="Ext App", slug="ext-app", visible=True):
    p = ar.upsert_product(product=None, name=name, slug=slug, icon_name="cube",
                          is_visible=visible)
    db.session.commit()
    return p


# ── service: create_url_release + validation ────────────────────────────────
def test_create_url_release_sets_external_fields(app):
    with app.app_context():
        p = _product()
        rel = ar.create_url_release(
            product=p, platform="android", channel="stable", version="v1.0",
            download_url="https://github.com/org/repo/releases/download/v1.0/app.apk",
            sha256="ABC123")
        db.session.commit()
        assert rel.is_external is True
        assert rel.download_url.endswith("/app.apk")
        assert rel.stored_filename == "" and rel.size_bytes == 0
        assert rel.is_current is True
        assert rel.file_ext == ".apk"          # derived for display
        assert rel.sha256 == "abc123"          # lowercased


def test_create_url_release_rejects_bad_url(app):
    with app.app_context():
        p = _product()
        for bad in ("", "ftp://x/y.apk", "javascript:alert(1)", "/local/path.apk"):
            with pytest.raises(ar.AppReleaseError):
                ar.create_url_release(product=p, platform="android", channel="stable",
                                      version="v1", download_url=bad)


# ── public landing renders the external link ─────────────────────────────────
def test_public_downloads_renders_external_link(app, client):
    with app.app_context():
        p = _product(name="Linky", slug="linky")
        ar.create_url_release(
            product=p, platform="android", channel="stable", version="v2.3",
            download_url="https://ext.example.com/dl/linky.apk")
        db.session.commit()
    html = client.get("/").get_data(as_text=True)
    assert "Linky" in html
    assert "https://ext.example.com/dl/linky.apk" in html
    assert 'target="_blank"' in html and "noopener" in html
    assert "v2.3" in html


def test_download_route_redirects_for_url_release(app, client):
    with app.app_context():
        p = _product(name="Redir", slug="redir")
        rel = ar.create_url_release(
            product=p, platform="android", channel="stable", version="v1",
            download_url="https://ext.example.com/r.apk")
        db.session.commit()
        rid = rel.id
    r = client.get(f"/downloads/{rid}", follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["Location"] == "https://ext.example.com/r.apk"


# ── admin add-by-URL ─────────────────────────────────────────────────────────
def test_admin_add_url_release(app, client):
    _login(client)
    with app.app_context():
        p = _product(name="AdminURL", slug="adminurl")
        pid = p.id
    r = client.post(f"/admin/landing/apps/{pid}/add-url", data={
        "platform": "android", "channel": "stable", "version": "v9.9",
        "download_url": "https://ext.example.com/admin.apk", "set_current": "on",
    }, follow_redirects=True)
    assert r.status_code == 200
    with app.app_context():
        rel = AppRelease.query.filter_by(product_id=pid).first()
        assert rel is not None and rel.is_external is True
        assert rel.download_url == "https://ext.example.com/admin.apk"
        assert rel.is_current is True


def test_admin_add_url_rejects_bad_url(app, client):
    _login(client)
    with app.app_context():
        p = _product(name="BadURL", slug="badurl")
        pid = p.id
    client.post(f"/admin/landing/apps/{pid}/add-url", data={
        "platform": "android", "channel": "stable", "version": "v1",
        "download_url": "notaurl",
    }, follow_redirects=True)
    with app.app_context():
        assert AppRelease.query.filter_by(product_id=pid).count() == 0


# ── seed of the two shipped apps is idempotent ───────────────────────────────
def test_seed_download_apps_idempotent(app):
    with app.app_context():
        # seed_defaults already ran it once (fixture). Run twice more.
        ar.seed_download_apps()
        ar.seed_download_apps()
        radius = AppProduct.query.filter_by(slug="radius_app").first()
        card = AppProduct.query.filter_by(slug="card_print_app").first()
        assert radius is not None and card is not None
        # Exactly one release per seeded app (no duplicates across re-runs).
        assert radius.releases.count() == 1
        assert card.releases.count() == 1
        rrel = radius.releases.first()
        assert rrel.is_external and rrel.is_current and rrel.platform == "android"
        assert rrel.version == "v0.1.0-test"
        assert rrel.sha256 == "f44a34ac2de99b953aececd64bd6c0247010a1e4ac7808a60d83d879c85c343f"
        assert "radius-app.apk" in rrel.download_url
        assert "app-release.apk" in card.releases.first().download_url


def test_seeded_apps_render_on_landing(client):
    html = client.get("/").get_data(as_text=True)
    assert "تطبيق الريدياس" in html
    assert "تطبيق طباعة الكروت" in html
    assert "radius-app.apk" in html and "app-release.apk" in html


# ── regression: the file-upload path still works (hosted, not external) ──────
def test_file_upload_release_still_served_as_attachment(app, client):
    _login(client)
    with app.app_context():
        p = _product(name="Hosted", slug="hosted")
        pid = p.id
    blob = b"MZ hosted installer"
    client.post(f"/admin/landing/apps/{pid}/upload", data={
        "platform": "windows", "channel": "stable", "version": "1.0.0",
        "set_current": "on", "binary": (io.BytesIO(blob), "setup.exe"),
    }, content_type="multipart/form-data", follow_redirects=True)
    with app.app_context():
        rel = AppRelease.query.filter_by(product_id=pid).first()
        assert rel is not None and rel.is_external is False  # hosted, not external
        assert rel.stored_filename and rel.download_url == ""
        rid = rel.id
    dr = client.get(f"/downloads/{rid}")
    assert dr.status_code == 200 and dr.data == blob
    assert "attachment" in dr.headers.get("Content-Disposition", "").lower()
