"""Tests for product apps + the public landing Downloads / Card-Print sections.

Covers: the app_releases service (extension validation, create+current, public
view), the public landing rendering from releases, the admin upload flow
(create + set-current + serve), bad-extension rejection, the Card-Print intro
link, admin auth gating, and the sidebar link (standing rule).
"""
from __future__ import annotations

import hashlib
import io

import pytest

from app.extensions import db
from app.models import Admin, AppProduct, AppRelease
from app.services import app_releases as ar


# ── helpers ───────────────────────────────────────────────────────────────--
def _login(client):
    admin = Admin.query.first()
    with client.session_transaction() as sess:
        sess["admin_id"] = admin.id
    return admin


def _product(name="HobeRadius Manager", slug="hr-manager", visible=True):
    p = ar.upsert_product(product=None, name=name, slug=slug, icon_name="cube",
                          is_visible=visible)
    db.session.commit()
    return p


def _upload_file(content: bytes, filename: str):
    return (io.BytesIO(content), filename)


# ── service: extension validation ───────────────────────────────────────────
def test_validate_extension_allows_and_rejects(app):
    with app.app_context():
        assert ar.validate_extension("windows", "setup.exe") == ".exe"
        assert ar.validate_extension("windows", "Setup.MSI") == ".msi"
        assert ar.validate_extension("windows", "HobeRadius-0.2.0.zip") == ".zip"  # portable/zipped desktop build
        assert ar.validate_extension("android", "app.apk") == ".apk"
        assert ar.validate_extension("android", "bundle.aab") == ".aab"
        with pytest.raises(ar.AppReleaseError):
            ar.validate_extension("windows", "app.apk")   # android ext on windows
        with pytest.raises(ar.AppReleaseError):
            ar.validate_extension("android", "build.zip")  # zip is windows-only
        with pytest.raises(ar.AppReleaseError):
            ar.validate_extension("android", "notes.txt")
        with pytest.raises(ar.AppReleaseError):
            ar.validate_extension("windows", "noext")


# ── service: create + set-current + sha256 + storage ─────────────────────────
def test_create_release_hashes_stores_and_sets_current(app):
    with app.app_context():
        p = _product()
        blob = b"MZ fake windows installer bytes"
        rel = ar.create_release(product=p, platform="windows", channel="stable",
                                version="1.0.0", filename="setup.exe", content=blob)
        db.session.commit()
        assert rel.sha256 == hashlib.sha256(blob).hexdigest()
        assert rel.size_bytes == len(blob) and rel.file_ext == ".exe"
        assert rel.is_current is True
        resolved = ar.get_release_file(rel)
        assert resolved is not None and resolved[0].exists()
        assert resolved[0].read_bytes() == blob

        # A second release for the same combo takes over "current".
        rel2 = ar.create_release(product=p, platform="windows", channel="stable",
                                 version="1.1.0", filename="setup.exe", content=b"newer")
        db.session.commit()
        assert rel2.is_current is True
        assert db.session.get(AppRelease, rel.id).is_current is False
        assert ar.current_release(p, "windows").id == rel2.id


def test_create_release_rejects_empty_and_bad_ext(app):
    with app.app_context():
        p = _product()
        with pytest.raises(ar.AppReleaseError):
            ar.create_release(product=p, platform="windows", channel="stable",
                              version="1.0", filename="x.exe", content=b"")
        with pytest.raises(ar.AppReleaseError):
            ar.create_release(product=p, platform="android", channel="stable",
                              version="1.0", filename="x.txt", content=b"data")


def test_public_downloads_shape_and_visibility(app):
    with app.app_context():
        shown = _product(name="Shown", slug="shown")
        hidden = _product(name="Hidden", slug="hidden", visible=False)
        ar.create_release(product=shown, platform="android", channel="stable",
                          version="2.0", filename="a.apk", content=b"apkbytes")
        db.session.commit()
        dl = ar.public_downloads()
        slugs = [d["product"].slug for d in dl]
        assert "shown" in slugs and "hidden" not in slugs   # hidden excluded
        entry = next(d for d in dl if d["product"].slug == "shown")
        assert entry["android"] is not None and entry["windows"] is None
        assert entry["has_any"] is True
        assert ar.has_any_downloads() is True


# ── public landing rendering ─────────────────────────────────────────────────
def test_landing_downloads_section_renders_from_releases(app, client):
    with app.app_context():
        p = _product(name="HobeRadius Desktop", slug="hr-desktop")
        rel = ar.create_release(product=p, platform="windows", channel="stable",
                                version="3.4.5", filename="setup.exe", content=b"binary")
        db.session.commit()
        rid = rel.id
    html = client.get("/").get_data(as_text=True)
    assert "HobeRadius Desktop" in html
    assert f"/downloads/{rid}" in html        # download link present
    assert "3.4.5" in html                    # version shown
    assert "SHA-256" in html                   # fingerprint surfaced


def test_landing_cardprint_intro_links_to_configured_url(app, client):
    with app.app_context():
        ar.set_cardprint_url("https://cards.hoberadius.example")
        db.session.commit()
    html = client.get("/").get_data(as_text=True)
    assert "https://cards.hoberadius.example" in html
    assert "بطاقات الطباعة" in html


# ── admin auth gating + sidebar link (standing rule) ─────────────────────────
def test_admin_apps_requires_login(client):
    r = client.get("/admin/landing/apps")
    assert r.status_code in (301, 302)
    assert "/login" in r.headers.get("Location", "")


def test_admin_apps_page_renders_with_sidebar_link(app, client):
    _login(client)
    r = client.get("/admin/landing/apps")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    # The sidebar link to this page exists (real clickable nav entry).
    assert "/admin/landing/apps" in body
    assert "التطبيقات والتنزيلات" in body


# ── admin upload flow: create + set-current + serve ──────────────────────────
def test_admin_upload_creates_sets_current_and_serves(app, client):
    _login(client)
    with app.app_context():
        p = _product(name="Uploader", slug="uploader")
        pid = p.id
    blob = b"MZ installer payload \x00\x01"
    r = client.post(f"/admin/landing/apps/{pid}/upload", data={
        "platform": "windows", "channel": "stable", "version": "1.2.3",
        "set_current": "on", "binary": _upload_file(blob, "setup.exe"),
    }, content_type="multipart/form-data", follow_redirects=False)
    assert r.status_code in (301, 302)

    with app.app_context():
        rel = AppRelease.query.filter_by(product_id=pid).first()
        assert rel is not None and rel.is_current is True
        assert rel.sha256 == hashlib.sha256(blob).hexdigest()
        rid = rel.id

    # Public download serves the exact bytes as an attachment.
    dr = client.get(f"/downloads/{rid}")
    assert dr.status_code == 200
    assert dr.data == blob
    assert "attachment" in dr.headers.get("Content-Disposition", "").lower()


def test_admin_upload_rejects_bad_extension(app, client):
    _login(client)
    with app.app_context():
        p = _product(name="BadExt", slug="badext")
        pid = p.id
    r = client.post(f"/admin/landing/apps/{pid}/upload", data={
        "platform": "windows", "channel": "stable", "version": "1.0",
        "binary": _upload_file(b"not an exe", "notes.txt"),
    }, content_type="multipart/form-data", follow_redirects=True)
    assert r.status_code == 200
    with app.app_context():
        assert AppRelease.query.filter_by(product_id=pid).count() == 0  # nothing stored


# ── admin Card-Print URL setting ─────────────────────────────────────────────
def test_admin_cardprint_url_save_and_reject_unsafe(app, client):
    _login(client)
    client.post("/admin/landing/apps/cardprint-url",
                data={"cardprint_url": "https://cards.example"}, follow_redirects=True)
    with app.app_context():
        assert ar.get_cardprint_url() == "https://cards.example"
    # Unsafe scheme rejected → value unchanged.
    client.post("/admin/landing/apps/cardprint-url",
                data={"cardprint_url": "javascript:alert(1)"}, follow_redirects=True)
    with app.app_context():
        assert ar.get_cardprint_url() == "https://cards.example"


def test_admin_apps_create_product(app, client):
    _login(client)
    client.post("/admin/landing/apps/save", data={
        "product_id": "", "name": "Created App", "slug": "created-app",
        "icon_name": "cube", "sort_order": "50", "is_visible": "on",
    }, follow_redirects=True)
    with app.app_context():
        assert AppProduct.query.filter_by(slug="created-app").count() == 1
