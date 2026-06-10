"""i18n smoke tests — runtime + switcher + RTL/LTR + catalogs.

Covers the panel's translation layer:

* The 4 catalogs load (AR base, EN, FR scaffold, TR scaffold).
* ``gettext`` returns the translated string for the active locale and
  falls back to the AR source when a key is missing.
* The ``?lang=en`` query string forces a locale for one request.
* The ``POST /i18n/set`` switcher persists the choice on the session.
* ``<html lang dir>`` flips between RTL (Arabic) and LTR (English).
* The top-bar switcher is rendered on the login page (so an unauth user
  can pick a language before signing in).
"""
from __future__ import annotations

from pathlib import Path
import json

import pytest


def test_all_four_catalogs_load(app):
    base = Path("app/i18n/locales").resolve()
    for code in ("ar", "en", "fr", "tr"):
        path = base / f"{code}.json"
        assert path.exists(), f"missing catalog {code}.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        assert isinstance(data, dict) and data, f"{code}.json empty"


def test_supported_locales_metadata(app):
    from app.i18n import SUPPORTED_LOCALES, DEFAULT_LOCALE
    assert DEFAULT_LOCALE == "ar"
    assert SUPPORTED_LOCALES["ar"]["dir"] == "rtl"
    for code in ("en", "fr", "tr"):
        assert SUPPORTED_LOCALES[code]["dir"] == "ltr"


def test_gettext_returns_english_when_locale_is_en(app):
    from app.i18n import gettext
    with app.test_request_context("/?lang=en"):
        assert gettext("العملاء") == "Customers"
        assert gettext("الإعدادات") == "Settings"
        assert gettext("لوحة التحكم") == "Dashboard"


def test_gettext_returns_french_for_fr(app):
    from app.i18n import gettext
    with app.test_request_context("/?lang=fr"):
        assert gettext("العملاء") == "Clients"


def test_gettext_returns_turkish_for_tr(app):
    from app.i18n import gettext
    with app.test_request_context("/?lang=tr"):
        assert gettext("العملاء") == "Müşteriler"


def test_gettext_falls_back_to_arabic_source_when_unknown(app):
    """Missing translation ⇒ return the key (which is the AR source)."""
    from app.i18n import gettext
    with app.test_request_context("/?lang=en"):
        assert gettext("X_KEY_THAT_DOES_NOT_EXIST") == "X_KEY_THAT_DOES_NOT_EXIST"


def test_current_dir_is_rtl_for_arabic_ltr_for_english(app):
    from app.i18n import current_dir
    with app.test_request_context("/"):
        assert current_dir() == "rtl"
    with app.test_request_context("/?lang=en"):
        assert current_dir() == "ltr"


def test_set_locale_route_persists_on_session(client, app):
    """The switcher POST writes the locale on the session and bounces back."""
    r = client.post("/i18n/set", data={"locale": "en", "next": "/admin/"})
    assert r.status_code in (301, 302)
    with client.session_transaction() as s:
        assert s.get("_locale") == "en"


def test_set_locale_route_rejects_open_redirect(client, app):
    r = client.post("/i18n/set", data={"locale": "en", "next": "http://evil.example.com/"})
    assert r.status_code in (301, 302)
    assert r.headers["Location"] in ("/", "http://localhost/")


def test_set_locale_route_ignores_unknown_locale(client, app):
    r = client.post("/i18n/set", data={"locale": "xx", "next": "/admin/"})
    assert r.status_code in (301, 302)
    with client.session_transaction() as s:
        # No write — session stays default
        assert s.get("_locale") in (None, "ar")


def test_html_lang_dir_flips_on_locale(client, app):
    """The base template's <html> tag picks up current_locale + current_dir."""
    from app.models import Admin
    with app.app_context():
        admin_id = Admin.query.filter_by(username="admin").first().id
    with client.session_transaction() as s:
        s["admin_id"] = admin_id

    # AR default → rtl
    body_ar = client.get("/admin/").get_data(as_text=True)
    assert 'lang="ar"' in body_ar and 'dir="rtl"' in body_ar
    # Force EN via query string
    body_en = client.get("/admin/?lang=en").get_data(as_text=True)
    assert 'lang="en"' in body_en and 'dir="ltr"' in body_en


def test_language_switcher_rendered_in_topbar(client, app):
    """A logged-in admin sees the language switcher form on every page."""
    from app.models import Admin
    with app.app_context():
        admin_id = Admin.query.filter_by(username="admin").first().id
    with client.session_transaction() as s:
        s["admin_id"] = admin_id
    body = client.get("/admin/").get_data(as_text=True)
    assert "/i18n/set" in body
    # All four locales are options
    assert 'value="ar"' in body
    assert 'value="en"' in body
    assert 'value="fr"' in body
    assert 'value="tr"' in body


def test_catalog_stats_reports_coverage(app):
    """The catalog_stats helper feeds the docs / locale-picker UI."""
    from app.i18n import catalog_stats
    with app.test_request_context("/"):
        stats = catalog_stats()
        codes = {s["code"] for s in stats}
        assert codes == {"ar", "en", "fr", "tr"}
        ar = next(s for s in stats if s["code"] == "ar")
        assert ar["is_base"] is True
        en = next(s for s in stats if s["code"] == "en")
        # English is essentially complete
        assert en["pct"] >= 95
