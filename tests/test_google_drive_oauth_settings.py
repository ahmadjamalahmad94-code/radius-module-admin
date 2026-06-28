"""Owner can configure Google Drive OAuth from the admin Settings UI.

Before this, the settings page had no inputs for the Google OAuth credentials,
so Drive linking could never be turned on from the UI (the project's rule is
config-from-UI, not env). These tests lock in the integrations section.
"""
from __future__ import annotations

from app.extensions import db
from app.models import Admin, Setting


def _login_super(client):
    admin = Admin.query.first()
    with client.session_transaction() as s:
        s["admin_id"] = admin.id
        s["is_super_admin"] = True
    return client


def _setting(key):
    row = db.session.get(Setting, key)
    return row.value if row else None


def test_settings_page_shows_integrations_tab_and_not_configured(app, client):
    _login_super(client)
    body = client.get("/admin/settings").get_data(as_text=True)
    assert 'id="tab-integrations"' in body
    assert "تكامل Google Drive" in body
    # Unconfigured → the clear, friendly message (not the cryptic banner).
    assert "ربط جوجل درايف غير مُهيّأ" in body


def test_section_save_persists_google_oauth_credentials(app, client):
    _login_super(client)
    r = client.post("/admin/settings/section", data={
        "section": "integrations",
        "google_oauth_client_id": "123-abc.apps.googleusercontent.com",
        "google_oauth_client_secret": "super-secret-value",
        "google_oauth_redirect_uri": "https://hoberadius.com/portal/google-drive/callback",
    }, follow_redirects=False)
    assert r.status_code in (301, 302)
    db.session.expire_all()
    assert _setting("google_oauth_client_id") == "123-abc.apps.googleusercontent.com"
    assert _setting("google_oauth_client_secret") == "super-secret-value"
    assert _setting("google_oauth_redirect_uri") == "https://hoberadius.com/portal/google-drive/callback"

    # Once configured, is_configured() flips True and the page says so.
    from app.services import google_drive as gd
    with app.test_request_context():
        assert gd.is_configured() is True
    body = client.get("/admin/settings").get_data(as_text=True)
    assert "ربط Google Drive مُهيّأ" in body


def test_blank_secret_preserves_stored_secret(app, client):
    _login_super(client)
    client.post("/admin/settings/section", data={
        "section": "integrations",
        "google_oauth_client_id": "cid-1",
        "google_oauth_client_secret": "keep-me",
    }, follow_redirects=False)
    db.session.expire_all()
    assert _setting("google_oauth_client_secret") == "keep-me"

    # Re-save with the secret field left blank → existing secret survives.
    client.post("/admin/settings/section", data={
        "section": "integrations",
        "google_oauth_client_id": "cid-2",
        "google_oauth_client_secret": "",
    }, follow_redirects=False)
    db.session.expire_all()
    assert _setting("google_oauth_client_id") == "cid-2"
    assert _setting("google_oauth_client_secret") == "keep-me"
