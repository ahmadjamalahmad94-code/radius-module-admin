"""Panel-managed Embedded Signup settings — render + persist + resolution tests.

Verifies the owner can enable + configure Meta Embedded Signup entirely from the
admin SETTINGS UI (no terminal/env), mirroring the cloud_settings pattern.
The default `admin` user is the primary super-admin (see app/__init__).
"""
from __future__ import annotations

from app.extensions import db
from app.models import Setting
from app.services.whatsapp import embedded_settings as wae
from app.services.whatsapp import embedded_signup as es
from app.services.whatsapp.crypto import decrypt_secret, encrypt_secret

SECRET = "super-secret-meta-app-secret-9f8e7d6c5b4a"


def _login(client):
    return client.post("/login", data={"username": "admin", "password": "admin12345"})


def _clear_env(app):
    """Drop the TestingConfig META_* env fallbacks so the DB fully drives state."""
    for k in ("META_APP_ID", "META_APP_SECRET", "META_CONFIG_ID", "META_GRAPH_VERSION"):
        app.config[k] = ""
    app.config["META_EMBEDDED_SIGNUP_ENABLED"] = False


def test_section_renders_with_masked_secret(client, app):
    _login(client)
    with app.app_context():
        wae._set_db_value(wae.FIELDS["app_secret"][0], encrypt_secret(SECRET))
        db.session.commit()
    resp = client.get("/admin/settings")
    assert resp.status_code == 200
    body = resp.data.decode("utf-8")
    assert "ربط واتساب التلقائي (Embedded Signup)" in body
    assert 'id="whatsapp-embedded"' in body
    # Secret is masked, never echoed in clear.
    assert SECRET not in body
    assert "محفوظ مشفّرًا" in body


def test_save_persists_and_enables(client, app):
    _login(client)
    with app.app_context():
        _clear_env(app)
    with client.session_transaction() as s:
        token = s.get("_csrf_token", "")
    resp = client.post(
        "/admin/settings/whatsapp-embedded",
        data={
            "_csrf_token": token,
            "enabled": "1",
            "app_id": "111222333",
            "config_id": "444555666",
            "app_secret": SECRET,
            "graph_version": "",
        },
        follow_redirects=False,
    )
    assert resp.status_code in (301, 302)
    with app.app_context():
        _clear_env(app)  # prove DB drives it, not env
        # app_id + config_id readable in clear.
        assert wae._resolve("app_id")[0] == "111222333"
        assert wae._resolve("config_id")[0] == "444555666"
        # Secret stored ENCRYPTED (ciphertext != plaintext) but decrypts back.
        raw = db.session.get(Setting, wae.FIELDS["app_secret"][0]).value
        assert raw and raw != SECRET
        assert decrypt_secret(raw) == SECRET
        # Availability now driven purely by DB.
        assert wae.is_enabled() is True
        assert wae.available() is True
        assert es.embedded_signup_available() is True


def test_disabled_or_empty_is_unavailable(client, app):
    _login(client)
    with app.app_context():
        _clear_env(app)
    with client.session_transaction() as s:
        token = s.get("_csrf_token", "")
    # Save with the toggle OFF (checkbox absent) + creds present.
    client.post(
        "/admin/settings/whatsapp-embedded",
        data={"_csrf_token": token, "app_id": "111", "config_id": "222", "app_secret": SECRET},
    )
    with app.app_context():
        _clear_env(app)
        assert wae.is_enabled() is False
        assert wae.available() is False
        assert es.embedded_signup_available() is False  # manual fallback


def test_reveal_secret_super_admin(client, app):
    _login(client)
    with app.app_context():
        wae._set_db_value(wae.FIELDS["app_secret"][0], encrypt_secret(SECRET))
        db.session.commit()
    with client.session_transaction() as s:
        token = s.get("_csrf_token", "")
    resp = client.post(
        "/admin/settings/whatsapp-embedded/reveal",
        data={"_csrf_token": token, "field": "app_secret"},
    )
    assert resp.status_code == 200
    assert resp.get_json()["value"] == SECRET
