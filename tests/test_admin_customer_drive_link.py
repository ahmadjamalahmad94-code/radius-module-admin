"""Centralized Google Drive: the owner links a customer's Drive FROM the
customer file in licensing. The token lands in customer_google_drive (the single
source of truth the backup-forwarding path uploads with).
"""
from __future__ import annotations

import pytest

from app.extensions import db
from app.models import Admin, Customer, CustomerGoogleDrive


@pytest.fixture()
def customer(app):
    c = Customer(company_name="Drive Co", email="drive@example.com", status="active")
    db.session.add(c)
    db.session.commit()
    return c


def _login_super(client):
    admin = Admin.query.first()
    with client.session_transaction() as s:
        s["admin_id"] = admin.id
        s["is_super_admin"] = True
    return client


def test_connect_redirects_to_google_and_marks_session(app, client, customer, monkeypatch):
    from app.services import google_drive as gd
    monkeypatch.setattr(gd, "is_configured", lambda *a, **k: True)
    monkeypatch.setattr(gd, "libs_available", lambda *a, **k: True)
    monkeypatch.setattr(gd, "authorization_url",
                        lambda cid: ("https://accounts.google.com/o/oauth2/auth?x=1", "verifier-abc"))
    _login_super(client)
    r = client.get(f"/admin/customers/{customer.id}/google-drive/connect", follow_redirects=False)
    assert r.status_code in (301, 302)
    assert r.headers["Location"].startswith("https://accounts.google.com/")
    with client.session_transaction() as s:
        assert s["gdrive_admin_customer_id"] == customer.id
        assert s["gdrive_code_verifier"] == "verifier-abc"


def test_connect_unconfigured_sends_owner_to_settings(app, client, customer, monkeypatch):
    from app.services import google_drive as gd
    monkeypatch.setattr(gd, "is_configured", lambda *a, **k: False)
    _login_super(client)
    r = client.get(f"/admin/customers/{customer.id}/google-drive/connect", follow_redirects=False)
    assert r.status_code in (301, 302)
    assert "/admin/settings" in r.headers["Location"]


def test_admin_callback_stores_token_on_customer(app, client, customer, monkeypatch):
    from app.services import google_drive as gd
    # The signed state resolves to our customer; the OAuth exchange is mocked.
    monkeypatch.setattr(gd, "read_state", lambda state, max_age=600: customer.id)
    monkeypatch.setattr(gd, "exchange_callback",
                        lambda url, code_verifier="": ("refresh-xyz", "owner@gmail.com"))
    _login_super(client)
    with client.session_transaction() as s:
        s["gdrive_admin_customer_id"] = customer.id
        s["gdrive_code_verifier"] = "verifier-abc"
    r = client.get("/portal/google-drive/callback?state=signed&code=auth-code", follow_redirects=False)
    assert r.status_code in (301, 302)
    assert f"/admin/customers/{customer.id}" in r.headers["Location"]
    conn = CustomerGoogleDrive.query.filter_by(customer_id=customer.id).first()
    assert conn is not None and conn.connected is True
    assert conn.google_email == "owner@gmail.com"
    # session marker consumed
    with client.session_transaction() as s:
        assert "gdrive_admin_customer_id" not in s


def test_disconnect_clears_connection(app, client, customer):
    db.session.add(CustomerGoogleDrive(customer_id=customer.id, connected=True,
                                       google_email="x@gmail.com", refresh_token_enc="enc"))
    db.session.commit()
    _login_super(client)
    r = client.post(f"/admin/customers/{customer.id}/google-drive/disconnect", follow_redirects=False)
    assert r.status_code in (301, 302)
    conn = CustomerGoogleDrive.query.filter_by(customer_id=customer.id).first()
    assert conn.connected is False


def test_customer_file_shows_connect_button_when_configured(app, client, customer, monkeypatch):
    from app.services import google_drive as gd
    monkeypatch.setattr(gd, "status", lambda cid: {
        "configured": True, "libs": True, "connected": False, "email": "",
        "folder_name": "", "last_upload_at": None, "last_error": "",
    })
    _login_super(client)
    body = client.get(f"/admin/customers/{customer.id}").get_data(as_text=True)
    assert f"/admin/customers/{customer.id}/google-drive/connect" in body
    assert "ربط جوجل درايف" in body


def test_customer_file_prompts_settings_when_unconfigured(app, client, customer, monkeypatch):
    from app.services import google_drive as gd
    monkeypatch.setattr(gd, "status", lambda cid: {
        "configured": False, "libs": True, "connected": False, "email": "",
        "folder_name": "", "last_upload_at": None, "last_error": "",
    })
    _login_super(client)
    body = client.get(f"/admin/customers/{customer.id}").get_data(as_text=True)
    assert "هيّئ بيانات Google OAuth" in body
