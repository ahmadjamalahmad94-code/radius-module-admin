"""The radius «ربط جوجل درايف» SSO must always mint a login link.

A customer with no portal user used to get 404 no_user, so the radius showed
«لم يصل رابط الدخول من لوحة التراخيص» and never reached /portal. The portal-sso
bridge endpoint now auto-provisions an owner portal user on demand, so the link
is always minted and the redirect lands on the Drive section (#gdrive).
"""
from __future__ import annotations

import time
from datetime import timedelta

import pytest

from app import create_app, seed_defaults
from app.config import TestingConfig
from app.extensions import db
from app.models import Customer, CustomerUser, License, Plan, utcnow
from app.services.license_service import generate_license_key


HTTPS_BASE = "https://license-panel.test"
SSO_PATH = "/api/integration/hoberadius/portal-sso"


@pytest.fixture()
def app():
    app = create_app(TestingConfig)
    with app.app_context():
        db.create_all()
        seed_defaults(app)
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


def _customer_with_license(company="Drive Co", email="owner@drive.test") -> tuple[int, str]:
    customer = Customer(company_name=company, contact_name="Owner", email=email, status="active")
    plan = Plan.query.filter_by(slug="pro").one()
    now = utcnow()
    db.session.add(customer)
    db.session.flush()
    lic = License(
        customer_id=customer.id, plan_id=plan.id, license_key=generate_license_key(),
        status="active", starts_at=now - timedelta(days=1), expires_at=now + timedelta(days=30),
        grace_until=now + timedelta(days=37), max_fingerprints=3,
    )
    db.session.add(lic)
    db.session.commit()
    return customer.id, lic.license_key


def _body(license_key: str, nonce: str = "n1") -> dict:
    return {
        "license_key": license_key, "server_fingerprint": f"fp-{nonce}",
        "hostname": "radius-runtime", "version": "test",
        "timestamp": int(time.time()), "nonce": nonce,
    }


def test_sso_autoprovisions_portal_user_and_mints_link(app, client):
    cid, key = _customer_with_license()
    assert CustomerUser.query.filter_by(customer_id=cid).count() == 0

    r = client.post(SSO_PATH, json=_body(key), base_url=HTTPS_BASE)
    assert r.status_code == 200, r.get_data(as_text=True)
    data = r.get_json()
    assert data["ok"] is True
    assert data["sso_url"] and "/portal" in data["sso_url"]
    assert "focus=gdrive" in data["sso_url"]

    users = CustomerUser.query.filter_by(customer_id=cid, active=True).all()
    assert len(users) == 1
    assert users[0].role_key == "owner"
    assert users[0].is_effective_super is True


def test_sso_is_idempotent_no_duplicate_user(app, client):
    cid, key = _customer_with_license()
    client.post(SSO_PATH, json=_body(key, "a"), base_url=HTTPS_BASE)
    client.post(SSO_PATH, json=_body(key, "b"), base_url=HTTPS_BASE)
    assert CustomerUser.query.filter_by(customer_id=cid).count() == 1


def test_sso_reuses_existing_active_user(app, client):
    cid, key = _customer_with_license()
    u = CustomerUser(customer_id=cid, username="preexisting", email="x@y.z",
                     full_name="Pre", role_key="owner", active=True)
    u.set_password("whatever-123")
    db.session.add(u)
    db.session.commit()
    r = client.post(SSO_PATH, json=_body(key), base_url=HTTPS_BASE)
    assert r.status_code == 200
    # no NEW user created
    assert CustomerUser.query.filter_by(customer_id=cid).count() == 1


def test_portal_dashboard_renders_drive_card_for_authed_customer(app, client):
    from app.models import CustomerUser
    cid, _key = _customer_with_license()
    u = CustomerUser(customer_id=cid, username="owner1", email="o@x.test",
                     full_name="Owner", role_key="owner", active=True)
    u.set_password("pw-12345678")
    db.session.add(u)
    db.session.commit()
    with client.session_transaction() as s:
        s["customer_user_id"] = u.id
        s["customer_id"] = cid
        s["customer_name"] = u.username
    body = client.get("/portal?view=backups").get_data(as_text=True)
    # The body is NOT empty: the backups pane + Google Drive card render
    # server-side (the connect button OR the not-configured admin notice).
    assert 'data-pp-pane="backups"' in body
    assert 'id="gdrive"' in body
    assert "Google Drive" in body
    assert ("ربط Google Drive" in body) or ("قيد التهيئة" in body)


def test_sso_landing_with_focus_redirects_to_gdrive_anchor(app, client):
    cid, key = _customer_with_license()
    data = client.post(SSO_PATH, json=_body(key), base_url=HTTPS_BASE).get_json()
    # follow the minted sso_url's path+query into the portal landing
    from urllib.parse import urlsplit
    parts = urlsplit(data["sso_url"])
    r = client.get(parts.path + "?" + parts.query, base_url=HTTPS_BASE, follow_redirects=False)
    assert r.status_code in (301, 302)
    # Lands on the backups VIEW (the SPA pane that holds the Drive card), with
    # the #gdrive anchor — not a bare #gdrive that the SPA reads as an unknown
    # view and blanks the page.
    loc = r.headers["Location"]
    assert "view=backups" in loc and loc.endswith("#gdrive")
