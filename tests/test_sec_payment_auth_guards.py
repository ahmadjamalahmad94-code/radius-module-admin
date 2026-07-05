"""Security guards (SEC C3 + C4) for license-payment endpoints.

C3: `approve-and-credit` and `apply-license` are financial actions and must be
    super-admin-only, matching the sibling `approve`/`reject` endpoints. They
    were previously only `@login_required`, so a non-super operator could
    approve+credit a payment.
C4: the public `POST /api/license-payments/requests` (customer-initiated) is
    per-IP rate-limited to blunt customer_id enumeration + queue flooding.
"""
from __future__ import annotations

import pytest

from app import db
from app.models import Admin
from app.services import platform_settings as ps


def _login(client, username, password):
    return client.post("/login", data={"username": username, "password": password})


def _make_operator(app, username="operator1", password="operator12345"):
    with app.app_context():
        a = Admin(username=username, is_super_admin=False, active=True)
        a.set_password(password)
        db.session.add(a)
        db.session.commit()
    return username, password


# ── C3: money endpoints are super-only ─────────────────────────────────
# super_admin_required wraps the view, so it fires BEFORE get_or_404 / any
# payment-enabled check — a non-super XHR gets 403 regardless of request id.
@pytest.mark.parametrize("suffix", ["approve-and-credit", "apply-license",
                                    "approve", "reject"])
def test_money_endpoints_reject_non_super(app, client, suffix):
    user, pw = _make_operator(app)
    _login(client, user, pw)
    resp = client.post(
        f"/admin/payments/requests/1/{suffix}",
        headers={"X-Requested-With": "XMLHttpRequest"},
    )
    # super_admin_required → JSON 403 for XHR. (Never 200/302-success.)
    assert resp.status_code == 403, (suffix, resp.status_code)


# ── C4: public create endpoint is rate-limited ─────────────────────────
def test_payment_request_create_is_rate_limited():
    from app import create_app, db as _db, seed_defaults
    from app.config import TestingConfig
    app = create_app(
        TestingConfig,
        RATE_LIMITS_ENABLED=True,
        PAYMENT_REQUEST_RATE_LIMIT_MAX=2,
        PAYMENT_REQUEST_RATE_LIMIT_WINDOW_SECONDS=60,
    )
    with app.app_context():
        _db.create_all()
        seed_defaults(app)
        client = app.test_client()
        # First 2 pass the limiter (the view itself may 400 on a bogus
        # customer_id — irrelevant; the limiter runs in before_request).
        client.post("/api/license-payments/requests", json={"customer_id": 999999})
        client.post("/api/license-payments/requests", json={"customer_id": 999999})
        limited = client.post("/api/license-payments/requests", json={"customer_id": 999999})
        assert limited.status_code == 429
        assert limited.headers["Retry-After"]
