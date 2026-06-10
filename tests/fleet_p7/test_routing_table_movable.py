"""Phase-7 panel gate — routing-table carries ``movable_users`` (additive §1.1).

The proxy reads ``movable_users`` from GET /api/proxy/routing-table to know which
users are opt-in relocatable. It is the lowercased set of usernames whose
``movable`` flag is TRUE in fleet_users; absent/empty ⇒ nobody movable.
"""
from __future__ import annotations

import hashlib
import hmac
import time

import pytest

from app.extensions import db
from fleet.brain.models_session import UserFleet

SHARED_SECRET = "test-proxy-shared-secret-32-chars-long-xxxxxxxxx"
ROUTING_URL = "/api/proxy/routing-table"


@pytest.fixture()
def configured_app(app):
    app.config["RADIUS_PROXY_SHARED_SECRET"] = SHARED_SECRET
    app.config["RADIUS_PROXY_TOKEN_TTL"] = 60
    from app.api import proxy_api
    proxy_api._NONCE_CACHE.clear()
    return app


def _sign_token(nonce: str = "mv1") -> str:
    ts = int(time.time())
    mac = hmac.new(SHARED_SECRET.encode(), f"{ts}:{nonce}".encode(), hashlib.sha256).hexdigest()
    return f"{ts}:{nonce}:{mac}"


def test_routing_table_includes_live_apply_and_movable_users(configured_app, client):
    # Two users: one opt-in movable, one not. Username deliberately mixed-case to
    # prove the response lowercases it.
    db.session.add(UserFleet(customer_id=1, realm="client5", username="Bob@Client5", movable=True))
    db.session.add(UserFleet(customer_id=1, realm="client5", username="alice@client5", movable=False))
    db.session.commit()

    r = client.get(ROUTING_URL, headers={"X-Proxy-Token": _sign_token()})
    assert r.status_code == 200, r.get_data(as_text=True)
    body = r.get_json()
    assert body["ok"] is True
    # Phase-7 fields both present.
    assert "live_apply_enabled" in body
    assert "movable_users" in body
    # Only the movable user, lowercased; the non-movable user is absent.
    assert body["movable_users"] == ["bob@client5"]


def test_movable_users_empty_when_none_opted_in(configured_app, client):
    r = client.get(ROUTING_URL, headers={"X-Proxy-Token": _sign_token(nonce="mv2")})
    assert r.status_code == 200
    body = r.get_json()
    # Absent ⇒ nobody movable (the safe default) — present but empty.
    assert body["movable_users"] == []
