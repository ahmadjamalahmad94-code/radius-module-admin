"""Shared fixtures for the customer-radius-tunnel test set.

Mirrors the proxy-token + nonce dance from
``tests/fix_routing_table/test_routing_table_publishes_fleet_nodes.py`` so
both test suites stay consistent on auth setup.
"""
from __future__ import annotations

import hashlib
import hmac
import time

import pytest

from app.extensions import db
from app.models import Customer, CustomerRadiusInstance


SHARED_SECRET = "tunnel-tests-proxy-shared-secret-very-long"


@pytest.fixture()
def proxy_app(app):
    """Sets X-Proxy-Token auth + a deterministic Fernet vault key so the
    chr-shared-secret encrypt/decrypt round-trip works in tests."""
    app.config["RADIUS_PROXY_SHARED_SECRET"] = SHARED_SECRET
    app.config["RADIUS_PROXY_TOKEN_TTL"] = 60
    # Deterministic 32-byte urlsafe-base64 Fernet key (test-only).
    app.config["CUSTOMER_VAULT_ENCRYPTION_KEY"] = "e1R4rJoOuYz751w-g5Xd1HzPIUPuIWwXdI8bD8Zty_8="
    # Reset the integration nonce cache (deferred-import to avoid eager load).
    from app.api import proxy_api
    proxy_api._NONCE_CACHE.clear()
    return app


_NONCE_SEQ: list[int] = [0]


def proxy_token() -> str:
    _NONCE_SEQ[0] += 1
    ts = int(time.time())
    nonce = f"tunnel-{ts}-{_NONCE_SEQ[0]}"
    mac = hmac.new(
        SHARED_SECRET.encode(), f"{ts}:{nonce}".encode(), hashlib.sha256,
    ).hexdigest()
    return f"{ts}:{nonce}:{mac}"


@pytest.fixture()
def customer_factory(proxy_app):
    """Persist a Customer + CustomerRadiusInstance pair for each test."""
    counter = {"n": 0}

    def _make(*, customer_id: int | None = None, **inst_overrides):
        counter["n"] += 1
        cust = Customer(
            company_name=f"Test Customer {counter['n']}",
            email=f"c{counter['n']}@example.com",
            phone="",
        )
        db.session.add(cust)
        db.session.flush()
        if customer_id is not None:
            cust.id = customer_id
            db.session.flush()
        defaults = {
            "customer_id": cust.id,
            "instance_name": f"client{cust.id}-radius",
            "realm": f"client{cust.id}",
            "radius_auth_ip": f"10.200.{cust.id}.2",
            "radius_auth_port": 1812,
            "radius_acct_port": 1813,
            "status": "online",
        }
        defaults.update(inst_overrides)
        inst = CustomerRadiusInstance(**defaults)
        db.session.add(inst)
        db.session.commit()
        return cust, inst

    return _make
