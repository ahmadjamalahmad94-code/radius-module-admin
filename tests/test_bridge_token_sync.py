"""End-to-end tests for the bridge-token bidirectional sync.

The headline guarantees (from the owner's requirement):

1. **One canonical source.** The panel holds the plaintext exactly once,
   encrypted at rest. There is no "panel copy" vs "customer copy" — both
   sides read the same value.
2. **Bidirectional reflection.** Rotating on the panel side makes the new
   value show up in the runtime-contract pull the customer reads next.
   Rotating on the customer side gets reported through the new reverse
   channel and the panel adopts the new value.
3. **Convergence on conflict.** Same version + different fingerprint →
   the **panel wins** (the customer overwrites locally on the next
   poll). Higher version on either side wins.
4. **No secret leakage.** Plaintext is never returned to a non-signed,
   non-HTTPS caller; never logged; never lands in audit metadata. Only
   SHA-256 fingerprints (and a short prefix for UI/audit).

The "customer side" is mocked here as a function that drives the panel
through the same HTTP endpoints the real radius-module will hit.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from datetime import datetime, timezone

import pytest

from app.extensions import db
from app.license_signing import sign_license_payload, verify_license_signature
from app.models import Admin, Customer, License, Plan, utcnow
from app.services.bridge_token_sync import (
    BridgeTokenError,
    BridgeTokenState,
    apply_customer_report,
    current_plaintext,
    ensure_state,
    fingerprint_of,
    fingerprints_equal,
    get_state,
    rotate_token,
    serialize_for_admin,
    serialize_for_contract,
    verify_signing_secret,
)


# ─────────────────────────────────────────────────────────────────────────────
# Test config + fixtures
# ─────────────────────────────────────────────────────────────────────────────
ROOT_SECRET = "test-license-check-hmac-root-secret-32+chars"
TEST_VAULT_KEY = "e1R4rJoOuYz751w-g5Xd1HzPIUPuIWwXdI8bD8Zty_8="


@pytest.fixture()
def configured_app(app):
    """Wire the secrets the bridge needs + relax HTTPS for the integration
    endpoints so the test client can hit them on plain http."""
    app.config["LICENSE_CHECK_HMAC_SECRET"] = ROOT_SECRET
    app.config["CUSTOMER_VAULT_ENCRYPTION_KEY"] = TEST_VAULT_KEY
    app.config["TRUST_PROXY_HEADERS"] = True
    # Reverse channel rejects unsigned bodies — mirror prod config:
    app.config["LICENSE_CHECK_SIGNATURE_REQUIRED"] = True
    app.config["LICENSE_CHECK_ALLOW_UNSIGNED"] = False
    return app


@pytest.fixture()
def customer_with_license(configured_app):
    plan = Plan(name="Basic", slug="basic", monthly_price=0)
    db.session.add(plan)
    db.session.flush()
    customer = Customer(
        company_name="Test Co",
        email="ops@example.com",
        phone="+10000000000",
    )
    db.session.add(customer)
    db.session.flush()
    lic = License(
        customer_id=customer.id,
        plan_id=plan.id,
        license_key="HBR2026TESTKEYABC1234567",
        status="active",
        starts_at=utcnow(),
        expires_at=datetime(2099, 1, 1),
    )
    db.session.add(lic)
    db.session.commit()
    return customer, lic


@pytest.fixture()
def super_admin_session(configured_app, client):
    """Log a super-admin in via the test client session so super_admin_required
    decorators pass."""
    admin = Admin(username="super", full_name="Super", email="s@x",
                  active=True, is_super_admin=True)
    admin.set_password("pw")
    db.session.add(admin)
    db.session.commit()
    with client.session_transaction() as sess:
        sess["admin_id"] = admin.id
        sess["admin_user"] = "super"
    return admin


def _sign_body(body: dict) -> dict:
    """Sign a payload with the root secret + a fresh timestamp/nonce."""
    body = dict(body)
    body.setdefault("timestamp", int(time.time()))
    body.setdefault("nonce", f"n-{body['timestamp']}-{id(body)}")
    body["signature"] = sign_license_payload(body, ROOT_SECRET)
    return body


def _post_signed(client, url, body, *, force_https=True):
    headers = {"X-Forwarded-Proto": "https"} if force_https else {}
    return client.post(url, json=body, headers=headers)


# ════════════════════════════════════════════════════════════════════════════
# Pure helpers
# ════════════════════════════════════════════════════════════════════════════
class TestHelpers:
    def test_fingerprint_is_sha256_hex(self):
        fp = fingerprint_of("hello-world")
        assert len(fp) == 64
        assert fp == hashlib.sha256(b"hello-world").hexdigest()

    def test_fingerprint_constant_time_compare(self):
        a = fingerprint_of("aaaa")
        b = fingerprint_of("aaaa")
        c = fingerprint_of("bbbb")
        assert fingerprints_equal(a, b) is True
        assert fingerprints_equal(a, c) is False
        assert fingerprints_equal("", "") is False  # empties must not match

    def test_fingerprint_of_non_string_rejected(self):
        with pytest.raises(BridgeTokenError):
            fingerprint_of(None)  # type: ignore[arg-type]


# ════════════════════════════════════════════════════════════════════════════
# Bootstrap + canonical-store invariants
# ════════════════════════════════════════════════════════════════════════════
class TestBootstrap:
    def test_state_is_lazily_bootstrapped(self, customer_with_license):
        _customer, lic = customer_with_license
        assert get_state(lic) is None
        state = ensure_state(lic)
        db.session.commit()
        assert state is not None
        assert state.version == 1
        assert state.rotated_by == "bootstrap"
        assert state.token_fingerprint == fingerprint_of(current_plaintext(lic))

    def test_ciphertext_is_not_the_plaintext(self, customer_with_license):
        _customer, lic = customer_with_license
        state = ensure_state(lic)
        db.session.commit()
        assert current_plaintext(lic) != state.token_ciphertext
        # Fernet token shape — starts with "gAAAAA" base64url prefix.
        assert state.token_ciphertext.startswith("gAAAAA")


# ════════════════════════════════════════════════════════════════════════════
# Service-level rotation paths
# ════════════════════════════════════════════════════════════════════════════
class TestPanelRotation:
    def test_rotate_bumps_version_and_changes_plaintext(
        self, customer_with_license
    ):
        _customer, lic = customer_with_license
        state0 = ensure_state(lic)
        original_plain = current_plaintext(lic)
        original_v = state0.version
        result = rotate_token(lic, actor="panel")
        db.session.commit()
        assert result.outcome == "rotated"
        assert result.version == original_v + 1
        assert result.plaintext != original_plain
        assert current_plaintext(lic) == result.plaintext
        assert result.fingerprint == fingerprint_of(result.plaintext)

    def test_rotate_rejects_unknown_actor(self, customer_with_license):
        _customer, lic = customer_with_license
        with pytest.raises(BridgeTokenError):
            rotate_token(lic, actor="customer")


class TestCustomerReport:
    def test_higher_version_adopts_customer_value(self, customer_with_license):
        _customer, lic = customer_with_license
        ensure_state(lic); db.session.commit()
        customer_token = "X" * 64
        result = apply_customer_report(
            lic,
            claimed_token=customer_token,
            claimed_version=42,
            claimed_fingerprint=None,
        )
        db.session.commit()
        assert result.outcome == "adopted_customer"
        assert result.version == 42
        assert current_plaintext(lic) == customer_token
        assert result.rotated_by == "customer"

    def test_same_version_same_fp_is_heartbeat(self, customer_with_license):
        _customer, lic = customer_with_license
        state = ensure_state(lic); db.session.commit()
        plain = current_plaintext(lic)
        result = apply_customer_report(
            lic, claimed_token=plain,
            claimed_version=state.version,
            claimed_fingerprint=fingerprint_of(plain),
        )
        db.session.commit()
        assert result.outcome == "no_change"
        assert result.version == state.version
        assert current_plaintext(lic) == plain

    def test_same_version_diff_value_panel_wins(self, customer_with_license):
        _customer, lic = customer_with_license
        state = ensure_state(lic); db.session.commit()
        panel_plain = current_plaintext(lic)
        result = apply_customer_report(
            lic, claimed_token=("Y" * 64),
            claimed_version=state.version,
            claimed_fingerprint=None,
        )
        db.session.commit()
        assert result.outcome == "panel_wins"
        # The plaintext returned is the PANEL's, not the customer's.
        assert result.plaintext == panel_plain
        assert current_plaintext(lic) == panel_plain
        assert result.version == state.version

    def test_lower_version_is_stale(self, customer_with_license):
        _customer, lic = customer_with_license
        # Force version up.
        ensure_state(lic); db.session.commit()
        rotate_token(lic, actor="panel"); db.session.commit()
        rotate_token(lic, actor="panel"); db.session.commit()
        panel_plain = current_plaintext(lic)
        result = apply_customer_report(
            lic, claimed_token=("Z" * 64),
            claimed_version=1,
            claimed_fingerprint=None,
        )
        db.session.commit()
        assert result.outcome == "stale_report"
        assert result.plaintext == panel_plain
        assert current_plaintext(lic) == panel_plain

    def test_fingerprint_mismatch_with_self_rejected(self, customer_with_license):
        """If the customer's own fingerprint does not match its own
        plaintext, that's an obviously broken emitter — reject loudly."""
        _customer, lic = customer_with_license
        ensure_state(lic); db.session.commit()
        with pytest.raises(BridgeTokenError):
            apply_customer_report(
                lic,
                claimed_token="A" * 64,
                claimed_version=99,
                claimed_fingerprint=fingerprint_of("not the same token"),
            )

    def test_invalid_version_rejected(self, customer_with_license):
        _customer, lic = customer_with_license
        ensure_state(lic); db.session.commit()
        with pytest.raises(BridgeTokenError):
            apply_customer_report(
                lic, claimed_token="A" * 64,
                claimed_version="not-a-number",  # type: ignore[arg-type]
                claimed_fingerprint=None,
            )

    def test_short_token_rejected(self, customer_with_license):
        _customer, lic = customer_with_license
        ensure_state(lic); db.session.commit()
        with pytest.raises(BridgeTokenError):
            apply_customer_report(
                lic, claimed_token="short",
                claimed_version=99,
                claimed_fingerprint=None,
            )


# ════════════════════════════════════════════════════════════════════════════
# Contract / admin serialisation
# ════════════════════════════════════════════════════════════════════════════
class TestSerialisation:
    def test_serialize_for_contract_has_plaintext_and_metadata(
        self, customer_with_license
    ):
        _customer, lic = customer_with_license
        ensure_state(lic); db.session.commit()
        block = serialize_for_contract(lic)
        assert set(block.keys()) >= {"token", "version", "fingerprint", "rotated_at", "rotated_by"}
        assert isinstance(block["token"], str) and len(block["token"]) >= 32
        assert block["fingerprint"] == fingerprint_of(block["token"])

    def test_serialize_for_admin_omits_plaintext(self, customer_with_license):
        _customer, lic = customer_with_license
        ensure_state(lic); db.session.commit()
        block = serialize_for_admin(lic)
        json_blob = json.dumps(block)
        plain = current_plaintext(lic)
        # The plaintext never appears in the admin shape — only the fingerprint.
        assert plain not in json_blob
        assert block["fingerprint"] == fingerprint_of(plain)
        assert "token" not in block


# ════════════════════════════════════════════════════════════════════════════
# Signature-verify integration — current rotated token must be accepted
# ════════════════════════════════════════════════════════════════════════════
class TestSignatureAcceptance:
    def test_verify_signing_secret_accepts_current_token(self, customer_with_license):
        _customer, lic = customer_with_license
        ensure_state(lic); db.session.commit()
        assert verify_signing_secret(lic, current_plaintext(lic)) is True
        assert verify_signing_secret(lic, "not the secret") is False
        assert verify_signing_secret(lic, "") is False

    def test_signature_with_current_bridge_token_is_accepted(
        self, configured_app, customer_with_license
    ):
        """Sign a request with the CURRENT bridge token (no root secret,
        no derived secret) — verify_license_signature accepts it via the
        new rotatable-token fallback."""
        _customer, lic = customer_with_license
        result = rotate_token(lic, actor="panel"); db.session.commit()
        body = {
            "license_key": lic.license_key,
            "server_fingerprint": "fp",
            "timestamp": int(time.time()),
            "nonce": "sig-nonce-1",
        }
        body["signature"] = sign_license_payload(body, result.plaintext)
        # Should NOT raise.
        verify_license_signature(configured_app, body)


# ════════════════════════════════════════════════════════════════════════════
# Reverse-channel endpoint — full HTTP round-trip
# ════════════════════════════════════════════════════════════════════════════
class TestReverseChannelEndpoint:
    URL = "/api/integration/hoberadius/bridge-token/report"

    def test_missing_license_key_is_401(self, configured_app, client, customer_with_license):
        """Bearer auth: a body without a resolvable license_key is denied."""
        body = {"server_fingerprint": "fp",
                "bridge_token": "Z" * 64, "bridge_token_version": 99}
        r = _post_signed(client, self.URL, body)
        assert r.status_code == 401

    def test_plain_http_is_426(self, configured_app, client, customer_with_license):
        _customer, lic = customer_with_license
        body = _sign_body({
            "license_key": lic.license_key, "server_fingerprint": "fp",
            "bridge_token": "Z" * 64, "bridge_token_version": 99,
        })
        r = client.post(self.URL, json=body)  # NO https header
        assert r.status_code == 426

    def test_higher_version_adopted_over_http(
        self, configured_app, client, customer_with_license
    ):
        _customer, lic = customer_with_license
        ensure_state(lic); db.session.commit()
        body = _sign_body({
            "license_key": lic.license_key,
            "server_fingerprint": "fp",
            "bridge_token": "K" * 64,
            "bridge_token_version": 7,
        })
        r = _post_signed(client, self.URL, body)
        assert r.status_code == 200, r.get_data(as_text=True)
        payload = r.get_json()
        assert payload["ok"] is True
        assert payload["outcome"] == "adopted_customer"
        assert payload["version"] == 7
        assert payload["token"] == "K" * 64
        # Persisted
        state = get_state(lic)
        assert state.version == 7
        assert current_plaintext(lic) == "K" * 64

    def test_panel_wins_on_same_version_mismatch(
        self, configured_app, client, customer_with_license
    ):
        _customer, lic = customer_with_license
        ensure_state(lic); db.session.commit()
        panel_plain = current_plaintext(lic)
        state = get_state(lic)
        body = _sign_body({
            "license_key": lic.license_key,
            "server_fingerprint": "fp",
            "bridge_token": "Q" * 64,
            "bridge_token_version": state.version,
        })
        r = _post_signed(client, self.URL, body)
        assert r.status_code == 200
        payload = r.get_json()
        assert payload["outcome"] == "panel_wins"
        # Panel's plaintext returned so the customer overwrites
        assert payload["token"] == panel_plain

    def test_fingerprint_mismatch_is_400(
        self, configured_app, client, customer_with_license
    ):
        _customer, lic = customer_with_license
        ensure_state(lic); db.session.commit()
        body = _sign_body({
            "license_key": lic.license_key,
            "server_fingerprint": "fp",
            "bridge_token": "A" * 64,
            "bridge_token_version": 99,
            "bridge_token_fingerprint": fingerprint_of("does-not-match"),
        })
        r = _post_signed(client, self.URL, body)
        assert r.status_code == 400
        assert r.get_json()["status"] == "fingerprint_mismatch"
