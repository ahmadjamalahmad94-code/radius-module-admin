"""Panel-wiring tests for accel-ppp DATA connections (2c): customer fields,
the Cloudflare token setting, and the VPS-IP validator."""
from __future__ import annotations

import pytest

from app.extensions import db
from app.models import Customer


def test_customer_has_data_connection_columns(app):
    with app.app_context():
        c = Customer(company_name="Acme")
        db.session.add(c)
        db.session.commit()
        # New 2c columns exist with sane defaults.
        assert c.vps_ip == ""
        assert c.dns_record_id == ""
        assert c.dns_synced_at is None
        assert c.cert_status == "unknown"


def test_dns_status_property(app):
    with app.app_context():
        c = Customer(company_name="Acme")
        db.session.add(c)
        db.session.commit()
        assert c.dns_status == "unset"          # no IP
        c.vps_ip = "203.0.113.10"
        assert c.dns_status == "missing"        # IP but no record
        c.dns_record_id = "rec1"
        assert c.dns_status == "synced"         # record on file


def test_cloudflare_token_setting_registered():
    from app.services import platform_settings as ps
    assert "CLOUDFLARE_API_TOKEN" in ps.KEYS
    spec = ps.KEYS["CLOUDFLARE_API_TOKEN"]
    assert spec.kind == "secret"               # encrypted at rest, masked in UI


def test_cloudflare_token_round_trip_encrypted(app):
    from app.services import platform_settings as ps
    from app.models import Setting
    with app.app_context():
        ps.set_value("CLOUDFLARE_API_TOKEN", "cf-secret-token-value")
        db.session.commit()
        # Stored ciphertext is NOT the plaintext.
        row = db.session.get(Setting, "CLOUDFLARE_API_TOKEN")
        assert row is not None and row.value != "cf-secret-token-value"
        # Decrypts back through the resolver.
        assert ps.get_secret("CLOUDFLARE_API_TOKEN") == "cf-secret-token-value"


def test_clean_vps_ip_validator():
    from app.admin.routes import _clean_vps_ip, CustomerControlValidationError
    assert _clean_vps_ip("") == ""
    assert _clean_vps_ip("  203.0.113.10 ") == "203.0.113.10"
    assert _clean_vps_ip("fd00::1") == "fd00::1"
    with pytest.raises(CustomerControlValidationError):
        _clean_vps_ip("999.1.1.1")
    with pytest.raises(CustomerControlValidationError):
        _clean_vps_ip("not-an-ip")
