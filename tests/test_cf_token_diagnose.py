"""Cloudflare token presence + customer-subdomain DNS diagnosis (2c).

Pins the root-cause findings for the «مزامنة النطاق» bug:
  * the customer sync reads the SAME `CLOUDFLARE_API_TOKEN` platform key (no
    separate/empty field), via platform_settings (DB-encrypted, env fallback);
  * `secret_state` distinguishes absent vs present-but-undecryptable (the silent
    Fernet-key-drift trap that looks like "not configured");
  * `diagnose` is a read-only live probe that surfaces the exact reason a
    subdomain doesn't resolve (token missing / unreadable / zone unreachable /
    record missing / proxied / IP mismatch / healthy).
"""
from __future__ import annotations

import pytest

from app.extensions import db
from app.models import Admin, Customer
from app.services import data_connection_dns as dns
from app.services import platform_settings as ps
from app.services.cloudflare import CLOUDFLARE_API_TOKEN_KEY
from app.services.cloudflare.client import CfResult, DnsRecord

IP = "187.77.70.18"


def _cust(vps_ip=IP):
    c = Customer(company_name="DNS Co", email="dns@x.com", status="active", vps_ip=vps_ip)
    db.session.add(c)
    db.session.commit()
    return c


class _FakeClient:
    """Stand-in for CloudflareDNSClient driving diagnose() deterministically."""
    def __init__(self, *, zone=None, record=None):
        self._zone = zone or CfResult(ok=True, zone_id="zone-1")
        self._record = record or CfResult(ok=True, zone_id="zone-1", record=None)

    def find_zone_id(self, zone_name):
        return self._zone

    def find_a_record(self, zone_id, fqdn, *, rtype="A"):
        return self._record


# ── secret_state: the key-presence truth ─────────────────────────────────────
def test_secret_state_absent_then_present(app):
    with app.app_context():
        # fresh: no token
        present, source, readable = ps.secret_state(CLOUDFLARE_API_TOKEN_KEY)
        assert present is False and source == "none" and readable is False
        # set it via the same platform-settings write path the Settings page uses
        ps.set_value(CLOUDFLARE_API_TOKEN_KEY, "cf-tok-abc123")
        db.session.commit()
        present, source, readable = ps.secret_state(CLOUDFLARE_API_TOKEN_KEY)
        assert present is True and readable is True            # decrypts fine
        assert ps.get_secret(CLOUDFLARE_API_TOKEN_KEY) == "cf-tok-abc123"


# ── diagnose: every failure mode → precise verdict ───────────────────────────
def test_diagnose_no_ip(app):
    with app.app_context():
        c = _cust(vps_ip="")
        dx = dns.diagnose(c)
        assert dx.healthy is False and "IP" in dx.verdict_ar


def test_diagnose_token_absent(app, monkeypatch):
    with app.app_context():
        c = _cust()
        monkeypatch.setattr(ps, "secret_state", lambda k: (False, "none", False))
        dx = dns.diagnose(c)
        assert dx.token_present is False and dx.healthy is False
        assert "غير مضبوط" in dx.verdict_ar


def test_diagnose_token_present_but_unreadable(app, monkeypatch):
    with app.app_context():
        c = _cust()
        monkeypatch.setattr(ps, "secret_state", lambda k: (True, "db", False))
        dx = dns.diagnose(c)
        assert dx.token_present is True and dx.token_readable is False
        assert dx.healthy is False and "فك تشفير" in dx.verdict_ar


def test_diagnose_zone_unreachable(app, monkeypatch):
    with app.app_context():
        c = _cust()
        monkeypatch.setattr(ps, "secret_state", lambda k: (True, "db", True))
        monkeypatch.setattr(dns.cloudflare, "get_client",
                            lambda: _FakeClient(zone=CfResult(ok=False, error="zone not found: hoberadius.com")))
        dx = dns.diagnose(c)
        assert dx.zone_ok is False and dx.healthy is False
        assert "النطاق" in dx.verdict_ar


def test_diagnose_record_missing(app, monkeypatch):
    with app.app_context():
        c = _cust()
        monkeypatch.setattr(ps, "secret_state", lambda k: (True, "db", True))
        monkeypatch.setattr(dns.cloudflare, "get_client", lambda: _FakeClient())  # zone ok, record None
        dx = dns.diagnose(c)
        assert dx.zone_ok is True and dx.record_exists is False and dx.healthy is False
        assert "لا يوجد سجل" in dx.verdict_ar


def test_diagnose_record_proxied(app, monkeypatch):
    with app.app_context():
        c = _cust()
        rec = DnsRecord(id="r1", name="client1.hoberadius.com", type="A", content=IP, proxied=True)
        monkeypatch.setattr(ps, "secret_state", lambda k: (True, "db", True))
        monkeypatch.setattr(dns.cloudflare, "get_client",
                            lambda: _FakeClient(record=CfResult(ok=True, zone_id="z", record=rec)))
        dx = dns.diagnose(c)
        assert dx.record_exists is True and dx.record_proxied is True and dx.healthy is False
        assert "بروكسي" in dx.verdict_ar


def test_diagnose_record_ip_mismatch(app, monkeypatch):
    with app.app_context():
        c = _cust()
        rec = DnsRecord(id="r1", name="client1.hoberadius.com", type="A", content="1.2.3.4", proxied=False)
        monkeypatch.setattr(ps, "secret_state", lambda k: (True, "db", True))
        monkeypatch.setattr(dns.cloudflare, "get_client",
                            lambda: _FakeClient(record=CfResult(ok=True, zone_id="z", record=rec)))
        dx = dns.diagnose(c)
        assert dx.record_exists is True and dx.record_matches_ip is False and dx.healthy is False
        assert "1.2.3.4" in dx.verdict_ar


def test_diagnose_healthy(app, monkeypatch):
    with app.app_context():
        c = _cust()
        rec = DnsRecord(id="r1", name="client1.hoberadius.com", type="A", content=IP, proxied=False)
        monkeypatch.setattr(ps, "secret_state", lambda k: (True, "db", True))
        monkeypatch.setattr(dns.cloudflare, "get_client",
                            lambda: _FakeClient(record=CfResult(ok=True, zone_id="z", record=rec)))
        dx = dns.diagnose(c)
        assert dx.healthy is True and dx.record_matches_ip is True
        assert "سليم" in dx.verdict_ar


# ── route ─────────────────────────────────────────────────────────────────--
def test_dns_diagnose_route(app, client, monkeypatch):
    with app.app_context():
        c = _cust()
        cid = c.id
        aid = Admin.query.first().id
        monkeypatch.setattr(ps, "secret_state", lambda k: (False, "none", False))
    with client.session_transaction() as s:
        s["admin_id"] = aid
    r = client.post(f"/admin/customers/{cid}/dns-diagnose", follow_redirects=False)
    assert r.status_code in (301, 302)
    assert f"/admin/customers/{cid}/edit" in r.headers["Location"]
