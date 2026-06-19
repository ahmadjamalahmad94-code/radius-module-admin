"""DNS sync fails LOUD + SPECIFIC, never fake-success (owner requirement).

Every Cloudflare/transport failure must (a) leave the customer UNSYNCED, and
(b) produce a specific Arabic message naming the real cause (token invalid /
zone not found / timeout / generic + the raw Cloudflare detail).
"""
from __future__ import annotations

import pytest

from app.extensions import db
from app.models import Admin, Customer
from app.services import data_connection_dns as dns
from app.services.cloudflare.client import CfResult, DnsRecord

IP = "187.77.70.18"


def _cust(vps_ip=IP):
    c = Customer(company_name="Err Co", email="err@x.com", status="active", vps_ip=vps_ip)
    db.session.add(c)
    db.session.commit()
    return c


class _FakeClient:
    def __init__(self, result):
        self._result = result

    def upsert_a_record(self, zone, fqdn, ip):
        if isinstance(self._result, Exception):
            raise self._result
        return self._result


def _patch_client(monkeypatch, result):
    monkeypatch.setattr(dns.cloudflare, "get_client", lambda: _FakeClient(result))


# ── classifier ────────────────────────────────────────────────────────────--
@pytest.mark.parametrize("err,expected", [
    ("zone not found: hoberadius.com", dns.STATUS_ZONE_NOT_FOUND),
    ("9109: Invalid access token", dns.STATUS_INVALID_TOKEN),
    ("10000: Authentication error", dns.STATUS_INVALID_TOKEN),
    ("6003: Invalid request headers", dns.STATUS_INVALID_TOKEN),
    ("The read operation timed out", dns.STATUS_TIMEOUT),
    ("1003: something else", dns.STATUS_API_ERROR),
    ("", dns.STATUS_API_ERROR),
])
def test_classify_cf_error(err, expected):
    assert dns._classify_cf_error(err) == expected


# ── failure paths → specific status, UNSYNCED, detail surfaced ───────────────
@pytest.mark.parametrize("cf_error,status,phrase", [
    ("9109: Invalid access token", dns.STATUS_INVALID_TOKEN, "غير صالح"),
    ("zone not found: hoberadius.com", dns.STATUS_ZONE_NOT_FOUND, "غير موجود"),
    ("The read operation timed out", dns.STATUS_TIMEOUT, "مهلة"),
    ("500: upstream boom", dns.STATUS_API_ERROR, "رفض Cloudflare"),
])
def test_sync_failure_is_specific_and_unsynced(app, monkeypatch, cf_error, status, phrase):
    with app.app_context():
        c = _cust()
        _patch_client(monkeypatch, CfResult(ok=False, error=cf_error))
        res = dns.ensure_subdomain_record(c, commit=True)
        assert res.status == status
        assert res.ok is False
        assert phrase in res.message_ar
        assert cf_error in res.message_ar           # the REAL detail is surfaced
        # state stays NOT synced
        c2 = db.session.get(Customer, c.id)
        assert (c2.dns_record_id or "") == ""
        assert c2.dns_synced_at is None


def test_sync_not_configured_is_unsynced(app, monkeypatch):
    with app.app_context():
        c = _cust()
        monkeypatch.setattr(dns.cloudflare, "get_client", lambda: None)
        res = dns.ensure_subdomain_record(c, commit=True)
        assert res.status == dns.STATUS_NOT_CONFIGURED and res.ok is False
        assert "غير مضبوط" in res.message_ar
        assert (db.session.get(Customer, c.id).dns_record_id or "") == ""


def test_sync_success_but_no_record_id_is_failure(app, monkeypatch):
    with app.app_context():
        c = _cust()
        _patch_client(monkeypatch, CfResult(ok=True, record=None))   # success env, no record
        res = dns.ensure_subdomain_record(c, commit=True)
        assert res.ok is False and res.status == dns.STATUS_API_ERROR
        assert (db.session.get(Customer, c.id).dns_record_id or "") == ""


def test_sync_client_exception_is_loud_not_500(app, monkeypatch):
    with app.app_context():
        c = _cust()
        _patch_client(monkeypatch, RuntimeError("boom"))
        res = dns.ensure_subdomain_record(c, commit=True)
        assert res.ok is False and res.status == dns.STATUS_API_ERROR
        assert (db.session.get(Customer, c.id).dns_record_id or "") == ""


# ── success path still works ─────────────────────────────────────────────────
def test_sync_real_success_marks_synced(app, monkeypatch):
    with app.app_context():
        c = _cust()
        rec = DnsRecord(id="rec-123", name="x", type="A", content=IP, proxied=False)
        _patch_client(monkeypatch, CfResult(ok=True, record=rec))
        res = dns.ensure_subdomain_record(c, commit=True)
        assert res.ok is True and res.status == dns.STATUS_OK
        c2 = db.session.get(Customer, c.id)
        assert c2.dns_record_id == "rec-123" and c2.dns_synced_at is not None


# ── route flashes the error + leaves state unsynced ──────────────────────────
def test_sync_route_flashes_error_and_stays_unsynced(app, client, monkeypatch):
    with app.app_context():
        c = _cust()
        cid = c.id
        aid = Admin.query.first().id
        _patch_client(monkeypatch, CfResult(ok=False, error="9109: Invalid access token"))
    with client.session_transaction() as s:
        s["admin_id"] = aid
    r = client.post(f"/admin/customers/{cid}/dns-sync", data={"action": "sync"}, follow_redirects=True)
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "غير صالح" in body or "Invalid access token" in body   # error toast shown
    with app.app_context():
        assert (db.session.get(Customer, cid).dns_record_id or "") == ""
