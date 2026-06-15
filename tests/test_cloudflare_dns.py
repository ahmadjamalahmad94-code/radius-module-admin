"""Tests for the Cloudflare DNS client + DATA-connection DNS orchestration (2c).

The single network seam (``app.services.cloudflare._http``) is stubbed — no
real HTTP. We assert the argv/URL/payload shape the client builds and that the
orchestration writes back the right state on the Customer row.
"""
from __future__ import annotations

import pytest

from app.extensions import db
from app.models import Customer
from app.services.cloudflare import _http
from app.services.cloudflare.client import CloudflareDNSClient, CfResult


API = "https://cf.test/client/v4"


def _ok(result):
    return _http.HttpResult(ok=True, status=200, body={"success": True, "result": result})


def _envelope_err(code, msg, status=400):
    return _http.HttpResult(ok=False, status=status,
                            body={"success": False, "errors": [{"code": code, "message": msg}]})


class Router:
    """Routes stubbed HTTP by (METHOD, url-substring) → HttpResult, records calls."""
    def __init__(self):
        self.calls: list[tuple[str, str, dict | None]] = []
        self.routes: list[tuple[str, str, _http.HttpResult]] = []

    def add(self, method, contains, result):
        self.routes.append((method, contains, result))
        return self

    def _handle(self, method, url, payload=None):
        self.calls.append((method, url, payload))
        for m, contains, result in self.routes:
            if m == method and contains in url:
                return result
        return _http.HttpResult(ok=False, status=500, error="unrouted")

    def install(self, monkeypatch):
        monkeypatch.setattr(_http, "get_json",
                            lambda url, **kw: self._handle("GET", url))
        monkeypatch.setattr(_http, "post_json",
                            lambda url, *, payload, **kw: self._handle("POST", url, payload))
        monkeypatch.setattr(_http, "put_json",
                            lambda url, *, payload, **kw: self._handle("PUT", url, payload))
        monkeypatch.setattr(_http, "delete_json",
                            lambda url, **kw: self._handle("DELETE", url))
        return self


@pytest.fixture()
def client():
    return CloudflareDNSClient("tok-123", api_base=API)


# ── envelope / primitives ────────────────────────────────────────────────────
def test_find_zone_id_ok(monkeypatch, client):
    Router().add("GET", "/zones?name=", _ok([{"id": "zoneABC"}])).install(monkeypatch)
    res = client.find_zone_id("hoberadius.com")
    assert res.ok and res.zone_id == "zoneABC"


def test_find_zone_id_not_found(monkeypatch, client):
    Router().add("GET", "/zones?name=", _ok([])).install(monkeypatch)
    res = client.find_zone_id("nope.com")
    assert not res.ok and "zone not found" in res.error


def test_find_a_record_present_and_absent(monkeypatch, client):
    Router().add("GET", "/dns_records",
                 _ok([{"id": "rec1", "name": "client5.hoberadius.com",
                       "type": "A", "content": "1.2.3.4", "ttl": 120}])).install(monkeypatch)
    res = client.find_a_record("zoneABC", "client5.hoberadius.com")
    assert res.ok and res.record and res.record.id == "rec1"

    Router().add("GET", "/dns_records", _ok([])).install(monkeypatch)
    res = client.find_a_record("zoneABC", "client5.hoberadius.com")
    assert res.ok and res.record is None  # looked up fine, none exists


def test_create_a_record_payload_is_dns_only(monkeypatch, client):
    r = Router().add("POST", "/dns_records",
                     _ok({"id": "recNEW", "name": "c.hoberadius.com",
                          "type": "A", "content": "9.9.9.9"})).install(monkeypatch)
    res = client.create_a_record("zoneABC", "c.hoberadius.com", "9.9.9.9")
    assert res.ok and res.record.id == "recNEW"
    method, url, payload = r.calls[-1]
    assert method == "POST" and "/zones/zoneABC/dns_records" in url
    # DNS-only A record: proxied MUST be False, type A, short TTL.
    assert payload["type"] == "A" and payload["content"] == "9.9.9.9"
    assert payload["proxied"] is False


def test_update_uses_put_on_record_id(monkeypatch, client):
    r = Router().add("PUT", "/dns_records/rec1", _ok({"id": "rec1", "type": "A",
                     "content": "5.5.5.5"})).install(monkeypatch)
    res = client.update_a_record("zoneABC", "rec1", "c.hoberadius.com", "5.5.5.5")
    assert res.ok
    assert r.calls[-1][0] == "PUT" and "/dns_records/rec1" in r.calls[-1][1]


def test_envelope_error_surfaces_code_and_message(monkeypatch, client):
    Router().add("GET", "/zones?name=",
                 _envelope_err(9109, "Invalid access token", status=403)).install(monkeypatch)
    res = client.find_zone_id("hoberadius.com")
    assert not res.ok
    assert "9109" in res.error and "Invalid access token" in res.error


# ── high-level idempotent ops ─────────────────────────────────────────────────
def test_upsert_creates_when_absent(monkeypatch, client):
    r = (Router()
         .add("GET", "/zones?name=", _ok([{"id": "zoneABC"}]))
         .add("GET", "/dns_records", _ok([]))                      # none exists
         .add("POST", "/dns_records", _ok({"id": "recNEW", "type": "A"}))
         .install(monkeypatch))
    res = client.upsert_a_record("hoberadius.com", "client5.hoberadius.com", "1.2.3.4")
    assert res.ok and res.record.id == "recNEW"
    assert [c[0] for c in r.calls] == ["GET", "GET", "POST"]  # zone, lookup, create


def test_upsert_updates_when_present(monkeypatch, client):
    r = (Router()
         .add("GET", "/zones?name=", _ok([{"id": "zoneABC"}]))
         .add("GET", "/dns_records", _ok([{"id": "rec1", "type": "A", "content": "old"}]))
         .add("PUT", "/dns_records/rec1", _ok({"id": "rec1", "type": "A", "content": "1.2.3.4"}))
         .install(monkeypatch))
    res = client.upsert_a_record("hoberadius.com", "client5.hoberadius.com", "1.2.3.4")
    assert res.ok and res.record.id == "rec1"
    assert [c[0] for c in r.calls] == ["GET", "GET", "PUT"]  # no POST — updated in place


def test_delete_with_known_id_skips_lookup(monkeypatch, client):
    r = (Router()
         .add("GET", "/zones?name=", _ok([{"id": "zoneABC"}]))
         .add("DELETE", "/dns_records/rec1", _ok({"id": "rec1"}))
         .install(monkeypatch))
    res = client.delete_a_record("hoberadius.com", "c.hoberadius.com", record_id="rec1")
    assert res.ok
    assert [c[0] for c in r.calls] == ["GET", "DELETE"]  # zone, delete — no record lookup


def test_delete_absent_is_idempotent_success(monkeypatch, client):
    (Router()
     .add("GET", "/zones?name=", _ok([{"id": "zoneABC"}]))
     .add("GET", "/dns_records", _ok([]))     # nothing to delete
     .install(monkeypatch))
    res = client.delete_a_record("hoberadius.com", "c.hoberadius.com")
    assert res.ok  # absent == success for "make sure it's gone"


# ── token gate ────────────────────────────────────────────────────────────────
def test_is_configured_and_get_client_gate(monkeypatch, app):
    from app.services import cloudflare
    with app.app_context():
        monkeypatch.setattr(cloudflare, "get_token", lambda: "")
        assert cloudflare.is_configured() is False
        assert cloudflare.get_client() is None
        monkeypatch.setattr(cloudflare, "get_token", lambda: "tok-xyz")
        assert cloudflare.is_configured() is True
        assert isinstance(cloudflare.get_client(), CloudflareDNSClient)


# ── orchestration (DB-backed) ─────────────────────────────────────────────────
def _customer(**kw):
    c = Customer(company_name=kw.pop("company_name", "Acme"), **kw)
    db.session.add(c)
    db.session.commit()
    return c


class _FakeClient:
    def __init__(self, result):
        self._result = result
        self.upserts = []
        self.deletes = []

    def upsert_a_record(self, zone, fqdn, ip, **kw):
        self.upserts.append((zone, fqdn, ip))
        return self._result

    def delete_a_record(self, zone, fqdn, *, record_id="", **kw):
        self.deletes.append((zone, fqdn, record_id))
        return self._result


def test_ensure_no_ip(app):
    from app.services import data_connection_dns as dns
    with app.app_context():
        c = _customer()
        res = dns.ensure_subdomain_record(c)
        assert res.status == dns.STATUS_NO_IP and not res.ok


def test_ensure_invalid_ip(app):
    from app.services import data_connection_dns as dns
    with app.app_context():
        c = _customer(vps_ip="not-an-ip")
        res = dns.ensure_subdomain_record(c)
        assert res.status == dns.STATUS_INVALID_IP


def test_ensure_not_configured_still_assigns_subdomain(monkeypatch, app):
    from app.services import data_connection_dns as dns
    from app.services import cloudflare
    with app.app_context():
        c = _customer(vps_ip="203.0.113.10")
        monkeypatch.setattr(cloudflare, "get_client", lambda: None)  # no token
        res = dns.ensure_subdomain_record(c)
        assert res.status == dns.STATUS_NOT_CONFIGURED
        assert c.subdomain == f"client{c.id}"        # subdomain assigned regardless
        assert res.fqdn.endswith("hoberadius.com")
        assert c.dns_record_id == ""                  # no record created


def test_ensure_ok_writes_back_state(monkeypatch, app):
    from app.services import data_connection_dns as dns
    from app.services import cloudflare
    with app.app_context():
        c = _customer(vps_ip="203.0.113.10")
        fake = _FakeClient(CfResult(ok=True, record=type("R", (), {"id": "recXYZ"})()))
        monkeypatch.setattr(cloudflare, "get_client", lambda: fake)
        res = dns.ensure_subdomain_record(c)
        assert res.status == dns.STATUS_OK and res.ok
        assert c.dns_record_id == "recXYZ"
        assert c.dns_synced_at is not None
        assert c.dns_status == "synced"
        assert fake.upserts and fake.upserts[0][2] == "203.0.113.10"


def test_ensure_api_error_does_not_write_state(monkeypatch, app):
    from app.services import data_connection_dns as dns
    from app.services import cloudflare
    with app.app_context():
        c = _customer(vps_ip="203.0.113.10")
        fake = _FakeClient(CfResult(ok=False, error="9109: bad token"))
        monkeypatch.setattr(cloudflare, "get_client", lambda: fake)
        res = dns.ensure_subdomain_record(c)
        assert res.status == dns.STATUS_API_ERROR and "bad token" in res.message_ar
        assert c.dns_record_id == ""


def test_remove_clears_state(monkeypatch, app):
    from app.services import data_connection_dns as dns
    from app.services import cloudflare
    with app.app_context():
        c = _customer(vps_ip="203.0.113.10", dns_record_id="recXYZ")
        fake = _FakeClient(CfResult(ok=True))
        monkeypatch.setattr(cloudflare, "get_client", lambda: fake)
        res = dns.remove_subdomain_record(c)
        assert res.status == dns.STATUS_DELETED and res.ok
        assert c.dns_record_id == "" and c.dns_synced_at is None
        assert fake.deletes and fake.deletes[0][2] == "recXYZ"  # known id passed through
