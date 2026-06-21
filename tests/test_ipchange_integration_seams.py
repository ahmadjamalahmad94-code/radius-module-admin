"""IP-change licensing integration seams: bridge intake, creds payload, monthly sweep."""
from __future__ import annotations

from datetime import timedelta

import pytest

from app.extensions import db
from app.models import (
    Customer, CustomerServiceRequest, CustomerVpnEntitlement, CustomerVpnTunnel,
    License, Plan, utcnow,
)
from fleet.registry.models_chr import FleetChrNode, FleetProvider
from fleet.notify.models_alert import Event
from app.services import ip_change_pricing as ipx
from app.services import ip_change_sweep as sweep
from app.services import vpn_tunnels as vt

HTTPS = {"base_url": "https://license-panel.test"}


def _cust(email="seam@x.com", status="active"):
    c = Customer(company_name="Seam Co", email=email, status=status)
    db.session.add(c); db.session.flush()
    return c


def _active_license(customer):
    plan = Plan.query.first() or Plan(name="b", slug="b")
    if plan.id is None:
        db.session.add(plan); db.session.flush()
    now = utcnow()
    lic = License(customer_id=customer.id, plan_id=plan.id, license_key=f"LIC-SEAM-{customer.id}",
                  status="active", starts_at=now - timedelta(days=1),
                  expires_at=now + timedelta(days=365), grace_until=now + timedelta(days=372))
    db.session.add(lic); db.session.commit()
    return lic


# ── 1. REQUEST INTAKE over the bridge → approval inbox ───────────────────────
def test_normalize_request_desired_limits():
    d = ipx.normalize_request_desired_limits(
        {"requested_speed_mbps": 100, "billing": "monthly", "data": "unlimited"})
    assert d["speed_mbps"] == 100 and d["download_mbps"] == 100 and d["upload_mbps"] == 100
    assert d["billing"] == "monthly" and d["data"] == "unlimited"


def test_customer_ipchange_request_reaches_inbox_via_bridge(app, client):
    with app.app_context():
        c = _cust(email="intake@x.com")
        lic = _active_license(c)
        key = lic.license_key
        cid = c.id
    r = client.post("/api/integration/hoberadius/service-requests", json={
        "license_key": key,
        "service_key": "ip_change_vpn",
        "request_type": "activation",
        "requested_speed_mbps": 100,
        "billing": "monthly",
        "data": "unlimited",
        "notes": "أريد تغيير الـIP بسرعة 100",
    }, **HTTPS)
    assert r.status_code == 201, r.get_data(as_text=True)
    body = r.get_json()
    assert body["ok"] is True and body["service_request"]["service_key"] == "ip_change_vpn"
    with app.app_context():
        sr = (CustomerServiceRequest.query
              .filter_by(customer_id=cid, service_key="ip_change_vpn")
              .order_by(CustomerServiceRequest.id.desc()).first())
        assert sr is not None and sr.status == "pending"          # in the approval inbox
        dl = sr.desired_limits or {}
        assert dl.get("speed_mbps") == 100 and dl.get("download_mbps") == 100
        assert dl.get("data") == "unlimited" and dl.get("billing") == "monthly"
        # the price the approval UI computes from the requested speed
        assert float(ipx.monthly_price(dl["speed_mbps"])) == float(ipx.monthly_price(100))


# ── 2. CREDS DELIVERY payload shape the customer panel expects ───────────────
class _StubClient:
    def __init__(self, **kw): pass
    def ensure_ip_pool(self, **kw): return {}
    def ensure_ppp_profile(self, **kw): return {}
    def create_ppp_secret(self, **kw): return {".id": "*A1"}
    def remove_ppp_secret(self, _id): return None


@pytest.fixture()
def _stub_client(monkeypatch):
    from app.services import fleet_node_router
    monkeypatch.setattr(fleet_node_router, "build_client_for", lambda node: _StubClient())


def _node():
    p = FleetProvider(name="pv", cost_model="open", price_per_tb=0)
    db.session.add(p); db.session.flush()
    n = FleetChrNode(provider_id=p.id, name="chr-seam", public_ip="198.51.100.7",
                     wg_mgmt_ip="10.99.0.7", wg_mgmt_pubkey="k", routeros_api_port=8443,
                     routeros_api_user="h", routeros_api_password_enc="", coa_port=3799,
                     max_sessions=1000, link_speed_mbps=1000, status="up",
                     enabled=True, drain=False, active_sessions=0)
    db.session.add(n); db.session.commit()
    return n


def test_snapshot_publishes_ip_change_creds(app, _stub_client):
    """The capacity/grant snapshot the customer pulls carries services.ip_change
    with the exact creds-display shape after provisioning, and flips to
    status=expired (kept) once the monthly term ends."""
    from app.services.customer_control import build_runtime_contract_for_license
    from app.services.vpn_entitlements import get_or_create_customer_vpn_entitlement
    with app.app_context():
        c = _cust(email="snap@x.com")
        lic = _active_license(c)
        node = _node()
        t = ipx.provision_ip_change(c, lic, speed_mbps=100, fleet_chr_node_id=node.id)
        ent = get_or_create_customer_vpn_entitlement(c)
        ent.enabled = True
        ent.status = "active"
        ent.expires_at = utcnow() + timedelta(days=30)
        db.session.add(ent)
        db.session.commit()

        snap = build_runtime_contract_for_license(lic, license_active=True, status="active")
        ipc = snap["services"]["ip_change"]
        assert ipc["status"] == "provisioned"
        assert ipc["server_host"] == "198.51.100.7" and ipc["server_ip"] == "198.51.100.7"
        assert ipc["sstp_username"] == t.username
        assert ipc["sstp_password"] and ipc["sstp_password_enc"]   # cleartext + Fernet
        assert ipc["speed_mbps"] == 100
        assert ipc["expires_at"]                                   # ISO term end
        assert set(ipc) >= {"status", "server_host", "server_ip", "sstp_username",
                            "sstp_password_enc", "speed_mbps", "expires_at"}

        # persist through expiry → status flips to expired (rollback stays available)
        ent.status = "expired"
        ent.expires_at = utcnow() - timedelta(days=1)
        db.session.add(ent); db.session.commit()
        snap2 = build_runtime_contract_for_license(lic, license_active=True, status="active")
        assert snap2["services"]["ip_change"]["status"] == "expired"


def test_creds_payload_shape_for_customer_ip_page(app, _stub_client):
    with app.app_context():
        c = _cust(email="creds@x.com")
        lic = _active_license(c)
        node = _node()
        t = ipx.provision_ip_change(c, lic, speed_mbps=100, fleet_chr_node_id=node.id)
        db.session.commit()
        p = vt.serialize_tunnel(t, include_password=True)
        # exact keys the customer «تغيير الـIP» page reads
        assert p["server_ip"] == "198.51.100.7"
        assert p["sstp_username"] == t.username
        assert p["sstp_password"] and p["sstp_password"] == p["password"]
        assert p["speed"] == 100 and p["speed_mbps"] == 100


# ── 3. MONTHLY SWEEP marks expired + emits ───────────────────────────────────
def _entitlement(customer, *, expires_in_days, status="active"):
    ent = CustomerVpnEntitlement(customer_id=customer.id, enabled=True, status=status,
                                 download_mbps=100, upload_mbps=100,
                                 expires_at=utcnow() + timedelta(days=expires_in_days))
    db.session.add(ent); db.session.commit()
    return ent


def test_sweep_marks_expired_and_emits_event(app):
    with app.app_context():
        c = _cust(email="sweep@x.com")
        ent = _entitlement(c, expires_in_days=-1)        # term ended yesterday
        cid = c.id
        res = sweep.sweep_expired_ip_change()
        assert cid in res["expired"] and res["count"] >= 1
        ent2 = db.session.get(CustomerVpnEntitlement, ent.id)
        assert ent2.status == "expired" and ent2.enabled is False
        # emitted into the notification backbone (fleet_events)
        ev = (Event.query.filter_by(kind=sweep.EVENT_EXPIRED)
              .order_by(Event.id.desc()).first())
        assert ev is not None and ev.detail.get("customer_id") == cid
        assert ev.detail.get("reason") == "monthly_term_ended"


def test_sweep_is_idempotent(app):
    with app.app_context():
        c = _cust(email="sweep2@x.com")
        _entitlement(c, expires_in_days=-1)
        first = sweep.sweep_expired_ip_change()["count"]
        second = sweep.sweep_expired_ip_change()["count"]   # already expired → no re-emit
        assert first >= 1 and second == 0


def test_sweep_leaves_active_in_term_alone(app):
    with app.app_context():
        c = _cust(email="sweep3@x.com")
        ent = _entitlement(c, expires_in_days=20)
        sweep.sweep_expired_ip_change()
        assert db.session.get(CustomerVpnEntitlement, ent.id).status == "active"


def test_countdown_queryable_within_thresholds(app):
    with app.app_context():
        c3 = _cust(email="cd3@x.com"); _entitlement(c3, expires_in_days=3)
        c30 = _cust(email="cd30@x.com"); _entitlement(c30, expires_in_days=30)
        rows = sweep.ip_change_countdown(thresholds=(7, 3, 1))
        ids = {r["customer_id"] for r in rows}
        assert c3.id in ids and c30.id not in ids        # 3 days in window, 30 not
        row = next(r for r in rows if r["customer_id"] == c3.id)
        assert row["days_left"] in (2, 3) and "expires_at" in row
