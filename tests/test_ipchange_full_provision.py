"""Phase 2 «full IP change» — pricing, monthly term, and approval → SSTP provision.

Verifies the licensing-panel side: per-Mbps pricing (admin-configurable), monthly
validity + renewal, and that APPROVING an ip_change_vpn request with the
provision flag creates an SSTP user (rate-limit = speed, UNLIMITED data) on the
chosen CHR (manual) or auto (brain), and that the credentials + server IP + speed
are deliverable to the customer over the existing pull bridge.
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from app.extensions import db
from app.models import (
    Admin, Customer, CustomerVpnEntitlement, CustomerVpnTunnel, License, Plan, utcnow,
)
from fleet.registry.models_chr import FleetChrNode, FleetProvider
from app.services import ip_change_pricing as ipx
from app.services import vpn_tunnels as vt
from app.services.customer_control import create_customer_service_request


# ── stub the CHR REST client (no real RouterOS) ──────────────────────────────
class _StubClient:
    last_host = ""

    def __init__(self, **kw):
        type(self).last_host = kw.get("host", "")

    def ensure_ip_pool(self, **kw): return {}
    def ensure_ppp_profile(self, **kw): return {}
    def create_ppp_secret(self, **kw): return {".id": "*A1"}
    def remove_ppp_secret(self, _id): return None


@pytest.fixture(autouse=True)
def _stub_node_client(monkeypatch):
    from app.services import fleet_node_router
    _StubClient.last_host = ""
    monkeypatch.setattr(fleet_node_router, "build_client_for",
                        lambda node: _StubClient(host=(node.public_ip or node.wg_mgmt_ip)))


def _provider():
    p = FleetProvider(name="prov", cost_model="open", price_per_tb=0)
    db.session.add(p); db.session.flush()
    return p


def _node(prov, *, name="chr-1", public_ip="203.0.113.9", wg="10.99.0.21", sessions=0):
    n = FleetChrNode(provider_id=prov.id, name=name, public_ip=public_ip,
                     wg_mgmt_ip=wg, wg_mgmt_pubkey="k", routeros_api_port=8443,
                     routeros_api_user="hobe", routeros_api_password_enc="",
                     coa_port=3799, max_sessions=1000, link_speed_mbps=1000,
                     status="up", enabled=True, drain=False, active_sessions=sessions)
    db.session.add(n); db.session.commit()
    return n


def _cust_lic(email="ipx@example.com"):
    plan = Plan.query.first() or Plan(name="basic", slug="basic")
    if plan.id is None:
        db.session.add(plan); db.session.flush()
    c = Customer(company_name="IPX Co", email=email, status="active")
    db.session.add(c); db.session.flush()
    now = utcnow()
    lic = License(customer_id=c.id, plan_id=plan.id, license_key=f"LIC-IPX-{c.id}",
                  status="active", starts_at=now - timedelta(days=1),
                  expires_at=now + timedelta(days=365), grace_until=now + timedelta(days=372))
    db.session.add(lic); db.session.commit()
    return c, lic


def _admin(client):
    with client.session_transaction() as s:
        s["admin_id"] = Admin.query.first().id


# ── pricing ───────────────────────────────────────────────────────────────---
def test_price_per_mbps_default_set_get(app):
    with app.app_context():
        assert ipx.get_price_per_mbps() == ipx.DEFAULT_PRICE_PER_MBPS
        ipx.set_price_per_mbps("0.75"); db.session.commit()
        assert str(ipx.get_price_per_mbps()) == "0.75"


def test_monthly_price_is_speed_times_rate(app):
    with app.app_context():
        ipx.set_price_per_mbps("0.50"); db.session.commit()
        assert float(ipx.monthly_price(100)) == 50.0     # 100 Mbps × 0.50
        assert float(ipx.monthly_price(0)) == 0.0


def test_price_validation(app):
    with app.app_context():
        with pytest.raises(ipx.IpChangePricingError):
            ipx.set_price_per_mbps("abc")
        with pytest.raises(ipx.IpChangePricingError):
            ipx.set_price_per_mbps("-5")


# ── monthly term + renewal ───────────────────────────────────────────────────
def test_monthly_expiry_one_month_ahead(app):
    with app.app_context():
        from datetime import datetime
        base = datetime(2026, 1, 31, 12, 0, 0)
        nxt = ipx.add_one_month(base)
        assert nxt.month == 2 and nxt.day == 28      # clamps Jan-31 → Feb-28


def test_renew_extends_one_month(app):
    with app.app_context():
        c, _lic = _cust_lic()
        from app.services.vpn_entitlements import get_or_create_customer_vpn_entitlement
        ent = get_or_create_customer_vpn_entitlement(c)
        ent.expires_at = utcnow() + timedelta(days=5)
        db.session.add(ent); db.session.commit()
        before = ent.expires_at
        new_exp = ipx.renew_ip_change(c); db.session.commit()
        assert new_exp > before                       # extended


# ── approval → provision SSTP (manual CHR) ───────────────────────────────────
def test_approve_provisions_sstp_unlimited_monthly_on_chosen_chr(app, client):
    with app.app_context():
        ipx.set_price_per_mbps("0.50"); db.session.commit()
        c, lic = _cust_lic()
        prov = _provider()
        node = _node(prov, name="chr-pick", public_ip="203.0.113.50")
        cid, nid = c.id, node.id
        req = create_customer_service_request(
            customer=c, service_key="ip_change_vpn", request_type="activation",
            desired_limits={"download_mbps": 100, "upload_mbps": 100})
        db.session.commit()
        rid = req.id
    _admin(client)
    r = client.post(f"/admin/service-requests/{rid}/approve", data={
        "provision_sstp": "1",
        "download_mbps": "100",
        "fleet_chr_node_id": str(nid),
        "price_monthly": "50.00",
    }, follow_redirects=False)
    assert r.status_code in (301, 302)
    with app.app_context():
        t = (CustomerVpnTunnel.query.filter_by(customer_id=cid, tunnel_type="sstp").one())
        assert t.fleet_chr_node_id == nid                       # manual CHR honored
        assert t.download_mbps == 100 and t.upload_mbps == 100
        assert "100M/100M" in (t.rate_limit or "")              # rate-limit = speed
        assert t.monthly_quota_gb is None                       # DATA UNLIMITED
        assert t.status == "active" and t.chr_provisioned is True
        ent = CustomerVpnEntitlement.query.filter_by(customer_id=cid).one()
        assert ent.traffic_quota_gb is None                     # unlimited
        assert ent.expires_at is not None                       # monthly term set
        assert ent.expires_at > utcnow() + timedelta(days=20)
        # price stored on the service entitlement
        from app.models import CustomerServiceEntitlement
        se = CustomerServiceEntitlement.query.filter_by(customer_id=cid, service_key="ip_change_vpn").one()
        assert float(se.price_monthly) == 50.0


# ── approval → auto CHR (brain) ──────────────────────────────────────────────
def test_approve_auto_assigns_chr_when_no_pick(app, client):
    with app.app_context():
        c, lic = _cust_lic(email="ipxauto@example.com")
        prov = _provider()
        only = _node(prov, name="chr-only", public_ip="203.0.113.77")
        cid, only_id = c.id, only.id
        req = create_customer_service_request(
            customer=c, service_key="ip_change_vpn", request_type="activation",
            desired_limits={"download_mbps": 250})
        db.session.commit()
        rid = req.id
    _admin(client)
    client.post(f"/admin/service-requests/{rid}/approve", data={
        "provision_sstp": "1", "download_mbps": "250", "fleet_chr_node_id": "",
    }, follow_redirects=False)
    with app.app_context():
        t = CustomerVpnTunnel.query.filter_by(customer_id=cid, tunnel_type="sstp").one()
        assert t.fleet_chr_node_id == only_id                   # auto-picked the node
        assert t.download_mbps == 250


# ── bridge delivery includes creds + server IP + speed ───────────────────────
def test_bridge_payload_has_creds_ip_speed(app):
    with app.app_context():
        c, lic = _cust_lic(email="ipxbridge@example.com")
        prov = _provider()
        node = _node(prov, name="chr-b", public_ip="203.0.113.88")
        t = ipx.provision_ip_change(c, lic, speed_mbps=100, fleet_chr_node_id=node.id)
        db.session.commit()
        payload = vt.serialize_tunnel(t, include_password=True)
        assert payload["username"] and payload["password"]      # credentials
        assert payload["chr_host"] == "203.0.113.88"            # server IP (CHR public)
        assert payload["download_mbps"] == 100                  # speed
        assert t in vt.deliverable_tunnels(c)                   # pullable over the bridge


# ── METHOD routing (merged «تغيير عنوان الإنترنت») ────────────────────────────
def test_server_public_ip_method_grants_without_tunnel(app, client):
    """The server-public-IP method grants the entitlement (capability on) but
    routes AWAY from SSTP provisioning even with the checkbox + a CHR pick — the
    actual IP change is the radius src-nat adapter / CHR-move, not a tunnel."""
    with app.app_context():
        c, lic = _cust_lic(email="ipxmethod@example.com")
        prov = _provider()
        node = _node(prov, name="chr-m", public_ip="203.0.113.99")
        cid, nid = c.id, node.id
        req = create_customer_service_request(
            customer=c, service_key="ip_change_vpn", request_type="activation",
            desired_limits={"method": "server_public_ip", "download_mbps": 100})
        db.session.commit()
        rid = req.id
    _admin(client)
    r = client.post(f"/admin/service-requests/{rid}/approve", data={
        "provision_sstp": "1", "download_mbps": "100", "fleet_chr_node_id": str(nid),
    }, follow_redirects=False)
    assert r.status_code in (301, 302)
    with app.app_context():
        from app.models import CustomerServiceEntitlement
        assert CustomerVpnTunnel.query.filter_by(customer_id=cid).count() == 0   # NO tunnel
        ve = CustomerVpnEntitlement.query.filter_by(customer_id=cid).one()
        assert ve.enabled is True and ve.status == "active"                      # granted
        se = CustomerServiceEntitlement.query.filter_by(customer_id=cid, service_key="ip_change_vpn").one()
        assert (se.config or {}).get("method") == "server_public_ip"             # method recorded


def test_tunnel_method_records_method_and_provisions(app, client):
    """The tunnel method records its method AND provisions the SSTP backend."""
    with app.app_context():
        c, lic = _cust_lic(email="ipxtun@example.com")
        prov = _provider()
        node = _node(prov, name="chr-t", public_ip="203.0.113.41")
        cid, nid = c.id, node.id
        req = create_customer_service_request(
            customer=c, service_key="ip_change_vpn", request_type="activation",
            desired_limits={"method": "tunnel", "download_mbps": 100, "upload_mbps": 100})
        db.session.commit()
        rid = req.id
    _admin(client)
    client.post(f"/admin/service-requests/{rid}/approve", data={
        "provision_sstp": "1", "download_mbps": "100", "fleet_chr_node_id": str(nid),
    }, follow_redirects=False)
    with app.app_context():
        from app.models import CustomerServiceEntitlement
        t = CustomerVpnTunnel.query.filter_by(customer_id=cid, tunnel_type="sstp").one()
        assert t.status == "active"                                              # tunnel backend live
        se = CustomerServiceEntitlement.query.filter_by(customer_id=cid, service_key="ip_change_vpn").one()
        assert (se.config or {}).get("method") == "tunnel"


# ── legacy traffic-quota path is untouched (no provision flag) ───────────────
def test_legacy_quota_path_unchanged_without_flag(app, client):
    with app.app_context():
        c, lic = _cust_lic(email="ipxlegacy@example.com")
        cid = c.id
        req = create_customer_service_request(
            customer=c, service_key="ip_change_vpn", request_type="activation",
            desired_limits={"download_mbps": 50, "upload_mbps": 50, "quota_gb": 500})
        db.session.commit()
        rid = req.id
    _admin(client)
    client.post(f"/admin/service-requests/{rid}/approve", data={
        "download_mbps": "50", "traffic_quota_gb": "500",   # NO provision_sstp
    }, follow_redirects=False)
    with app.app_context():
        ent = CustomerVpnEntitlement.query.filter_by(customer_id=cid).one()
        assert ent.traffic_quota_gb == 500                  # legacy quota preserved
        assert CustomerVpnTunnel.query.filter_by(customer_id=cid).count() == 0   # no tunnel
