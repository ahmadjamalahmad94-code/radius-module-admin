"""اختبارات التحكّم بالسرعة: بروفايلات السرعة المركزية + تطبيق rate-limit عند التزويد.

استدعاءات RouterOS مُستبدَلة (monkeypatch) — لا اتصال بأي CHR حقيقي.
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from app.extensions import db
from app.models import (
    ChrSpeedProfile,
    Customer,
    CustomerVpnEntitlement,
    CustomerVpnTunnel,
    License,
    Plan,
    utcnow,
)
from app.services import chr_settings, speed_profiles, vpn_tunnels
from app.services.routeros_client import RouterOSError


# ───────────────────────── fixtures ─────────────────────────

def _configure_chr():
    chr_settings.validate_and_save(
        {"host": "vpn-test.hoberadius.com", "port": "8443", "username": "admin",
         "password": "s3cret-chr-pass", "use_tls": "1", "verify_tls": ""},
        actor_audit=lambda *a, **k: None,
    )
    db.session.commit()


@pytest.fixture()
def customer(app):
    plan = Plan.query.filter_by(slug="pro").first()
    cust = Customer(company_name="Speed ISP", status="active")
    db.session.add(cust)
    db.session.flush()
    db.session.add(License(
        customer_id=cust.id, plan_id=plan.id, license_key="HBR-SPEED-TEST-1",
        status="active", starts_at=utcnow(), expires_at=utcnow() + timedelta(days=30),
        max_fingerprints=3,
    ))
    db.session.add(CustomerVpnEntitlement(
        customer_id=cust.id, enabled=True, status="active",
        download_mbps=100, upload_mbps=100, max_vpn_users=10, max_locations=1,
    ))
    db.session.commit()
    return cust


class _FakeClient:
    created: list = []
    profiles_ensured: list = []

    def __init__(self, *a, **k):
        pass

    def ensure_ppp_profile(self, *, name, rate_limit=""):
        _FakeClient.profiles_ensured.append((name, rate_limit))
        return {".id": "*p", "name": name, "rate-limit": rate_limit}

    def create_ppp_secret(self, **kwargs):
        _FakeClient.created.append(kwargs)
        return {".id": f"*{len(_FakeClient.created)}", **kwargs}

    def remove_ppp_secret(self, secret_id):
        pass

    def set_ppp_secret_disabled(self, secret_id, disabled):
        pass

    # IPsec infra (so ipsec provisioning doesn't explode if reached)
    def ensure_ipsec_mode_config(self, **k): return {".id": "*mc"}
    def ensure_ipsec_peer(self, **k): return {".id": "*peer"}
    def ensure_ipsec_identity(self, **k): return {".id": "*id"}
    def find_ipsec_user(self, name): return None
    def create_ipsec_user(self, *, name, password, comment=""):
        return {".id": "*u1", "name": name}
    def remove_ipsec_user(self, user_id): pass
    def set_ipsec_user_disabled(self, user_id, disabled): pass


@pytest.fixture()
def fake_chr(app, monkeypatch):
    _FakeClient.created = []
    _FakeClient.profiles_ensured = []
    monkeypatch.setattr(chr_settings, "build_client", lambda: _FakeClient())
    return _FakeClient


def _make_profile(code="50m", name="باقة 50", down=50, up=50, active=True):
    p = ChrSpeedProfile(name=name, code=code, download_mbps=down, upload_mbps=up, active=active)
    db.session.add(p)
    db.session.commit()
    return p


# ───────────────────────── rate-limit string ─────────────────────────

def test_rate_limit_string_direction():
    # rx=upload, tx=download  ⇒  "<upload>M/<download>M"
    assert speed_profiles.rate_limit_string(50, 10) == "10M/50M"
    assert speed_profiles.rate_limit_string(0, 0) == ""
    assert speed_profiles.rate_limit_string(100, None) == ""


def test_custom_profile_name():
    assert speed_profiles.custom_profile_name(50, 10) == "hob-50d-10u"


# ───────────────────────── profile CRUD (service) ─────────────────────────

def test_create_profile_validation(app):
    with pytest.raises(speed_profiles.SpeedProfileError):
        speed_profiles.create_profile({"name": "", "download_mbps": "10", "upload_mbps": "10"})
    with pytest.raises(speed_profiles.SpeedProfileError):
        speed_profiles.create_profile({"name": "x", "download_mbps": "abc", "upload_mbps": "10"})
    p = speed_profiles.create_profile({"name": "Test", "code": "t1", "download_mbps": "30", "upload_mbps": "20"})
    db.session.commit()
    assert p.code == "t1" and p.download_mbps == 30 and p.upload_mbps == 20
    # duplicate code rejected
    with pytest.raises(speed_profiles.SpeedProfileError):
        speed_profiles.create_profile({"name": "Other", "code": "t1", "download_mbps": "5", "upload_mbps": "5"})


def test_update_and_delete_profile(app):
    p = _make_profile(code="d1")
    speed_profiles.update_profile(p, {"name": "جديد", "download_mbps": "80", "upload_mbps": "40", "active": "1"})
    db.session.commit()
    assert p.name == "جديد" and p.download_mbps == 80
    speed_profiles.delete_profile(p)
    db.session.commit()
    assert speed_profiles.get(p.id) is None


def test_delete_profile_in_use_deactivates(app, customer, fake_chr):
    _configure_chr()
    p = _make_profile(code="inuse")
    lic = customer.licenses.first()
    vpn_tunnels.provision_tunnel(customer, lic, tunnel_type="sstp", speed_profile_id=p.id)
    db.session.commit()
    with pytest.raises(speed_profiles.SpeedProfileError):
        speed_profiles.delete_profile(p)
    db.session.commit()
    # لم يُحذف بل عُطِّل.
    assert speed_profiles.get(p.id) is not None
    assert speed_profiles.get(p.id).active is False


# ───────────────────────── provisioning applies rate-limit ─────────────────────────

def test_provision_with_speed_profile_applies_rate_limit(app, customer, fake_chr):
    _configure_chr()
    p = _make_profile(code="t50", down=50, up=10)
    lic = customer.licenses.first()
    tunnel = vpn_tunnels.provision_tunnel(customer, lic, tunnel_type="sstp", speed_profile_id=p.id)
    db.session.commit()
    # هيّئ بروفايل CHR بالـrate-limit الصحيح قبل إنشاء الحساب.
    assert ("hob-t50", "10M/50M") in fake_chr.profiles_ensured
    # الحساب أُنشئ بهذا البروفايل.
    assert fake_chr.created[0]["profile"] == "hob-t50"
    # السرعة محفوظة على النفق.
    assert tunnel.download_mbps == 50 and tunnel.upload_mbps == 10
    assert tunnel.rate_limit == "10M/50M"
    assert tunnel.speed_profile_id == p.id


def test_provision_with_custom_speed(app, customer, fake_chr):
    _configure_chr()
    lic = customer.licenses.first()
    tunnel = vpn_tunnels.provision_tunnel(
        customer, lic, tunnel_type="pptp", download_mbps=30, upload_mbps=5,
    )
    db.session.commit()
    assert ("hob-30d-5u", "5M/30M") in fake_chr.profiles_ensured
    assert fake_chr.created[0]["profile"] == "hob-30d-5u"
    assert tunnel.download_mbps == 30 and tunnel.rate_limit == "5M/30M"
    assert tunnel.speed_profile_id is None


def test_provision_without_speed_uses_default_no_rate_limit(app, customer, fake_chr):
    _configure_chr()
    lic = customer.licenses.first()
    tunnel = vpn_tunnels.provision_tunnel(customer, lic, tunnel_type="sstp")
    db.session.commit()
    # لم يُهيَّأ أي بروفايل سرعة، والحساب على البروفايل الافتراضي.
    assert fake_chr.profiles_ensured == []
    assert fake_chr.created[0]["profile"] == "default"
    assert tunnel.download_mbps is None and tunnel.rate_limit == ""


def test_invalid_speed_profile_rejected(app, customer, fake_chr):
    _configure_chr()
    lic = customer.licenses.first()
    with pytest.raises(vpn_tunnels.VpnTunnelError) as exc:
        vpn_tunnels.provision_tunnel(customer, lic, tunnel_type="sstp", speed_profile_id=999999)
    assert exc.value.code == "invalid_speed_profile"


def test_ipsec_speed_recorded_only_not_shaped(app, customer, fake_chr):
    _configure_chr()
    lic = customer.licenses.first()
    tunnel = vpn_tunnels.provision_tunnel(
        customer, lic, tunnel_type="ipsec", download_mbps=40, upload_mbps=20, source="admin_manual",
    )
    db.session.commit()
    # لا rate-limit مطبَّق على IPsec، لكنها مسجَّلة + ملاحظة صريحة.
    assert tunnel.rate_limit == ""
    assert tunnel.download_mbps == 40 and tunnel.upload_mbps == 20
    assert fake_chr.profiles_ensured == []  # لم يُهيَّأ بروفايل PPP لـ IPsec
    assert "IPsec" in tunnel.notes or "queue" in tunnel.notes


def test_serialize_tunnel_includes_speed(app, customer, fake_chr):
    _configure_chr()
    p = _make_profile(code="t100", down=100, up=100)
    lic = customer.licenses.first()
    tunnel = vpn_tunnels.provision_tunnel(customer, lic, tunnel_type="sstp", speed_profile_id=p.id)
    db.session.commit()
    data = vpn_tunnels.serialize_tunnel(tunnel, include_password=True)
    assert data["download_mbps"] == 100 and data["upload_mbps"] == 100


# ───────────────────────── routes ─────────────────────────

def _login(client):
    return client.post("/login", data={"username": "admin", "password": "admin12345"})


def _csrf(client):
    with client.session_transaction() as sess:
        return sess.get("_csrf_token", "")


def test_speed_profiles_page_renders(app, client):
    _login(client)
    resp = client.get("/admin/chr/speed-profiles")
    assert resp.status_code == 200
    assert "بروفايلات السرعة".encode() in resp.data
    # البروفايلات المزروعة الافتراضية ظاهرة.
    assert "10m".encode() in resp.data


def test_speed_profile_create_route(app, client):
    _login(client)
    token = _csrf(client)
    resp = client.post("/admin/chr/speed-profiles", data={
        "name": "باقة 200", "code": "200m", "download_mbps": "200", "upload_mbps": "200",
        "_csrf_token": token,
    }, follow_redirects=True)
    assert resp.status_code == 200
    assert ChrSpeedProfile.query.filter_by(code="200m").count() == 1


def test_tunnel_form_shows_speed_picker(app, client, customer):
    _login(client)
    resp = client.get(f"/admin/customers/{customer.id}/vpn-tunnels")
    assert resp.status_code == 200
    assert b'name="speed_profile_id"' in resp.data
    assert b'name="download_mbps"' in resp.data
