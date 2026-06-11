"""اختبارات تزويد أنفاق CHR المركزية: إعدادات CHR، خدمة التزويد، وجسر الأنفاق.

كل استدعاءات الشبكة لـ RouterOS مُستبدَلة (monkeypatch) فلا نتصل بأي CHR حقيقي،
تمامًا كما تفعل اختبارات whatsapp مع المزوّد.
"""
from __future__ import annotations

import time
from datetime import datetime, timedelta

import pytest

from app.extensions import db
from app.license_signing import sign_license_payload
from app.models import (
    Customer,
    CustomerVpnEntitlement,
    CustomerVpnTunnel,
    License,
    Plan,
    Setting,
    utcnow,
)
from app.services import chr_settings, vpn_tunnels
from app.services.routeros_client import RouterOSClient, RouterOSError


# ───────────────────────── fixtures / helpers ─────────────────────────

@pytest.fixture()
def customer(app):
    plan = Plan.query.filter_by(slug="pro").first()
    cust = Customer(company_name="Test ISP", status="active")
    db.session.add(cust)
    db.session.flush()
    lic = License(
        customer_id=cust.id,
        plan_id=plan.id,
        license_key="HBR-TUNNEL-TEST-0001",
        status="active",
        starts_at=utcnow(),
        expires_at=utcnow() + timedelta(days=30),
        max_fingerprints=3,
    )
    db.session.add(lic)
    # صلاحية VPN تسمح بثلاثة مستخدمين (= ثلاثة أنفاق).
    db.session.add(CustomerVpnEntitlement(
        customer_id=cust.id, enabled=True, status="active",
        download_mbps=50, upload_mbps=50, max_vpn_users=3, max_locations=1,
    ))
    db.session.commit()
    return cust


def _configure_chr():
    """يحفظ بيانات CHR صالحة في الإعدادات (كلمة المرور تُشفَّر)."""
    chr_settings.validate_and_save(
        {
            "host": "vpn-test.hoberadius.com",
            "port": "443",
            "username": "admin",
            "password": "s3cret-chr-pass",
            "use_tls": "1",
            "verify_tls": "",
        },
        actor_audit=lambda *a, **k: None,
    )
    db.session.commit()


class _FakeClient:
    """عميل RouterOS وهمي يسجّل ما أُنشئ/حُذف بدل لمس الشبكة.

    يحاكي idempotency لـ IPsec: ``ip/ipsec/user`` يُخزَّن باسمه، و``ensure_*``
    تُنشئ البنية المشتركة مرّة واحدة وتُحصي الاستدعاءات للتحقق.
    """

    created: list[dict] = []
    removed: list[str] = []
    raise_on_create = False
    # IPsec state
    ipsec_users: dict[str, dict] = {}
    ipsec_removed: list[str] = []
    ipsec_disabled: list[tuple] = []
    infra_calls: dict[str, int] = {}
    # PPP profiles ensured (name, rate_limit) for speed-control assertions.
    profiles_ensured: list[tuple] = []

    def __init__(self, *a, **k):
        pass

    def test_connection(self):
        return {"identity": "CHR-Test", "version": "7.15", "board_name": "CHR", "uptime": "1d"}

    def ensure_ip_pool(self, *, name, ranges="", **_kw):
        return {".id": "*pool", "name": name, "ranges": ranges}

    def ensure_ppp_profile(self, *, name, rate_limit="", **_kw):
        _FakeClient.profiles_ensured.append((name, rate_limit))
        return {".id": "*p", "name": name, "rate-limit": rate_limit}

    def create_ppp_secret(self, **kwargs):
        if _FakeClient.raise_on_create:
            raise RouterOSError("request_invalid", "اسم مستخدم مكرر على CHR.")
        _FakeClient.created.append(kwargs)
        return {".id": f"*{len(_FakeClient.created)}", **kwargs}

    def remove_ppp_secret(self, secret_id):
        _FakeClient.removed.append(secret_id)

    def set_ppp_secret_disabled(self, secret_id, disabled):
        pass

    # ── IPsec ──
    def _bump(self, key):
        _FakeClient.infra_calls[key] = _FakeClient.infra_calls.get(key, 0) + 1

    def ensure_ipsec_mode_config(self, **kwargs):
        self._bump("mode_config")
        return {".id": "*mc", **kwargs}

    def ensure_ipsec_peer(self, **kwargs):
        self._bump("peer")
        return {".id": "*peer", **kwargs}

    def ensure_ipsec_identity(self, **kwargs):
        self._bump("identity")
        return {".id": "*id", **kwargs}

    def find_ipsec_user(self, name):
        return _FakeClient.ipsec_users.get(name)

    def create_ipsec_user(self, *, name, password, comment=""):
        if _FakeClient.raise_on_create:
            raise RouterOSError("request_invalid", "تعذّر إنشاء مستخدم IPsec.")
        rec = {".id": f"*u{len(_FakeClient.ipsec_users) + 1}", "name": name, "comment": comment}
        _FakeClient.ipsec_users[name] = rec
        return rec

    def remove_ipsec_user(self, user_id):
        _FakeClient.ipsec_removed.append(user_id)

    def set_ipsec_user_disabled(self, user_id, disabled):
        _FakeClient.ipsec_disabled.append((user_id, disabled))


@pytest.fixture()
def fake_chr(app, monkeypatch):
    _FakeClient.created = []
    _FakeClient.removed = []
    _FakeClient.raise_on_create = False
    _FakeClient.ipsec_users = {}
    _FakeClient.ipsec_removed = []
    _FakeClient.ipsec_disabled = []
    _FakeClient.infra_calls = {}
    _FakeClient.profiles_ensured = []
    monkeypatch.setattr(chr_settings, "build_client", lambda: _FakeClient())
    return _FakeClient


# ───────────────────────── chr_settings ─────────────────────────

def test_chr_settings_password_encrypted_and_masked(app):
    _configure_chr()
    # القيمة المخزّنة ليست النص الصريح.
    raw = db.session.get(Setting, "chr.password").value
    assert raw and raw != "s3cret-chr-pass"
    state = chr_settings.get_state()
    assert state["configured"] is True
    assert state["fields"]["password"]["present"] is True
    assert "s3cret-chr-pass" not in state["fields"]["password"]["masked"]
    # القيمة الفعّالة تُفكّ صحيحة.
    assert chr_settings.resolved()["password"] == "s3cret-chr-pass"


def test_chr_settings_blank_password_keeps_existing(app):
    _configure_chr()
    chr_settings.validate_and_save(
        {"host": "new-host", "port": "8729", "username": "admin2", "password": "", "use_tls": "1"},
        actor_audit=lambda *a, **k: None,
    )
    db.session.commit()
    assert chr_settings.resolved()["password"] == "s3cret-chr-pass"
    assert chr_settings.resolved()["host"] == "new-host"


def test_chr_settings_requires_host(app):
    with pytest.raises(chr_settings.ChrSettingsError):
        chr_settings.validate_and_save(
            {"host": "", "username": "admin", "password": "x"},
            actor_audit=lambda *a, **k: None,
        )


def test_chr_test_connection_ok(app, fake_chr):
    _configure_chr()
    result = chr_settings.test_connection(actor_audit=lambda *a, **k: None)
    assert result["ok"] is True
    assert result["identity"] == "CHR-Test"


# ───────────────────────── provisioning service ─────────────────────────

def test_provision_sstp_creates_on_chr_and_encrypts_password(app, customer, fake_chr):
    _configure_chr()
    lic = customer.licenses.first()
    tunnel = vpn_tunnels.provision_tunnel(customer, lic, tunnel_type="sstp", source="bridge_request")
    db.session.commit()
    assert tunnel.chr_provisioned is True
    assert tunnel.chr_secret_id
    assert tunnel.status == "active"
    assert len(fake_chr.created) == 1
    assert fake_chr.created[0]["service"] == "sstp"
    # كلمة المرور مخزّنة مشفّرة، وتُفكّ صحيحة.
    assert tunnel.password_encrypted and "password" not in tunnel.password_encrypted.lower()[:4]
    assert len(vpn_tunnels.get_tunnel_password(tunnel)) >= 16


def test_provision_respects_connection_allowance(app, customer, fake_chr):
    _configure_chr()
    lic = customer.licenses.first()
    for _ in range(3):  # الحدّ = 3 (max_vpn_users)
        vpn_tunnels.provision_tunnel(customer, lic, tunnel_type="sstp")
    db.session.commit()
    with pytest.raises(vpn_tunnels.VpnTunnelError) as exc:
        vpn_tunnels.provision_tunnel(customer, lic, tunnel_type="sstp")
    assert exc.value.code == "limit_reached"


def test_provision_chr_failure_persists_nothing(app, customer, fake_chr):
    _configure_chr()
    fake_chr.raise_on_create = True
    lic = customer.licenses.first()
    with pytest.raises(vpn_tunnels.VpnTunnelError) as exc:
        vpn_tunnels.provision_tunnel(customer, lic, tunnel_type="sstp")
    assert exc.value.code == "chr_create_failed"
    db.session.rollback()
    assert CustomerVpnTunnel.query.filter_by(customer_id=customer.id).count() == 0


def test_ipsec_provisions_user_on_chr(app, customer, fake_chr):
    """IPsec يُؤتمت الآن: يُنشأ /ip/ipsec/user وتُهيَّأ البنية المشتركة."""
    _configure_chr()
    lic = customer.licenses.first()
    tunnel = vpn_tunnels.provision_tunnel(customer, lic, tunnel_type="ipsec", source="admin_manual")
    db.session.commit()
    assert tunnel.chr_provisioned is True
    assert tunnel.chr_secret_id  # معرّف /ip/ipsec/user
    assert tunnel.status == "active"
    assert len(fake_chr.ipsec_users) == 1
    # لم يُنشأ /ppp/secret لنوع IPsec.
    assert len(fake_chr.created) == 0
    # البنية المشتركة هُيّئت.
    assert fake_chr.infra_calls.get("mode_config") == 1
    assert fake_chr.infra_calls.get("peer") == 1
    assert fake_chr.infra_calls.get("identity") == 1


def test_ipsec_provisioning_idempotent(app, fake_chr):
    """إعادة التزويد لنفس المستخدم (بعد فقد الرد) لا تُكرّره — يُعاد المعرّف نفسه."""
    _configure_chr()
    client = fake_chr()
    id1 = vpn_tunnels._provision_ipsec_user(client, "c1-fixeduser", "pw-1", "comment")
    id2 = vpn_tunnels._provision_ipsec_user(client, "c1-fixeduser", "pw-1", "comment")
    assert id1 and id1 == id2
    assert len(fake_chr.ipsec_users) == 1


def test_ipsec_record_only_when_automation_disabled(app, customer, fake_chr):
    """عند تعطيل CHR_IPSEC_AUTO_PROVISION يعود السلوك إلى «سجل فقط»."""
    _configure_chr()
    app.config["CHR_IPSEC_AUTO_PROVISION"] = False
    try:
        lic = customer.licenses.first()
        tunnel = vpn_tunnels.provision_tunnel(customer, lic, tunnel_type="ipsec", source="admin_manual")
        db.session.commit()
        assert tunnel.chr_provisioned is False
        assert tunnel.status == "active"
        assert len(fake_chr.ipsec_users) == 0
        assert "IPsec" in tunnel.notes or "سجل" in tunnel.notes
    finally:
        app.config["CHR_IPSEC_AUTO_PROVISION"] = True


def test_ipsec_revoke_removes_user_from_chr(app, customer, fake_chr):
    _configure_chr()
    lic = customer.licenses.first()
    tunnel = vpn_tunnels.provision_tunnel(customer, lic, tunnel_type="ipsec")
    db.session.commit()
    secret_id = tunnel.chr_secret_id
    vpn_tunnels.revoke_tunnel(tunnel)
    db.session.commit()
    assert tunnel.status == "revoked"
    assert secret_id in fake_chr.ipsec_removed


def test_revoke_removes_from_chr(app, customer, fake_chr):
    _configure_chr()
    lic = customer.licenses.first()
    tunnel = vpn_tunnels.provision_tunnel(customer, lic, tunnel_type="sstp")
    db.session.commit()
    vpn_tunnels.revoke_tunnel(tunnel)
    db.session.commit()
    assert tunnel.status == "revoked"
    assert tunnel.chr_secret_id in fake_chr.removed


def test_serialize_hides_password_after_delivery(app, customer, fake_chr):
    _configure_chr()
    lic = customer.licenses.first()
    tunnel = vpn_tunnels.provision_tunnel(customer, lic, tunnel_type="sstp")
    db.session.commit()
    assert "password" in vpn_tunnels.serialize_tunnel(tunnel, include_password=True)
    vpn_tunnels.acknowledge_delivery(customer, [tunnel.username])
    db.session.commit()
    assert "password" not in vpn_tunnels.serialize_tunnel(tunnel, include_password=True)


def test_serialize_includes_public_endpoint_and_service_port(app, customer, fake_chr):
    """رد الجسر يحمل العنوان العام والمنفذ لكل خدمة (يتصل بهما عميلُ العميل)."""
    # عنوان عام مخصّص ومنفذ SSTP مخصّص.
    chr_settings.validate_and_save(
        {
            "host": "mgmt.hoberadius.com", "port": "8729", "username": "admin",
            "password": "s3cret-chr-pass", "use_tls": "1", "verify_tls": "",
            "public_host": "vpn.hoberadius.com", "port_sstp": "4443",
        },
        actor_audit=lambda *a, **k: None,
    )
    db.session.commit()
    lic = customer.licenses.first()
    tunnel = vpn_tunnels.provision_tunnel(customer, lic, tunnel_type="sstp")
    db.session.commit()
    data = vpn_tunnels.serialize_tunnel(tunnel, include_password=True)
    assert data["chr_public_host"] == "vpn.hoberadius.com"
    assert data["service_port"] == 4443


def test_public_endpoint_falls_back_to_admin_host_and_defaults(app):
    """بلا عنوان عام/منافذ مخصّصة: نستخدم المضيف الإداري والمنافذ الافتراضية."""
    _configure_chr()  # host=vpn-test.hoberadius.com، بلا public_host/منافذ خدمات
    ep = chr_settings.public_endpoint()
    assert ep["public_host"] == "vpn-test.hoberadius.com"
    assert ep["ports"]["sstp"] == chr_settings.SERVICE_PORT_DEFAULTS["sstp"]
    assert ep["ports"]["ipsec"] == chr_settings.SERVICE_PORT_DEFAULTS["ipsec"]


# ───────────────────────── bridge endpoints ─────────────────────────

def _signed_body(app, customer, **extra):
    lic = customer.licenses.first()
    body = {
        "license_key": lic.license_key,
        "server_fingerprint": "fp-test-1",
        "nonce": f"n-{time.time()}-{extra.get('_n','')}",
        "timestamp": int(time.time()),
        **{k: v for k, v in extra.items() if not k.startswith("_")},
    }
    secret = app.config["LICENSE_CHECK_HMAC_SECRET"] or "test-secret"
    app.config["LICENSE_CHECK_HMAC_SECRET"] = secret
    body["signature"] = sign_license_payload(body, secret)
    return body


def test_bridge_request_provisions_and_returns_password(app, client, customer, fake_chr):
    _configure_chr()
    app.config["LICENSE_CHECK_SIGNATURE_REQUIRED"] = True
    app.config["LICENSE_CHECK_ALLOW_UNSIGNED"] = False
    # أول بصمة تُسجّل تلقائيًا (max_fingerprints=3) فالترخيص يبقى نشطًا.
    body = _signed_body(app, customer, _n="req")
    resp = client.post(
        "/api/integration/hoberadius/vpn/tunnels/request",
        json=body,
        headers={"X-Forwarded-Proto": "https"},
        environ_overrides={"wsgi.url_scheme": "https"},
    )
    assert resp.status_code == 201, resp.get_json()
    data = resp.get_json()
    assert data["ok"] is True
    assert data["tunnel"]["password"]
    assert data["tunnel"]["tunnel_type"] == "sstp"


def test_bridge_list_then_ack_hides_password(app, client, customer, fake_chr):
    _configure_chr()
    app.config["LICENSE_CHECK_SIGNATURE_REQUIRED"] = True
    app.config["LICENSE_CHECK_ALLOW_UNSIGNED"] = False
    lic = customer.licenses.first()
    tunnel = vpn_tunnels.provision_tunnel(customer, lic, tunnel_type="sstp")
    db.session.commit()
    username = tunnel.username

    body = _signed_body(app, customer, _n="list")
    resp = client.post(
        "/api/integration/hoberadius/vpn/tunnels",
        json=body,
        environ_overrides={"wsgi.url_scheme": "https"},
    )
    data = resp.get_json()
    assert data["ok"] is True
    assert any(t.get("password") for t in data["tunnels"])

    ack = _signed_body(app, customer, usernames=[username], _n="ack")
    resp2 = client.post(
        "/api/integration/hoberadius/vpn/tunnels/ack",
        json=ack,
        environ_overrides={"wsgi.url_scheme": "https"},
    )
    assert resp2.get_json()["acknowledged"] == 1

    body2 = _signed_body(app, customer, _n="list2")
    resp3 = client.post(
        "/api/integration/hoberadius/vpn/tunnels",
        json=body2,
        environ_overrides={"wsgi.url_scheme": "https"},
    )
    assert all("password" not in t for t in resp3.get_json()["tunnels"])


def test_bridge_request_unsigned_rejected(app, client, customer, fake_chr):
    _configure_chr()
    app.config["LICENSE_CHECK_SIGNATURE_REQUIRED"] = True
    app.config["LICENSE_CHECK_ALLOW_UNSIGNED"] = False
    lic = customer.licenses.first()
    resp = client.post(
        "/api/integration/hoberadius/vpn/tunnels/request",
        json={"license_key": lic.license_key, "server_fingerprint": "fp"},
        environ_overrides={"wsgi.url_scheme": "https"},
    )
    assert resp.status_code == 401


def test_bridge_request_requires_https(app, client, customer, fake_chr):
    _configure_chr()
    resp = client.post(
        "/api/integration/hoberadius/vpn/tunnels/request",
        json={"license_key": "x", "server_fingerprint": "y"},
    )
    assert resp.status_code == 426


# ───────────────────────── admin UI render ─────────────────────────

def _login(client):
    return client.post("/login", data={"username": "admin", "password": "admin12345"})


def test_settings_page_shows_chr_section(app, client):
    _login(client)
    resp = client.get("/admin/settings")
    assert resp.status_code == 200
    # The CHR connection section lives in the live settings page (general_new.html)
    # as the «MikroTik CHR» tab — it was previously orphaned in the unused
    # settings.html. Assert the tab + its save form are present.
    assert "MikroTik CHR".encode() in resp.data
    assert b'id="tab-chr"' in resp.data
    assert b'action="/admin/settings/chr"' in resp.data


def test_customer_tunnels_page_renders(app, client, customer):
    _login(client)
    resp = client.get(f"/admin/customers/{customer.id}/vpn-tunnels")
    assert resp.status_code == 200
    assert "أنفاق VPN المركزية".encode() in resp.data


def test_admin_manual_create_tunnel(app, client, customer, fake_chr):
    _configure_chr()
    _login(client)
    with client.session_transaction() as sess:
        token = sess.get("_csrf_token", "")
    resp = client.post(
        f"/admin/customers/{customer.id}/vpn-tunnels",
        data={"tunnel_type": "pptp", "profile": "default", "max_connections": "1", "_csrf_token": token},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert CustomerVpnTunnel.query.filter_by(customer_id=customer.id, tunnel_type="pptp").count() == 1


# ───────────────────────── routeros client (offline) ─────────────────────────

def test_routeros_client_not_configured_raises():
    client = RouterOSClient(host="", username="a", password="b")
    with pytest.raises(RouterOSError) as exc:
        client._request("GET", "system/resource")
    assert exc.value.code == "not_configured"


def test_routeros_password_never_in_error():
    client = RouterOSClient(host="", username="admin", password="TOPSECRET")
    try:
        client._request("GET", "system/resource")
    except RouterOSError as exc:
        assert "TOPSECRET" not in str(exc)
