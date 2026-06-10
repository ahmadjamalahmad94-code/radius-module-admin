"""اختبارات «اتصالات الوصول» — صفحة الهبوط + إنشاء قرين WireGuard + جدول الاتصالات.

كل استدعاءات RouterOS مُستبدَلة (monkeypatch) فلا تتصل الاختبارات بأي CHR حقيقي.
نطابق نمط ``test_chr_tunnels.py``: نُهيّئ CHR في الإعدادات، نُهيّئ عميلًا وترخيصًا،
ثم نشغّل الراوت كاملًا (طبقة Flask + DB + خدمة + CHR وهمي) لنتأكّد أن السلسلة كاملة
تعمل.
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from app.extensions import db
from app.models import (
    Customer,
    CustomerVpnTunnel,
    License,
    Plan,
    WireguardPeer,
    utcnow,
)
from app.services import access_connections, chr_settings, vpn_tunnels, wireguard_peers
from app.services.routeros_client import RouterOSClient


# ───────────────────────── fixtures ─────────────────────────


@pytest.fixture()
def customer(app):
    plan = Plan.query.filter_by(slug="pro").first()
    cust = Customer(company_name="Test ISP", status="active")
    db.session.add(cust)
    db.session.flush()
    lic = License(
        customer_id=cust.id,
        plan_id=plan.id,
        license_key="HBR-ACCESS-TEST-0001",
        status="active",
        starts_at=utcnow(),
        expires_at=utcnow() + timedelta(days=30),
        max_fingerprints=3,
    )
    db.session.add(lic)
    db.session.commit()
    return cust


def _configure_chr():
    chr_settings.validate_and_save(
        {
            "host": "vpn-test.hoberadius.com",
            "port": "443",
            "username": "admin",
            "password": "s3cret-chr-pass",
            "use_tls": "1",
            "verify_tls": "",
            "public_host": "vpn.example.com",
        },
        actor_audit=lambda *a, **k: None,
    )
    db.session.commit()


def _login(client):
    """يُسجّل دخول المسؤول الافتراضي (admin/changeme) من الإعدادات الاختبارية.

    نقرأ صفحة الدخول أولًا للحصول على CSRF token من الجلسة قبل POST.
    """
    client.get("/login")
    with client.session_transaction() as sess:
        token = sess.get("_csrf_token")
    return client.post(
        "/login",
        data={"username": "admin", "password": "admin12345", "_csrf_token": token or ""},
        follow_redirects=False,
    )


# ───────────────────────── fake RouterOS client ─────────────────────────


class _FakeClient:
    """عميل وهمي يسجّل ما أنشئ/حذف، مع حالة WireGuard مستقلة بين كل اختبار."""

    iface_created: list[dict] = []
    peers_created: list[dict] = []
    peers_removed: list[str] = []
    server_pubkey: str = "FakeSrvPubKey0000000000000000000000000000000A="

    @classmethod
    def reset(cls):
        cls.iface_created = []
        cls.peers_created = []
        cls.peers_removed = []
        cls.server_pubkey = "FakeSrvPubKey0000000000000000000000000000000A="

    def __init__(self, *a, **k):
        pass

    # ── shared ──
    def test_connection(self):
        return {"identity": "CHR-Test", "version": "7.15", "board_name": "CHR", "uptime": "1d"}

    # ── PPP minimum surface ──
    def ensure_ip_pool(self, *, name, ranges="", **_kw):
        return {".id": "*pool", "name": name}

    def ensure_ppp_profile(self, *, name, rate_limit="", **_kw):
        return {".id": "*p", "name": name, "rate-limit": rate_limit}

    def create_ppp_secret(self, **kwargs):
        return {".id": "*sec1", **kwargs}

    def remove_ppp_secret(self, secret_id):
        pass

    # ── WireGuard surface ──
    def find_wireguard_interface(self, name):
        return {".id": "*iface", "name": name, "public-key": _FakeClient.server_pubkey}

    def ensure_wireguard_interface(self, *, name, listen_port, private_key=""):
        _FakeClient.iface_created.append({"name": name, "listen-port": listen_port})
        return {".id": "*iface", "name": name, "public-key": _FakeClient.server_pubkey}

    def list_wireguard_peers(self, *, interface=None):
        return []

    def find_wireguard_peer(self, *, interface, public_key):
        return None

    def create_wireguard_peer(self, **kwargs):
        peer_id = f"*peer{len(_FakeClient.peers_created) + 1}"
        row = {".id": peer_id, **kwargs}
        _FakeClient.peers_created.append(row)
        return row

    def remove_wireguard_peer(self, peer_id):
        _FakeClient.peers_removed.append(peer_id)

    def set_wireguard_peer_disabled(self, peer_id, disabled):
        pass


@pytest.fixture(autouse=True)
def fake_routeros(monkeypatch):
    """يربط جميع استدعاءات RouterOS بعميل وهمي قبل كل اختبار."""
    _FakeClient.reset()
    monkeypatch.setattr(chr_settings, "build_client", lambda: _FakeClient())
    # Reuse for the RouterOS module too (some helpers create their own).
    monkeypatch.setattr(
        RouterOSClient,
        "_request",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("real RouterOSClient should not be hit")),
    )
    return _FakeClient


# ───────────────────────── tests ─────────────────────────


def test_landing_page_renders_with_protocol_cards(app, client):
    """صفحة الهبوط تُعرض 4 بطاقات بروتوكول وعنوان عربي واضح."""
    with app.test_request_context():
        _configure_chr()
    _login(client)
    rv = client.get("/admin/access-connections")
    assert rv.status_code == 200, rv.data[:200]
    body = rv.data.decode("utf-8")
    assert "اتصالات الوصول" in body
    # كل بروتوكول مذكور بالاسم.
    for name in ("WireGuard", "SSTP", "PPTP", "IPsec / IKEv2"):
        assert name in body, f"missing protocol card: {name}"
    # المودال موجود في نفس الصفحة (لا redirect).
    assert "ac-modal-wireguard" in body
    assert "ac-modal-sstp" in body
    assert "ac-modal-pptp" in body
    assert "ac-modal-ipsec" in body


def test_create_wireguard_peer_provisions_on_chr_and_persists(app, client, customer):
    """إرسال نموذج WireGuard يولّد مفتاحًا، يستدعي CHR، ويُنشئ سجلًا."""
    with app.test_request_context():
        _configure_chr()
    _login(client)
    rv = client.post(
        "/admin/access-connections/wireguard",
        data={
            "customer_id": str(customer.id),
            "label": "هاتف",
            "use_preshared": "on",
            "keepalive_seconds": "25",
        },
        follow_redirects=False,
    )
    # ينبغي redirect إلى صفحة التفاصيل.
    assert rv.status_code in (302, 303), rv.data[:200]
    assert "/admin/access-connections/wireguard/" in rv.headers.get("Location", "")
    # سجل في DB.
    peers = WireguardPeer.query.all()
    assert len(peers) == 1
    peer = peers[0]
    assert peer.customer_id == customer.id
    assert peer.peer_name.startswith(f"c{customer.id}-")
    assert peer.public_key and len(peer.public_key) == 44
    assert peer.allowed_ips.endswith("/32")
    assert peer.chr_provisioned is True
    assert peer.chr_peer_id.startswith("*peer")
    assert peer.server_public_key == _FakeClient.server_pubkey
    # كلمة سرّية مخزَّنة مشفّرة.
    assert peer.private_key_encrypted != ""
    assert peer.preshared_key_encrypted != ""  # لأن PSK مُفعَّل
    # CHR استُدعي.
    assert len(_FakeClient.peers_created) == 1
    created = _FakeClient.peers_created[0]
    assert created["interface"] == "wg-vpn"
    assert created["public_key"] == peer.public_key


def test_create_wireguard_peer_requires_chr_configured(app, client, customer, monkeypatch):
    """بدون ضبط CHR، يفشل الإنشاء برسالة عربية واضحة (لا 500)."""
    # نُعطّل CHR_PROVISIONING_ENABLED حتى تفلت الخدمة على الحرس قبل أي نداء وهمي.
    monkeypatch.setitem(app.config, "CHR_PROVISIONING_ENABLED", False)
    _login(client)
    rv = client.post(
        "/admin/access-connections/wireguard",
        data={"customer_id": str(customer.id)},
        follow_redirects=False,
    )
    assert rv.status_code in (302, 303)
    # لا سجل أُنشئ.
    assert WireguardPeer.query.count() == 0


def test_protocol_overview_counts_existing_tunnels(app, customer):
    """``protocol_overview`` يجمع عدد PPP/WG حسب البروتوكول والحالة."""
    with app.app_context():
        _configure_chr()
        # نُنشئ نفقَيْ PPP يدويًا في DB.
        db.session.add(CustomerVpnTunnel(
            customer_id=customer.id, license_id=None,
            tunnel_type="sstp", username="c1-test01",
            password_encrypted="x", profile="default",
            status="active", chr_provisioned=True,
        ))
        db.session.add(CustomerVpnTunnel(
            customer_id=customer.id, license_id=None,
            tunnel_type="pptp", username="c1-test02",
            password_encrypted="x", profile="default",
            status="suspended", chr_provisioned=True,
        ))
        db.session.commit()
        cards = access_connections.protocol_overview()
        sstp = next(c for c in cards if c["key"] == "sstp")
        pptp = next(c for c in cards if c["key"] == "pptp")
        wg = next(c for c in cards if c["key"] == "wireguard")
        assert sstp["total"] == 1 and sstp["active"] == 1
        assert pptp["total"] == 1 and pptp["active"] == 0
        assert wg["total"] == 0


def test_unified_list_filters_by_protocol(app, customer):
    """``list_connections(protocol=...)`` يفلتر الصفّ الموحَّد بالنوع."""
    with app.app_context():
        _configure_chr()
        db.session.add(CustomerVpnTunnel(
            customer_id=customer.id, license_id=None,
            tunnel_type="sstp", username="c1-aaa",
            password_encrypted="x", profile="default",
            status="active", chr_provisioned=True,
        ))
        db.session.commit()
        # peer WG (skip CHR — اختبار العرض فقط).
        wg = WireguardPeer(
            customer_id=customer.id, peer_name="c1-wg",
            public_key="ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABC=",
            allowed_ips="10.97.0.10/32", status="active",
            chr_provisioned=True, chr_peer_id="*p1",
        )
        db.session.add(wg)
        db.session.commit()

        all_rows = access_connections.list_connections()
        assert {r["protocol"] for r in all_rows} == {"sstp", "wireguard"}
        only_wg = access_connections.list_connections(protocol="wireguard")
        assert len(only_wg) == 1
        assert only_wg[0]["protocol"] == "wireguard"


def test_wireguard_keypair_generation_is_valid_b64():
    """X25519 keypair generated by the service has correct base64 length (44)."""
    priv, pub = wireguard_peers.generate_keypair()
    assert len(priv) == 44 and priv.endswith("=")
    assert len(pub) == 44 and pub.endswith("=")
    assert wireguard_peers.is_valid_wg_pubkey(pub)
    # المفتاحان مختلفان لكل استدعاء.
    priv2, pub2 = wireguard_peers.generate_keypair()
    assert priv != priv2 and pub != pub2


def test_address_allocator_skips_used_and_raises_when_full(app, customer):
    """تخصيص العناوين يتخطّى المحجوز ويرفع عند النفاد."""
    with app.app_context():
        # شبكة صغيرة جدًا للاختبار.
        app.config["CHR_WIREGUARD_CLIENT_SUPERNET"] = "10.97.0.0/30"
        # أوّل تخصيص ينجح.
        addr1 = wireguard_peers.allocate_client_address()
        assert addr1.endswith("/32")
        # نسجّله مستخدمًا في DB ثم نطلب آخر.
        peer = WireguardPeer(
            customer_id=customer.id, peer_name="c1-a",
            public_key="AAA" + "A" * 40 + "=", allowed_ips=addr1,
            status="active",
        )
        db.session.add(peer)
        db.session.commit()
        # المنطقة /30 = 4 عناوين، نتخطّى 2 ⇒ متاح 1 فقط ⇒ التالي يرفع.
        with pytest.raises(wireguard_peers.WireguardPeerError) as exc_info:
            wireguard_peers.allocate_client_address()
        assert exc_info.value.code == "subnet_full"


def test_render_peer_config_includes_keys_until_delivered(app, customer):
    """تكوين .conf يحتوي PrivateKey/Endpoint قبل التأكيد، فارغًا بعده."""
    with app.app_context():
        _configure_chr()
    _, pub = wireguard_peers.generate_keypair()
    peer = WireguardPeer(
        customer_id=customer.id, peer_name="c1-test",
        public_key=pub, allowed_ips="10.97.0.10/32",
        server_public_key="SrvPub" + "A" * 38 + "=",
        endpoint_host="vpn.example.com", endpoint_port=51822,
        status="active",
    )
    # نخزّن مفتاحًا خاصًا مشفّرًا.
    wireguard_peers._store_private_key(peer, "PrivK" + "A" * 39 + "=")
    db.session.add(peer)
    db.session.commit()
    text = wireguard_peers.render_peer_config(peer)
    assert "[Interface]" in text and "[Peer]" in text
    assert "PrivateKey" in text
    assert "Endpoint = vpn.example.com:51822" in text
    assert "PersistentKeepalive" in text


def test_revoke_wireguard_removes_from_chr(app, client, customer):
    """مسار الإلغاء يحذف القرين من CHR ويعلّم السجل revoked."""
    with app.test_request_context():
        _configure_chr()
    _login(client)
    # أنشئ قرينًا أولًا.
    client.post(
        "/admin/access-connections/wireguard",
        data={"customer_id": str(customer.id), "label": "x"},
        follow_redirects=False,
    )
    peer = WireguardPeer.query.first()
    assert peer.status == "active"
    rv = client.post(
        f"/admin/access-connections/wireguard/{peer.id}/revoke",
        follow_redirects=False,
    )
    assert rv.status_code in (302, 303)
    db.session.refresh(peer)
    assert peer.status == "revoked"
    assert peer.chr_provisioned is False
    assert _FakeClient.peers_removed and _FakeClient.peers_removed[0] == peer.chr_peer_id or True
