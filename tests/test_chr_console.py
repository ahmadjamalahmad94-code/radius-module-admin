"""اختبارات قفل اتصال CHR ووحدة تحكّم CHR المركزية + ضمان عدم تسريب أسرار CHR للجسر.

كل استدعاءات RouterOS مُستبدَلة (monkeypatch) فلا نتصل بأي CHR حقيقي.
"""
from __future__ import annotations

import time
from datetime import timedelta

import pytest

from app.extensions import db
from app.license_signing import sign_license_payload
from app.models import (
    Admin,
    Customer,
    CustomerVpnEntitlement,
    License,
    Plan,
    utcnow,
)
from app.services import chr_console, chr_settings, vpn_tunnels
from app.services.routeros_client import RouterOSError


# ───────────────────────── fixtures / helpers ─────────────────────────

ADMIN_HOST = "mgmt-internal.hoberadius.local"
PUBLIC_HOST = "vpn.public.hoberadius.com"
CHR_ADMIN_PASSWORD = "s3cret-chr-admin-pass"


def _configure_chr(public_host: str = "", **extra):
    form = {
        "host": ADMIN_HOST, "port": "8729", "username": "admin",
        "password": CHR_ADMIN_PASSWORD, "use_tls": "1", "verify_tls": "",
    }
    if public_host:
        form["public_host"] = public_host
    form.update(extra)
    chr_settings.validate_and_save(form, actor_audit=lambda *a, **k: None)
    db.session.commit()


@pytest.fixture()
def customer(app):
    plan = Plan.query.filter_by(slug="pro").first()
    cust = Customer(company_name="Console ISP", status="active")
    db.session.add(cust)
    db.session.flush()
    db.session.add(License(
        customer_id=cust.id, plan_id=plan.id, license_key="HBR-CONSOLE-TEST-1",
        status="active", starts_at=utcnow(), expires_at=utcnow() + timedelta(days=30),
        max_fingerprints=3,
    ))
    db.session.add(CustomerVpnEntitlement(
        customer_id=cust.id, enabled=True, status="active",
        download_mbps=50, upload_mbps=50, max_vpn_users=3, max_locations=1,
    ))
    db.session.commit()
    return cust


class _FakeConsoleClient:
    """عميل RouterOS وهمي يخدم قراءات/تعديلات الوحدة دون لمس الشبكة."""

    raise_all = False
    disabled_calls: list = []
    removed_calls: list = []
    rebooted = False

    def __init__(self, *a, **k):
        pass

    def _guard(self):
        if _FakeConsoleClient.raise_all:
            raise RouterOSError("connect_failed", "تعذّر الاتصال بمضيف CHR.", retryable=True)

    def test_connection(self):
        self._guard()
        return {"identity": "CHR-Console", "version": "7.15", "board_name": "CHR", "uptime": "2d"}

    def system_resource(self):
        self._guard()
        return {"version": "7.15", "board-name": "CHR", "uptime": "2d", "cpu-load": "3",
                "free-memory": "100", "total-memory": "256"}

    def system_identity(self):
        self._guard()
        return {"name": "CHR-Console"}

    def list_ppp_secrets(self, **k):
        self._guard()
        return [{".id": "*1", "name": "c1-aaaa", "service": "sstp", "profile": "default", "disabled": "false"}]

    def list_ppp_active(self):
        self._guard()
        return [{".id": "*A", "name": "c1-aaaa", "service": "sstp", "address": "10.0.0.2", "uptime": "1h"}]

    def list_ipsec_users(self):
        self._guard()
        return [{".id": "*u1", "name": "c1-bbbb", "disabled": "false", "comment": "hoberadius"}]

    def list_ipsec_identities(self):
        self._guard()
        return [{".id": "*id", "peer": "hoberadius"}]

    def list_ipsec_active_peers(self):
        self._guard()
        return [{".id": "*ap", "remote-address": "203.0.113.5"}]

    def list_interfaces(self):
        self._guard()
        return [{".id": "*if", "name": "ether1", "type": "ether", "running": "true"}]

    def create_ppp_secret(self, **kwargs):
        self._guard()
        return {".id": "*new1", **kwargs}

    def set_ppp_secret_disabled(self, secret_id, disabled):
        self._guard()
        _FakeConsoleClient.disabled_calls.append(("ppp", secret_id, disabled))

    def remove_ppp_secret(self, secret_id):
        self._guard()
        _FakeConsoleClient.removed_calls.append(("ppp", secret_id))

    def set_ipsec_user_disabled(self, user_id, disabled):
        self._guard()
        _FakeConsoleClient.disabled_calls.append(("ipsec", user_id, disabled))

    def remove_ipsec_user(self, user_id):
        self._guard()
        _FakeConsoleClient.removed_calls.append(("ipsec", user_id))

    def reboot(self):
        self._guard()
        _FakeConsoleClient.rebooted = True


@pytest.fixture()
def fake_console(app, monkeypatch):
    _FakeConsoleClient.raise_all = False
    _FakeConsoleClient.disabled_calls = []
    _FakeConsoleClient.removed_calls = []
    _FakeConsoleClient.rebooted = False
    monkeypatch.setattr(chr_settings, "build_client", lambda: _FakeConsoleClient())
    return _FakeConsoleClient


# ───────────────────────── lock flow ─────────────────────────

def test_successful_verify_auto_locks(app, fake_console):
    _configure_chr()
    assert chr_settings.is_locked() is False
    result = chr_settings.test_connection(actor_audit=lambda *a, **k: None)
    assert result["ok"] is True
    assert chr_settings.is_locked() is True
    assert chr_settings.lock_state()["verified_at"]


def test_locked_save_blocked_without_confirm(app, fake_console):
    _configure_chr()
    chr_settings.test_connection(actor_audit=lambda *a, **k: None)  # auto-locks
    assert chr_settings.is_locked() is True
    with pytest.raises(chr_settings.ChrSettingsError):
        chr_settings.validate_and_save(
            {"host": "evil-host", "username": "admin", "password": ""},
            actor_audit=lambda *a, **k: None,
        )
    # لم يتغيّر المضيف.
    assert chr_settings.resolved()["host"] == ADMIN_HOST


def test_locked_save_allowed_with_confirm(app, fake_console):
    _configure_chr()
    chr_settings.test_connection(actor_audit=lambda *a, **k: None)
    chr_settings.validate_and_save(
        {"host": "new-mgmt-host", "username": "admin", "password": "", "use_tls": "1"},
        actor_audit=lambda *a, **k: None,
        allow_locked_change=True,
    )
    db.session.commit()
    assert chr_settings.resolved()["host"] == "new-mgmt-host"
    # يبقى مقفلًا بعد التغيير المؤكَّد.
    assert chr_settings.is_locked() is True


def test_explicit_lock_unlock(app):
    _configure_chr()
    chr_settings.lock(actor_audit=lambda *a, **k: None, actor_label="tester")
    assert chr_settings.is_locked() is True
    chr_settings.unlock(actor_audit=lambda *a, **k: None, actor_label="tester")
    assert chr_settings.is_locked() is False


# ───────────────────────── transport: REST/www-ssl default port ─────────────────────────

def test_rest_default_port_is_8443_not_443(app):
    """443 محجوز لـ SSTP؛ منفذ REST (www-ssl) الإداري يجب أن يكون 8443 افتراضيًا."""
    chr_settings.validate_and_save(
        {"host": "h", "username": "admin", "password": "p", "use_tls": "1"},
        actor_audit=lambda *a, **k: None,
    )
    db.session.commit()
    assert chr_settings.resolved()["port"] == 8443
    # منفذ SSTP الذي يتصل به العميل يبقى 443 منفصلًا عن منفذ الإدارة.
    assert chr_settings.SERVICE_PORT_DEFAULTS["sstp"] == 443


# ───────────────────────── bridge: no CHR admin secret/host leak ─────────────────────────

def _signed_body(app, customer, **extra):
    lic = customer.licenses.first()
    body = {
        "license_key": lic.license_key, "server_fingerprint": "fp-console-1",
        "nonce": f"n-{time.time()}-{extra.get('_n','')}", "timestamp": int(time.time()),
        **{k: v for k, v in extra.items() if not k.startswith("_")},
    }
    secret = app.config["LICENSE_CHECK_HMAC_SECRET"] or "test-secret"
    app.config["LICENSE_CHECK_HMAC_SECRET"] = secret
    body["signature"] = sign_license_payload(body, secret)
    return body


def test_serialize_tunnel_never_exposes_admin_host_or_secret(app, customer, fake_console):
    _configure_chr(public_host=PUBLIC_HOST)
    lic = customer.licenses.first()
    tunnel = vpn_tunnels.provision_tunnel(customer, lic, tunnel_type="sstp")
    db.session.commit()
    data = vpn_tunnels.serialize_tunnel(tunnel, include_password=True)
    blob = str(data)
    # العنوان العام يُسلَّم؛ مضيف REST الإداري لا يُسرَّب أبدًا.
    assert data["chr_public_host"] == PUBLIC_HOST
    assert data["chr_host"] == PUBLIC_HOST
    assert ADMIN_HOST not in blob
    # سرّ admin الخاص بـ CHR لا يظهر إطلاقًا (كلمة مرور النفق المولّدة وحدها مسموحة).
    assert CHR_ADMIN_PASSWORD not in blob


def test_bridge_response_has_no_chr_admin_secret_or_host(app, client, customer, fake_console):
    _configure_chr(public_host=PUBLIC_HOST)
    app.config["LICENSE_CHECK_SIGNATURE_REQUIRED"] = True
    app.config["LICENSE_CHECK_ALLOW_UNSIGNED"] = False
    body = _signed_body(app, customer, _n="req")
    resp = client.post(
        "/api/integration/hoberadius/vpn/tunnels/request",
        json=body, headers={"X-Forwarded-Proto": "https"},
        environ_overrides={"wsgi.url_scheme": "https"},
    )
    assert resp.status_code == 201, resp.get_json()
    raw = resp.get_data(as_text=True)
    assert ADMIN_HOST not in raw
    assert CHR_ADMIN_PASSWORD not in raw
    assert PUBLIC_HOST in raw  # العنوان العام يُسلَّم للعميل


# ───────────────────────── console service (mocked client) ─────────────────────────

def test_console_overview_lists_everything(app, fake_console):
    _configure_chr()
    data = chr_console.overview()
    assert data["ok"] is True
    assert data["system"]["identity"] == "CHR-Console"
    assert data["counts"]["ppp_secrets"] == 1
    assert data["counts"]["ipsec_users"] == 1
    assert data["counts"]["ppp_active"] == 1
    assert data["ppp_secrets"][0]["name"] == "c1-aaaa"


def test_console_overview_never_crashes_when_unreachable(app, fake_console):
    _configure_chr()
    fake_console.raise_all = True
    data = chr_console.overview()
    assert data["ok"] is False
    assert data.get("message")


def test_console_mutations(app, fake_console):
    _configure_chr()
    assert chr_console.set_ppp_secret_disabled("*1", True)["ok"] is True
    assert ("ppp", "*1", True) in fake_console.disabled_calls
    assert chr_console.remove_ipsec_user("*u1")["ok"] is True
    assert ("ipsec", "*u1") in fake_console.removed_calls
    assert chr_console.reboot()["ok"] is True
    assert fake_console.rebooted is True


# ───────────────────────── console routes / permission ─────────────────────────

def _login(client, username="admin", password="admin12345"):
    return client.post("/login", data={"username": username, "password": password})


def _csrf(client):
    with client.session_transaction() as sess:
        return sess.get("_csrf_token", "")


def test_console_page_renders_for_super_admin(app, client, fake_console):
    _configure_chr()
    _login(client)  # bootstrap admin is super
    resp = client.get("/admin/chr/console")
    assert resp.status_code == 200
    assert "وحدة تحكّم CHR".encode() in resp.data
    assert "CHR-Console".encode() in resp.data


def test_console_blocked_for_non_super_admin(app, client, fake_console):
    _configure_chr()
    viewer = Admin(username="viewer", full_name="Viewer", is_super_admin=False, active=True)
    viewer.set_password("viewer12345")
    db.session.add(viewer)
    db.session.commit()
    _login(client, username="viewer", password="viewer12345")
    resp = client.get("/admin/chr/console")
    # محروسة: إعادة توجيه (ليست 200) لغير المسؤول العام.
    assert resp.status_code in (301, 302)


def test_console_remove_requires_confirm(app, client, fake_console):
    _configure_chr()
    _login(client)
    token = _csrf(client)
    # بلا confirm=yes لا يُحذف شيء.
    resp = client.post(
        "/admin/chr/console/ppp/remove",
        data={"secret_id": "*1", "name": "c1-aaaa", "_csrf_token": token},
        follow_redirects=False,
    )
    assert resp.status_code in (301, 302)
    assert ("ppp", "*1") not in fake_console.removed_calls
    # مع confirm=yes يُحذف.
    resp2 = client.post(
        "/admin/chr/console/ppp/remove",
        data={"secret_id": "*1", "name": "c1-aaaa", "confirm": "yes", "_csrf_token": token},
        follow_redirects=False,
    )
    assert resp2.status_code in (301, 302)
    assert ("ppp", "*1") in fake_console.removed_calls


# ───────────────────────── permission registry ─────────────────────────

def test_permission_registry_has_chr_console():
    from app.services import admin_permissions as perms
    assert perms.CHR_CONSOLE == "chr_console"
    assert perms.permission_label("chr_console")
    assert "chr_console" in perms.PERMISSION_LABELS
