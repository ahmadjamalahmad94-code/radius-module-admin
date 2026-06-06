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

    # أسماء دوال القراءة التي يجب أن ترفع 400 (لمحاكاة رفض CHR لمسار واحد).
    bad_400 = set()
    # دوال ترفع عطلًا حقيقيًا (اتصال) لاختبار أن المعالجة الناعمة لا تبتلعه.
    bad_connect = set()
    # دوال تعيد قائمة فارغة (لاختبار الحالة الفارغة).
    empty = set()

    def __init__(self, *a, **k):
        pass

    def _guard(self, name=""):
        if _FakeConsoleClient.raise_all:
            raise RouterOSError("connect_failed", "تعذّر الاتصال بمضيف CHR.", retryable=True)
        if name and name in _FakeConsoleClient.bad_400:
            raise RouterOSError("request_invalid", "طلب غير مقبول من CHR — Bad Request", http_status=400)
        if name and name in _FakeConsoleClient.bad_connect:
            raise RouterOSError("connect_failed", "تعذّر الاتصال بمضيف CHR.", retryable=True)

    def test_connection(self):
        self._guard("test_connection")
        return {"identity": "CHR-Console", "version": "7.15", "board_name": "CHR", "uptime": "2d"}

    def system_resource(self):
        self._guard("system_resource")
        return {"version": "7.15", "board-name": "CHR", "uptime": "2d", "cpu-load": "3",
                "free-memory": "100", "total-memory": "256"}

    def system_identity(self):
        self._guard("system_identity")
        return {"name": "CHR-Console"}

    def list_ppp_secrets(self, **k):
        self._guard("list_ppp_secrets")
        return [{".id": "*1", "name": "c1-aaaa", "service": "sstp", "profile": "default", "disabled": "false"}]

    def list_ppp_active(self):
        self._guard("list_ppp_active")
        return [{".id": "*A", "name": "c1-aaaa", "service": "sstp", "address": "10.0.0.2", "uptime": "1h"}]

    def list_ipsec_users(self):
        self._guard("list_ipsec_users")
        if "list_ipsec_users" in _FakeConsoleClient.empty:
            return []
        return [{".id": "*u1", "name": "c1-bbbb", "disabled": "false", "comment": "hoberadius"}]

    def list_ipsec_identities(self):
        self._guard("list_ipsec_identities")
        return [{".id": "*id", "peer": "hoberadius"}]

    def list_ipsec_active_peers(self):
        self._guard("list_ipsec_active_peers")
        return [{".id": "*ap", "remote-address": "203.0.113.5"}]

    def list_interfaces(self):
        self._guard("list_interfaces")
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
    _FakeConsoleClient.bad_400 = set()
    _FakeConsoleClient.bad_connect = set()
    _FakeConsoleClient.empty = set()
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
    assert data["reachable"] is True
    assert data["system"]["available"] is True
    assert data["system"]["identity"] == "CHR-Console"
    assert data["counts"]["ppp_secrets"] == 1
    assert data["counts"]["ipsec_users"] == 1
    assert data["counts"]["ppp_active"] == 1
    assert data["sections"]["ppp_secrets"]["available"] is True
    assert data["sections"]["ppp_secrets"]["rows"][0]["name"] == "c1-aaaa"


def test_console_overview_never_crashes_when_unreachable(app, fake_console):
    _configure_chr()
    fake_console.raise_all = True
    data = chr_console.overview()
    # العميل مضبوط (ok=True) لكن لا شيء يستجيب ⇒ reachable=False، دون انهيار.
    assert data["ok"] is True
    assert data["reachable"] is False
    assert data["system"]["available"] is False


def test_console_one_section_400_others_still_render(app, fake_console):
    """رفض CHR لمسار واحد (400) يبقى محصورًا في قسمه ولا يُسقط بقية الوحدة."""
    _configure_chr()
    fake_console.bad_400 = {"list_ipsec_active_peers"}
    data = chr_console.overview()
    assert data["ok"] is True and data["reachable"] is True
    # القسم المرفوض «غير متاح» برسالته، وبقية الأقسام تعمل.
    assert data["sections"]["ipsec_active"]["available"] is False
    assert "Bad Request" in data["sections"]["ipsec_active"]["error"]
    assert data["sections"]["ppp_secrets"]["available"] is True
    assert data["sections"]["interfaces"]["available"] is True
    assert data["system"]["available"] is True


def test_ipsec_users_success_renders_list(app, fake_console):
    _configure_chr()
    data = chr_console.overview()
    sec = data["sections"]["ipsec_users"]
    assert sec["available"] is True
    assert sec["rows"][0]["name"] == "c1-bbbb"


def test_ipsec_users_empty_renders_empty_state(app, fake_console):
    _configure_chr()
    fake_console.empty = {"list_ipsec_users"}
    data = chr_console.overview()
    sec = data["sections"]["ipsec_users"]
    assert sec["available"] is True   # متاح لكن فارغ ⇒ حالة فارغة لا خطأ
    assert sec["rows"] == []
    assert not sec.get("error")


def test_ipsec_users_400_renders_empty_not_error(app, fake_console):
    """الخلل الحيّ: GET /rest/ip/ipsec/user يرجع 400 على هذا CHR (قائمة غير مُهيّأة).
    يُعرَض كحالة فارغة لا كـ «Bad Request»، وبقية الأقسام تعمل."""
    _configure_chr()
    fake_console.bad_400 = {"list_ipsec_users"}
    data = chr_console.overview()
    sec = data["sections"]["ipsec_users"]
    assert sec["available"] is True          # ليس خطأ
    assert sec["rows"] == []                  # حالة فارغة
    assert sec.get("soft_empty") is True
    assert not sec.get("error")
    # بقية الأقسام سليمة.
    assert data["sections"]["ipsec_identities"]["available"] is True
    assert data["sections"]["ipsec_active"]["available"] is True


def test_ipsec_users_real_failure_still_shows_error(app, fake_console):
    """عطل حقيقي (اتصال) لا يُبتلع — يبقى خطأً ظاهرًا في القسم."""
    _configure_chr()
    fake_console.bad_connect = {"list_ipsec_users"}
    data = chr_console.overview()
    sec = data["sections"]["ipsec_users"]
    assert sec["available"] is False
    assert sec["error"]


def test_console_page_ipsec_users_400_shows_empty_state(app, client, fake_console):
    _configure_chr()
    fake_console.bad_400 = {"list_ipsec_users"}
    _login(client)
    resp = client.get("/admin/chr/console")
    assert resp.status_code == 200
    # القسم يظهر بحالة فارغة (رسالة الفراغ) لا بشارة «غير متاح».
    assert "لم تُهيّأ هذه القائمة".encode() in resp.data
    # وبقية الأقسام ظاهرة.
    assert "ether1".encode() in resp.data


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


def test_console_page_renders_despite_one_section_400(app, client, fake_console):
    """تكرار الخلل الحيّ: مسار واحد يرجع 400 — الصفحة تظل تُحمَّل ببقية الأقسام
    وتُظهر «غير متاح» للقسم المرفوض بدل فشل الوحدة كلها بـ Bad Request."""
    _configure_chr()
    fake_console.bad_400 = {"list_ipsec_active_peers"}
    _login(client)
    resp = client.get("/admin/chr/console")
    assert resp.status_code == 200
    # بقية الأقسام ظهرت (نظام/واجهات)، والقسم المرفوض «غير متاح».
    assert "CHR-Console".encode() in resp.data
    assert "ether1".encode() in resp.data
    assert "غير متاح".encode() in resp.data


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


# ───────────────────────── DB-backed config + resolution order ─────────────────────────

def test_resolution_order_db_over_env_over_default(app, monkeypatch):
    """لكل قيمة: قاعدة البيانات → متغيّر البيئة → الافتراضي المدمج."""
    # لا قيمة في القاعدة بعد ⇒ نأخذ البيئة (host/username) والافتراضي (port=8443).
    monkeypatch.setitem(app.config, "CHR_PUBLIC_HOST", "env-host.example.com")
    monkeypatch.setitem(app.config, "CHR_USERNAME", "env-admin")
    r = chr_settings.resolved()
    assert r["host"] == "env-host.example.com"
    assert r["username"] == "env-admin"
    assert r["port"] == 8443
    # حفظ من الواجهة ⇒ قاعدة البيانات تفوز على البيئة.
    chr_settings.validate_and_save(
        {"host": "db-host.example.com", "username": "db-admin", "password": "p", "use_tls": "1"},
        actor_audit=lambda *a, **k: None,
    )
    db.session.commit()
    r2 = chr_settings.resolved()
    assert r2["host"] == "db-host.example.com"
    assert r2["username"] == "db-admin"


def test_new_fields_saved_and_cert_verbatim(app):
    chr_settings.validate_and_save(
        {
            "host": "h", "username": "admin", "password": "p", "use_tls": "1",
            "public_ip": "178.105.244.112",
            "ipsec_certificate": "Lets encrypt1780754140",  # فيه مسافة داخلية
            "ipsec_address_pool": "ipsec-pool",
            "api_allowed_ip": "178.105.180.6",
        },
        actor_audit=lambda *a, **k: None,
    )
    db.session.commit()
    r = chr_settings.resolved()
    assert r["public_ip"] == "178.105.244.112"
    # الاسم يُخزَّن ويُعاد حرفيًا بمسافته الداخلية.
    assert r["ipsec_certificate"] == "Lets encrypt1780754140"
    assert r["ipsec_address_pool"] == "ipsec-pool"
    assert r["api_allowed_ip"] == "178.105.180.6"
    assert chr_settings.ipsec_overrides()["certificate"] == "Lets encrypt1780754140"


def test_lockdown_commands_rendered_verbatim_cert(app):
    chr_settings.validate_and_save(
        {
            "host": "h", "port": "8443", "username": "admin", "password": "p", "use_tls": "1",
            "ipsec_certificate": "Lets encrypt1780754140", "api_allowed_ip": "178.105.180.6",
        },
        actor_audit=lambda *a, **k: None,
    )
    db.session.commit()
    cmds = chr_settings.lockdown_commands()
    assert cmds, "expected lockdown commands when api_allowed_ip is set"
    www = cmds[0]
    assert "/ip service set www-ssl" in www
    assert "address=178.105.180.6/32" in www
    assert "port=8443" in www
    assert 'certificate="Lets encrypt1780754140"' in www  # اسم بين اقتباسين (مسافة)


def test_lockdown_commands_empty_without_allowed_ip(app):
    chr_settings.validate_and_save(
        {"host": "h", "username": "admin", "password": "p", "use_tls": "1"},
        actor_audit=lambda *a, **k: None,
    )
    db.session.commit()
    assert chr_settings.lockdown_commands() == []


def test_settings_page_shows_new_chr_fields(app, client):
    _login(client)
    resp = client.get("/admin/settings")
    assert resp.status_code == 200
    for needle in (b'name="public_ip"', b'name="ipsec_certificate"',
                   b'name="ipsec_address_pool"', b'name="api_allowed_ip"'):
        assert needle in resp.data


def test_settings_page_warns_when_master_key_missing(app, client, monkeypatch):
    monkeypatch.setitem(app.config, "CUSTOMER_VAULT_ENCRYPTION_KEY", "")
    _login(client)
    resp = client.get("/admin/settings")
    assert resp.status_code == 200
    assert "CUSTOMER_VAULT_ENCRYPTION_KEY".encode() in resp.data


# ───────────────────────── permission registry ─────────────────────────

def test_permission_registry_has_chr_console():
    from app.services import admin_permissions as perms
    assert perms.CHR_CONSOLE == "chr_console"
    assert perms.permission_label("chr_console")
    assert "chr_console" in perms.PERMISSION_LABELS
