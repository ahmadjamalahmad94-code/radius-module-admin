"""WhatsApp Cloud API settings panel — service + routes + UI + audit tests.

No Meta network: MetaCloudWhatsAppProvider._request (the single network point)
is monkeypatched. Uses conftest's app (seeded super-admin 'admin') + client.
"""
from __future__ import annotations

import pytest
from flask import url_for

from app.extensions import db
from app.models import Admin, AuditLog, Setting
from app.services.whatsapp import cloud_settings as wac
from app.services.whatsapp.crypto import decrypt_secret
from app.services.whatsapp.providers import MetaCloudWhatsAppProvider, WhatsAppProviderError

PLAINTEXT_TOKEN = "EAAB-cloud-house-token-abcdefghijklmnop-1234567890"


# ───────────────────────── helpers ─────────────────────────

def _urls(app):
    with app.test_request_context():
        return {
            "page": url_for("admin.settings_page"),
            "save": url_for("admin.whatsapp_cloud_save"),
            "test": url_for("admin.whatsapp_cloud_test"),
            "msg": url_for("admin.whatsapp_cloud_test_message"),
            "reveal": url_for("admin.whatsapp_cloud_reveal"),
            "templates": url_for("admin.whatsapp_cloud_templates"),
        }


def _super_id(app):
    with app.app_context():
        return Admin.query.filter_by(username="admin").first().id


def _nonsuper_id(app):
    with app.app_context():
        a = Admin(username="staff", full_name="Staff", active=True, is_super_admin=False)
        a.set_password("staffpass123")
        db.session.add(a)
        db.session.commit()
        return a.id


def _login(client, admin_id):
    with client.session_transaction() as s:
        s["admin_id"] = admin_id


def _csrf(client, page_url):
    client.get(page_url)  # render sets session _csrf_token
    with client.session_transaction() as s:
        return s.get("_csrf_token", "")


def _valid_form(token=PLAINTEXT_TOKEN):
    return {
        "access_token": token,
        "phone_number_id": "123456789012345",
        "whatsapp_business_account_id": "987654321098765",
        "meta_app_id": "111222333",
        "meta_config_id": "444555666",
        "meta_app_secret": "app-secret-value",
    }


def _save(client, urls, form):
    return client.post(urls["save"], data={**form, "_csrf_token": _csrf(client, urls["page"])},
                       follow_redirects=False)


# Canned provider network: success unless overridden.
def _ok_request(self, method, path, token, *, json_body=None, params=None):
    if method == "POST" and path.endswith("/messages"):
        return 200, {"messages": [{"id": "wamid.TESTMSG"}]}
    if method == "GET":
        if (params or {}).get("fields", "").startswith("display_phone_number"):
            return 200, {"display_phone_number": "+970 599 000111", "verified_name": "House ISP",
                         "quality_rating": "GREEN", "messaging_limit_tier": "TIER_1K"}
        return 200, {"id": path}  # waba reachability
    return 200, {}


def _fail_auth(self, method, path, token, *, json_body=None, params=None):
    raise WhatsAppProviderError("meta_auth_failed", "فشل التحقق من بيانات الاعتماد لدى Meta.",
                                retryable=False, http_status=401)


# ───────────────────────── 1. render + feature flag ─────────────────────────

def test_section_renders_when_enabled(client, app):
    urls = _urls(app)
    _login(client, _super_id(app))
    body = client.get(urls["page"]).get_data(as_text=True)
    assert "واتساب Cloud API" in body
    assert "رمز الوصول" in body
    assert 'action="' + urls["test"] + '"' in body or urls["test"] in body
    assert "إرسال رسالة اختبار" in body


def test_section_hidden_when_flag_off(client, app, monkeypatch):
    urls = _urls(app)
    monkeypatch.setitem(app.config, "WHATSAPP_CLOUD_SETTINGS_ENABLED", False)
    _login(client, _super_id(app))
    body = client.get(urls["page"]).get_data(as_text=True)
    assert "واتساب Cloud API" not in body


# ───────────────────────── 2. save + validation ─────────────────────────

def test_save_persists_encrypted_and_redirects(client, app):
    urls = _urls(app)
    _login(client, _super_id(app))
    r = _save(client, urls, _valid_form())
    assert r.status_code in (301, 302)
    with app.app_context():
        row = db.session.get(Setting, "whatsapp_cloud.access_token")
        assert row and row.value and row.value != PLAINTEXT_TOKEN          # encrypted
        assert decrypt_secret(row.value) == PLAINTEXT_TOKEN                 # recoverable
        assert db.session.get(Setting, "whatsapp_cloud.phone_number_id").value == "123456789012345"


def test_save_missing_required_is_rejected(client, app):
    urls = _urls(app)
    _login(client, _super_id(app))
    form = _valid_form()
    form["phone_number_id"] = ""  # required
    r = client.post(urls["save"], data={**form, "_csrf_token": _csrf(client, urls["page"])},
                    follow_redirects=True)
    body = r.get_data(as_text=True)
    assert "مطلوب" in body
    with app.app_context():
        assert db.session.get(Setting, "whatsapp_cloud.access_token") is None  # nothing saved


def test_save_non_numeric_id_rejected(client, app):
    urls = _urls(app)
    _login(client, _super_id(app))
    form = _valid_form()
    form["phone_number_id"] = "abc123"
    r = client.post(urls["save"], data={**form, "_csrf_token": _csrf(client, urls["page"])},
                    follow_redirects=True)
    assert "أرقامًا فقط" in r.get_data(as_text=True)


def test_blank_secret_keeps_existing(client, app):
    urls = _urls(app)
    _login(client, _super_id(app))
    _save(client, urls, _valid_form())
    # Re-save with blank token (write-only keep) + changed phone.
    form = _valid_form(token="")
    form["phone_number_id"] = "555555555555555"
    _save(client, urls, form)
    with app.app_context():
        assert decrypt_secret(db.session.get(Setting, "whatsapp_cloud.access_token").value) == PLAINTEXT_TOKEN
        assert db.session.get(Setting, "whatsapp_cloud.phone_number_id").value == "555555555555555"


# ───────────────────────── 3. masked display ─────────────────────────

def test_masked_display_never_shows_token(client, app):
    urls = _urls(app)
    _login(client, _super_id(app))
    _save(client, urls, _valid_form())
    body = client.get(urls["page"]).get_data(as_text=True)
    assert PLAINTEXT_TOKEN not in body
    assert "محفوظ في إعدادات اللوحة" in body  # source badge = panel
    # the write-only token field carries no value
    assert 'name="access_token" type="password" autocomplete="new-password"\n               value=""' in body or 'name="access_token"' in body


# ───────────────────────── 4. env fallback + source ─────────────────────────

def test_env_fallback_source(client, app, monkeypatch):
    urls = _urls(app)
    monkeypatch.setitem(app.config, "WHATSAPP_PHONE_NUMBER_ID", "700700700700700")
    _login(client, _super_id(app))
    with app.app_context():
        value, source = wac._resolve("phone_number_id")
        assert value == "700700700700700" and source == "env"
    body = client.get(urls["page"]).get_data(as_text=True)
    assert "مُحمّل من البيئة" in body


def test_saved_db_overrides_env(client, app, monkeypatch):
    urls = _urls(app)
    monkeypatch.setitem(app.config, "WHATSAPP_PHONE_NUMBER_ID", "700700700700700")
    _login(client, _super_id(app))
    _save(client, urls, _valid_form())  # saves phone 123456789012345
    with app.app_context():
        value, source = wac._resolve("phone_number_id")
        assert value == "123456789012345" and source == "panel"


# ───────────────────────── 5. test connection (mocked) ─────────────────────────

def test_connection_success(client, app, monkeypatch):
    urls = _urls(app)
    _login(client, _super_id(app))
    _save(client, urls, _valid_form())
    monkeypatch.setattr(MetaCloudWhatsAppProvider, "_request", _ok_request)
    r = client.post(urls["test"], data={"_csrf_token": _csrf(client, urls["page"])}, follow_redirects=True)
    assert "نجح الاتصال" in r.get_data(as_text=True)
    with app.app_context():
        assert AuditLog.query.filter_by(action="whatsapp_cloud_test_success").first() is not None


def test_connection_failure(client, app, monkeypatch):
    urls = _urls(app)
    _login(client, _super_id(app))
    _save(client, urls, _valid_form())
    monkeypatch.setattr(MetaCloudWhatsAppProvider, "_request", _fail_auth)
    r = client.post(urls["test"], data={"_csrf_token": _csrf(client, urls["page"])}, follow_redirects=True)
    assert "فشل الاتصال" in r.get_data(as_text=True)
    with app.app_context():
        assert AuditLog.query.filter_by(action="whatsapp_cloud_test_failed").first() is not None


def test_connection_ok_when_restricted_fields_forbidden(client, app, monkeypatch):
    """A messaging-scoped token can read display_phone_number but 403s on the
    restricted health fields — the connection test must still pass."""
    urls = _urls(app)
    _login(client, _super_id(app))
    _save(client, urls, _valid_form())

    def fake_request(self, method, path, token, *, json_body=None, params=None):
        fields = (params or {}).get("fields", "")
        if method == "GET" and fields == "display_phone_number":
            return 200, {"display_phone_number": "+970 599 000111"}
        if method == "GET" and fields.startswith("verified_name"):
            raise WhatsAppProviderError("meta_auth_failed", "فشل التحقق", retryable=False, http_status=403)
        if method == "GET":  # waba reachability (fields=id)
            return 200, {"id": path}
        return 200, {}

    monkeypatch.setattr(MetaCloudWhatsAppProvider, "_request", fake_request)
    r = client.post(urls["test"], data={"_csrf_token": _csrf(client, urls["page"])}, follow_redirects=True)
    assert "نجح الاتصال" in r.get_data(as_text=True)
    with app.app_context():
        assert AuditLog.query.filter_by(action="whatsapp_cloud_test_success").first() is not None


def test_connection_auth_failure_hints_expiry(client, app, monkeypatch):
    urls = _urls(app)
    _login(client, _super_id(app))
    _save(client, urls, _valid_form())
    monkeypatch.setattr(MetaCloudWhatsAppProvider, "_request", _fail_auth)
    r = client.post(urls["test"], data={"_csrf_token": _csrf(client, urls["page"])}, follow_redirects=True)
    body = r.get_data(as_text=True)
    assert "فشل الاتصال" in body
    assert "منتهيًا" in body  # expiry hint surfaced


def test_connection_without_creds_errors(client, app):
    urls = _urls(app)
    _login(client, _super_id(app))
    r = client.post(urls["test"], data={"_csrf_token": _csrf(client, urls["page"])}, follow_redirects=True)
    assert "أكمل" in r.get_data(as_text=True)


# ───────────────────────── 6. send test message (mocked) ─────────────────────────

def test_send_message_success(client, app, monkeypatch):
    urls = _urls(app)
    _login(client, _super_id(app))
    _save(client, urls, _valid_form())
    monkeypatch.setattr(MetaCloudWhatsAppProvider, "_request", _ok_request)
    r = client.post(urls["msg"], data={"recipient": "970599000111", "_csrf_token": _csrf(client, urls["page"])},
                    follow_redirects=True)
    assert "تم إرسال رسالة الاختبار" in r.get_data(as_text=True)
    with app.app_context():
        assert AuditLog.query.filter_by(action="whatsapp_cloud_test_message_sent").first() is not None


def test_send_message_failure(client, app, monkeypatch):
    urls = _urls(app)
    _login(client, _super_id(app))
    _save(client, urls, _valid_form())
    monkeypatch.setattr(MetaCloudWhatsAppProvider, "_request", _fail_auth)
    r = client.post(urls["msg"], data={"recipient": "970599000111", "_csrf_token": _csrf(client, urls["page"])},
                    follow_redirects=True)
    assert "تعذّر إرسال رسالة الاختبار" in r.get_data(as_text=True)


def test_send_uses_template_and_hint_on_invalid(client, app, monkeypatch):
    """Test message must go out as an APPROVED TEMPLATE (free-form text is
    blocked outside the 24h window), and an invalid template surfaces a hint."""
    urls = _urls(app)
    _login(client, _super_id(app))
    _save(client, urls, _valid_form())
    seen = {}

    def fake_request(self, method, path, token, *, json_body=None, params=None):
        if method == "POST" and path.endswith("/messages"):
            seen["body"] = json_body
            raise WhatsAppProviderError("meta_request_invalid",
                                        "تعذّر إرسال الرسالة: الطلب أو القالب غير صالح.",
                                        retryable=False, http_status=400)
        return 200, {}

    monkeypatch.setattr(MetaCloudWhatsAppProvider, "_request", fake_request)
    r = client.post(urls["msg"], data={"recipient": "970599000111", "_csrf_token": _csrf(client, urls["page"])},
                    follow_redirects=True)
    # sent as a template (not free-form text), defaulting to hello_world
    assert seen["body"]["type"] == "template"
    assert seen["body"]["template"]["name"] == "hello_world"
    assert seen["body"]["template"]["language"]["code"] == "en_US"
    # helpful Arabic hint about template approval surfaced to the admin
    assert "معتمد في حسابك" in r.get_data(as_text=True)


def test_list_templates_returns_approved_first(client, app, monkeypatch):
    urls = _urls(app)
    _login(client, _super_id(app))
    _save(client, urls, _valid_form())

    def fake_request(self, method, path, token, *, json_body=None, params=None):
        if method == "GET" and path.endswith("/message_templates"):
            return 200, {"data": [
                {"name": "promo", "language": "ar", "status": "PENDING", "category": "MARKETING"},
                {"name": "order_update", "language": "ar", "status": "APPROVED", "category": "UTILITY"},
            ]}
        return 200, {}

    monkeypatch.setattr(MetaCloudWhatsAppProvider, "_request", fake_request)
    r = client.post(urls["templates"], data={"_csrf_token": _csrf(client, urls["page"])},
                    headers={"X-Requested-With": "XMLHttpRequest"})
    assert r.status_code == 200
    j = r.get_json()
    assert j["ok"] is True
    assert j["templates"][0]["name"] == "order_update"      # APPROVED sorted first
    assert j["templates"][0]["status"] == "APPROVED"


def test_recommended_and_simple_flags_sorted_first(client, app, monkeypatch):
    urls = _urls(app)
    _login(client, _super_id(app))
    _save(client, urls, _valid_form())

    def fake_request(self, method, path, token, *, json_body=None, params=None):
        if method == "GET" and path.endswith("/message_templates"):
            return 200, {"data": [
                {"name": "zeta_custom", "language": "ar", "status": "APPROVED",
                 "components": [{"type": "BODY", "text": "أهلًا {{1}}"}]},
                {"name": "promo_img", "language": "en_US", "status": "APPROVED",
                 "components": [{"type": "HEADER", "format": "IMAGE"}, {"type": "BODY", "text": "x"}]},
                {"name": "hello_world", "language": "en_US", "status": "APPROVED",
                 "components": [{"type": "BODY", "text": "Hello"}]},
            ]}
        return 200, {}

    monkeypatch.setattr(MetaCloudWhatsAppProvider, "_request", fake_request)
    r = client.post(urls["templates"], data={"_csrf_token": _csrf(client, urls["page"])},
                    headers={"X-Requested-With": "XMLHttpRequest"})
    j = r.get_json()
    assert j["templates"][0]["name"] == "hello_world"   # recommended → first
    hw = j["templates"][0]
    assert hw["recommended"] is True and hw["simple"] is True
    by = {t["name"]: t for t in j["templates"]}
    assert by["zeta_custom"]["simple"] is False and by["zeta_custom"]["body_params"] == 1
    assert by["promo_img"]["needs_media"] is True and by["promo_img"]["testable"] is False


def test_send_autofills_body_params(client, app, monkeypatch):
    """A template with {{1}} {{2}} body params is auto-filled so it sends."""
    urls = _urls(app)
    _login(client, _super_id(app))
    _save(client, urls, _valid_form())
    seen = {}

    def fake_request(self, method, path, token, *, json_body=None, params=None):
        if method == "GET" and path.endswith("/message_templates"):
            return 200, {"data": [{"name": "order_update", "language": "ar", "status": "APPROVED",
                                   "components": [{"type": "BODY", "text": "مرحبا {{1}} طلبك {{2}}"}]}]}
        if method == "POST" and path.endswith("/messages"):
            seen["body"] = json_body
            return 200, {"messages": [{"id": "wamid.X"}]}
        return 200, {}

    monkeypatch.setattr(MetaCloudWhatsAppProvider, "_request", fake_request)
    r = client.post(urls["msg"], data={"recipient": "970599000111", "template_name": "order_update",
                                       "language": "ar", "_csrf_token": _csrf(client, urls["page"])},
                    follow_redirects=True)
    assert "تم إرسال رسالة الاختبار" in r.get_data(as_text=True)
    body_comp = [c for c in seen["body"]["template"]["components"] if c["type"] == "body"][0]
    assert len(body_comp["parameters"]) == 2  # both {{1}} {{2}} auto-filled


def test_send_rejects_media_header_template(client, app, monkeypatch):
    """A template needing a media header is refused with a friendly message."""
    urls = _urls(app)
    _login(client, _super_id(app))
    _save(client, urls, _valid_form())

    def fake_request(self, method, path, token, *, json_body=None, params=None):
        if method == "GET" and path.endswith("/message_templates"):
            return 200, {"data": [{"name": "image_cta", "language": "en_US", "status": "APPROVED",
                                   "components": [{"type": "HEADER", "format": "IMAGE"},
                                                  {"type": "BODY", "text": "hi"}]}]}
        return 200, {}

    monkeypatch.setattr(MetaCloudWhatsAppProvider, "_request", fake_request)
    r = client.post(urls["msg"], data={"recipient": "970599000111", "template_name": "image_cta",
                                       "language": "en_US", "_csrf_token": _csrf(client, urls["page"])},
                    follow_redirects=True)
    assert "يتطلّب وسائط" in r.get_data(as_text=True)


def test_send_message_requires_recipient(client, app):
    urls = _urls(app)
    _login(client, _super_id(app))
    _save(client, urls, _valid_form())
    r = client.post(urls["msg"], data={"recipient": "", "_csrf_token": _csrf(client, urls["page"])},
                    follow_redirects=True)
    assert "أدخل رقم" in r.get_data(as_text=True)


# ───────────────────────── 7. reveal: permissions + audit ─────────────────────────

def test_reveal_super_admin_ok_and_audited(client, app):
    urls = _urls(app)
    _login(client, _super_id(app))
    _save(client, urls, _valid_form())
    r = client.post(urls["reveal"], data={"field": "access_token", "_csrf_token": _csrf(client, urls["page"])},
                    headers={"X-Requested-With": "XMLHttpRequest"})
    assert r.status_code == 200
    assert r.get_json()["value"] == PLAINTEXT_TOKEN
    with app.app_context():
        ev = AuditLog.query.filter_by(action="whatsapp_cloud_secret_revealed").first()
        assert ev is not None
        # audit must record the field, NEVER the secret value
        assert PLAINTEXT_TOKEN not in (ev.summary or "")
        assert PLAINTEXT_TOKEN not in (str(ev.meta) if hasattr(ev, "meta") else "")


def test_reveal_denied_for_non_super(client, app):
    urls = _urls(app)
    _login(client, _super_id(app))
    _save(client, urls, _valid_form())   # save as super
    _login(client, _nonsuper_id(app))     # then act as non-super
    r = client.post(urls["reveal"], data={"field": "access_token", "_csrf_token": _csrf(client, urls["page"])},
                    headers={"X-Requested-With": "XMLHttpRequest"})
    assert r.status_code == 403
    assert PLAINTEXT_TOKEN not in r.get_data(as_text=True)


# ───────────────────────── 8. unauthenticated blocked ─────────────────────────

def test_unauthenticated_save_redirects_to_login(client, app):
    urls = _urls(app)
    r = client.post(urls["save"], data=_valid_form(), follow_redirects=False)
    assert r.status_code in (301, 302)
    assert "/login" in r.headers.get("Location", "")
    with app.app_context():
        assert db.session.get(Setting, "whatsapp_cloud.access_token") is None


# ───────────────────────── 9. audit on save ─────────────────────────

BRIDGE_URL = "/api/integration/hoberadius/whatsapp/cloud-test"


def test_bridge_cloud_test_sends_via_house_creds(client, app, monkeypatch):
    urls = _urls(app)
    _login(client, _super_id(app))
    _save(client, urls, _valid_form())
    # Bypass the integration auth triad (HTTPS+signature+license) for the unit test.
    from app.api import routes as api_routes
    monkeypatch.setattr(api_routes, "_whatsapp_integration_context", lambda body: (object(), 1, None))
    monkeypatch.setattr(MetaCloudWhatsAppProvider, "_request", _ok_request)
    r = client.post(BRIDGE_URL, json={"recipient_phone": "970599000111"})
    assert r.status_code == 200
    body = r.get_json()
    assert body["ok"] is True
    assert "provider_message_id" in body
    with app.app_context():
        assert AuditLog.query.filter_by(action="whatsapp_cloud_test_message_sent").first() is not None


def test_bridge_cloud_test_requires_creds(client, app, monkeypatch):
    from app.api import routes as api_routes
    monkeypatch.setattr(api_routes, "_whatsapp_integration_context", lambda body: (object(), 1, None))
    r = client.post(BRIDGE_URL, json={"recipient_phone": "970599000111"})
    assert r.status_code == 400
    assert r.get_json()["ok"] is False


def test_bridge_cloud_test_respects_auth_guard(client, app, monkeypatch):
    # When the integration guard rejects (e.g. unsigned), the endpoint returns
    # that response and never sends.
    from app.api import routes as api_routes
    from flask import jsonify
    monkeypatch.setattr(api_routes, "_whatsapp_integration_context",
                        lambda body: (None, None, (jsonify({"ok": False, "status": "signature_invalid"}), 401)))
    r = client.post(BRIDGE_URL, json={"recipient_phone": "970599000111"})
    assert r.status_code == 401


def test_save_is_audited(client, app):
    urls = _urls(app)
    _login(client, _super_id(app))
    _save(client, urls, _valid_form())
    with app.app_context():
        assert AuditLog.query.filter_by(action="whatsapp_cloud_saved").first() is not None
