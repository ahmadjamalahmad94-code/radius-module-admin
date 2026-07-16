"""RBAC (أربعة أدوار) + 2FA/TOTP — إعادة تصميم 2026-07.

يتحقق أن الأدوار الأربعة تُنفَّذ فعليًا (لا مجرد تسميات) وأن تدفّق TOTP يعمل.
"""
from __future__ import annotations

import pyotp
import pytest

from app.extensions import db
from app.models import Admin
from app.services import rbac
from app.services import two_factor as tf


def _mk(app, username, role, *, super_=False, pw="test12345"):
    with app.app_context():
        a = Admin(username=username, email=f"{username}@x.com", full_name=username,
                  active=True, is_super_admin=super_, role_key=role)
        a.set_password(pw)
        db.session.add(a)
        db.session.commit()
        return a.id


def _login(client, username, pw="test12345"):
    r = client.post("/login", data={"username": username, "password": pw},
                    follow_redirects=False)
    return r


# ── وحدة منطق RBAC ────────────────────────────────────────────────────────
class TestRbacUnit:
    def test_role_caps_are_nested(self):
        assert rbac.CAP_MANAGE_SETTINGS in rbac.ROLE_CAPS[rbac.ROLE_SUPER]
        assert rbac.CAP_MANAGE_SETTINGS not in rbac.ROLE_CAPS[rbac.ROLE_OPERATOR]
        assert rbac.CAP_MANAGE_CUSTOMERS not in rbac.ROLE_CAPS[rbac.ROLE_SUPPORT]
        assert rbac.ROLE_CAPS[rbac.ROLE_VIEWER] == frozenset({rbac.CAP_VIEW})

    def test_super_flag_overrides_role_key(self, app):
        with app.app_context():
            a = Admin(username="z", role_key="viewer", is_super_admin=True)
            assert rbac.role_of(a) == rbac.ROLE_SUPER
            assert rbac.can(a, rbac.CAP_MANAGE_SETTINGS)

    def test_required_capability_map(self):
        assert rbac.required_capability("admin.customer_edit", "GET") == rbac.CAP_VIEW
        assert rbac.required_capability("admin.customer_edit", "POST") == rbac.CAP_MANAGE_CUSTOMERS
        assert rbac.required_capability("admin.settings_admins_post", "POST") == rbac.CAP_MANAGE_SETTINGS
        assert rbac.required_capability("admin.license_revoke", "POST") == rbac.CAP_MANAGE_LICENSES
        # الخدمة الذاتية للأمان متاحة لأي مدير
        assert rbac.required_capability("admin.settings_2fa_enable", "POST") == rbac.CAP_VIEW


# ── إنفاذ HTTP عبر الحارس المركزي ─────────────────────────────────────────
class TestRbacEnforcement:
    def test_all_roles_can_view_dashboard(self, app, client):
        for u, role in [("s", "super_admin"), ("o", "operator"),
                        ("p", "support"), ("v", "viewer")]:
            _mk(app, u, role, super_=(role == "super_admin"))
        for u in ["s", "o", "p", "v"]:
            c = app.test_client()
            _login(c, u)
            assert c.get("/admin/dashboard").status_code == 200

    # ملاحظة: منع HTML = إعادة توجيه 302 مع flash؛ منع JSON = 403 نظيف.
    # نستخدم Accept: application/json للتأكيد الحاسم على المنع.
    _JSON = {"Accept": "application/json"}

    def test_viewer_blocked_from_customer_write(self, app):
        _mk(app, "v", "viewer")
        c = app.test_client()
        _login(c, "v")
        r = c.post("/admin/customers/1/edit", data={"full_name": "x"},
                   headers=self._JSON, follow_redirects=False)
        assert r.status_code == 403

    def test_support_blocked_from_customer_write(self, app):
        _mk(app, "p", "support")
        c = app.test_client()
        _login(c, "p")
        r = c.post("/admin/customers/1/edit", data={"full_name": "x"},
                   headers=self._JSON, follow_redirects=False)
        assert r.status_code == 403

    def test_operator_blocked_from_settings(self, app):
        _mk(app, "o", "operator")
        c = app.test_client()
        _login(c, "o")
        r = c.post("/admin/settings/admins", data={"action": "noop"},
                   headers=self._JSON, follow_redirects=False)
        assert r.status_code == 403

    def test_support_can_reach_disconnect(self, app):
        # الدعم يملك disconnect_session — لا يُمنع من مسار فيه «disconnect»
        _mk(app, "p2", "support")
        c = app.test_client()
        _login(c, "p2")
        r = c.post("/admin/customers/1/google-drive/disconnect", data={},
                   headers=self._JSON, follow_redirects=False)
        assert r.status_code != 403  # قد يكون 404/400/302 لكن ليس منعًا بالدور

    def test_super_allowed_everywhere(self, app):
        _mk(app, "s", "super_admin", super_=True)
        c = app.test_client()
        _login(c, "s")
        # لا 403 على مسار الإعدادات (قد يكون 302/200/400 لكن ليس منعًا)
        r = c.post("/admin/settings/admins", data={"action": "noop"},
                   follow_redirects=False)
        assert r.status_code != 403


# ── 2FA / TOTP ────────────────────────────────────────────────────────────
class TestTwoFactor:
    def test_verify_accepts_current_code(self):
        secret = tf.new_secret()
        code = pyotp.TOTP(secret).now()
        assert tf.verify(secret, code)
        assert not tf.verify(secret, "000000")
        assert not tf.verify(secret, "")

    def test_qr_is_data_uri(self):
        secret = tf.new_secret()
        uri = tf.qr_data_uri(secret, "admin@x.com")
        assert uri.startswith("data:image/png;base64,")

    def test_login_with_2fa_requires_second_step(self, app):
        aid = _mk(app, "tfa", "operator")
        secret = tf.new_secret()
        with app.app_context():
            a = db.session.get(Admin, aid)
            a.totp_secret = secret
            a.totp_enabled = True
            db.session.commit()
        c = app.test_client()
        # المرحلة الأولى: كلمة مرور صحيحة → إعادة توجيه لـ 2FA، لا جلسة كاملة بعد
        r = c.post("/login", data={"username": "tfa", "password": "test12345"},
                   follow_redirects=False)
        assert r.status_code == 302 and "/login/2fa" in r.headers["Location"]
        # قبل الرمز: لوحة التحكم ما زالت محجوبة
        assert c.get("/admin/dashboard", follow_redirects=False).status_code == 302
        # المرحلة الثانية: رمز صحيح → دخول كامل
        code = pyotp.TOTP(secret).now()
        r2 = c.post("/login/2fa", data={"code": code}, follow_redirects=False)
        assert r2.status_code == 302 and "/admin" in r2.headers["Location"]
        assert c.get("/admin/dashboard").status_code == 200

    def test_login_2fa_rejects_wrong_code(self, app):
        aid = _mk(app, "tfa2", "operator")
        with app.app_context():
            a = db.session.get(Admin, aid)
            a.totp_secret = tf.new_secret()
            a.totp_enabled = True
            db.session.commit()
        c = app.test_client()
        c.post("/login", data={"username": "tfa2", "password": "test12345"})
        r = c.post("/login/2fa", data={"code": "000000"}, follow_redirects=False)
        assert r.status_code == 401
