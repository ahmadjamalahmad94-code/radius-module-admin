"""إعدادات اتصال CHR المركزية — يُدخلها المالك في لوحة التراخيص.

تخزّن مجموعة بيانات اعتماد CHR واحدة (مضيف/منفذ/مستخدم/كلمة مرور/TLS) في جدول
``settings`` (مفتاح-قيمة). كلمة المرور تُخزَّن مشفّرة عبر ``customer_vault_crypto``
(مفتاح ``CUSTOMER_VAULT_ENCRYPTION_KEY`` من البيئة) — وهذا مسموح هنا لأنها لوحة
المالك المركزية لا لوحة العميل. لا تُكتب أي قيمة سرّية بالكود.

قواعد الأمان (مطابقة لنمط whatsapp/cloud_settings):
* كلمة المرور لا تُعاد أبدًا للواجهة بنصها الصريح — فقط معاينة ``mask_secret``
  وعلم ``present``. الكشف الصريح إجراء منفصل ومُدقَّق ومحصور بالمسؤول العام.
* لا تُسجَّل كلمة المرور ولا تُوضع في نص استثناء.
* اختبار الاتصال يمرّ عبر :class:`RouterOSClient` (طبقة الشبكة الوحيدة).
"""
from __future__ import annotations

from flask import current_app

from ..extensions import db
from ..models import Setting
from .customer_vault_crypto import (
    VaultCryptoError,
    decrypt_secret,
    encrypt_secret,
    encryption_available,
    mask_secret,
)
from .routeros_client import RouterOSClient, RouterOSError


class ChrSettingsError(ValueError):
    """خطأ تحقق/أمان يُعرض على واجهة المسؤول (رسالة عربية)."""


# اسم الحقل → (مفتاح الإعداد، هل هو سرّي، مطلوب، رقمي)
_SETTING_PREFIX = "chr."
FIELDS: dict[str, tuple[str, bool, bool, bool]] = {
    "host": (_SETTING_PREFIX + "host", False, True, False),
    "port": (_SETTING_PREFIX + "port", False, False, True),
    "username": (_SETTING_PREFIX + "username", False, True, False),
    "password": (_SETTING_PREFIX + "password", True, True, False),
    "use_tls": (_SETTING_PREFIX + "use_tls", False, False, False),
    "verify_tls": (_SETTING_PREFIX + "verify_tls", False, False, False),
}
SECRET_FIELDS = {name for name, f in FIELDS.items() if f[1]}
BOOL_FIELDS = {"use_tls", "verify_tls"}

ARABIC_LABEL = {
    "host": "مضيف CHR (Host)",
    "port": "منفذ REST (Port)",
    "username": "اسم المستخدم",
    "password": "كلمة المرور",
    "use_tls": "اتصال آمن (HTTPS)",
    "verify_tls": "التحقق من شهادة TLS",
}


# ───────────────────────── config / availability ─────────────────────────

def enabled() -> bool:
    return bool(current_app.config.get("CHR_PROVISIONING_ENABLED", False))


def _default_port() -> int:
    return 443


def _http_timeout() -> int:
    return int(current_app.config.get("CHR_HTTP_TIMEOUT_SECONDS", 15))


# ───────────────────────── low-level store ─────────────────────────

def _db_value(key: str) -> str:
    row = db.session.get(Setting, key)
    return (row.value or "") if row else ""


def _set_db_value(key: str, value: str) -> None:
    row = db.session.get(Setting, key)
    if not row:
        row = Setting(key=key)
    row.value = value
    db.session.add(row)


def _resolve(name: str) -> str:
    """يعيد القيمة الصريحة لحقل (يفكّ تشفير السرّي). فارغة إن لم تُضبط."""
    setting_key, is_secret, _req, _num = FIELDS[name]
    raw = _db_value(setting_key)
    if not raw:
        return ""
    if is_secret:
        try:
            return decrypt_secret(raw)
        except VaultCryptoError:
            return ""  # نص مشفّر تالف/مفتاح خاطئ → نعامله كغير مضبوط بدل 500
    return raw


def _resolve_bool(name: str, default: bool) -> bool:
    raw = _db_value(FIELDS[name][0])
    if raw == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


# ───────────────────────── public read API ─────────────────────────

def get_state() -> dict:
    """حالة آمنة للواجهة. السرّ يُظهر فقط ``present`` + ``masked`` (لا نص صريح)."""
    host = _resolve("host")
    port = _resolve("port") or str(_default_port())
    username = _resolve("username")
    password = _resolve("password")
    use_tls = _resolve_bool("use_tls", True)
    verify_tls = _resolve_bool("verify_tls", bool(current_app.config.get("CHR_TLS_VERIFY", False)))
    return {
        "fields": {
            "host": {"label": ARABIC_LABEL["host"], "value": host, "present": bool(host)},
            "port": {"label": ARABIC_LABEL["port"], "value": port, "present": bool(_resolve("port"))},
            "username": {"label": ARABIC_LABEL["username"], "value": username, "present": bool(username)},
            "password": {
                "label": ARABIC_LABEL["password"],
                "present": bool(password),
                "masked": mask_secret(password) if password else "—",
            },
            "use_tls": {"label": ARABIC_LABEL["use_tls"], "value": use_tls},
            "verify_tls": {"label": ARABIC_LABEL["verify_tls"], "value": verify_tls},
        },
        "configured": bool(host and username and password),
        "encryption_available": encryption_available(),
    }


def resolved() -> dict:
    """داخلي: القيم الفعّالة للاختبار/التزويد (ليست للواجهة)."""
    return {
        "host": _resolve("host"),
        "port": int(_resolve("port") or _default_port()),
        "username": _resolve("username"),
        "password": _resolve("password"),
        "use_tls": _resolve_bool("use_tls", True),
        "verify_tls": _resolve_bool("verify_tls", bool(current_app.config.get("CHR_TLS_VERIFY", False))),
    }


def build_client() -> RouterOSClient:
    """ينشئ عميل RouterOS من القيم المحفوظة. يرفع ChrSettingsError إن لم تكتمل."""
    creds = resolved()
    if not (creds["host"] and creds["username"] and creds["password"]):
        raise ChrSettingsError("أكمل مضيف CHR واسم المستخدم وكلمة المرور أولًا.")
    return RouterOSClient(
        host=creds["host"],
        port=creds["port"],
        username=creds["username"],
        password=creds["password"],
        use_tls=creds["use_tls"],
        verify_tls=creds["verify_tls"],
        timeout=_http_timeout(),
    )


# ───────────────────────── validation + save ─────────────────────────

def validate_and_save(form, *, actor_audit) -> None:
    """يتحقق من النموذج المُرسَل ويحفظ. كلمة المرور للكتابة فقط: إرسالها فارغة يُبقي
    القيمة المحفوظة. ``actor_audit`` هي دالة auth.audit. يرفع :class:`ChrSettingsError`."""
    host = (form.get("host") or "").strip()[:255]
    port = (form.get("port") or "").strip()
    username = (form.get("username") or "").strip()[:80]
    password = (form.get("password") or "").strip()
    use_tls = bool(form.get("use_tls"))
    verify_tls = bool(form.get("verify_tls"))

    if not host:
        raise ChrSettingsError(f"الحقل «{ARABIC_LABEL['host']}» مطلوب.")
    if not username:
        raise ChrSettingsError(f"الحقل «{ARABIC_LABEL['username']}» مطلوب.")
    if port and not port.isdigit():
        raise ChrSettingsError(f"الحقل «{ARABIC_LABEL['port']}» يجب أن يكون أرقامًا فقط.")
    if port and not (1 <= int(port) <= 65535):
        raise ChrSettingsError(f"الحقل «{ARABIC_LABEL['port']}» خارج النطاق المسموح.")

    # كلمة المرور: إذا فارغة نُبقي المحفوظة؛ وإلا لا بد من توفّر التشفير لحفظها مشفّرة.
    if password and not encryption_available():
        raise ChrSettingsError(
            "تخزين كلمة مرور CHR يتطلّب ضبط CUSTOMER_VAULT_ENCRYPTION_KEY في البيئة."
        )
    if not password and not _resolve("password"):
        raise ChrSettingsError(f"الحقل «{ARABIC_LABEL['password']}» مطلوب.")

    _set_db_value(FIELDS["host"][0], host)
    _set_db_value(FIELDS["port"][0], port or str(_default_port()))
    _set_db_value(FIELDS["username"][0], username)
    if password:
        _set_db_value(FIELDS["password"][0], encrypt_secret(password))
    _set_db_value(FIELDS["use_tls"][0], "1" if use_tls else "0")
    _set_db_value(FIELDS["verify_tls"][0], "1" if verify_tls else "0")

    actor_audit(
        "chr_settings_saved", "chr_settings", "global",
        "حفظ بيانات اتصال CHR",
        {"host": host, "port": port or _default_port(), "use_tls": use_tls, "verify_tls": verify_tls,
         "password_changed": bool(password)},
    )


def reveal(*, actor_audit) -> str:
    """يعيد كلمة مرور CHR الصريحة للعرض المؤقت. مُدقَّق (للمسؤول العام فقط عبر المسار)."""
    value = _resolve("password")
    if not value:
        raise ChrSettingsError("لا توجد كلمة مرور محفوظة لكشفها.")
    actor_audit(
        "chr_secret_revealed", "chr_settings", "password",
        "كشف مؤقت لكلمة مرور CHR", {"field": "password"},
    )
    return value


# ───────────────────────── test connection ─────────────────────────

def test_connection(*, actor_audit) -> dict:
    """يتحقق من بيانات الاعتماد المحفوظة ضد CHR. لا يرفع لأخطاء الشبكة — يعيد نتيجة
    منظّمة. يُدقّق النجاح/الفشل."""
    client = build_client()
    try:
        info = client.test_connection()
    except RouterOSError as exc:
        actor_audit(
            "chr_test_failed", "chr_settings", "global",
            "فشل اختبار اتصال CHR", {"code": exc.code},
        )
        return {"ok": False, "code": exc.code, "message": exc.message}
    actor_audit(
        "chr_test_success", "chr_settings", "global",
        "نجاح اختبار اتصال CHR",
        {"identity": info.get("identity"), "version": info.get("version")},
    )
    return {"ok": True, **info}
