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
from ..models import Setting, utcnow
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
    # العنوان العام الذي يتصل به عميلُ العميل (قد يختلف عن مضيف REST الإداري إن
    # كان CHR خلف NAT/عنوان عام). فارغ ⇒ نستخدم host نفسه.
    "public_host": (_SETTING_PREFIX + "public_host", False, False, False),
    # منفذ كل خدمة كما يراه عميل العميل (يُضمَّن في رد الجسر لكل نفق).
    "port_sstp": (_SETTING_PREFIX + "port_sstp", False, False, True),
    "port_pptp": (_SETTING_PREFIX + "port_pptp", False, False, True),
    "port_l2tp": (_SETTING_PREFIX + "port_l2tp", False, False, True),
    "port_ipsec": (_SETTING_PREFIX + "port_ipsec", False, False, True),
}
SECRET_FIELDS = {name for name, f in FIELDS.items() if f[1]}
BOOL_FIELDS = {"use_tls", "verify_tls"}

# ── قفل اتصال CHR ──────────────────────────────────────────────────────────
# بمجرد ضبط الاتصال والتحقق منه يُقفَل كي لا يُداس بصمت؛ تغييره بعدها يتطلّب تأكيدًا
# صريحًا من مسؤول عام (super-admin) ويُسجَّل في التدقيق. هذه مفاتيح وصفية منفصلة عن
# حقول الاتصال نفسها (FIELDS) فلا تخضع لتشفير ولا تظهر للعميل أبدًا.
LOCK_KEY = _SETTING_PREFIX + "locked"
LOCK_AT_KEY = _SETTING_PREFIX + "locked_at"
LOCK_BY_KEY = _SETTING_PREFIX + "locked_by"
VERIFIED_AT_KEY = _SETTING_PREFIX + "verified_at"
# المنافذ الافتراضية لكل خدمة (تُستخدم حين لا يضبطها المالك). IPsec/IKEv2 على UDP 4500.
SERVICE_PORT_DEFAULTS = {"sstp": 443, "pptp": 1723, "l2tp": 1701, "ovpn": 1194, "ipsec": 4500}

ARABIC_LABEL = {
    "host": "مضيف CHR (Host)",
    "port": "منفذ REST (Port)",
    "username": "اسم المستخدم",
    "password": "كلمة المرور",
    "use_tls": "اتصال آمن (HTTPS)",
    "verify_tls": "التحقق من شهادة TLS",
    "public_host": "العنوان العام للعملاء (Public Host)",
    "port_sstp": "منفذ SSTP",
    "port_pptp": "منفذ PPTP",
    "port_l2tp": "منفذ L2TP",
    "port_ipsec": "منفذ IPsec/IKEv2",
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


# ───────────────────────── lock state ─────────────────────────

def is_locked() -> bool:
    """هل اتصال CHR مقفل (لا يُداس إلا بتأكيد صريح من مسؤول عام)."""
    return _db_value(LOCK_KEY).strip().lower() in {"1", "true", "yes", "on"}


def lock_state() -> dict:
    """حالة القفل للعرض: مقفل؟ ومتى/مَن، ووقت آخر تحقق ناجح."""
    return {
        "locked": is_locked(),
        "locked_at": _db_value(LOCK_AT_KEY),
        "locked_by": _db_value(LOCK_BY_KEY),
        "verified_at": _db_value(VERIFIED_AT_KEY),
    }


def lock(*, actor_audit, actor_label: str = "") -> None:
    """يقفل اتصال CHR صراحةً. يُسجَّل في التدقيق. (المسار يحصره بالمسؤول العام.)"""
    if not bool(_resolve("host") and _resolve("username") and _resolve("password")):
        raise ChrSettingsError("أكمل بيانات اتصال CHR قبل قفله.")
    _set_db_value(LOCK_KEY, "1")
    _set_db_value(LOCK_AT_KEY, utcnow().replace(microsecond=0).isoformat() + "Z")
    _set_db_value(LOCK_BY_KEY, (actor_label or "")[:120])
    actor_audit(
        "chr_connection_locked", "chr_settings", "global",
        "قفل اتصال CHR (يتطلّب تأكيدًا صريحًا لتغييره)", {"by": actor_label},
    )


def unlock(*, actor_audit, actor_label: str = "") -> None:
    """يفكّ قفل اتصال CHR صراحةً (لإتاحة تعديله). يُسجَّل في التدقيق."""
    if not is_locked():
        raise ChrSettingsError("اتصال CHR غير مقفل أصلًا.")
    _set_db_value(LOCK_KEY, "0")
    actor_audit(
        "chr_connection_unlocked", "chr_settings", "global",
        "فكّ قفل اتصال CHR (أصبح قابلًا للتعديل)", {"by": actor_label},
    )


def _mark_verified() -> None:
    """يسجّل وقت آخر تحقق ناجح، ويقفل الاتصال تلقائيًا أول مرة يكتمل فيها ويُتحقق منه."""
    _set_db_value(VERIFIED_AT_KEY, utcnow().replace(microsecond=0).isoformat() + "Z")
    configured = bool(_resolve("host") and _resolve("username") and _resolve("password"))
    if configured and not is_locked():
        _set_db_value(LOCK_KEY, "1")
        _set_db_value(LOCK_AT_KEY, utcnow().replace(microsecond=0).isoformat() + "Z")
        _set_db_value(LOCK_BY_KEY, "auto-verify")


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
            "public_host": {
                "label": ARABIC_LABEL["public_host"],
                "value": _resolve("public_host"),
                "present": bool(_resolve("public_host")),
            },
            "port_sstp": {"label": ARABIC_LABEL["port_sstp"], "value": _resolve("port_sstp")},
            "port_pptp": {"label": ARABIC_LABEL["port_pptp"], "value": _resolve("port_pptp")},
            "port_l2tp": {"label": ARABIC_LABEL["port_l2tp"], "value": _resolve("port_l2tp")},
            "port_ipsec": {"label": ARABIC_LABEL["port_ipsec"], "value": _resolve("port_ipsec")},
        },
        "configured": bool(host and username and password),
        "encryption_available": encryption_available(),
        "service_port_defaults": SERVICE_PORT_DEFAULTS,
        "lock": lock_state(),
    }


def public_endpoint() -> dict:
    """العنوان العام والمنافذ لكل خدمة كما يتصل بها عميلُ العميل.

    يُضمَّن في رد الجسر لكل نفق. العنوان العام يقع على ``public_host`` وإلا على
    ``host`` الإداري. المنافذ غير المضبوطة تأخذ الافتراضي لكل خدمة.
    """
    host = _resolve("public_host") or _resolve("host")
    ports: dict[str, int] = {}
    for svc, default in SERVICE_PORT_DEFAULTS.items():
        raw = _resolve("port_" + svc) if ("port_" + svc) in FIELDS else ""
        ports[svc] = int(raw) if raw and raw.isdigit() else default
    return {"public_host": host, "ports": ports}


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

def validate_and_save(form, *, actor_audit, allow_locked_change: bool = False) -> None:
    """يتحقق من النموذج المُرسَل ويحفظ. كلمة المرور للكتابة فقط: إرسالها فارغة يُبقي
    القيمة المحفوظة. ``actor_audit`` هي دالة auth.audit. يرفع :class:`ChrSettingsError`.

    إن كان الاتصال مقفلًا (:func:`is_locked`) يُرفض الحفظ ما لم يُمرَّر
    ``allow_locked_change=True`` — وهذا تقرّره طبقة المسار بعد التأكد من أن الفاعل
    مسؤول عام وأرسل تأكيدًا صريحًا. أي تعديل لاتصال مقفل يُسجَّل بإجراء مميَّز.
    """
    if is_locked() and not allow_locked_change:
        raise ChrSettingsError(
            "اتصال CHR مقفل لحمايته من الكتابة بالخطأ. لتغييره فعّل «تأكيد تغيير اتصال مقفل» "
            "(يتطلّب صلاحية مسؤول عام)."
        )
    host = (form.get("host") or "").strip()[:255]
    port = (form.get("port") or "").strip()
    username = (form.get("username") or "").strip()[:80]
    password = (form.get("password") or "").strip()
    use_tls = bool(form.get("use_tls"))
    verify_tls = bool(form.get("verify_tls"))
    public_host = (form.get("public_host") or "").strip()[:255]
    # خدمات لها حقل منفذ عام صريح في الإعدادات (ovpn يأخذ الافتراضي فقط).
    service_ports = {
        svc: (form.get("port_" + svc) or "").strip()
        for svc in SERVICE_PORT_DEFAULTS
        if ("port_" + svc) in FIELDS
    }

    if not host:
        raise ChrSettingsError(f"الحقل «{ARABIC_LABEL['host']}» مطلوب.")
    if not username:
        raise ChrSettingsError(f"الحقل «{ARABIC_LABEL['username']}» مطلوب.")
    if port and not port.isdigit():
        raise ChrSettingsError(f"الحقل «{ARABIC_LABEL['port']}» يجب أن يكون أرقامًا فقط.")
    if port and not (1 <= int(port) <= 65535):
        raise ChrSettingsError(f"الحقل «{ARABIC_LABEL['port']}» خارج النطاق المسموح.")
    for svc, value in service_ports.items():
        if value and not value.isdigit():
            raise ChrSettingsError(f"الحقل «{ARABIC_LABEL['port_' + svc]}» يجب أن يكون أرقامًا فقط.")
        if value and not (1 <= int(value) <= 65535):
            raise ChrSettingsError(f"الحقل «{ARABIC_LABEL['port_' + svc]}» خارج النطاق المسموح.")

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
    _set_db_value(FIELDS["public_host"][0], public_host)
    for svc, value in service_ports.items():
        _set_db_value(FIELDS["port_" + svc][0], value)

    actor_audit(
        "chr_settings_overwritten_while_locked" if (allow_locked_change and is_locked()) else "chr_settings_saved",
        "chr_settings", "global",
        "تغيير اتصال CHR مقفل بتأكيد صريح" if (allow_locked_change and is_locked()) else "حفظ بيانات اتصال CHR",
        {"host": host, "port": port or _default_port(), "use_tls": use_tls, "verify_tls": verify_tls,
         "public_host": public_host, "password_changed": bool(password),
         "locked_change": bool(allow_locked_change and is_locked())},
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
    # نجاح التحقق ⇒ نسجّل وقته ونقفل الاتصال تلقائيًا أول مرة (حماية من الكتابة بالخطأ).
    was_locked = is_locked()
    _mark_verified()
    actor_audit(
        "chr_test_success", "chr_settings", "global",
        "نجاح اختبار اتصال CHR",
        {"identity": info.get("identity"), "version": info.get("version"),
         "auto_locked": bool(is_locked() and not was_locked)},
    )
    return {"ok": True, "locked": is_locked(), **info}
