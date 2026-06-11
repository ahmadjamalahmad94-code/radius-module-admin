"""Platform settings — DB-first resolver for keys previously set via env only.

Goal
====
The owner's rule is "everything from the UI, never the terminal". This module
moves a curated set of operational config keys (rate limits, license-check
policy, WhatsApp worker tuning, log level, three operational secrets) from
``os.environ`` / ``app.config`` into the ``Setting`` table and exposes them
through a small, well-defined API that all callers go through.

Resolution order per key
========================
1. The ``Setting`` table row (if present and non-empty after stripping).
2. ``current_app.config`` (kept as a fallback so a bootstrap with env vars
   only — before the owner saves anything in the UI — keeps behaving the
   same as today).
3. The schema-defined default.

For SECRETS the same chain applies but the DB row carries Fernet ciphertext
(via ``app.services.whatsapp.crypto.encrypt_secret``) — never plaintext.

Per-request caching
===================
A read is one PK lookup which is fast, but a typical request reads several
of these knobs (rate-limit check + signature check). We memoize per-request
via ``flask.g.platform_settings_cache`` and invalidate it on every write.

Public API
==========
* :data:`KEYS` — the migration catalog (key -> Spec).
* :func:`get_str` / :func:`get_int` / :func:`get_bool` / :func:`get_secret`
  — read with type coercion + fallback chain.
* :func:`set_value` — write (raw plaintext for non-secrets, encrypted on disk
  for secrets). Caller is expected to commit + audit.
* :func:`snapshot` — UI-safe dict per key: ``{value, source, masked, present,
  default}``. Never includes the plaintext value of a secret.
* :func:`save_form` — process a posted form (works with the same dict shape
  ``request.form``); coerces + persists + writes an audit row.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from flask import current_app, g

from ..extensions import db
from ..models import Setting


# ────────────────────────────────────────────────────────────────────
# Migration catalog
# ────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Spec:
    """Schema for one migrated key.

    Attributes:
        key: canonical key name (matches the env var / app.config attribute).
        kind: type tag — "str" | "int" | "bool" | "secret" | "enum".
        default: fallback when the DB row and app.config are both empty.
        group: UI group label (Arabic), purely cosmetic.
        label_ar: short Arabic field label shown in the form.
        hint_ar: optional helper text shown below the input.
        enum_choices: only for ``kind="enum"``.
        min_value / max_value: numeric bounds for ``kind="int"`` (inclusive).
    """
    key: str
    kind: str
    default: Any
    group: str
    label_ar: str
    hint_ar: str = ""
    enum_choices: tuple[str, ...] = ()
    min_value: Optional[int] = None
    max_value: Optional[int] = None


_GROUP_RATE = "حدود المعدّل (Rate Limits)"
_GROUP_LIC  = "سياسة فحص التراخيص"
_GROUP_WA   = "واتساب — إعدادات تشغيل"
_GROUP_LOG  = "السجلات"
_GROUP_SEC  = "مفاتيح تكامل (سرّ مشترك)"


# Curated migration set — operational knobs that today live only in env vars.
# This list is INTENTIONAL: master keys (FLASK_SECRET, *_FERNET_KEY,
# CUSTOMER_VAULT_ENCRYPTION_KEY, DATABASE_URL, ADMIN_*) stay env-only by
# security/bootstrap design — moving them into a DB they're used to read
# would create a circular dependency.
KEYS: dict[str, Spec] = {
    # ── Rate limits ────────────────────────────────────────────────────
    "RATE_LIMITS_ENABLED": Spec(
        "RATE_LIMITS_ENABLED", "bool", True, _GROUP_RATE,
        "تفعيل حدود المعدّل",
        "عند الإيقاف: لن يُطبَّق أي حد على تسجيل الدخول أو فحوصات التراخيص.",
    ),
    "LOGIN_RATE_LIMIT_MAX": Spec(
        "LOGIN_RATE_LIMIT_MAX", "int", 10, _GROUP_RATE,
        "محاولات الدخول الأقصى",
        "أقصى محاولات تسجيل دخول مسموحة لكل IP في النافذة الزمنية.",
        min_value=1, max_value=10000,
    ),
    "LOGIN_RATE_LIMIT_WINDOW_SECONDS": Spec(
        "LOGIN_RATE_LIMIT_WINDOW_SECONDS", "int", 900, _GROUP_RATE,
        "نافذة الدخول (ثانية)",
        "طول النافذة الزمنية لحساب محاولات الدخول.",
        min_value=10, max_value=86400,
    ),
    "LICENSE_CHECK_RATE_LIMIT_MAX": Spec(
        "LICENSE_CHECK_RATE_LIMIT_MAX", "int", 120, _GROUP_RATE,
        "فحوصات الترخيص الأقصى",
        "أقصى عدد فحوصات ترخيص لكل IP خلال النافذة.",
        min_value=1, max_value=100000,
    ),
    "LICENSE_CHECK_RATE_LIMIT_WINDOW_SECONDS": Spec(
        "LICENSE_CHECK_RATE_LIMIT_WINDOW_SECONDS", "int", 60, _GROUP_RATE,
        "نافذة فحص الترخيص (ثانية)",
        "النافذة الزمنية لاحتساب فحوصات الترخيص لكل IP.",
        min_value=10, max_value=3600,
    ),
    "LICENSE_KEY_RATE_LIMIT_MAX": Spec(
        "LICENSE_KEY_RATE_LIMIT_MAX", "int", 600, _GROUP_RATE,
        "فحص لكل مفتاح ترخيص — الأقصى",
        "أقصى عدد فحوصات لمفتاح ترخيص واحد خلال النافذة.",
        min_value=1, max_value=100000,
    ),
    "LICENSE_KEY_RATE_LIMIT_WINDOW_SECONDS": Spec(
        "LICENSE_KEY_RATE_LIMIT_WINDOW_SECONDS", "int", 300, _GROUP_RATE,
        "نافذة الفحص لكل مفتاح (ثانية)",
        "النافذة الزمنية لاحتساب فحوصات مفتاح ترخيص واحد.",
        min_value=10, max_value=86400,
    ),

    # ── License-check verification policy ──────────────────────────────
    "LICENSE_CHECK_SIGNATURE_REQUIRED": Spec(
        "LICENSE_CHECK_SIGNATURE_REQUIRED", "bool", True, _GROUP_LIC,
        "يجب أن يكون فحص الترخيص موقّعًا",
        "عند التفعيل: تُرفض أي فحوصات بدون توقيع HMAC صالح.",
    ),
    "LICENSE_CHECK_ALLOW_UNSIGNED": Spec(
        "LICENSE_CHECK_ALLOW_UNSIGNED", "bool", False, _GROUP_LIC,
        "السماح بالفحوصات غير الموقّعة",
        "للتجارب فقط — لا تُفعّل في الإنتاج.",
    ),
    "LICENSE_BEARER_AUTH_ENABLED": Spec(
        "LICENSE_BEARER_AUTH_ENABLED", "bool", True, _GROUP_LIC,
        "الربط المبسّط — مفتاح الترخيص يكفي",
        "عند التفعيل: مفتاح الترخيص في جسم الطلب (عبر HTTPS) يوثّق الجسر بنفسه "
        "بدون توقيع HMAC أو سر ربط. الطلبات الموقّعة القديمة تبقى مقبولة دائمًا.",
    ),
    "LICENSE_CHECK_MAX_CLOCK_SKEW_SECONDS": Spec(
        "LICENSE_CHECK_MAX_CLOCK_SKEW_SECONDS", "int", 300, _GROUP_LIC,
        "هامش انحراف الساعة المسموح (ثانية)",
        "الفرق المسموح بين توقيت الفحص وتوقيت الخادم.",
        min_value=0, max_value=86400,
    ),
    "LICENSE_CHECK_REPLAY_WINDOW_SECONDS": Spec(
        "LICENSE_CHECK_REPLAY_WINDOW_SECONDS", "int", 600, _GROUP_LIC,
        "نافذة كشف الإعادة (ثانية)",
        "كم من الوقت نتذكر فيه nonces قديمة لمنع إعادة استخدامها.",
        min_value=0, max_value=86400,
    ),

    # ── WhatsApp operational ───────────────────────────────────────────
    "WHATSAPP_HTTP_TIMEOUT_SECONDS": Spec(
        "WHATSAPP_HTTP_TIMEOUT_SECONDS", "int", 15, _GROUP_WA,
        "مهلة طلب HTTP لواتساب (ثانية)",
        "مهلة الطلبات الصادرة إلى Meta Graph API.",
        min_value=1, max_value=600,
    ),
    "WHATSAPP_DRAIN_BATCH_SIZE": Spec(
        "WHATSAPP_DRAIN_BATCH_SIZE", "int", 50, _GROUP_WA,
        "حجم دفعة معالجة الطابور",
        "كم رسالة واتساب يعالج العامل في كل دورة.",
        min_value=1, max_value=10000,
    ),
    "WHATSAPP_MAX_ATTEMPTS": Spec(
        "WHATSAPP_MAX_ATTEMPTS", "int", 3, _GROUP_WA,
        "أقصى محاولات إعادة الإرسال",
        "بعد هذا العدد تُعتبر الرسالة فاشلة نهائيًا.",
        min_value=1, max_value=20,
    ),
    "WHATSAPP_DEFAULT_TIMEZONE": Spec(
        "WHATSAPP_DEFAULT_TIMEZONE", "str", "Asia/Hebron", _GROUP_WA,
        "المنطقة الزمنية الافتراضية",
        "تُستخدم لحساب نوافذ المعدّل اليومي/الشهري للقوالب.",
    ),
    "WHATSAPP_DEFAULT_COUNTRY": Spec(
        "WHATSAPP_DEFAULT_COUNTRY", "str", "PS", _GROUP_WA,
        "كود الدولة الافتراضي",
        "ISO-3166 alpha-2 — لتطبيع أرقام الهواتف عند الإرسال.",
    ),

    # ── Logging ────────────────────────────────────────────────────────
    "LOG_LEVEL": Spec(
        "LOG_LEVEL", "enum", "INFO", _GROUP_LOG,
        "مستوى السجل",
        "مستوى التسجيل المطبَّق على جذر التطبيق.",
        enum_choices=("DEBUG", "INFO", "WARNING", "ERROR"),
    ),

    # ── Integration secrets (encrypted, masked, write-only) ────────────
    "LICENSE_CHECK_HMAC_SECRET": Spec(
        "LICENSE_CHECK_HMAC_SECRET", "secret", "", _GROUP_SEC,
        "مفتاح HMAC لفحص التراخيص",
        "يُستخدم لتوقيع طلبات /api/license/check. ٣٢ حرفًا عشوائيًا على الأقل.",
    ),
    "RADIUS_PROXY_SHARED_SECRET": Spec(
        "RADIUS_PROXY_SHARED_SECRET", "secret", "", _GROUP_SEC,
        "السرّ المشترك لوكيل RADIUS",
        "يُستخدم في X-Proxy-Token (HMAC-SHA256). ٣٢ حرفًا على الأقل.",
    ),
    # NOTE: META_APP_SECRET is intentionally NOT here — it's already managed
    # by the existing /admin/settings (WhatsApp Cloud + Embedded sub-sections)
    # which store it encrypted under its own namespace. Listing it again here
    # would split the source of truth.
}


# ────────────────────────────────────────────────────────────────────
# Crypto + DB helpers
# ────────────────────────────────────────────────────────────────────

def _crypto():
    """Lazy import — keeps the resolver usable before the app is configured."""
    from .whatsapp import crypto as wac
    return wac


def _is_secret(key: str) -> bool:
    spec = KEYS.get(key)
    return bool(spec and spec.kind == "secret")


def _setting_row(key: str) -> Optional[Setting]:
    return db.session.get(Setting, key)


def _invalidate_cache() -> None:
    try:
        g.pop("platform_settings_cache", None)
    except RuntimeError:
        # outside request context — no cache to drop.
        pass


def _cache() -> dict:
    try:
        cache = g.get("platform_settings_cache", None)
    except RuntimeError:
        return {}
    if cache is None:
        cache = {}
        try:
            g.platform_settings_cache = cache
        except RuntimeError:
            return {}
    return cache


# ────────────────────────────────────────────────────────────────────
# Core read API
# ────────────────────────────────────────────────────────────────────

def _read_raw(key: str) -> tuple[str, str]:
    """Return ``(raw_value, source)`` for one key.

    ``raw_value`` is the DB row's ``value`` (a Fernet token for secrets) when
    set, else the ``app.config`` value coerced to string, else ``""``.
    ``source`` is ``"db" | "config" | "default"``.
    """
    cache = _cache()
    if key in cache:
        return cache[key]
    row = _setting_row(key)
    if row is not None and (row.value or "").strip() != "":
        out = ((row.value or "").strip(), "db")
        cache[key] = out
        return out

    spec = KEYS.get(key)
    cfg_val: Any = None
    try:
        cfg_val = current_app.config.get(key)
    except RuntimeError:
        cfg_val = None
    if cfg_val is not None and str(cfg_val).strip() != "":
        out = (str(cfg_val).strip(), "config")
        cache[key] = out
        return out

    if spec is not None:
        out = (str(spec.default), "default")
    else:
        out = ("", "default")
    cache[key] = out
    return out


def get_str(key: str, default: Optional[str] = None) -> str:
    raw, _src = _read_raw(key)
    if raw == "":
        if default is not None:
            return str(default)
        spec = KEYS.get(key)
        return str(spec.default) if spec is not None else ""
    return raw


def get_int(key: str, default: Optional[int] = None) -> int:
    raw, _src = _read_raw(key)
    try:
        return int(raw)
    except (TypeError, ValueError):
        if default is not None:
            return int(default)
        spec = KEYS.get(key)
        if spec is not None:
            try:
                return int(spec.default)
            except Exception:  # noqa: BLE001
                return 0
        return 0


_TRUE = {"1", "true", "yes", "on", "y", "t"}
_FALSE = {"0", "false", "no", "off", "n", "f", ""}


def get_bool(key: str, default: Optional[bool] = None) -> bool:
    raw, _src = _read_raw(key)
    low = raw.strip().lower()
    if low in _TRUE:
        return True
    if low in _FALSE:
        if default is not None and raw == "":
            return bool(default)
        return False
    if default is not None:
        return bool(default)
    spec = KEYS.get(key)
    return bool(spec.default) if spec is not None else False


def get_secret(key: str, default: str = "") -> str:
    """Return the decrypted secret. Empty string when key/crypto is missing.

    Never raises — callers are typically request handlers that should keep
    serving even if the secret is unrecoverable (the worst case is a flow
    that uses the secret fails its own validation downstream).
    """
    raw, src = _read_raw(key)
    if src == "db" and raw:
        try:
            return _crypto().decrypt_secret(raw)
        except Exception:  # noqa: BLE001 — never crash on bad keystate
            return ""
    # config / default paths come back already in plaintext.
    return raw or default


# ────────────────────────────────────────────────────────────────────
# Write API
# ────────────────────────────────────────────────────────────────────

class PlatformSettingsError(ValueError):
    """Raised when a posted setting fails validation."""


def _coerce(spec: Spec, raw: Any) -> str:
    """Coerce a posted form value to the canonical string form stored in DB."""
    if spec.kind == "bool":
        # Form checkboxes only appear in the submission when checked.
        s = (str(raw) if raw is not None else "").strip().lower()
        if raw is True or s in _TRUE:
            return "1"
        return "0"
    if spec.kind == "int":
        s = str(raw or "").strip()
        if s == "":
            raise PlatformSettingsError(f"{spec.label_ar}: قيمة مطلوبة.")
        try:
            n = int(s)
        except ValueError as exc:
            raise PlatformSettingsError(f"{spec.label_ar}: يجب أن تكون رقمًا صحيحًا.") from exc
        if spec.min_value is not None and n < spec.min_value:
            raise PlatformSettingsError(f"{spec.label_ar}: الحد الأدنى {spec.min_value}.")
        if spec.max_value is not None and n > spec.max_value:
            raise PlatformSettingsError(f"{spec.label_ar}: الحد الأعلى {spec.max_value}.")
        return str(n)
    if spec.kind == "enum":
        s = str(raw or "").strip()
        if s not in spec.enum_choices:
            raise PlatformSettingsError(f"{spec.label_ar}: قيمة غير مسموحة.")
        return s
    if spec.kind == "secret":
        s = (str(raw) if raw is not None else "").strip()
        # Empty -> caller will decide whether to keep or clear (handled in save_form).
        return s
    # default: string
    return (str(raw) if raw is not None else "").strip()


def set_value(key: str, value: Any) -> None:
    """Persist a single setting.

    Secrets are encrypted at rest via the panel's app master Fernet key
    (same key that protects WhatsApp / CHR settings). Empty values clear
    the row's value field — the resolver then falls back to config/default.
    """
    spec = KEYS.get(key)
    if spec is None:
        raise PlatformSettingsError(f"مفتاح غير معروف: {key}")
    coerced = _coerce(spec, value)
    if spec.kind == "secret" and coerced:
        coerced = _crypto().encrypt_secret(coerced)
    row = _setting_row(key)
    if row is None:
        row = Setting(key=key)
    row.value = coerced
    db.session.add(row)
    _invalidate_cache()


def save_form(form: dict[str, Any], *, actor_audit: Optional[Callable] = None) -> dict[str, Any]:
    """Persist every key declared in :data:`KEYS`.

    Form conventions:
      * Booleans: missing key == False (HTML checkbox semantics).
      * Secrets: an empty value LEAVES the existing stored value alone (so the
        masked placeholder doesn't blow away a previously saved key).
      * Numeric / enum / str: validated against the Spec.

    Returns a small dict the audit log + UI can read:
      ``{count_saved, count_kept, secrets_rotated, fields_changed}``.

    Raises :class:`PlatformSettingsError` on the first invalid value. The
    caller is expected to wrap in try / rollback / flash.
    """
    saved = 0
    kept = 0
    secrets_rotated: list[str] = []
    fields_changed: dict[str, bool] = {}

    for key, spec in KEYS.items():
        if spec.kind == "secret":
            raw = (form.get(key) or "").strip()
            if not raw:
                # Leave the stored value alone (masked placeholder convention).
                kept += 1
                continue
            set_value(key, raw)
            secrets_rotated.append(key)
            fields_changed[key] = True
            saved += 1
            continue

        if spec.kind == "bool":
            # Checkbox semantics: missing => False, present => True.
            present = form.get(key)
            raw = "1" if present else "0"
        else:
            raw = form.get(key)
            if raw is None:
                kept += 1
                continue

        set_value(key, raw)
        fields_changed[key] = True
        saved += 1

    if actor_audit is not None:
        actor_audit(
            "platform_settings_saved",
            "platform_settings",
            "global",
            "حفظ إعدادات المنصة (مهاجَرة من البيئة).",
            {
                "saved": saved,
                "kept": kept,
                # Booleans only — NEVER include the plaintext for secrets.
                "fields_changed": fields_changed,
                "secrets_rotated": secrets_rotated,
            },
        )
    return {
        "saved": saved,
        "kept": kept,
        "secrets_rotated": secrets_rotated,
        "fields_changed": fields_changed,
    }


# ────────────────────────────────────────────────────────────────────
# UI snapshot
# ────────────────────────────────────────────────────────────────────

@dataclass
class SettingView:
    key: str
    kind: str
    label_ar: str
    hint_ar: str
    group: str
    value: str               # for str/int/enum: the actual value; for secret: "" (never plaintext)
    masked: str              # secrets: masked preview; non-secrets: the value
    source: str              # db | config | default
    default: str
    has_db_override: bool
    needs_owner_input: bool  # True for unset secrets — drives "بانتظار تفعيلك" badge
    enum_choices: tuple[str, ...] = field(default_factory=tuple)
    min_value: Optional[int] = None
    max_value: Optional[int] = None
    bool_value: bool = False


def _view_for(spec: Spec) -> SettingView:
    raw, src = _read_raw(spec.key)
    needs_input = False
    if spec.kind == "secret":
        # We never expose the plaintext; the form will show a masked hint and
        # accept a new value (empty = keep existing).
        if src == "db" and raw:
            try:
                plain = _crypto().decrypt_secret(raw)
            except Exception:  # noqa: BLE001
                plain = ""
            masked = _crypto().mask_secret(plain) if plain else "—"
            value = ""
        else:
            # No DB value, env may still have one but we don't show env secrets
            # in plaintext either — the UI says "بانتظار تفعيلك".
            cfg = current_app.config.get(spec.key, "") if current_app else ""
            if cfg:
                masked = _crypto().mask_secret(str(cfg))
            else:
                masked = "—"
                needs_input = True
            value = ""
        bool_value = False
    elif spec.kind == "bool":
        bool_value = raw.lower() in _TRUE
        value = "1" if bool_value else "0"
        masked = "نعم" if bool_value else "لا"
    elif spec.kind == "int":
        value = raw or str(spec.default)
        masked = value
        bool_value = False
    elif spec.kind == "enum":
        value = raw or str(spec.default)
        masked = value
        bool_value = False
    else:
        value = raw or str(spec.default)
        masked = value
        bool_value = False

    return SettingView(
        key=spec.key,
        kind=spec.kind,
        label_ar=spec.label_ar,
        hint_ar=spec.hint_ar,
        group=spec.group,
        value=value,
        masked=masked,
        source=src,
        default=str(spec.default),
        has_db_override=(src == "db"),
        needs_owner_input=needs_input,
        enum_choices=spec.enum_choices,
        min_value=spec.min_value,
        max_value=spec.max_value,
        bool_value=bool_value,
    )


def snapshot() -> dict[str, list[SettingView]]:
    """Group :class:`SettingView` rows by ``group`` for the template.

    Group order is the first-encounter order in :data:`KEYS`.
    """
    out: dict[str, list[SettingView]] = {}
    for spec in KEYS.values():
        out.setdefault(spec.group, []).append(_view_for(spec))
    return out


def health() -> dict[str, Any]:
    """Tiny snapshot for the page header.

    Returns: ``{total, with_db_override, secrets_pending}``.
    """
    total = len(KEYS)
    with_db = 0
    pending = 0
    for spec in KEYS.values():
        view = _view_for(spec)
        if view.has_db_override:
            with_db += 1
        if spec.kind == "secret" and view.needs_owner_input:
            pending += 1
    return {"total": total, "with_db_override": with_db, "secrets_pending": pending}


__all__ = [
    "KEYS",
    "PlatformSettingsError",
    "SettingView",
    "Spec",
    "get_bool",
    "get_int",
    "get_secret",
    "get_str",
    "health",
    "save_form",
    "set_value",
    "snapshot",
]
