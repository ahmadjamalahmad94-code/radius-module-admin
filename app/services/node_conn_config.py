"""app.services.node_conn_config — per-CHR end-user CONNECTION config.

feat/chr-conn-config-panel (M2). The «إدارة عقد البيانات» page lets the
operator tune, PER CHR, the end-user connection plane WITHOUT touching a
terminal: the IP pool range, pushed DNS, the PPP gateway address +
encryption policy, and the SSTP port + cert mode (auto-self-signed vs a
custom pre-installed cert) + an optional cert common-name override.

Stored as a JSON blob on ``FleetChrNode.conn_config_json``. Empty/missing
keys fall back to the fleet-constant DEFAULTS, so existing nodes keep the
exact behaviour they had before this column landed. The renderer
(:func:`fleet.registry.onboarding_service.OnboardingService._build_bindings`)
overlays the effective values onto the template bindings.

This module is the SINGLE place that validates + persists the blob:
  * :func:`get_conn_config`   — effective config (defaults ∪ stored).
  * :func:`set_conn_config`   — validate a partial update, merge, persist.

Validation is enforced HERE (the route calls this, never writes raw), so
an API client can't bypass the UI checks. Reserved-subnet overlap
(10.98/10.99/10.51 + the other fleet reserves) is rejected via
``app.services.reserved_subnets`` — the same guard onboarding uses for
the PPP gateway.
"""
from __future__ import annotations

import ipaddress
import json
import logging
from typing import Any

from app.extensions import db
from app.services.reserved_subnets import is_reserved_address, is_reserved_range

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════════
# Defaults — MUST match the fleet-constant template defaults so a node with
# an empty blob renders byte-identically to the pre-M2 behaviour.
# ════════════════════════════════════════════════════════════════════════
DEFAULTS: dict[str, Any] = {
    "pool_ranges": "10.50.0.10-10.50.255.254",
    "dns": "1.1.1.1,1.0.0.1",
    "gw_local_addr": "10.0.0.1",
    "encryption": "required",      # use-encryption: required | yes | no
    "sstp_port": 443,
    "sstp_cert_mode": "auto",      # auto (self-signed) | custom
    "sstp_cert_name": "",          # used only when sstp_cert_mode == custom
    "sstp_cert_cn": "",            # CN override; "" ⇒ template uses CHR public IP
}

_ENCRYPTION_VALUES = frozenset({"required", "yes", "no"})
_CERT_MODES = frozenset({"auto", "custom"})

# A defensive cap so a fat-fingered range can't ask RouterOS for a
# /8-sized pool. The fleet default is a /16-ish span; allow generous head-
# room but reject absurd inputs.
_MAX_POOL_ADDRESSES = 1 << 20  # ~1M


class ConnConfigError(ValueError):
    """Validation failure with an operator-facing Arabic message."""


# ════════════════════════════════════════════════════════════════════════
# Read
# ════════════════════════════════════════════════════════════════════════


def _load_raw(node) -> dict[str, Any]:
    raw = getattr(node, "conn_config_json", None) or "{}"
    try:
        loaded = json.loads(raw) if isinstance(raw, str) else dict(raw or {})
    except (TypeError, ValueError):
        loaded = {}
    return loaded if isinstance(loaded, dict) else {}


def get_conn_config(node) -> dict[str, Any]:
    """Return the EFFECTIVE config: DEFAULTS overlaid with stored keys.

    Only known keys are surfaced; unknown stored keys are dropped so the
    UI + renderer see a stable shape.
    """
    stored = _load_raw(node)
    cfg = dict(DEFAULTS)
    for k in DEFAULTS:
        if k in stored and stored[k] not in (None, ""):
            cfg[k] = stored[k]
        elif k in stored and k in ("sstp_cert_name", "sstp_cert_cn"):
            # empty string IS a meaningful value for these (clears the override)
            cfg[k] = stored[k]
    # Coerce the int field.
    try:
        cfg["sstp_port"] = int(cfg["sstp_port"])
    except (TypeError, ValueError):
        cfg["sstp_port"] = DEFAULTS["sstp_port"]
    return cfg


# ════════════════════════════════════════════════════════════════════════
# Validation
# ════════════════════════════════════════════════════════════════════════


def _validate_pool_ranges(value: str) -> str:
    v = (value or "").strip()
    if not v:
        raise ConnConfigError("نطاق العناوين (pool) مطلوب.")
    # RouterOS accepts comma-separated ``A-B`` or single addresses.
    total = 0
    for part in v.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_s, hi_s = part.split("-", 1)
            try:
                lo = ipaddress.IPv4Address(lo_s.strip())
                hi = ipaddress.IPv4Address(hi_s.strip())
            except ipaddress.AddressValueError:
                raise ConnConfigError(f"نطاق غير صالح: «{part}».")
            if int(hi) < int(lo):
                raise ConnConfigError(f"بداية النطاق أكبر من نهايته: «{part}».")
            total += int(hi) - int(lo) + 1
        else:
            try:
                ipaddress.IPv4Address(part)
            except ipaddress.AddressValueError:
                raise ConnConfigError(f"عنوان غير صالح: «{part}».")
            total += 1
    if total <= 0:
        raise ConnConfigError("نطاق العناوين فارغ.")
    if total > _MAX_POOL_ADDRESSES:
        raise ConnConfigError(
            "نطاق العناوين ضخم جداً — قلّصه إلى أقل من مليون عنوان."
        )
    # Reserved-subnet overlap: the end-user pool must NOT collide with the
    # fleet control/data/users planes (10.99 / 10.98 / 10.51) or the other
    # reserves — that would steal addresses from the tunnels themselves.
    if is_reserved_range(v):
        raise ConnConfigError(
            "نطاق العناوين يتقاطع مع شبكات الأسطول المحجوزة "
            "(10.98/10.99/10.51) — اختر نطاقاً خارجها (مثل 10.50.x)."
        )
    return v


def _validate_dns(value: str) -> str:
    v = (value or "").strip()
    if not v:
        raise ConnConfigError("خوادم DNS مطلوبة.")
    out = []
    for part in v.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            ipaddress.IPv4Address(part)
        except ipaddress.AddressValueError:
            raise ConnConfigError(f"عنوان DNS غير صالح: «{part}».")
        out.append(part)
    if not out:
        raise ConnConfigError("خوادم DNS فارغة.")
    return ",".join(out)


def _validate_gw(value: str) -> str:
    v = (value or "").strip()
    if not v:
        raise ConnConfigError("عنوان بوابة PPP مطلوب.")
    try:
        ipaddress.IPv4Address(v)
    except ipaddress.AddressValueError:
        raise ConnConfigError(f"عنوان بوابة PPP غير صالح: «{v}».")
    if is_reserved_address(v):
        raise ConnConfigError(
            "عنوان بوابة PPP يقع داخل شبكات الأسطول المحجوزة "
            "(10.98/10.99/10.51) — اختر عنواناً خارجها."
        )
    return v


def _validate_port(value: Any) -> int:
    try:
        p = int(value)
    except (TypeError, ValueError):
        raise ConnConfigError("منفذ SSTP يجب أن يكون رقماً.")
    if not (1 <= p <= 65535):
        raise ConnConfigError("منفذ SSTP يجب أن يكون بين 1 و 65535.")
    return p


def _validate_cn(value: str) -> str:
    v = (value or "").strip()
    if not v:
        return ""  # empty ⇒ template falls back to CHR public IP
    # A CN is a hostname or an IP. Keep it conservative: letters, digits,
    # dot, hyphen; no spaces / quotes (it lands inside common-name="...").
    if len(v) > 64:
        raise ConnConfigError("الاسم الشائع (CN) طويل جداً (الحد 64 حرفاً).")
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-")
    if any(c not in allowed for c in v):
        raise ConnConfigError(
            "الاسم الشائع (CN) يحوي رموزاً غير مسموحة — استخدم حروفاً "
            "وأرقاماً ونقاطاً وشرطات فقط (اسم مضيف أو IP)."
        )
    return v


def _validate(partial: dict[str, Any], *, base: dict[str, Any]) -> dict[str, Any]:
    """Merge ``partial`` onto ``base`` (effective current) and validate the
    RESULT. Returns the clean, full config dict ready to store."""
    merged = dict(base)
    for k, v in (partial or {}).items():
        if k in DEFAULTS:
            merged[k] = v

    out: dict[str, Any] = {}
    out["pool_ranges"] = _validate_pool_ranges(str(merged.get("pool_ranges", "")))
    out["dns"] = _validate_dns(str(merged.get("dns", "")))
    out["gw_local_addr"] = _validate_gw(str(merged.get("gw_local_addr", "")))

    enc = str(merged.get("encryption", "required")).strip().lower()
    if enc not in _ENCRYPTION_VALUES:
        raise ConnConfigError("قيمة التشفير يجب أن تكون required أو yes أو no.")
    out["encryption"] = enc

    out["sstp_port"] = _validate_port(merged.get("sstp_port", 443))

    mode = str(merged.get("sstp_cert_mode", "auto")).strip().lower()
    if mode not in _CERT_MODES:
        raise ConnConfigError("وضع شهادة SSTP يجب أن يكون auto أو custom.")
    out["sstp_cert_mode"] = mode

    cert_name = str(merged.get("sstp_cert_name", "") or "").strip()
    if mode == "custom" and not cert_name:
        raise ConnConfigError(
            "في وضع الشهادة المخصّصة يجب إدخال اسم الشهادة المثبّتة على الـ CHR."
        )
    # In auto mode we ignore any stale custom name.
    out["sstp_cert_name"] = cert_name if mode == "custom" else ""

    out["sstp_cert_cn"] = _validate_cn(str(merged.get("sstp_cert_cn", "") or ""))
    return out


# ════════════════════════════════════════════════════════════════════════
# Write
# ════════════════════════════════════════════════════════════════════════


def set_conn_config(node, partial: dict[str, Any], *, commit: bool = False) -> dict[str, Any]:
    """Validate ``partial`` against the node's effective config, persist the
    merged result, and return it. Raises :class:`ConnConfigError` on a bad
    value (the route maps that to a 400 + Arabic message). ``commit=False``
    lets the caller batch the write."""
    base = get_conn_config(node)
    clean = _validate(partial or {}, base=base)
    node.conn_config_json = json.dumps(clean, ensure_ascii=False, sort_keys=True)
    db.session.add(node)
    if commit:
        db.session.commit()
    return clean


__all__ = ["DEFAULTS", "ConnConfigError", "get_conn_config", "set_conn_config"]
