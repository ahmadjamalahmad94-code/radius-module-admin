"""fleet.registry.infra_settings — UI-managed fleet-infrastructure settings.

The «إعدادات بنية الأسطول» page (feat/fleet-infrastructure-settings) writes
the seven keys the unified RouterOS template needs as fleet-constants:

    PANEL_WG_PUBKEY       — panel's wg-mgmt public key (the panel keeps the
                             private side encrypted in this module)
    PANEL_WG_ENDPOINT     — panel's public Host:Port for wg-mgmt
    PROXY_WG_PUBKEY       — central RADIUS proxy's wg-data public key
    PROXY_WG_ENDPOINT     — proxy's public Host:Port for wg-data
    CHR_SHARED_SECRET     — RFC-2865 RADIUS secret (CHR ↔ proxy); MUST match
                             the proxy's PROXY_CHR_SECRET
    SSTP_CERT_NAME        — /certificate row on each CHR (empty → SSTP off)
    IKE_CERT_NAME         — /certificate row on each CHR (empty → IPsec off)

All values land in the existing ``Setting`` key/value table under namespaced
keys ``fleet.infra.<TEMPLATE_VAR>`` so they never collide with legacy
settings. Secret-bearing values (the panel's private WG key + the RADIUS
shared secret) are Fernet-encrypted at rest with the WHATSAPP_FERNET_KEY
master, matching the rest of the panel's secrets (vault, WhatsApp Cloud,
Fleet DNS token).

The renderer reads these through ``OnboardingService._const``, which calls
:func:`get_fleet_const` below; so once a Setting row is written, no other
code changes — the validator's «بانتظار» clears for that key on the next
render.

Security
--------
* The panel WireGuard PRIVATE key is encrypted at rest. It NEVER appears
  in any response from this module's public functions, never in templates,
  never in logs. Only :func:`get_panel_wg_private_key_decrypted` reveals
  it — that helper is intentionally NOT exported and is reserved for a
  future bring-up-the-wg-mgmt-interface daemon, not the UI.
* The RADIUS shared secret is encrypted at rest. :func:`get_fleet_const`
  returns the plaintext (the renderer needs to emit it into the .rsc, so
  there's no avoiding plaintext at render time) but the read path is
  audited and gated.
* All mutators emit an audit log row with the change context but NEVER
  with the secret value.
"""
from __future__ import annotations

import re
import secrets
import string
from dataclasses import dataclass
from typing import Any

from app.extensions import db
from app.models import Setting
from app.services.whatsapp.crypto import (
    WhatsAppCryptoError,
    decrypt_secret,
    encrypt_secret,
    mask_secret,
)


# ════════════════════════════════════════════════════════════════════════
# Storage layout
# ════════════════════════════════════════════════════════════════════════

#: Key prefix in the Setting table (separates these rows from legacy ones).
_PREFIX = "fleet.infra."

#: Template-var names that map 1:1 onto Setting keys. Keep IDENTICAL to the
#: names the unified RouterOS template substitutes, so the renderer's
#: resolver picks them up unchanged.
_INFRA_KEYS = (
    "PANEL_WG_PUBKEY",
    "PANEL_WG_ENDPOINT",
    "PROXY_WG_PUBKEY",
    "PROXY_WG_ENDPOINT",
    "CHR_SHARED_SECRET",
    "SSTP_CERT_NAME",
    "IKE_CERT_NAME",
    # CUSTOMER_RADIUS_TUNNEL_DESIGN §2 — the wg-radius plane (customer ↔ proxy).
    # Three slots the owner pastes once at proxy deploy and the panel then
    # serves to every customer over the bridge heartbeat.
    "PROXY_RADIUS_WG_PUBKEY",
    "PROXY_RADIUS_WG_ENDPOINT",
    "PROXY_RADIUS_WG_TUNNEL_IP",
    # Stable panel-side wg-radius pubkey (mirror of PANEL_WG_PUBKEY for the
    # radius plane). The private side lives in an out-of-band slot —
    # _PANEL_RADIUS_PRIVKEY_SLOT below — so the wg-radius daemon can pick
    # it up without rotation. Reusing PANEL_WG_PUBKEY would have conflated
    # the wg-mgmt and wg-radius keys.
    "PANEL_RADIUS_WG_PUBKEY",
)

#: Subset whose stored value is a Fernet ciphertext that must be decrypted
#: on read. Plain strings for everything else.
_SECRET_KEYS = frozenset({"CHR_SHARED_SECRET"})

#: Out-of-band slot for the panel's WireGuard PRIVATE key. NOT in
#: ``_INFRA_KEYS`` because the template never reads it directly — only the
#: PUBLIC key goes into the script. We store the private key here so a
#: future "bring up wg-mgmt" daemon can consume it without rotating.
_PANEL_PRIVKEY_SLOT = _PREFIX + "PANEL_WG_PRIVKEY"

#: Out-of-band slot for the panel's wg-radius PRIVATE key — same pattern
#: as ``_PANEL_PRIVKEY_SLOT`` but for the wg-radius plane (customer ↔
#: proxy). Kept separate so a rotation on one plane never disturbs the
#: other.
_PANEL_RADIUS_PRIVKEY_SLOT = _PREFIX + "PANEL_RADIUS_WG_PRIVKEY"

#: Subset of UI-managed keys that the validator considers REQUIRED
#: (mirrors ``fleet.registry.script_bindings_check`` order). The two cert
#: names are intentionally NOT here — leaving them empty is valid (skips
#: SSTP + IPsec cleanly via the cert-conditional template).
REQUIRED_KEYS = (
    "PANEL_WG_PUBKEY",
    "PANEL_WG_ENDPOINT",
    "PROXY_WG_PUBKEY",
    "PROXY_WG_ENDPOINT",
    "CHR_SHARED_SECRET",
)


# ════════════════════════════════════════════════════════════════════════
# View shapes the UI consumes
# ════════════════════════════════════════════════════════════════════════


@dataclass
class FleetConstStatus:
    """One row in the status panel + the per-section state for the page."""

    key: str
    label_ar: str
    is_set: bool
    is_secret: bool
    masked: str  # safe to render; "—" when unset
    detail: str = ""   # optional extra hint for the UI


_LABELS_AR = {
    "PANEL_WG_PUBKEY":   "مفتاح اللوحة العام (WireGuard control-plane)",
    "PANEL_WG_ENDPOINT": "نقطة وصول اللوحة (Host:Port)",
    "PROXY_WG_PUBKEY":   "مفتاح وكيل RADIUS العام (data-plane)",
    "PROXY_WG_ENDPOINT": "نقطة وصول الوكيل (Host:Port)",
    "CHR_SHARED_SECRET": "السر المشترك لـ RADIUS (CHR ↔ Proxy)",
    "SSTP_CERT_NAME":    "اسم شهادة SSTP على CHR",
    "IKE_CERT_NAME":     "اسم شهادة IKEv2 على CHR",
}


# ════════════════════════════════════════════════════════════════════════
# Low-level Setting access
# ════════════════════════════════════════════════════════════════════════


def _setting_key(template_var: str) -> str:
    return _PREFIX + template_var


def _raw_get(template_var: str) -> str:
    """Read the raw stored string (ciphertext if secret) or "" if not set."""
    row = db.session.get(Setting, _setting_key(template_var))
    return (row.value or "") if row else ""


def _raw_set(template_var: str, value: str) -> None:
    """Persist the raw string (caller is responsible for encryption)."""
    key = _setting_key(template_var)
    row = db.session.get(Setting, key)
    if row is None:
        row = Setting(key=key, value=value or "")
        db.session.add(row)
    else:
        row.value = value or ""


# ════════════════════════════════════════════════════════════════════════
# Public read API — consumed by ``OnboardingService._const``
# ════════════════════════════════════════════════════════════════════════


def get_fleet_const(template_var: str) -> str | None:
    """Resolve one fleet-constant.

    Returns:
        * The plaintext value (decrypting if it's a secret-key).
        * ``None`` when no Setting row exists OR the row is empty.
          (Empty/None signals the resolver in
          ``OnboardingService._const`` to fall through to the next layer.)

    Never raises on a missing master key — encryption errors degrade to
    ``None`` so a misconfigured panel falls back to env/defaults rather
    than crashing the render.
    """
    if template_var not in _INFRA_KEYS:
        return None
    raw = _raw_get(template_var)
    if not raw:
        return None
    if template_var in _SECRET_KEYS:
        try:
            return decrypt_secret(raw)
        except WhatsAppCryptoError:
            return None
    return raw


# ════════════════════════════════════════════════════════════════════════
# UI-facing view + setters
# ════════════════════════════════════════════════════════════════════════


def _is_set(template_var: str) -> bool:
    raw = _raw_get(template_var)
    return bool(raw)


def status_for(template_var: str) -> FleetConstStatus:
    """Build the masked/ready view for one key."""
    is_secret = template_var in _SECRET_KEYS or template_var == "PANEL_WG_PUBKEY"
    raw = _raw_get(template_var)
    is_set = bool(raw)
    if not is_set:
        masked = "—"
    elif template_var in _SECRET_KEYS:
        # raw is ciphertext; mask the CIPHERTEXT directly so we never
        # decrypt unnecessarily in the UI path.
        masked = mask_secret(raw)
    elif template_var == "PANEL_WG_PUBKEY":
        # Pubkey is NOT a secret but its 44-char base64 is awkward in UI;
        # show the head + tail so the operator can verify identity.
        masked = mask_secret(raw)
    else:
        masked = raw
    return FleetConstStatus(
        key=template_var,
        label_ar=_LABELS_AR.get(template_var, template_var),
        is_set=is_set,
        is_secret=template_var in _SECRET_KEYS,
        masked=masked,
    )


def view_all() -> list[FleetConstStatus]:
    """Status panel feed — REQUIRED keys first (in their setup order), then
    the optional cert names. Mirrors the renderer's validator order."""
    ordered = list(REQUIRED_KEYS) + [k for k in _INFRA_KEYS if k not in REQUIRED_KEYS]
    return [status_for(k) for k in ordered]


def is_fleet_ready() -> bool:
    """True when every REQUIRED key has a non-empty stored value. Cert
    names are intentionally NOT required (the template skips their blocks
    cleanly when they're empty)."""
    return all(_is_set(k) for k in REQUIRED_KEYS)


def missing_required() -> list[str]:
    """Names of the REQUIRED keys that are still empty."""
    return [k for k in REQUIRED_KEYS if not _is_set(k)]


# ════════════════════════════════════════════════════════════════════════
# Mutators (each commits + returns the post-state for the UI)
# ════════════════════════════════════════════════════════════════════════


class InfraSettingsError(ValueError):
    """Validation / encryption error surfaced to the UI with an Arabic message."""


#: Default ports per plane. Used when the operator types just a host without
#: a ``:port`` suffix. These match what the unified RouterOS template's
#: ``listen-port`` lines bind on the CHR side, so the two ends agree.
_DEFAULT_PORTS = {
    "PANEL_WG_ENDPOINT": 51820,
    "PROXY_WG_ENDPOINT": 51821,
}

#: Host-only regex (no ``:port`` — the port lives in a separate group).
#: IPv6 must be wrapped in ``[...]`` so we can split on the last ``:`` safely.
_HOST_RE = re.compile(
    r"^(?:"
    r"  (?:\[[0-9a-fA-F:.]+\])"                                   # [IPv6]
    r"  | (?:\d{1,3}(?:\.\d{1,3}){3})"                            # IPv4
    r"  | (?:[A-Za-z0-9](?:[A-Za-z0-9.\-]{0,253}[A-Za-z0-9])?)"  # FQDN
    r")$",
    re.VERBOSE,
)


def split_endpoint(value: str, *, default_port: int) -> tuple[str, int]:
    """Parse an endpoint into ``(host, port)``.

    Accepts ``host``, ``host:port``, or ``[ipv6]:port``. Anything else (extra
    colons, empty parts, port out of 1..65535) raises ``InfraSettingsError``.
    The single canonical parser used by both the UI validator and the
    renderer, so the two paths can never disagree on what an endpoint means.
    """
    raw = (value or "").strip()
    if not raw:
        raise InfraSettingsError("نقطة الوصول مطلوبة.")

    # IPv6 literal must be bracketed; rsplit at the last ']' / ':' boundary.
    if raw.startswith("["):
        if "]" not in raw:
            raise InfraSettingsError(
                "صيغة عنوان IPv6 يجب أن تكون داخل أقواس مربعة، مثل "
                "`[2001:db8::1]:51820`."
            )
        close = raw.index("]")
        host = raw[: close + 1]
        rest = raw[close + 1 :]
        if rest == "":
            port_str = ""
        elif rest.startswith(":"):
            port_str = rest[1:]
        else:
            raise InfraSettingsError(
                "صيغة عنوان IPv6 يجب أن تتبع الأقواس بـ `:port` أو لا شيء."
            )
    else:
        if raw.count(":") > 1:
            raise InfraSettingsError(
                "صيغة نقطة الوصول غير صحيحة — استخدم `host` أو `host:port` "
                "فقط (للـ IPv6 ضع العنوان داخل أقواس مربعة)."
            )
        if ":" in raw:
            host, _, port_str = raw.partition(":")
        else:
            host, port_str = raw, ""

    if not _HOST_RE.match(host):
        raise InfraSettingsError(
            "اسم المضيف غير صالح — استخدم اسم نطاق أو عنوان IP."
        )

    if port_str == "":
        port = default_port
    else:
        if not port_str.isdigit():
            raise InfraSettingsError("المنفذ يجب أن يكون رقماً.")
        port = int(port_str)
        if not (1 <= port <= 65535):
            raise InfraSettingsError("المنفذ يجب أن يكون بين 1 و 65535.")
    return host, port


def _validate_host_port(value: str, field_label: str, *, template_var: str | None = None) -> str:
    """Normalize an endpoint to canonical ``host:port`` for storage.

    The stored Setting row keeps the combined form (so the operator sees what
    they typed, with any defaulted port made explicit). The renderer splits
    again at render time via :func:`split_endpoint` — single source of truth.
    """
    default_port = _DEFAULT_PORTS.get(template_var or "", 51820)
    raw = (value or "").strip()
    if not raw:
        raise InfraSettingsError(f"{field_label} مطلوب.")
    try:
        host, port = split_endpoint(raw, default_port=default_port)
    except InfraSettingsError as exc:
        # Re-label with the field's Arabic name for a clearer UI error.
        raise InfraSettingsError(f"{field_label}: {exc}") from None
    return f"{host}:{port}"


def _validate_pubkey(value: str, field_label: str) -> str:
    value = (value or "").strip()
    if not value:
        raise InfraSettingsError(f"{field_label} مطلوب.")
    # WireGuard pubkey: 43 base64 chars + '=' padding → 44 total.
    if len(value) != 44 or not re.match(r"^[A-Za-z0-9+/]{43}=$", value):
        raise InfraSettingsError(
            f"{field_label} يجب أن يكون مفتاح WireGuard صالحاً (44 حرفاً "
            "base64 ينتهي بـ '=')."
        )
    return value


def _validate_cert_name(value: str, field_label: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""  # empty is OK — skips the cert-bound section
    if not re.match(r"^[A-Za-z0-9._\- ]{1,80}$", value):
        raise InfraSettingsError(
            f"{field_label} يجب أن يحتوي على أحرف لاتينية وأرقام والشرطات "
            "والنقاط فقط."
        )
    return value


def _require_crypto() -> None:
    """Probe that ``WHATSAPP_FERNET_KEY`` is set before writing a secret."""
    try:
        encrypt_secret("probe")  # discarded
    except WhatsAppCryptoError as exc:
        raise InfraSettingsError(
            "مفتاح التشفير على الخادم غير مضبوط (WHATSAPP_FERNET_KEY). "
            "لا يمكن حفظ السرّ المشفّر."
        ) from exc


# ── individual setters ─────────────────────────────────────────────────


def set_panel_endpoint(value: str) -> None:
    clean = _validate_host_port(value, "نقطة وصول اللوحة",
                                template_var="PANEL_WG_ENDPOINT")
    _raw_set("PANEL_WG_ENDPOINT", clean)
    db.session.commit()


def set_proxy_pubkey(value: str) -> None:
    clean = _validate_pubkey(value, "مفتاح وكيل RADIUS العام")
    _raw_set("PROXY_WG_PUBKEY", clean)
    db.session.commit()


def set_proxy_endpoint(value: str) -> None:
    clean = _validate_host_port(value, "نقطة وصول الوكيل",
                                template_var="PROXY_WG_ENDPOINT")
    _raw_set("PROXY_WG_ENDPOINT", clean)
    db.session.commit()


def set_chr_shared_secret(plaintext: str) -> None:
    plaintext = (plaintext or "").strip()
    if not plaintext:
        raise InfraSettingsError("السر المشترك مطلوب.")
    if len(plaintext) < 16:
        raise InfraSettingsError(
            "السر المشترك يجب أن يكون 16 حرفاً على الأقل (يُنصح بـ 32 حرفاً "
            "أو أكثر)."
        )
    _require_crypto()
    ciphertext = encrypt_secret(plaintext)
    _raw_set("CHR_SHARED_SECRET", ciphertext)
    db.session.commit()


def generate_chr_shared_secret() -> str:
    """Generate a strong 48-char random secret, persist it, return the
    plaintext ONCE for an in-flight UI flash. Returns "" if crypto is
    unavailable; caller surfaces an Arabic error."""
    alphabet = string.ascii_letters + string.digits + "_-"
    plaintext = "".join(secrets.choice(alphabet) for _ in range(48))
    set_chr_shared_secret(plaintext)
    return plaintext


def set_cert_name(template_var: str, value: str) -> None:
    if template_var not in {"SSTP_CERT_NAME", "IKE_CERT_NAME"}:
        raise InfraSettingsError("مفتاح غير معروف.")
    clean = _validate_cert_name(value, _LABELS_AR.get(template_var, template_var))
    _raw_set(template_var, clean)
    db.session.commit()


# ── panel WireGuard keypair (the only key the panel KEEPS) ─────────────


def generate_panel_wg_keypair() -> dict[str, str]:
    """Mint a new wg-mgmt keypair on the panel, encrypt + store the
    private side, store the public side verbatim. Returns
    ``{"public_key": "...", "regenerated": bool}`` for the UI to flash.

    Caller is responsible for warning the operator when ``regenerated`` is
    True (any previously-distributed CHR script becomes invalid against the
    new public key).
    """
    from fleet.registry.wg_keys import generate_keypair
    _require_crypto()

    had_previous = bool(_raw_get("PANEL_WG_PUBKEY"))
    kp = generate_keypair()
    # Encrypt the PRIVATE key; store under the out-of-band slot.
    ciphertext = encrypt_secret(kp.private_key)
    priv_row = db.session.get(Setting, _PANEL_PRIVKEY_SLOT)
    if priv_row is None:
        priv_row = Setting(key=_PANEL_PRIVKEY_SLOT, value=ciphertext)
        db.session.add(priv_row)
    else:
        priv_row.value = ciphertext
    # Public side goes verbatim into the template-var slot.
    _raw_set("PANEL_WG_PUBKEY", kp.public_key)
    db.session.commit()
    return {"public_key": kp.public_key, "regenerated": had_previous}


def set_panel_pubkey(value: str) -> dict[str, bool]:
    """Manually set ``PANEL_WG_PUBKEY`` to a pubkey the operator pasted from
    the panel host (where they ran ``wg genkey | tee /etc/wireguard/wg-mgmt.key
    | wg pubkey``). The private side stays on the host — we never see it.

    If a panel-minted private key was previously stored under the out-of-band
    slot (i.e. the operator had clicked «توليد مفتاح اللوحة» on a prior visit),
    we delete that ciphertext row so the on-host private key is now the only
    authoritative copy — no orphaned private-key ciphertext drifts in the DB.

    Returns ``{"replaced": bool, "cleared_server_privkey": bool}`` for the
    UI to flash an honest message.
    """
    clean = _validate_pubkey(value, "مفتاح اللوحة العام")
    had_previous = bool(_raw_get("PANEL_WG_PUBKEY"))
    cleared_priv = False
    priv_row = db.session.get(Setting, _PANEL_PRIVKEY_SLOT)
    if priv_row is not None:
        db.session.delete(priv_row)
        cleared_priv = True
    _raw_set("PANEL_WG_PUBKEY", clean)
    db.session.commit()
    return {"replaced": had_previous, "cleared_server_privkey": cleared_priv}


def panel_privkey_is_on_server() -> bool:
    """True iff a server-minted PANEL_WG_PRIVKEY ciphertext row exists.

    Drives the «تنزيل المفتاح الخاص» UI affordance: only shown after a
    server-side ``generate_panel_wg_keypair()``, hidden after a manual paste
    (which wipes the private side)."""
    return db.session.get(Setting, _PANEL_PRIVKEY_SLOT) is not None


def panel_pubkey_is_set() -> bool:
    return bool(_raw_get("PANEL_WG_PUBKEY"))


def panel_pubkey_for_display() -> str:
    """Plaintext pubkey for the read-only UI field (NOT a secret)."""
    return _raw_get("PANEL_WG_PUBKEY") or ""


def get_panel_wg_private_key_decrypted() -> str:
    """Decrypted private key — for the future wg-mgmt daemon, NOT the UI.

    Kept in this module to centralise the decrypt-once boundary. Raises
    ``InfraSettingsError`` if no key has been generated yet.
    """
    raw = ""
    row = db.session.get(Setting, _PANEL_PRIVKEY_SLOT)
    if row:
        raw = row.value or ""
    if not raw:
        raise InfraSettingsError("لم يُولَّد مفتاح اللوحة الخاص بعد.")
    return decrypt_secret(raw)


# ── wg-radius plane (customer ↔ proxy) — design §2 + §6.3 ─────────────


def get_chr_shared_secret_plaintext() -> str:
    """Return the decrypted CHR↔proxy RADIUS secret, or ``""`` when unset.

    This is the SAME plaintext that the unified RouterOS template bakes
    into every CHR script. The routing-table publisher (design §6.1)
    embeds it in the authenticated response so the proxy reads the
    current value per-packet instead of trusting a hand-edited env, and
    the two sides can never drift again. NEVER log the return value —
    callers stage it directly into the response payload.
    """
    raw = _raw_get("CHR_SHARED_SECRET")
    if not raw:
        return ""
    try:
        return decrypt_secret(raw)
    except Exception:  # noqa: BLE001 — degrade to "" on a missing master key
        return ""


def get_proxy_radius_tunnel() -> dict[str, str]:
    """Return the three operator-pasted PROXY_RADIUS_WG_* values.

    Shape::

        {"public_key": str, "endpoint": str, "tunnel_ip": str}

    Empty strings when the owner has not configured the proxy side yet —
    callers (heartbeat-response builder, radius-peers publisher) treat
    empty values as "tunnel disabled at the panel" and surface a clear
    state to the customer instead of returning a half-baked config.
    """
    return {
        "public_key": _raw_get("PROXY_RADIUS_WG_PUBKEY"),
        "endpoint":   _raw_get("PROXY_RADIUS_WG_ENDPOINT"),
        "tunnel_ip":  _raw_get("PROXY_RADIUS_WG_TUNNEL_IP"),
    }


def set_proxy_radius_pubkey(value: str) -> None:
    clean = _validate_pubkey(value, "مفتاح وكيل الراديوس (wg-radius)")
    _raw_set("PROXY_RADIUS_WG_PUBKEY", clean)
    db.session.commit()


def set_proxy_radius_endpoint(value: str) -> None:
    clean = _validate_host_port(value, "نقطة وصول وكيل الراديوس (wg-radius)",
                                template_var="PROXY_RADIUS_WG_ENDPOINT")
    _raw_set("PROXY_RADIUS_WG_ENDPOINT", clean)
    db.session.commit()


def set_proxy_radius_tunnel_ip(value: str) -> None:
    raw = (value or "").strip()
    if not raw:
        _raw_set("PROXY_RADIUS_WG_TUNNEL_IP", "")
        db.session.commit()
        return
    # Accept either a bare IP or CIDR — strip mask if present.
    if "/" in raw:
        raw = raw.split("/", 1)[0]
    import ipaddress as _ip
    try:
        _ip.ip_address(raw)
    except ValueError as exc:
        raise InfraSettingsError("عنوان IP غير صالح لنقطة الوصول الداخلية.") from exc
    _raw_set("PROXY_RADIUS_WG_TUNNEL_IP", raw)
    db.session.commit()


def ensure_panel_radius_keypair() -> dict[str, str]:
    """Idempotent stable-key bringup for the panel's wg-radius side.

    Mints a wg keypair on the FIRST call (encrypted private side stored
    under ``_PANEL_RADIUS_PRIVKEY_SLOT``, public side under
    ``PANEL_RADIUS_WG_PUBKEY``) and is a no-op afterwards — the same
    "stable slot, never regenerate implicitly" invariant the wg-mgmt
    key follows. Returns ``{"public_key": <str>, "minted": <bool>}``
    so the caller knows whether to audit-log the bringup.

    Why a separate plane: PANEL_WG_PUBKEY is the wg-mgmt control plane;
    this is wg-radius (customer ↔ proxy). Reusing one key for both
    would couple their lifetimes (rotate one → break the other).
    """
    from fleet.registry.wg_keys import generate_keypair
    existing = _raw_get("PANEL_RADIUS_WG_PUBKEY")
    if existing:
        return {"public_key": existing, "minted": False}
    _require_crypto()
    kp = generate_keypair()
    ciphertext = encrypt_secret(kp.private_key)
    priv_row = db.session.get(Setting, _PANEL_RADIUS_PRIVKEY_SLOT)
    if priv_row is None:
        priv_row = Setting(key=_PANEL_RADIUS_PRIVKEY_SLOT, value=ciphertext)
        db.session.add(priv_row)
    else:
        priv_row.value = ciphertext
    _raw_set("PANEL_RADIUS_WG_PUBKEY", kp.public_key)
    db.session.commit()
    return {"public_key": kp.public_key, "minted": True}


def panel_radius_pubkey() -> str:
    """Read-only accessor for the panel's wg-radius public key.

    Returns ``""`` if no key has been minted yet — callers should bring
    one up via :func:`ensure_panel_radius_keypair` on the first publish
    pass so the response is never empty under normal operation.
    """
    return _raw_get("PANEL_RADIUS_WG_PUBKEY")


__all__ = [
    "FleetConstStatus",
    "InfraSettingsError",
    "REQUIRED_KEYS",
    "get_fleet_const",
    "view_all",
    "status_for",
    "is_fleet_ready",
    "missing_required",
    "set_panel_endpoint",
    "set_panel_pubkey",
    "set_proxy_pubkey",
    "set_proxy_endpoint",
    "split_endpoint",
    "set_chr_shared_secret",
    "generate_chr_shared_secret",
    "set_cert_name",
    "generate_panel_wg_keypair",
    "panel_pubkey_is_set",
    "panel_pubkey_for_display",
    "panel_privkey_is_on_server",
    "get_panel_wg_private_key_decrypted",
    # wg-radius plane (customer ↔ proxy)
    "get_chr_shared_secret_plaintext",
    "get_proxy_radius_tunnel",
    "set_proxy_radius_pubkey",
    "set_proxy_radius_endpoint",
    "set_proxy_radius_tunnel_ip",
    "ensure_panel_radius_keypair",
    "panel_radius_pubkey",
]
