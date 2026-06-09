"""fleet.dns.settings_store — encrypted store for the Cloudflare API token + mode.

Secrets handling rule (Phase 6 / task C):

* The Cloudflare API token is a hard secret. It is entered ONLY in the
  front-door settings form; this module is the single place that writes it
  to disk, ALWAYS as a Fernet ciphertext under
  ``fleet.dns.cloudflare.api_token``.
* The mask we show to the operator is computed on the **ciphertext** —
  ``mask_secret`` only inspects string slice positions; we never need the
  plaintext to draw the chip. That means the UI layer (route + template)
  never decrypts the token, never holds it in a local, never sees it.
* The plaintext is decrypted ONLY when the Cloudflare driver actually issues
  a request (a separate code path, not this module).

Reused encryption
-----------------
Same Fernet pipeline as the WhatsApp settings — see
``app/services/whatsapp/crypto.py``. The fleet does not introduce a second
key: this would force the operator to manage two rotation lifecycles for the
same threat surface (one panel secrets vault).

Non-secret identifiers
----------------------
Zone id, account id, and the FQDN ``vpn.hoberadius.com`` are documented
constants exposed via ``FRONTDOOR_FQDN`` / ``ZONE_ID`` / ``ACCOUNT_ID`` so
the route + template don't string-literal them in three places. They are
public knowledge (zone/account ids are not exploitable without the API
token); they live here only for code locality.
"""
from __future__ import annotations

from typing import TypedDict

from app.extensions import db
from app.models import Setting
from app.services.whatsapp.crypto import (
    WhatsAppCryptoError,
    encrypt_secret,
    mask_secret,
)


# ────────────────────────────────────────────────────────────────────────────
# Documented public identifiers — keep in one place.
# ────────────────────────────────────────────────────────────────────────────

#: Front-door host clients resolve when they connect to the fleet.
FRONTDOOR_FQDN = "vpn.hoberadius.com"

#: Cloudflare zone id for ``hoberadius.com`` (public, not a secret).
ZONE_ID = "8bc55c137bb3eeefef4348b0b51990c5"

#: Cloudflare account id (public, not a secret).
ACCOUNT_ID = "4db5e3f4c135474a8d26638ce5c9ede4"


# ────────────────────────────────────────────────────────────────────────────
# Setting keys (namespaced so the legacy ``settings`` table doesn't conflate
# fleet config with messaging / landing / etc).
# ────────────────────────────────────────────────────────────────────────────

_KEY_TOKEN = "fleet.dns.cloudflare.api_token"   # encrypted ciphertext only
_KEY_MODE = "fleet.dns.mode"                     # "free" | "paid"

#: Allowed mode values + Arabic labels (kept here so the template doesn't
#: hard-code English keys).
MODE_FREE = "free"
MODE_PAID = "paid"
MODE_VALUES = (MODE_FREE, MODE_PAID)
MODE_LABELS_AR = {
    MODE_FREE: "مجاني — سجلات A موزونة / استبعاد",
    MODE_PAID: "مدفوع — موازنة Cloudflare",
}


# ────────────────────────────────────────────────────────────────────────────
# Return shape for the UI loader
# ────────────────────────────────────────────────────────────────────────────


class FrontDoorView(TypedDict):
    """What the route hands to the template. No plaintext token ever lives here."""

    frontdoor_fqdn: str
    zone_id: str
    account_id: str
    mode: str                 # one of MODE_VALUES
    mode_label_ar: str        # human Arabic label
    token_present: bool
    token_masked: str          # safe to print; computed from ciphertext
    crypto_available: bool    # WHATSAPP_FERNET_KEY configured?


# ────────────────────────────────────────────────────────────────────────────
# Low-level k/v access (reused from messaging settings pattern)
# ────────────────────────────────────────────────────────────────────────────


def _get_raw(key: str) -> str:
    row = db.session.get(Setting, key)
    return (row.value or "") if row else ""


def _set_raw(key: str, value: str) -> None:
    row = db.session.get(Setting, key)
    if row is None:
        row = Setting(key=key)
    row.value = value
    db.session.add(row)


def _crypto_available() -> bool:
    """The WHATSAPP_FERNET_KEY config presence — without doing crypto."""
    from flask import current_app
    return bool((current_app.config.get("WHATSAPP_FERNET_KEY") or "").strip())


# ────────────────────────────────────────────────────────────────────────────
# Public API
# ────────────────────────────────────────────────────────────────────────────


def load_view() -> FrontDoorView:
    """Read everything the UI needs — never touches the plaintext token."""
    ciphertext = _get_raw(_KEY_TOKEN)
    mode = (_get_raw(_KEY_MODE) or MODE_FREE).lower()
    if mode not in MODE_VALUES:
        mode = MODE_FREE
    return FrontDoorView(
        frontdoor_fqdn=FRONTDOOR_FQDN,
        zone_id=ZONE_ID,
        account_id=ACCOUNT_ID,
        mode=mode,
        mode_label_ar=MODE_LABELS_AR[mode],
        token_present=bool(ciphertext),
        # mask_secret accepts the ciphertext directly (it only slices the
        # string). No plaintext is ever materialised by this codepath.
        token_masked=mask_secret(ciphertext),
        crypto_available=_crypto_available(),
    )


def token_is_set() -> bool:
    """Cheap probe used by the reconciler/preview routes — does NOT decrypt."""
    return bool(_get_raw(_KEY_TOKEN))


def save_token(plaintext: str) -> None:
    """Encrypt + persist. The plaintext is **never logged** here; the caller
    must drop the local reference as soon as this returns.

    Raises ``WhatsAppCryptoError`` if the fernet key isn't configured —
    callers should surface a clear Arabic message ("لم يُضبط مفتاح التشفير
    على الخادم") and NOT fall back to writing the plaintext.
    """
    plaintext = (plaintext or "").strip()
    if not plaintext:
        raise ValueError("empty token")
    if not _crypto_available():
        raise WhatsAppCryptoError("WHATSAPP_FERNET_KEY not configured")
    ciphertext = encrypt_secret(plaintext)
    # `plaintext` is dropped when this function returns — Python has no
    # secure-erase primitive; the strongest guarantee we can give the
    # operator is "only this function ever sees it".
    _set_raw(_KEY_TOKEN, ciphertext)
    db.session.commit()


def clear_token() -> None:
    """Used by the «تغيير» flow when the operator wants to wipe before re-pasting."""
    _set_raw(_KEY_TOKEN, "")
    db.session.commit()


def save_mode(mode: str) -> None:
    """Persist the front-door mode. ``mode`` must be in ``MODE_VALUES``."""
    mode = (mode or "").strip().lower()
    if mode not in MODE_VALUES:
        raise ValueError(f"invalid mode: {mode!r}")
    _set_raw(_KEY_MODE, mode)
    db.session.commit()


def get_token_for_driver() -> str:
    """Return the decrypted token — used **only** by the Cloudflare driver.

    Imported into the reconciler/driver code path, NEVER into the UI render
    path. Raises ``WhatsAppCryptoError`` if the key is missing or the
    ciphertext is tampered. Returns an empty string when no token is set so
    the driver can short-circuit to a "dry-run only" mode without an
    exception.
    """
    from app.services.whatsapp.crypto import decrypt_secret
    ciphertext = _get_raw(_KEY_TOKEN)
    if not ciphertext:
        return ""
    return decrypt_secret(ciphertext)


__all__ = [
    "FRONTDOOR_FQDN",
    "ZONE_ID",
    "ACCOUNT_ID",
    "MODE_FREE",
    "MODE_PAID",
    "MODE_VALUES",
    "MODE_LABELS_AR",
    "FrontDoorView",
    "load_view",
    "token_is_set",
    "save_token",
    "clear_token",
    "save_mode",
    "get_token_for_driver",
]
