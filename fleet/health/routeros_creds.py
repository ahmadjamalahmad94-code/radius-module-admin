"""fleet.health.routeros_creds — per-CHR RouterOS API password storage.

The live-metrics poller logs into each CHR's RouterOS REST API to read
CPU, active sessions and interface counters. The password for that read-
only user is a SECRET — it never lives on disk in clear:

* On the panel side it's stored in
  ``fleet_chr_nodes.routeros_api_password_enc`` as a Fernet ciphertext
  using the panel master key (``WHATSAPP_FERNET_KEY``), the same
  wrapper the customer vault + legacy CHR-console password use.
* On the CHR side it's installed by the unified RouterOS provisioning
  script (``chr_unified.rsc.j2``) for a dedicated read-group user that
  is only reachable over ``wg-mgmt`` — never on the WAN interface.

This module is the seam:

* :func:`encrypt_password` / :func:`decrypt_password` — mirror the
  customer-vault crypto wrapper; never log plaintext.
* :func:`set_credentials` / :func:`clear_credentials` — UI / onboarding
  callers store the user + password on a node row in one call. The
  ``Setting`` row that backs the fleet-constant default password is
  read by the onboarding service when no per-CHR override exists.
* :func:`credentials_for` — returns ``(user, password, port)`` for the
  poller; returns ``None`` if the node has no usable creds yet (so the
  poller can skip it without crashing).
* :func:`mask_password` — for the operator UI (never the plaintext).

The default CHR-side API username + password are fleet-constants the
owner sets once in **إعدادات بنية الأسطول** (the panel's fleet-infra
settings page). The onboarding script renders them as bindings and the
panel stores the password encrypted on every freshly-onboarded node so
the poller has working credentials as soon as the script lands.
"""
from __future__ import annotations

import logging
from typing import Optional

from app.extensions import db
from app.models import Setting
from app.services.whatsapp.crypto import (
    WhatsAppCryptoError,
    decrypt_secret as _master_decrypt,
    encrypt_secret as _master_encrypt,
    mask_secret as _master_mask,
)

from fleet.registry.models_chr import FleetChrNode


logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════════
# Fleet-constant defaults (the unified script reads these too)
# ════════════════════════════════════════════════════════════════════════

#: Setting key for the fleet-default API username (script binding).
DEFAULT_USER_SETTING_KEY = "fleet.routeros.api_user"
#: Setting key for the fleet-default API password ciphertext (script
#: binding). The plaintext is rendered into the script as the password
#: argument of ``/user add``; we keep it encrypted at rest on the panel.
DEFAULT_PASSWORD_SETTING_KEY = "fleet.routeros.api_password_enc"

#: Hard-default username when the operator has not set one yet. The
#: unified script provisions exactly this name as a read-group user.
HARD_DEFAULT_USER = "hobe-panel"


# ════════════════════════════════════════════════════════════════════════
# Crypto helpers
# ════════════════════════════════════════════════════════════════════════


def encrypt_password(plaintext: str) -> str:
    """Encrypt ``plaintext`` → Fernet token string.

    Empty input returns empty (so the caller can write ``""`` to clear
    a row without a special case). Raises :class:`WhatsAppCryptoError`
    via the master wrapper if the panel key isn't configured — the
    onboarding service catches that and surfaces an Arabic error to
    the operator.
    """
    if not plaintext:
        return ""
    return _master_encrypt(plaintext)


def decrypt_password(ciphertext: str) -> str:
    """Decrypt a Fernet token → plaintext. Empty/invalid → empty string.

    Failures collapse to ``""`` so the poller can degrade to "skip this
    node" rather than crashing. The plaintext NEVER lands in a log
    line — :func:`mask_password` is the safe display path.
    """
    if not ciphertext:
        return ""
    try:
        return _master_decrypt(ciphertext)
    except WhatsAppCryptoError:
        return ""
    except Exception:  # noqa: BLE001 — defensive
        return ""


def mask_password(value: str) -> str:
    """A non-reversible preview suitable for the operator UI."""
    return _master_mask(value or "")


# ════════════════════════════════════════════════════════════════════════
# Per-node credential lifecycle
# ════════════════════════════════════════════════════════════════════════


def set_credentials(
    node: FleetChrNode, *, username: str | None, password: str | None,
) -> None:
    """Write the API user + password (encrypted) onto a node row.

    ``username=None`` keeps the existing value; same for ``password``.
    The caller commits — this only stages.
    """
    if username is not None:
        node.routeros_api_user = (username or "").strip()
    if password is not None:
        node.routeros_api_password_enc = encrypt_password(password)
    db.session.add(node)


def clear_credentials(node: FleetChrNode) -> None:
    """Wipe the API user + password. Used when a CHR is decommissioned."""
    node.routeros_api_user = ""
    node.routeros_api_password_enc = ""
    db.session.add(node)


def credentials_for(node: FleetChrNode) -> Optional[dict]:
    """Return the live polling creds for a node, or ``None`` if unusable.

    Resolution path (per-node override beats fleet default):

    1. Per-node user + password from ``fleet_chr_nodes``.
    2. Fleet defaults from the Setting layer (user + encrypted pwd).
    3. Hard default user (``hobe-panel``) — but a missing password
       still returns ``None`` so the poller skips the node rather
       than logging in with a blank.

    Returns ``{"user": str, "password": str, "port": int, "host": str}``
    or ``None``. The host comes from the node's ``wg_mgmt_ip`` because
    api-ssl is bound to the management interface (the unified script
    enforces that — never the WAN).
    """
    if node is None or not node.wg_mgmt_ip:
        return None
    user, password = _resolve_user_and_password(node)
    if not password:
        # No password we can use — skip cleanly.
        return None
    port = int(node.routeros_api_port or 8443)
    return {
        "user": user or HARD_DEFAULT_USER,
        "password": password,
        "host": node.wg_mgmt_ip,
        "port": port,
    }


def _resolve_user_and_password(node: FleetChrNode) -> tuple[str, str]:
    # Per-node override
    user = (node.routeros_api_user or "").strip()
    password = decrypt_password(node.routeros_api_password_enc or "")
    if password:
        return user or HARD_DEFAULT_USER, password
    # Fleet defaults
    fleet_user = (_setting_value(DEFAULT_USER_SETTING_KEY) or "").strip()
    fleet_pwd = decrypt_password(_setting_value(DEFAULT_PASSWORD_SETTING_KEY) or "")
    if fleet_pwd:
        return fleet_user or HARD_DEFAULT_USER, fleet_pwd
    return user or fleet_user or HARD_DEFAULT_USER, ""


def _setting_value(key: str) -> str:
    try:
        row = db.session.get(Setting, key)
        return (row.value or "") if row else ""
    except Exception:  # noqa: BLE001
        return ""


# ════════════════════════════════════════════════════════════════════════
# Fleet-constant default password — UI / onboarding writes here
# ════════════════════════════════════════════════════════════════════════


def set_default_password(plaintext: str) -> None:
    """Stage the fleet-default API password (encrypted) into Settings.

    Used by the «إعدادات بنية الأسطول» UI + by the onboarding
    service the first time it provisions a node. Caller commits.
    """
    ciphertext = encrypt_password(plaintext)
    row = db.session.get(Setting, DEFAULT_PASSWORD_SETTING_KEY)
    if row is None:
        row = Setting(key=DEFAULT_PASSWORD_SETTING_KEY, value=ciphertext)
    else:
        row.value = ciphertext
    db.session.add(row)


def set_default_user(username: str) -> None:
    """Stage the fleet-default API username into Settings."""
    cleaned = (username or "").strip() or HARD_DEFAULT_USER
    row = db.session.get(Setting, DEFAULT_USER_SETTING_KEY)
    if row is None:
        row = Setting(key=DEFAULT_USER_SETTING_KEY, value=cleaned)
    else:
        row.value = cleaned
    db.session.add(row)


def get_default_user() -> str:
    """Read the fleet-default API username (or the hard default)."""
    return (_setting_value(DEFAULT_USER_SETTING_KEY) or HARD_DEFAULT_USER).strip()


def get_default_password_plaintext() -> str:
    """Decrypt the fleet-default API password for binding into the
    onboarding script. Empty when the operator hasn't set it yet —
    the script render then skips the API-user block (the binding
    is documented as optional)."""
    return decrypt_password(_setting_value(DEFAULT_PASSWORD_SETTING_KEY) or "")


# ════════════════════════════════════════════════════════════════════════
# UI-safe summaries (the operator UI consumes these — NEVER plaintext)
# ════════════════════════════════════════════════════════════════════════


def fleet_default_view() -> dict:
    """Snapshot the infra-settings page renders.

    Never returns the plaintext password. ``masked`` is computed off the
    CIPHERTEXT so we don't even need to decrypt to draw the chip.
    """
    user = get_default_user()
    pwd_cipher = _setting_value(DEFAULT_PASSWORD_SETTING_KEY) or ""
    return {
        "user": user,
        "is_set": bool(pwd_cipher),
        "masked": mask_password(pwd_cipher) if pwd_cipher else "—",
        # The owner needs to know which keys to fill — surface them
        # so the template can show «Setting key:» without hardcoding.
        "user_setting_key": DEFAULT_USER_SETTING_KEY,
        "password_setting_key": DEFAULT_PASSWORD_SETTING_KEY,
    }


def node_creds_view(node: FleetChrNode) -> dict:
    """Snapshot for the per-node row on the dashboard.

    ``has_override`` is True iff the node row holds a per-node user or
    password (i.e. it does NOT fall back to the fleet default). The
    plaintext password is NEVER returned.
    """
    has_user = bool((node.routeros_api_user or "").strip())
    has_pwd = bool((node.routeros_api_password_enc or "").strip())
    return {
        "has_override": has_user or has_pwd,
        "user": (node.routeros_api_user or "").strip(),
        "password_masked": (
            mask_password(node.routeros_api_password_enc) if has_pwd else "—"
        ),
        "port": int(node.routeros_api_port or 8443),
        "host": node.wg_mgmt_ip,
        # Convenience: tells the UI whether the poller has anything to use.
        "effective_ready": credentials_for(node) is not None,
    }


__all__ = [
    "DEFAULT_USER_SETTING_KEY",
    "DEFAULT_PASSWORD_SETTING_KEY",
    "HARD_DEFAULT_USER",
    "encrypt_password",
    "decrypt_password",
    "mask_password",
    "set_credentials",
    "clear_credentials",
    "credentials_for",
    "set_default_user",
    "set_default_password",
    "get_default_user",
    "get_default_password_plaintext",
]
