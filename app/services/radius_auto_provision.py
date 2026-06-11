"""Auto-provision the RADIUS instance + proxy realm route on bridge link.

Owner intent (overnight build session 2026-06-11): "Registering the RADIUS
instance + route is ESSENTIAL for the link — make it AUTOMATIC."

When a customer's radius-module successfully links to the panel using the
license key, the panel's heartbeat endpoint calls
:func:`provision_on_link` with whatever the radius-module reported about
its own RADIUS server. The function then:

1. Creates / updates the ``CustomerRadiusInstance`` row keyed by
   ``customer_id``. Realm + auth IP + ports + secret-vault-ref are
   refreshed from the bridge payload; missing/blank fields preserve
   whatever's already stored.
2. Generates a shared secret IF the bridge didn't supply one AND the
   instance row doesn't already have a Setting-backed secret. The new
   secret is stored in ``Setting[settings_key]`` (Fernet-encrypted via
   the customer-vault wrapper) and a stable ``vault://<key>`` reference
   is written to ``CustomerRadiusInstance.secret_vault_ref``.
3. Creates / updates the ``ProxyRealmRoute`` (realm → instance) with
   status=active and the allow-list set to EVERY enabled fleet CHR node
   (so RADIUS traffic from any node is accepted out of the box).

The function is fully IDEMPOTENT — re-linking refreshes mutable fields
but never duplicates rows. The returned dict carries the same shape on
every call so the heartbeat handler can echo it to the radius-module
(``status``, ``instance_id``, ``realm``, ``radius_target``, ``route_id``,
``shared_secret`` — only when a NEW one was just minted).
"""
from __future__ import annotations

import logging
import secrets
import string
from typing import Any, Iterable

from flask import Flask

from ..extensions import db
from ..models import (
    Customer,
    CustomerRadiusInstance,
    License,
    ProxyRealmRoute,
    Setting,
    utcnow,
)


_log = logging.getLogger(__name__)


_DEFAULT_AUTH_PORT = 1812
_DEFAULT_ACCT_PORT = 1813
_SHARED_SECRET_LEN = 32
_VAULT_REF_PREFIX = "vault://"


def _alnum_secret(length: int = _SHARED_SECRET_LEN) -> str:
    """RADIUS shared secret: URL-safe-ish charset, high entropy."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _setting_key_for(customer_id: int) -> str:
    """Where the RADIUS shared secret lives in ``Setting``."""
    return f"radius_secret.customer.{int(customer_id)}"


def _write_secret_setting(key: str, plaintext: str) -> None:
    """Persist a generated shared secret into the Setting table.

    Encryption: we reuse the customer-vault Fernet wrapper when
    available — same key the rest of the panel uses for at-rest secrets.
    On a fresh dev box without a vault key configured, we fall back to
    PLAINTEXT in Setting (visible in audit, but never logged) so the
    bridge link doesn't break in test environments.
    """
    value = plaintext
    try:
        from .customer_vault_crypto import encrypt_secret, encryption_available
        if encryption_available():
            value = encrypt_secret(plaintext)
    except Exception:  # noqa: BLE001 — fall back to plaintext storage in dev
        pass
    row = db.session.get(Setting, key)
    if row is None:
        row = Setting(key=key, value=value)
        db.session.add(row)
    else:
        row.value = value


def _read_secret_setting(key: str) -> str:
    row = db.session.get(Setting, key)
    if row is None or not row.value:
        return ""
    raw = str(row.value)
    try:
        from .customer_vault_crypto import decrypt_secret, encryption_available
        if encryption_available():
            try:
                return decrypt_secret(raw)
            except Exception:  # noqa: BLE001
                # Wasn't a Fernet token after all → return verbatim (plaintext
                # fallback path used in dev).
                return raw
    except Exception:  # noqa: BLE001
        pass
    return raw


def _fleet_node_ids_for_allowlist() -> list[int]:
    """All enabled, non-draining fleet CHR node ids — the «every CHR
    accepted» allowlist seed.

    Returns ``[]`` (which the routing-table reader treats as «empty allow
    list» — i.e. accept any node) if the fleet package isn't available.
    """
    try:
        from fleet.registry.models_chr import FleetChrNode  # noqa: WPS433
        rows = (
            FleetChrNode.query
            .filter(FleetChrNode.enabled.is_(True))
            .filter(FleetChrNode.drain.is_(False))
            .filter(FleetChrNode.status != "disabled")
            .all()
        )
        return sorted(int(n.id) for n in rows)
    except Exception:  # noqa: BLE001 — branch w/o fleet
        return []


def _derive_realm(customer: Customer, suggested: str = "") -> str:
    """Pick a realm: explicit > existing > slug-of-company > c<id>."""
    cleaned = str(suggested or "").strip().lower()
    if cleaned:
        return cleaned[:80]
    inst = (
        CustomerRadiusInstance.query
        .filter_by(customer_id=customer.id)
        .first()
    )
    if inst and inst.realm:
        return inst.realm
    # Slug fallback — alphanumerics from the company name, else c<id>.
    slug = "".join(ch.lower() for ch in (customer.company_name or "") if ch.isalnum())
    return (slug or f"c{customer.id}")[:80]


def _ports(suggested_auth: Any, suggested_acct: Any) -> tuple[int, int]:
    def _as_port(value, fallback):
        try:
            n = int(value)
        except (TypeError, ValueError):
            return fallback
        return n if 1 <= n <= 65535 else fallback

    return (
        _as_port(suggested_auth, _DEFAULT_AUTH_PORT),
        _as_port(suggested_acct, _DEFAULT_ACCT_PORT),
    )


def _truthy(value: Any) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _resolve_or_mint_secret(
    instance: CustomerRadiusInstance,
    customer_id: int,
    suggested_secret: str,
) -> tuple[str, bool]:
    """Return ``(plaintext, newly_minted)``.

    Order:
      * explicit body ``shared_secret`` → store it, no minting.
      * existing vault-backed secret on the instance → reuse.
      * nothing → mint a fresh 32-char secret + persist it.
    """
    setting_key = _setting_key_for(customer_id)

    if suggested_secret:
        _write_secret_setting(setting_key, suggested_secret)
        instance.secret_vault_ref = _VAULT_REF_PREFIX + setting_key
        return suggested_secret, False

    if instance.secret_vault_ref and instance.secret_vault_ref.startswith(_VAULT_REF_PREFIX):
        existing = _read_secret_setting(instance.secret_vault_ref[len(_VAULT_REF_PREFIX):])
        if existing:
            return existing, False

    fresh = _alnum_secret()
    _write_secret_setting(setting_key, fresh)
    instance.secret_vault_ref = _VAULT_REF_PREFIX + setting_key
    return fresh, True


def provision_on_link(
    app: Flask,
    license_obj: License,
    *,
    instance_url: str = "",
    realm: str = "",
    radius_auth_ip: str = "",
    radius_auth_port: Any = None,
    radius_acct_port: Any = None,
    shared_secret: str = "",
    mgmt_wg_ip: str = "",
    hostname: str = "",
    fingerprint: str = "",
    return_secret_when_minted: bool = True,
) -> dict[str, Any]:
    """Idempotently create / refresh the customer's RADIUS instance + route.

    Returns a dict — never raises for "expected" failures (missing
    customer, fleet absent, etc.); the heartbeat handler echoes the
    ``status`` field back to the radius-module so it can react.

    ``shared_secret``: pass the empty string to let the panel mint one.
    The minted plaintext is included in the response under
    ``shared_secret`` ONLY when it was just generated AND
    ``return_secret_when_minted`` is True, so the radius-module can
    configure its own RADIUS to match in the SAME bridge call (no
    second round-trip).
    """
    del app  # unused — kept in the signature for future logging hooks
    customer = license_obj.customer
    if customer is None:
        return {"status": "no_customer", "ok": False}

    # ── 1. RADIUS instance row ────────────────────────────────────────
    instance = (
        CustomerRadiusInstance.query
        .filter_by(customer_id=customer.id)
        .first()
    )
    realm_value = _derive_realm(customer, suggested=realm)
    auth_port, acct_port = _ports(radius_auth_port, radius_acct_port)
    auth_ip = (radius_auth_ip or "").strip()[:64]
    mgmt_ip = (mgmt_wg_ip or "").strip()[:64]

    if instance is None:
        instance = CustomerRadiusInstance(
            customer_id=customer.id,
            instance_name=(customer.company_name or f"customer-{customer.id}")[:80],
            realm=realm_value,
            radius_auth_ip=auth_ip,
            radius_auth_port=auth_port,
            radius_acct_port=acct_port,
            mgmt_wg_ip=mgmt_ip,
            status="active",
            secret_vault_ref="",
        )
        db.session.add(instance)
        db.session.flush()
        action = "created"
    else:
        # Refresh only the fields the bridge supplied — preserve previous
        # values (manual fixes by the operator stay intact) when blank.
        if realm and realm_value != instance.realm:
            instance.realm = realm_value
        if auth_ip:
            instance.radius_auth_ip = auth_ip
        if radius_auth_port is not None:
            instance.radius_auth_port = auth_port
        if radius_acct_port is not None:
            instance.radius_acct_port = acct_port
        if mgmt_ip:
            instance.mgmt_wg_ip = mgmt_ip
        instance.status = "active"
        action = "updated"

    instance.last_seen_at = utcnow()

    plaintext_secret, minted = _resolve_or_mint_secret(
        instance, customer.id, shared_secret.strip()
    )

    # ── 2. Proxy realm route ──────────────────────────────────────────
    route = (
        ProxyRealmRoute.query
        .filter_by(customer_id=customer.id, radius_instance_id=instance.id)
        .first()
    )
    allowlist = _fleet_node_ids_for_allowlist()
    if route is None:
        route = ProxyRealmRoute(
            customer_id=customer.id,
            radius_instance_id=instance.id,
            realm=instance.realm,
            target_radius_ip=instance.radius_auth_ip or "",
            target_auth_port=instance.radius_auth_port,
            target_acct_port=instance.radius_acct_port,
            secret_vault_ref=instance.secret_vault_ref,
            status="active",
        )
        route.allowed_fleet_chr_node_ids = allowlist
        db.session.add(route)
        db.session.flush()
        route_action = "created"
    else:
        route.realm = instance.realm
        if instance.radius_auth_ip:
            route.target_radius_ip = instance.radius_auth_ip
        route.target_auth_port = instance.radius_auth_port
        route.target_acct_port = instance.radius_acct_port
        if not route.secret_vault_ref:
            route.secret_vault_ref = instance.secret_vault_ref
        if not route.allowed_fleet_chr_node_ids and allowlist:
            route.allowed_fleet_chr_node_ids = allowlist
        if route.status != "active":
            route.status = "active"
        route_action = "updated"

    _log.info(
        "radius_auto_provision: customer_id=%s instance=%s route=%s realm=%s minted_secret=%s",
        customer.id, action, route_action, instance.realm, minted,
    )

    response = {
        "ok": True,
        "status": "provisioned",
        "instance_action": action,
        "route_action": route_action,
        "instance_id": int(instance.id),
        "route_id": int(route.id),
        "realm": instance.realm,
        "radius_auth_ip": instance.radius_auth_ip,
        "radius_auth_port": instance.radius_auth_port,
        "radius_acct_port": instance.radius_acct_port,
        "radius_target": (
            f"{instance.radius_auth_ip}:{instance.radius_auth_port}"
            if instance.radius_auth_ip else ""
        ),
        "allowed_fleet_chr_node_ids": allowlist,
        "secret_minted": bool(minted),
    }
    if minted and return_secret_when_minted:
        # Closing the loop: the radius-module receives the freshly minted
        # secret in the SAME bridge call so it can configure its own RADIUS
        # to match. After this call returns, the panel never echoes the
        # plaintext again — it lives in the Setting (encrypted) only.
        response["shared_secret"] = plaintext_secret
    return response


__all__ = ["provision_on_link"]
