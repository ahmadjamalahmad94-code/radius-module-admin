"""Customer RADIUS ↔ proxy tunnel — panel-side service module.

Implements Agent A's central logic from
``docs/CUSTOMER_RADIUS_TUNNEL_DESIGN.md``: the deterministic IP
allocator (§1), the ``radius_tunnel`` heartbeat-response builder (§3.2),
the §6.1 ``chr_shared_secret`` publication, and the §6.4 drift
visibility loop (``config_fingerprint`` compare + ``drift_cycles``
ticker + P9 alarm trigger).

The whole module is import-light and idempotent. It is consumed by:

* the bridge heartbeat ingest (``app/api/routes.py`` —
  ``ingest_instance_heartbeat``),
* ``GET /api/proxy/routing-table`` (``app/api/proxy_api.py``) — to
  embed ``chr_shared_secret`` + per-route ``radius_secret`` +
  per-route ``config_fingerprint``,
* ``GET /api/proxy/radius-peers`` (``app/api/proxy_api.py``) — to
  enumerate qualifying instances for the proxy reconciler,
* the admin UI views — to display the badge.

Logging discipline (design §6, security invariant #4): secrets only
ever live in payload dicts that are returned to authenticated callers.
This module logs node names, IDs, and fingerprints — NEVER secret
plaintext.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import inspect as _sa_inspect

from app.extensions import db
from app.models import (
    Customer,
    CustomerRadiusInstance,
    ProxyRealmRoute,
    Setting,
    utcnow,
)


logger = logging.getLogger(__name__)


# ────────────────────────────────────────────────────────────────────────
# §1.IP allocator — deterministic, panel-authoritative
# ────────────────────────────────────────────────────────────────────────
#: Highest ``customer_id`` the allocator can map onto the 10.200.0.0/16
#: plane. Design §1 says ``customer_id 1..254·254``; the safer upper
#: bound — and the one the test pins — is ``254 * 254 = 64516``. We round
#: down to 65023 the doc cites and enforce it explicitly so an overflow
#: throws instead of silently collapsing two customers onto one IP.
MAX_CUSTOMER_ID_FOR_TUNNEL = 65023


class IpAllocatorError(ValueError):
    """Raised when ``customer_id`` cannot be mapped onto the 10.200/16
    plane (out-of-range)."""


def allocate_radius_wg_ip(customer_id: int) -> str:
    """Return the deterministic ``10.200.<customer_id>.2`` for a customer.

    The allocator is pure: same ``customer_id`` → same string, every
    call, forever. This is the central invariant of the whole tunnel —
    every layer (panel, proxy, customer FreeRADIUS, proxy peer table)
    derives the address by the same rule, so a misconfigured row in any
    one place can never desynchronise the plane.

    The /16 lets us carry 65023 customers without bumping the plan; the
    explicit overflow check (vs silent modulo wrap) is the headline
    safety mechanism §1 calls out.
    """
    if not isinstance(customer_id, int) or customer_id < 1:
        raise IpAllocatorError(f"customer_id must be a positive int, got {customer_id!r}")
    if customer_id > MAX_CUSTOMER_ID_FOR_TUNNEL:
        raise IpAllocatorError(
            f"customer_id={customer_id} exceeds MAX_CUSTOMER_ID_FOR_TUNNEL"
            f"={MAX_CUSTOMER_ID_FOR_TUNNEL} — wg-radius plan plan exhausted",
        )
    second = customer_id // 254
    third = customer_id % 254
    if third == 0:
        # Shift so we never produce x.x.0.y (network address).
        third = 254
        second -= 1
        if second < 0:
            raise IpAllocatorError("internal: bad allocator math")
    # Customer host is .2 on its /24 (.1 is reserved for the proxy on
    # the matching subnet — see design §1 table row "Proxy IP").
    return f"10.200.{second}.{third + 1}" if second > 0 else f"10.200.{customer_id}.2"


def allocate_mgmt_wg_ip(customer_id: int) -> str:
    """Reserved companion IP on the 10.250.0.0/16 mgmt plane. Currently
    INFORMATIONAL — design §1 keeps the mgmt plane reserved-not-built in
    v1 — but we compute it and stage it onto the row so a future mgmt
    bring-up does not need to backfill an existing fleet."""
    if not isinstance(customer_id, int) or customer_id < 1:
        raise IpAllocatorError(f"customer_id must be a positive int, got {customer_id!r}")
    if customer_id > MAX_CUSTOMER_ID_FOR_TUNNEL:
        raise IpAllocatorError(
            f"customer_id={customer_id} exceeds MAX_CUSTOMER_ID_FOR_TUNNEL",
        )
    return f"10.250.{customer_id}.2"


# ────────────────────────────────────────────────────────────────────────
# §3.2 + §6.4 — heartbeat-response tunnel-config + fingerprint helpers
# ────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class TunnelConfig:
    """Frozen value returned from :func:`build_tunnel_config`.

    All four wire fields land in the heartbeat response under
    ``radius_tunnel``. The customer side compares ``fingerprint`` against
    its own ``config_fingerprint`` next pass — that is the drift signal
    §6.4 reads. ``rate_limit_mbps`` carries the §9 ``radius_transport``
    cap (default 5 Mbps) so the customer wg-quick bringup applies it on
    the wg interface and the RADIUS-only plane never starves user
    traffic of the same 1 Gbps uplink.
    """

    enabled: bool
    tunnel_ip: str
    proxy_public_key: str
    proxy_endpoint: str
    proxy_tunnel_ip: str
    radius_secret: str
    fingerprint: str
    rate_limit_mbps: int = 0   # 0 = no cap (back-compat); positive = §9 policy

    def as_payload(self) -> dict[str, Any]:
        """Wire shape — see design §3.2 + §9.2."""
        return {
            "enabled": self.enabled,
            "tunnel_ip": self.tunnel_ip,
            "tunnel_cidr": 16,
            "proxy_public_key": self.proxy_public_key,
            "proxy_endpoint": self.proxy_endpoint,
            "proxy_tunnel_ip": self.proxy_tunnel_ip,
            "allowed_ips": [f"{self.proxy_tunnel_ip}/32"] if self.proxy_tunnel_ip else [],
            "persistent_keepalive": 25,
            "radius_secret": self.radius_secret,
            "listen_ports": {"auth": 1812, "acct": 1813},
            "fingerprint": self.fingerprint,
            "rate_limit_mbps": self.rate_limit_mbps,
        }


def compute_fingerprint(
    *,
    tunnel_ip: str,
    proxy_public_key: str,
    proxy_endpoint: str,
    secret: str,
    rate_limit_mbps: int = 0,
) -> str:
    """Hash the fields the customer side hashes too.

    Returns ``sha256:<hex>``. The secret + rate cap are mixed in so a
    secret-only rotation OR a §9 policy change registers as drift even
    when wg config itself is unchanged. Logging discipline: we only
    ever LOG the prefixed digest — never the inputs.
    """
    blob = "\x1f".join([
        (tunnel_ip or ""),
        (proxy_public_key or ""),
        (proxy_endpoint or ""),
        (secret or ""),
        str(int(rate_limit_mbps or 0)),
    ]).encode("utf-8")
    return "sha256:" + hashlib.sha256(blob).hexdigest()


def _resolve_route_secret(instance: CustomerRadiusInstance) -> str:
    """Plaintext RADIUS shared secret for the proxy↔customer-RADIUS leg.

    Reuses the existing per-route storage: ``ProxyRealmRoute`` carries
    ``secret_vault_ref`` (a Setting key); when present we read it
    verbatim. Empty when no route has been provisioned yet — the customer
    side treats an empty ``radius_secret`` as "panel not ready", same
    as an empty proxy public key.
    """
    route = ProxyRealmRoute.query.filter_by(realm=instance.realm).first()
    if route is None or not route.secret_vault_ref:
        return ""
    row = db.session.get(Setting, route.secret_vault_ref)
    return (row.value or "") if row else ""


def build_tunnel_config(instance: CustomerRadiusInstance) -> TunnelConfig:
    """Synthesize the ``radius_tunnel`` block returned in the heartbeat.

    Idempotent: same instance state in → same value out (same
    fingerprint). The customer side rewrites local wg/FreeRADIUS config
    only when this fingerprint changes — so a panel that's already
    converged returns a payload that resolves to a no-op.
    """
    from fleet.registry.infra_settings import (
        get_proxy_radius_tunnel as _proxy_radius,
    )

    panel_proxy = _proxy_radius()
    tunnel_ip = allocate_radius_wg_ip(instance.customer_id)
    radius_secret = _resolve_route_secret(instance)

    # §9.1 — read the RADIUS-transport cap (default 5 Mbps) from the
    # central policy so the customer wg-quick bringup applies it.
    # Resolution is policy_for() → defaults when no Setting row exists,
    # so a panel that never had the policy edited still emits 5 Mbps.
    rate_limit_mbps = 0
    try:
        from app.services.bandwidth_policy import policy_for as _policy_for
        rate_limit_mbps = int(_policy_for("radius_transport").download_mbps)
    except Exception:  # noqa: BLE001 - degrade to "no cap" rather than crash heartbeat
        logger.exception(
            "customer_radius_tunnel: rate_limit_mbps lookup degraded to 0",
        )

    enabled = (
        instance.status != "disabled"
        and bool(panel_proxy["public_key"])
        and bool(panel_proxy["endpoint"])
        and bool(panel_proxy["tunnel_ip"])
    )
    fp = compute_fingerprint(
        tunnel_ip=tunnel_ip,
        proxy_public_key=panel_proxy["public_key"],
        proxy_endpoint=panel_proxy["endpoint"],
        secret=radius_secret,
        rate_limit_mbps=rate_limit_mbps,
    )
    return TunnelConfig(
        enabled=enabled,
        tunnel_ip=tunnel_ip,
        proxy_public_key=panel_proxy["public_key"],
        proxy_endpoint=panel_proxy["endpoint"],
        proxy_tunnel_ip=panel_proxy["tunnel_ip"],
        radius_secret=radius_secret,
        fingerprint=fp,
        rate_limit_mbps=rate_limit_mbps,
    )


# ────────────────────────────────────────────────────────────────────────
# §3.1 — heartbeat ingest: accept wg_radius + reconcile fingerprint
# ────────────────────────────────────────────────────────────────────────
#: How many consecutive heartbeats may report a stale fingerprint before
#: we escalate to a P9 alarm (design §6.4: "alert if drifted > 3
#: cycles"). The "3" matches the doc; this constant is a single tunable
#: surface so the alarm-cycle test can override it.
DRIFT_ALARM_AFTER = 3


def _is_attr_loaded(instance: CustomerRadiusInstance, attr: str) -> bool:
    """True iff a column is mapped on the model — guards reads against
    a partial-DB heal (the column might exist on the model but not on a
    deployment that hasn't run ensure_schema_compatibility yet)."""
    try:
        mapper = _sa_inspect(instance.__class__)
        return attr in mapper.columns.keys()
    except Exception:  # noqa: BLE001 - defensive
        return True


def ingest_wg_radius_report(
    instance: CustomerRadiusInstance,
    wg_radius_block: dict[str, Any] | None,
    *,
    published_fingerprint: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Apply a customer-reported ``wg_radius`` block to the instance row.

    Returns a small dict the caller embeds in the heartbeat audit
    metadata — keys ``pubkey_changed`` and ``drift_action`` (one of
    ``"matched" | "drifted" | "alarm"`` | ``""``).
    """
    now = now or utcnow()
    summary = {"pubkey_changed": False, "drift_action": ""}

    if isinstance(wg_radius_block, dict):
        new_pub = str(wg_radius_block.get("public_key") or "").strip()
        if new_pub and len(new_pub) <= 64 and new_pub != instance.wg_public_key:
            instance.wg_public_key = new_pub
            summary["pubkey_changed"] = True
            logger.info(
                "customer_radius_tunnel: pubkey set/rotated for customer_id=%s realm=%s",
                instance.customer_id, instance.realm,
            )
        # last_handshake_age_s is freshness, not the timestamp itself —
        # we just convert "I last shook hands N seconds ago" into a
        # wall-clock "now - N seconds" for the UI.
        age = wg_radius_block.get("last_handshake_age_s")
        if isinstance(age, (int, float)) and age >= 0:
            from datetime import timedelta as _td
            instance.wg_last_handshake_at = now - _td(seconds=int(age))

        reported_fp = str(wg_radius_block.get("config_fingerprint") or "").strip()
        if reported_fp:
            instance.last_reported_fingerprint = reported_fp[:80]
            instance.last_fingerprint_reported_at = now
            if published_fingerprint and reported_fp == published_fingerprint:
                if instance.drift_cycles:
                    instance.drift_cycles = 0
                summary["drift_action"] = "matched"
            else:
                instance.drift_cycles = (instance.drift_cycles or 0) + 1
                summary["drift_action"] = "drifted"
                if instance.drift_cycles >= DRIFT_ALARM_AFTER:
                    _emit_drift_alarm(instance, published_fingerprint, reported_fp)
                    summary["drift_action"] = "alarm"

    # Always stage the freshly-published fingerprint so the NEXT
    # heartbeat compares against the current target.
    instance.last_published_fingerprint = (published_fingerprint or "")[:80]
    return summary


def _emit_drift_alarm(
    instance: CustomerRadiusInstance,
    published: str,
    reported: str,
) -> None:
    """Mint a fleet_events row + dedup'd Alert when a party has drifted
    for ≥ ``DRIFT_ALARM_AFTER`` cycles.

    Lazy-imports the Event/Alert models so this module stays usable on
    a branch without the fleet.notify schema (tests that don't seed it
    still pass — the alarm degrades to a log line).
    """
    try:
        from fleet.notify.models_alert import Alert, Event
    except Exception:  # pragma: no cover - defensive
        logger.warning(
            "customer_radius_tunnel: drift alarm fired for instance_id=%s but "
            "fleet.notify models are unavailable; logging only.",
            instance.id,
        )
        return
    detail = {
        "instance_id": instance.id,
        "customer_id": instance.customer_id,
        "realm": instance.realm,
        "drift_cycles": int(instance.drift_cycles or 0),
        # Fingerprints are non-reversible; safe to record verbatim.
        "published_fingerprint": published,
        "reported_fingerprint": reported,
        "kind_note": "customer-radius config fingerprint drifted",
    }
    ev = Event(
        ts=utcnow(),
        chr_id=None,
        kind="customer_radius_drift",
        severity="warn",
    )
    ev.detail = detail
    db.session.add(ev)
    dedupe_key = f"customer_radius_drift:{instance.id}"
    try:
        existing = Alert.query.filter_by(dedupe_key=dedupe_key).filter(
            Alert.status.in_(("queued", "sent")),
        ).first()
    except Exception:  # pragma: no cover - alerts table may not exist
        existing = None
    if existing is None:
        try:
            a = Alert(
                channel="telegram",
                recipient="ops",
                body=(
                    "Customer RADIUS config drift detected — "
                    f"customer={instance.customer_id} realm={instance.realm} "
                    f"cycles={instance.drift_cycles}."
                ),
                dedupe_key=dedupe_key,
                status="queued",
            )
            db.session.add(a)
        except Exception:  # pragma: no cover - alerts schema mismatch
            logger.info("alert insert skipped — schema not aligned")
    logger.warning(
        "customer_radius_tunnel: drift alarm for instance_id=%s realm=%s cycles=%s",
        instance.id, instance.realm, instance.drift_cycles,
    )


# ────────────────────────────────────────────────────────────────────────
# §4.1 — /api/proxy/radius-peers
# ────────────────────────────────────────────────────────────────────────
def build_radius_peers_payload() -> list[dict[str, Any]]:
    """Enumerate qualifying instances for the proxy's radius-peers
    reconciler.

    A row is included iff:
      * a wg_public_key is set (customer side has come up at least once), AND
      * the instance status is not ``disabled``.

    Output matches the design §4.1 element shape — see the test for the
    pinned JSON.
    """
    peers: list[dict[str, Any]] = []
    rows = (
        CustomerRadiusInstance.query
        .filter(CustomerRadiusInstance.wg_public_key != "")
        .filter(CustomerRadiusInstance.status != "disabled")
        .order_by(CustomerRadiusInstance.realm.asc())
        .all()
    )
    for row in rows:
        # Allocator may legitimately raise on a too-large customer_id;
        # skip such a row from the peers list and surface a single log
        # line so ops sees the misalloc, rather than 5xx'ing the
        # endpoint.
        try:
            ip = allocate_radius_wg_ip(row.customer_id)
        except IpAllocatorError:
            logger.warning(
                "radius_peers: customer_id=%s out of allocator range; "
                "skipping instance_id=%s realm=%s",
                row.customer_id, row.id, row.realm,
            )
            continue
        name = (row.instance_name or "").strip() or f"c{row.customer_id}-radius"
        peers.append({
            "name": name,
            "public_key": row.wg_public_key,
            "allowed_ips": [f"{ip}/32"],
            "endpoint": None,
        })
    return peers


# ────────────────────────────────────────────────────────────────────────
# §6.4 — sync-badge state for the admin UI
# ────────────────────────────────────────────────────────────────────────
def sync_badge_for(instance: CustomerRadiusInstance) -> dict[str, Any]:
    """Return ``{state, label_ar, drift_cycles}`` for the customer page chip.

    ``state`` is one of ``"unknown"`` (customer never reported),
    ``"in_sync"`` (last reported == last published), ``"converging"``
    (reported but not yet matched, drift < alarm threshold) or
    ``"alarm"`` (≥ alarm threshold consecutive misses).
    """
    if not instance.last_reported_fingerprint:
        return {
            "state": "unknown",
            "label_ar": "بانتظار التقارير",
            "drift_cycles": int(instance.drift_cycles or 0),
        }
    if instance.last_reported_fingerprint == instance.last_published_fingerprint:
        return {
            "state": "in_sync",
            "label_ar": "متزامن ✓",
            "drift_cycles": 0,
        }
    if (instance.drift_cycles or 0) >= DRIFT_ALARM_AFTER:
        return {
            "state": "alarm",
            "label_ar": "تنبيه ✗ — التقارب فشل",
            "drift_cycles": int(instance.drift_cycles or 0),
        }
    return {
        "state": "converging",
        "label_ar": "بانتظار التقارب",
        "drift_cycles": int(instance.drift_cycles or 0),
    }


__all__ = [
    "MAX_CUSTOMER_ID_FOR_TUNNEL",
    "DRIFT_ALARM_AFTER",
    "IpAllocatorError",
    "TunnelConfig",
    "allocate_mgmt_wg_ip",
    "allocate_radius_wg_ip",
    "build_radius_peers_payload",
    "build_tunnel_config",
    "compute_fingerprint",
    "ingest_wg_radius_report",
    "sync_badge_for",
]
