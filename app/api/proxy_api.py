"""API الوكيل المركزي لـ RADIUS — endpoints يستدعيها وكيل radius-proxy.

التحقق من الهوية:
  كل طلب يحمل رأس ``X-Proxy-Token: <timestamp>:<nonce>:<hmac>``
  حيث hmac = HMAC-SHA256(f"{timestamp}:{nonce}", RADIUS_PROXY_SHARED_SECRET)
  نافذة القبول: RADIUS_PROXY_TOKEN_TTL ثانية (افتراضي 60).

Endpoints:
  GET  /api/proxy/routing-table  — جدول التوجيه الكامل للوكيل
  POST /api/proxy/heartbeat      — نبضة حياة من الوكيل + مقاييس
  GET  /api/proxy/chr-nodes      — قائمة عقد CHR المسموح لها

الوكيل لا يعرف بيانات العملاء الداخلية — يعرف فقط:
  - realm → target RADIUS IP:port + secret_value
  - قائمة عناوين CHR المسموح لها بالإرسال
"""
from __future__ import annotations

import hashlib
import hmac
import time
from datetime import datetime, timezone

from flask import Blueprint, current_app, jsonify, request

from ..extensions import db
from ..models import ChrNode, CustomerRadiusInstance, ProxyRealmRoute, utcnow
from ..services.customer_vault import get_secret_by_ref  # tries vault lookup

bp = Blueprint("proxy_api", __name__, url_prefix="/api/proxy")

# ──────────────────────────────────────────────────────────────────────────────
# Auth helper
# ──────────────────────────────────────────────────────────────────────────────

_NONCE_CACHE: dict[str, int] = {}
_NONCE_CACHE_MAX = 2000


def _verify_proxy_token() -> bool:
    """Validate the X-Proxy-Token header. Returns True if valid."""
    # DB-first resolution: the owner sets/rotates the shared secret in
    # /admin/settings/platform; env var stays as the bootstrap fallback.
    try:
        from ..services import platform_settings as ps
        secret = ps.get_secret("RADIUS_PROXY_SHARED_SECRET")
        if not secret:
            secret = str(current_app.config.get("RADIUS_PROXY_SHARED_SECRET") or "").strip()
    except Exception:  # noqa: BLE001
        secret = str(current_app.config.get("RADIUS_PROXY_SHARED_SECRET") or "").strip()
    if not secret:
        # No secret configured — deny all proxy API calls in production.
        return False

    header = request.headers.get("X-Proxy-Token", "").strip()
    if not header:
        return False

    parts = header.split(":", 2)
    if len(parts) != 3:
        return False

    raw_ts, nonce, provided_hmac = parts
    try:
        ts = int(raw_ts)
    except ValueError:
        return False

    ttl = int(current_app.config.get("RADIUS_PROXY_TOKEN_TTL", 60))
    now = int(time.time())
    if abs(now - ts) > ttl:
        return False

    # Replay protection
    cache_key = f"{ts}:{nonce}"
    if cache_key in _NONCE_CACHE:
        return False
    _NONCE_CACHE[cache_key] = now
    if len(_NONCE_CACHE) > _NONCE_CACHE_MAX:
        oldest = sorted(_NONCE_CACHE.items(), key=lambda x: x[1])[:500]
        for k, _ in oldest:
            _NONCE_CACHE.pop(k, None)

    message = f"{ts}:{nonce}".encode()
    expected = hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()
    return hmac.compare_digest(provided_hmac.lower(), expected.lower())


def _auth_required():
    """Returns 401 response if not authenticated, else None."""
    if not _verify_proxy_token():
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    return None


# ──────────────────────────────────────────────────────────────────────────────
# Routing table
# ──────────────────────────────────────────────────────────────────────────────

def _resolve_secret(vault_ref: str, customer_id: int) -> str:
    """Look up the actual secret value from the customer vault."""
    if not vault_ref:
        return ""
    try:
        return get_secret_by_ref(customer_id, vault_ref) or ""
    except Exception:
        return ""


# wg-mgmt pool → wg-data pool conversion. Onboarding mints the wg-data
# address by mirroring the wg-mgmt host octet into the parallel 10.98.0/24
# pool (see fleet/registry/onboarding_service.py §6.3). We replay the same
# rule here so the proxy can resolve "RADIUS arrived from 10.98.0.11 →
# this is chr-vpn-1" without us having to migrate a new column onto
# FleetChrNode at production.
_WG_MGMT_PREFIX = "10.99."
_WG_DATA_PREFIX = "10.98."


def _derive_wg_data_ip(wg_mgmt_ip: str | None) -> str:
    """Return the wg-data IP for a node given its wg-mgmt IP.

    Empty / non-mgmt-pool input ⇒ empty string. We never fabricate an
    address; the proxy gets the empty string and falls back to its
    legacy public-IP allowlist for that node.
    """
    if not wg_mgmt_ip:
        return ""
    s = wg_mgmt_ip.strip()
    if s.startswith(_WG_MGMT_PREFIX):
        return _WG_DATA_PREFIX + s[len(_WG_MGMT_PREFIX):]
    # Defensive: a CHR that for some reason lives outside the canonical
    # 10.99/16 pool gets no derived address rather than a wrong one.
    return ""


@bp.get("/routing-table")
def routing_table():
    """Return the routing table the proxy needs to forward RADIUS traffic.

    Two SOURCES of CHR nodes are merged into ``chr_nodes[]``:

    * **Fleet registry** (``fleet_chr_nodes``) — produced by the onboarding
      wizard. Status vocabulary ``provisioning | up | degraded | down | disabled``.
      A node is published as soon as it is ``enabled = TRUE`` AND
      ``drain = FALSE`` AND ``status != 'disabled'`` — i.e. ``provisioning``,
      ``up``, ``degraded`` AND ``down`` are all published.
      RATIONALE — **publication tracks DATA-plane + admin intent, NOT
      control-plane health.** ``status='down'`` means the panel's
      wg-mgmt ping/api-ssl probe failed; it does NOT mean the CHR
      can't carry RADIUS (the wg-data path is independent and routinely
      works long before / well after the control plane is reachable).
      Excluding ``down`` here causes the catch-22 we hit on the live
      deployment: chr-vpn-1's data plane was fully connected, but the
      panel couldn't ping wg-mgmt (not deployed yet), so the node was
      ``down`` → routing-table dropped it → proxy had nothing to
      allowlist → RADIUS over wg-data was rejected. NEW-placement
      ranking is the right place for health to matter; the brain's
      :func:`fleet.brain.placement.rank` already excludes ``down`` from
      eligibility (Phase-5 contract), so a ``down`` node stays in the
      allowlist but receives no NEW logins — once it recovers it can
      take traffic again without a routing-table refresh fight.
    * **Legacy CHR-console table** (``chr_nodes``, ``app.models.ChrNode``) —
      pre-fleet table some operators still rely on. Kept as a secondary
      source, filtered to ``status="active"`` for backward compatibility.

    Each entry carries the fields the proxy needs to map an incoming RADIUS
    packet back to a node identity:

      * ``name``          – registry node name (telemetry / placement key).
      * ``public_ip``     – front-door candidate + RADIUS-from-internet IP.
      * ``wg_data_ip``    – the RADIUS source IP the proxy actually SEES
                            (RADIUS arrives over the wg-data tunnel from
                            ``10.98.0.X``). Derived from ``wg_mgmt_ip``
                            by swapping the management-pool prefix
                            ``10.99.`` → data-pool prefix ``10.98.``
                            (parallel pools — see onboarding §6.3 /
                            ``fleet/registry/onboarding_service.py``).
      * ``wg_mgmt_ip``    – control-plane address (api-ssl, CoA listener).
      * ``status``        – the underlying registry status string.
      * ``enabled``       – administrative on/off switch.
      * ``drain``         – fleet drain flag (no new placements).
      * ``source``        – ``"fleet"`` or ``"legacy"`` so a future change
                            of source can be debugged without re-reading
                            this file.

    ``routes[]`` is the realm table (``ProxyRealmRoute``). It is **only
    populated by the owner via the Infra → Proxy Routes admin UI**. New
    rows land with ``status="draft"`` and stay invisible to the proxy
    until the owner explicitly switches them to ``"active"``. An empty
    ``routes[]`` is therefore EXPECTED on a fresh install — see the
    ``realms_status`` summary in the response footer for a quick health
    line the operator can read at a glance.
    """
    denied = _auth_required()
    if denied:
        return denied

    routes_q = (
        ProxyRealmRoute.query
        .filter_by(status="active")
        .order_by(ProxyRealmRoute.realm)
        .all()
    )

    # Build legacy + fleet CHR IP/name lookups for allowed_chr_node_ids.
    legacy_chr_nodes = {n.id: n for n in ChrNode.query.all()}

    # Fleet registry (the post-Phase-2 table the onboarding wizard writes).
    # Lazy import so the module still boots on a branch without fleet.
    fleet_chr_nodes_q = []
    try:
        from fleet.registry.models_chr import FleetChrNode  # noqa: WPS433
        # DATA-plane intent: enabled + not draining + not admin-disabled.
        # Control-plane health ('down' / 'degraded') is intentionally NOT a
        # publication gate — see the docstring above for the live-deploy
        # catch-22 this avoids. The brain still filters 'down' from NEW
        # placements in fleet.brain.placement.rank().
        fleet_chr_nodes_q = (
            FleetChrNode.query
            .filter(FleetChrNode.enabled.is_(True))
            .filter(FleetChrNode.drain.is_(False))
            .filter(FleetChrNode.status != "disabled")
            .order_by(FleetChrNode.name.asc())
            .all()
        )
    except Exception as exc:  # noqa: BLE001 — defensive
        current_app.logger.warning(
            "routing_table: fleet_chr_nodes read failed (%s); skipping fleet source",
            exc.__class__.__name__,
        )

    # Index fleet nodes by id for the allow-list resolver below.
    fleet_chr_by_id = {n.id: n for n in fleet_chr_nodes_q}

    routes_out = []
    for r in routes_q:
        # Resolve actual secret from vault
        secret_value = _resolve_secret(r.secret_vault_ref, r.customer_id)

        # Resolve allowed CHR IPs from BOTH the legacy and the fleet
        # registries. The two tables have independent autoincrement
        # sequences and their ids could otherwise collide, so the model
        # carries them in separate columns and we union them here.
        allowed_ips: list[str] = []
        seen: set[str] = set()
        for nid in (r.allowed_fleet_chr_node_ids or []):
            node = fleet_chr_by_id.get(nid)
            if node and node.public_ip and node.public_ip not in seen:
                allowed_ips.append(node.public_ip)
                seen.add(node.public_ip)
        for nid in (r.allowed_chr_node_ids or []):
            node = legacy_chr_nodes.get(nid)
            if node and node.public_ip and node.public_ip not in seen:
                allowed_ips.append(node.public_ip)
                seen.add(node.public_ip)

        routes_out.append({
            "realm": r.realm,
            "customer_id": r.customer_id,
            "target_ip": r.target_radius_ip,
            "auth_port": r.target_auth_port,
            "acct_port": r.target_acct_port,
            "secret": secret_value,
            "allowed_chr_ips": allowed_ips,
        })

    # ── Build chr_nodes[] from BOTH sources, fleet-first, deduped by name. ──
    chr_list: list[dict] = []
    seen_names: set[str] = set()
    for n in fleet_chr_nodes_q:
        if not n.name:
            continue
        chr_list.append({
            "name": n.name,
            "public_ip": n.public_ip,
            "wg_mgmt_ip": n.wg_mgmt_ip,
            "wg_data_ip": _derive_wg_data_ip(n.wg_mgmt_ip),
            "status": n.status,
            "enabled": bool(n.enabled),
            "drain": bool(n.drain),
            "source": "fleet",
        })
        seen_names.add(n.name)
    # Legacy entries — kept for backward compatibility with operators
    # who still drive the CHR-console table. Filtered to active per the
    # pre-fix behaviour.
    for n in legacy_chr_nodes.values():
        if n.status != "active":
            continue
        if n.name in seen_names:
            continue
        chr_list.append({
            "name": n.name,
            "public_ip": n.public_ip,
            "wg_mgmt_ip": n.management_ip,
            "wg_data_ip": _derive_wg_data_ip(n.management_ip),
            "status": n.status,
            "enabled": True,                 # legacy: filtered on status == "active"
            "drain": False,
            "source": "legacy",
            # Keep the legacy fields too so an older proxy that reads them
            # continues to work without a config change.
            "management_ip": n.management_ip,
            "enabled_services": n.enabled_services,
        })
        seen_names.add(n.name)

    # Phase 7: surface the UI-controlled live-apply switch (default OFF).
    # The proxy reads this to decide whether to ENFORCE moves/CoA — see
    # docs/contracts/fleet_api.md §1.1. Import is lazy so an older fleet
    # branch without the control package still boots; missing → false.
    try:
        from fleet.control.live_apply_settings import is_enabled as _live_apply_on
        live_apply_enabled = bool(_live_apply_on())
    except Exception:  # noqa: BLE001 — read path must be defensive
        live_apply_enabled = False

    # Phase 7: the opt-in movable set. Lowercased usernames whose per-user
    # ``movable`` flag is TRUE in fleet_users — this is what the proxy reads to
    # know who may be relocated by enforcement. Absent/empty ⇒ nobody movable.
    # See docs/contracts/fleet_api.md §1.1. Defensive: any read failure ⇒ [].
    try:
        from fleet.brain.models_session import UserFleet
        movable_users = sorted({
            (u or "").strip().lower()
            for (u,) in db.session.query(UserFleet.username)
            .filter(UserFleet.movable.is_(True))
            .all()
            if u
        })
    except Exception:  # noqa: BLE001 — read path must be defensive
        movable_users = []

    # Realms diagnostic — answers "why is routes[] empty?" in one read.
    # If the owner has only DRAFT realms, the proxy needs to be told
    # exactly that so the operator knows where to look (Admin → Infra →
    # Proxy Routes). Counts are cheap and the field shape is additive.
    try:
        total_realms = ProxyRealmRoute.query.count()
        draft_realms = ProxyRealmRoute.query.filter_by(status="draft").count()
        suspended_realms = ProxyRealmRoute.query.filter_by(status="suspended").count()
    except Exception:  # noqa: BLE001 — defensive
        total_realms = draft_realms = suspended_realms = 0
    realms_status = {
        "active": len(routes_out),
        "draft": draft_realms,
        "suspended": suspended_realms,
        "total": total_realms,
        "hint": (
            "إنشئ ProxyRealmRoute ثم اضبط الحالة إلى active "
            "من Admin → البنية التحتية → مسارات الوكيل"
            if total_realms == 0 or len(routes_out) == 0 else ""
        ),
    }

    # Debug logging — owner-toggleable. Single structured line per call.
    try:
        from app.services.proxy_api_debug import dlog
        dlog(
            "routing-table",
            chr_nodes=len(chr_list),
            fleet=len([c for c in chr_list if c["source"] == "fleet"]),
            legacy=len([c for c in chr_list if c["source"] == "legacy"]),
            realms_active=len(routes_out),
            realms_draft=draft_realms,
            realms_total=total_realms,
            live_apply=live_apply_enabled,
            movable_users=len(movable_users),
        )
    except Exception:  # noqa: BLE001
        pass

    return jsonify({
        "ok": True,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "route_count": len(routes_out),
        "routes": routes_out,
        "chr_nodes": chr_list,
        "live_apply_enabled": live_apply_enabled,
        "movable_users": movable_users,
        "realms_status": realms_status,
    })


# ──────────────────────────────────────────────────────────────────────────────
# Heartbeat / status
# ──────────────────────────────────────────────────────────────────────────────

@bp.post("/heartbeat")
def heartbeat():
    """Accept a heartbeat from the proxy agent with optional metrics.

    Body (JSON):
    {
      "proxy_id": "proxy-01",
      "uptime_seconds": 3600,
      "routes_loaded": 5,
      "requests_total": 1200,
      "requests_accepted": 1100,
      "requests_rejected": 80,
      "requests_error": 20,
      "active_realms": ["client1", "client5"],
      "realms_not_found": ["unknown1"]
    }
    """
    denied = _auth_required()
    if denied:
        return denied

    body = request.get_json(silent=True) or {}
    # Log to app logger — can be wired to Prometheus/Loki in future
    current_app.logger.info(
        "radius-proxy heartbeat | id=%s routes=%s reqs=%s accepted=%s rejected=%s",
        body.get("proxy_id", "?"),
        body.get("routes_loaded", "?"),
        body.get("requests_total", "?"),
        body.get("requests_accepted", "?"),
        body.get("requests_rejected", "?"),
    )
    # Persist last-seen on matching CustomerRadiusInstances for active realms
    active_realms = body.get("active_realms") or []
    if active_realms:
        now = utcnow()
        (
            CustomerRadiusInstance.query
            .filter(CustomerRadiusInstance.realm.in_(active_realms))
            .update({"last_seen_at": now, "status": "online"}, synchronize_session=False)
        )
        db.session.commit()

    # Flag realms the proxy couldn't find — useful for misconfiguration alerts
    unknown = body.get("realms_not_found") or []
    try:
        from app.services.proxy_api_debug import dlog
        dlog(
            "heartbeat",
            proxy_id=body.get("proxy_id", "?"),
            routes_loaded=body.get("routes_loaded"),
            requests_total=body.get("requests_total"),
            requests_rejected=body.get("requests_rejected"),
            unknown_realms_in=len(unknown),
            active_realms_in=len(active_realms),
        )
    except Exception:  # noqa: BLE001
        pass
    return jsonify({
        "ok": True,
        "ack": {
            "proxy_id": body.get("proxy_id", ""),
            "unknown_realms": unknown,
            "server_time": datetime.now(timezone.utc).isoformat(),
        },
    })


# ──────────────────────────────────────────────────────────────────────────────
# CHR node list (for proxy to validate source IPs)
# ──────────────────────────────────────────────────────────────────────────────

@bp.get("/chr-nodes")
def chr_nodes_list():
    """Return active CHR node IPs the proxy should accept RADIUS from."""
    denied = _auth_required()
    if denied:
        return denied

    nodes = ChrNode.query.filter_by(status="active").all()
    return jsonify({
        "ok": True,
        "chr_nodes": [
            {
                "name": n.name,
                "public_ip": n.public_ip,
                "enabled_services": n.enabled_services,
            }
            for n in nodes
        ],
    })
