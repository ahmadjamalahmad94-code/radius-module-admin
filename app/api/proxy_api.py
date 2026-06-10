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


@bp.get("/routing-table")
def routing_table():
    """Return the active ProxyRealmRoute entries the proxy uses for routing.

    Response shape:
    {
      "ok": true,
      "generated_at": "2026-06-08T12:00:00Z",
      "routes": [
        {
          "realm": "client5",
          "customer_id": 3,
          "target_ip": "10.200.5.2",
          "auth_port": 1812,
          "acct_port": 1813,
          "secret": "<actual radius shared secret>",
          "allowed_chr_ips": ["x.x.x.x", ...]  // empty = all CHR nodes
        }
      ],
      "chr_nodes": [
        {"name": "chr-exit-01", "public_ip": "x.x.x.x", "status": "active"}
      ]
    }
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

    # Build CHR IP lookup for allowed_chr_node_ids
    chr_nodes = {n.id: n for n in ChrNode.query.all()}

    routes_out = []
    for r in routes_q:
        # Resolve actual secret from vault
        secret_value = _resolve_secret(r.secret_vault_ref, r.customer_id)

        # Resolve allowed CHR IPs
        allowed_ips: list[str] = []
        if r.allowed_chr_node_ids:
            for nid in r.allowed_chr_node_ids:
                node = chr_nodes.get(nid)
                if node and node.public_ip:
                    allowed_ips.append(node.public_ip)

        routes_out.append({
            "realm": r.realm,
            "customer_id": r.customer_id,
            "target_ip": r.target_radius_ip,
            "auth_port": r.target_auth_port,
            "acct_port": r.target_acct_port,
            "secret": secret_value,
            "allowed_chr_ips": allowed_ips,
        })

    chr_list = [
        {
            "name": n.name,
            "public_ip": n.public_ip,
            "management_ip": n.management_ip,
            "status": n.status,
            "enabled_services": n.enabled_services,
        }
        for n in chr_nodes.values()
        if n.status == "active"
    ]

    # Phase 7: surface the UI-controlled live-apply switch (default OFF).
    # The proxy reads this to decide whether to ENFORCE moves/CoA — see
    # docs/contracts/fleet_api.md §1.1. Import is lazy so an older fleet
    # branch without the control package still boots; missing → false.
    try:
        from fleet.control.live_apply_settings import is_enabled as _live_apply_on
        live_apply_enabled = bool(_live_apply_on())
    except Exception:  # noqa: BLE001 — read path must be defensive
        live_apply_enabled = False

    return jsonify({
        "ok": True,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "route_count": len(routes_out),
        "routes": routes_out,
        "chr_nodes": chr_list,
        "live_apply_enabled": live_apply_enabled,
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
