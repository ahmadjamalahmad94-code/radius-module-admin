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
from ..models import CustomerRadiusInstance, ProxyRealmRoute, utcnow
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
      * ``source``        – always ``"fleet"`` after step 6 of
                            docs/CONSOLIDATION.md. The field is preserved
                            so proxy clients that pinned the contract
                            keep parsing — and so a future change of
                            source can be debugged without re-reading
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

    # Fleet registry (the post-Phase-2 table the onboarding wizard writes).
    # Step 6 of docs/CONSOLIDATION.md dropped the legacy chr_nodes union;
    # this is the only source now. The lazy import keeps the module
    # bootable on the (no-fleet) branches the CI matrix still touches.
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

        # Resolve allowed CHR IPs from the fleet registry. We publish BOTH
        # the public IP AND the wg-data IP for every eligible node — RADIUS
        # may legitimately arrive over either path:
        #   * public_ip   — RADIUS-from-internet (no wg tunnel).
        #   * wg_data_ip  — the canonical post-fleet path. The CHR sends
        #                   over the wg-data tunnel and the proxy SEES the
        #                   10.98.0.X source address, NOT the public IP.
        # Without wg_data_ip in this per-realm allowlist the proxy logs
        # "Packet from unknown CHR IP 10.98.0.11 — dropped" — the live
        # regression chr-vpn-1 hit. See tests/fix_routing_table/.
        allowed_ips: list[str] = []
        seen: set[str] = set()

        def _push(ip: str | None) -> None:
            if ip and ip not in seen:
                allowed_ips.append(ip)
                seen.add(ip)

        for nid in (r.allowed_fleet_chr_node_ids or []):
            node = fleet_chr_by_id.get(nid)
            if node is None:
                continue
            _push(node.public_ip)
            _push(_derive_wg_data_ip(node.wg_mgmt_ip))

        routes_out.append({
            "realm": r.realm,
            "customer_id": r.customer_id,
            "target_ip": r.target_radius_ip,
            "auth_port": r.target_auth_port,
            "acct_port": r.target_acct_port,
            "secret": secret_value,
            "allowed_chr_ips": allowed_ips,
        })

    # ── Build chr_nodes[] from the fleet registry only. ──
    chr_list: list[dict] = []
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
            fleet=len(chr_list),  # fleet-only after step 6
            realms_active=len(routes_out),
            realms_draft=draft_realms,
            realms_total=total_realms,
            live_apply=live_apply_enabled,
            movable_users=len(movable_users),
        )
    except Exception:  # noqa: BLE001
        pass

    # CUSTOMER_RADIUS_TUNNEL_DESIGN §6.1 — publish the CHR↔proxy RADIUS
    # secret in the authenticated routing-table response so the proxy
    # reads it per-packet instead of trusting a hand-edited env. The
    # value is the decrypted Setting CHR_SHARED_SECRET — the SAME value
    # the unified RouterOS template bakes into every CHR script — so
    # the two sides are equal by construction, not by operator
    # diligence. Empty string when the owner has not minted one yet
    # (proxy treats "" as "use my bootstrap env fallback"). NEVER log
    # the value: dlog below intentionally excludes it.
    chr_shared_secret = ""
    try:
        from fleet.registry.infra_settings import get_chr_shared_secret_plaintext
        chr_shared_secret = get_chr_shared_secret_plaintext()
    except Exception:  # noqa: BLE001 — degrade to empty on a partial deploy
        current_app.logger.exception(
            "routing-table: chr_shared_secret resolution degraded to empty",
        )

    return jsonify({
        "ok": True,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "route_count": len(routes_out),
        "routes": routes_out,
        "chr_nodes": chr_list,
        "live_apply_enabled": live_apply_enabled,
        "movable_users": movable_users,
        "realms_status": realms_status,
        # §6.1 — single source-of-truth secret. Authenticated channel only.
        "chr_shared_secret": chr_shared_secret,
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

    # CUSTOMER_RADIUS_TUNNEL_DESIGN §6.4 — the proxy reports a
    # config_fingerprint over (chr_shared_secret + peer-set hash). The
    # panel persists it in the proxy heartbeat trace (here logged; a
    # later admin badge reads the same field). NEVER persist or log the
    # secret behind the fingerprint — only the digest.
    proxy_fingerprint = str(body.get("config_fingerprint") or "")[:80].strip()
    if proxy_fingerprint:
        current_app.logger.info(
            "radius-proxy fingerprint | id=%s fp=%s",
            body.get("proxy_id", "?"), proxy_fingerprint,
        )

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
# WireGuard data-plane peers (zero-touch auto peer sync)
# ──────────────────────────────────────────────────────────────────────────────

@bp.get("/wg-peers")
def wg_peers():
    """Publish the desired wg-DATA peer set for the proxy agent to apply.

    The panel mints every CHR's wg-data keypair, so it already KNOWS the public
    key the proxy must trust + the ``10.98.0.X/32`` allowed-ip the RADIUS
    traffic arrives from. This endpoint hands the proxy that desired set so a
    coordinated proxy-side agent can reconcile its ``wg-data`` interface with no
    manual hand-peering — closing the second half of the WireGuard drift that
    caused ``panel_key_mismatch`` / dropped-RADIUS incidents.

    Auth: the same ``X-Proxy-Token`` HMAC as the rest of ``/api/proxy/*``.

    Eligibility mirrors ``/api/proxy/routing-table`` EXACTLY (enabled + not
    drain + status != 'disabled'); a node missing its wg-data pubkey or whose
    wg-data IP can't be derived is omitted (the panel surfaces that as a FAILED
    sync stage, not a silent gap).

    Response shape — the proxy reconciler reads ``data["peers"]`` and expects a
    TOP-LEVEL list, so ``peers`` is the canonical contract field. Each peer is
    exactly ``{name, public_key, allowed_ips:[...], endpoint}``. ``endpoint`` is
    always ``null``: the proxy is the wg-data LISTENER (CHRs dial IN), so it
    needs no per-peer endpoint. ``allowed_ips`` is authoritative. The remaining
    top-level fields (``ok``, ``generated_at``, ``panel_wg_pubkey``,
    ``interface``, ``listen_port``, ``peer_count``) are additive metadata a
    ``data["peers"]`` parser ignores::

        {
          "ok": true,
          "generated_at": "2026-06-11T12:00:00Z",
          "panel_wg_pubkey": "PANEL_MGMT_PUBKEY=",
          "interface": "wg-data",
          "listen_port": 51821,
          "peer_count": 1,
          "peers": [
            {
              "name": "chr-vpn-1",
              "public_key": "CHR_WG_DATA_PUBKEY=",
              "allowed_ips": ["10.98.0.11/32"],
              "endpoint": null
            }
          ]
        }

    The proxy SHOULD treat ``peers`` as the COMPLETE desired set for its
    ``wg-data`` interface (add missing, remove peers not listed).
    """
    denied = _auth_required()
    if denied:
        return denied

    try:
        from fleet.sync.peers import desired_proxy_peers
        desired = desired_proxy_peers()
    except Exception as exc:  # noqa: BLE001 — defensive: branch w/o fleet/sync
        current_app.logger.warning(
            "wg_peers: desired_proxy_peers failed (%s); returning empty set",
            exc.__class__.__name__,
        )
        desired = []

    panel_pubkey = ""
    try:
        from fleet.registry.infra_settings import panel_pubkey_for_display
        panel_pubkey = (panel_pubkey_for_display() or "").strip()
    except Exception:  # noqa: BLE001
        panel_pubkey = ""

    # Top-level `peers` list, exactly the shape the proxy reconciler parses:
    # name + public_key + allowed_ips + endpoint(null). The CHR public IP /
    # wg-data IP / status flags are intentionally NOT here — the proxy keys off
    # allowed_ips, and an unexpected extra field once tripped a strict parser.
    peers_out = [
        {
            "name": p.name,
            "public_key": p.public_key,
            "allowed_ips": list(p.allowed_ips),
            "endpoint": None,
        }
        for p in desired
    ]

    try:
        from app.services.proxy_api_debug import dlog
        dlog("wg-peers", peer_count=len(peers_out))
    except Exception:  # noqa: BLE001
        pass

    return jsonify({
        "ok": True,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "panel_wg_pubkey": panel_pubkey,
        "interface": "wg-data",
        "listen_port": 51821,
        "peer_count": len(peers_out),
        "peers": peers_out,
    })


# ──────────────────────────────────────────────────────────────────────────────
# wg-radius peers — CUSTOMER_RADIUS_TUNNEL_DESIGN §4.1
# ──────────────────────────────────────────────────────────────────────────────

@bp.get("/radius-peers")
def radius_peers():
    """Publish the desired wg-radius peer set for the proxy reconciler.

    A peer is one customer's RADIUS server (10.200.<customer_id>.2/32).
    Every customer who has reported a wg-radius public key on their
    bridge heartbeat AND whose instance is not ``disabled`` is included
    here; the proxy diffs against ``wg show wg-radius dump`` and applies
    the deltas, the same way ``wg-peers`` already drives ``wg-data``.

    Shape — top-level ``peers`` list (matching the §1421c16 wg-peers fix):

    .. code-block:: json

        {
          "ok": true,
          "generated_at": "...Z",
          "interface": "wg-radius",
          "listen_port": 51822,
          "panel_wg_pubkey": "...",
          "peer_count": 1,
          "peers": [
            {
              "name": "client5-radius",
              "public_key": "...",
              "allowed_ips": ["10.200.5.2/32"],
              "endpoint": null
            }
          ]
        }

    ``endpoint`` is always null: customers DIAL the proxy (they're behind
    NAT in the general case), so the proxy never dials out. The
    ``panel_wg_pubkey`` echoes the stable wg-radius public key — minted
    on first call via the same key-stability pattern that holds
    ``PANEL_WG_PUBKEY`` — so the bootstrap deploy can copy it into the
    proxy's ``/etc/wireguard/wg-radius.conf`` once and never again.
    """
    denied = _auth_required()
    if denied:
        return denied
    try:
        from app.services.customer_radius_tunnel import build_radius_peers_payload
        peers_out = build_radius_peers_payload()
    except Exception as exc:  # noqa: BLE001 - never 5xx the publisher
        current_app.logger.exception(
            "radius-peers: build_radius_peers_payload failed: %s", exc,
        )
        peers_out = []

    # Mint the stable panel-radius pubkey on first ever call (and a
    # no-op thereafter — the doc's "stable slot, never implicitly
    # regenerated" invariant).
    panel_pubkey = ""
    try:
        from fleet.registry.infra_settings import ensure_panel_radius_keypair
        panel_pubkey = ensure_panel_radius_keypair().get("public_key", "") or ""
    except Exception:  # noqa: BLE001 — degrade gracefully on missing crypto
        try:
            from fleet.registry.infra_settings import panel_radius_pubkey as _read
            panel_pubkey = _read() or ""
        except Exception:  # noqa: BLE001
            panel_pubkey = ""

    return jsonify({
        "ok": True,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "interface": "wg-radius",
        "listen_port": 51822,
        "panel_wg_pubkey": panel_pubkey,
        "peer_count": len(peers_out),
        "peers": peers_out,
    })


# ──────────────────────────────────────────────────────────────────────────────
# CHR node list (for proxy to validate source IPs)
# ──────────────────────────────────────────────────────────────────────────────

@bp.get("/chr-nodes")
def chr_nodes_list():
    """Return active CHR node IPs the proxy should accept RADIUS from.

    Fleet-only after step 6 of docs/CONSOLIDATION.md. Filters mirror the
    routing-table query so a node that's published in one is published in
    both: enabled + not draining + not admin-disabled (status != disabled).
    Control-plane health ('down' / 'degraded') is intentionally NOT a
    publication gate — placement health is the brain's concern.
    """
    denied = _auth_required()
    if denied:
        return denied

    try:
        from fleet.registry.models_chr import FleetChrNode  # noqa: WPS433
    except Exception:  # noqa: BLE001 — defensive: branch w/o fleet
        return jsonify({"ok": True, "chr_nodes": []})

    nodes = (
        FleetChrNode.query
        .filter(FleetChrNode.enabled.is_(True))
        .filter(FleetChrNode.drain.is_(False))
        .filter(FleetChrNode.status != "disabled")
        .order_by(FleetChrNode.name.asc())
        .all()
    )
    return jsonify({
        "ok": True,
        "chr_nodes": [
            {
                "name": n.name,
                "public_ip": n.public_ip,
                # No per-service flag exists on FleetChrNode — every fleet
                # node carries the standard stack (SSTP/PPTP/L2TP/IPsec +
                # WireGuard) wired by the onboarding wizard. The proxy
                # uses the IP for filtering, not this list.
                "enabled_services": ["sstp", "pptp", "l2tp_ipsec", "ikev2_ipsec", "wireguard_data"],
            }
            for n in nodes
        ],
    })
