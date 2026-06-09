"""fleet.registry.routes_chr — CRUD API for ``fleet_chr_nodes``.

Phase 3 / task T5 deliverable for the registry-side CRUD over CHR nodes. This
module owns the JSON API the panel UI (the onboarding wizard + the fleet
dashboard) talks to. It is **separate** from ``fleet.registry.routes_onboarding``
(owned by a peer agent in this phase), which drives the multi-step state machine
in ``docs/chr_fleet/06_ONBOARDING_WIZARD.md §6.2``. Boundaries:

* This module: **lifecycle CRUD on already-onboarded nodes** — list/get/create-
  via-wizard-finalisation/update/enable/disable. No key minting, no script
  rendering — those are the onboarding agent's job.
* Onboarding agent: ``POST /admin/fleet/onboarding/jobs`` etc. — accepts the
  wizard form, walks the state machine, and finally calls into the registry to
  upsert the node row. The wizard frontend in ``fleet/ui/`` posts to that
  endpoint, NOT to this one.

Endpoint surface (all under ``/admin/fleet`` and gated by ``@login_required``):

==========================================  =======================================
``GET    /admin/fleet/chr-nodes``            list (?status=, ?provider=, ?enabled=)
``GET    /admin/fleet/chr-nodes/<id>``       get one (or 404)
``POST   /admin/fleet/chr-nodes``            create (finalisation hand-off / direct)
``PATCH  /admin/fleet/chr-nodes/<id>``       partial update (weights, capacity…)
``POST   /admin/fleet/chr-nodes/<id>/enable``  enable + clear drain
``POST   /admin/fleet/chr-nodes/<id>/disable`` drain → status='disabled' (NEVER delete)
==========================================  =======================================

Disable is a **drain**, not a delete: the node row stays so historical metrics
and placement decisions can still resolve. The model encodes this with the
``enabled`` + ``drain`` columns and ``status='disabled'`` (see
``fleet/registry/models_chr.py:139`` and the partial index ``idx_fleet_chr_status``).

Response envelope (matches ``app/api/proxy_api.py`` for the rest of the panel):
``{"ok": true, ...}`` on success, ``{"ok": false, "error": "<code>"}`` with the
right HTTP status on failure. Codes used: ``bad_request`` (400),
``unauthorized`` (401 — via ``@login_required`` redirect for HTML, JSON 401 for
API consumers), ``not_found`` (404), ``conflict`` (409), ``server_error`` (500).
"""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Any

from flask import Blueprint, jsonify, request
from sqlalchemy.exc import IntegrityError

from app.auth.routes import audit, login_required
from app.extensions import db
from fleet.registry.models_chr import (
    NODE_COST_MODELS,
    NODE_STATUSES,
    FleetChrNode,
    FleetProvider,
)


bp = Blueprint("fleet_registry_api", __name__, url_prefix="/admin/fleet")


# ────────────────────────────────────────────────────────────────────────────
# JSON helpers
# ────────────────────────────────────────────────────────────────────────────


def _err(code: str, status: int, detail: str = "") -> tuple[Any, int]:
    """House error envelope. ``detail`` is human-readable, ``code`` is machine."""
    body: dict[str, Any] = {"ok": False, "error": code}
    if detail:
        body["detail"] = detail
    return jsonify(body), status


def _dec(value: Any) -> str | None:
    """Decimal-safe JSON value (None preserved, numerics → string for precision)."""
    if value is None:
        return None
    if isinstance(value, Decimal):
        return str(value)
    return value  # int/float pass through, the JSON encoder handles them


def _to_dec(value: Any, *, allow_none: bool = True) -> Decimal | None:
    """Parse a request value into ``Decimal``. Empty/None → None when allowed."""
    if value in (None, "", "null"):
        if allow_none:
            return None
        raise ValueError("missing decimal value")
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"invalid decimal: {value!r}") from exc


def _to_bool(value: Any, *, default: bool | None = None) -> bool | None:
    """Lenient bool parser (form + JSON). Returns ``default`` when missing."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    s = str(value).strip().lower()
    if s in {"1", "true", "yes", "on"}:
        return True
    if s in {"0", "false", "no", "off", ""}:
        return False
    return default


def _to_int(value: Any) -> int | None:
    if value in (None, "", "null"):
        return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid integer: {value!r}") from exc


def _node_to_dict(node: FleetChrNode) -> dict[str, Any]:
    """Serialise a node for JSON responses. Mirrors model column order so the
    UI can rely on a stable shape. Public IPs ARE returned (they're not secrets);
    keys/secrets are NOT — onboarding stores those via vault refs, never here.
    """
    return {
        "id": node.id,
        "provider_id": node.provider_id,
        "provider_name": node.provider.name if node.provider else None,
        "name": node.name,
        "public_ip": node.public_ip,
        "public_ipv6": node.public_ipv6,
        "wg_mgmt_ip": node.wg_mgmt_ip,
        "wg_mgmt_pubkey": node.wg_mgmt_pubkey,
        "routeros_api_port": node.routeros_api_port,
        "coa_port": node.coa_port,
        "max_sessions": node.max_sessions,
        "link_speed_mbps": node.link_speed_mbps,
        "bandwidth_cap_tb": _dec(node.bandwidth_cap_tb),
        "cost_model": node.cost_model,
        "price_per_tb": _dec(node.price_per_tb),
        "overage_allowed": node.overage_allowed,
        "weight": _dec(node.weight),
        "enabled": bool(node.enabled),
        "drain": bool(node.drain),
        "status": node.status,
        "cpu_pct": _dec(node.cpu_pct),
        "active_sessions": node.active_sessions,
        "used_tb_cycle": _dec(node.used_tb_cycle),
        "score": _dec(node.score),
        "last_seen_at": node.last_seen_at.isoformat() + "Z" if node.last_seen_at else None,
        "last_ping_ok_at": node.last_ping_ok_at.isoformat() + "Z" if node.last_ping_ok_at else None,
        "created_at": node.created_at.isoformat() + "Z" if node.created_at else None,
        "updated_at": node.updated_at.isoformat() + "Z" if node.updated_at else None,
    }


# ────────────────────────────────────────────────────────────────────────────
# Validation
# ────────────────────────────────────────────────────────────────────────────


# Fields the wizard / hand-off carries when creating a row. Onboarding usually
# fills the WG/cert columns AFTER key minting (status will be 'provisioning'),
# but a direct create (e.g. an already-prepared node) MAY supply them.
_REQUIRED_CREATE_FIELDS = (
    "provider_id",
    "name",
    "public_ip",
    "wg_mgmt_ip",
    "wg_mgmt_pubkey",
    "max_sessions",
    "link_speed_mbps",
)

# Fields the operator may tweak after the fact via PATCH.
_PATCHABLE_FIELDS = {
    "name",
    "public_ip",
    "public_ipv6",
    "wg_mgmt_ip",
    "wg_mgmt_pubkey",
    "routeros_api_port",
    "coa_port",
    "max_sessions",
    "link_speed_mbps",
    "bandwidth_cap_tb",
    "cost_model",
    "price_per_tb",
    "overage_allowed",
    "weight",
}


def _read_request_body() -> dict[str, Any]:
    """Accept both JSON and form-encoded bodies. The wizard uses JSON; CRUD
    callers may post forms. ``request.get_json(silent=True)`` returns ``None``
    when content-type isn't JSON or the body is malformed."""
    body = request.get_json(silent=True)
    if isinstance(body, dict):
        return body
    if request.form:
        return {k: v for k, v in request.form.items()}
    return {}


def _validate_create_payload(payload: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
    missing = [f for f in _REQUIRED_CREATE_FIELDS if payload.get(f) in (None, "")]
    if missing:
        return {}, f"missing required: {', '.join(missing)}"
    try:
        provider_id = _to_int(payload["provider_id"])
        if provider_id is None:
            return {}, "provider_id must be an integer"
        provider = db.session.get(FleetProvider, provider_id)
        if provider is None:
            return {}, f"provider_id={provider_id} not found"
        cost_model = (payload.get("cost_model") or "inherit").strip().lower()
        if cost_model not in NODE_COST_MODELS:
            return {}, f"cost_model must be one of {NODE_COST_MODELS}"
        spec: dict[str, Any] = {
            "provider_id": provider_id,
            "name": str(payload["name"]).strip()[:120],
            "public_ip": str(payload["public_ip"]).strip()[:45],
            "public_ipv6": (str(payload.get("public_ipv6") or "").strip() or None),
            "wg_mgmt_ip": str(payload["wg_mgmt_ip"]).strip()[:45],
            "wg_mgmt_pubkey": str(payload["wg_mgmt_pubkey"]).strip(),
            "routeros_api_port": _to_int(payload.get("routeros_api_port")) or 8729,
            "coa_port": _to_int(payload.get("coa_port")) or 3799,
            "max_sessions": _to_int(payload["max_sessions"]),
            "link_speed_mbps": _to_int(payload["link_speed_mbps"]),
            "bandwidth_cap_tb": _to_dec(payload.get("bandwidth_cap_tb")),
            "cost_model": cost_model,
            "price_per_tb": _to_dec(payload.get("price_per_tb")),
            "overage_allowed": _to_bool(payload.get("overage_allowed")),
            "weight": _to_dec(payload.get("weight")) or Decimal("1.0"),
        }
        if spec["max_sessions"] is None or spec["max_sessions"] <= 0:
            return {}, "max_sessions must be a positive integer"
        if spec["link_speed_mbps"] is None or spec["link_speed_mbps"] <= 0:
            return {}, "link_speed_mbps must be a positive integer"
        if cost_model == "metered" and spec["bandwidth_cap_tb"] is None:
            return {}, "metered cost_model requires bandwidth_cap_tb"
    except ValueError as exc:
        return {}, str(exc)
    return spec, None


def _apply_patch(node: FleetChrNode, payload: dict[str, Any]) -> str | None:
    try:
        for field in payload:
            if field not in _PATCHABLE_FIELDS:
                continue
            raw = payload.get(field)
            if field in {"max_sessions", "link_speed_mbps", "routeros_api_port", "coa_port"}:
                value = _to_int(raw)
                if value is None or value <= 0:
                    return f"{field} must be a positive integer"
                setattr(node, field, value)
            elif field in {"bandwidth_cap_tb", "price_per_tb", "weight"}:
                setattr(node, field, _to_dec(raw))
            elif field == "overage_allowed":
                setattr(node, field, _to_bool(raw))
            elif field == "cost_model":
                cm = str(raw or "").strip().lower()
                if cm not in NODE_COST_MODELS:
                    return f"cost_model must be one of {NODE_COST_MODELS}"
                setattr(node, field, cm)
            elif field == "name":
                setattr(node, field, str(raw or "").strip()[:120])
            elif field in {"public_ip", "public_ipv6", "wg_mgmt_ip"}:
                setattr(node, field, (str(raw or "").strip()[:45]) or None)
            elif field == "wg_mgmt_pubkey":
                setattr(node, field, str(raw or "").strip())
    except ValueError as exc:
        return str(exc)
    return None


# ────────────────────────────────────────────────────────────────────────────
# Endpoints
# ────────────────────────────────────────────────────────────────────────────


@bp.get("/chr-nodes")
@login_required
def list_chr_nodes():
    """List nodes. Query: ``?status=up`` ``?provider=<id>`` ``?enabled=1``.

    Defaults to all rows (including drains) so the dashboard can show "needs
    attention" entries; the brain has its own healthy-only filter.
    """
    q = FleetChrNode.query
    status = (request.args.get("status") or "").strip().lower()
    if status:
        if status not in NODE_STATUSES:
            return _err("bad_request", 400, f"status must be one of {NODE_STATUSES}")
        q = q.filter(FleetChrNode.status == status)
    provider_id = request.args.get("provider")
    if provider_id:
        try:
            q = q.filter(FleetChrNode.provider_id == int(provider_id))
        except ValueError:
            return _err("bad_request", 400, "provider must be an integer id")
    enabled_filter = _to_bool(request.args.get("enabled"))
    if enabled_filter is not None:
        q = q.filter(FleetChrNode.enabled.is_(enabled_filter))
    nodes = q.order_by(FleetChrNode.name.asc()).all()
    return jsonify({
        "ok": True,
        "count": len(nodes),
        "items": [_node_to_dict(n) for n in nodes],
    })


@bp.get("/chr-nodes/<int:node_id>")
@login_required
def get_chr_node(node_id: int):
    node = db.session.get(FleetChrNode, node_id)
    if node is None:
        return _err("not_found", 404, f"chr-node {node_id} not found")
    return jsonify({"ok": True, "item": _node_to_dict(node)})


@bp.post("/chr-nodes")
@login_required
def create_chr_node():
    """Create a node row. Called by the onboarding service after key minting
    OR directly by an operator hand-off. ``status`` defaults to ``provisioning``
    so the brain ignores the row until onboarding promotes it to ``up``.

    Idempotency: ``(provider_id, name)`` is unique (see model
    ``uq_fleet_chr_nodes_provider_name``); a duplicate returns ``409 conflict``.
    """
    spec, err = _validate_create_payload(_read_request_body())
    if err:
        return _err("bad_request", 400, err)
    node = FleetChrNode(**spec, status="provisioning", enabled=True, drain=False)
    db.session.add(node)
    try:
        db.session.flush()
    except IntegrityError as exc:
        db.session.rollback()
        return _err("conflict", 409, _shorten_db_error(str(exc.orig)))
    audit(
        "fleet_chr_node_created",
        "fleet_chr_node",
        str(node.id),
        f"تم إنشاء عقدة CHR جديدة {node.name} (المزود #{node.provider_id})",
    )
    db.session.commit()
    return jsonify({"ok": True, "item": _node_to_dict(node)}), 201


@bp.patch("/chr-nodes/<int:node_id>")
@login_required
def patch_chr_node(node_id: int):
    node = db.session.get(FleetChrNode, node_id)
    if node is None:
        return _err("not_found", 404, f"chr-node {node_id} not found")
    err = _apply_patch(node, _read_request_body())
    if err:
        return _err("bad_request", 400, err)
    try:
        db.session.flush()
    except IntegrityError as exc:
        db.session.rollback()
        return _err("conflict", 409, _shorten_db_error(str(exc.orig)))
    audit(
        "fleet_chr_node_updated",
        "fleet_chr_node",
        str(node.id),
        f"تم تحديث عقدة CHR {node.name}",
    )
    db.session.commit()
    return jsonify({"ok": True, "item": _node_to_dict(node)})


@bp.post("/chr-nodes/<int:node_id>/enable")
@login_required
def enable_chr_node(node_id: int):
    """Bring a previously disabled/drained node back into eligibility. Clears
    the drain flag and flips ``status`` back to ``provisioning`` so health
    re-evaluates it from a clean slate (NOT 'up' — the metrics loop owns 'up')."""
    node = db.session.get(FleetChrNode, node_id)
    if node is None:
        return _err("not_found", 404, f"chr-node {node_id} not found")
    node.enabled = True
    node.drain = False
    if node.status == "disabled":
        node.status = "provisioning"
    audit(
        "fleet_chr_node_enabled",
        "fleet_chr_node",
        str(node.id),
        f"تم تفعيل عقدة CHR {node.name}",
    )
    db.session.commit()
    return jsonify({"ok": True, "item": _node_to_dict(node)})


@bp.post("/chr-nodes/<int:node_id>/disable")
@login_required
def disable_chr_node(node_id: int):
    """Drain + disable. The row is KEPT (historical metrics / placement
    decisions resolve), ``enabled=0`` excludes it from the partial status
    index, and ``status='disabled'`` excludes it from the brain. Re-enable
    via the sibling endpoint above."""
    node = db.session.get(FleetChrNode, node_id)
    if node is None:
        return _err("not_found", 404, f"chr-node {node_id} not found")
    node.enabled = False
    node.drain = True
    node.status = "disabled"
    audit(
        "fleet_chr_node_disabled",
        "fleet_chr_node",
        str(node.id),
        f"تم تعطيل (drain) عقدة CHR {node.name}",
    )
    db.session.commit()
    return jsonify({"ok": True, "item": _node_to_dict(node)})


# ────────────────────────────────────────────────────────────────────────────
# Provider helpers — small, read-only; the wizard's "select / new provider"
# dropdown calls these. Creating a provider is one POST so a brand-new CHR can
# be onboarded without leaving the wizard. Updates/deletes live in a future
# providers admin page, not here.
# ────────────────────────────────────────────────────────────────────────────


# NOTE (Phase-3 gate): provider CRUD endpoints used to live here too, but they
# duplicated P3-T6's canonical provider API (fleet.registry.routes_provider,
# blueprint ``admin_fleet_provider``) at the SAME ``/admin/fleet/providers`` URL.
# To avoid a route collision + two divergent response shapes, the integrator
# dropped them here; this blueprint now owns CHR-NODE CRUD only. The wizard's
# "new provider" panel posts to the T6 endpoint, which returns the fuller shape.


def _shorten_db_error(text: str) -> str:
    """Surface only the UNIQUE/CHECK label, not the full driver message —
    keeps the JSON response free of dialect-specific noise."""
    text = (text or "").strip().splitlines()[0][:200]
    return text or "database constraint violated"


__all__ = ["bp"]
