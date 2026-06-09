"""fleet.ui.dns_reconciler_view — preview + reconcile_now seam for the UI.

Phase-6 task C deliverable. The UI calls this module's two functions
(``preview``, ``reconcile_now``); they delegate to the real reconciler
(Phase-6 task B) when its branch is importable and fall back to a local
computation otherwise — so the front-door page works end-to-end on every
branch in the parallel build matrix.

CONTRACT consumed
-----------------
We expect the real reconciler module to expose **either** of:

    fleet.dns.reconciler.preview() -> dict | object
    fleet.dns.reconciler.reconcile_now() -> dict | object

Each return value MAY look like::

    {
        "fqdn": "vpn.hoberadius.com",
        "mode": "free" | "paid",
        "intended": {
            "A": [
                {"node_id": int, "name": str, "ip": str, "weight": float},
                ...
            ],
            "AAAA": [...],
        },
        "current": {
            "A": ["1.2.3.4", "1.2.3.5"],
            "AAAA": [],
            "ttl": int,
            "last_change_reason": str | None,
        },
        "would_change": bool,
        "applied": bool,                    # only set by reconcile_now
        "reason": str | None,
    }

We accept ANY mapping with that shape (and dataclasses by reading attributes
through ``getattr``), so a future tweak by the reconciler agent won't break
this view.

Fallback behaviour
------------------
When the reconciler isn't importable yet, we compute the *intended* set
ourselves so the operator sees a meaningful "معاينة" even before the real
reconciler ships:

* Read the healthy ``up`` nodes from the registry (excluding ``drain`` and
  ``disabled``).
* Sort by ``score`` desc (denormalised on chr_nodes by the brain) then name.
* Cap at ``fleet.config.DnsConfig.top_n_cap`` (default 8).
* Weights: for the free/paid mode banner we surface a uniform ``1.0`` — the
  real reconciler picks per-mode weights; this is just an explainable
  placeholder so the column is never blank.

``reconcile_now()`` in the fallback path will NOT call out to Cloudflare
(there's no driver). It only updates the local ``fleet_dns_records_state``
snapshot to reflect "what we would have published" — explicitly flagged as
``applied=False, reason="fallback: no driver available"`` so the operator
can't mistake a local snapshot for a real DNS write.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from app.extensions import db
from fleet.config import FLEET
from fleet.dns.models_dns import DnsRecordState
from fleet.dns.settings_store import (
    FRONTDOOR_FQDN,
    MODE_FREE,
    MODE_PAID,
    load_view,
    token_is_set,
)
from fleet.registry.models_chr import FleetChrNode


# ────────────────────────────────────────────────────────────────────────────
# Soft-import the real reconciler. ANY ImportError or AttributeError silently
# leaves the seam open for the fallback path.
# ────────────────────────────────────────────────────────────────────────────
try:  # pragma: no cover - import probe
    from fleet.dns import reconciler as _real_reconciler  # type: ignore[attr-defined]
except Exception:  # noqa: BLE001
    _real_reconciler = None  # type: ignore[assignment]


def reconciler_available() -> bool:
    """For the UI banner — did the real reconciler import?"""
    return _real_reconciler is not None and (
        hasattr(_real_reconciler, "preview") or hasattr(_real_reconciler, "reconcile_now")
    )


# ────────────────────────────────────────────────────────────────────────────
# Public surface
# ────────────────────────────────────────────────────────────────────────────


def preview() -> dict[str, Any]:
    """Dry-run: return the would-be DNS state without touching the provider."""
    real = _call_real("preview")
    if real is not None:
        return _annotate_source(real, "reconciler")
    return _annotate_source(_fallback_preview(apply=False), "fallback")


def reconcile_now() -> dict[str, Any]:
    """Apply: ask the reconciler to publish if the set differs from
    ``fleet_dns_records_state``. In the fallback path we only refresh the
    state snapshot — see module docstring for why."""
    real = _call_real("reconcile_now")
    if real is not None:
        return _annotate_source(real, "reconciler")
    return _annotate_source(_fallback_preview(apply=True), "fallback")


# ────────────────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────────────────


def _call_real(method_name: str) -> dict[str, Any] | None:
    if _real_reconciler is None:
        return None
    fn = getattr(_real_reconciler, method_name, None)
    if fn is None:
        return None
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001 - never blow up the dashboard
        return {
            "ok": False,
            "error": "reconciler raised: " + str(exc)[:160],
            "fqdn": FRONTDOOR_FQDN,
        }
    return _coerce(result)


def _coerce(result: Any) -> dict[str, Any]:
    """Accept dicts or dataclasses; return a plain dict (no ORM rows)."""
    if isinstance(result, dict):
        return result
    # Best-effort attribute snapshot.
    keys = ("fqdn", "mode", "intended", "current", "would_change", "applied", "reason")
    return {k: getattr(result, k, None) for k in keys}


def _annotate_source(result: dict[str, Any], source: str) -> dict[str, Any]:
    """Stamp the source label so the UI banner can be honest about provenance."""
    out = dict(result)
    out.setdefault("source", source)
    out.setdefault("fqdn", FRONTDOOR_FQDN)
    return out


def _fallback_preview(*, apply: bool) -> dict[str, Any]:
    """Compute would-be A-set from the registry; never calls Cloudflare."""
    view = load_view()
    mode = view["mode"]
    cap = FLEET.dns.top_n_cap
    ttl = FLEET.dns.ttl
    min_healthy = FLEET.dns.min_healthy

    # "Healthy" in the fallback: status='up' (denormalised by the brain),
    # enabled=true, not drain. This matches the contract's healthy_nodes()
    # description in docs/contracts/fleet_api.md §4.2.
    candidates = (
        FleetChrNode.query
        .filter(FleetChrNode.status == "up")
        .filter(FleetChrNode.enabled.is_(True))
        .filter(FleetChrNode.drain.is_(False))
        .order_by(FleetChrNode.score.desc().nulls_last(), FleetChrNode.name.asc())
        .limit(cap)
        .all()
    )

    intended_a: list[dict[str, Any]] = []
    intended_aaaa: list[dict[str, Any]] = []
    for node in candidates:
        weight = _fallback_weight(node, mode=mode)
        intended_a.append({
            "node_id": node.id,
            "name": node.name,
            "ip": node.public_ip,
            "weight": weight,
        })
        if node.public_ipv6:
            intended_aaaa.append({
                "node_id": node.id,
                "name": node.name,
                "ip": node.public_ipv6,
                "weight": weight,
            })

    # Read the last-published snapshot (no provider call).
    current_a_row = DnsRecordState.get(FRONTDOOR_FQDN, "A")
    current_aaaa_row = DnsRecordState.get(FRONTDOOR_FQDN, "AAAA")

    intended_a_ips = sorted({c["ip"] for c in intended_a})
    intended_aaaa_ips = sorted({c["ip"] for c in intended_aaaa})

    current_a_ips = current_a_row.published_ips if current_a_row else []
    current_aaaa_ips = current_aaaa_row.published_ips if current_aaaa_row else []

    would_change = (intended_a_ips != current_a_ips) or (intended_aaaa_ips != current_aaaa_ips)
    min_healthy_ok = len(intended_a) >= min_healthy

    # In the fallback we never write to Cloudflare. We MAY persist the
    # snapshot row so the rest of the dashboard reflects the intended state
    # — but only when the operator clicks "تطبيق" AND we have ≥ min_healthy
    # nodes (per the empty-set guard in 03_FRONT_DOOR_DNS §3.6).
    applied = False
    reason: str | None = None
    if apply:
        if not min_healthy_ok:
            reason = (
                f"عدد العقد الصحيحة ({len(intended_a)}) أقل من الحد الأدنى "
                f"({min_healthy}). لم يتم تحديث الحالة."
            )
        elif not view["token_present"]:
            reason = (
                "لم يُضبط توكن Cloudflare بعد — حُدِّثت لقطة الحالة محلياً فقط، "
                "ولن يُكتب أي سجل على Cloudflare."
            )
            _persist_snapshot(intended_a_ips, intended_aaaa_ips, ttl,
                              reason="fallback_local_snapshot_no_token")
            applied = False  # still NOT a real publish
        else:
            reason = (
                "ميزة النشر الفعلي لم تُربط بعد (مستوى المؤقت)؛ حُدِّثت لقطة "
                "الحالة محلياً فقط."
            )
            _persist_snapshot(intended_a_ips, intended_aaaa_ips, ttl,
                              reason="fallback_local_snapshot_pending_driver")
            applied = False

    return {
        "fqdn": FRONTDOOR_FQDN,
        "mode": mode,
        "intended": {"A": intended_a, "AAAA": intended_aaaa},
        "current": {
            "A": current_a_ips,
            "AAAA": current_aaaa_ips,
            "ttl": (current_a_row.ttl if current_a_row else None) or ttl,
            "last_change_reason": (
                current_a_row.last_change_reason if current_a_row else None
            ),
        },
        "would_change": would_change,
        "min_healthy": min_healthy,
        "min_healthy_ok": min_healthy_ok,
        "applied": applied,
        "reason": reason,
        "ok": True,
        "checked_at": datetime.utcnow().isoformat() + "Z",
        "token_present": view["token_present"],
        # The label is intentionally Arabic — the UI surfaces this directly.
        "mode_label_ar": view["mode_label_ar"],
    }


def _fallback_weight(node: FleetChrNode, *, mode: str) -> float:
    """Best-effort placeholder weight.

    * Free mode: weight∝score (so the operator sees the ordering they'd get
      from the brain). Defaults to 1.0 when score isn't set yet.
    * Paid mode: 1.0 across the board — Cloudflare Load Balancer does the
      weighting on its side; the panel doesn't preempt that.
    """
    if mode == MODE_PAID:
        return 1.0
    if node.score is None:
        return 1.0
    return round(float(node.score), 2)


def _persist_snapshot(
    a_ips: list[str],
    aaaa_ips: list[str],
    ttl: int,
    *,
    reason: str,
) -> None:
    """Update the local ``fleet_dns_records_state`` snapshot. Never reaches
    Cloudflare. Honours the §3.6 empty-set guard by NOT writing an empty
    set — callers must check ``min_healthy_ok`` before invoking this."""
    if a_ips:
        DnsRecordState.upsert(FRONTDOOR_FQDN, "A", a_ips, ttl, reason=reason)
    if aaaa_ips:
        DnsRecordState.upsert(FRONTDOOR_FQDN, "AAAA", aaaa_ips, ttl, reason=reason)
    db.session.commit()


__all__ = [
    "preview",
    "reconcile_now",
    "reconciler_available",
]
