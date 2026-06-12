"""«نقل الـCHR / تغيير الـIP العام» — service layer.

Re-home a customer's RADIUS realm + its live sessions from one CHR to
another so the customer's egress public IP changes — without
provisioning multiple public IPs on a single CHR.

The service is the single place the move logic lives. The admin route
+ the customer detail UI are thin shells over this function. The
behaviour is fully specified in ``docs/CHR_MOVE_DESIGN.md``.

What the move does (in order, inside ONE transaction except the CoA
emit which is best-effort + post-commit):

  1. Resolve the customer's ``CustomerRadiusInstance`` (the realm).
     Refuse if missing — the customer has no realm to move.
  2. Resolve the target ``FleetChrNode`` and run eligibility checks:
       * must exist
       * must be in ``available_nodes()`` (enabled + not drain + status
         not "disabled")
       * must have at least one ``vpn_*`` role enabled — a pure
         ``radius_transport``-only node has no VPN server to terminate
         the reconnect, so the move would silently kill traffic.
     Each refusal returns a precise Arabic message.
  3. Read the CURRENT allowed-node set for every ``ProxyRealmRoute``
     owned by the customer's instance — used for the old→new IP report.
  4. If the only currently-allowed node is the target, the move is a
     no-op: nothing to write, but the CoA-Disconnect still emits (so
     the operator can force-reconnect on the same node from the same
     button — useful for «خلّيه يعيد الاتصال»).
  5. Otherwise, write ``allowed_fleet_chr_node_ids = [target.id]`` on
     every route; refresh the instance's ``last_published_fingerprint``
     so the proxy's routing-table reconciler picks up the change on
     its next poll.
  6. Commit the transaction.
  7. Emit the CoA-Disconnect best-effort (the result is reported back
     but does not roll the routing change back — see §5 of the design).
  8. Audit. Return ``MoveResult``.

Notes
-----
* Owner-triggered only — the caller is responsible for enforcing
  ``@super_admin_required``. We accept an ``actor`` string only to
  thread it through the audit row; we don't authenticate.
* Idempotent: re-running with the same ``target_node`` after a
  successful move is a no-op (routes already point at it). Re-running
  after a failed CoA re-issues the CoA only.
* CoA failure is NOT a move failure. The result struct reports both
  outcomes; the UI surfaces them separately.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Iterable, Optional

from app.extensions import db
from app.models import (
    Customer,
    CustomerRadiusInstance,
    ProxyRealmRoute,
)


logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════════
# Error class — surfaces an Arabic message verbatim to the UI
# ════════════════════════════════════════════════════════════════════════
class ChrMoveError(ValueError):
    """Pre-flight refusal. The Arabic message is the UI message — the
    caller flashes it as-is."""


# ════════════════════════════════════════════════════════════════════════
# Result struct
# ════════════════════════════════════════════════════════════════════════
@dataclass(frozen=True)
class MoveResult:
    """One row of post-move state the UI shows to the operator.

    ``coa`` carries the disconnect outcome (one of the ``STATUS_*``
    strings in ``app.services.coa_disconnect``). ``coa_message`` is the
    Arabic line the toast surfaces verbatim.
    """

    customer_id: int
    target_node_id: int
    target_node_name: str
    target_public_ip: str
    # IPs the customer was egressing through BEFORE the move. Sorted +
    # de-duplicated. May be empty when no route had any allowed node yet
    # (first time the operator pins the customer to a CHR).
    old_public_ips: tuple[str, ...]
    # True when the routing change actually wrote something; False when
    # every route already had ``[target.id]`` — no-op.
    routing_changed: bool
    # CoA emission outcome.
    coa_status: str
    coa_http_status: int
    coa_message: str
    coa_request_id: str
    realm: str

    def as_dict(self) -> dict:
        return {
            "customer_id": self.customer_id,
            "target_node_id": self.target_node_id,
            "target_node_name": self.target_node_name,
            "target_public_ip": self.target_public_ip,
            "old_public_ips": list(self.old_public_ips),
            "routing_changed": self.routing_changed,
            "coa_status": self.coa_status,
            "coa_http_status": self.coa_http_status,
            "coa_message": self.coa_message,
            "coa_request_id": self.coa_request_id,
            "realm": self.realm,
        }


# ════════════════════════════════════════════════════════════════════════
# Eligibility — the brain of the refusal layer
# ════════════════════════════════════════════════════════════════════════
def eligible_targets() -> list:
    """Every CHR the operator can move a customer to right now.

    Filter:
      (a) ``fleet_node_router.available_nodes()`` — enabled + not drain
          + status not disabled (the same filter the routing-table uses);
      (b) at least one ``vpn_*`` role enabled — a pure
          ``radius_transport``-only node can't terminate VPN traffic.

    Returns the list of ``FleetChrNode`` rows ready for the UI's
    target dropdown. Sorted by name (the ``available_nodes`` order).
    """
    from app.services import fleet_node_router, node_roles

    nodes = fleet_node_router.available_nodes()
    out = []
    for node in nodes:
        roles = node_roles.enabled_roles(node)
        if any(r.startswith("vpn_") for r in roles):
            out.append(node)
    return out


def _check_target_eligible(target_node) -> None:
    """Run the same eligibility gates as ``eligible_targets`` but raise
    a precise Arabic ``ChrMoveError`` per failure mode so the UI can
    surface the exact reason."""
    from app.services import node_roles

    if target_node is None:
        raise ChrMoveError("العقدة الهدف غير موجودة.")
    if not getattr(target_node, "enabled", False):
        raise ChrMoveError(
            f"العقدة «{target_node.name}» معطَّلة — فعِّلها من «بنية الأسطول» "
            "قبل النقل."
        )
    if getattr(target_node, "drain", False):
        raise ChrMoveError(
            f"العقدة «{target_node.name}» في وضع التصريف (drain) — لا "
            "تقبل اتصالات جديدة."
        )
    status = (getattr(target_node, "status", "") or "").lower()
    if status == "disabled":
        raise ChrMoveError(f"العقدة «{target_node.name}» في حالة «disabled».")
    if status == "down":
        raise ChrMoveError(
            f"العقدة «{target_node.name}» غير قابلة للوصول حاليًا (down) — "
            "انتظر استعادتها أو اختر عقدة أخرى."
        )
    roles = node_roles.enabled_roles(target_node)
    if not any(r.startswith("vpn_") for r in roles):
        raise ChrMoveError(
            f"العقدة «{target_node.name}» لا تشغّل أي دور VPN — لا يمكن "
            "أن تنهي اتصالات العميل عليها."
        )


# ════════════════════════════════════════════════════════════════════════
# Old-IP read — used by both the UI preflight + the result struct
# ════════════════════════════════════════════════════════════════════════
def current_public_ips_for_customer(customer: Customer) -> list[str]:
    """The set of public IPs the customer's traffic egresses through
    right now. Walks every ``ProxyRealmRoute`` for the customer →
    collects every ``allowed_fleet_chr_node_ids`` → reads each node's
    ``public_ip``. Empty list when the customer has no instance yet OR
    every route's allowed-set is empty.
    """
    from fleet.registry.models_chr import FleetChrNode

    if customer is None or customer.id is None:
        return []
    routes = ProxyRealmRoute.query.filter_by(customer_id=customer.id).all()
    node_ids: set[int] = set()
    for r in routes:
        for nid in r.allowed_fleet_chr_node_ids or []:
            try:
                node_ids.add(int(nid))
            except (TypeError, ValueError):
                continue
    if not node_ids:
        return []
    nodes = (
        FleetChrNode.query
        .filter(FleetChrNode.id.in_(node_ids))
        .all()
    )
    ips = sorted({(n.public_ip or "").strip() for n in nodes if n.public_ip})
    return ips


# ════════════════════════════════════════════════════════════════════════
# The move
# ════════════════════════════════════════════════════════════════════════
def move_customer_to_chr(
    customer: Customer,
    target_node,
    *,
    actor: str = "",
    coa_emitter=None,
) -> MoveResult:
    """Re-home ``customer`` to ``target_node``. See module docstring.

    ``coa_emitter`` is a test seam — production callers pass nothing
    and the canonical ``emit_coa_disconnect`` from
    ``app.services.coa_disconnect`` is used. Tests inject a callable
    matching the same signature.

    Always returns a ``MoveResult`` on success; raises ``ChrMoveError``
    on a refusal (missing instance / ineligible target). Database
    errors propagate (Flask error handler converts to 500).
    """
    if customer is None:
        raise ChrMoveError("العميل غير محدَّد.")
    instance: CustomerRadiusInstance | None = customer.radius_instance
    if instance is None:
        raise ChrMoveError(
            "لا يوجد realm RADIUS لهذا العميل بعد — أنشئ نسخة RADIUS "
            "للعميل قبل تنفيذ النقل."
        )
    _check_target_eligible(target_node)

    # Compute old IPs BEFORE writing — the result struct surfaces them
    # to the UI for the «كان X.X → صار Y.Y» line.
    old_ips = tuple(current_public_ips_for_customer(customer))

    # Pull every realm route owned by this customer's instance.
    routes: list[ProxyRealmRoute] = (
        ProxyRealmRoute.query
        .filter_by(customer_id=customer.id, radius_instance_id=instance.id)
        .all()
    )

    target_id = int(target_node.id)
    routing_changed = False
    for r in routes:
        current = sorted(int(x) for x in (r.allowed_fleet_chr_node_ids or []))
        desired = [target_id]
        if current != desired:
            r.allowed_fleet_chr_node_ids = desired
            db.session.add(r)
            routing_changed = True

    if routing_changed:
        # Refresh the instance's fingerprint so the proxy's reconciler
        # notices the change on its next poll. We don't actually
        # recompute the fingerprint here — we just clear the
        # "last_reported" so the badge flips to «بانتظار التقارب» until
        # the proxy reports a fresh value back.
        try:
            instance.last_reported_fingerprint = ""
            instance.drift_cycles = 0
            db.session.add(instance)
        except Exception:  # noqa: BLE001 — older instances may lack the columns
            pass

    db.session.commit()

    # Emit CoA-Disconnect best-effort POST-commit. We do this AFTER the
    # commit so a CoA failure doesn't lose the routing change.
    if coa_emitter is None:
        from app.services.coa_disconnect import emit_coa_disconnect
        coa_emitter = emit_coa_disconnect
    coa = coa_emitter(
        realm=instance.realm,
        target_node_id=target_id,
        reason="panel:chr-move",
    )

    # Audit. ``audit`` is the canonical helper used by every admin
    # mutation in the panel (see app/auth/routes.audit).
    try:
        from app.auth.routes import audit
        audit(
            "chr_move_executed",
            "customer",
            str(customer.id),
            (
                f"نقل العميل «{customer.company_name}» إلى العقدة "
                f"«{target_node.name}» — IP العام: "
                f"{', '.join(old_ips) or '—'} ← {target_node.public_ip} "
                f"(CoA: {coa.status})"
            ),
            {
                "from_node_ids": sorted(
                    {int(x) for r in routes for x in (r.allowed_fleet_chr_node_ids or [])
                     if str(x).lstrip("-").isdigit()}
                ),
                "to_node_id": target_id,
                "to_public_ip": target_node.public_ip,
                "from_public_ips": list(old_ips),
                "routing_changed": routing_changed,
                "coa_status": coa.status,
                "coa_http_status": coa.http_status,
                "coa_request_id": coa.request_id,
                "actor": actor or "",
            },
        )
        db.session.commit()
    except Exception:  # noqa: BLE001 — never fail the move on audit
        logger.exception("chr_move: audit write failed (move itself OK)")

    return MoveResult(
        customer_id=int(customer.id),
        target_node_id=target_id,
        target_node_name=target_node.name,
        target_public_ip=target_node.public_ip or "",
        old_public_ips=old_ips,
        routing_changed=routing_changed,
        coa_status=coa.status,
        coa_http_status=coa.http_status,
        coa_message=coa.message,
        coa_request_id=coa.request_id,
        realm=instance.realm,
    )


__all__ = [
    "ChrMoveError",
    "MoveResult",
    "eligible_targets",
    "current_public_ips_for_customer",
    "move_customer_to_chr",
]
