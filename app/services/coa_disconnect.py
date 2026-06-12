"""Panel-side CoA-Disconnect queue — proxy is outbound-only, so we publish.

The proxy has NO inbound HTTP server (enforced by
``test_proxy_not_in_license_path``). It **polls**
``GET /api/proxy/routing-table`` ≤60 seconds and POSTs back telemetry +
heartbeat + this module's NEW result endpoint. So the panel can't push
a CoA-Disconnect over HTTP — it has to publish.

Mechanism
---------
1. Panel enqueues a ``PendingCoaCommand`` row (UUID, realm, action,
   target_node_id, reason, status=``pending``).
2. The next ``GET /api/proxy/routing-table`` response includes a
   top-level ``pending_coa`` array listing every command still alive
   (not done/failed/expired). We mark each included row ``sent`` +
   stamp ``picked_up_at`` lazily on read so the panel UI can show
   «أُرسل» vs «بانتظار الاستلام».
3. Proxy sends RFC 5176 Disconnect-Request UDP 3799 to the CHR.
4. Proxy POSTs ``/api/proxy/coa-result`` with
   ``{id, status: "done"|"failed", coa_code: 41|42, detail}``. Panel
   marks the row, stops publishing it, audits the result against the
   chr-move row.

TTL
---
Commands without a result are considered ``expired`` after
``DEFAULT_TTL_SECONDS`` (5 minutes by default). Expired rows are not
republished — the operator's UI shows «انتهى وقت الانتظار» and the
button re-arms.

Idempotency
-----------
* ``enqueue_coa_disconnect`` returns a new row each call; the proxy may
  re-fetch the same row across multiple polls without side-effects.
* ``apply_coa_result`` dedups by ``command_id``: re-applying a terminal
  state is a no-op + still returns ``ok=True`` so the proxy can retry
  the POST freely.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional

from app.extensions import db
from app.models import PendingCoaCommand


logger = logging.getLogger(__name__)


# ─── Status vocabulary — the chr_move result struct + UI surface this ──
STATUS_PENDING = "pending"
STATUS_SENT = "sent"
STATUS_DONE = "done"
STATUS_FAILED = "failed"
STATUS_EXPIRED = "expired"

#: Statuses the panel still publishes in ``pending_coa``. ``done`` /
#: ``failed`` / ``expired`` are terminal and dropped from the list.
ALIVE_STATUSES: frozenset[str] = frozenset({STATUS_PENDING, STATUS_SENT})

#: How long a command is held in ``pending_coa`` before it expires.
#: The proxy polls ≤60 s so 5 minutes covers ~5 retries comfortably; the
#: number is exposed as a constant so tests can override.
DEFAULT_TTL_SECONDS: int = 300


@dataclass(frozen=True)
class CoaResult:
    """What the move service reports back to the UI after the enqueue.

    For the QUEUE model the result is always optimistic: routing change
    was committed + a command was enqueued. ``status`` is always
    ``"pending"`` here — the final outcome arrives asynchronously via
    ``/api/proxy/coa-result`` and is recorded in the audit log of the
    same customer.
    """

    status: str
    message: str
    command_id: str

    @property
    def ok(self) -> bool:
        return self.status in ALIVE_STATUSES

    @property
    def http_status(self) -> int:
        """Back-compat shim for the chr_move result struct — the queue
        model has no HTTP status; we always return 0."""
        return 0

    @property
    def request_id(self) -> str:
        """Back-compat: chr_move's MoveResult names this field
        ``coa_request_id``; we map it to the command's UUID."""
        return self.command_id

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "message": self.message,
            "command_id": self.command_id,
        }


# ════════════════════════════════════════════════════════════════════════
# Enqueue
# ════════════════════════════════════════════════════════════════════════
def enqueue_coa_disconnect(
    *,
    realm: str,
    target_node_id: Optional[int] = None,
    reason: str = "panel:chr-move",
    customer_id: Optional[int] = None,
    command_id: Optional[str] = None,
) -> CoaResult:
    """Create a new ``PendingCoaCommand`` row, return a CoaResult the
    caller folds into its own response struct.

    ``command_id`` is exposed as an argument so tests can pin a known
    UUID; production callers pass nothing and we mint a fresh one.
    """
    cid = command_id or uuid.uuid4().hex
    row = PendingCoaCommand(
        command_id=cid,
        realm=realm,
        action="disconnect",
        target_node_id=int(target_node_id) if target_node_id is not None else None,
        reason=reason,
        customer_id=int(customer_id) if customer_id is not None else None,
        status=STATUS_PENDING,
    )
    db.session.add(row)
    db.session.commit()
    logger.info(
        "coa_queue: enqueued command_id=%s realm=%s target=%s reason=%s",
        cid, realm, target_node_id, reason,
    )
    return CoaResult(
        status=STATUS_PENDING,
        message=(
            "أُدرج الأمر في قائمة CoA — سيلتقطه الوكيل خلال ≤60 ثانية "
            "ويسقط الجلسات الحيّة. ستتحدّث الحالة تلقائيًا حين يصل التأكيد."
        ),
        command_id=cid,
    )


# ════════════════════════════════════════════════════════════════════════
# Publish — used by GET /api/proxy/routing-table
# ════════════════════════════════════════════════════════════════════════
def alive_commands(*, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> list[PendingCoaCommand]:
    """Every CoA command still alive — pending OR sent, not yet expired.

    Expires commands older than ``ttl_seconds`` lazily on each call:
    a row that has been waiting too long is transitioned to
    ``expired`` so the next routing-table response no longer publishes
    it. We do NOT delete — the audit chain stays intact.
    """
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=ttl_seconds)
    rows = (
        PendingCoaCommand.query
        .filter(PendingCoaCommand.status.in_(ALIVE_STATUSES))
        .order_by(PendingCoaCommand.created_at.asc())
        .all()
    )
    fresh: list[PendingCoaCommand] = []
    expired_any = False
    for r in rows:
        created = r.created_at
        if created is not None and created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        if created is None or created < cutoff:
            r.status = STATUS_EXPIRED
            r.detail = (r.detail or "") + " | TTL elapsed without result"
            db.session.add(r)
            expired_any = True
            continue
        fresh.append(r)
    if expired_any:
        db.session.commit()
    return fresh


def serialize_for_routing_table(
    rows: Iterable[PendingCoaCommand], *, mark_sent: bool = True,
) -> list[dict]:
    """Encode the alive rows for inclusion in the routing-table response.

    Side-effect when ``mark_sent`` is True: every row still in
    ``pending`` is transitioned to ``sent`` with a fresh
    ``picked_up_at`` stamp. The status is what lets the panel UI
    distinguish «بانتظار الاستلام» from «أُرسل، بانتظار التنفيذ».
    """
    now = datetime.now(timezone.utc)
    out: list[dict] = []
    dirty = False
    for r in rows:
        out.append({
            "id": r.command_id,
            "realm": r.realm,
            "action": r.action,
            "target_node_id": r.target_node_id,
            "reason": r.reason,
        })
        if mark_sent and r.status == STATUS_PENDING:
            r.status = STATUS_SENT
            r.picked_up_at = now
            db.session.add(r)
            dirty = True
    if dirty:
        db.session.commit()
    return out


# ════════════════════════════════════════════════════════════════════════
# Apply result — used by POST /api/proxy/coa-result
# ════════════════════════════════════════════════════════════════════════
@dataclass(frozen=True)
class ApplyResult:
    """Outcome of applying a proxy-reported result. ``found`` is False
    when the id is unknown (we still 200 the proxy — silent-ack-unknown
    is more forgiving than 404 in a polling loop)."""

    found: bool
    already_terminal: bool
    new_status: str
    command_id: str


def apply_coa_result(
    *,
    command_id: str,
    status: str,
    detail: str = "",
    coa_code: Optional[int] = None,
) -> ApplyResult:
    """Mark the command done/failed; idempotent on a row already in a
    terminal state (the proxy retries are not punished)."""
    if status not in (STATUS_DONE, STATUS_FAILED):
        raise ValueError(
            f"apply_coa_result: status must be 'done' or 'failed', got {status!r}",
        )
    row = PendingCoaCommand.query.filter_by(command_id=command_id).first()
    if row is None:
        return ApplyResult(False, False, status, command_id)

    already_terminal = row.status in (STATUS_DONE, STATUS_FAILED, STATUS_EXPIRED)
    if not already_terminal:
        row.status = status
        row.completed_at = datetime.now(timezone.utc)
        if detail:
            row.detail = (row.detail + " | " + detail).strip(" |") if row.detail else detail
        if coa_code is not None:
            try:
                row.coa_code = int(coa_code)
            except (TypeError, ValueError):
                pass
        db.session.add(row)
        db.session.commit()
        _audit_result(row)
    return ApplyResult(True, already_terminal, row.status, command_id)


def _audit_result(row: PendingCoaCommand) -> None:
    """Audit the result against the customer (when the row carries one)
    so the operator's customer detail page audit-log shows the lifecycle
    end-to-end: chr_move_executed → chr_move_coa_result."""
    try:
        from app.auth.routes import audit
        audit(
            "chr_move_coa_result",
            "customer",
            str(row.customer_id) if row.customer_id else "",
            (
                f"نتيجة CoA للأمر {row.command_id}: {row.status}"
                + (f" (RFC 5176 code {row.coa_code})" if row.coa_code else "")
                + (f" — {row.detail}" if row.detail else "")
            ),
            {
                "command_id": row.command_id,
                "realm": row.realm,
                "target_node_id": row.target_node_id,
                "coa_status": row.status,
                "coa_code": row.coa_code,
                "detail": row.detail,
            },
        )
        db.session.commit()
    except Exception:  # noqa: BLE001 — never fail the proxy POST on audit
        logger.exception("coa_queue: audit write failed for command_id=%s", row.command_id)


__all__ = [
    "STATUS_PENDING",
    "STATUS_SENT",
    "STATUS_DONE",
    "STATUS_FAILED",
    "STATUS_EXPIRED",
    "ALIVE_STATUSES",
    "DEFAULT_TTL_SECONDS",
    "CoaResult",
    "ApplyResult",
    "enqueue_coa_disconnect",
    "alive_commands",
    "serialize_for_routing_table",
    "apply_coa_result",
]
