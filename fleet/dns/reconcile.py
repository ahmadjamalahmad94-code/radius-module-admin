"""fleet.dns.reconcile — health-aware DNS reconciler for the front door.

Sits between the brain (``fleet.brain.rank``) + monitor
(``fleet.health.monitor.state_of``) and the DNS driver
(``fleet.dns.driver_adapter.apply_desired_state``). One job:

    Compute what the front door (``vpn.hoberadius.com``) SHOULD answer
    right now, then ask the driver to apply it — but only if the desired
    set actually differs from what we last published.

Why this module exists separately from the driver
-------------------------------------------------
Two reasons. First, the policy questions ("is this node healthy enough?
how do we turn a brain score into an integer weight? when do we suppress a
re-apply?") are independent of the provider API choice — Cloudflare,
PowerDNS, and Route53 share this logic verbatim. Second, this lets the
P6 task A and task B agents build in parallel: task A owns the provider
wire bindings, task B (this file) owns the policy.

What we do per ``reconcile_now()`` / ``preview()`` call
-------------------------------------------------------
1. **Rank** — ``fleet.brain.rank()`` returns ``NodeScore`` rows for all
   eligible nodes, best-first. Ineligible nodes are NOT returned (the
   brain already filters them).
2. **Health gate** — for each returned node, double-check
   ``fleet.health.monitor.state_of(name)``. We only publish nodes in
   ``up`` or ``degraded`` state. ``down`` / ``unknown`` / missing → skip.
3. **IP resolution** — read ``public_ip`` from ``fleet_chr_nodes``;
   nodes with no public IP are skipped.
4. **Weight normalisation** — turn brain scores into integer weights in
   ``[weight_min, weight_max]`` (default ``1..100``). Linear mapping over
   the live score range; if all scores tie, every node gets the median
   weight.
5. **top-N cap** — clip to ``cfg.dns.top_n_cap``.
6. **min-healthy guard** — if the publishable set is empty AND the
   currently-published set is non-empty, we DO NOT publish empty (don't
   black-hole the front door). The current set is left in place; the
   reconciler returns the diff that was suppressed.
7. **Flap guard** — read ``fleet_dns_records_state`` for the FQDN/A
   record. If the desired IP set equals the published IP set AND we re-
   applied within ``min_reapply_interval`` seconds, return ``no_change``
   without touching the driver.
8. **Apply** — call ``apply_desired_state`` with the per-call mode +
   dry_run choice.
9. **Persist** — on success, upsert ``fleet_dns_records_state`` so the
   next diff sees the new set; record an ``fleet_events`` row keyed by
   ``kind='dns_update'`` (or ``'dns_no_change'`` / ``'dns_suppressed'``)
   with the full reason snapshot.

Pure / testable
---------------
The compute side (``compute_desired``, the weight function) does NOT touch
the DB beyond reading the brain + health + node table; it returns a value
object. ``preview()`` exposes that without applying. ``reconcile_now()``
adds the apply + persist + audit. No live scheduler is wired up; the task
brief says cron-it-later.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from typing import Any, Callable

from app.extensions import db
from app.models import utcnow
from fleet.brain import rank
from fleet.brain.scoring import NodeScore
from fleet.config import FLEET, FleetConfig
from fleet.dns.driver_adapter import (
    DRIVER_BACKEND,
    DRIVER_MODES,
    ApplyResult,
    NodeRecord,
    apply_desired_state,
)
from fleet.dns.models_dns import DnsRecordState
from fleet.health.monitor import state_of as _health_state_of
from fleet.notify.models_alert import Event
from fleet.registry.models_chr import FleetChrNode


logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Per-call config — separate from the global FleetConfig so the task brief's
# "mode=<from settings>" call site can drop them in without editing the shared
# dataclass.
# ─────────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class ReconcileConfig:
    """Knobs the reconciler reads. All have safe defaults; callers override
    per call when they have stronger signal (Settings UI, env vars)."""

    fqdn: str = "vpn.hoberadius.com"
    record_type: str = "A"
    mode: str = "free"  # Phase-6 gate: driver vocabulary "free" | "paid"
    dry_run: bool = False
    min_reapply_interval_seconds: int = 30
    weight_min: int = 1
    weight_max: int = 100
    #: States ``state_of()`` may return that count as eligible for publication.
    #: ``up`` and ``degraded`` make it; ``down``/``unknown``/``None`` do not.
    healthy_states: tuple[str, ...] = ("up", "degraded")

    def __post_init__(self) -> None:
        if self.mode not in DRIVER_MODES:
            raise ValueError(f"mode must be one of {DRIVER_MODES}, got {self.mode!r}")
        if self.record_type not in ("A", "AAAA"):
            raise ValueError(f"record_type must be A or AAAA, got {self.record_type!r}")
        if self.weight_min < 1 or self.weight_max < self.weight_min:
            raise ValueError(
                f"weight bounds invalid: [{self.weight_min}, {self.weight_max}]"
            )
        if self.min_reapply_interval_seconds < 0:
            raise ValueError("min_reapply_interval_seconds must be >= 0")


# ─────────────────────────────────────────────────────────────────────────────
# Result envelopes
# ─────────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class DesiredState:
    """What we WANT the front door to answer right now.

    ``records`` carries every node the reconciler considered — included
    ones first, excluded ones with ``included=False`` and a reason in
    ``excluded_reasons[node]``. The driver only publishes ``included=True``
    rows; the excluded ones ride along so the audit row can show *why*
    a node didn't make it.
    """

    fqdn: str
    record_type: str
    records: list[NodeRecord]
    excluded_reasons: dict[str, str] = field(default_factory=dict)

    @property
    def publishable(self) -> list[NodeRecord]:
        return [r for r in self.records if r.included]

    @property
    def publish_ips(self) -> list[str]:
        return sorted({r.ip for r in self.publishable})


@dataclass(frozen=True)
class ReconcileResult:
    """What reconcile_now() did. ``preview()`` returns the same envelope
    but with ``applied=False`` and ``apply=None``."""

    desired: DesiredState
    apply: ApplyResult | None
    applied: bool
    changed: bool
    suppressed: bool
    reason: str
    previous_ips: list[str]


# ─────────────────────────────────────────────────────────────────────────────
# Weight normalisation
# ─────────────────────────────────────────────────────────────────────────────
def normalize_weights(
    scores: list[float],
    *,
    weight_min: int = 1,
    weight_max: int = 100,
) -> list[int]:
    """Linearly map a list of brain scores onto ``[weight_min, weight_max]``.

    Two edge cases the linear map alone doesn't handle:

    * **All equal** — including the empty list and the single-score list.
      Returns the median weight for every entry. Median is preferred over
      ``weight_max`` because a degenerate "1 node, 1 weight" answer should
      not look like "this is a perfect choice"; it's the only choice.
    * **Negative scores** — the brain MAY return negative numbers for
      heavily-penalised nodes. We shift the range up so the worst becomes
      ``weight_min`` rather than 0 (which the driver would treat as "do
      not include" for some providers).

    The mapping is monotone in the input — better score ⇒ ≥ weight — so
    the order of brain rank survives normalisation.
    """
    if not scores:
        return []
    if weight_min < 1:
        raise ValueError("weight_min must be >= 1")
    if weight_max < weight_min:
        raise ValueError("weight_max must be >= weight_min")

    lo, hi = min(scores), max(scores)
    if hi <= lo:
        median = (weight_min + weight_max) // 2
        return [median] * len(scores)

    span = hi - lo
    out: list[int] = []
    for s in scores:
        ratio = (s - lo) / span                    # 0..1, top score = 1
        raw = weight_min + ratio * (weight_max - weight_min)
        out.append(max(weight_min, min(weight_max, round(raw))))
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Compute step
# ─────────────────────────────────────────────────────────────────────────────
def _node_by_name(name: str) -> FleetChrNode | None:
    return FleetChrNode.query.filter_by(name=name).first()


def _node_ip(node: FleetChrNode, record_type: str) -> str | None:
    """Return the IP the front door should answer with for this node + record type."""
    if record_type == "A":
        ip = node.public_ip
    elif record_type == "AAAA":
        ip = node.public_ipv6
    else:  # pragma: no cover - guarded by ReconcileConfig
        return None
    if not ip:
        return None
    return str(ip).strip() or None


def compute_desired(
    *,
    cfg: ReconcileConfig | None = None,
    fleet_cfg: FleetConfig | None = None,
    rank_fn: Callable[[], list[NodeScore]] | None = None,
    state_of: Callable[[str], str | None] | None = None,
) -> DesiredState:
    """Build the desired-state envelope for the front door.

    ``rank_fn`` and ``state_of`` are injectable so tests can drive
    deterministic scenarios without seeding the entire brain + monitor
    chain. Production callers leave them as ``None`` (the module-level
    ``fleet.brain.rank`` / ``fleet.health.monitor.state_of`` are used).
    """
    cfg = cfg or ReconcileConfig()
    fcfg = fleet_cfg or FLEET
    rank_call: Callable[[], list[NodeScore]] = rank_fn or (lambda: rank())
    state_fn: Callable[[str], str | None] = state_of or _health_state_of

    ranking = rank_call()
    excluded_reasons: dict[str, str] = {}

    # Pre-filter: brain returns only eligible nodes, but it doesn't know
    # the monitor's authoritative hysteresis state — re-check here.
    candidates: list[tuple[NodeScore, FleetChrNode, str]] = []
    for ns in ranking:
        node = _node_by_name(ns.name)
        if node is None:
            excluded_reasons[ns.name] = "no_node_row"
            continue
        if not node.enabled:
            excluded_reasons[ns.name] = "disabled"
            continue
        if node.drain:
            excluded_reasons[ns.name] = "draining"
            continue
        ip = _node_ip(node, cfg.record_type)
        if ip is None:
            excluded_reasons[ns.name] = f"no_{cfg.record_type.lower()}_address"
            continue
        h = state_fn(ns.name)
        if h not in cfg.healthy_states:
            excluded_reasons[ns.name] = f"health_{h or 'none'}"
            continue
        candidates.append((ns, node, ip))

    # top-N cap (DnsConfig.top_n_cap is the fleet-wide knob; cfg may shrink it).
    cap = max(1, int(fcfg.dns.top_n_cap))
    candidates = candidates[:cap]

    # Weight normalisation runs over the candidates that survived the
    # health/IP gates — that way the lowest score among the eligible set
    # still gets ``weight_min`` (not 0).
    scores = [float(ns.score) for ns, _node, _ip in candidates]
    weights = normalize_weights(
        scores, weight_min=cfg.weight_min, weight_max=cfg.weight_max,
    )
    records: list[NodeRecord] = []
    for (ns, _node, ip), w in zip(candidates, weights, strict=True):
        records.append(NodeRecord(node=ns.name, ip=ip, weight=int(w), included=True))

    # Trailing audit entries for the excluded set.
    for name, reason in excluded_reasons.items():
        records.append(NodeRecord(node=name, ip="", weight=0, included=False))

    return DesiredState(
        fqdn=cfg.fqdn,
        record_type=cfg.record_type,
        records=records,
        excluded_reasons=excluded_reasons,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Apply step
# ─────────────────────────────────────────────────────────────────────────────
def _previous_state(fqdn: str, record_type: str) -> DnsRecordState | None:
    return DnsRecordState.get(fqdn, record_type)


def _within_reapply_window(
    prev: DnsRecordState | None, *, min_seconds: int, now: datetime,
) -> bool:
    """True if ``prev.updated_at`` is younger than the re-apply window.

    Returns False when there is no previous state (first reconcile is
    never inside a "re-apply" window). ``updated_at`` is naive UTC per the
    project's ``utcnow()`` convention.
    """
    if prev is None or prev.updated_at is None or min_seconds <= 0:
        return False
    age = now - prev.updated_at
    return age >= timedelta(0) and age < timedelta(seconds=min_seconds)


def _emit_event(*, kind: str, severity: str, detail: dict[str, Any]) -> Event:
    """Append a row to ``fleet_events`` for the operator audit feed.

    Also runs the Phase-9 notifier so an owner alert is queued/sent. The
    notifier is best-effort: never raises, never blocks the reconcile
    cycle.
    """
    row = Event(ts=utcnow(), chr_id=None, kind=kind, severity=severity)
    row.detail = detail
    db.session.add(row)
    db.session.flush()  # so the alert row's FK can point at this event
    try:
        from fleet.notify.notifier import dispatch_event
        dispatch_event(row)
    except Exception:  # never let alerting break the reconcile cycle
        pass
    return row


def _record_published(
    desired: DesiredState, *, ttl: int, reason: str,
) -> DnsRecordState:
    """Upsert ``fleet_dns_records_state`` with the just-published set."""
    return DnsRecordState.upsert(
        desired.fqdn,
        desired.record_type,
        desired.publish_ips,
        ttl,
        reason=reason,
    )


def _no_change_result(
    desired: DesiredState, prev_ips: list[str], reason: str,
) -> ReconcileResult:
    return ReconcileResult(
        desired=desired, apply=None,
        applied=False, changed=False, suppressed=False,
        reason=reason, previous_ips=prev_ips,
    )


def _suppressed_result(
    desired: DesiredState, prev_ips: list[str], reason: str,
) -> ReconcileResult:
    return ReconcileResult(
        desired=desired, apply=None,
        applied=False, changed=False, suppressed=True,
        reason=reason, previous_ips=prev_ips,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────
def preview(
    *,
    cfg: ReconcileConfig | None = None,
    fleet_cfg: FleetConfig | None = None,
    rank_fn: Callable[[], list[NodeScore]] | None = None,
    state_of: Callable[[str], str | None] | None = None,
) -> DesiredState:
    """Compute the desired front-door state WITHOUT calling the driver.

    Idempotent (no DB writes, no provider calls). Safe to call from a
    Settings → "Preview" button or an operator REPL.
    """
    return compute_desired(
        cfg=cfg, fleet_cfg=fleet_cfg, rank_fn=rank_fn, state_of=state_of,
    )


def reconcile_now(
    *,
    cfg: ReconcileConfig | None = None,
    fleet_cfg: FleetConfig | None = None,
    now: datetime | None = None,
    rank_fn: Callable[[], list[NodeScore]] | None = None,
    state_of: Callable[[str], str | None] | None = None,
) -> ReconcileResult:
    """Compute the desired state and apply it via the driver.

    Behaviour summary:

    * No publishable nodes ⇒ if the front door currently has a non-empty
      set, we SUPPRESS the empty (anti-black-hole). The previous answer
      stays live and an ``Event(kind='dns_suppressed')`` is recorded.
      If both the desired and previous sets are empty, we record a
      ``dns_no_change`` and return.
    * Set is unchanged AND within ``min_reapply_interval_seconds`` of the
      last publish ⇒ skip the driver entirely and return ``no_change``.
    * Otherwise ⇒ call ``apply_desired_state`` (honouring ``cfg.dry_run``),
      upsert ``fleet_dns_records_state`` on success, and record
      ``Event(kind='dns_update')`` with the diff.

    The function commits on success. On a driver exception the in-flight
    audit row is committed (so we know we tried) but the published-state
    table is NOT mutated (so the next call retries against the right
    baseline).
    """
    cfg = cfg or ReconcileConfig()
    fcfg = fleet_cfg or FLEET
    now = now or utcnow()

    desired = compute_desired(
        cfg=cfg, fleet_cfg=fcfg, rank_fn=rank_fn, state_of=state_of,
    )
    publish_ips = desired.publish_ips
    prev = _previous_state(desired.fqdn, desired.record_type)
    prev_ips = list(prev.published_ips) if prev else []

    # ── Empty-set guard ─────────────────────────────────────────────────────
    if not publish_ips:
        if prev_ips:
            _emit_event(
                kind="dns_suppressed", severity="warn",
                detail={
                    "fqdn": desired.fqdn,
                    "record_type": desired.record_type,
                    "previous_ips": prev_ips,
                    "excluded_reasons": desired.excluded_reasons,
                    "reason": "publishable_set_empty",
                },
            )
            db.session.commit()
            return _suppressed_result(desired, prev_ips, "publishable_set_empty")
        # both empty — first reconcile against an empty fleet
        _emit_event(
            kind="dns_no_change", severity="info",
            detail={
                "fqdn": desired.fqdn,
                "record_type": desired.record_type,
                "reason": "fleet_empty",
            },
        )
        db.session.commit()
        return _no_change_result(desired, prev_ips, "fleet_empty")

    # ── Flap guard ──────────────────────────────────────────────────────────
    if (
        prev is not None
        and publish_ips == prev_ips
        and _within_reapply_window(prev, min_seconds=cfg.min_reapply_interval_seconds, now=now)
    ):
        _emit_event(
            kind="dns_no_change", severity="info",
            detail={
                "fqdn": desired.fqdn,
                "record_type": desired.record_type,
                "published_ips": publish_ips,
                "reason": "set_unchanged_within_min_interval",
            },
        )
        db.session.commit()
        return _no_change_result(desired, prev_ips, "set_unchanged_within_min_interval")

    # Set unchanged but we're past the re-apply window — still skip the
    # driver but record the no-change for the audit feed (and refresh
    # ``updated_at`` so the next window starts now).
    if prev is not None and publish_ips == prev_ips:
        DnsRecordState.upsert(
            desired.fqdn, desired.record_type, publish_ips, fcfg.dns.ttl,
            reason="heartbeat",
        )
        _emit_event(
            kind="dns_no_change", severity="info",
            detail={
                "fqdn": desired.fqdn,
                "record_type": desired.record_type,
                "published_ips": publish_ips,
                "reason": "set_unchanged",
            },
        )
        db.session.commit()
        return _no_change_result(desired, prev_ips, "set_unchanged")

    # ── Apply via the driver ────────────────────────────────────────────────
    try:
        apply_result = apply_desired_state(
            desired.records, mode=cfg.mode, dry_run=cfg.dry_run,
        )
    except Exception as exc:  # pragma: no cover - real driver only; fake never raises
        _emit_event(
            kind="dns_update_failed", severity="crit",
            detail={
                "fqdn": desired.fqdn,
                "record_type": desired.record_type,
                "desired_ips": publish_ips,
                "previous_ips": prev_ips,
                "error": repr(exc),
                "driver_backend": DRIVER_BACKEND,
            },
        )
        db.session.commit()
        raise

    if cfg.dry_run or not apply_result.applied:
        _emit_event(
            kind="dns_dry_run" if cfg.dry_run else "dns_no_change",
            severity="info",
            detail={
                "fqdn": desired.fqdn,
                "record_type": desired.record_type,
                "desired_ips": publish_ips,
                "previous_ips": prev_ips,
                "driver_message": apply_result.message,
                "driver_backend": DRIVER_BACKEND,
                "mode": cfg.mode,
                "dry_run": cfg.dry_run,
            },
        )
        db.session.commit()
        return ReconcileResult(
            desired=desired, apply=apply_result,
            applied=False, changed=apply_result.changed,
            suppressed=False,
            reason="dry_run" if cfg.dry_run else "driver_no_apply",
            previous_ips=prev_ips,
        )

    # Real apply happened — refresh the published-state mirror.
    _record_published(desired, ttl=fcfg.dns.ttl, reason="reconcile")
    _emit_event(
        kind="dns_update", severity="info",
        detail={
            "fqdn": desired.fqdn,
            "record_type": desired.record_type,
            "desired_ips": publish_ips,
            "previous_ips": prev_ips,
            "mode": cfg.mode,
            "driver_message": apply_result.message,
            "driver_backend": DRIVER_BACKEND,
            "weights": [
                {"node": r.node, "ip": r.ip, "weight": r.weight}
                for r in desired.publishable
            ],
        },
    )
    db.session.commit()
    return ReconcileResult(
        desired=desired, apply=apply_result,
        applied=True, changed=apply_result.changed or (publish_ips != prev_ips),
        suppressed=False, reason="applied", previous_ips=prev_ips,
    )


__all__ = [
    "ReconcileConfig",
    "DesiredState",
    "ReconcileResult",
    "compute_desired",
    "normalize_weights",
    "preview",
    "reconcile_now",
]
