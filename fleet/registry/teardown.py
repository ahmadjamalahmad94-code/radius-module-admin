"""fix/fleet-delete-complete-teardown — centralized node teardown cascade.

Owner's complaint: «لما حذفت ما تنظفت العقد، بضل بقايا». The previous
delete-job handler deleted the OnboardingJob row + (optionally) the
FleetChrNode row, leaving several remnants:

  1. ``ProxyRealmRoute.allowed_fleet_chr_node_ids_json`` — JSON list,
     not a FK. Stale node ids were never scrubbed; the proxy's
     routing-table reader skipped them silently on read but the
     config stayed dirty.
  2. ``PendingCoaCommand`` rows targeting the deleted node id orphaned
     in the queue with no FK cascade.
  3. ``FleetSession`` rows lost their ``chr_id`` parent silently
     (no FK cascade); orphan sessions polluted the DB.
  4. ``UserFleet.pinned_chr_id`` references became dangling ints.
  5. Panel's wg-mgmt peer table on the host kept a peer entry until
     someone manually clicked «إعادة مزامنة» — until then the panel
     trusted a node that no longer existed.

This module owns the COMPLETE teardown chain. Every caller that
removes a fleet node MUST go through ``teardown_node`` so the cascade
is identical across paths (job delete + direct orphan delete + purge).

The functions are FK-aware and idempotent — they tolerate already-
gone rows + commit nothing themselves (caller controls the
transaction).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

from app.extensions import db
from fleet.registry.models_chr import FleetChrNode
from fleet.registry.models_onboarding import OnboardingJob


logger = logging.getLogger(__name__)


@dataclass
class TeardownReport:
    """What teardown_node actually removed. Returned to the caller for
    auditing + UI feedback."""

    node_id: int
    node_name: str = ""
    node_row_deleted: bool = False
    routes_scrubbed: int = 0        # ProxyRealmRoute rows whose JSON list lost the id
    coa_commands_dropped: int = 0   # PendingCoaCommand rows deleted
    sessions_dropped: int = 0       # FleetSession rows deleted
    pinned_user_refs_cleared: int = 0  # UserFleet rows whose pinned_chr_id was reset
    panel_peer_apply: dict = field(default_factory=dict)  # reconcile_panel_host return

    def as_dict(self) -> dict:
        return {
            "node_id": self.node_id,
            "node_name": self.node_name,
            "node_row_deleted": self.node_row_deleted,
            "routes_scrubbed": self.routes_scrubbed,
            "coa_commands_dropped": self.coa_commands_dropped,
            "sessions_dropped": self.sessions_dropped,
            "pinned_user_refs_cleared": self.pinned_user_refs_cleared,
            "panel_peer_apply": self.panel_peer_apply,
        }


def _scrub_routes(node_id: int) -> int:
    """Remove ``node_id`` from every ``ProxyRealmRoute.allowed_fleet_chr_node_ids_json``
    that lists it. The proxy's routing-table reader already SKIPS unknown
    ids on read, so this is operationally a config-hygiene scrub — but
    leaving the id behind means a future re-issue of the same id (the
    allocator gap-fills row ids) would silently allow the new node
    through the OLD route. Scrub-on-delete prevents that drift entirely.
    """
    from app.models import ProxyRealmRoute

    count = 0
    for route in ProxyRealmRoute.query.all():
        current = list(route.allowed_fleet_chr_node_ids or [])
        if node_id not in {int(x) for x in current if str(x).lstrip("-").isdigit()}:
            continue
        route.allowed_fleet_chr_node_ids = [
            int(x) for x in current
            if str(x).lstrip("-").isdigit() and int(x) != node_id
        ]
        db.session.add(route)
        count += 1
    if count:
        logger.info("teardown: scrubbed node_id=%s from %s routes", node_id, count)
    return count


def _drop_pending_coa(node_id: int) -> int:
    """Delete PendingCoaCommand rows targeting this node. A queued CoA
    that the proxy hasn't picked up yet is now meaningless — the target
    CHR is gone, the realm may have moved. Deleting is safer than
    leaving the row to expire on its own TTL (which would still publish
    a stale ``target_node_id`` in the next ``pending_coa`` array)."""
    try:
        from app.models import PendingCoaCommand
    except Exception:  # noqa: BLE001 — older deploys without the model
        return 0
    rows = PendingCoaCommand.query.filter_by(target_node_id=int(node_id)).all()
    for r in rows:
        db.session.delete(r)
    if rows:
        logger.info("teardown: dropped %s pending_coa rows for node_id=%s",
                    len(rows), node_id)
    return len(rows)


def _drop_sessions(node_id: int) -> int:
    """Delete fleet sessions rows for this node, if the model exists in
    this deploy. The model name varies across branches; we try the
    canonical anchors and skip cleanly when none is present."""
    candidates = (
        ("fleet.brain.models_session", "FleetSession"),
        ("fleet.registry.models_chr", "FleetSession"),
    )
    cls = None
    for module_name, attr in candidates:
        try:
            mod = __import__(module_name, fromlist=[attr])
            cls = getattr(mod, attr, None)
            if cls is not None:
                break
        except Exception:  # noqa: BLE001
            continue
    if cls is None:
        return 0
    rows = cls.query.filter_by(chr_id=int(node_id)).all()
    for r in rows:
        db.session.delete(r)
    if rows:
        logger.info("teardown: dropped %s session rows for node_id=%s",
                    len(rows), node_id)
    return len(rows)


def _clear_pinned_refs(node_id: int) -> int:
    """``UserFleet.pinned_chr_id`` is a non-cascade FK; clear it so the
    user's preference doesn't dangle to a row that no longer exists.
    ``UserFleet`` lives in ``fleet.brain.models_session`` in this
    repo."""
    try:
        from fleet.brain.models_session import UserFleet
    except Exception:  # noqa: BLE001
        return 0
    rows = UserFleet.query.filter_by(pinned_chr_id=int(node_id)).all()
    for r in rows:
        r.pinned_chr_id = None
        db.session.add(r)
    if rows:
        logger.info("teardown: cleared %s pinned_chr_id refs for node_id=%s",
                    len(rows), node_id)
    return len(rows)


def _reconcile_panel_peers() -> dict:
    """Re-run the panel-host wg-mgmt apply so a deleted node's peer
    is dropped immediately (rather than waiting for the operator to
    click «إعادة مزامنة»). Returns the ApplyResult dict; an absent
    helper or non-zero error degrades silently — the delete itself
    is already committed."""
    try:
        from fleet.sync.service import reconcile_panel_host
        return reconcile_panel_host()
    except Exception as exc:  # noqa: BLE001 — never fail the delete on the apply
        logger.warning("teardown: panel-peer reconcile degraded: %s", exc)
        return {"available": False, "applied": False,
                "message": f"reconcile degraded: {exc.__class__.__name__}"}


def teardown_node(node: FleetChrNode | int) -> TeardownReport:
    """Run the complete teardown cascade for one fleet node. SAFE TO
    CALL even when the node row is already gone — every sub-step is
    a SELECT-then-action, so a missing parent collapses each step to
    a no-op.

    Caller is responsible for the transaction (we add/delete but do
    NOT commit). The wg-mgmt peer reconcile DOES require the prior
    DB writes to be visible, so we flush before calling it.
    """
    node_id = int(node.id if hasattr(node, "id") else node)
    row: Optional[FleetChrNode] = (
        node if isinstance(node, FleetChrNode)
        else db.session.get(FleetChrNode, node_id)
    )

    name = (row.name if row else "") or ""

    routes = _scrub_routes(node_id)
    coa = _drop_pending_coa(node_id)
    sessions = _drop_sessions(node_id)
    pinned = _clear_pinned_refs(node_id)

    node_deleted = False
    if row is not None:
        db.session.delete(row)
        node_deleted = True

    # Make the deletes visible so the wg-mgmt reconciler's desired set
    # query sees an empty result for this node.
    db.session.flush()

    panel_apply = _reconcile_panel_peers()

    return TeardownReport(
        node_id=node_id,
        node_name=name,
        node_row_deleted=node_deleted,
        routes_scrubbed=routes,
        coa_commands_dropped=coa,
        sessions_dropped=sessions,
        pinned_user_refs_cleared=pinned,
        panel_peer_apply=panel_apply,
    )


# ════════════════════════════════════════════════════════════════════════
# Orphan discovery + purge
# ════════════════════════════════════════════════════════════════════════
@dataclass
class OrphanSurvey:
    """What a purge would find (returned by ``find_orphans`` so the
    operator can preview before clicking «نظِّف»). All ids are
    documented and visible in the audit log of the eventual purge."""

    orphan_node_ids: list[int] = field(default_factory=list)
    orphan_job_ids: list[int] = field(default_factory=list)
    stale_route_node_ids: dict = field(default_factory=dict)
    stale_coa_node_ids: list[int] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "orphan_node_ids": list(self.orphan_node_ids),
            "orphan_job_ids": list(self.orphan_job_ids),
            "stale_route_node_ids": dict(self.stale_route_node_ids),
            "stale_coa_node_ids": list(self.stale_coa_node_ids),
        }

    @property
    def is_empty(self) -> bool:
        return (
            not self.orphan_node_ids
            and not self.orphan_job_ids
            and not self.stale_route_node_ids
            and not self.stale_coa_node_ids
        )


_LIVE_JOB_STATES = (
    "draft", "keys_generated", "script_generated",
    "pushed", "verifying", "active",
)


def find_orphans() -> OrphanSurvey:
    """Read-only survey of every dangling reference. Used by both
    the «معاينة المهملات» preview action and the audit metadata of
    the purge."""
    from app.models import ProxyRealmRoute

    # FleetChrNode rows not referenced by any live OnboardingJob.
    live_chr_ids = {
        cid for (cid,) in db.session.query(OnboardingJob.chr_id)
        .filter(OnboardingJob.status.in_(_LIVE_JOB_STATES)).all()
        if cid is not None
    }
    all_node_ids = {nid for (nid,) in db.session.query(FleetChrNode.id).all()}
    orphan_node_ids = sorted(all_node_ids - live_chr_ids)

    # OnboardingJob rows that have NULL chr_id AND are still in a
    # pending-card state. These show up in the dashboard pending count
    # without a node to act on — pure UI noise.
    orphan_job_ids = sorted(
        j_id for (j_id,) in (
            db.session.query(OnboardingJob.id)
            .filter(OnboardingJob.chr_id.is_(None))
            .filter(OnboardingJob.status.in_(
                ("draft", "keys_generated", "script_generated",
                 "pushed", "verifying", "failed"),
            ))
            .all()
        )
    )

    # ProxyRealmRoute entries listing node ids that don't exist anymore.
    stale_route_node_ids: dict[int, list[int]] = {}
    for route in ProxyRealmRoute.query.all():
        ids = [
            int(x) for x in (route.allowed_fleet_chr_node_ids or [])
            if str(x).lstrip("-").isdigit()
        ]
        stale = [i for i in ids if i not in all_node_ids]
        if stale:
            stale_route_node_ids[int(route.id)] = stale

    # PendingCoaCommand entries pointing at deleted node ids.
    stale_coa: list[int] = []
    try:
        from app.models import PendingCoaCommand
        rows = (
            db.session.query(PendingCoaCommand.id, PendingCoaCommand.target_node_id)
            .all()
        )
        for cid, tid in rows:
            if tid is not None and int(tid) not in all_node_ids:
                stale_coa.append(int(cid))
    except Exception:  # noqa: BLE001
        pass

    return OrphanSurvey(
        orphan_node_ids=orphan_node_ids,
        orphan_job_ids=orphan_job_ids,
        stale_route_node_ids=stale_route_node_ids,
        stale_coa_node_ids=stale_coa,
    )


@dataclass
class PurgeReport:
    """What the purge actually removed. The orphan survey is captured
    BEFORE the work runs (for the audit log)."""

    survey_before: OrphanSurvey
    node_teardown_reports: list[dict] = field(default_factory=list)
    orphan_jobs_deleted: int = 0
    panel_peer_apply: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "survey_before": self.survey_before.as_dict(),
            "node_teardown_reports": list(self.node_teardown_reports),
            "orphan_jobs_deleted": self.orphan_jobs_deleted,
            "panel_peer_apply": self.panel_peer_apply,
        }


def purge_orphans() -> PurgeReport:
    """Run a complete sweep: tear down every orphan node + delete
    every orphan job + scrub every stale route id + drop every stale
    CoA. Caller commits."""
    survey = find_orphans()
    node_reports: list[dict] = []
    for nid in survey.orphan_node_ids:
        report = teardown_node(nid)
        node_reports.append(report.as_dict())
    jobs_deleted = 0
    for jid in survey.orphan_job_ids:
        job = db.session.get(OnboardingJob, jid)
        if job is not None:
            db.session.delete(job)
            jobs_deleted += 1
    # Final reconcile so the panel host sees the post-purge state.
    db.session.flush()
    panel_apply = _reconcile_panel_peers()
    return PurgeReport(
        survey_before=survey,
        node_teardown_reports=node_reports,
        orphan_jobs_deleted=jobs_deleted,
        panel_peer_apply=panel_apply,
    )


__all__ = [
    "TeardownReport",
    "OrphanSurvey",
    "PurgeReport",
    "teardown_node",
    "find_orphans",
    "purge_orphans",
]
