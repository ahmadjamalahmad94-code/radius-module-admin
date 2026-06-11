"""fleet.sync.service — create + drive sync jobs; reconcile fleet peers.

The progress UI is driven WITHOUT a task queue or background threads: a job
stores its full per-node/per-stage payload, and the front-end polls
:func:`tick`, which advances exactly ONE real stage per call and persists. Each
tick runs a genuine check, so the bar only moves when real state changes. This
is deterministic and trivially testable (a test can tick a job to completion and
assert the recorded states, including a forced failure).

``create_job`` also performs the once-per-run panel-host reconcile (apply the
desired wg-mgmt peer set via the scoped helper, safe-by-default) and snapshots
the desired panel/proxy peer names + current panel pubkey into the payload as
the stage ``ctx``.
"""
from __future__ import annotations

from typing import Any

from app.extensions import db
from fleet.registry.models_chr import FleetChrNode
from fleet.sync.models import STAGE_TERMINAL, SyncJob
from fleet.sync.stages import HARD_STAGES, STAGES, run_stage


def _fresh_stage(key: str, label_ar: str) -> dict[str, Any]:
    return {"key": key, "label_ar": label_ar, "state": "pending", "reason": "", "value": ""}


def _node_entry(node: FleetChrNode) -> dict[str, Any]:
    return {
        "node_id": node.id,
        "name": node.name,
        "wg_mgmt_ip": node.wg_mgmt_ip,
        "needs_reimport": bool(node.needs_reimport),
        "stages": [_fresh_stage(k, lbl) for (k, lbl) in STAGES],
    }


def _resolve_nodes(scope: str, node_ids: list[int] | None) -> list[FleetChrNode]:
    if scope == "node" and node_ids:
        rows = FleetChrNode.query.filter(FleetChrNode.id.in_(node_ids)).all()
        # preserve requested order
        by_id = {n.id: n for n in rows}
        return [by_id[i] for i in node_ids if i in by_id]
    return FleetChrNode.query.order_by(FleetChrNode.name.asc()).all()


def reconcile_panel_host() -> dict[str, Any]:
    """Apply the desired wg-mgmt peer set on the panel host (idempotent).

    Returns the ApplyResult dict. Safe-by-default: a no-op report when the
    scoped helper isn't installed.
    """
    from fleet.sync.peers import desired_panel_peers
    from fleet.sync.wg_apply import apply_panel_peers
    return apply_panel_peers(desired_panel_peers()).to_dict()


def create_job(scope: str = "fleet", node_ids: list[int] | None = None) -> SyncJob:
    """Create a sync job and perform the once-per-run panel reconcile."""
    from fleet.sync.keys import panel_pubkey
    from fleet.sync.peers import desired_panel_peers, desired_proxy_peers

    scope = scope if scope in ("node", "fleet") else "fleet"
    nodes = _resolve_nodes(scope, node_ids)

    desired_panel = desired_panel_peers()
    desired_proxy = desired_proxy_peers()
    panel_apply = reconcile_panel_host()

    payload: dict[str, Any] = {
        "scope": scope,
        "panel_pubkey_set": bool(panel_pubkey()),
        "panel_apply": panel_apply,
        "desired_panel_names": sorted({p.name for p in desired_panel}),
        "desired_proxy_names": sorted({p.name for p in desired_proxy}),
        "nodes": [_node_entry(n) for n in nodes],
    }
    job = SyncJob(scope=scope, status="running" if nodes else "done")
    job.payload = payload
    db.session.add(job)
    db.session.commit()
    return job


def _build_ctx(payload: dict[str, Any]) -> dict[str, Any]:
    from fleet.sync.keys import panel_pubkey
    return {
        "panel_apply": payload.get("panel_apply") or {},
        "desired_panel_names": set(payload.get("desired_panel_names") or []),
        "desired_proxy_names": set(payload.get("desired_proxy_names") or []),
        "panel_pubkey": panel_pubkey(),
    }


def _recompute_status(payload: dict[str, Any]) -> str:
    for ne in payload.get("nodes", []):
        for st in ne.get("stages", []):
            if st.get("state") not in STAGE_TERMINAL:
                return "running"
    return "done"


def tick(job: SyncJob) -> SyncJob:
    """Advance ONE pending stage (run its real check) and persist.

    Processes nodes in order: a node's pipeline runs to a terminal end before
    the next node starts, so the UI shows exactly where work is happening. A
    HARD-stage failure blocks the rest of that node's stages ("where it
    stopped"); a ``warn`` never blocks.
    """
    if job.status == "done":
        return job
    payload = job.payload
    ctx = _build_ctx(payload)

    for ne in payload.get("nodes", []):
        stages = ne.get("stages", [])
        # First non-terminal stage of this node.
        idx = next((i for i, s in enumerate(stages)
                    if s.get("state") not in STAGE_TERMINAL), None)
        if idx is None:
            continue  # node fully processed → next node

        stage = stages[idx]
        node = db.session.get(FleetChrNode, ne.get("node_id"))
        if node is None:
            stage.update({"state": "failed", "reason": "حُذِفت العقدة أثناء المزامنة.", "value": ""})
        else:
            outcome = run_stage(stage["key"], node, ctx)
            stage.update(outcome.as_update())
            ne["needs_reimport"] = bool(node.needs_reimport)
            # HARD failure → block the remaining pending stages of this node.
            if outcome.state == "failed" and stage["key"] in HARD_STAGES:
                for s in stages[idx + 1:]:
                    if s.get("state") == "pending":
                        s.update({"state": "blocked",
                                  "reason": "توقّفت السلسلة عند فشل مرحلة سابقة.", "value": ""})

        job.payload = payload
        job.status = _recompute_status(payload)
        db.session.commit()
        return job

    # Nothing pending anywhere.
    job.status = "done"
    job.payload = payload
    db.session.commit()
    return job


def run_to_completion(job: SyncJob, *, max_ticks: int = 4096) -> SyncJob:
    """Drive a job to terminal state synchronously (used by tests + the
    non-interactive reconcile). Bounded so a logic bug can't spin forever."""
    ticks = 0
    while job.status != "done" and ticks < max_ticks:
        before = _progress_counts(job.payload)
        tick(job)
        ticks += 1
        if _progress_counts(job.payload) == before and job.status != "done":
            # No forward progress in a tick that didn't finish → bail defensively.
            break
    return job


def _progress_counts(payload: dict[str, Any]) -> int:
    return sum(
        1
        for ne in payload.get("nodes", [])
        for s in ne.get("stages", [])
        if s.get("state") in STAGE_TERMINAL
    )


# ── serialisation for the progress API ──────────────────────────────────────
def to_dict(job: SyncJob) -> dict[str, Any]:
    payload = job.payload
    total = 0
    terminal = 0
    counts = {"done": 0, "warn": 0, "failed": 0, "blocked": 0, "pending": 0}
    node_views = []
    for ne in payload.get("nodes", []):
        stages = ne.get("stages", [])
        n_terminal = 0
        first_pending = None
        node_state = "done"
        for i, s in enumerate(stages):
            total += 1
            state = s.get("state", "pending")
            counts[state] = counts.get(state, 0) + 1
            if state in STAGE_TERMINAL:
                terminal += 1
                n_terminal += 1
            elif first_pending is None:
                first_pending = i
            if state == "failed":
                node_state = "failed"
            elif state == "blocked" and node_state != "failed":
                node_state = "blocked"
            elif state == "warn" and node_state == "done":
                node_state = "warn"
        if first_pending is not None:
            node_state = "running"
        node_views.append({
            "node_id": ne.get("node_id"),
            "name": ne.get("name"),
            "wg_mgmt_ip": ne.get("wg_mgmt_ip"),
            "needs_reimport": ne.get("needs_reimport", False),
            "node_state": node_state,
            "running_stage": first_pending,   # index of the animated spinner
            "stages": stages,
        })
    return {
        "id": job.id,
        "scope": job.scope,
        "status": job.status,
        "panel_apply": payload.get("panel_apply") or {},
        "panel_pubkey_set": payload.get("panel_pubkey_set", False),
        "progress": {
            "total": total,
            "terminal": terminal,
            "percent": round(100 * terminal / total) if total else 100,
            "counts": counts,
        },
        "nodes": node_views,
    }


__all__ = [
    "create_job", "tick", "run_to_completion", "to_dict",
    "reconcile_panel_host",
]
