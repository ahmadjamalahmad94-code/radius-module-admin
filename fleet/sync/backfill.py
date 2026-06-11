"""fleet.sync.backfill — heal wg_data_pubkey for pre-existing CHR rows.

The ``wg_data_pubkey`` column lands with feat/fleet-zero-touch-sync. Rows
created by the onboarding wizard BEFORE this column existed have their wg-data
public key only inside ``fleet_onboarding_jobs.wg_keypair_ref`` (the JSON blob
``{"mgmt_pubkey": ..., "data_pubkey": ...}``). This backfill copies that
``data_pubkey`` onto the node row so the proxy peer publisher has a complete
set without us re-minting any keys (which would defeat key stability).

Idempotent + defensive: only writes rows whose ``wg_data_pubkey`` is still
empty, only when the job carries a usable ``data_pubkey``. Runs inside
``ensure_schema_compatibility`` at boot; never raises (caller rolls back).
"""
from __future__ import annotations

import json

from app.extensions import db


def backfill_wg_data_pubkeys() -> int:
    """Populate empty ``wg_data_pubkey`` from onboarding job refs.

    Returns the number of node rows updated. Safe to call repeatedly.
    """
    from fleet.registry.models_chr import FleetChrNode
    from fleet.registry.models_onboarding import OnboardingJob

    # Map chr_id -> data_pubkey from any job that recorded one.
    job_data_pubkey: dict[int, str] = {}
    for job in OnboardingJob.query.filter(OnboardingJob.chr_id.isnot(None)).all():
        if not job.wg_keypair_ref:
            continue
        try:
            refs = json.loads(job.wg_keypair_ref)
        except (ValueError, TypeError):
            continue
        pub = str(refs.get("data_pubkey") or "").strip()
        if pub and job.chr_id is not None:
            job_data_pubkey[job.chr_id] = pub

    if not job_data_pubkey:
        return 0

    updated = 0
    nodes = (
        FleetChrNode.query
        .filter(FleetChrNode.id.in_(list(job_data_pubkey.keys())))
        .all()
    )
    for node in nodes:
        if (node.wg_data_pubkey or "").strip():
            continue  # already populated — idempotent
        pub = job_data_pubkey.get(node.id)
        if pub:
            node.wg_data_pubkey = pub
            updated += 1

    if updated:
        db.session.commit()
    return updated


__all__ = ["backfill_wg_data_pubkeys"]
