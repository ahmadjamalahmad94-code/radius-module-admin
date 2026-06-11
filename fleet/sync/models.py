"""fleet.sync.models — the sync-job record that drives the live progress UI.

One ``fleet_sync_jobs`` row per onboarding-finalize or fleet re-sync run. The
full staged state lives in a single JSON payload (same text-JSON convention as
``fleet_onboarding_jobs``) so the eight-stage, per-node structure can evolve
without a migration per field. The payload is the source of truth the progress
API serialises straight to the browser.

State vocabulary per stage::

    pending  → not run yet (UI shows the FIRST pending stage of the active
               node as the animated "running" spinner)
    done     → real check passed (green check)
    warn     → ran but couldn't be fully confirmed / intentionally skipped
               (amber; non-blocking — pipeline continues)
    failed   → real check failed (red ✗; HARD — blocks the rest of this
               node's pipeline so the UI shows exactly WHERE it stopped)
    blocked  → a prior hard failure stopped this stage from running

Job ``status`` is ``running`` until every node's pipeline is terminal (no
pending stage left), then ``done``.
"""
from __future__ import annotations

from typing import Any

from app.extensions import db
from app.models import TimestampMixin, json_dumps, json_loads

SYNC_SCOPES = ("node", "fleet")
SYNC_JOB_STATUSES = ("running", "done")
STAGE_STATES = ("pending", "running", "done", "warn", "failed", "blocked")
#: Terminal stage states — a stage in one of these is finished for this run.
STAGE_TERMINAL = frozenset({"done", "warn", "failed", "blocked"})


class SyncJob(TimestampMixin, db.Model):
    """A zero-touch sync run (single node or whole fleet)."""

    __tablename__ = "fleet_sync_jobs"
    __table_args__ = (
        db.Index("idx_fleet_sync_jobs_status", "status"),
    )

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    scope = db.Column(db.String(16), nullable=False, default="fleet", server_default="fleet")
    status = db.Column(db.String(16), nullable=False, default="running", server_default="running")
    # Full per-node, per-stage structure (see module docstring).
    payload_json = db.Column(db.Text, nullable=False, default="{}", server_default="{}")

    @property
    def payload(self) -> dict[str, Any]:
        return json_loads(self.payload_json, {})

    @payload.setter
    def payload(self, value: dict[str, Any] | None) -> None:
        self.payload_json = json_dumps(value or {})

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"<SyncJob id={self.id} scope={self.scope!r} status={self.status!r}>"


__all__ = [
    "SyncJob",
    "SYNC_SCOPES",
    "SYNC_JOB_STATUSES",
    "STAGE_STATES",
    "STAGE_TERMINAL",
]
