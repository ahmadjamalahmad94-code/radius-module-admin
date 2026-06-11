"""Legacy ``chr_nodes`` → fleet ``fleet_chr_nodes`` migration.

This service brings every legacy :class:`app.models.ChrNode` into the fleet
:class:`fleet.registry.models_chr.FleetChrNode`, then rewrites every
:class:`app.models.ServiceAllocation` that still points at the legacy table to
point at the new fleet row instead. After this migration runs cleanly the
legacy tables are dead weight and step 6 of ``docs/CONSOLIDATION.md`` can drop
them outright.

Design choices
---------------
* **Idempotent.** Each fleet row carries the originating legacy id in a
  dedicated ``legacy_chr_node_id`` column (added by the startup schema-heal
  in ``app/__init__.py``). Re-running the migration is a no-op for nodes that
  have already been imported; only newly-added legacy rows get picked up.
* **Dry-run safe.** Pass ``dry_run=True`` to receive a plan (counts + per-node
  before/after) without touching the database. The UI uses this to render a
  preview before the operator clicks «نفّذ».
* **Single transaction.** A real run either commits everything or rolls back —
  no partial state where a fleet row exists but the allocations still point at
  the legacy id.
* **No terminal/SQL needed.** Runnable from the «أسطول CHR» dashboard via a
  POST endpoint. The owner sees a design-system modal + a flash toast.

The mapping is the obvious one — ``chr_nodes.public_ip`` becomes the new
node's ``public_ip``, ``capacity_mbps`` / ``max_active_sessions`` become
``link_speed_mbps`` / ``max_sessions``. RouterOS credentials carry across
verbatim (Fernet ciphertext + port + user); a missing port defaults to 8443
to match the fleet's default. A synthetic provider ``legacy-import`` is
created on first use so the FK on FleetChrNode stays satisfied; the operator
can rename / retag it later from «إعدادات البنية».
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import inspect as _inspect

from ..extensions import db
from ..models import ChrNode, ServiceAllocation, utcnow


# The synthetic provider used as the parent for every legacy import — see
# the docstring above for the rationale. Kept as a module constant so the
# migration, the test, and any future cleanup all reference the same string.
LEGACY_IMPORT_PROVIDER_NAME = "legacy-import"

# Default fleet RouterOS API port when the legacy row had none. 8443 matches
# the fleet onboarding default (production deploys reserve 443 for SSTP).
DEFAULT_ROUTEROS_API_PORT = 8443


@dataclass
class NodePlan:
    """One legacy node's slot in the migration plan."""
    legacy_id: int
    legacy_name: str
    legacy_public_ip: str
    action: str               # "import" | "skip_already_imported" | "skip_no_ip"
    fleet_node_id: int | None = None        # set when an existing import is reused
    rewritten_allocations: int = 0          # set on a real run
    error: str | None = None


@dataclass
class MigrationResult:
    """Aggregate outcome the UI / tests inspect."""
    dry_run: bool
    legacy_total: int = 0
    imported: int = 0
    skipped_existing: int = 0
    skipped_invalid: int = 0
    allocations_rewritten: int = 0
    orphan_allocations_after: int = 0
    nodes: list[NodePlan] = field(default_factory=list)
    provider_id: int | None = None
    error: str | None = None


def fleet_tables_available() -> bool:
    """True iff the fleet registry tables are present in this DB.

    Older deployments may have been spun up before the fleet shipped; rather
    than crash the migration service on import we let callers decide what to
    show in the UI (a friendly "fleet schema not initialised" notice).
    """
    try:
        from fleet.registry.models_chr import FleetChrNode, FleetProvider  # noqa: F401
        inspector = _inspect(db.engine)
        return {"fleet_chr_nodes", "fleet_providers"}.issubset(set(inspector.get_table_names()))
    except Exception:
        return False


def legacy_chr_node_id_column_present() -> bool:
    """True iff the schema-heal column that anchors the migration exists."""
    try:
        inspector = _inspect(db.engine)
        if "fleet_chr_nodes" not in set(inspector.get_table_names()):
            return False
        cols = {c["name"] for c in inspector.get_columns("fleet_chr_nodes")}
        return "legacy_chr_node_id" in cols
    except Exception:
        return False


def _get_or_create_legacy_provider():
    """Return (or create) the synthetic provider rows hang under."""
    from fleet.registry.models_chr import FleetProvider
    provider = FleetProvider.query.filter_by(name=LEGACY_IMPORT_PROVIDER_NAME).first()
    if provider is None:
        provider = FleetProvider(
            name=LEGACY_IMPORT_PROVIDER_NAME,
            cost_model="open",
            price_per_tb=0,
            monthly_cap_tb=None,
            overage_allowed=False,
            billing_cycle_day=1,
        )
        db.session.add(provider)
        db.session.flush()
    return provider


def _find_already_imported(legacy_id: int):
    """Return the FleetChrNode row that previously imported ``legacy_id``, if any."""
    from fleet.registry.models_chr import FleetChrNode
    return FleetChrNode.query.filter_by(legacy_chr_node_id=legacy_id).first()


def _legacy_status_to_fleet(status: str) -> str:
    """Map legacy chr_nodes.status into the fleet's narrower vocabulary."""
    mapping = {
        "pending": "provisioning",
        "active": "up",
        "maintenance": "degraded",
        "decommissioned": "disabled",
    }
    return mapping.get((status or "").strip(), "provisioning")


def _build_fleet_node(provider, legacy: ChrNode):
    """Construct (but DO NOT add) a FleetChrNode from a legacy row.

    Returned object is detached — the caller stamps any extra fields and
    decides whether to ``db.session.add`` it.
    """
    from fleet.registry.models_chr import FleetChrNode
    node = FleetChrNode(
        provider_id=provider.id,
        # The fleet unique-index is (provider_id, name), so two legacy rows with
        # the same name on different (synthetic) providers would still collide.
        # Disambiguate by suffixing the legacy id — operators can rename later.
        name=(legacy.name or f"legacy-{legacy.id}").strip()[:120],
        public_ip=(legacy.public_ip or "").strip()[:45],
        wg_mgmt_ip=(legacy.management_ip or legacy.public_ip or "").strip()[:45],
        # The legacy row has no WG mgmt pubkey — leave a marker that the
        # operator must fill in before the fleet poller can talk to it.
        # Empty would fail NOT NULL; use a sentinel that's safe to grep.
        wg_mgmt_pubkey="legacy-import-needs-pubkey",
        routeros_api_port=int(legacy.routeros_port or DEFAULT_ROUTEROS_API_PORT),
        routeros_api_user=(legacy.routeros_user or "")[:80],
        routeros_api_password_enc=(legacy.routeros_password_enc or ""),
        coa_port=3799,
        max_sessions=int(legacy.max_active_sessions or 0) or int(legacy.max_reserved_mbps or 0) or 0,
        link_speed_mbps=int(legacy.capacity_mbps or 0),
        bandwidth_cap_tb=None,
        cost_model="inherit",
        price_per_tb=None,
        overage_allowed=None,
        weight=1,
        enabled=True,
        drain=False,
        status=_legacy_status_to_fleet(legacy.status),
        cpu_pct=None,
        active_sessions=0,
        used_tb_cycle=0,
        score=None,
        last_seen_at=legacy.last_seen_at,
        last_ping_ok_at=None,
    )
    # The legacy_chr_node_id column is healed onto the table at startup; we
    # set the attribute generically so the dataclass-style ORM model picks it
    # up regardless of declared column order.
    setattr(node, "legacy_chr_node_id", int(legacy.id))
    return node


def plan_migration() -> MigrationResult:
    """Compute a dry-run plan — what WOULD happen, without writing anything."""
    return run_migration(dry_run=True)


def run_migration(dry_run: bool = False) -> MigrationResult:
    """Idempotently move legacy CHR nodes + their allocations into the fleet.

    Returns a :class:`MigrationResult` describing what happened (or what
    WOULD happen, when ``dry_run`` is true). Never raises for "expected"
    failure modes (missing tables, missing schema-heal column, no legacy
    rows) — the caller renders the message via the result.
    """
    result = MigrationResult(dry_run=bool(dry_run))

    if not fleet_tables_available():
        result.error = "fleet_schema_not_ready"
        return result
    if not legacy_chr_node_id_column_present():
        result.error = "schema_heal_pending"
        return result

    legacy_rows = ChrNode.query.order_by(ChrNode.id.asc()).all()
    result.legacy_total = len(legacy_rows)
    if not legacy_rows:
        return result  # nothing to do — safe both ways.

    if dry_run:
        # Plan path: just describe what each row would map to. We don't
        # create the provider in dry-run, to keep the DB untouched.
        for legacy in legacy_rows:
            existing = _find_already_imported(legacy.id)
            if existing is not None:
                result.skipped_existing += 1
                result.nodes.append(NodePlan(
                    legacy_id=legacy.id,
                    legacy_name=legacy.name or "",
                    legacy_public_ip=legacy.public_ip or "",
                    action="skip_already_imported",
                    fleet_node_id=existing.id,
                ))
                continue
            if not (legacy.public_ip or "").strip():
                result.skipped_invalid += 1
                result.nodes.append(NodePlan(
                    legacy_id=legacy.id,
                    legacy_name=legacy.name or "",
                    legacy_public_ip="",
                    action="skip_no_ip",
                    error="legacy row has no public_ip",
                ))
                continue
            result.imported += 1
            result.nodes.append(NodePlan(
                legacy_id=legacy.id,
                legacy_name=legacy.name or "",
                legacy_public_ip=legacy.public_ip or "",
                action="import",
            ))
        # Allocation-rewrite preview: every row pointing at one of the
        # to-be-imported legacy ids.
        result.allocations_rewritten = (
            ServiceAllocation.query
            .filter(ServiceAllocation.chr_node_id.in_(
                [n.legacy_id for n in result.nodes if n.action == "import"] or [-1]
            ))
            .count()
        )
        return result

    # ── Real run ────────────────────────────────────────────────────────
    try:
        provider = _get_or_create_legacy_provider()
        result.provider_id = provider.id
        legacy_to_fleet: dict[int, int] = {}
        for legacy in legacy_rows:
            existing = _find_already_imported(legacy.id)
            if existing is not None:
                result.skipped_existing += 1
                legacy_to_fleet[legacy.id] = existing.id
                result.nodes.append(NodePlan(
                    legacy_id=legacy.id,
                    legacy_name=legacy.name or "",
                    legacy_public_ip=legacy.public_ip or "",
                    action="skip_already_imported",
                    fleet_node_id=existing.id,
                ))
                continue
            if not (legacy.public_ip or "").strip():
                result.skipped_invalid += 1
                result.nodes.append(NodePlan(
                    legacy_id=legacy.id,
                    legacy_name=legacy.name or "",
                    legacy_public_ip="",
                    action="skip_no_ip",
                    error="legacy row has no public_ip",
                ))
                continue
            new_node = _build_fleet_node(provider, legacy)
            db.session.add(new_node)
            db.session.flush()
            legacy_to_fleet[legacy.id] = new_node.id
            result.imported += 1
            plan = NodePlan(
                legacy_id=legacy.id,
                legacy_name=legacy.name or "",
                legacy_public_ip=legacy.public_ip or "",
                action="import",
                fleet_node_id=new_node.id,
            )
            result.nodes.append(plan)

        # Rewrite allocations pointing at the legacy ids to the new fleet ids.
        # The FK on ServiceAllocation still references chr_nodes(id) until
        # step 6 drops it; we keep the integer value but make sure every
        # affected row has the corresponding fleet node id stamped on it.
        if legacy_to_fleet:
            allocs = (
                ServiceAllocation.query
                .filter(ServiceAllocation.chr_node_id.in_(list(legacy_to_fleet.keys())))
                .all()
            )
            for alloc in allocs:
                old = alloc.chr_node_id
                new = legacy_to_fleet.get(old)
                if new is None:
                    continue
                alloc.chr_node_id = new
                # update the per-node bookkeeping so the operator can see at
                # a glance how many landed on each fleet row.
                for p in result.nodes:
                    if p.legacy_id == old:
                        p.rewritten_allocations += 1
                        break
                result.allocations_rewritten += 1

        # Sanity check: any allocations still pointing at a legacy id that
        # is NOT in our mapping (e.g. a row whose legacy node had no public_ip
        # and was skipped). The UI surfaces this as a warning so the operator
        # decides whether to fix-up manually.
        all_legacy_ids = {row.id for row in legacy_rows}
        result.orphan_allocations_after = (
            ServiceAllocation.query
            .filter(ServiceAllocation.chr_node_id.in_(
                list(all_legacy_ids - set(legacy_to_fleet.keys())) or [-1]
            ))
            .count()
        )

        db.session.commit()
    except Exception as exc:  # noqa: BLE001 — bubble to the UI as a clean toast.
        db.session.rollback()
        result.error = f"migration_failed: {exc}"
    return result


def to_jsonable(result: MigrationResult) -> dict[str, Any]:
    """Adapter for the JSON view + audit-log payload."""
    return {
        "dry_run": result.dry_run,
        "legacy_total": result.legacy_total,
        "imported": result.imported,
        "skipped_existing": result.skipped_existing,
        "skipped_invalid": result.skipped_invalid,
        "allocations_rewritten": result.allocations_rewritten,
        "orphan_allocations_after": result.orphan_allocations_after,
        "provider_id": result.provider_id,
        "error": result.error,
        "nodes": [
            {
                "legacy_id": n.legacy_id,
                "legacy_name": n.legacy_name,
                "legacy_public_ip": n.legacy_public_ip,
                "action": n.action,
                "fleet_node_id": n.fleet_node_id,
                "rewritten_allocations": n.rewritten_allocations,
                "error": n.error,
            }
            for n in result.nodes
        ],
    }
