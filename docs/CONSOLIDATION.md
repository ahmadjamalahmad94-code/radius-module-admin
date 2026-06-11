# CHR / Fleet / Infrastructure consolidation

The radius-module-admin panel used to expose TWO parallel «CHR node» concepts
to the operator — a legacy `chr_nodes` table on `/admin/infra/chr-nodes` and
the canonical `fleet_chr_nodes` table behind `/admin/fleet/...`. This doc is
the contract for collapsing them into **one** system: «أسطول CHR» is the
single canonical place to add, edit, monitor, and decommission MikroTik CHR
nodes. Everything else either consolidates under it, gets hidden, or is
removed.

The plan is the one from the read-only audit; this file is the running
record of what's done and what's pending.

> **TL;DR for future-you**: the customer's mental model is now
> «أسطول CHR» = fleet. The legacy table still exists for one more cycle so
> we can migrate existing rows safely. Step 6 below is the destructive cleanup
> and is intentionally NOT included in this branch.

---

## Status snapshot

| Step | Description | State |
| ---- | ----------- | ----- |
| 1 | Wire `/admin/infra/system-health` to real psutil values (nested `health.resources` dict). | ✅ Done — `app/admin/infra_routes.py:system_health()`. Adds `psutil>=5.9` to `requirements.txt` and a stdlib `shutil.disk_usage` + `os.getloadavg` fallback for psutil-less envs. Also surfaces the fleet metrics-poller liveness pill inside the «الخادم الرئيسي» card. |
| 2 | Sidebar regroup: move «تحكّم RouterOS», «بروفايلات السرعة», «نسخ RADIUS», «تخصيصات الخدمة», «وكيل RADIUS» under «أسطول CHR». Hide legacy «عقد CHR». | ✅ Done — `app/templates/admin/base_new.html` groups ④/⑤/⑤b. |
| 3 | Deprecation banner on every legacy `/admin/infra/chr-nodes*` page. Short-circuit WRITE endpoints (create / edit / poll / poll-all) to flash + redirect into the fleet wizard / dashboard. List stays read-only until step 6. | ✅ Done — partial `app/templates/_partials/_legacy_chr_banner.html`, view changes in `app/admin/infra_routes.py`. |
| 4 | Relabel `/admin/settings#chr-settings` to «MikroTik CHR — نمط الـCHR الواحد» + explain when to use the fleet instead. Cross-reference notice on the fleet dashboard when the singleton's `host` matches any `FleetChrNode.public_ip`. | ✅ Done — `app/templates/admin/settings/general_new.html` + `fleet/ui/routes.py:fleet_dashboard()` + `app/templates/admin/fleet/dashboard.html`. |
| 5 | Idempotent, UI-runnable legacy → fleet migration with dry-run preview. | ✅ Done — `app/services/fleet_consolidation.py`, `/admin/infra/consolidation` GET + POST, `app/templates/admin/infra/consolidation.html`. Schema-heal column `fleet_chr_nodes.legacy_chr_node_id` lands at startup. |
| 6 | Destructive: drop legacy tables + code + dead column. | ✅ Done — `app/__init__.py` schema heal drops `chr_nodes` / `chr_node_metrics` + the legacy allowlist column + renames `service_allocations.chr_node_id` → `fleet_chr_node_id`. Model + view + template + service files for the legacy CHR system are gone. Routing-table is fleet-only with `wg_data_ip` + `allowed_chr_ips` intact. See "Step 6 — what was removed" below for the post-mortem. |

---

## How the migration works (step 5)

Files: `app/services/fleet_consolidation.py`, `app/admin/infra_routes.py`
routes `consolidation_page` / `consolidation_run`, template
`app/templates/admin/infra/consolidation.html`.

* **Where to find it in the UI.** Legacy banner on `/admin/infra/chr-nodes*`
  pages links to `/admin/infra/consolidation`. The page renders a dry-run
  plan (each legacy row's destination, the count of allocations that will be
  rewritten) and a single «نفّذ الترحيل» button. A design-system confirm
  modal is shown before the POST — never `confirm()`.
* **Idempotency anchor.** A nullable column `fleet_chr_nodes.legacy_chr_node_id`
  is added via the existing `_add_columns_if_missing` heal in
  `app/__init__.py`. Every fleet row imported from the legacy table is stamped
  with its origin id; reruns skip rows that already have an import.
* **Single transaction.** The real run is one commit — either everything
  lands or nothing does (`db.session.rollback()` on exceptions). Skipped
  rows (no `public_ip`) get logged in the result, not silently dropped.
* **Synthetic provider.** Fleet nodes need a parent provider FK. The
  migration creates `legacy-import` once (`FleetProvider`, `cost_model="open"`)
  and hangs every imported node off it. Operators can rename / retag from
  «إعدادات البنية» afterwards.
* **Field mapping (legacy → fleet):**
  | Legacy `chr_nodes` column | Fleet `fleet_chr_nodes` column | Notes |
  | --- | --- | --- |
  | `name` | `name` | suffix `legacy-<id>` when blank to satisfy `(provider_id, name)` uniqueness |
  | `public_ip` | `public_ip` | required — rows with no IP are skipped |
  | `management_ip` | `wg_mgmt_ip` | falls back to `public_ip` so the NOT NULL holds |
  | (none) | `wg_mgmt_pubkey` | seeded with marker `legacy-import-needs-pubkey` — operator must fill this in before the fleet poller can talk to the box; node stays `provisioning` until then |
  | `routeros_port` | `routeros_api_port` | defaults to 8443 (fleet default; production reserves 443 for SSTP) |
  | `routeros_user` | `routeros_api_user` | verbatim |
  | `routeros_password_enc` | `routeros_api_password_enc` | Fernet ciphertext is the same encoding — no re-encryption needed |
  | `capacity_mbps` | `link_speed_mbps` | direct copy |
  | `max_active_sessions` (`or max_reserved_mbps` fallback) | `max_sessions` | required NOT NULL |
  | `status='active'` | `status='up'` | lifecycle remap (see `_legacy_status_to_fleet`) |
  | `status='pending'` | `status='provisioning'` | — |
  | `status='maintenance'` | `status='degraded'` | — |
  | `status='decommissioned'` | `status='disabled'` | — |
  | `last_seen_at` | `last_seen_at` | direct copy |
* **Allocation rewrite.** After all imports succeed, every
  `service_allocations` row whose `chr_node_id` is in the migration's
  legacy→fleet map gets rewritten to point at the new fleet id. Rows whose
  legacy node was SKIPPED (no IP) are counted in
  `orphan_allocations_after` so the UI can warn the operator.
* **Backout plan.** Until step 6 runs, the legacy `chr_nodes` rows are still
  there. If the migration introduces a bad row, the operator can DELETE the
  fleet rows that carry `legacy_chr_node_id` (or just truncate the
  `legacy-import` provider's nodes) and `chr_node_id` values can be re-pointed
  manually. Audit log row `fleet_consolidation_run` carries the full JSON
  result for forensic replay.

---

## Step 6 — what was removed (DONE, this branch)

The owner decided everything was experimental and approved the destructive
removal. The full list of what landed in `feat/fleet-consolidation-step6`:

* **Tables dropped** (idempotent heal in `app/__init__.py`):
  * `chr_nodes`
  * `chr_node_metrics`
  * Column `proxy_realm_routes.allowed_chr_node_ids_json`
* **Service-allocation FK repointed**: `service_allocations.chr_node_id` is
  renamed to `fleet_chr_node_id` (NULL-out before rename so any stale legacy id
  can never accidentally collide with an unrelated fleet id), and the model FK
  now points at `fleet_chr_nodes(id)`. Old rows survive with NULL.
* **Python models deleted** in `app/models.py`: `ChrNode`, `ChrNodeMetric`.
* **Properties deleted** on `ProxyRealmRoute`: `allowed_chr_node_ids` (getter +
  setter). Only `allowed_fleet_chr_node_ids` survives.
* **Services deleted**: `app/services/chr_metrics.py`,
  `app/services/fleet_consolidation.py`.
* **Admin views deleted** in `app/admin/infra_routes.py`: `chr_nodes_list`,
  `chr_node_create`, `chr_node_detail`, `chr_node_edit`, `chr_node_poll`,
  `chr_nodes_poll_all`, `consolidation_page`, `consolidation_run`. Legacy
  URLs now return 404.
* **Templates deleted**: `app/templates/admin/infra/chr_nodes_new.html`,
  `chr_detail_new.html`, `consolidation.html`,
  `_partials/_legacy_chr_banner.html`, the orphan `proxy_routes.html`.
* **Form scrubs**: `proxy_routes_new.html` no longer shows the «عقد
  CHR-Console التقليدية» allow-list section; `customer_service_allocations.html`
  now reads fleet props (`link_speed_mbps`, `public_ip`, `a.fleet_chr_node`)
  instead of the legacy `n.location` / `n.max_reserved_mbps` /
  `a.chr_node`. The dead `chr_node_id` dropdown in `vpn_tunnels_new.html`
  is gone — the VPN-tunnel form will get a real fleet picker as part of
  the settings#chr singleton retirement work.
* **`app/api/proxy_api.py`**: `routing_table()` is now fleet-only — the dual
  source union (`ChrNode.query.all() + FleetChrNode.query`) was replaced by
  the fleet query alone. `wg_data_ip` derivation and the per-realm
  `allowed_chr_ips` resolver are unchanged; every published entry carries
  `source="fleet"`. `/api/proxy/chr-nodes` was rewired to read
  `FleetChrNode` (enabled + not drain + status != disabled). Existing
  routing-table tests (`tests/fix_routing_table/`) updated and all green.
* **`fleet/ui/troubleshoot_view.py`**: `_routing_table_chr_entries()` dropped
  the legacy fallback so the troubleshooter compares each fleet node against
  the actual published shape only.

### Schema-heal block

`app/__init__.py`'s `ensure_schema_compatibility` got the following idempotent
block (after the FleetChrNode column heal). Every operation runs only when
the legacy artefact is still present, so a fresh DB via `db.create_all()`
sees a quiet no-op.

```
if "service_allocations" in tables:
    sa_cols = inspect(...).get_columns("service_allocations")
    if "chr_node_id" in sa_cols and "fleet_chr_node_id" not in sa_cols:
        UPDATE service_allocations SET chr_node_id = NULL
        ALTER TABLE service_allocations RENAME COLUMN chr_node_id TO fleet_chr_node_id

if "proxy_realm_routes" in tables and "allowed_chr_node_ids_json" in cols:
    ALTER TABLE proxy_realm_routes DROP COLUMN allowed_chr_node_ids_json

if "chr_node_metrics" in tables: DROP TABLE chr_node_metrics
if "chr_nodes" in tables: DROP TABLE chr_nodes   # CASCADE retry on Postgres
```

### Verification

* `python -c "import app; a = app.create_app()"` boots cleanly. Both required
  log lines (`SQLite database resolved to …`, `fleet.metrics_poller: background
  worker started`) appear, and 328 routes register (was 336 on the step-5
  merge — the eight removed = 6 legacy chr-node routes + 2 consolidation routes).
* `tests/test_fleet_consolidation.py` — 9/9 passing (post-removal contract).
* `tests/fix_routing_table/` — 61/61 passing.
* Smoke: every surviving consolidated page (fleet dashboard, system-health,
  proxy-routes, service-allocations, radius-instances, chr console, speed
  profiles) renders 200; `/admin/infra/chr-nodes` and
  `/admin/infra/consolidation` both 404.
* Routing-table JSON proof — `chr_nodes[]` carries every fleet node tagged
  `source="fleet"` with `public_ip` + `wg_data_ip` (10.99.0.X → 10.98.0.X).

### Out of scope — settings#chr singleton retirement

See the separate scope report attached to the PR — every caller of
`chr_settings.resolved()` (access-connections / chr console / speed-profiles /
WG peer provisioning / tunnel quota throttle) needs a per-FleetChrNode rewire
before the singleton can go. That work is the next dispatch.

## Step 6 — original plan (kept for history)


Step 6 is purely additive removal: once every operator has run the migration
and the legacy tables are empty (or at least every still-referenced row has
a fleet twin), the following land in ONE commit.

### Things to delete

1. **Database tables.** Drop in this order (FK from `service_allocations`
   first):
   - `chr_node_metrics`
   - `chr_nodes`

   Drop method: write an idempotent block in `ensure_schema_compatibility`
   (`app/__init__.py`) that:
     - asserts `ChrNode.query.count() == 0` (or `legacy_chr_node_id` is
       set on a fleet row for every still-allocated `chr_node_id`);
     - issues `DROP TABLE` for both. SQLite needs the FK constraint dropped
       implicitly via `PRAGMA foreign_keys`; PostgreSQL needs `CASCADE`.

2. **Legacy allow-list column on proxy routes.** Drop
   `proxy_realm_routes.allowed_chr_node_ids_json`. The fleet column
   `allowed_fleet_chr_node_ids_json` stays and becomes the only source.
   Drop method: same heal block.

3. **Schema-heal anchor column.** Drop `fleet_chr_nodes.legacy_chr_node_id`
   in the same migration that drops the legacy tables — at that point its
   only job (preventing duplicate imports) is moot.

4. **Python models.** Delete classes `ChrNode` and `ChrNodeMetric` from
   `app/models.py` (lines 1484–1610 today). Update any export lists.

5. **Admin views.** From `app/admin/infra_routes.py`:
   - `chr_nodes_list` (GET `/chr-nodes`)
   - `chr_node_create` (POST `/chr-nodes/create`) — currently the deprecated
     short-circuit
   - `chr_node_detail` (GET `/chr-nodes/<id>`)
   - `chr_node_edit` (POST `/chr-nodes/<id>/edit`) — short-circuit
   - `chr_node_poll` (POST `/chr-nodes/<id>/poll`) — short-circuit
   - `chr_nodes_poll_all` (POST `/chr-nodes/poll-all`) — short-circuit
   - Both consolidation routes (`consolidation_page` / `consolidation_run`)
     can stay or be removed; they degrade naturally (the page would show
     "0 legacy nodes").

6. **Templates.**
   - `app/templates/admin/infra/chr_nodes_new.html`
   - `app/templates/admin/infra/chr_detail_new.html`
   - `app/templates/_partials/_legacy_chr_banner.html`

7. **Migration service + tests.**
   - `app/services/fleet_consolidation.py` (or keep as a stub for audit
     trail; the active code becomes dead).
   - `tests/test_fleet_consolidation.py` migration cases — keep the ones
     that pin sidebar/banner/relabel behavior, drop the migration cases.

8. **`app/api/proxy_api.py`.** ⚠️ **Coordinated with another agent.** Replace
   the dual-source union (`ChrNode.query.all() + FleetChrNode.query`) with a
   fleet-only query, and drop the `legacy` / `fleet` source tag from the
   response payload. **Do NOT do this in step 5's branch** — the
   `fix/fleet-deterministic-onboarding`-aligned routing-table fix owns
   `proxy_api.py` until it merges. Coordinate when scheduling step 6.

9. **Services that still import `ChrNode`.** Grep before deleting:
   ```
   grep -rn "ChrNode\b" app/ fleet/ tests/
   ```
   At the time of writing:
   - `app/services/chr_metrics.py` (`_collect_one`, `collect_all_nodes`)
     — DELETE; replaced by `fleet/health/metrics_poller.py`.
   - `app/services/allocation_enforcer.py` if it references `ChrNode` —
     verify and rewire to `FleetChrNode`.
   - `app/admin/infra_routes.py` (proxy routes form) — drop the
     legacy allow-list field.

### Pre-flight checks step 6 must do

Before deleting anything, the heal block should bail with a loud
`RuntimeError` if any of these is true:
- `ChrNode.query.count() > 0` AND not every row has a matching
  `FleetChrNode.legacy_chr_node_id` stamp. This means the operator never ran
  the migration.
- Any `ServiceAllocation.chr_node_id` does not correspond to a `FleetChrNode.id`.
  (Either the row was rewritten correctly, or it's an orphan that needs the
  operator's attention.)

Both can be wrapped in a single check using
`app.services.fleet_consolidation.run_migration(dry_run=True)`'s return value:
the run must show `legacy_total == skipped_existing` (every legacy row has
already been imported) AND `orphan_allocations_after == 0` AND `error is None`.

### Order of operations on a live DB

1. Tag the panel: `git tag pre-consolidation-step-6`.
2. Drain traffic from the panel for a few seconds (no-op for SQLite,
   important for PostgreSQL deployments under load).
3. Deploy the step-6 commit. Startup heal runs the pre-flight check and the
   `DROP TABLE` block.
4. Verify `/admin/fleet/` renders, `/admin/infra/proxy-routes` works, and
   `/api/proxy/routing-table` returns the same node count as before.
5. Run the full pytest suite against the live DB schema (`pytest -k consolidation`
   should still pass — the cases that survived).
6. Delete the `pre-consolidation-step-6` tag once a few days pass and no
   regressions surface.

---

## Open questions for the next dispatch (not blockers)

- **WireGuard mgmt pubkey for imported rows.** The migration seeds
  `legacy-import-needs-pubkey` as a placeholder. We should add a yellow pill
  on the fleet dashboard for any node where the pubkey starts with
  `legacy-import-needs-` so the owner knows where to click.
- **`chr_settings` (singleton) phase-out.** Long term it should be a thin
  shim over a chosen FleetChrNode row — until then we keep both, and the
  cross-ref banner on the fleet dashboard surfaces overlap.
- **Default `weight=1` on imported nodes.** Operators with capacity
  hierarchy in the legacy `max_reserved_mbps` might want this proportionally
  scaled. Easy follow-up if requested.
