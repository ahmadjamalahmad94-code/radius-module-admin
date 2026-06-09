# CHR Fleet — documentation index (panel side)

The **canonical architecture blueprint** for the CHR Fleet lives in the
`radius-proxy` repository, on branch **`arch/chr-fleet-blueprint`**
(commit **`54646fb`**) — 10 design docs authored by the architect agent.

That repo is the source of truth for the cross-component design. We keep this
local `docs/chr_fleet/` folder in the **panel** repo because the panel owns most
of the fleet code (`fleet/*`, the ingest APIs, the brain, DNS and control layers),
and we want the contracts we implement against to be versioned alongside that code.

> The panel repo cannot `git show` another repo's branch, so the 10 blueprint docs
> are **not** copied in verbatim here. To read them, check out
> `radius-proxy@arch/chr-fleet-blueprint` (commit `54646fb`). If/when we vendor a
> snapshot, it will land in this folder.

## Frozen contracts implemented here

- [`../contracts/fleet_api.md`](../contracts/fleet_api.md) — **Phase 1 frozen API
  contracts**: telemetry ingest, placement ingest, CoA/Disconnect, and the internal
  `fleet/*` interface signatures. Later phases implement against these shapes.

## Code skeleton (Phase 1)

- `fleet/config.py` — all fleet tunables with documented defaults.
- `fleet/{registry,health,brain,dns,control,notify}/` — package skeletons, one
  responsibility each (see each package docstring).

## Phase map (panel side)

| Phase | Scope |
|-------|-------|
| **1 (this)** | Freeze contracts + config + package skeleton. No behaviour. |
| 2+ | Implement registry → health → brain → dns → control → notify against the frozen contracts. |
