# radius-vps-agent (skeleton)

On-VPS executor for **accel-ppp DATA connections** (design phase 2c). Installed
to `/opt/radius-vps-agent` by `../setup-radius-vps.sh`.

## What it does

| Job | Entry | Real OS call (behind the executor seam) |
|---|---|---|
| Apply a WireGuard DATA peer (RouterOS v7) | `VpsAgent.apply_wireguard_peer` | `wg set <iface> peer …` |
| Per-peer 5 Mbit speed cap | `build_shaper_argv` / `apply_shaper` | `tc qdisc/class/filter …` (HTB) |
| Read live sessions | `VpsAgent.list_active_sessions` | `accel-cmd show sessions` |
| Trigger cert renew | `VpsAgent.renew_cert` | `certbot renew` (+ deploy-hook reloads accel-ppp) |

## Design: the testable seam

Every OS call goes through a `CommandExecutor`:

- `SystemExecutor` — the **only** code that shells out (`subprocess`). Not run in CI.
- `FakeExecutor` — records argv + replays canned output. Used by the unit tests.

All the *logic* — building argv, parsing `accel-cmd` output, Mbit→kbit — is
**pure** and unit-tested in `tests/test_vps_agent.py`. CI never touches the OS.

## Status & where this should live

This is a **skeleton**. It builds the right-shaped commands but several details
are **LAB-PENDING** (marked in the code):

- exact `tc` ingress/egress direction + a collision-free classid allocator;
- WireGuard preshared-key file handling;
- the `accel-cmd show sessions` column set on the pinned accel-ppp build;
- the `--serve` daemon loop (poll the bridge for peer specs, reconcile, report)
  is a stub.

Per design §1 this executor may ultimately live in the **`radius-module`** repo
(co-located with the RADIUS app) rather than here. It sits in this repo for now
so the one-time setup script has something concrete to install.

## Run locally

```bash
python3 vps_agent.py --list-sessions          # parse accel-cmd output
python3 vps_agent.py --dry-run --serve         # prints would-run commands
```
