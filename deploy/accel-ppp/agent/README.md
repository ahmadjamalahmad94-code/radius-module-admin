# radius-vps-agent

On-VPS executor for **accel-ppp DATA connections** (design phase 2c). Installed
to `/opt/radius-vps-agent` by `../setup-radius-vps.sh`.

## What it does

| Job | Entry | Real OS call (behind a seam) |
|---|---|---|
| Reconcile WG peers to the panel's desired set | `VpsAgent.reconcile_once` / `serve` | `wg show/set …`, `tc …` |
| Apply a WireGuard DATA peer | `VpsAgent.apply_wireguard_peer` | `wg set <iface> peer …` |
| Per-peer 5 Mbit cap (collision-free classid) | `build_peer_shaper_argv` + `ClassidAllocator` | `tc class/qdisc/filter …` (HTB) |
| Read live sessions | `VpsAgent.list_active_sessions` | `accel-cmd show sessions` |
| Issue cert (challenge auto/http01/dns01) | `VpsAgent.ensure_cert` | `certbot certonly …` |
| Reload after renewal | `VpsAgent.reload_accel_ppp` | `accel-cmd reload` → `systemctl …` |
| WG data-port clash check | `VpsAgent.check_wg_port` | `ss -lun` |

## Design: testable seams

Every OS call goes through `CommandExecutor`, every DNS lookup through
`Resolver`, every port-80 probe through `Port80Prober`, and the desired peer set
through `PeerSource`. Production uses `System*`; tests use `Fake*` + a
`StaticPeerSource` and inject `sleep`/`monotonic` so the loops run instantly.

All logic — argv building, `accel-cmd`/`ss` parsing, the classid allocator, the
DNS-wait + challenge selection, the reconcile loop — is **pure/seam-driven** and
unit-tested in `tests/test_vps_agent.py`. CI never touches the OS or network.

## Reconcile loop (safe-by-default)

`--serve` fetches the desired peers from the panel contract and each tick:
adds/updates missing peers, **removes only peers it added** (never operator
peers), and is a **no-op when in sync**. Each peer gets a **unique** tc classid
(no last-octet collisions); the htb root qdisc is ensured once (add-when-absent,
never `replace`, so existing peers' classes survive).

## Status

Implemented + tested without a live VPS: reconcile loop, classid allocator,
cert challenge selection (HTTP-01 / DNS-01 fallback), WG-port clash check.

**LAB-PENDING** (genuinely needs a live box — flagged in code, see `../RUNBOOK.md`):
exact `tc` ingress/egress direction; the `accel-cmd show sessions` column set on
the pinned build; the peer-source endpoint path + `X-Proxy-Token` HMAC auth; and
the RADIUS-side knobs (Filter-Id form, attr 227, Disconnect NAS IP).

Per design §1 this executor may ultimately live in the **`radius-module`** repo;
it sits here for now so the activation script has something concrete to install.

## Run locally

```bash
python3 vps_agent.py --list-sessions                       # parse accel-cmd output
python3 vps_agent.py --check-wg-port 51830                  # WG port clash check
python3 vps_agent.py --ensure-cert --subdomain c.x --vps-ip 1.2.3.4 --email a@b.com
python3 vps_agent.py --serve --peer-source-url https://panel/api/proxy/wg-peers
```
