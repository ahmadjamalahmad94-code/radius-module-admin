# Zero-touch fleet onboarding + auto peer sync

Adding/syncing a CHR is now fully panel-driven — no manual WireGuard hand-peering
on three places, no silent panel-key drift, and a live staged progress view that
shows where the system is working, what's done, and where (and why) it stopped.

Branch: `feat/fleet-zero-touch-sync`. Subsystem: `fleet/sync/`.

## The problem this fixes

A CHR needed manual WireGuard peering in **three** places and keys drifted:

- CHR `wg-mgmt` ↔ panel `wg-mgmt` (panel must trust the CHR's pubkey; CHR must
  trust the panel's pubkey).
- CHR `wg-data` ↔ proxy `wg-data` (proxy must trust the CHR's wg-data pubkey).

The panel **already mints + stores every CHR's keypairs**, so it already knows
every pubkey. The gaps were: (a) auto-applying peers, and (b) a **stable** panel
key. When the panel key changed, nothing cascaded — already-pushed CHRs kept the
old key and the next health run reported `panel_key_mismatch` with no flag to
say which nodes were stale.

## 1. Key stability (single source of truth)

The panel `wg-mgmt` keypair is the single stable source of truth. It is **never**
auto-regenerated — only the two explicit super-admin routes
(`/infrastructure/panel-keypair`, `/infrastructure/panel-pubkey`) change it, and
a test (`tests/fleet_zero_touch/test_key_stability.py`) locks down that no
onboarding / render / resync path regenerates it.

When the key **does** legitimately change, the route fires a **cascade**
(`fleet/sync/keys.flag_fleet_needs_reimport`): every node is flagged
`needs_reimport` and a fleet re-sync job is created so the owner immediately sees
live staged progress instead of silent drift. A node's `needs_reimport` flag is
cleared automatically the moment its `wg-mgmt` handshake proves it trusts the
current panel key (sync stage 5).

## 2. Auto peer registration

- **Panel host (wg-mgmt).** `fleet/sync/peers.desired_panel_peers()` derives the
  desired peer set from `fleet_chr_nodes` (one `10.99.0.x/32` per eligible node).
  `fleet/sync/wg_apply.apply_panel_peers()` applies it via the scoped root helper
  (below). **Safe by default:** if the helper isn't installed, this is a reported
  no-op — the wg-mgmt handshake stage still surfaces the real on-host truth.
- **Proxy host (wg-data).** The proxy is external; the panel **publishes** the
  desired wg-data peer set over `GET /api/proxy/wg-peers` for a coordinated proxy
  agent to apply. Eligibility mirrors `/api/proxy/routing-table` exactly.

The CHR `wg-data` pubkey is now denormalized onto `fleet_chr_nodes.wg_data_pubkey`
(written at onboarding, backfilled for old rows from the onboarding job refs).

## 3. The privileged-wg mechanism

The app runs unprivileged (`User=hoberadius`) and has no standing root. Peer
application is delegated to **one** tiny, scoped root helper:

```
/usr/local/sbin/hobe-wg-sync        # deploy/zero_touch/hobe-wg-sync
```

installed **once** by `deploy/zero_touch/install_wg_helper.sh`, with a scoped
sudoers rule (`/etc/sudoers.d/hoberadius-wg-sync`) letting `hoberadius` run only
`hobe-wg-sync apply|show` with NOPASSWD. The helper:

- manages **only** the `wg-mgmt` interface (hardcoded allow-list),
- never reads/writes the `[Interface]` private key,
- validates every pubkey (44-char base64) and allowed-ip (must be inside
  `10.99.0.0/24`) before applying,
- reconciles peers (`wg set ... allowed-ips`, removes stale) and persists with
  `wg-quick save`.

That is the entire privileged surface — one command, one-time install.

## Proxy contract: `GET /api/proxy/wg-peers`

Auth: the same `X-Proxy-Token` HMAC as the rest of `/api/proxy/*`. The
`routing-table` contract is unchanged (still carries `wg_data_ip` +
`allowed_chr_ips`); this is an additive, sibling endpoint.

The proxy reconciler reads `data["peers"]` and expects a **top-level list**, so
`peers` is the canonical contract field; each peer is exactly
`{name, public_key, allowed_ips, endpoint}` with `endpoint` always `null`.

```json
{
  "ok": true,
  "generated_at": "2026-06-11T12:00:00Z",
  "panel_wg_pubkey": "PANEL_MGMT_PUBKEY=",
  "interface": "wg-data",
  "listen_port": 51821,
  "peer_count": 1,
  "peers": [
    {
      "name": "chr-vpn-1",
      "public_key": "CHR_WG_DATA_PUBKEY=",
      "allowed_ips": ["10.98.0.11/32"],
      "endpoint": null
    }
  ]
}
```

Proxy obligations: treat `peers` as the **complete desired set** for its
`wg-data` interface (add missing, remove peers not listed). `allowed_ips` is
authoritative; `endpoint` is `null` because the proxy is the wg-data listener —
CHRs dial in, so no per-peer endpoint is needed.

## The live staged progress UI

Page: `/admin/fleet/sync/` («إعادة مزامنة الأسطول» from the dashboard hero). The
backend `SyncJob` (`fleet_sync_jobs`) drives a per-node, eight-stage pipeline.
No background workers: the browser creates a job, then polls
`POST /jobs/<id>/tick`, which runs **one real check** per call and returns the
full state. The bar only moves when real state changes — no fake progress.

| # | Stage | Real check |
|---|-------|-----------|
| 1 | توليد المفاتيح | node has `wg_mgmt_pubkey` + `wg_data_pubkey` |
| 2 | تسجيل peer على اللوحة | desired panel set + helper apply readback |
| 3 | تسجيل peer على البروكسي | node in `/api/proxy/wg-peers` publish set |
| 4 | توليد/تطبيق السكربت | render with current panel pubkey; bindings complete |
| 5 | مصافحة wg-mgmt | `verify_node_wg_identity` (clears `needs_reimport` on ok) |
| 6 | مصافحة wg-data | CHR REST wg-data peer last-handshake toward proxy |
| 7 | النشر بجدول التوجيه | routing-table recognition |
| 8 | فحص RADIUS | troubleshoot RADIUS-reachability hint |

Stage states: `pending` / `running` (animated spinner on the first pending stage
of the active node) / `done` / `warn` (ran, not fully confirmable — non-blocking)
/ `failed` (hard — stops the node's pipeline so you see exactly where it stopped)
/ `blocked` (a prior hard failure stopped this stage).
