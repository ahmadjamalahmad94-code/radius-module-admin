# CHR Provisioning — Rollback Guard, wg-data Peering & REST Auth

**Branch:** `fix/chr-rollback-wgdata-rest`
**CHR:** chr-vpn-2, RouterOS 7.21.x
**Status before:** script imports + executes to the end ("Script file
loaded and executed successfully") but fails validation for three real
reasons. All three are fixed in the GENERATOR / panel — never a one-off
.rsc patch.

This supersedes the narrower "REST-500" note; it is the definitive
root-cause list for the post-`/import` validation failures.

---

## Issue 1 — rollback guard fired forever

### Symptom
Every 3 minutes the CHR logged:
```
hobe-fleet: rollback fired (no cancel within 3m)
executing script from scheduler (hobe-fleet-rollback) failed
Script Error: missing value(s) of argument(s) password
```
~20 times (08:54→09:54), never restoring, never self-removing.

### Root cause
The §0a armed scheduler was:
```
/system scheduler add comment=hobe-fleet-rollback-guard interval=3m \
  name=hobe-fleet-rollback \
  on-event=":log warning \"...\"; /system backup load name=hobe-fleet-pre-apply" \
  policy=read,write,policy,test,password,sensitive
```
Two defects:
1. `/system backup load name=X` requires a `password` argument in
   scheduler/non-interactive context → errors every fire.
2. `interval=3m` makes it **recurring** — even a valid command would
   repeat every 3 minutes forever.

### Fix (generator, `chr_unified.rsc.j2` §0a)
One-shot, valid, self-removing, bounded:
```
on-event=(":log warning \"...one-shot\"; \
  /system scheduler remove [find name=hobe-fleet-rollback]; \
  :do { /system backup load name=hobe-fleet-pre-apply password=\"\" } \
  on-error={ :log error \"...restore FAILED... NOT retrying...\" }")
```
* The on-event's **first action removes the scheduler**, so it can
  never fire twice (removing the currently-running scheduler does not
  abort the running event).
* The restore uses the correct **`password=""`** non-interactive form.
* The restore is wrapped in `:do/on-error` — a failed/unsupported
  `backup load` logs a precise reason and **stops** (already
  self-removed). Break-glass access stays active for manual recovery.
* On validation **success** the §12 gate removes the scheduler (and the
  backup file). Now that the script reaches the end, this fires.
* On **local** validation failure the guard is left armed (one-shot).

---

## Issue 2 — wg-data no handshake to 10.98.0.1 (the onboarding blocker)

### Symptom
Validation failed with `(4) wg-data no handshake AND no ping to
10.98.0.1`, which (pre-fix) left the broken rollback armed.

### Root cause
The CHR's **local** wg-data config was correct (interface 10.98.0.12/24,
peer endpoint 178.105.251.67:51821, proxy pubkey 8wYy…, RADIUS client
toward 10.98.0.1). The handshake never completes because the **proxy**
has no WireGuard peer for this CHR's wg-data pubkey (allowed-ips
10.98.0.12/32).

**Smoking gun:** the script logged the wg-mgmt + wg-users pubkeys but
**never the wg-data pubkey**, so the operator had no way to confirm the
key the proxy must trust.

The panel already mints + persists the wg-data pubkey on the node row
(`fleet_chr_nodes.wg_data_pubkey`, set at `generate_keys`) and publishes
it at `GET /api/proxy/wg-peers` with `allowed_ips: ["10.98.0.12/32"]`
(`fleet/sync/peers.py::desired_proxy_peers`). The proxy is responsible
for polling that endpoint and adding the peer — the panel-side contract
was already in place.

### Fix (generator + panel)
1. **Log the wg-data pubkey on the CHR** (`chr_unified.rsc.j2`, §2c),
   mirroring the wg-mgmt log line, naming the allowed-ips the proxy must
   use. Closes the diagnostic loop.
2. **Reclassify the §12 handshake checks (2)+(4) as REMOTE-PENDING, not
   rollback-gating.** A missing handshake when local config is correct
   means the panel/proxy hasn't added this CHR's peer **yet** — a
   remote-pending state that self-heals (panel autosync for wg-mgmt;
   proxy `wg-peers` poll for wg-data). Reverting in that case would
   **destroy correct local config** the remote side is about to talk to.
   The rollback now cancels on **LOCAL checks only**; the pending-remote
   state is reported (`hobePendingRemote`) but never arms the revert.
3. **Panel-side preflight** (`fleet/sync/preflight.py::preflight_wg_data`)
   classifies, from the panel DB (no network), whether a CHR's wg-data
   peer will be published + is well-formed + unique → `ok` /
   `pending_remote` / `blocked`. Catches a missing pubkey or a
   non-derivable/colliding 10.98.0.X/32 BEFORE export.

### Validation classification (CHR side)
| Check | Class | Effect |
|---|---|---|
| (1) wg-mgmt endpoint non-empty | LOCAL | rollback-gating |
| (2) wg-mgmt handshake/ping | **REMOTE-PENDING** | reported, never reverts |
| (3) wg-data endpoint non-empty | LOCAL | rollback-gating |
| (4) wg-data handshake/ping | **REMOTE-PENDING** | reported, never reverts |
| (5) www-ssl enabled/scoped | LOCAL | rollback-gating |
| (6) firewall api-ssl accept | LOCAL | rollback-gating |
| (7) firewall drop-last | LOCAL | rollback-gating |
| (8) no-public-radius drop | LOCAL | rollback-gating |
| (9)(10) break-glass scripts | LOCAL | rollback-gating |
| (11) break-glass auto-close | LOCAL | rollback-gating |
| (12) winbox not wide-open | LOCAL | rollback-gating |

---

## Issue 3 — "login failure for user hobe-panel via api"

### Symptom
CHR log: `login failure for user hobe-panel via api`. (RouterOS labels
**REST** auth failures "via api"; `api`/`api-ssl` are disabled — this is
the REST poll on www-ssl:8443 being **auth-rejected**, which the
troubleshoot page surfaced as "REST 500 / Internal Server Error".)

### Root cause
**Smoking gun:** the dump showed `/user set hobe-panel comment=... group=...`
— group set, **no password**. The §11 user provisioning used ADD-OR-SET
where the SET branch (user already exists) deliberately omitted
`password=`, on the theory that the first `/user add` already pinned it.
That theory is wrong: a `hobe-panel` row can pre-exist from an earlier
import with a **different** generated password, or the panel rotated the
stored secret — and the SET branch then left the CHR password **stale**,
diverging from what the panel dials with over REST.

### Fix (generator, `chr_unified.rsc.j2` §11)
Set `password="{{ API_PASSWORD }}"` in **both** the add AND set
branches. The panel is the single source of truth
(panel-mints-panel-knows), so the script **converges** the CHR password
to the panel-known secret on every import. Guarantees:
```
CHR hobe-panel password == panel-stored secret == panel REST creds
```

### API-vs-REST audit
Confirmed (this round + the previous one): the panel speaks **only**
REST over `https://<wg_mgmt_ip>:8443/rest/` via
`app/services/routeros_client.py`. There is **no** binary RouterOS-API
client anywhere in the panel. The metrics collector now logs an
explicit `transport=REST url=https://host:port/rest/` line on auth
failure (`fleet/health/routeros_collector.py`) so a CHR-side "via api"
failure is unambiguously matched to a panel-side REST poll, not a legacy
api probe. The historical 8729 (binary api-ssl) default that produced
earlier noise was already fixed + self-healed in main.

---

## Files changed
| File | Change |
|---|---|
| `fleet/registry/templates/chr_unified.rsc.j2` | §0a rollback redesign; §2c wg-data pubkey log; §12 checks 2+4 → remote-pending + success/fail block reports pending; §11 password convergence in both user branches |
| `fleet/sync/preflight.py` | NEW — `preflight_wg_data(node)` panel-side readiness gate |
| `fleet/health/routeros_collector.py` | explicit REST-transport log on auth failure |
| `tests/fleet_p3/test_rollback_wgdata_rest.py` | NEW — rollback/wgdata/rest + preflight regression |
| `tests/fleet_p3/test_wireguard_provisioning_fixes.py` | updated check 2/4 classification |
| `tests/fleet_p3/test_group_user_reimport_idempotent.py` | reversed the no-rotate-password contract |
| `docs/fleet/CHR_PROVISIONING_ROLLBACK_AND_VALIDATION.md` | this doc |

## Regen steps for the owner
1. Pull `main`.
2. On the dashboard, open chr-vpn-2 → «عرض السكربت» / «تنزيل .rsc» (the
   regenerated script reflects all three fixes).
3. `/import file=chr-vpn-2.rsc` on the CHR while connected via WinBox —
   no `/ip service get` crash (foreach-skip-dynamic held), no infinite
   rollback, password converges.
4. Expect: validation PASSES locally; if the proxy hasn't yet added the
   wg-data peer, the dump shows a PENDING-remote line (not a failure,
   not a revert). The wg-data handshake appears once the proxy polls
   `/api/proxy/wg-peers`.
5. Confirm in `/log print where message~"hobe-fleet"`: the new
   `this CHR wg-data pubkey ... = <key>` line is present.
