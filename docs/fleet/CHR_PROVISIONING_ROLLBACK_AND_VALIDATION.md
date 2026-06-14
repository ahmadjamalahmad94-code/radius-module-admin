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

---

## Follow-up — REST wireguard read PERMISSION (branch `fix/chr-rest-wireguard-permission`)

After the password converged (REST now authenticates), one blocker
remained from the live troubleshoot:

```
GET /rest/interface/wireguard/peers
→ HTTP 500 {"detail":"std failure: not allowed (9)","error":500,"message":"Internal Server Error"}
```

`std failure: not allowed (9)` is a RouterOS **permission** denial
(authenticated but **un**authorized; RouterOS wraps permission errors as
HTTP 500). The `hobe-panel` group had `read,write,sensitive,reboot,
rest-api` — enough to read `system/resource` etc., but **not** to read
the secret-bearing `/interface/wireguard/peers` menu over REST.

### Root cause
RouterOS REST is built on the **same API permission layer** as the
binary API. Reading the wireguard peer/interface menus (which carry key
material) over REST is gated on the **`api` policy** in addition to
`read` + `sensitive` + `rest-api`. General reads (system/resource) don't
require it, which is why only the wireguard path failed.

### Fix
1. **Generator §11** — grant the group the `api` policy:
   `read,write,sensitive,reboot,rest-api,api` (both the add and set
   branches). **This does NOT widen the attack surface**: the binary
   `api` + `api-ssl` **services** stay `disabled=yes` at `/ip service`,
   so no 8728/8729 session can be established regardless of the policy
   bit — it only governs what the already-authenticated REST session may
   read.
2. **Panel hardening** (`app/services/routeros_client.py` +
   `fleet/health/wg_verify.py`) — the wireguard REST reads now request a
   non-secret `.proplist` (`public-key,comment,last-handshake,
   current-endpoint-address,endpoint-address,rx,tx` for peers;
   `name,public-key` for the interface). Private/preshared keys never
   traverse REST. `.proplist` is a field selector, not the server-side
   `?interface=` filter that earlier 500'd, so the fetch-all-then-filter
   pattern is preserved.

### The 12:19 "login failure ... via api" line
A single `login failure for user hobe-panel via api` was logged at
12:19:01, ~46s after the password converged at 12:18:15. Analysis:
**transient cert-swap race** — during `/import` the script runs
`/user set ... password=`, re-signs `hobe-fleet-api-cert`, and restarts
`www-ssl`; a poll landing in that window is briefly refused. There is
**no second wrong-credential code path**: both `wg_verify` and the
metrics collector resolve credentials through the same
`credentials_for(node)` (one Fernet-encrypted secret on the node row),
and the steady state afterward is a *permission* error, not an auth
error — proving the creds are accepted. RouterOS labels REST auth
failures "via api"; api/api-ssl services are disabled, so this is REST,
not a legacy probe.

Mitigation: `wg_verify` now retries the wireguard read **once** on a
bare `auth_failed` after a 1.2s backoff (operator-facing troubleshoot
only — turns a cert-swap-race false-negative into a pass). Non-auth
errors (the permission case) are **not** retried, so a real failure
surfaces immediately. The background metrics poller self-heals on its
next cadence and needs no retry.

### Verify on 7.21.x
After re-export + re-import, `GET /rest/interface/wireguard/peers`
returns 200 (the group now carries `api`); the troubleshoot wg-mgmt key
check goes green; `/ip service` still shows `api`/`api-ssl` disabled.

---

## wg-data peer-publishing pipeline (branch `fix/wg-data-peer-publish-pipeline`)

### Live evidence
chr-vpn-2 wg-data peer: **no `last-handshake`, rx=0**, tx=5.5KiB; `/ping
10.98.0.1` = 100% loss. The CHR sends WG handshake initiations (tx>0)
but receives nothing back (rx=0) → the **proxy is not responding** → the
proxy has not added this CHR's wg-data peer
(`QyVOMA0/nByaNl9D85VD60xuMFFui90sS1W0IdOuuFE=`, allowed-ips
`10.98.0.12/32`).

### VERDICT — it is a PROXY-DEPLOY gap, not a panel gap

**Does the panel mint the wg-data key or learn it from the CHR?**
It **MINTS** it. `OnboardingService.generate_keys` mints BOTH keypairs
(`data = self.key_provider.generate_keypair()`), vaults the private key,
and persists the public key on the node row
(`fleet_chr_nodes.wg_data_pubkey`). The unified script bakes
`private-key="{{ WG_DATA_PRIVKEY }}"` on `wg-data`, so the CHR never
self-generates the key — its on-device wg-data pubkey is deterministic
from the panel-minted private key and therefore **equals** the panel's
stored `wg_data_pubkey`.

Consequences:
* **NOT a "panel can't learn the key" gap (c).** The panel never reads
  the wg-data key from the CHR, so the `not allowed (9)` REST-permission
  bug is **irrelevant** to wg-data publishing. (That bug only affected
  the wg-mgmt *verification read*, now fixed.)
* **NOT a panel-publish gap (a)** when the row carries the pubkey. Proven
  end-to-end in `tests/.../test_wg_data_peer_publish_pipeline.py`: a
  provisioning node with `wg_data_pubkey` set appears in
  `desired_proxy_peers()` AND in `GET /api/proxy/wg-peers` with
  `public_key=QyVOMA0/…` + `allowed_ips=["10.98.0.12/32"]`.
* **IS a proxy-deploy gap (b).** The panel publishes correctly; the
  **proxy** (separate repo `radius-proxy`, host `178.105.251.67`) must
  POLL `GET /api/proxy/wg-peers` and apply the peer set to its `wg-data`
  interface. The owner deployed the control panel (`be28aa6`/`07a3e43`)
  but the proxy was not pulled+restarted, so its poll loop is stale /
  not applying the new peer.

### Live confirmation on the panel (no proxy access needed)
Open the CHR troubleshoot page — a new row **«نشر peer الـ wg-data
للوكيل (proxy)»** shows, from the panel DB:
`pubkey=QyVOMA0/…… allowed-ips=10.98.0.12/32 will_publish=نعم` (GREEN).
A GREEN row here + rx=0 on the CHR ⇒ the gap is the proxy. (RED here ⇒ a
panel-side gap — fix that first.)

### Remediation for the owner
1. **No re-import needed** for this (the CHR's local wg-data config is
   already correct; the panel already publishes the peer).
2. **Deploy the proxy** on `178.105.251.67` so its wg-peers poll loop
   runs the latest code and applies the peer. Exact commands (confirm
   the repo path + systemd unit name on the proxy host — the proxy lives
   in `radius-proxy@arch/chr-fleet-blueprint`):
   ```bash
   # on 178.105.251.67, as the proxy deploy user:
   cd /opt/radius-proxy            # <-- confirm path
   git pull --ff-only
   sudo systemctl restart radius-proxy   # <-- confirm unit: `systemctl list-units | grep -i proxy`
   sudo systemctl status  radius-proxy
   # then watch it poll + apply:
   journalctl -u radius-proxy -f | grep -i "wg-peers\|wg-data\|peer"
   ```
3. **Verify the proxy actually pulled the peer set** (from the proxy
   host) — this also rules out an HMAC/secret mismatch:
   ```bash
   # RADIUS_PROXY_SHARED_SECRET must match the panel's
   # /admin/settings/platform value:
   curl -s -H "X-Proxy-Token: <ts>:<nonce>:<hmac>" \
        https://<panel-host>/api/proxy/wg-peers | jq '.peers[] | select(.public_key|startswith("QyVOMA0"))'
   # expect: {"public_key":"QyVOMA0/…","allowed_ips":["10.98.0.12/32"],"endpoint":null}
   wg show wg-data            # expect a peer with that pubkey + 10.98.0.12/32
   ```
4. **Proxy host network checks** (rx=0 can also be a dropped inbound):
   * `wg-data` interface up + listening on **UDP 51821**;
   * host firewall allows inbound **UDP/51821** (`ufw allow 51821/udp`
     or the cloud SG);
   * no stale/duplicate peer already claiming `10.98.0.12/32` (the proxy
     reconciler should treat `peers` as the complete set and remove
     strays — confirm it does).

### Acceptance (verify live after the proxy deploy)
* `wg show wg-data` on the proxy lists `QyVOMA0/…` with a **recent
  handshake**;
* `/ping 10.98.0.1` from the CHR = 0% loss; `/ping 10.98.0.12` from the
  proxy = 0% loss;
* the CHR's wg-data peer shows `last-handshake` + rx>0;
* the panel troubleshoot goes fully green.

### "login failure ... via api"
Already analyzed in the section above — a transient cert-swap race, not a
second credential path; no panel/proxy job uses legacy binary API (the
panel is REST-only over www-ssl:8443, api/api-ssl services disabled). The
`wg_verify` one-shot retry-on-auth_failed (1.2s backoff) absorbs the
post-import transient; the metrics poller self-heals on cadence.

### Files changed (panel side)
| File | Change |
|---|---|
| `fleet/ui/troubleshoot_view.py` | new «نشر peer الـ wg-data للوكيل» row via `preflight_wg_data` — surfaces publish state live (green panel ⇒ proxy gap; red ⇒ panel gap) |
| `tests/fleet_p3/test_wg_data_peer_publish_pipeline.py` | NEW — proves `desired_proxy_peers()` + `/api/proxy/wg-peers` publish the peer; troubleshoot row green/red |

The proxy-side poll/apply lives in the separate `radius-proxy` repo and
is delivered by the deploy command above, not by a panel code change.
