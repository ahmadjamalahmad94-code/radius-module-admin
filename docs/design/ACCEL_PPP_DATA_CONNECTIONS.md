# accel-ppp DATA connections — design (Phase 1, DESIGN ONLY)

> **Status:** design + artifacts only. NO production code changed, NOT merged
> to main. Branch `design/accel-ppp-data`. Review before Phase 2.

## 0. Goal & scope

Give a subscriber a **DATA VPN** connection (SSTP / PPTP / L2TP) served
**directly by the customer's own RADIUS VPS** running **accel-ppp**, with:

- **Speed cap** 5–10 Mbit/s per connection (RADIUS-driven shaper).
- **Quota** 5 GB with **auto-cutoff** (RADIUS accounting → Disconnect).
- **Per-client TLS** via Let's Encrypt on `clientN.hoberadius.com`
  (DNS-only A record, DNS-01 via Cloudflare API), automated from the panel.
- Owner UX = **ONE BUTTON**; output = a **version-aware, ready-to-paste
  client script** for the subscriber's device/router.

**Boundary (agreed):**
- **DATA connections → customer RADIUS VPS (accel-ppp).** This doc.
- **IP-CHANGE connections → the CHR fleet** (existing SSTP/PPTP on CHR,
  shaped via `/ppp/profile`, proxied RADIUS). **Unchanged by this work.**
- **WireGuard → VPS-native** (unchanged).

The two transports MUST coexist with **zero risk to the live CHR path**.
A per-plan / per-subscriber switch `transport ∈ {vps_accel, chr_mikrotik}`
selects which pipeline provisions a given connection (§4).

## 1. Where the pieces live (repos)

| Concern | Repo | Phase-2 touch |
|---|---|---|
| Panel UI (one button), client-script generator, transport toggle, cert orchestration trigger | **radius-module-admin** | yes |
| RADIUS attribute emission (accel-ppp dialect), quota accounting → Disconnect, ACME/cert automation, accel-ppp config render + reload | **radius-module** (customer RADIUS VPS app) | yes — separate git origin |
| On-VPS execution (write accel-ppp.conf, run certbot, reload accel-ppp, read live sessions) | **NEW `radius-vps-agent`** (does not exist yet) — OR a subpackage inside `radius-module` if we co-locate | yes — **create in Phase 2** |
| Proxy / CHR fleet | radius-proxy / CHR template | **NOT touched** (DATA bypasses the fleet) |

`radius-module` already has the foundations we build on:
- `app/radius/services/freeradius_translator.py` — writes `radcheck` /
  `radgroupreply` / `radreply` (today: `Mikrotik-Rate-Limit`,
  `Acct-Interim-Interval`, `Session-Timeout`, …).
- `app/radius/integration/radius_coa.py` — RFC 5176 **Disconnect-Request**
  + **CoA-Request** (UDP 3799), vendor-attr encoding.
- `app/radius/db/repos/accounting_repo.py` + `bandwidth_repo.py` — octet
  accounting; quota types (`quota_total_mb`, `on_quota_exhaust`).

## 2. End-to-end one-click flow

```
[Owner clicks «إنشاء اتصال بيانات» on a subscriber]
        │  (panel: radius-module-admin)
        ▼
1. Panel resolves the subscriber's customer → customer RADIUS VPS
   (clientN.hoberadius.com) + plan (speed/quota) + transport=vps_accel.
        │  bridge call → radius-module (customer RADIUS app on the VPS)
        ▼
2. radius-module:
   a. ensure ACME cert for clientN.hoberadius.com (DNS-01/Cloudflare) —
      idempotent; renew-aware. Cert lands at the templated ssl paths.
   b. ensure accel-ppp.conf rendered (deploy/accel-ppp/accel-ppp.conf.tmpl)
      with this VPS's pool/secret/cert/subdomain; reload accel-ppp.
   c. write the subscriber's RADIUS rows (accel-ppp dialect, §3):
      radcheck password + radreply Filter-Id (speed) +
      Session-Octets-Limit/Octets-Direction (quota) + Acct-Interim-Interval.
        │  bridge response → panel
        ▼
3. Panel renders a READY-TO-PASTE client script (version-aware, §5):
   server = clientN.hoberadius.com, user/pass, protocol = sstp|pptp|l2tp.
        ▼
4. Subscriber connects → accel-ppp authenticates via local RADIUS →
   Access-Accept carries speed (Filter-Id) → shaper applies →
   accounting interim updates flow → at 5 GB the server sends
   Disconnect-Request → session drops; re-auth refused until reset.
```

**One button** = step 1; everything else is automated + idempotent.

## 3. RADIUS attribute mapping (accel-ppp dialect) + coexistence

accel-ppp is **not** MikroTik: its shaper reads a configurable attribute
(default `Filter-Id`), not `Mikrotik-Rate-Limit`. So a DATA subscriber
needs a **different reply set** than the existing CHR/MikroTik subscriber.
We keep BOTH and select by `transport`.

### 3.1 Speed (shaper)
accel-ppp `shaper` module, `attr=Filter-Id`. Rate value forms accel-ppp
accepts (confirm exact form against the deployed accel-ppp version in the
Phase-2 lab step):

- **Symmetric kbit:** `Filter-Id = "10240"` → 10 Mbit down = up.
- **Down/Up explicit:** `Filter-Id = "10240/10240"` (rx/tx in kbit, from
  the BRAS/subscriber perspective — validate direction in lab).

Panel stores Mbit; radius-module converts Mbit → the accel-ppp form.

### 3.2 Quota (5 GB auto-cutoff)
Two layers, defence-in-depth:

1. **Hint to the NAS (best-effort):** `Session-Octets-Limit` (RADIUS attr
   **227**) = `5_000_000_000`, with `Octets-Direction` (**228**) =
   `0` (total = in+out) — some NAS enforce locally. accel-ppp support for
   227/228 is version-dependent → **do not rely on it alone**.
2. **Authoritative (server-side):** radius-module accumulates octets from
   **Acct interim updates** (`Acct-Interim-Interval = 60`) in
   `accounting_repo`; when `total ≥ quota`, it sends a **Disconnect-Request**
   via the existing `radius_coa.py` to the VPS NAS (127.0.0.1:3799, local).
   Next Access-Request is **rejected** until the quota period resets
   (`on_quota_exhaust = stop`). This is the real cutoff — it works on any
   accel-ppp version.

`on_quota_exhaust = reduce_speed` (optional) → instead of Disconnect, send
a **CoA-Request** changing `Filter-Id` to a throttle rate (radius_coa.py
already encodes CoA).

### 3.3 The reply sets (side by side)

| Purpose | `transport = chr_mikrotik` (EXISTING, unchanged) | `transport = vps_accel` (NEW) |
|---|---|---|
| Speed | `Mikrotik-Rate-Limit = "10M/10M"` | `Filter-Id = "10240"` |
| Quota cap | (CHR-side / panel poll) | `Session-Octets-Limit=5e9` + `Octets-Direction=0` + server-side accounting Disconnect |
| Acct cadence | `Acct-Interim-Interval = 60` | `Acct-Interim-Interval = 60` |
| Auth | radcheck password | radcheck password |
| NAS | CHR via proxy | accel-ppp on the customer VPS (NAS-IP = 127.0.0.1 / VPS) |

**Coexistence rule:** `freeradius_translator` branches on the subscriber/plan
`transport`. The CHR/MikroTik branch is **byte-for-byte unchanged**; the
accel branch is additive. A subscriber is one transport or the other,
never both → no attribute collision in `radreply`.

### 3.4 CoA / Disconnect mapping
- **Cutoff at quota:** Disconnect-Request (Code 40) → NAS drops session.
- **Live speed change:** CoA-Request (Code 43) with new `Filter-Id`.
- **Kick/move:** Disconnect-Request.

All already implemented in `radius_coa.py`; Phase 2 wires the quota watcher
to call it for `vps_accel` sessions.

## 4. Data-model additions (minimal)

Panel (`radius-module-admin`) — additive columns, schema-heal pattern
(same idempotent `_add_columns_if_missing` we use for CHR):

- `plan` / `service` (or subscriber): **`transport`** `VARCHAR(16)` default
  `chr_mikrotik` (back-compat: every existing row stays on the CHR path).
- DATA-plan fields (reuse existing speed/quota where present):
  `data_speed_mbit INT`, `data_quota_gb INT`, `data_protocols` (csv of
  sstp/pptp/l2tp).
- Per-customer VPS link: `radius_vps_subdomain` (`clientN.hoberadius.com`),
  `radius_vps_id` → the `CustomerRadiusInstance` already models the VPS;
  add `accel_enabled BOOL` + `cert_status` there.

radius-module — additive: a `transport` flag on the subscriber/plan mirror;
cert state table (`acme_certs`: subdomain, status, issued_at, renew_at).

No destructive migrations. Default values keep the **entire current CHR
flow unchanged** until a row is explicitly switched to `vps_accel`.

## 5. Client-script generator (version-aware)

Panel emits a protocol-specific, **RouterOS-version-aware** script (the
subscriber's device is usually a MikroTik; also provide plain
Windows/Android steps). The generator must branch on **v6 vs v7** — they
differ for SSTP/PPTP clients:

| Aspect | RouterOS v6 | RouterOS v7 |
|---|---|---|
| SSTP client add | `/interface sstp-client add connect-to=clientN.hoberadius.com:443 user=… password=… profile=default-encryption verify-server-certificate=yes` | same menu, but `verify-server-certificate=yes` requires the CA in `/certificate`; `tls-version` available; `http-proxy` field added — keep `connect-to` host-only + `port=` separate where the build requires it |
| Cert trust | import CA to verify | with a real Let's Encrypt cert, `verify-server-certificate=yes` works against the public chain (no import) |
| PPTP client | `/interface pptp-client add connect-to=… user=… password=…` | same; v7 changed default `profile` encryption handling — set `profile=default-encryption` explicitly |
| `add-default-route` | on the client interface | semantics changed in v7 (use `/ip route` or `default-route-distance`) |
| L2TP | `/interface l2tp-client add … use-ipsec=yes ipsec-secret=…` | same; v7 IPsec policy generation differs |

The generator stores the version choice (auto-detect later via API) and
emits the matching block. Because the cert is a **real public LE cert on
clientN.hoberadius.com**, native Windows SSTP works with no cert import —
this is the key advantage over the CHR self-signed path.

## 6. accel-ppp config

See `deploy/accel-ppp/accel-ppp.conf.tmpl` — production-grade, commented,
with clearly-marked template vars (pool range, RADIUS secret, cert paths,
subdomain). radius-module renders it per-VPS and reloads accel-ppp.

## 7. Phase plan

- **Phase 1 (this):** design + `accel-ppp.conf.tmpl` + attribute mapping +
  repo-access answer. No code.
- **Phase 2a (radius-module):** `transport` flag + accel-branch in
  `freeradius_translator` (additive, CHR branch untouched) + tests proving
  the CHR reply set is byte-identical when `transport=chr_mikrotik`.
- **Phase 2b (radius-vps-agent, new repo):** render accel-ppp.conf from the
  template, certbot DNS-01/Cloudflare, reload accel-ppp, report live
  sessions. Idempotent, one-shot installer + a small daemon.
- **Phase 2c (radius-module quota watcher):** accounting → Disconnect at
  cap, reusing `radius_coa.py`.
- **Phase 3 (radius-module-admin):** the one button + version-aware
  client-script generator + cert-status surfacing.
- **Phase 4:** lab validation of the exact accel-ppp `Filter-Id` rate form
  + `Session-Octets-Limit` support on the pinned accel-ppp version, then a
  single live customer pilot.

## 8. Open items to validate in lab before building (flagged, not assumed)
1. Exact accel-ppp shaper rate string form for `Filter-Id` (symmetric vs
   `rx/tx`, kbit vs bit) on the pinned accel-ppp version.
2. Whether the pinned accel-ppp honors `Session-Octets-Limit` (227); if
   not, rely solely on the server-side accounting Disconnect (§3.2.2).
3. accel-ppp NAS source IP for Disconnect (loopback vs VPS public) so the
   CoA secret/client config matches.
4. RouterOS v6/v7 exact SSTP `connect-to` port syntax per build.
