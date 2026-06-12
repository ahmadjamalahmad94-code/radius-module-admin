# Customer RADIUS ↔ Proxy Tunnel — Design + Cross-Repo Contract
**Status:** APPROVED DESIGN (no code yet) · **Date:** 2026-06-12 · **Spec for 3 parallel build agents**
**Repos:** radius-module-admin (panel @ `ffaa2e6`) · radius-module (customer) · radius-proxy

> **THE GAP (live-confirmed):** the proxy forwards client5's RADIUS auth to
> `10.200.5.2:1812`, but `ping 10.200.5.2` from the proxy = 100% loss — the
> WireGuard tunnel between the customer's RADIUS server (187.77.70.18) and the
> proxy **does not exist**. Nothing today creates it. This document designs its
> auto-provisioning — the customer-side analog of the CHR↔proxy `wg-data`
> tunnel that already works.

> **HEADLINE REQUIREMENT (owner, first-class principle):** *ALL secrets and
> keys are AUTOMATICALLY synchronized — the operator must NEVER hunt for which
> one differs and fix it manually.* The panel is the single source of truth
> for every credential; every party FETCHES/RECEIVES its copy from the panel
> over an authenticated channel; continuous reconcile self-heals drift. No
> secret is ever typed twice. See §6 — it governs every other section.

---

## 1. Topology + IP plan

```
                        ┌──────────────────────────────┐
                        │       PANEL (HTTPS)           │
                        │  radius-module-admin          │
                        │  bridge: license-key bearer   │
                        └───────┬───────────────┬──────┘
              heartbeat ▲ + cfg ▼               ▼ X-Proxy-Token
        (instance-ops/heartbeat)        (routing-table / radius-peers)
                        │                       │
┌───────────────────┐   │   ┌───────────────────────────────┐   ┌──────────────┐
│ CUSTOMER RADIUS   │   │   │           PROXY               │   │  CHR FLEET   │
│ radius-module     │   │   │  wg-data   10.98.0.1/24 :51821│◄──┤ 10.98.0.X    │
│ (docker, host net)│   │   │  wg-radius 10.200.0.1/16:51822│   │ (works today)│
│                   │   │   │  (NEW — this design)          │   └──────────────┘
│ wg-radius (NEW)   │═══╪══►│                               │
│  10.200.5.2/32    │ dials │  UDP fwd: realm→10.200.5.2    │
│ FreeRADIUS:       │  out  └───────────────────────────────┘
│  listens 10.200.5.2:1812/1813; client = 10.200.0.1        │
└───────────────────┘
```

**Planes (all disjoint):**

| Plane | Subnet | Proxy IP | Port | Who dials | Purpose |
|---|---|---|---|---|---|
| `wg-mgmt` (panel↔CHR) | 10.99.0.0/16 | — | 51820/panel | CHR → panel | control plane (existing) |
| `wg-data` (CHR↔proxy) | 10.98.0.0/24 | 10.98.0.1 | 51821 | CHR → proxy | RADIUS ingress (existing) |
| **`wg-radius` (customer↔proxy)** | **10.200.0.0/16** | **10.200.0.1** | **51822** | **customer → proxy** | **RADIUS egress (NEW)** |
| mgmt plane (reserved) | 10.250.0.0/16 | — | — | — | reserved; NOT built in v1 (bridge HTTPS covers mgmt) |

**Per-customer IP assignment — deterministic, panel-authoritative:**
`radius_wg_ip = 10.200.<customer_id>.2` (matches the live value already on the
instance row: customer 5 → `10.200.5.2`). Valid for customer_id 1..254·254; the
panel allocator MUST verify `customer_id ≤ 65023` and fail loudly otherwise.
`mgmt_wg_ip = 10.250.<customer_id>.2` stays reserved/informational (column
exists: `app/models.py:1534`). The panel writes both onto
`CustomerRadiusInstance` in `provision_on_link` — **the bridge stops being a
"suggestion" source for these two; the panel is the single allocator** (today
`_resolve_auth_ip` falls back to the runtime_url public host — that fallback
remains ONLY for instances explicitly marked tunnel-disabled).

**Junction with today's rows:** `CustomerRadiusInstance.radius_auth_ip` keeps
its meaning — "where the proxy sends RADIUS" — and for tunnel-enabled
instances it EQUALS `10.200.<id>.2`. `ProxyRealmRoute.target ip` already flows
to the proxy via `GET /api/proxy/routing-table`; **zero proxy forwarding-code
changes** (confirmed: `proxy.py` line 205 just UDP-sends to `route.target_ip`;
the OS routes 10.200/16 via wg-radius once the interface exists).

---

## 2. Key management

| Key | Generated where | Stored where | Distributed how |
|---|---|---|---|
| Customer wg-radius keypair | **radius-module** (`wg_peer_manager.generate_keypair()`, X25519, exists at `app/radius/services/wg_peer_manager.py:149`) | private: local file `/etc/hoberadius/wg-radius.key` (0600, uid 999); **never leaves the box** | pubkey → panel in every heartbeat (§3) |
| Proxy wg-radius keypair | proxy host, once, at deploy (`wg genkey` → `/etc/wireguard/wg-radius.privkey`) | proxy host only | pubkey + endpoint pasted ONCE by owner into panel infra settings (§3 response source) |
| Panel knowledge | — | `Setting`: `PROXY_RADIUS_WG_PUBKEY`, `PROXY_RADIUS_WG_ENDPOINT` (e.g. `proxy.hoberadius.com:51822`), `PROXY_RADIUS_WG_TUNNEL_IP` (10.200.0.1) — same key-stability pattern as `PANEL_WG_PUBKEY` in `fleet/registry/infra_settings.py:71-96` (UI-editable, never regenerated implicitly) | down the heartbeat response |

Key rotation v1: manual (owner regenerates on either side; reconcilers
converge). No automatic rotation machinery — keep the foundation simple.

---

## 3. Bridge-heartbeat contract (the core)

Carried on the EXISTING `POST /api/integration/hoberadius/instance-ops/heartbeat`
(panel ingest: `app/api/routes.py:861`, already calls `provision_on_link`;
client: `admin_panel_client.py:600` `post_instance_heartbeat`, worker every
300s at `app/workers/admin_bridge_sync_worker.py:30-40`). Auth: license-key
bearer (body `license_key`) per `docs/SIMPLE_LINK_CONTRACT.md` — no new auth.

### 3.1 Request additions (radius → panel)

```jsonc
{
  // ...existing heartbeat fields (license_key, instance_id, db, freeradius, ...)
  "wg_radius": {
    "public_key": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",  // 44-char b64; REQUIRED once generated
    "interface_up": true,                  // wg interface exists locally
    "tunnel_ip": "10.200.5.2",             // what the instance is currently using ("" before first config)
    "last_handshake_age_s": 35,            // from `wg show wg-radius latest-handshakes`; null when never
    "freeradius_proxy_client_present": true, // proxy client block written + reload triggered
    "config_fingerprint": "sha256:…"       // hash of (tunnel_ip|proxy_pubkey|proxy_endpoint|secret) it applied — lets the panel detect drift
  }
}
```

Panel ingest: stores `public_key` → `CustomerRadiusInstance.wg_public_key`
(NEW column, `String(64)`, + `wg_last_handshake_at DATETIME` — added via the
`ensure_schema_compatibility` pattern, see `chr_nodes.device_facts_json`
precedent in `app/__init__.py`). A pubkey CHANGE is accepted (reinstall case)
+ audited.

### 3.2 Response additions (panel → radius)

Appended to the heartbeat response the ingest already returns (alongside the
existing `provision` block):

```jsonc
{
  "ok": true,
  // ...existing provision fields (status, realm, radius_target, route_id ...)
  "radius_tunnel": {
    "enabled": true,                        // false ⇒ instance marked tunnel-disabled; client tears down nothing, just skips
    "tunnel_ip": "10.200.5.2",              // THIS instance's wg-radius address (panel-allocated, deterministic)
    "tunnel_cidr": 16,                      // interface Address = 10.200.5.2/32; route scope = /16 informational
    "proxy_public_key": "9KLi…tQk=",        // from Setting PROXY_RADIUS_WG_PUBKEY ("" ⇒ owner hasn't configured proxy yet ⇒ client no-ops)
    "proxy_endpoint": "proxy.hoberadius.com:51822",
    "proxy_tunnel_ip": "10.200.0.1",
    "allowed_ips": ["10.200.0.1/32"],       // customer only ever needs the proxy
    "persistent_keepalive": 25,             // customer dials out; keepalive holds NAT mappings
    "radius_secret": "rR7…K2m",             // the ProxyRealmRoute shared secret — ALWAYS included (see §6)
    "listen_ports": {"auth": 1812, "acct": 1813}
  }
}
```

**Idempotency:** the response is the full desired state, every heartbeat. The
radius side compares against its `config_fingerprint` and only rewrites
wg/FreeRADIUS config (and triggers reloads) on change. Convergence time ≤ one
heartbeat interval (300s default; the client SHOULD also run one immediate
sync right after a successful license link).

---

## 4. Proxy peer publish + apply

### 4.1 Panel endpoint (NEW)

```
GET /api/proxy/radius-peers          auth: X-Proxy-Token (same middleware as
                                     /api/proxy/wg-peers — proxy_api.py:40-93)
200 {
  "ok": true,
  "radius_peers": [
    {
      "name": "client5-radius",                      // instance_name or c<id>
      "public_key": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
      "allowed_ips": ["10.200.5.2/32"],
      "endpoint": null                               // customer dials IN — proxy never dials out
    }
  ]
}
```

Source: every `CustomerRadiusInstance` with non-empty `wg_public_key` and
`status != "disabled"`. This is the COMPLETE desired set (add missing, remove
stale-managed) — same semantics the wg-data publisher documents at
`app/api/proxy_api.py:441-525` (note: that endpoint's array key is
`wg_data_peers`; the new one uses `radius_peers` — each reconciler reads its
own key, no compatibility shim needed).

### 4.2 Proxy reconciler (clone of `wg_peer_sync.py`, 442 lines, proven)

New module `wg_radius_sync.py` instantiating the SAME class design:
`wg show wg-radius dump` → diff → `wg set wg-radius peer <PK> allowed-ips …` /
`… peer <PK> remove`. Inherits the full safety model verbatim:
- rc=126/127 → log once, **degrade to dry-run**, never crash (`wg_peer_sync.py:311-320, 373-409`);
- managed-peers state file → never removes operator-added peers (`:19-24, 368-370`);
- pubkey/allowed-ips validation, `0.0.0.0/0` refused (`:59-79`);
- 404 from panel → "endpoint not exposed", inert (`:337-343`).

Config knobs (mirror `config.py:287-327`): `PROXY_WG_RADIUS_SYNC_ENABLED`
(default true), `PROXY_WG_RADIUS_INTERFACE=wg-radius`,
`PROXY_WG_RADIUS_STATE_PATH=/var/lib/hobe-radius-proxy/managed-radius-peers.json`,
`PROXY_WG_RADIUS_SYNC_INTERVAL=60`, `PROXY_WG_RADIUS_SYNC_TIMEOUT=10`,
shares `PROXY_WG_BIN` + `PROXY_WG_APPLY_MODE`. New asyncio loop cloned from
`proxy.py:528-544`, registered beside it (`proxy.py:551`).

Host bootstrap (DEPLOY_PROXY.md new §2bis): wg-radius keypair →
`/etc/wireguard/wg-radius.conf` (`Address 10.200.0.1/16`, `ListenPort 51822`,
no static peers — reconciler owns them) → `wg-quick up` + enable → UFW
`allow 51822/udp` → extend `systemd/setup-wg-sudoers.sh` Cmnd_Alias to cover
`wg show wg-radius dump` + `wg set wg-radius peer *`. The `Address …/16`
installs the 10.200/16 route automatically — **no forwarding-code change**.

---

## 5. RADIUS-side bring-up (radius-module, dockerized)

Constraints (verified): app container = bridge net, uid 999, NO docker socket;
FreeRADIUS container = **host network**; config flows app→freeradius via the
shared `/app/instance` volume + `.reload-trigger` watcher (`deploy/freeradius/
entrypoint.sh:119-146`, ~5s); host-level wg changes flow via files in
`/etc/hoberadius/…` + a host systemd **path-unit** (the proven
`init-wg-reloader` pattern in `deploy.sh`).

New service `app/radius/services/proxy_tunnel_manager.py`, invoked from the
heartbeat response handler (hook: `license_admin_instance_health.py:105` —
response is currently dropped) and once immediately after license link:

1. **Keypair:** ensure `/etc/hoberadius/wg-radius.key` exists (else
   `generate_keypair()`); pubkey goes into the next heartbeat request.
2. **wg config:** when `radius_tunnel.enabled` and `proxy_public_key` is
   non-empty and the fingerprint changed, atomically write
   `/etc/hoberadius/wg-radius.conf`:
   ```ini
   [Interface]
   PrivateKey = <local>
   Address    = 10.200.5.2/32
   [Peer]
   PublicKey           = <proxy_public_key>
   Endpoint            = <proxy_endpoint>
   AllowedIPs          = 10.200.0.1/32
   PersistentKeepalive = 25
   ```
   Host applies it via NEW systemd path-unit `hobe-wg-radius-reload.{path,service}`
   (`wg-quick down wg-radius || true; wg-quick up /etc/hoberadius/wg-radius.conf`),
   installed by `deploy.sh init-wg-radius` (clone of `init-wg-reloader`).
3. **FreeRADIUS client:** write
   `/app/instance/freeradius-clients-wizard/proxy-client.conf` (the include
   dir FreeRADIUS already reads):
   ```
   client radius-proxy {
       ipaddr      = 10.200.0.1
       secret      = <radius_secret from response>
       require_message_authenticator = no
       nas_type    = other
       shortname   = central-proxy
   }
   ```
   using the EXACT `write_client_for_run` pattern (atomic tmp+rename, secret
   charset guard, `setup_wizard_v3_radius_server_provisioning.py:76-191`) then
   touch `.reload-trigger`.
4. **Listen scope (§7):** FreeRADIUS today listens 0.0.0.0 in host mode and
   ALSO serves the customer's own routers over `wg0` (10.10.0.0/24) — so we do
   NOT bind exclusively to 10.200.5.2. v1: explicit `listen` blocks for
   `10.10.0.1`, `10.200.5.2`, `127.0.0.1` replace the wildcard (template in
   `deploy/freeradius/sites-enabled/default`), AND `deploy.sh` adds host UFW:
   deny 1812-1813/udp on the public interface, allow on wg0 + wg-radius. The
   firewall rule alone already closes the public exposure even before the
   listen-block change lands.
5. **Report back:** next heartbeat carries `interface_up`,
   `last_handshake_age_s`, `freeradius_proxy_client_present`,
   `config_fingerprint` — the panel surfaces tunnel health on the customer
   page (and the proxy's existing `ping`-style health can finally reach
   10.200.5.2).

---

## 6. Automatic Secret & Key Synchronization (zero manual matching) — THE HEADLINE

**Principle (owner, non-negotiable):** the PANEL is the single source of truth
for every secret and key in the system. Every party FETCHES/RECEIVES its copy
from the panel over an authenticated channel, applies it automatically, and a
continuous reconcile loop self-heals drift. **The operator never compares two
strings, never edits a config file to "make them match", and never types a
secret more than once (most are never typed at all — the panel mints them).**

**The incident this must make impossible:** the CHR↔proxy RADIUS secret lived
in TWO hand-managed places — the panel Setting `CHR_SHARED_SECRET` (baked into
every CHR script) and the proxy's hand-edited env `PROXY_CHR_SECRET`
(`radius-proxy/config.py:120`, frozen into the relay at `proxy.py:56`). They
drifted (64-char vs 34-char), every Access-Request died on
Message-Authenticator mismatch, and the owner diffed secrets by eye.
**Unacceptable; eliminated by construction below.**

The lifecycle of EVERY credential: **mint once on the panel → push everywhere
automatically → reconcile continuously → mismatches self-heal.**

| # | Credential | Minted / canonical | Auto-distribution channel | Consumers | Convergence | Manual steps |
|---|---|---|---|---|---|---|
| 1 | CHR↔proxy RADIUS secret | panel Setting `CHR_SHARED_SECRET` (Fernet; `fleet/registry/infra_settings.py:407-428`, mint button exists) | baked into every CHR script (existing) **+ NEW: `chr_shared_secret` field in the authenticated `GET /api/proxy/routing-table` response** | every CHR + the proxy relay | proxy ≤60s (table refresh); CHRs on re-import | **zero** (env becomes bootstrap-only) |
| 2 | proxy↔customer-RADIUS route secret | panel mints in `provision_on_link` → `Setting["radius_secret.customer.<id>"]` (`radius_auto_provision.py:59-110`) | routing-table → proxy route (existing, `routing_table.py:121`) **+ heartbeat `radius_tunnel.radius_secret` → customer FreeRADIUS (§3.2)** | proxy + customer `clients.conf` | proxy ≤60s; customer ≤300s (next heartbeat) | **zero** (never typed by anyone) |
| 3 | WG keys (panel / proxy / CHR / customer) | each party generates its OWN keypair; panel is canonical for its own (stable slot `PANEL_WG_PRIVKEY`, never implicitly regenerated) and the registry of everyone's PUBKEYS | pubkeys flow over authenticated channels: CHR→panel (onboarding + verify), customer→panel (heartbeat §3.1), proxy→panel (pasted once at deploy); peers re-published every cycle via `/api/proxy/wg-peers` + `/api/proxy/radius-peers` | wg interfaces on all parties | ≤60s reconcile cycle | proxy pubkey pasted ONCE at deploy; everything else zero |
| 4 | X-Proxy-Token (`RADIUS_PROXY_SHARED_SECRET`) | panel Setting (UI-editable) | **the one bootstrap credential** — it authenticates the channel all other secrets ride on; set once on both sides at proxy deploy | panel + proxy | — | typed once at deploy (unavoidable trust anchor) |

### 6.1 CHR↔proxy secret — proxy fetches from the panel (kills the live incident)

**Panel:** the routing-table response gains one authenticated field:

```jsonc
GET /api/proxy/routing-table   (X-Proxy-Token; existing endpoint)
{
  "ok": true,
  "chr_shared_secret": "u8Qk…N2p",   // decrypted from Setting CHR_SHARED_SECRET; "" when unset
  "routes": [ ... ],                  // existing
  "chr_nodes": [ ... ]                // existing
}
```

This is the SAME value the panel bakes into every CHR script — equality is now
**by construction**, not by operator diligence.

**Proxy:** `RouteTable` stores `chr_shared_secret` from each refresh and the
relay reads it **per packet through the table** (replace the constructor-frozen
`self._chr_secret`, `proxy.py:56`, with a provider —
`routing.chr_secret()`). Precedence: **panel value wins whenever non-empty**;
the `PROXY_CHR_SECRET` env is demoted to a bootstrap-only fallback used solely
before the first successful table fetch, and when the env value differs from
the panel's, the proxy logs ONE deprecation warning and **adopts the panel
value** (never the reverse). Caching: last-known secret persists in the
existing state-dir (`/var/lib/hobe-radius-proxy/`, mode 0600) so a proxy
restart during a panel outage keeps relaying.

**Rotation without an outage window:** CHRs converge slower than the proxy
(re-import vs 60s), so the proxy keeps the PREVIOUS secret and validates each
inbound Message-Authenticator against **current, then previous** (grace window
`PROXY_CHR_SECRET_GRACE_SECONDS`, default 24h after a change); responses are
always signed with whichever secret validated the request. Rotation flow:
owner mints in panel → proxy dual-accepts within 60s → owner re-imports CHR
scripts at leisure → grace expires. No RADIUS drop at any point.

### 6.2 Route secret — one mint, two automatic consumers

Already single-sourced (`provision_on_link`); the design completes its second
leg: the SAME stored secret is included as `radius_tunnel.radius_secret` in
EVERY heartbeat response (§3.2) — not once — so the customer side always
reconverges (lost disk, reinstall) with zero operator action. The radius side
writes it only into `proxy-client.conf` (atomic write, wizard secret-charset
guard, never logged). Rotation = owner regenerates in panel → proxy ≤60s,
FreeRADIUS ≤300s. The customer-side `config_fingerprint` (§3.1) lets the panel
SEE convergence (and the customer page shows "secret in sync ✓" instead of the
owner ever wondering).

### 6.3 WG keys — generate locally, register automatically, re-sync heals

Private keys never move. Public keys are registry data the panel owns:
CHR pubkeys land via onboarding/verify (existing), customer-RADIUS pubkeys
land via heartbeat (§3.1), and the reconcilers (`wg-peers` / `radius-peers`)
re-publish the COMPLETE desired peer set every cycle — so the
`panel_key_mismatch` class of failure self-heals on the next sync instead of
requiring a human: a party that regenerated its key simply reports the new
pubkey and every peer table converges within one cycle. The panel's own key
follows the stable-slot rule (`PANEL_WG_PRIVKEY` is never regenerated
implicitly — the zero-touch invariant).

### 6.4 Drift visibility (trust but verify, automatically)

Every consumer reports a non-reversible `config_fingerprint` of what it
actually applied (customer: §3.1; proxy: add the same to its heartbeat
payload). The panel compares against what it published and surfaces a single
boolean per party — «متزامن ✓ / بانتظار التقارب…» — on the proxy page and the
customer page. Alert (fleet-alerts P9 pipeline) if any party stays divergent
for > 3 cycles. The operator's job collapses to reading a green checkmark.

---

## 7. Security invariants

1. RADIUS auth/acct for proxied realms travels ONLY inside wg-radius; the
   customer host firewall denies 1812/1813/udp from the public interface
   (deploy.sh rule; §5.4).
2. FreeRADIUS accepts the proxy only as `client 10.200.0.1` with the route
   secret — never a 0.0.0.0/0 client.
3. The proxy's wg-radius peer set is allowlist-by-pubkey with `/32`
   allowed-ips per customer (one IP each — a compromised customer cannot
   spoof another's tunnel IP; wg cryptokey routing enforces it).
4. Private keys never transit: customer's stays on the customer host, proxy's
   on the proxy host; the panel stores only pubkeys + endpoint.
5. The reconciler never touches operator-added peers and degrades to dry-run
   without privilege (inherited).
6. Proxy UFW: 51822/udp open publicly (handshake), RADIUS ports NOT open on
   wg-radius toward the proxy (the proxy only dials OUT to customers).

---

## 8. Per-repo task breakdown (3 parallel agents)

### A) radius-module-admin (panel — the allocator + both publishers)
1. `app/models.py` — `CustomerRadiusInstance`: add `wg_public_key`
   (String(64), default ""), `wg_last_handshake_at` (DateTime, nullable);
   `app/__init__.py ensure_schema_compatibility` block for existing DBs.
2. `app/services/radius_auto_provision.py` — deterministic allocator:
   `radius_auth_ip = 10.200.<customer_id>.2`, `mgmt_wg_ip = 10.250.<customer_id>.2`
   (panel-authoritative; runtime_url-host fallback only when tunnel disabled);
   build the `radius_tunnel` response block (§3.2) reading
   `PROXY_RADIUS_WG_PUBKEY/ENDPOINT/TUNNEL_IP` settings + the stored secret.
3. `app/api/routes.py` heartbeat ingest (`:861`) — accept `wg_radius` request
   block (store pubkey + handshake age, audit pubkey changes), return
   `radius_tunnel`.
4. `app/api/proxy_api.py` — `GET /api/proxy/radius-peers` (§4.1), same
   `_auth_required()` guard; publisher reads qualifying instances.
5. Settings UI (infra page): the three `PROXY_RADIUS_WG_*` fields with the
   same masked/stable treatment as `PANEL_WG_*` (`fleet/registry/infra_settings.py`).
6. Customer page: tunnel-health chip (pubkey present? last handshake age?) on
   the «ربط الريدياس» card.
7. **§6.1 — publish the CHR secret:** routing-table response gains
   `chr_shared_secret` (decrypted from the infra Setting; `""` when unset) —
   `app/api/proxy_api.py` routing_table handler. Audit-log on every rotation
   (`set_chr_shared_secret` already exists at `infra_settings.py:407`).
8. **§6.4 — drift visibility:** accept `config_fingerprint` from both the
   proxy heartbeat (`/api/proxy/heartbeat`) and the customer heartbeat; store
   + compare against published state; sync chip on proxy/customer pages +
   P9 alert after 3 divergent cycles.
9. **Tests:** allocator determinism + bounds (`customer_id` overflow), pubkey
   ingest + change-audit, `radius_tunnel` block shape (enabled/disabled, no
   proxy key configured ⇒ `proxy_public_key:""`), radius-peers endpoint
   (auth-gated 401, complete-set semantics, /32 allowed_ips, excludes
   disabled + missing-pubkey instances), secret always present in response,
   **`chr_shared_secret` present in routing-table (and absent → `""` when
   unset; never logged)**, fingerprint compare + alert trigger, heartbeat
   round-trip integration.

### B) radius-module (customer — keygen, wg bring-up, FreeRADIUS)
1. `app/radius/services/proxy_tunnel_manager.py` (NEW) — keypair ensure,
   fingerprint compare, atomic `/etc/hoberadius/wg-radius.conf` write (§5.2),
   FreeRADIUS `proxy-client.conf` write + `.reload-trigger` (§5.3).
2. `license_admin_instance_health.py` — request: add `wg_radius` block
   (`:68-88`); response: process `radius_tunnel` (`:105`, currently dropped).
3. `admin_panel_client.py` — surface the heartbeat response to the caller
   (it already returns `response`; just stop ignoring it).
4. `deploy/deploy.sh` — `init-wg-radius`: install
   `hobe-wg-radius-reload.{path,service}` + `/etc/hoberadius` perms (uid 999)
   + UFW deny-public/allow-wg for 1812-1813.
5. `deploy/freeradius/sites-enabled/default` — explicit listen blocks
   (10.10.0.1, 10.200.5.2 via include/env, 127.0.0.1) — SECOND PR (riskier);
   the UFW rule ships first.
6. **Tests:** keypair persistence (no regen when file exists), wg-conf
   rendering golden file (Address /32, AllowedIPs proxy /32, keepalive),
   fingerprint no-op (no rewrite/reload on identical state),
   proxy-client.conf golden + secret-guard rejection + reload-trigger touch,
   response-handler matrix (enabled=false ⇒ no writes; empty proxy key ⇒
   no-op + warning; secret change ⇒ clients.conf rewritten), heartbeat
   request carries pubkey after generation.

### C) radius-proxy (reconciler clone + host bootstrap)
1. `wg_radius_sync.py` (NEW) — parametrized clone of `wg_peer_sync.py`
   (interface/endpoint/state-path/JSON-key `radius_peers`); ideally refactor
   the existing class to take these as ctor args and instantiate twice.
2. `config.py` — the `PROXY_WG_RADIUS_*` knobs (§4.2).
3. `proxy.py` — `_build_wg_radius_sync()` + `_wg_radius_sync_loop()`
   (clone `:528-544`), register task.
4. `systemd/setup-wg-sudoers.sh` — extend aliases to wg-radius;
   `systemd/setup-ufw.sh` — `allow 51822/udp`.
5. `DEPLOY_PROXY.md` — §2bis wg-radius host bootstrap (keypair, conf with
   `Address 10.200.0.1/16` + `ListenPort 51822`, wg-quick enable, where to
   paste the pubkey/endpoint into the panel).
6. **§6.1 — CHR secret from the panel (kills the live mismatch):**
   `routing_table.py` ingests `chr_shared_secret` from the table response +
   persists last-known value in the state dir (0600); `proxy.py` reads the
   secret per-packet via a `routing.chr_secret()` provider instead of the
   constructor-frozen `self._chr_secret` (`proxy.py:56`); precedence
   panel-over-env with a one-time deprecation warning when the env differs;
   dual-accept grace on inbound Message-Authenticator (current → previous,
   `PROXY_CHR_SECRET_GRACE_SECONDS` default 86400) so rotation never drops
   RADIUS while CHRs re-import.
7. **§6.4:** include `config_fingerprint` (chr_secret + peer-set hash) in the
   existing heartbeat POST.
8. **Tests:** clone the `tests/test_wg_peer_sync.py` matrix against the new
   JSON key + interface (fetch/parse/validate, complete-set add/remove,
   managed-state protection, dry-run degradation, 404-inert), loop
   registration smoke, **chr-secret sync (panel value adopted over env,
   bootstrap fallback before first fetch, persisted across restart,
   dual-accept validates old+new during grace then rejects old after,
   re-sign uses the secret that validated)**, sudoers script idempotence if
   tested today.

### Sequencing
Panel (A) ships first — endpoints tolerate empty peer sets and missing proxy
settings. B and C are then independent and parallel. End-to-end acceptance:
on the live pair, after one heartbeat + one reconcile cycle,
`ping 10.200.5.2` from the proxy succeeds and a CHR test-auth for
`user@client5` returns Access-Accept end-to-end.

---

## 9. Bandwidth policy per connection type (panel-controlled, per direction)

**Owner requirement:** the panel CONTROLS WireGuard / VPN bandwidth PER
CONNECTION TYPE — never hand-edited on the device. Defaults are operator-set
once on the infra page; per-instance / per-plan overrides ride on existing
service config rows. All values are **per-direction symmetric by default**
(reusing the 850⇒`850M/850M` rule from `feat/bandwidth-per-direction`):
a single `mbps` setting means "Xm download AND Xm upload, simultaneously",
emitted as `<upload>M/<download>M` for RouterOS rate-limit.

### 9.1 Policy schema (panel-side, single Setting key)

A single JSON Setting row holds the fleet-wide defaults so the operator edits
one surface and every emitter reads it:

```jsonc
Setting key: "fleet.bandwidth_policy"
value (JSON):
{
  "radius_transport":  {"download_mbps":   5, "upload_mbps":   5},  // wg-data / wg-radius — RADIUS only
  "vpn_sstp":          {"download_mbps": 100, "upload_mbps": 100},
  "vpn_pptp":          {"download_mbps":  50, "upload_mbps":  50},
  "vpn_ipsec":         {"download_mbps":  50, "upload_mbps":  50},
  "vpn_wireguard":     {"download_mbps": 100, "upload_mbps": 100}
}
```

* `radius_transport` is intentionally low (default **5 Mbps**) — the wg-data
  and wg-radius planes carry only `RADIUS auth/acct/CoA` traffic, never user
  payload.
* `vpn_*` keys default to operator-typical values (50 / 100 Mbps) and are
  the source the «اتصالات الوصول» SSTP/PPTP/IPsec/WG provisioning consults
  for sessions that do NOT carry an explicit `download_mbps`/`upload_mbps`
  override.
* Per-direction emission goes through the single helper
  `app.services.speed_profiles.rate_limit_string(down, up)` — same formatter
  the bandwidth-per-direction sibling rolled out. Symmetric values come out
  as `Xm/Xm`; asymmetric values are still allowed via the «متقدّم» toggle.

### 9.2 Emission paths

| Surface | Where the policy reads | What it emits |
|---|---|---|
| wg-radius heartbeat response (§3.2) | `radius_transport` | New field `radius_tunnel.rate_limit_mbps` (single int, symmetric) — the customer-side wg-quick bringup applies it as `Mbps` cap on the wg interface (5 M default). |
| Per-session VPN config (SSTP/PPTP/IPsec/WG; existing) | `vpn_<type>` when the tunnel row has no explicit `download_mbps`/`upload_mbps` | Existing `Mikrotik-Rate-Limit` attribute = `<upload>M/<download>M` per direction. No new attribute; the existing path now has a default. |
| RouterOS unified script per CHR | (informational only — script knobs are per-tunnel) | The script still consumes per-tunnel speed where present; this section ensures empty rows pick up the fleet default at provision time, not at script render. |

### 9.3 UI

* Infra page → new card «سياسة عرض النطاق لكل نوع اتصال»: one input row
  per connection type with a single Mbps input (symmetric) + a small
  «متقدّم» toggle that splits it into a `download_mbps`/`upload_mbps`
  pair. Mirrors the «العرض الترددي حسب الاتجاه» pattern from the
  sibling branch — same Arabic labels, same per-direction hint.
* Customer-service config: the existing speed picker keeps overriding
  the policy when a value is set; an empty value now resolves to the
  fleet default automatically.

### 9.4 Tests

* Default policy applies when no value is set; `radius_transport` is 5 Mbps.
* `radius_tunnel.rate_limit_mbps` appears in the heartbeat response.
* VPN session provisioning calls `rate_limit_string(default_down,
  default_up)` when the tunnel row has no explicit speed.
* Policy CRUD round-trips through the Setting JSON (read → set → read).
* Symmetric default `100` ⇒ `100M/100M`; explicit asymmetric still works.

---

## 10. Node roles + capacity utilization (flexible, combinable)

**Owner requirement:** a 1 Gbps VPS used only for RADIUS-transport (~5 M)
wastes capacity. So node roles are **a SET, not a single value** — a CHR
can be RADIUS-only, VPN-only, or **BOTH simultaneously** on the same
1 G uplink. The bandwidth-policy layer of §9 then ALLOCATES the 1 G
across whichever roles are enabled.

### 10.1 Role tag on `fleet_chr_nodes`

Additive column `roles_json` (JSON list of strings) with helpers:

```python
# app/services/node_roles.py
NODE_ROLES = (
    "radius_transport",  # wg-data / wg-radius — light, ~5 Mbps per §9
    "vpn_sstp",          # client SSTP terminator
    "vpn_pptp",          # client PPTP terminator
    "vpn_ipsec",         # client IKEv2 / IPsec
    "vpn_wireguard",     # client wg
)

# Helpers (all node-aware; honour roles_json or fall back to "all if empty"):
node_has_role(node, role) -> bool
enabled_roles(node)        -> set[str]
toggle_role(node, role)    -> None
```

* `enabled_roles(node)` defaults to "all roles enabled" when the column is
  empty so existing fleets behave unchanged on first deploy (operator-led
  rollout: pick a node, narrow the roles, watch the spare capacity grow).
* The «اتصالات الوصول» provisioning (SSTP/PPTP/IPsec/WG) refuses to place
  a connection on a node whose role for that connection type is disabled
  (clear Arabic error, link to the role-edit page).
* The placement/brain ranker excludes nodes that don't have the matching
  role from its candidate set — same shape as the existing
  `enabled`/`drain` filters.

### 10.2 Capacity allocator

A single read-only helper the dashboard + the provisioning layer share:

```python
# app/services/node_capacity.py
def capacity_for(node) -> {
  "uplink_mbps": int,                          # node.link_speed_mbps (default 1000)
  "policy_by_role": dict[role, {down, up}],    # from §9 policy
  "allocated_by_role": dict[role, int],        # active_sessions * default_per_role
  "spare_mbps": int,                           # uplink − Σ allocated
}
```

The dashboard renders `spare_mbps` per node alongside the existing headroom
chips (P8 surfaces today). A node serving only RADIUS-transport on a 1 G
uplink shows ≈ 995 Mbps spare, which is the operator's cue to enable a
VPN role on the same box. No high-speed VPS sits idle.

### 10.3 What ships now vs design-only

| Layer | Tonight | Follow-up |
|---|---|---|
| `roles_json` column + heal | **built** | — |
| `node_roles` helpers + tests | **built** | — |
| `bandwidth_policy` module + tests | **built** | — |
| `capacity_for(node)` helper + tests | **built** | — |
| `rate_limit_mbps` in heartbeat response | **built** | — |
| Infra page UI for the policy | design-only (this section) | mechanical clone of the existing «إعدادات الأسطول» card patterns |
| «اتصالات الوصول» role enforcement | design-only | one-line check in the existing provisioner — added when the brain/placement branch lands its enabled-role read |
| Brain ranker `enabled_roles()` filter | design-only | additive filter alongside `enabled`/`drain` |

This keeps tonight's PR small + verifiable: the data + the policy + the
emission seam land green; the two UI/enforcement clones plug into the same
helpers without touching the foundation again.

---

## 11. Per-customer subdomain + TLS cert (SSTP/IPsec clients validate hostname)

**Owner requirement:** every customer node gets a subdomain
(`client<id>.hoberadius.com`) and a valid TLS cert auto-provisioned, so
SSTP/IPsec clients present a hostname-matching cert and validate cleanly.

This is SEPARATE from the per-CHR self-signed `www-ssl` certificate that
the metrics endpoint already uses (§3.6 of the unified script); that cert
authenticates the panel→CHR REST channel only. The subdomain + cert here
faces the END USER on `tcp/443` (SSTP) and `udp/500+4500` (IKE).

### 11.1 Chosen path: wildcard `*.hoberadius.com` (one cert covers all)

**Decision — wildcard cert.** Phased per-subdomain ACME is the alternative
(§11.4) but a wildcard sweeps the entire customer-onboarding problem under
one ops step: provision the wildcard ONCE on the panel, replicate it onto
every CHR + the proxy at deploy time, and `client<id>.hoberadius.com`
resolves + validates for every customer with zero per-customer cert flow.

| Decision | Choice | Reason |
|---|---|---|
| Cert shape | `*.hoberadius.com` wildcard (single cert, single chain) | One ACME flow at the panel, no per-customer ACME on the CHR. |
| Renewal | Panel runs `certbot renew --dns-…` against the same DNS provider that holds the wildcard `_acme-challenge` record. | One cron, one place. |
| Distribution | Panel uploads the new chain to every CHR on rotation via the existing wg-mgmt channel + the unified-script renderer. | Reuses the deployment seam the §6.3 wg-keys leg already uses. |
| Per-customer subdomain | `client<customer_id>.hoberadius.com` is **panel-minted** on customer create + persisted on ``customers.subdomain``. Operators can override per row. | Deterministic + matches the existing `client<id>` realm convention. |
| DNS | Owner adds ONE wildcard A/AAAA record `*.hoberadius.com → <panel-public-ip-or-front-door>` once. Every `client<id>.hoberadius.com` resolves under it. | One DNS row → infinite customers. |

The cert + the wildcard A record are **operator/ops responsibilities**
(documented in `DEPLOY_PANEL.md` → new §"Wildcard TLS + DNS"); the panel
piece is purely: (a) mint + persist the subdomain on customer create,
(b) surface `customer_fqdn(customer)` to the bridge/runtime contract +
the CHR script renderer, (c) audit the assignment.

### 11.2 What the panel stores + emits

* **`customers.subdomain`** — new column (String(120), default ""),
  populated on create by `assign_subdomain(customer)`. Idempotent: the
  helper returns the existing value once set, never re-mints.
* **`Setting key fleet.tls.zone_base`** — owner-editable default
  `"hoberadius.com"`; emitted as `<subdomain>.<zone_base>` so the same
  panel can drive a staging zone alongside production.
* **Bridge runtime contract addition** — every runtime-contract /
  heartbeat response carries `fqdn: "client5.hoberadius.com"` so the
  customer side bakes it into local FreeRADIUS/SSTP listeners as the
  cert CN it's listening as.
* **CHR script renderer surface** — the per-CHR unified script consumes
  the customer's FQDN where SSTP / IKE need a `certificate-common-name`
  binding. Today the existing `SSTP_CERT_NAME` / `IKE_CERT_NAME` binders
  emit the per-CHR self-signed cert; under §11 they switch to the
  wildcard once `customer_fqdn(customer)` is populated.

### 11.3 Sequencing

1. Tonight (this branch) — `customers.subdomain` column + heal +
   assigner + `customer_fqdn(customer)` helper + tests.
2. Next PR (deploy/ops branch) — `DEPLOY_PANEL.md` §"Wildcard TLS + DNS"
   + `certbot --dns-…` automation + cert-rotation push to CHRs.
3. Next PR (CHR renderer) — switch `{{SSTP_CERT_NAME}}` /
   `{{IKE_CERT_NAME}}` from the per-CHR cert to the wildcard chain
   the panel pushed; cert-CN binding reads `customer_fqdn(...)`.

### 11.4 Alternative considered: per-subdomain ACME (NOT chosen)

Per-customer Let's-Encrypt would let every CHR mint + renew its own
`client<id>.hoberadius.com` cert via `--dns-` plugin. Strictly stronger
isolation (compromise of one cert doesn't expose the others) but adds:
ACME runner on every CHR, per-customer DNS-01 row coordination, rate-
limit exposure (50 certs/week/registered domain), and harder bring-up
when wg-mgmt is offline. **We accept the shared-cert risk for the
one-cert-one-DNS-row simplicity.** Future hardening: when an individual
customer requests cert isolation (regulatory ask), promote that customer
alone to the per-subdomain ACME path — the data model is forward-
compatible since `customers.subdomain` already exists.

---

## 12. Panel-enforced per-connection speed (business model: free creation, locked speed)

**Owner requirement (THE monetization control):** the subscriber is FREE
to generate unlimited connections / link unlimited NAS, but is NOT free
to set the speed. **Default 5 Mbps per connection** (per-direction,
`5M/5M`). When the owner agrees / gets paid, the owner UNLOCKS the
customer to 10 / 50 / 100 Mbps from the panel; the new cap rides the
RADIUS `Mikrotik-Rate-Limit` attribute on the next Access-Accept;
applied **immediately** on next auth. The subscriber CANNOT override
this from their MikroTik because the rate-limit is on the
Access-Accept itself — local config does not see it.

### 12.1 Where the unlock lives

Two layers, customer wins over plan:

| Layer | Column | Default | Editable by |
|---|---|---|---|
| Per-customer override | `customers.speed_unlock_mbps` | `0` ⇒ inherit from plan | Owner (super-admin only) |
| Per-plan default | `plans.speed_unlock_mbps` | `0` ⇒ falls back to floor `5` | Owner (super-admin only) |
| Floor (every unauthorised connection) | hard-coded `5` | — | not editable; this IS the locked-speed default |

`0` everywhere is the back-compat sentinel meaning "no explicit
unlock"; the resolver collapses it to the floor 5 Mbps. The owner sets
**one number** to open a customer: `speed_unlock_mbps = 50` →
50M/50M everywhere.

### 12.2 Resolution rule (the one source the emitter uses)

```python
def resolve_speed_for(customer, connection_type) -> (download, upload):
    if connection_type == "radius_transport":
        # RADIUS plane is ALWAYS the §9 policy cap (5M default), never
        # the customer unlock — the unlock is about user-traffic speed.
        return policy_for("radius_transport").download_mbps, .upload_mbps

    unlock_mbps = customer.speed_unlock_mbps or _plan_unlock(customer) or LOCKED_DEFAULT_MBPS  # 5
    type_policy = policy_for(connection_type)   # e.g. vpn_sstp = 100/100
    # Ceiling binds: a customer unlock of 200 against a 100-capped vpn_sstp
    # emits 100. Floor binds: an unlock of 5 emits 5.
    down = min(unlock_mbps, type_policy.download_mbps)
    up   = min(unlock_mbps, type_policy.upload_mbps)
    return down, up
```

Composing two layers protects the operator:
* The fleet **type policy** (§9.1) is the absolute upper bound — even an
  owner who fat-fingered a customer to 1000 Mbps still serves at most
  the per-type cap (100 for SSTP/wg, 50 for PPTP/IPsec).
* The **customer unlock** is the per-deal lever the owner moves when
  they get paid.

### 12.3 RADIUS emission (where the panel-locked speed becomes wire bytes)

`mikrotik_rate_limit_for(customer, connection_type)` returns the
`Mikrotik-Rate-Limit` attribute string for the Access-Accept:

```python
down, up = resolve_speed_for(customer, connection_type)
return rate_limit_string(down, up)   # → "<up>M/<down>M"
```

The shared `rate_limit_string` helper is the SAME one
`feat/bandwidth-per-direction` shipped — 850 ⇒ `850M/850M`,
asymmetric pairs emit as `<upload>M/<download>M`. No duplicate
formatter; the per-direction rule the sibling branch owns is the rule
this layer honours.

Every existing call-site that builds RADIUS Access-Accept attributes
for SSTP/PPTP/IPsec/wg sessions runs through this resolver. Specifically:

1. The auto-provision layer (`radius_auto_provision.provision_on_link`)
   no longer writes a `radius_secret`-only payload — it now ALSO sets
   the per-customer rate-limit so first connection inherits the floor.
2. The «اتصالات الوصول» SSTP/PPTP/IPsec/wg provisioner consults the
   resolver when it builds the per-tunnel rate-limit string, replacing
   the previous "policy default" call.
3. CoA: when the owner bumps `speed_unlock_mbps`, the panel queues a
   `Mikrotik-Rate-Limit` CoA via the existing proxy CoA path so live
   sessions get the new cap without a reconnect (forwards-compatible —
   landed in Phase-7).

### 12.4 UI

* **Customer page** — single «سرعة الاتصالات المُفعّلة» dropdown next
  to the existing speed picker. Values: `قفل (5)` / `10` / `50` / `100`
  / `مخصّص…`. Super-admin only; non-super sees a read-only chip.
* **Plan form** — same field on the plan; resolver falls back here when
  the customer row says 0.
* **«اتصالات الوصول» tunnel row** — small chip «السرعة الفعّالة: 5M/5M»
  (or whatever the resolver returns) so the operator can see at a glance
  what the customer is being served.

### 12.5 What ships now vs design-only

| Layer | Tonight | Follow-up |
|---|---|---|
| `customers.subdomain` column + heal + `assign_subdomain` + `customer_fqdn` helpers | **built** | — |
| `customers.speed_unlock_mbps` + `plans.speed_unlock_mbps` columns + heal | **built** | — |
| `app/services/customer_speed_enforcement.py` — `resolve_speed_for(...)` + `mikrotik_rate_limit_for(...)` | **built** | — |
| Tests pinning default 5M / customer overrides / plan fallback / ceiling binds / `radius_transport` exemption | **built** | — |
| Wildcard cert + DNS automation (ops/deploy) | **design-only (§11.3)** | `DEPLOY_PANEL.md` §"Wildcard TLS + DNS" + certbot DNS-01 cron |
| CHR script renderer switch to the wildcard | **design-only (§11.3)** | per-CHR unified-script template patch + cert push |
| Owner-set unlock UI on customer page + plan form | **design-only (§12.4)** | mechanical clone of existing speed pickers; `serialize_for_ui()`-style hook ready |
| CoA on speed-unlock change | **design-only (§12.3 step 3)** | one-line emit through the existing Phase-7 proxy CoA path |

The foundation locked in (§12.1 + §12.2 + §12.3 emission, all tested)
makes every UI/ops follow-up additive. The monetization control —
default 5M, owner unlocks 10/50/100 — IS the wire path now; UI is the
final mile.
