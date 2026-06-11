# Customer RADIUS ↔ Proxy Tunnel — Design + Cross-Repo Contract
**Status:** APPROVED DESIGN (no code yet) · **Date:** 2026-06-12 · **Spec for 3 parallel build agents**
**Repos:** radius-module-admin (panel @ `ffaa2e6`) · radius-module (customer) · radius-proxy

> **THE GAP (live-confirmed):** the proxy forwards client5's RADIUS auth to
> `10.200.5.2:1812`, but `ping 10.200.5.2` from the proxy = 100% loss — the
> WireGuard tunnel between the customer's RADIUS server (187.77.70.18) and the
> proxy **does not exist**. Nothing today creates it. This document designs its
> auto-provisioning — the customer-side analog of the CHR↔proxy `wg-data`
> tunnel that already works.

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

## 6. The FreeRADIUS secret (one secret, two consumers)

The secret ALREADY has a single source of truth: `provision_on_link` mints it
into `Setting["radius_secret.customer.<id>"]` (Fernet) and points
`ProxyRealmRoute.secret_vault_ref` at it (`app/services/radius_auto_provision.py:59-110`).
Today it reaches ONE consumer — the proxy — in plaintext via
`/api/proxy/routing-table` (`routing_table.py:121` on the proxy ingests it).

Design: the SAME stored secret is included as `radius_tunnel.radius_secret` in
EVERY heartbeat response (§3.2) — not once — so the radius side can always
reconverge (lost disk, reinstall) without operator action. Channel security is
identical to the proxy path (HTTPS + authenticated peer). The radius side
writes it only into `proxy-client.conf` (never logs it; reuse the wizard's
secret-charset guard). Rotation = owner edits/regenerates in panel → next
routing-table refresh updates the proxy (≤60s) and next heartbeat updates
FreeRADIUS (≤300s); the brief skew window equals today's router-secret
rotation behaviour.

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
7. **Tests:** allocator determinism + bounds (`customer_id` overflow), pubkey
   ingest + change-audit, `radius_tunnel` block shape (enabled/disabled, no
   proxy key configured ⇒ `proxy_public_key:""`), radius-peers endpoint
   (auth-gated 401, complete-set semantics, /32 allowed_ips, excludes
   disabled + missing-pubkey instances), secret always present in response,
   heartbeat round-trip integration.

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
6. **Tests:** clone the `tests/test_wg_peer_sync.py` matrix against the new
   JSON key + interface (fetch/parse/validate, complete-set add/remove,
   managed-state protection, dry-run degradation, 404-inert), loop
   registration smoke, sudoers script idempotence if tested today.

### Sequencing
Panel (A) ships first — endpoints tolerate empty peer sets and missing proxy
settings. B and C are then independent and parallel. End-to-end acceptance:
on the live pair, after one heartbeat + one reconcile cycle,
`ping 10.200.5.2` from the proxy succeeds and a CHR test-auth for
`user@client5` returns Access-Accept end-to-end.
