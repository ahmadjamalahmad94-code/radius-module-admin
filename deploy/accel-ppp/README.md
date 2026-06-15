# accel-ppp DATA-connection activation (2c)

Turns a customer's RADIUS VPS into a DATA-connection BRAS (SSTP / PPTP / L2TP
served **directly** by accel-ppp — no proxy, no CHR, no panel in the data path).
The TLS cert is issued **on the VPS** by certbot (HTTP-01); the panel's only job
is to point the subdomain at the VPS so that issuance can succeed.

## End-to-end order (get this right)

**(a) Panel — add the customer + VPS IP → DNS record is auto-created.**
In the licensing panel, create/edit the customer and set **VPS IP** to the
public IP the VPS will have. Then trigger **مزامنة النطاق الفرعي (DNS)** on the
customer record. The panel:
- assigns the deterministic subdomain `clientN.hoberadius.com`, and
- creates a **DNS-only A record** `clientN.hoberadius.com → <VPS IP>` via the
  Cloudflare API (requires `CLOUDFLARE_API_TOKEN` in panel Settings).

This happens **before** the VPS exists, so by first boot the name already
resolves.

**(b) Create the VPS with the cloud-init user-data → zero-touch activation.**
Fill the `# >>> SET ME` values in [`cloud-init.yaml`](./cloud-init.yaml) (VPS IP,
subdomain/FQDN, RADIUS secret, certbot email; WG port/pool optional) and paste
the whole file into the provider's **user-data** field at VPS creation. First
boot runs [`setup-radius-vps.sh`](./setup-radius-vps.sh), which:
1. installs `accel-ppp` + `certbot` + `wireguard-tools`,
2. renders `/etc/accel-ppp.conf` from [`accel-ppp.conf.tmpl`](./accel-ppp.conf.tmpl),
3. installs the [vps-agent](./agent/),
4. **waits (bounded) for `clientN.hoberadius.com` to resolve to this VPS**, then
   **issues the Let's Encrypt cert** via `certbot --standalone` (HTTP-01),
5. wires **auto-renewal** (`certbot.timer`) + a **deploy-hook** that reloads
   accel-ppp on every renewal,
6. starts accel-ppp.

**(c) Done — fully automatic.** The subscriber-facing one-click script lives in
the `radius-module` repo (branches `feat/accel-ppp-radius-attrs`,
`feat/data-connection-oneclick`).

### Manual fallback (no cloud-init)
If the provider can't take user-data, do **(a)** as above, then on the VPS:

```bash
sudo VPS_IP=203.0.113.10 SUBDOMAIN=client5.hoberadius.com \
     RADIUS_SECRET='…32+ random chars…' CERTBOT_EMAIL=you@example.com \
     bash setup-radius-vps.sh
```

Same script, same result.

## Cert automation details

- **DNS-wait before certbot.** `setup-radius-vps.sh` calls
  `vps_agent.py --ensure-cert`, which polls DNS up to `DNS_WAIT_TIMEOUT` (default
  300s) until the subdomain resolves to this VPS, *then* runs certbot. This
  absorbs first-boot propagation lag.
- **Non-fatal.** If DNS never resolves or certbot fails, the script logs a
  precise, actionable message and **continues** — accel-ppp stays installed
  (without SSTP TLS). Fix DNS / port 80 reachability and re-run, or wait for the
  next `certbot.timer` tick. Nothing hard-fails the boot.
- **Idempotent.** `certbot certonly --keep-until-expiring` won't reissue a live
  cert; re-running the whole script is safe.
- **Renewal → reload.** `certbot.timer` renews unattended; the deploy-hook runs
  `vps_agent.py --reload-accel` so accel-ppp serves the fresh chain (graceful
  reload, full restart only as a last resort).

### Challenge selection + DNS-01 fallback (firewalled :80)

`CERT_CHALLENGE=auto` (default) probes port 80 → **HTTP-01** if reachable, else
**DNS-01** via the Cloudflare certbot plugin. Force with `CERT_CHALLENGE=http01`
or `dns01`. HTTP-01 needs nothing secret on the VPS. DNS-01 works when inbound
:80 is blocked, but has a **security trade-off**:

> **DNS-01 puts a Cloudflare API token on the customer VPS**
> (`/etc/letsencrypt/cloudflare.ini`, mode 600). Mint a **separate, narrowly
> scoped** token (`Zone.DNS:Edit` on `hoberadius.com` only) — never reuse the
> panel's token — and revoke it independently when the VPS is decommissioned.
> Set `CERT_CHALLENGE=dns01` (or `auto`) **and** `CLOUDFLARE_API_TOKEN=…`.

### Reconcile daemon (WireGuard peers)

`vps_agent.py --serve` fetches the desired wg-peer set from the panel's
`/wg-peers`-style contract and applies WG peers + per-peer `tc` shapers with a
**collision-free classid allocator**. It is **safe-by-default**: it removes only
peers it added — never an operator-added peer. It's enabled only when
`PEER_SOURCE_URL` is set (else installed but disabled).

### WG data-port clash check

The setup script runs `vps_agent.py --check-wg-port <port>` (parses `ss -lun`)
and warns clearly if the chosen UDP port is already bound; re-run with a free
`WG_DATA_PORT`.

## Files

| File | Role |
|---|---|
| `cloud-init.yaml` | **Generated** self-contained user-data (PRIMARY delivery). |
| `build_cloud_init.py` | Regenerates `cloud-init.yaml` from the sources below. |
| `setup-radius-vps.sh` | The idempotent activation script (both delivery paths). |
| `accel-ppp.conf.tmpl` | accel-ppp config template (rendered per-VPS). |
| `agent/` | On-VPS executor: cert automation + reconcile daemon + WG/tc/session logic. |
| `RUNBOOK.md` | Step-by-step LIVE operator guide (do this for a real customer). |

> `cloud-init.yaml` is generated — never hand-edit the base64 blobs. Edit the
> sources and run `python3 build_cloud_init.py > cloud-init.yaml` (a unit test
> enforces they stay in sync).

The full live procedure (with per-step verifies + troubleshooting) is in
[`RUNBOOK.md`](./RUNBOOK.md).

## LAB-PENDING (genuinely needs a live VPS — do NOT guess)

These stay flagged; confirm each on a live box then set the value:

- exact accel-ppp **`Filter-Id`** shaper rate form (symmetric vs rx/tx, kbit vs bit);
- **`Session-Octets-Limit`** (attr 227) support on the pinned build (else rely on
  the server-side accounting → Disconnect, already authoritative);
- **Disconnect NAS source IP** (loopback vs VPS public) so the CoA secret matches;
- the peer-source **endpoint path + `X-Proxy-Token` HMAC** auth for the reconcile
  daemon (`HttpPeerSource`);
- the **`tc` shaper direction** (ingress vs egress) on the live kernel/iproute2.

Done WITHOUT a live VPS (implemented + unit-tested with fakes): the reconcile
loop, the collision-free classid allocator, the cert challenge selection +
DNS-01 fallback, and the WG-port clash check.
