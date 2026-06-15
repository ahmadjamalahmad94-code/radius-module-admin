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

## Files

| File | Role |
|---|---|
| `cloud-init.yaml` | **Generated** self-contained user-data (PRIMARY delivery). |
| `build_cloud_init.py` | Regenerates `cloud-init.yaml` from the sources below. |
| `setup-radius-vps.sh` | The idempotent activation script (both delivery paths). |
| `accel-ppp.conf.tmpl` | accel-ppp config template (rendered per-VPS). |
| `agent/` | On-VPS executor: cert automation (tested) + WG/tc/session skeleton. |

> `cloud-init.yaml` is generated — never hand-edit the base64 blobs. Edit the
> sources and run `python3 build_cloud_init.py > cloud-init.yaml` (a unit test
> enforces they stay in sync).

## LAB-PENDING (before any live customer)

- exact accel-ppp `Filter-Id` shaper rate form; `Session-Octets-Limit` (227)
  support on the pinned build; NAS source IP for Disconnect (CoA secret match);
- the agent's WG-peer/`tc`-shaper classid allocator + the `--serve` daemon loop
  are skeleton stubs (see [`agent/README.md`](./agent/README.md));
- confirm `WG_DATA_PORT` does not clash with the mgmt/data WG already on the box;
- if the provider firewalls port 80, switch certbot to `--webroot` or DNS-01.
