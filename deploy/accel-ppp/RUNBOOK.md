# RUNBOOK — accel-ppp DATA-connection activation (LIVE stage)

Operator guide to bring up a customer's RADIUS VPS as a DATA-connection BRAS.
Follow top-to-bottom; each step has a **verify** you must see green before moving on.

> Architecture: DATA VPNs are served **directly** by accel-ppp on the customer's
> own VPS — no proxy, no CHR, no panel in the data path. The panel only points
> the subdomain at the VPS (Cloudflare DNS); the VPS issues its own TLS cert.

---

## 0. Prerequisites

- [ ] Panel Settings → **`CLOUDFLARE_API_TOKEN`** is set (scoped: `Zone.DNS:Edit`
      on `hoberadius.com`). Verify: the customer DNS-sync action succeeds (step 1).
- [ ] You can create the VPS at the provider and set **user-data** (cloud-init).
      If not, use the **Manual fallback** (step 2b).
- [ ] You know the VPS's **public IP** before/at creation, the customer's plan
      (speed/quota), and a **RADIUS shared secret** (≥ 32 random chars).
- [ ] **Local radius-module is configured** (this script does NOT touch it): it
      must accept a RADIUS **client `127.0.0.1`** with the **same** shared secret,
      and return **`Filter-Id=5120`** (5 Mbit) for DATA users — plus at least one
      **test RADIUS user** (username/password) to verify a connection. The owner's
      model is **5 Mbit cap, NO quota, NO disconnect** (no Session-Octets-Limit /
      no CoA-Disconnect needed).
- [ ] The script enables **IPv4 forwarding + NAT MASQUERADE** for the pool and
      **opens 80/443/1723+GRE** surgically (ADD-only; never flushes, never sets a
      default-DROP, never touches SSH). On an **existing** box it warns (non-fatal)
      if **:443 / :80 / :1723** are already in use — free :443 (SSTP can't share it).
- [ ] Decide the ACME challenge: **`auto`** (default — probes port 80) is fine
      unless you already know inbound **:80 is firewalled** at this provider, in
      which case plan for **DNS-01** (needs a Cloudflare token on the VPS — see §6).

---

## 1. Panel — add the customer + VPS IP → subdomain DNS record

1. Customers → **add/edit** the customer. Set **VPS IP** to the VPS's public IP.
2. On the customer record, click **«مزامنة النطاق الفرعي (DNS)»**.

**Verify (panel):**
- The customer record shows **DNS state = «مُزامَن»** with a recent «آخر مزامنة».
- FQDN shown is `clientN.hoberadius.com`.

**Verify (independent DNS):**
```bash
dig +short clientN.hoberadius.com    # → the VPS public IP
```
Do this **before** creating the VPS so the record has time to propagate.

---

## 2a. Create the VPS with cloud-init (PRIMARY)

1. Open `deploy/accel-ppp/cloud-init.yaml`. Fill the `# >>> SET ME` block:
   `VPS_IP`, `SUBDOMAIN` (= the FQDN), `RADIUS_SECRET`, `CERTBOT_EMAIL`
   (optional: `WG_DATA_PORT`, `POOL_*`, `DNS_WAIT_TIMEOUT`, `CERT_CHALLENGE`).
2. Paste the whole file into the provider's **user-data** field. Create the VPS
   with that IP.

First boot runs `setup-radius-vps.sh`: installs accel-ppp + certbot, renders the
config, installs the agent, waits for DNS, issues the cert, wires renewal, and
starts accel-ppp.

**Verify (on the VPS), in order:**
```bash
# activation log (cloud-init runcmd tee's here)
tail -n 50 /var/log/hoberadius-activation.log

systemctl status accel-ppp            # → active (running)
ls -l /etc/letsencrypt/live/clientN.hoberadius.com/fullchain.pem   # cert present
accel-cmd show sessions               # → header prints (0 sessions is fine)
ss -lun | grep -E ':(1701)\b' ; ss -ltn | grep -E ':(443|1723)\b'  # listeners up
```

---

## 2b. Manual fallback (no cloud-init)

Do step 1 first, then on the VPS:
```bash
sudo VPS_IP=203.0.113.10 SUBDOMAIN=clientN.hoberadius.com \
     RADIUS_SECRET='…32+ random chars…' CERTBOT_EMAIL=you@example.com \
     bash setup-radius-vps.sh
```
Same script, same verifies as 2a. Re-running is safe (idempotent).

---

## 3. Verify a real connection (per protocol you offer)

- **SSTP (Windows / RouterOS v7):** connect to `clientN.hoberadius.com:443`.
  Native Windows SSTP trusts the **public Let's Encrypt** cert with **no import**.
  Verify: client connects; `accel-cmd show sessions` lists the session with an IP
  from `POOL_RANGE`.
- **PPTP:** connect to the VPS IP / FQDN; verify session appears (legacy/weak —
  offer only if required).
- **WireGuard (v7):** the panel publishes the peer; the agent reconcile daemon
  applies it. Verify: `wg show wg-data` lists the peer; `tc -s class show dev
  wg-data` shows the per-peer class with the rate cap.

**Verify shaping:** run a speed test from the client → throughput is capped at the
plan rate (default 5 Mbit). (The exact `Filter-Id` form is LAB-PENDING — see §7.)

**Verify internet egress (NAT):** from a connected client, browse / ping `1.1.1.1`
— traffic must reach the internet (forwarding + MASQUERADE). On the VPS:
```bash
sysctl net.ipv4.ip_forward                              # = 1
iptables -t nat -S POSTROUTING | grep MASQUERADE        # pool → WAN masquerade present
systemctl status hoberadius-accel-net                   # active (exited) — reboot-safe
iptables -S INPUT | grep -E 'dport (80|443|1723)'       # surgical opens present
```

> **WireGuard (v7):** the SSTP/PPTP path above is the **live, lab-validated** one
> (RouterOS v7 has a first-class SSTP client that trusts the public LE cert with
> no import). WG-native is **scaffolded but not lab-validated** — the script opens
> the WG udp port only when `ENABLE_WG_DATA=1`, but the WG **server bring-up**,
> the **peer-publish** from the panel, and the **tc** shaper are LAB-PENDING (§7).
> Install SSTP/PPTP now; treat WG as a later phase.

---

## 4. Verify auto-renewal

```bash
systemctl list-timers | grep certbot          # certbot.timer scheduled
certbot renew --dry-run                        # succeeds
ls /etc/letsencrypt/renewal-hooks/deploy/      # 10-reload-accel-ppp.sh present
```
On renewal the deploy-hook runs `vps_agent.py --reload-accel` (graceful reload,
full restart only as a last resort).

---

## 5. Verify the reconcile daemon (WireGuard peers)

Only when `PEER_SOURCE_URL` is set (else the unit is installed but DISABLED):
```bash
systemctl status radius-vps-agent              # active (running)
journalctl -u radius-vps-agent -n 50           # "reconcile daemon on wg-data…"
wg show wg-data peers                           # matches the panel's desired set
```
The daemon **only removes peers it added** — operator-added WG peers are never
touched (safe-by-default). Each peer gets a **unique** tc classid (collision-free
allocator), so two pool IPs sharing a last octet no longer clash.

---

## 6. Cert challenge & the DNS-01 security trade-off

- **`CERT_CHALLENGE=auto`** (default): probe port 80 → HTTP-01 if reachable, else
  DNS-01.
- **HTTP-01** (preferred): no secrets on the VPS; needs inbound **:80** reachable
  (the panel's A record makes the name resolve here).
- **DNS-01** (fallback for firewalled :80): certbot's Cloudflare plugin writes a
  TXT record. **Trade-off:** this puts a **Cloudflare API token on the VPS**
  (`/etc/letsencrypt/cloudflare.ini`, mode 600). Mitigate by minting a **separate,
  narrowly-scoped token** (`Zone.DNS:Edit` on `hoberadius.com` only) — NOT the
  panel's token, and revoke it independently if the VPS is decommissioned.
  Set `CERT_CHALLENGE=dns01` (or `auto`) **and** `CLOUDFLARE_API_TOKEN=…`.
- Alternative without any VPS token: serve the HTTP-01 challenge from an existing
  webroot (`--webroot`) if something already listens on :80.

Verify which path ran: `grep "ensure-cert" /var/log/hoberadius-activation.log`
→ `cert issued for … via http01` (or `via dns01`).

---

## 7. Troubleshooting & the LAB-PENDING knobs

| Symptom | Check | Fix |
|---|---|---|
| Cert not issued, log says "DNS wait failed" | `dig +short clientN.hoberadius.com` | Ensure step 1 done + propagated; re-run the script (idempotent). |
| Cert not issued, ":80 unreachable" / HTTP-01 fails | provider firewall on :80 | `CERT_CHALLENGE=dns01` + `CLOUDFLARE_API_TOKEN=…`, re-run (§6). |
| accel-ppp won't start | `journalctl -u accel-ppp` | Usually a missing cert path — fix the cert, then `systemctl restart accel-ppp`. |
| WG data port clash at install | activation log "udp/<port> in use" | Re-run with a free `WG_DATA_PORT=<port>`. |
| Reconcile daemon refuses to start | `journalctl -u radius-vps-agent` | Set `PEER_SOURCE_URL` (+ token); wire the HMAC auth (LAB-PENDING). |

**LAB-PENDING knobs — confirm LIVE, then set (do NOT guess these):**

1. **`Filter-Id` shaper rate form** — confirm the exact string the pinned
   accel-ppp build accepts (symmetric kbit `"10240"` vs `rx/tx` `"10240/10240"`,
   kbit vs bit). Test a connect + speed test, then set the form in
   `radius-module`'s attribute emitter.
2. **`Session-Octets-Limit` (attr 227)** — confirm whether the build honors it.
   If yes, set it as the in-NAS quota hint; if not, rely solely on the
   server-side accounting → Disconnect path (already the authoritative cutoff).
3. **Disconnect NAS source IP** — confirm the source IP accel-ppp uses for
   DM/CoA (loopback vs VPS public) so the CoA secret/client config matches, then
   set it where `radius_coa.py` targets the NAS.
4. **Peer-source HMAC auth + endpoint path** — wire `HttpPeerSource` to the
   panel's `/api/proxy/wg-peers`-style contract with the real `X-Proxy-Token`
   signing before enabling the reconcile daemon in production.
5. **tc shaper direction** — confirm ingress vs egress on the live kernel/
   iproute2 so the cap applies to the intended traffic direction.
