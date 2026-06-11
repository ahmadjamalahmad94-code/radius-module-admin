# Deploy the Panel Control Plane (`wg-mgmt`)

This runbook brings up the **WireGuard control-plane interface on the panel
host** so every CHR in the fleet can dial home to `control.hoberadius.com:51820`.
The CHR provisioning script the panel renders already configures its end of
this tunnel — this document is what you do on the **panel server** to receive
those connections.

| Component             | Value                              |
| --------------------- | ---------------------------------- |
| Panel host (this VM)  | `178.105.180.6`                    |
| Panel DNS names       | `hoberadius.com`, `control.hoberadius.com` |
| Proxy host (separate) | `178.105.251.67`                   |
| WireGuard interface   | `wg-mgmt`                          |
| Panel `wg-mgmt` IP    | `10.99.0.1/24` (gateway for the fleet) |
| Panel `wg-mgmt` port  | `UDP 51820`                        |
| First CHR `wg-mgmt` IP | `10.99.0.11`                      |

> **What this tunnel is for today.** Read [§ Panel ↔ CHR control-plane —
> what's wired, what isn't](#panel--chr-control-plane--whats-wired-what-isnt)
> **before** you start, so you know what `wg-mgmt` actually does in the
> current build versus what's reserved for future tooling.

---

## 0. Pre-flight checks

On your laptop:

```bash
ssh root@178.105.180.6 'uname -a; ip -4 addr show; ss -lntu | grep :51820 || echo "51820 is free"'
```

You should see Ubuntu 22.04+ and `51820 is free`. If something already
listens on UDP 51820, stop here and figure out what — do not reuse the
port silently.

---

## 1. Install WireGuard

On the panel host:

```bash
apt update
apt install -y wireguard wireguard-tools qrencode
modprobe wireguard
lsmod | grep wireguard       # confirm kernel module loaded
```

`qrencode` is convenient when you later add a CHR by phone-tethered hotspot.
The other two are mandatory.

---

## 2. Obtain the panel WG keypair

You have two paths. **Path A is preferred** because the panel never sees
your private key — easier to reason about and aligns with how the
infra-settings page is designed.

### Path A — Generate on the host (recommended)

On the **panel host**:

```bash
umask 077
mkdir -p /etc/wireguard
cd /etc/wireguard
wg genkey | tee wg-mgmt.key | wg pubkey > wg-mgmt.pub
chmod 600 wg-mgmt.key
chmod 644 wg-mgmt.pub
cat wg-mgmt.pub
```

Copy that 44-character base64 line. On the panel, open
**أسطول CHR → إعدادات البنية → الباب الخلفي للوحة**, paste it into
**«المفتاح العام للوحة»**, click **«حفظ المفتاح العام»**. The page
records an audit row `fleet_infra_panel_pubkey_pasted` and shows the
key as «مضبوط ✓».

> If you previously clicked the «توليد على الخادم» button (Path B),
> pasting your own pubkey here also **deletes the server-stored
> private-key ciphertext** so the host copy is the only one. The flash
> message will say so explicitly.

### Path B — Let the panel mint it, then reveal once

If you prefer the panel to generate the keypair (e.g. you'd rather have
the panel's encrypted vault hold the backup), open the same page,
expand **«بديل: توليد الزوج على الخادم»**, click **«توليد على الخادم»**.
A private key is generated on the panel and stored Fernet-encrypted in
the `settings` table under `fleet.infra.PANEL_WG_PRIVKEY`.

To install it on the host, click **«كشف/تنزيل المفتاح الخاص للوحة»** —
the page shows the 44-char private key in a copy-to-clipboard box and
writes an audit row `fleet_infra_panel_privkey_revealed`. **Copy it
immediately** into `/etc/wireguard/wg-mgmt.key`:

```bash
umask 077
mkdir -p /etc/wireguard
printf '%s\n' '<paste-private-key-here>' > /etc/wireguard/wg-mgmt.key
chmod 600 /etc/wireguard/wg-mgmt.key
# Recompute the pubkey from the privkey for cross-checking:
wg pubkey < /etc/wireguard/wg-mgmt.key
```

The recomputed pubkey **must** match what the infra-settings page is
showing. If it doesn't, you copied wrong — paste again.

After installation, you may want to switch to Path A's posture: paste
your own pubkey (computed above) back into the infra page. That deletes
the server's copy of the private key, leaving the host's copy
authoritative — recommended over time.

---

## 3. Write `/etc/wireguard/wg-mgmt.conf`

The panel host is the **server** end of `wg-mgmt`; every CHR is a peer.

Start with the interface block. **You only fill the [Peer] blocks once
CHRs come online** — initially you may have zero peers and that's fine.

```bash
cat > /etc/wireguard/wg-mgmt.conf <<'EOF'
# Panel control-plane — WireGuard server
# Each CHR appears here as a [Peer] block once it joins the fleet.

[Interface]
Address    = 10.99.0.1/24
ListenPort = 51820
PrivateKey = <paste contents of /etc/wireguard/wg-mgmt.key here>
# Read the privkey from a file instead of inlining it — safer rotation:
#   wg set wg-mgmt private-key /etc/wireguard/wg-mgmt.key
SaveConfig = false

# === Peers (one block per CHR) ===
# [Peer]
# # chr-vpn-1 (allocated 10.99.0.11 by the onboarding wizard)
# PublicKey  = <wg-mgmt PUBLIC key from CHR's `/interface wireguard print`>
# AllowedIPs = 10.99.0.11/32
EOF

chmod 600 /etc/wireguard/wg-mgmt.conf
```

Replace the `PrivateKey =` line with the actual 44-char private key
from `wg-mgmt.key`. Alternative: leave `PrivateKey` out and use
`PostUp = wg set %i private-key /etc/wireguard/wg-mgmt.key` — keeps the
private side in one file.

> **Why `Address = 10.99.0.1/24`** — the CHRs generate `wg-mgmt`
> addresses out of `10.99.0.0/24` starting at `.11`. Pool prefix
> `_WG_MGMT_POOL_PREFIX = "10.99.0."` lives in
> `fleet/registry/onboarding_service.py` — change it there if you ever
> renumber.

---

## 4. Bring the interface up + persist

```bash
systemctl enable --now wg-quick@wg-mgmt
wg show wg-mgmt
ip -4 addr show wg-mgmt
```

You should see the interface up with `inet 10.99.0.1/24`, listen-port
51820, no errors. `wg show` reports zero peers until you add CHRs in
§ 6 below.

---

## 5. Open UDP 51820 (host + cloud firewall)

### Local firewall (ufw)

```bash
ufw allow 51820/udp comment 'wg-mgmt control plane'
ufw status verbose
```

### Cloud provider firewall

On the provider's panel (Hetzner / DigitalOcean / Vultr / …), open an
inbound rule:

| Field      | Value         |
| ---------- | ------------- |
| Direction  | Inbound       |
| Protocol   | UDP           |
| Port       | 51820         |
| Source     | 0.0.0.0/0     |

CHRs come from variable public IPs; you can't lock the source. The
WireGuard handshake itself rejects anything not signed by a configured
peer pubkey, so UDP open is the right posture here.

### DNS — `control.hoberadius.com`

In Cloudflare DNS:

| Type | Name      | Content          | Proxy status     | TTL  |
| ---- | --------- | ---------------- | ---------------- | ---- |
| A    | `control` | `178.105.180.6`  | **DNS only** (grey cloud) | Auto |

**Must be DNS-only** (orange-cloud / proxied breaks WireGuard — Cloudflare
proxy is HTTPS-only). Wait 2–5 minutes, then on your laptop:

```bash
dig +short control.hoberadius.com
# → 178.105.180.6
```

Now the «نقطة وصول اللوحة» in the infra page can be set to
`control.hoberadius.com:51820`. That value (`PANEL_WG_ENDPOINT`) is
what each CHR's WireGuard peer block points to via
`endpoint-address=control.hoberadius.com:51820` in the unified
RouterOS template.

---

## 6. Onboard a CHR — its pubkey lands here as a `[Peer]` block

When the onboarding wizard finishes provisioning a CHR (status →
`active`), grab the CHR's `wg-mgmt` **public** key from the CHR itself.
SSH to the CHR (or use Winbox) and run:

```routeros
/interface wireguard print where name=wg-mgmt
# → name="wg-mgmt"  …  public-key="…44-char base64…"  …
```

Take that public-key value. On the panel host:

```bash
# Edit /etc/wireguard/wg-mgmt.conf — append:
[Peer]
# chr-vpn-1 — allocated wg-mgmt IP 10.99.0.11
PublicKey  = <44-char CHR wg-mgmt public key>
AllowedIPs = 10.99.0.11/32
```

Apply without restarting the interface (preserves in-flight traffic on
the other peers):

```bash
wg syncconf wg-mgmt <(wg-quick strip wg-mgmt)
wg show wg-mgmt
```

You should now see a peer line for the CHR. The CHR's wg client will
initiate the handshake as soon as its `persistent-keepalive=25s` fires.

---

## 7. Verify the tunnel works

On the panel host:

```bash
wg show wg-mgmt
# Expect:
#   peer: <CHR pubkey>
#     endpoint: <CHR public IP>:51820
#     latest handshake: 4 seconds ago
#     transfer: … received, … sent

ping -c 4 10.99.0.11        # ping the CHR's wg-mgmt IP
# Expect 4/4 replies, ~ms latency over the public network.
```

If `latest handshake: (none)` after 60 s:

* Confirm the CHR's wg-mgmt peer endpoint resolves to `178.105.180.6`
  (DNS-only A record live? `dig +short control.hoberadius.com` from
  the CHR).
* Confirm UDP 51820 reaches the panel from the CHR's public IP
  (`tcpdump -i any udp port 51820 -n` on the panel while the CHR
  retries).
* Confirm the panel pubkey in the CHR's `.rsc` matches the one the
  infra page is showing. If you re-generated the panel key after
  shipping a script, the CHR is using a stale `public-key=` — re-render
  its `.rsc` from the dashboard.

---

## 8. Set the infra page

Once the host is up, fill the infra-settings page:

| Field                  | Value                              |
| ---------------------- | ---------------------------------- |
| المفتاح العام للوحة   | (from § 2 — pasted)                |
| نقطة وصول اللوحة      | `control.hoberadius.com:51820`     |

The «حالة الإعدادات» panel shows `PANEL_WG_PUBKEY` and
`PANEL_WG_ENDPOINT` as **«مضبوط ✓»**.

---

## Panel ↔ CHR control-plane — what's wired, what isn't

**Honest current state of the code in this repo:**

* **Health monitoring does NOT depend on `wg-mgmt`.** `fleet.health.monitor`
  picks `node.public_ip` first (TCP-connect probe to the RouterOS API
  port, default `8729`), and only falls back to `node.wg_mgmt_ip` if
  `public_ip` is empty (a path that's effectively dead today, since the
  onboarding form requires a public IP). Bringing `wg-mgmt` up does
  **not** unlock health-polling — that already works as soon as the CHR
  is reachable on the public internet at its api-ssl port.
* **No live panel→CHR command path goes over `wg-mgmt` yet.**
  - The brain (`fleet.brain`) is pure-DB algorithm — it doesn't connect
    to any CHR.
  - The enforcement flag (`fleet.control.live_apply`) is a boolean the
    **proxy** reads from the panel's `/api/proxy/routing-table` JSON.
  - The brain's session moves (CoA-disconnect / rebalance) are handed to
    the **proxy**, which talks to CHRs via RADIUS CoA (UDP 3799) over
    the **`wg-data`** tunnel — not `wg-mgmt`.
  - The bootstrap pusher (`fleet.registry.bootstrap_push`) has no
    transport registered yet (Phase-7 work) and was always the *first
    contact* channel, not a steady-state one.
* **What `wg-mgmt` IS today:** the architectural control plane that
  every CHR's `.rsc` brings up, addressed and routed end-to-end. Once it
  comes up on a CHR, the panel can `ping 10.99.0.11` and SSH/Winbox over
  it — useful for the operator, and the channel future panel→CHR tooling
  (live config push, log streaming, on-demand `wg show`) will sit on.

**Translation:** completing this runbook does not magically light up
extra features in the panel today. It does (a) prove the tunnel works
end-to-end, (b) give the operator an out-of-band ssh path into each CHR
that doesn't depend on the CHR's public IP / management firewall, and
(c) make the `.rsc`'s `endpoint-address=control.hoberadius.com:51820`
line not point at a black hole. Health polling will keep working over
the public IP regardless.

---

## Troubleshooting

### `wg-quick@wg-mgmt` won't start

```bash
journalctl -u wg-quick@wg-mgmt -n 50 --no-pager
```

Common causes:
* **Bad PrivateKey** — `Line unrecognized: 'PrivateKey'` usually means
  the key has whitespace. Re-paste without trailing newline.
* **`Address` conflict** — `RTNETLINK answers: File exists`: something
  else holds `10.99.0.1`. `ip -4 addr show | grep 10.99` to find it.
* **Module missing** — `modprobe wireguard` failed: install kernel
  headers (`apt install linux-headers-$(uname -r)`).

### Handshake never completes from a CHR

* `tcpdump -ni any udp port 51820` on the panel: do you see inbound
  packets? If no, the CHR can't reach you — cloud-firewall or
  Cloudflare-proxy-on issue.
* If yes but they're rejected: pubkey mismatch. The `[Peer] PublicKey`
  in `wg-mgmt.conf` MUST be the **CHR**'s public key, not the panel's.
  And the CHR's `.rsc` `public-key="…"` for `wg-mgmt` peer MUST be the
  **panel**'s. These two sides crossed is a common copy-paste error.

### `ping 10.99.0.11` times out though handshake is up

* `ip route` on the panel: `10.99.0.0/24 dev wg-mgmt` must be present.
  If not, the interface didn't come up cleanly — `systemctl restart
  wg-quick@wg-mgmt`.
* CHR side: `/ip route print` must have `10.99.0.0/24` reachable via
  `wg-mgmt`. The unified template doesn't add a default route via
  `wg-mgmt` on purpose — that's correct (we don't want control-plane
  carrying data).

### Rotating the panel key later

Generate a new keypair (Path A again), paste the new pubkey on the
infra page. **Every existing CHR script becomes invalid** — re-render
each from the dashboard's «عرض السكربت» and re-import on the CHR. The
infra page warns you about this before the replace.

### Removing a CHR

When you delete a CHR from the fleet (dashboard → «حذف»), also remove
its `[Peer]` block from `wg-mgmt.conf` and `wg syncconf wg-mgmt <(wg-quick strip wg-mgmt)`.
A dangling peer block is harmless but accumulates.

---

## Cheatsheet

```bash
# Status
wg show wg-mgmt
ip -4 addr show wg-mgmt
systemctl status wg-quick@wg-mgmt

# Reload config without dropping live peers
wg syncconf wg-mgmt <(wg-quick strip wg-mgmt)

# Restart cleanly
systemctl restart wg-quick@wg-mgmt

# Live packet capture
tcpdump -ni any udp port 51820

# Routing table — confirm 10.99.0.0/24 → wg-mgmt
ip route | grep wg-mgmt

# What the infra-settings page is showing the fleet
psql -d license_panel -c "select key, value from settings where key like 'fleet.infra.PANEL%'"
```
