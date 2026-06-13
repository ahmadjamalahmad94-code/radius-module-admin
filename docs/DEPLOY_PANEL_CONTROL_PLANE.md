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
| Panel `wg-mgmt` **public** key | `GKkomdrepZWPkJ1Bpqy65maeIAJ/hZOmEn52RtdlQhE=` |
| Panel `wg-mgmt` **private** key | server-stored (Fernet-encrypted in `settings`); reveal once — see § 2 Path B |
| First CHR `wg-mgmt` IP | `10.99.0.11` (`chr-vpn-1`)        |
| `chr-vpn-1` `wg-mgmt` **public** key | `bkS4myVYQ3U88Rfk7vKjWghNQYLpgQCK+lneq2i9yh8=` |

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

> **For this deployment the panel keypair already exists** — it was minted
> server-side and its public key is `GKkomdrepZWPkJ1Bpqy65maeIAJ/hZOmEn52RtdlQhE=`
> (this is the key already baked into `chr-vpn-1`'s `.rsc`). **Do not
> regenerate** it (that would invalidate every shipped node script). Skip
> straight to **Path B → reveal once** to copy the matching private key onto
> the host. Path A is documented for future fleets where you start from
> scratch.

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
# → must print exactly:
#   GKkomdrepZWPkJ1Bpqy65maeIAJ/hZOmEn52RtdlQhE=
```

The recomputed pubkey **must** equal `GKkomdrepZWPkJ1Bpqy65maeIAJ/hZOmEn52RtdlQhE=`
(the value the infra-settings page shows). If it doesn't, you copied wrong —
re-reveal and paste again. **Do not** regenerate the keypair to "fix" a
mismatch — that breaks every node already holding `GKkom…`.

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

Take that public-key value. **For `chr-vpn-1` it is already known** —
`bkS4myVYQ3U88Rfk7vKjWghNQYLpgQCK+lneq2i9yh8=` — so you can append the peer
block without SSHing the CHR (still worth confirming with the `print` above
if in doubt). On the panel host:

```bash
# Edit /etc/wireguard/wg-mgmt.conf — append:
[Peer]
# chr-vpn-1 — allocated wg-mgmt IP 10.99.0.11
PublicKey  = bkS4myVYQ3U88Rfk7vKjWghNQYLpgQCK+lneq2i9yh8=
AllowedIPs = 10.99.0.11/32
PersistentKeepalive = 25
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

This `ping` is **exactly what the health monitor does** (it shells out to
`ping` over `wg-mgmt`). So the moment 4/4 replies come back, the node is
reachable for health:

* **Flip it now:** on the panel, open the **CHR Fleet dashboard** and click
  **«فحص الآن»** on `chr-vpn-1` (or **«فحص الكل»**). A node that has never
  been probed flips to **«نشطة»** on this first successful probe.
* **Or wait for the cron pass:** the monitor (`python -m fleet.health.monitor`,
  on its timer) will flip it automatically on its next run. If the node was
  previously `down`, recovery needs 5 minutes of continuous success first.

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

* **Health monitoring runs OVER `wg-mgmt`.** `fleet.health.monitor`
  (`_resolve_target`) probes `node.wg_mgmt_ip` **first** — `10.99.0.11`
  for `chr-vpn-1` — and only falls back to `public_ip` if a node somehow
  has no mgmt IP. The default probe is **ICMP echo** (`IcmpPinger`): the
  panel shells out to `ping -c 1 -W <t> 10.99.0.11` over the tunnel, and
  a reply means "the CHR is alive." It is **not** a TCP dial to RouterOS
  api-ssl — that port (`8729`, binary api-ssl) is **deliberately disabled**
  by the unified script; the only management port the CHR opens is `8443`
  (www-ssl REST), and only on `wg-mgmt` from the panel `/32`, for the
  separate live-metrics collector — never for the up/down probe.
  **Consequence: bringing this tunnel up is exactly what lets the monitor
  reach the CHR.** Until `wg-mgmt` is up, `ping 10.99.0.11` fails and the
  node reads `down`; the moment the tunnel is up and ICMP flows, the next
  probe flips it to **`up` / «نشطة»**. (A never-probed node — health state
  `unknown` — flips up on the **first** successful ping; a node already in
  `down` needs continuous success for `up_after` = **5 min** before it
  flips back.)
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

**Translation:** completing this runbook is what flips `chr-vpn-1` (and
every future CHR) to **«نشطة»** on the dashboard — the health monitor can
only reach the node once this tunnel is up. It also (a) proves the tunnel
works end-to-end, (b) gives the operator an out-of-band ssh/Winbox path
into each CHR that doesn't depend on the CHR's public IP, and (c) makes the
`.rsc`'s `endpoint-address=control.hoberadius.com:51820` line resolve to a
live listener instead of a black hole. The live panel→CHR *command* paths
(config push, log streaming) are still future work — but **health is no
longer one of them; it rides this tunnel today.**

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

### Node still shows «معطّلة»/`down` even though `ping 10.99.0.11` works

* Is the monitor actually running? It flips state only when it runs.
  Trigger one pass by hand from the panel host:
  ```bash
  cd /opt/hoberadius-license-panel
  python -m fleet.health.monitor      # one probe over every enabled node
  ```
  or click **«فحص الآن»** on the dashboard for an immediate probe.
* The node must be `enabled = TRUE` and `drain = FALSE` — a disabled node
  is never probed on the cron path (only via the explicit «فحص الآن»).
* If it was already `down`, the up-edge needs **5 min** of *continuous*
  successful pings (`HealthConfig.up_after`). A single «فحص الآن» won't
  shortcut that window — keep the tunnel healthy and it settles.
* Confirm the probe target is the mgmt IP: the monitor pings
  `node.wg_mgmt_ip` (`10.99.0.11`), not the public IP. If `wg_mgmt_ip` is
  blank on the row, fix the registry — the public-IP fallback won't pass
  (the CHR firewall blocks ICMP/api there by design).

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
