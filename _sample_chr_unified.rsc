# ============================================================
# HobeRadius unified CHR provisioning script  (v3, idempotent)
# Safe to re-import: every resource removes prior copies first.
# Self-lockout safe: arms a 3m rollback BEFORE
# touching anything; cancels it on clean completion. If you lose your
# session mid-apply, the CHR auto-reverts and you can re-run.
# ============================================================

/system identity set name="chr-vpn-1"

# ============================================================
# 0a. SELF-LOCKOUT GUARD — snapshot + auto-rollback
# ============================================================
# Take a backup of the CURRENT (working) config, then arm a one-shot
# scheduler that, in 3m, loads it back. The
# very last block of this script removes the scheduler. If anything
# below fails or breaks the admin session, the scheduler fires and the
# CHR boots into the snapshot, recovering the prior working state.
:do { /file remove [find name="hobe-fleet-pre-apply.backup"] } on-error={}
/system backup save name="hobe-fleet-pre-apply" dont-encrypt=yes
:delay 1s
/system scheduler
remove [find name="hobe-fleet-rollback"]
add name="hobe-fleet-rollback" interval=3m \
    on-event=(":log warning \"hobe-fleet: rollback fired (no cancel within 3m)\"; /system backup load name=hobe-fleet-pre-apply") \
    policy=read,write,policy,test,password,sensitive \
    comment="hobe-fleet-rollback-guard"
:log info "hobe-fleet: rollback guard armed (3m window) — script must run to completion to cancel it"

# ---- 0b. DNS bootstrap (so :resolve works in section 2b) ----
# If the CHR has no DNS servers configured yet, set a public fallback.
# We DO NOT overwrite an operator-set DNS list.
:if ([:len [/ip dns get servers]] = 0) do={
    /ip dns set servers=1.1.1.1,8.8.8.8 allow-remote-requests=no
    :log info "hobe-fleet: bootstrapped /ip dns servers=1.1.1.1,8.8.8.8 (was empty)"
}

# ---- 1. WireGuard CONTROL tunnel (wg-mgmt) -----------------
# Control/telemetry ONLY. No default route, no NAT, no forwarding over this.
/interface wireguard peers
remove [find interface="wg-mgmt"]
/ip address
remove [find interface="wg-mgmt"]
/interface wireguard
remove [find name="wg-mgmt"]
add name=wg-mgmt listen-port=51820 private-key="MGMT_PRIVKEY_BASE64_PLACEHOLDER=="
/interface wireguard peers

add interface=wg-mgmt public-key="PANELPUBKEY_BASE64_PLACEHOLDER_AAAAAAAAAAAA=" \
    endpoint-address=control.hoberadius.com endpoint-port=51820 \
    allowed-address=10.99.0.1/32 persistent-keepalive=25s \
    comment="hobe-fleet-mgmt"
/ip address
add interface=wg-mgmt address=10.99.0.11/24     ;# e.g. 10.99.0.11/24 (shared mgmt net; /32 broke the return route)


# ---- 2. WireGuard DATA path to RADIUS proxy (wg-data) ------
# Carries ONLY RADIUS 1812/1813 + CoA 3799 to the proxy. Role-gated on
# ``radius_transport``: nodes that are pure VPN terminators (no RADIUS
# transport) skip this block entirely.
/interface wireguard peers
remove [find interface="wg-data"]
/ip address
remove [find interface="wg-data"]
/interface wireguard
remove [find name="wg-data"]
add name=wg-data listen-port=51821 private-key="DATA_PRIVKEY_BASE64_PLACEHOLDER=="
/interface wireguard peers

add interface=wg-data public-key="PROXYPUBKEY_BASE64_PLACEHOLDER_AAAAAAAAAAAA=" \
    endpoint-address=proxy.hoberadius.com endpoint-port=51821 \
    allowed-address=10.98.0.1/32 persistent-keepalive=25s \
    comment="hobe-fleet-data"
/ip address
add interface=wg-data address=10.98.0.11/24     ;# e.g. 10.98.0.11/24 (shared data net; /32 broke the RADIUS return path)


# ---- 2b. Resolve peer hostnames → set IP literal on each peer ----
# Field finding (fix/fleet-endpoint-resolve): RouterOS doesn't always
# resolve the peer host into a working endpoint at peer-add time.
# Retries 5x with 2s back-off; on permanent failure we leave the hostname
# in place + :log error.
:local hobeResolve do={
    :local host $1
    :for i from=1 to=5 do={
        :do {
            :local ip [:resolve $host]
            :log info ("hobe-fleet: resolved " . $host . " -> " . $ip . " (attempt " . $i . ")")
            :return $ip
        } on-error={
            :log warning ("hobe-fleet: :resolve " . $host . " failed (attempt " . $i . "/5)")
            :delay 2s
        }
    }
    :log error ("hobe-fleet: :resolve " . $host . " gave up after 5 attempts; leaving hostname on peer")
    :return $host
}

:local panelIP [$hobeResolve "control.hoberadius.com"]
/interface wireguard peers
set [find comment="hobe-fleet-mgmt"] endpoint-address=$panelIP endpoint-port=51820

:local proxyIP [$hobeResolve "proxy.hoberadius.com"]
/interface wireguard peers
set [find comment="hobe-fleet-data"] endpoint-address=$proxyIP endpoint-port=51821


# ---- 2c. Key-identity audit trail ----
# Identity log lines: when a key mismatch produces a silent dead tunnel,
# /log carries the EXPECTED identities for one-glance comparison against
# «إعدادات بنية الأسطول» on the panel.
:log info ("hobe-fleet: wg-mgmt peer expects PANEL pubkey = PANELPUBKEY_BASE64_PLACEHOLDER_AAAAAAAAAAAA=")

:log info ("hobe-fleet: wg-data peer expects PROXY pubkey = PROXYPUBKEY_BASE64_PLACEHOLDER_AAAAAAAAAAAA=")

:log info ("hobe-fleet: this CHR wg-mgmt pubkey (give to panel) = " . [/interface wireguard get [find name="wg-mgmt"] public-key])


# ---- 3. RADIUS client → the central proxy (FLEET-CONSTANT) -
/radius
remove [find comment="hobe-fleet-radius"]
add service=ppp,login address=10.98.0.1 secret="PLACEHOLDER_central_shared_secret_from_panel" \
    authentication-port=1812 accounting-port=1813 \
    src-address=10.98.0.11 timeout=3s \
    comment="hobe-fleet-radius"
# Force the entry to ENABLED on every (re-)import (X - DISABLED was seen on
# the first live install and silently killed RADIUS).
/radius enable [find comment="hobe-fleet-radius"]
/radius incoming
# Enable CoA / Disconnect listener so panel can kill/move sessions (RFC 5176)
set accept=yes port=3799

# Make PPP + login use RADIUS:
/ppp aaa
set use-radius=yes accounting=yes interim-update=5m


# ---- 4. Shared IP pool + unified PPP profile (FLEET-CONSTANT) --
# §10.2 / §6.5.2: every node carries the SAME pool name + ranges + the
# SAME PPP profile (rate-limit driven by RADIUS Mikrotik-Rate-Limit).
# Subscriber roaming/failover keeps the same Framed-IP and the same
# profile across nodes ⇒ no disconnect.
#
# Idempotent: remove by stable comment/name-prefix, then re-add.
/ppp profile
remove [find comment="hobe-fleet-ppp"]
remove [find name="hobe-fleet-default"]
/ip pool
remove [find name~"^hobe-fleet-pool"]
remove [find name="hobe-fleet-pool"]
add name="hobe-fleet-pool" ranges="10.50.0.10-10.50.255.254" comment="hobe-fleet-pool"
/ppp profile
# IP allocation flow: prefer RADIUS Framed-IP (Access-Accept attribute);
# fall back to the shared pool by name. Same name + ranges on every node
# guarantees the framed IP is also valid post-roam.
add name="hobe-fleet-default" local-address=10.10.0.1 \
    remote-address="hobe-fleet-pool" \
    use-encryption=required dns-server=1.1.1.1,1.0.0.1 \
    only-one=yes comment="hobe-fleet-ppp"
# Built-in default-encryption stays in sync as a safety mirror; CHR-level
# defaults (RouterOS pre-creates `default-encryption`) still need their
# remote-address to point at the shared pool so a tunnel that lands on
# the built-in profile still gets an IP.
set default-encryption local-address=10.10.0.1 \
    remote-address="hobe-fleet-pool" \
    use-encryption=required dns-server=1.1.1.1,1.0.0.1 \
    only-one=yes        ;# RADIUS Framed-IP wins when present


# ---- 5. PPTP server (role: vpn_pptp) ----------------------
/interface pptp-server server
set enabled=yes authentication=mschap2 default-profile=hobe-fleet-default \
    keepalive-timeout=30



# ---- 6. SSTP server (role: vpn_sstp; TLS 443) ----------------


/interface sstp-server server
set enabled=yes port=443 authentication=mschap2 \
    certificate=hobe-sstp-cert tls-version=only-1.2 \
    default-profile=hobe-fleet-default verify-client-certificate=no




# ---- 7. IPsec / IKEv2 server (role: vpn_ipsec) -----------
# IPsec children reference parents by name — clean child→parent order on
# remove, then parent→child on add.
/ip ipsec identity
remove [find peer="hobe-peer"]
/ip ipsec peer
remove [find name="hobe-peer"]
/ip ipsec mode-config
remove [find name="hobe-mc"]
/ip ipsec proposal
remove [find name="hobe-prop"]
/ip ipsec profile
remove [find name="hobe-ike"]
add name=hobe-ike dh-group=modp2048 enc-algorithm=aes-256 hash-algorithm=sha256
/ip ipsec proposal
add name=hobe-prop enc-algorithms=aes-256-cbc,aes-256-gcm pfs-group=modp2048
/ip ipsec mode-config
# Address ALSO via RADIUS for IKEv2 (no local pool); identity = vpn.hoberadius.com
add name=hobe-mc responder=yes

/ip ipsec peer
add name=hobe-peer exchange-mode=ike2 profile=hobe-ike passive=yes
/ip ipsec identity
add auth-method=eap-radius generate-policy=port-strict mode-config=hobe-mc \
    peer=hobe-peer certificate=hobe-ike-cert


# ---- 7b. L2TP/IPsec server (role: vpn_ipsec) ----------------
# L2TP rides inside an IPsec transport. Enable L2TP and require the
# IPsec PSK so a plain-L2TP client can't reach us. The PSK is the same
# central CHR_SHARED_SECRET — the panel is the SINGLE source of truth.
/interface l2tp-server server
set enabled=yes authentication=mschap2 default-profile=hobe-fleet-default \
    use-ipsec=required ipsec-secret="PLACEHOLDER_central_shared_secret_from_panel"



# ---- 7c. WireGuard user server (role: vpn_wireguard) -------
# A dedicated wg interface for end-user clients. RouterOS auto-generates
# the private key on `add` (we deliberately do NOT pass private-key= so
# the device mints its own); the panel reads the matching public key
# back via the existing heartbeat/identity channel and distributes it to
# customer client devices when their tunnel is provisioned.
#
# Peers are added per-customer by a later panel call, NOT here — this
# block only stands up the listener + gateway address. The firewall block
# below opens WG_USERS_PORT only when this role is enabled.
/interface wireguard peers
remove [find interface="wg-users"]
/ip address
remove [find interface="wg-users"]
/interface wireguard
remove [find name="wg-users"]
add name=wg-users listen-port=51822 comment="hobe-fleet-users"
/ip address
add interface=wg-users address=10.51.0.1/24 comment="hobe-fleet-users"
:log info ("hobe-fleet: wg-users public key (give to panel) = " . [/interface wireguard get [find name="wg-users"] public-key])


# ---- 8. NAT / masquerade to the internet ------------------
# Client (RADIUS-assigned or pool-assigned) range egresses via this CHR's
# public IP.
/ip firewall nat
remove [find comment="hobe-fleet-nat-egress"]
add chain=srcnat action=masquerade out-interface=ether1 \
    src-address=10.0.0.0/8 comment="hobe-fleet-nat-egress" ;# e.g. 10.0.0.0/8

# ============================================================
# 9. SURGICAL FIREWALL (input chain) — see header comment for full spec.
# ============================================================
# Strip every prior hobe-fleet-fw-* rule in one go, then re-add the
# current set. The regex remove catches stale rules even if role/cert
# flags flipped between renders.
/ip firewall filter
remove [find comment~"^hobe-fleet-fw-"]

# (a) Conntrack accept — first match for established/related/untracked.
#     The SSH session running this very import lives here; it MUST come
#     before any drop or we self-lockout the moment the next rule lands.
add chain=input action=accept connection-state=established,related,untracked \
    comment="hobe-fleet-fw-conntrack"

# (b) Hygiene: drop conntrack=invalid early.
add chain=input action=drop connection-state=invalid \
    comment="hobe-fleet-fw-invalid"

# (c) MANAGEMENT FIRST — wg-mgmt accepts panel-only, before any drop.
#     Scoped: in-interface=wg-mgmt AND src-address=PANEL_WG_ADDR/32.
#     This is what keeps the connected admin alive across re-imports.
add chain=input in-interface=wg-mgmt src-address=10.99.0.1/32 \
    action=accept comment="hobe-fleet-fw-mgmt"


# (d) RADIUS over wg-data — auth/acct + CoA, scoped to the proxy IP.
add chain=input in-interface=wg-data src-address=10.98.0.1/32 \
    protocol=udp dst-port=1812,1813 action=accept comment="hobe-fleet-fw-radius"
add chain=input in-interface=wg-data src-address=10.98.0.1/32 \
    protocol=udp dst-port=3799 action=accept comment="hobe-fleet-fw-coa"


# (e) WG handshake UDP on the WAN — required for either peer to come up.
add chain=input in-interface=ether1 protocol=udp dst-port=51820 \
    action=accept comment="hobe-fleet-fw-wg-mgmt-udp"

add chain=input in-interface=ether1 protocol=udp dst-port=51821 \
    action=accept comment="hobe-fleet-fw-wg-data-udp"


# (f) VPN service ports — role-gated, cert-gated where the server needs a cert.

add chain=input in-interface=ether1 protocol=tcp dst-port=443 \
    action=accept comment="hobe-fleet-fw-sstp"


add chain=input in-interface=ether1 protocol=tcp dst-port=1723 \
    action=accept comment="hobe-fleet-fw-pptp-ctrl"
add chain=input in-interface=ether1 protocol=gre \
    action=accept comment="hobe-fleet-fw-pptp-data"



add chain=input in-interface=ether1 protocol=udp dst-port=500,4500 \
    action=accept comment="hobe-fleet-fw-ike"

add chain=input in-interface=ether1 protocol=ipsec-esp \
    action=accept comment="hobe-fleet-fw-esp"
add chain=input in-interface=ether1 protocol=udp dst-port=1701 \
    action=accept comment="hobe-fleet-fw-l2tp"


add chain=input in-interface=ether1 protocol=udp dst-port=51822 \
    action=accept comment="hobe-fleet-fw-wg-users"


# (g) Sane ICMP — pings work but can't flood.
add chain=input protocol=icmp action=accept limit=50,5:packet \
    comment="hobe-fleet-fw-icmp"

# (h) Defence vs. an operator that forgot the role flag — RADIUS ports
#     must NEVER answer on the public iface. wg-data is whitelisted
#     above, so this drop applies to every OTHER iface.
add chain=input protocol=udp dst-port=1812,1813,3799 action=drop \
    comment="hobe-fleet-fw-no-public-radius"

# (i) FINAL drop — every accept must be ABOVE this rule. Comment-tagged
#     so the regex remove at top of §9 picks it up on re-import.
add chain=input action=drop comment="hobe-fleet-fw-drop-last"

# ---- 9b. HOIST critical accepts to absolute top of input chain ----
# Defence vs operator-set stale drops further up the chain (real
# incident: a pre-existing src-address=!<public-ip> drop landed above
# our wg-mgmt accept). RouterOS firewall is first-match; we explicitly
# hoist the critical accepts to position 0 in reverse-priority order
# so the final on-CHR order is: conntrack(0), radius(1), coa(2), mgmt(3),
# then everything else. The :do/on-error wraps the «cannot move rule
# before itself» error some builds raise when the rule is already at
# position 0 — desired order is in place, error is noise.
:do { /ip firewall filter move [find comment="hobe-fleet-fw-mgmt"] destination=0 } on-error={}

:do { /ip firewall filter move [find comment="hobe-fleet-fw-coa"] destination=0 } on-error={}
:do { /ip firewall filter move [find comment="hobe-fleet-fw-radius"] destination=0 } on-error={}

:do { /ip firewall filter move [find comment="hobe-fleet-fw-conntrack"] destination=0 } on-error={}

# ---- 10. control-plane is NOT a data route ----------------
# Ensure wg-mgmt carries no default route / no forwarding (invariant).
/ip route
# (no default via wg-mgmt — intentionally absent)

# ---- 11. Panel-side read-only API user (live-metrics poller) ----
# A dedicated RouterOS user the panel logs in as to read CPU, /ppp/active
# count and interface bytes — over the REST API on www-ssl ONLY, exposed
# on the wg-mgmt source (NEVER the WAN). The collector at
# app/services/routeros_client.py speaks HTTPS REST against
# https://<host>:<port>/rest/, so the matching service is `www-ssl`.
#
# Three live-incident fixes baked into this block (fix/fleet-metrics-wire-bugs):
#   1. PROTOCOL: www-ssl (REST), not api-ssl (binary).
#   2. CERTIFICATE: cert assigned so the TCP listener actually binds.
#   3. ACL DIRECTION: source-IP ACL points at the PANEL's wg-mgmt IP,
#      not the CHR's own — so the panel itself isn't blocked.

/user
remove [find name="panel-poller"]
add name="panel-poller" group=read password="metrics-password-from-vault" \
    comment="hobe-fleet-api-readonly"

# Self-signed PKI for www-ssl: a tiny local CA + a leaf signed by it.
/certificate
remove [find name="hobe-fleet-api-cert"]
remove [find name="hobe-fleet-ca"]
add name=hobe-fleet-ca common-name=hobe-fleet-ca \
    days-valid=3650 key-usage=key-cert-sign,crl-sign
sign hobe-fleet-ca
:delay 2s
/certificate
add name=hobe-fleet-api-cert common-name=hobe-fleet-api \
    days-valid=3650 key-usage=digital-signature,key-encipherment,tls-server
sign hobe-fleet-api-cert ca=hobe-fleet-ca
:delay 2s

# www-ssl = REST API over HTTPS. address= is the SOURCE-IP ACL —
# restrict to the PANEL's wg-mgmt IP (PANEL_WG_ADDR/32).
/ip service
set www-ssl disabled=no port=8443 \
    certificate=hobe-fleet-api-cert address=10.99.0.1/32
set api     disabled=yes  ;# binary API stays off (we use REST)
set api-ssl disabled=yes  ;# binary-over-TLS stays off (we use REST/www-ssl)
set www     disabled=yes  ;# plain HTTP stays off
# SSH + WinBox restricted to the panel source-IP over wg-mgmt — the only
# way an operator hand-touches a CHR is through the panel-controlled
# management plane. Defence-in-depth on top of the surgical firewall.
set ssh    address=10.99.0.1/32 disabled=no
set winbox address=10.99.0.1/32 disabled=no
set telnet disabled=yes
set ftp    disabled=yes

/ip firewall filter
remove [find comment="hobe-fleet-fw-api-ssl"]
# Place the API accept just BEFORE the drop-last rule so a re-import
# always lands it above the deny — and the regex remove at §9 already
# swept the prior copy.
add chain=input in-interface=wg-mgmt src-address=10.99.0.1/32 \
    protocol=tcp dst-port=8443 \
    place-before=[find comment="hobe-fleet-fw-drop-last"] \
    action=accept comment="hobe-fleet-fw-api-ssl"


# CHR_PUBLIC_IP for this node (egress identity, documented for ops): 178.105.244.112

# ============================================================
# 12. SELF-LOCKOUT GUARD — CANCEL (we made it through cleanly)
# ============================================================
# Last block of the script. If we get here, every section above ran
# without halting, so the apply is good. Cancel the rollback scheduler
# armed in §0a; without this line the CHR would auto-revert at T+3m.
:do { /system scheduler remove [find name="hobe-fleet-rollback"] } on-error={}
:do { /file remove [find name="hobe-fleet-pre-apply.backup"] } on-error={}
:log info "hobe-fleet: rollback guard CANCELLED — apply complete"

# ============================================================
# END unified script.
# Re-importable: every resource clears its prior copy first.
# Role-gated: services + firewall accepts emitted only for enabled roles.
# Self-lockout proof: §0a arms, §12 cancels.
# ============================================================
