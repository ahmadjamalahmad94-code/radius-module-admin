
# ============================================================
# HobeRadius unified CHR provisioning script  (v2, idempotent)
# Safe to re-import: every resource removes prior copies first.
# ============================================================

/system identity set name="chr-vpn-1"

# ---- 0. DNS bootstrap (so :resolve works in section 2b) ----
# If the CHR has no DNS servers configured yet (fresh install / cloud image
# without DHCP-pushed DNS), set a public fallback so :resolve below can run.
# We DO NOT overwrite operator-set DNS — checked via :len of current list.
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
add name=wg-mgmt listen-port=51820 private-key="<vault>"
/interface wireguard peers

add interface=wg-mgmt public-key="PANELpubkey...=" \
    endpoint-address=panel.hoberadius.com endpoint-port=51820 \
    allowed-address=10.99.0.1/32 persistent-keepalive=25s \
    comment="hobe-fleet-mgmt"
/ip address
add interface=wg-mgmt address=10.99.0.11/24     ;# e.g. 10.99.0.11/24 (shared mgmt net; /32 broke the return route)

# ---- 2. WireGuard DATA path to RADIUS proxy (wg-data) ------
# Carries ONLY RADIUS 1812/1813 + CoA 3799 to the proxy.
/interface wireguard peers
remove [find interface="wg-data"]
/ip address
remove [find interface="wg-data"]
/interface wireguard
remove [find name="wg-data"]
add name=wg-data listen-port=51821 private-key="<vault>"
/interface wireguard peers

add interface=wg-data public-key="PROXYpubkey...=" \
    endpoint-address=proxy.hoberadius.com endpoint-port=51821 \
    allowed-address=10.98.0.1/32 persistent-keepalive=25s \
    comment="hobe-fleet-data"
/ip address
add interface=wg-data address=10.98.0.11/24     ;# e.g. 10.98.0.11/24 (shared data net; /32 broke the RADIUS return path)

# ---- 2b. Resolve peer hostnames → set IP literal on each peer ----
# Field finding (fix/fleet-endpoint-resolve): even with host-only
# endpoint-address=proxy.hoberadius.com on the wg-data peer, RouterOS left
# current-endpoint-address="" and never handshaked. Replacing with the
# resolved IP literal (178.105.251.67) made the handshake fire instantly.
# So we explicitly resolve at import time and overwrite endpoint-address.
# Retries 5x with 2s back-off (handles a cold WAN that's not up at import).
# If :resolve never succeeds we leave the hostname in place + :log error;
# that is no worse than the prior behaviour and the operator sees why.
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

:local panelIP [$hobeResolve "panel.hoberadius.com"]
:local proxyIP [$hobeResolve "proxy.hoberadius.com"]

/interface wireguard peers
set [find comment="hobe-fleet-mgmt"] endpoint-address=$panelIP endpoint-port=51820
set [find comment="hobe-fleet-data"] endpoint-address=$proxyIP endpoint-port=51821

# ---- 2c. Key-identity audit trail ----
# Field incident: a wrong panel public key on the wg-mgmt peer produced a
# silent dead tunnel (stale handshake, no ping) that took hours to spot.
# These log lines print the EXPECTED identities into /log so the operator
# can compare against «إعدادات بنية الأسطول» on the panel with one glance:
#   - expected PANEL pubkey (what the wg-mgmt peer must trust)
#   - expected PROXY pubkey (what the wg-data peer must trust)
#   - this CHR's OWN wg-mgmt pubkey (what the panel's peer must trust)
:log info ("hobe-fleet: wg-mgmt peer expects PANEL pubkey = PANELpubkey...=")
:log info ("hobe-fleet: wg-data peer expects PROXY pubkey = PROXYpubkey...=")
:log info ("hobe-fleet: this CHR wg-mgmt pubkey (give to panel) = " . [/interface wireguard get [find name="wg-mgmt"] public-key])

# ---- 3. RADIUS client → the central proxy (FLEET-CONSTANT) -
/radius
remove [find comment="hobe-fleet-radius"]
add service=ppp,login address=10.98.0.1 secret="<secret>" \
    authentication-port=1812 accounting-port=1813 \
    src-address=10.98.0.11 timeout=3s \
    comment="hobe-fleet-radius"
# Guarantee the entry is ENABLED. The first live install hit this: PPP AAA
# was using RADIUS and the entry existed, but `/radius print detail` showed
# Flags: X - DISABLED, so no packets ever reached the proxy. Belt-and-braces
# `enable` against the comment tag forces disabled=no on every (re-)import,
# regardless of what state a prior run or operator edit left it in.
/radius enable [find comment="hobe-fleet-radius"]
/radius incoming
# Enable CoA / Disconnect listener so panel can kill/move sessions (RFC 5176)
set accept=yes port=3799

# Make PPP + login use RADIUS:
/ppp aaa
set use-radius=yes accounting=yes interim-update=5m

# ---- 4. IP-FROM-RADIUS ONLY (no local pool!) --------------
# default-profile must NOT reference any local-address pool for clients.
#
# Defensive idempotency: drop any prior hobe-tagged ppp profile / ip pool
# from earlier re-imports before re-`set`ting the built-in default-encryption
# profile. The current template does NOT `add` either (we only `set` the
# built-in profile, and we deliberately use NO local pool — clients get IPs
# from RADIUS Framed-IP). These two cleanups exist to (a) sweep stale
# hobe-tagged rows left by older script revisions the owner may have applied,
# and (b) be the anchor any future custom profile/pool `add` will sit under.
/ppp profile
remove [find comment="hobe-fleet-ppp"]
/ip pool
remove [find name~"^hobe-fleet-pool"]
/ppp profile
set default-encryption local-address=10.255.255.1 \
    use-encryption=required dns-server=1.1.1.1 \
    only-one=yes        ;# remote-address from RADIUS Framed-IP; refuse 2nd local session

# ---- 5. PPTP server ---------------------------------------
/interface pptp-server server
set enabled=yes authentication=mschap2 default-profile=default-encryption \
    keepalive-timeout=30

# ---- 6. SSTP server (TLS 443) -----------------------------


# SSTP skipped: no TLS certificate configured on the panel yet.
# Set SSTP_CERT_NAME in /admin/fleet config (and pre-install the matching
# /certificate row on each CHR) to enable the SSTP server block here.


# ---- 7. IPsec / IKEv2 server ------------------------------
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

# IPsec identity + peer skipped: no IKEv2 certificate configured on the
# panel yet. Set IKE_CERT_NAME in /admin/fleet config (and pre-install the
# matching /certificate row on each CHR) to enable IKEv2.


# ---- 8. NAT / masquerade to the internet ------------------
# Client (RADIUS-assigned) range egresses via this CHR's public IP.
/ip firewall nat
remove [find comment="hobe-fleet-nat-egress"]
add chain=srcnat action=masquerade out-interface=ether1 \
    src-address=10.0.0.0/8 comment="hobe-fleet-nat-egress" ;# e.g. 10.0.0.0/8

# ---- 9. Firewall: RADIUS/CoA only over wg, never public ---
# Strip every prior hobe-fleet-fw-* rule in one go, then re-add the current
# set. The regex remove catches stale rules even if cert config flipped
# between renders (SSTP/IKE openings come and go).
/ip firewall filter
remove [find comment~"^hobe-fleet-fw-"]
add chain=input in-interface=wg-data protocol=udp dst-port=1812,1813 action=accept comment="hobe-fleet-fw-radius"
add chain=input in-interface=wg-data protocol=udp dst-port=3799 action=accept           comment="hobe-fleet-fw-coa"
add chain=input in-interface=wg-mgmt action=accept                                       comment="hobe-fleet-fw-mgmt"
add chain=input protocol=udp dst-port=1812,1813,3799 action=drop                         comment="hobe-fleet-fw-no-public-radius"
# Allow VPN protocols inbound on WAN — each gate matches the corresponding
# server block above (skip the SSTP/IKE openings when their certs aren't
# configured so we don't expose a dangling port to the internet).

add chain=input in-interface=ether1 protocol=tcp dst-port=1723 action=accept    comment="hobe-fleet-fw-pptp-ctrl"
add chain=input in-interface=ether1 protocol=gre action=accept                  comment="hobe-fleet-fw-pptp-data"


# ---- 9b. RULE ORDER: hoist wg allow rules above any stale drops ----
# Field incident: a pre-existing operator rule
#   chain=input action=drop protocol=tcp src-address=!<public-ip> dst-port=8443
# sat ABOVE our wg-mgmt accept and silently killed REST from the panel —
# RouterOS firewall is first-match, so add-order isn't enough on a CHR
# that carries older hand-written rules. We explicitly MOVE the critical
# wg-plane accepts to the very top of the input chain after (re-)adding
# them. `move destination=0` works on RouterOS v7 with find-by-comment;
# moving the radius rule last leaves the final order:
#   [0] hobe-fleet-fw-radius  (wg-data 1812,1813)
#   [1] hobe-fleet-fw-coa     (wg-data 3799)
#   [2] hobe-fleet-fw-mgmt    (wg-mgmt — carries REST 8443 too)
# i.e. every hobe allow precedes every drop (ours or stale).
/ip firewall filter
move [find comment="hobe-fleet-fw-mgmt"] destination=0
move [find comment="hobe-fleet-fw-coa"] destination=0
move [find comment="hobe-fleet-fw-radius"] destination=0

# ---- 10. control-plane is NOT a data route ----------------
# Ensure wg-mgmt carries no default route / no forwarding (invariant).
/ip route
# (no default via wg-mgmt — intentionally absent)

# ---- 11. Panel-side read-only API user (live-metrics poller) ----
# A dedicated RouterOS user the panel logs in as to read CPU, /ppp/active
# count and interface bytes — over the REST API on www-ssl ONLY, exposed
# on the wg-mgmt source (NEVER the WAN). The collector at
# app/services/routeros_client.py speaks HTTPS REST against
# https://<host>:<port>/rest/... (see _base_url at line 83-85), so the
# matching RouterOS service is `www-ssl`, NOT the binary `api-ssl`.
#
# Three live-incident fixes are baked into this block (live-down on
# the first prod CHR, fix/fleet-metrics-wire-bugs):
#
#   1. PROTOCOL: previously `set api-ssl disabled=no`. That's the binary
#      api protocol — the panel's HTTPS REST client gets a connection
#      reset because /rest/ has no handler on api-ssl. We now enable
#      `www-ssl` (REST over HTTPS) on 8443.
#
#   2. CERTIFICATE: RouterOS refuses to bind a TCP listener on www-ssl
#      (or api-ssl) without a `certificate=` argument. The previous
#      script left this empty, so the socket never opened → panel TCP
#      SYN got nothing back → `connect_failed`. We now provision a
#      self-signed cert `hobe-fleet-api-cert` and assign it.
#
#   3. ACL DIRECTION: `/ip service ... address=` is a SOURCE-IP filter,
#      not a bind address. Previously we set address=WG_MGMT_ADDR (the
#      CHR's own 10.99.0.11/32) which filters every connection that
#      DIDN'T come from 10.99.0.11 — i.e. the panel at 10.99.0.1 was
#      itself blocked at the service layer. Correct value is the PANEL's
#      wg-mgmt IP (PANEL_WG_ADDR, 10.99.0.1) so only the panel can hit
#      the REST endpoint.
#
# Idempotent: cert + user + service are all remove-before-add or set-
# based. The block is skipped entirely when the panel hasn't set both
# API_USER and API_PASSWORD — keeps the script installable on a virgin
# node before the operator has configured the credentials in
# «إعدادات بنية الأسطول».

/user
remove [find name="hobe-panel"]
add name="hobe-panel" group=read password="pw" \
    comment="hobe-fleet-api-readonly"

# Self-signed cert for www-ssl. Re-imports replace the cert so the
# script stays idempotent. The cert's only consumer is www-ssl on this
# CHR — the panel collector uses `verify_tls=False` (CERT_NONE) at
# routeros_client.py:99 because every CHR carries its own self-signed
# leaf; centralising a CA is a later phase. days-valid=3650 keeps
# silent rotation off the critical path.
/certificate
remove [find name="hobe-fleet-api-cert"]
add name=hobe-fleet-api-cert common-name=hobe-fleet-api \
    days-valid=3650 key-usage=tls-server
sign hobe-fleet-api-cert

# www-ssl = REST API over HTTPS (matches app/services/routeros_client.py).
# address= is the SOURCE-IP ACL — restrict to the PANEL's wg-mgmt IP, NOT
# the CHR's own. PANEL_WG_ADDR is a fleet-constant binding (10.99.0.1 in
# the standard pool) coming from infra_settings via _build_bindings.
/ip service
set www-ssl disabled=no port=8443 \
    certificate=hobe-fleet-api-cert address=10.99.0.1/32
set api     disabled=yes  ;# binary API stays off (we use REST)
set api-ssl disabled=yes  ;# binary-over-TLS stays off (we use REST/www-ssl)
set www     disabled=yes  ;# plain HTTP stays off

/ip firewall filter
remove [find comment="hobe-fleet-fw-api-ssl"]
add chain=input in-interface=wg-mgmt protocol=tcp dst-port=8443 \
    action=accept comment="hobe-fleet-fw-api-ssl"


# CHR_PUBLIC_IP for this node (egress identity, documented for ops): 178.105.244.112
# ============================================================
# END unified script — bindings above are the ONLY per-CHR delta.
# Re-importable: every resource above clears its prior copy first.
# ============================================================
