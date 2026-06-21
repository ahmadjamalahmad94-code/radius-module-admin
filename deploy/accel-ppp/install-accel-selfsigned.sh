#!/usr/bin/env bash
# ============================================================================
# install-accel-selfsigned.sh — ONE-SHOT accel-ppp installer (NO Cloudflare/DNS)
# HobeRadius — branch feat/accel-selfsigned-installer
#
# WHAT IT DOES (production RADIUS VPS):
#   * installs accel-ppp (distro-aware: apt) — FAILS LOUD if unavailable;
#   * serves SSTP (TCP 443) + PPTP, authenticating against the LOCAL FreeRADIUS
#     (use-radius, no local users) with your RADIUS secret;
#   * generates a SELF-SIGNED cert/key for SSTP (MikroTik connects with
#     verify-server-certificate=no) — bypasses Let's Encrypt/DNS entirely;
#   * NAT MASQUERADE for the PPP pool + a SURGICAL add-only firewall
#     (opens 443/tcp, 1723/tcp + GRE; KEEPS SSH/22 — never locks you out);
#   * idempotent: safe to re-run; does NOT touch port 80 / the panel / FreeRADIUS.
#
# Baked defaults (override via env): VPS_IP, RADIUS_SECRET, ENABLE_PPTP, pool.
# ============================================================================
set -euo pipefail

# ── values (override via env; sane defaults baked) ──────────────────────────
VPS_IP="${VPS_IP:-187.77.70.18}"
RADIUS_SECRET="${RADIUS_SECRET:-4e72d766dd3ae535c3af90f7e5a5e1ed6e0d4def94a0db9c}"
ENABLE_PPTP="${ENABLE_PPTP:-1}"
RADIUS_AUTH_PORT="${RADIUS_AUTH_PORT:-1812}"
RADIUS_ACCT_PORT="${RADIUS_ACCT_PORT:-1813}"
COA_PORT="${COA_PORT:-3799}"
POOL_GATEWAY="${POOL_GATEWAY:-10.20.0.1}"
POOL_RANGE="${POOL_RANGE:-10.20.0.2-10.20.255.254}"
POOL_CIDR="${POOL_CIDR:-10.20.0.0/16}"
DNS1="${DNS1:-1.1.1.1}"
DNS2="${DNS2:-1.0.0.1}"
WAN_IFACE="${WAN_IFACE:-$(ip -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')}"

ACCEL_CONF="/etc/accel-ppp.conf"
CERT_DIR="/etc/accel-ppp/ssl"
CERT_PEM="${CERT_DIR}/sstp-cert.pem"
CERT_KEY="${CERT_DIR}/sstp-key.pem"
NET_SCRIPT="/usr/local/sbin/hoberadius-accel-net.sh"
NET_UNIT="/etc/systemd/system/hoberadius-accel-net.service"

log()  { printf '\033[1;36m[install]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[FAIL]\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run as root (sudo bash $0)."
[[ -n "$VPS_IP" ]] || die "VPS_IP is empty."
[[ -n "$RADIUS_SECRET" ]] || die "RADIUS_SECRET is empty."
[[ -n "$WAN_IFACE" ]] || warn "could not detect WAN interface — set WAN_IFACE=<iface> and re-run if NAT is missing."

log "accel-ppp self-signed install on ${VPS_IP} (WAN=${WAN_IFACE:-?}, pool=${POOL_CIDR})"

# ── 1. packages (distro-aware) ──────────────────────────────────────────────
. /etc/os-release 2>/dev/null || true
log "Distro: ${PRETTY_NAME:-unknown} (${ID:-?} ${VERSION_ID:-?})"
case "${ID:-}" in
  ubuntu|debian) : ;;
  *) warn "untested distro '${ID:-unknown}' — proceeding with apt; verify accel-ppp installs." ;;
esac
command -v apt-get >/dev/null 2>&1 || die "apt-get not found — this installer supports Debian/Ubuntu only."
export DEBIAN_FRONTEND=noninteractive
log "Installing accel-ppp + openssl + iproute2 (idempotent)…"
apt-get update -qq || die "apt-get update failed (check network/sources)."
if ! apt-get install -y --no-install-recommends accel-ppp openssl iproute2 >/dev/null 2>&1; then
  warn "accel-ppp not in the default repos for this release — enabling 'universe' and retrying…"
  apt-get install -y --no-install-recommends software-properties-common >/dev/null 2>&1 || true
  add-apt-repository -y universe >/dev/null 2>&1 || true
  apt-get update -qq || true
  apt-get install -y --no-install-recommends accel-ppp openssl iproute2 >/dev/null 2>&1 \
    || die "accel-ppp is unavailable via apt on ${PRETTY_NAME:-this distro}. Install it manually (build from https://accel-ppp.org or your distro's package) then re-run this script."
fi
command -v accel-pppd >/dev/null 2>&1 || command -v accel-cmd >/dev/null 2>&1 \
  || die "accel-ppp installed but its binaries are missing — aborting."
log "  accel-ppp present."

# ── 2. self-signed cert for SSTP ─────────────────────────────────────────────
install -d -m 0755 "$CERT_DIR"
if [[ -f "$CERT_PEM" && -f "$CERT_KEY" ]]; then
  log "Self-signed cert already present — keeping it."
else
  log "Generating self-signed SSTP cert (CN=${VPS_IP}, 10y)…"
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout "$CERT_KEY" -out "$CERT_PEM" \
    -subj "/CN=${VPS_IP}" -addext "subjectAltName=IP:${VPS_IP}" >/dev/null 2>&1 \
    || openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
         -keyout "$CERT_KEY" -out "$CERT_PEM" -subj "/CN=${VPS_IP}" >/dev/null 2>&1 \
    || die "openssl failed to generate the self-signed cert."
  chmod 0600 "$CERT_KEY"; chmod 0644 "$CERT_PEM"
fi

# ── 3. render /etc/accel-ppp.conf ────────────────────────────────────────────
log "Writing ${ACCEL_CONF}…"
install -d -m 0755 /var/log/accel-ppp
_pptp_mod=""; [[ "$ENABLE_PPTP" == "1" ]] && _pptp_mod="pptp"
cat > "$ACCEL_CONF" <<CONF
[modules]
sstp
${_pptp_mod}
radius
shaper
ippool
log_file

[core]
log-error=/var/log/accel-ppp/core.log
thread-count=2

[log]
log-file=/var/log/accel-ppp/accel-ppp.log
copy=1
level=3

[ppp]
verbose=1
min-mtu=1280
mtu=1400
mru=1400
single-session=replace
lcp-echo-interval=30
lcp-echo-failure=3
ipv4=require
ipv6=deny

[auth]
# RADIUS-backed MSCHAP-v2 (SSTP/PPTP default); PAP allowed for older clients.
methods=MSCHAP-v2,MSCHAP-v1,PAP

[radius]
# AAA against the LOCAL FreeRADIUS — no local users (use-radius).
nas-identifier=hoberadius-${VPS_IP}
nas-ip-address=127.0.0.1
server=127.0.0.1,${RADIUS_SECRET},auth-port=${RADIUS_AUTH_PORT},acct-port=${RADIUS_ACCT_PORT},req-limit=0,fail-time=0
dae-server=127.0.0.1:${COA_PORT},${RADIUS_SECRET}
acct-interim-interval=60
timeout=5
max-try=3

[shaper]
attr=Filter-Id
verbose=1

[ip-pool]
gw-ip-address=${POOL_GATEWAY}
${POOL_RANGE}

[dns]
dns1=${DNS1}
dns2=${DNS2}

[sstp]
verbose=1
accept=ssl
ssl-pemfile=${CERT_PEM}
ssl-keyfile=${CERT_KEY}
ssl-protocol=tlsv1.2,tlsv1.3
port=443
CONF
if [[ "$ENABLE_PPTP" == "1" ]]; then
cat >> "$ACCEL_CONF" <<'CONF'

[pptp]
verbose=1
echo-interval=30
echo-failure=3
CONF
fi
cat >> "$ACCEL_CONF" <<'CONF'

[cli]
telnet=127.0.0.1:2000
tcp=127.0.0.1:2001
CONF

# ── 4. networking: forwarding + NAT + SURGICAL add-only firewall ─────────────
# Add-only: enables forwarding, adds a MASQUERADE for the pool, adds inbound
# ACCEPTs for the VPN ports. NEVER flushes, NEVER sets a default-DROP, NEVER
# touches SSH/22 → no self-lockout. Reboot-safe via a oneshot unit.
log "Configuring forwarding + NAT + firewall (add-only, SSH preserved)…"
cat > /etc/sysctl.d/99-hoberadius-accel.conf <<SYSCTL
net.ipv4.ip_forward=1
SYSCTL
sysctl -q --system 2>/dev/null || sysctl -q -w net.ipv4.ip_forward=1 || true

cat > "$NET_SCRIPT" <<NET
#!/usr/bin/env bash
set -e
WAN_IFACE="${WAN_IFACE}"
POOL_CIDR="${POOL_CIDR}"
sysctl -q -w net.ipv4.ip_forward=1 || true
if [ -n "\$WAN_IFACE" ]; then
  iptables -t nat -C POSTROUTING -s "\$POOL_CIDR" -o "\$WAN_IFACE" -j MASQUERADE 2>/dev/null \\
    || iptables -t nat -A POSTROUTING -s "\$POOL_CIDR" -o "\$WAN_IFACE" -j MASQUERADE
fi
iptables -C FORWARD -s "\$POOL_CIDR" -j ACCEPT 2>/dev/null || iptables -A FORWARD -s "\$POOL_CIDR" -j ACCEPT
iptables -C FORWARD -d "\$POOL_CIDR" -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null \\
  || iptables -A FORWARD -d "\$POOL_CIDR" -m state --state ESTABLISHED,RELATED -j ACCEPT
open_tcp(){ iptables -C INPUT -p tcp --dport "\$1" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p tcp --dport "\$1" -j ACCEPT; }
open_tcp 443   # SSTP
NET
if [[ "$ENABLE_PPTP" == "1" ]]; then
cat >> "$NET_SCRIPT" <<'NET'
open_tcp 1723  # PPTP control
modprobe nf_conntrack_pptp 2>/dev/null || true
iptables -C INPUT -p gre -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p gre -j ACCEPT
NET
fi
chmod 0755 "$NET_SCRIPT"
cat > "$NET_UNIT" <<UNIT
[Unit]
Description=HobeRadius accel-ppp networking (forwarding + NAT + surgical port opens)
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=${NET_SCRIPT}
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now hoberadius-accel-net.service >/dev/null 2>&1 \
  || { warn "applying net rules directly…"; bash "$NET_SCRIPT" || warn "net rules NOT applied — check ${NET_SCRIPT}."; }

# ── 5. start accel-ppp ───────────────────────────────────────────────────────
log "Enabling accel-ppp…"
systemctl enable accel-ppp >/dev/null 2>&1 || true
systemctl restart accel-ppp || systemctl start accel-ppp \
  || die "accel-ppp failed to start — check: journalctl -u accel-ppp -n 50"
sleep 1

# ── 6. summary ───────────────────────────────────────────────────────────────
echo
log "DONE. accel-ppp is serving (self-signed SSTP + PPTP, RADIUS-backed)."
echo "  -------------------------------------------------------------------"
echo "  Listening:"
ss -ltnp 2>/dev/null | grep -E ':(443|1723)\b' || echo "    (run: ss -ltnp | grep -E ':(443|1723)')"
echo "  accel-ppp status:  systemctl status accel-ppp --no-pager"
echo "  sessions:          accel-cmd show sessions"
echo
echo "  MikroTik — SSTP (recommended, v6 & v7):"
echo "    /interface sstp-client add name=hobe connect-to=${VPS_IP} port=443 \\"
echo "      user=<radius-user> password=<radius-pass> \\"
echo "      profile=default-encryption verify-server-certificate=no \\"
echo "      add-default-route=no disabled=no"
if [[ "$ENABLE_PPTP" == "1" ]]; then
echo
echo "  MikroTik — PPTP (legacy):"
echo "    /interface pptp-client add name=hobe-pptp connect-to=${VPS_IP} \\"
echo "      user=<radius-user> password=<radius-pass> profile=default-encryption disabled=no"
fi
echo
echo "  NOTE: the RADIUS user/pass come from your LOCAL FreeRADIUS (secret baked,"
echo "        client 127.0.0.1). Self-signed cert ⇒ verify-server-certificate=no."
echo "  -------------------------------------------------------------------"
