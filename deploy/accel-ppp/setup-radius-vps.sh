#!/usr/bin/env bash
# ============================================================================
# setup-radius-vps.sh — ONE-TIME accel-ppp DATA-connection activation
# HobeRadius — branch feat/data-conn-2c-panel-vps-activation
#
# WHAT THIS IS
#   The operator runs this ONCE on a freshly-provisioned customer RADIUS VPS to
#   turn it into a DATA-connection BRAS (SSTP / PPTP / L2TP served directly by
#   accel-ppp — no proxy, no CHR). See docs/design/ACCEL_PPP_DATA_CONNECTIONS.md.
#
#   The licensing panel CANNOT install software on the customer's box, so this
#   step is manual + one-time. After it runs, the panel's only ongoing job is
#   to keep clientN.<zone> pointing at this VPS (Cloudflare DNS), which lets the
#   certbot step below succeed and renew unattended.
#
# IDEMPOTENT
#   Safe to re-run. Every step checks-before-acting (apt install is a no-op when
#   present; the conf is only rewritten when it changed; certbot won't
#   re-issue a live cert; systemd units are 'enable --now' which is idempotent).
#
# USAGE
#   1. Edit the VARIABLES block below (or export them in the environment).
#   2. sudo bash setup-radius-vps.sh
#
#   Every value you MUST set is marked  # >>> SET ME.
#   Every item still pending lab validation is marked  # !!! LAB-PENDING.
# ============================================================================
set -euo pipefail

# ── VARIABLES ───────────────────────────────────────────────────────────────
# These are the only things that change per-VPS. Override via env or edit here.

# Public IP of THIS VPS (the value the panel stores as customer.vps_ip and the
# value clientN.<zone> resolves to). Used for sanity-checking DNS before certbot.
VPS_IP="${VPS_IP:-}"                              # >>> SET ME  e.g. 203.0.113.10

# The customer's subdomain FQDN — must already resolve to VPS_IP (the panel
# creates this A record via Cloudflare). certbot HTTP-01 validates against it.
SUBDOMAIN="${SUBDOMAIN:-}"                         # >>> SET ME  e.g. client5.hoberadius.com

# Shared secret between accel-ppp and the LOCAL radius-module (loopback only).
RADIUS_SECRET="${RADIUS_SECRET:-}"                 # >>> SET ME  (>= 32 random chars)

# Email certbot registers for expiry notices.
CERTBOT_EMAIL="${CERTBOT_EMAIL:-admin@hoberadius.com}"   # >>> SET ME

# End-user IP pool handed out to DATA subscribers (keep clear of fleet reserves
# 10.51/10.98/10.99 and the VPS's own subnets — see template comments).
POOL_GATEWAY="${POOL_GATEWAY:-10.20.0.1}"
POOL_RANGE="${POOL_RANGE:-10.20.0.2-10.20.255.254}"

# WireGuard DATA listener (RouterOS v7 path). The per-peer 5 Mbit shaper is
# applied by the vps-agent via tc; see deploy/accel-ppp/agent/.
WG_DATA_PORT="${WG_DATA_PORT:-51830}"              # !!! LAB-PENDING confirm no clash with mgmt/data WG
WG_DATA_IFACE="${WG_DATA_IFACE:-wg-data}"

# Local RADIUS + DM/CoA ports (defaults match the template).
RADIUS_AUTH_PORT="${RADIUS_AUTH_PORT:-1812}"
RADIUS_ACCT_PORT="${RADIUS_ACCT_PORT:-1813}"
COA_PORT="${COA_PORT:-3799}"
DNS1="${DNS1:-1.1.1.1}"
DNS2="${DNS2:-1.0.0.1}"

# Derived — NAS identity = the subdomain label (clientN).
NAS_IDENTIFIER="${NAS_IDENTIFIER:-${SUBDOMAIN%%.*}}"

# Paths.
ACCEL_CONF="/etc/accel-ppp.conf"
TEMPLATE="$(dirname "$0")/accel-ppp.conf.tmpl"
LE_LIVE="/etc/letsencrypt/live/${SUBDOMAIN}"
SSTP_CERT_FULLCHAIN="${LE_LIVE}/fullchain.pem"
SSTP_CERT_KEY="${LE_LIVE}/privkey.pem"
RELOAD_HOOK="/etc/letsencrypt/renewal-hooks/deploy/10-reload-accel-ppp.sh"
AGENT_SRC="$(dirname "$0")/agent"
AGENT_DST="/opt/radius-vps-agent"

log()  { printf '\033[1;36m[setup]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[fail]\033[0m %s\n' "$*" >&2; exit 1; }

# ── 0. preflight ─────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "run as root (sudo)."
[[ -n "$VPS_IP"        ]] || die "VPS_IP is required (# >>> SET ME)."
[[ -n "$SUBDOMAIN"     ]] || die "SUBDOMAIN is required (# >>> SET ME)."
[[ -n "$RADIUS_SECRET" ]] || die "RADIUS_SECRET is required (# >>> SET ME)."
[[ -f "$TEMPLATE"      ]] || die "template not found at $TEMPLATE"
[[ ${#RADIUS_SECRET} -ge 32 ]] || warn "RADIUS_SECRET is shorter than 32 chars — strongly discouraged."

log "Activating DATA BRAS on ${SUBDOMAIN} (${VPS_IP})"

# ── 1. packages: accel-ppp + certbot ─────────────────────────────────────────
# accel-ppp ships in Debian/Ubuntu repos as 'accel-ppp'. certbot via apt keeps
# auto-renew wired through systemd's certbot.timer out of the box.
log "Installing packages (idempotent)…"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends \
    accel-ppp certbot wireguard-tools iproute2 python3 >/dev/null
# NOTE: this VPS issues its OWN cert via certbot HTTP-01 (port 80 must reach
# this box — that's exactly what the panel's Cloudflare A record guarantees).
# We do NOT need the Cloudflare DNS plugin here: DNS-01 would only be required
# for a wildcard, which is out of scope for per-client certs.   # !!! LAB-PENDING
# If port 80 is firewalled, switch the certbot call in step 4 to --standalone
# with a brief open, or to the DNS-01/cloudflare plugin.

# ── 2. render accel-ppp.conf from the template ───────────────────────────────
# Substitute every {{ VAR }} the template declares. Render to a temp file and
# only swap it in when it differs (keeps the step idempotent + reload-light).
log "Rendering ${ACCEL_CONF} from template…"
TMP_CONF="$(mktemp)"
sed \
  -e "s|{{ POOL_RANGE }}|${POOL_RANGE}|g" \
  -e "s|{{ POOL_GATEWAY }}|${POOL_GATEWAY}|g" \
  -e "s|{{ DNS1 }}|${DNS1}|g" \
  -e "s|{{ DNS2 }}|${DNS2}|g" \
  -e "s|{{ RADIUS_SECRET }}|${RADIUS_SECRET}|g" \
  -e "s|{{ RADIUS_AUTH_PORT }}|${RADIUS_AUTH_PORT}|g" \
  -e "s|{{ RADIUS_ACCT_PORT }}|${RADIUS_ACCT_PORT}|g" \
  -e "s|{{ NAS_IDENTIFIER }}|${NAS_IDENTIFIER}|g" \
  -e "s|{{ COA_PORT }}|${COA_PORT}|g" \
  -e "s|{{ SSTP_CERT_FULLCHAIN }}|${SSTP_CERT_FULLCHAIN}|g" \
  -e "s|{{ SSTP_CERT_KEY }}|${SSTP_CERT_KEY}|g" \
  -e "s|{{ SUBDOMAIN }}|${SUBDOMAIN}|g" \
  "$TEMPLATE" > "$TMP_CONF"

if grep -q '{{' "$TMP_CONF"; then
    warn "template still has unrendered {{ vars }}:"
    grep -n '{{' "$TMP_CONF" >&2 || true
    die "refusing to install a partially-rendered config."
fi

if [[ -f "$ACCEL_CONF" ]] && cmp -s "$TMP_CONF" "$ACCEL_CONF"; then
    log "  accel-ppp.conf unchanged."
    rm -f "$TMP_CONF"
else
    install -m 0640 "$TMP_CONF" "$ACCEL_CONF"
    rm -f "$TMP_CONF"
    log "  accel-ppp.conf updated."
fi
install -d -m 0755 /var/log/accel-ppp

# ── 3. cert: certbot HTTP-01 against the subdomain ───────────────────────────
# The panel already created the A record (clientN.<zone> -> VPS_IP). HTTP-01
# proves control by serving a token over port 80 on this box.
log "Ensuring certificate for ${SUBDOMAIN}…"
if [[ -f "$SSTP_CERT_FULLCHAIN" ]]; then
    log "  cert already present — certbot.timer handles renewal."
else
    # --webroot needs a running webserver; --standalone binds :80 itself for
    # the brief challenge. We use --standalone for a box that isn't serving HTTP
    # yet (accel-ppp owns 443, not 80). Re-runs are safe (certbot is idempotent).
    certbot certonly --standalone --non-interactive --agree-tos \
        --email "$CERTBOT_EMAIL" -d "$SUBDOMAIN" \
        || die "certbot failed — confirm ${SUBDOMAIN} resolves to ${VPS_IP} and :80 is reachable."
fi

# ── 4. auto-renew → reload accel-ppp ─────────────────────────────────────────
# certbot.timer (installed by the apt package) renews silently; this deploy
# hook makes accel-ppp pick up the fresh cert without a full restart.
log "Installing certbot deploy hook → accel-ppp reload…"
install -d -m 0755 "$(dirname "$RELOAD_HOOK")"
cat > "$RELOAD_HOOK" <<'HOOK'
#!/usr/bin/env bash
# Reload accel-ppp after a successful cert renewal so SSTP serves the new chain.
set -e
if command -v accel-cmd >/dev/null 2>&1; then
    accel-cmd reload || systemctl reload accel-ppp || systemctl restart accel-ppp
else
    systemctl reload accel-ppp || systemctl restart accel-ppp
fi
HOOK
chmod 0755 "$RELOAD_HOOK"

# ── 5. install + enable the vps-agent ────────────────────────────────────────
# The agent applies WireGuard peers + per-peer 5 Mbit tc queues, reads live
# sessions, and triggers cert renew on demand. It's a SKELETON (see its README);
# the real OS calls are stubbed behind an executor interface.
log "Installing vps-agent → ${AGENT_DST}…"
install -d -m 0755 "$AGENT_DST"
cp -r "$AGENT_SRC/." "$AGENT_DST/"
cat > /etc/systemd/system/radius-vps-agent.service <<UNIT
[Unit]
Description=HobeRadius VPS agent (accel-ppp DATA connections)
After=network-online.target accel-ppp.service
Wants=network-online.target

[Service]
Type=simple
# !!! LAB-PENDING the agent CLI entrypoint + daemon mode are skeleton stubs.
ExecStart=/usr/bin/python3 ${AGENT_DST}/vps_agent.py --serve --wg-iface ${WG_DATA_IFACE}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

# ── 6. enable services ───────────────────────────────────────────────────────
log "Enabling services…"
systemctl daemon-reload
systemctl enable --now accel-ppp.service || warn "accel-ppp not started — check ${ACCEL_CONF} + ${SSTP_CERT_FULLCHAIN}."
systemctl enable certbot.timer >/dev/null 2>&1 || warn "certbot.timer not found — auto-renew may be manual on this distro."
# The agent is enabled but its daemon mode is a stub; leave it disabled until
# the agent is finished if you prefer:  systemctl disable radius-vps-agent
systemctl enable radius-vps-agent.service >/dev/null 2>&1 || warn "vps-agent unit not enabled (skeleton)."

log "Done. DATA BRAS active for ${SUBDOMAIN}."
cat <<SUMMARY

  Summary
  -------
  subdomain : ${SUBDOMAIN}  ->  ${VPS_IP}
  conf      : ${ACCEL_CONF}
  cert      : ${SSTP_CERT_FULLCHAIN}
  renew     : certbot.timer + ${RELOAD_HOOK}
  agent     : ${AGENT_DST} (skeleton — see README)
  pool      : ${POOL_RANGE} (gw ${POOL_GATEWAY})
  wg-data   : ${WG_DATA_IFACE} udp/${WG_DATA_PORT}

  LAB-PENDING before any live customer (see design §8):
    * exact accel-ppp Filter-Id rate form (shaper)
    * Session-Octets-Limit (227) support on the pinned accel-ppp build
    * accel-ppp NAS source IP for Disconnect (CoA secret match)
    * WG_DATA_PORT must not clash with the mgmt/data WG already on the box
SUMMARY
