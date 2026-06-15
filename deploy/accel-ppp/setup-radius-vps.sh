#!/usr/bin/env bash
# ============================================================================
# setup-radius-vps.sh — ONE-TIME accel-ppp DATA-connection activation
# HobeRadius — branch feat/data-conn-2c-panel-vps-activation
#
# WHAT THIS IS
#   Turns a freshly-provisioned customer RADIUS VPS into a DATA-connection BRAS
#   (SSTP / PPTP / L2TP served directly by accel-ppp — no proxy, no CHR). It
#   installs accel-ppp + certbot, renders the config, ISSUES the Let's Encrypt
#   cert (certbot HTTP-01, after waiting for DNS), wires auto-renewal, and
#   installs the vps-agent. See deploy/accel-ppp/README.md for the full order.
#
# HOW IT'S DELIVERED
#   PRIMARY  — cloud-init: paste deploy/accel-ppp/cloud-init.yaml (with your
#              values filled in) into the provider's user-data field at VPS
#              creation. First boot runs THIS script → zero-touch activation.
#   FALLBACK — manual: if the provider has no cloud-init, set the variables
#              below (or export them) and `sudo bash setup-radius-vps.sh`.
#   Same script both ways.
#
#   The licensing panel creates the subdomain DNS A record (Cloudflare) when the
#   customer is added with the VPS IP — BEFORE this VPS exists. So by first boot
#   the record normally already resolves; the cert step still WAITS for DNS
#   (bounded) to absorb any propagation lag.
#
# IDEMPOTENT
#   Safe to re-run. Every step checks-before-acting (apt install is a no-op when
#   present; the conf is only rewritten when it changed; certbot
#   --keep-until-expiring won't reissue a live cert; systemd units use
#   'enable --now' which is idempotent).
#
# Every value you MUST set is marked  # >>> SET ME.
# Every item still pending lab validation is marked  # !!! LAB-PENDING.
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

# Cert/DNS automation knobs. The cert step waits up to DNS_WAIT_TIMEOUT seconds
# (polling every DNS_WAIT_INTERVAL) for SUBDOMAIN to resolve to VPS_IP before
# calling certbot, so a first-boot DNS lag doesn't fail the install.
DNS_WAIT_TIMEOUT="${DNS_WAIT_TIMEOUT:-300}"
DNS_WAIT_INTERVAL="${DNS_WAIT_INTERVAL:-10}"
CERTBOT_STAGING="${CERTBOT_STAGING:-0}"            # set 1 to test against LE staging

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

# Render with python3 (installed in step 1) doing LITERAL substitution. We
# deliberately avoid `sed` here: a random RADIUS_SECRET can contain `|` (the
# delimiter), `&` (whole-match backref), or `\` — all of which corrupt or
# crash a sed s-command. Values are passed via the environment (never
# interpolated into the script) so no shell/sed metachar can leak in.
R_POOL_RANGE="$POOL_RANGE" R_POOL_GATEWAY="$POOL_GATEWAY" \
R_DNS1="$DNS1" R_DNS2="$DNS2" R_RADIUS_SECRET="$RADIUS_SECRET" \
R_RADIUS_AUTH_PORT="$RADIUS_AUTH_PORT" R_RADIUS_ACCT_PORT="$RADIUS_ACCT_PORT" \
R_NAS_IDENTIFIER="$NAS_IDENTIFIER" R_COA_PORT="$COA_PORT" \
R_SSTP_CERT_FULLCHAIN="$SSTP_CERT_FULLCHAIN" R_SSTP_CERT_KEY="$SSTP_CERT_KEY" \
R_SUBDOMAIN="$SUBDOMAIN" R_TEMPLATE="$TEMPLATE" \
python3 - "$TMP_CONF" <<'PY'
import os, sys
keys = ["POOL_RANGE", "POOL_GATEWAY", "DNS1", "DNS2", "RADIUS_SECRET",
        "RADIUS_AUTH_PORT", "RADIUS_ACCT_PORT", "NAS_IDENTIFIER", "COA_PORT",
        "SSTP_CERT_FULLCHAIN", "SSTP_CERT_KEY", "SUBDOMAIN"]
with open(os.environ["R_TEMPLATE"], "r", encoding="utf-8") as f:
    text = f.read()
for k in keys:
    text = text.replace("{{ %s }}" % k, os.environ.get("R_" + k, ""))
with open(sys.argv[1], "w", encoding="utf-8") as f:
    f.write(text)
PY

# Match only real, unrendered {{ VAR }} tokens (UPPER_SNAKE) — NOT the literal
# "{{ ... }}" example that lives in the template's own header comment.
if grep -qE '\{\{ [A-Z][A-Z0-9_]* \}\}' "$TMP_CONF"; then
    warn "template still has unrendered {{ VAR }} tokens:"
    grep -nE '\{\{ [A-Z][A-Z0-9_]* \}\}' "$TMP_CONF" >&2 || true
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

# ── 3. install the vps-agent (needed for the cert step) ──────────────────────
# The agent applies WireGuard peers + per-peer 5 Mbit tc queues, reads live
# sessions, and owns the cert automation (DNS-wait + certbot + reload). The
# WG/tc/session parts are a SKELETON (see its README); the cert + reload logic
# is unit-tested. Installed BEFORE the cert step because that step calls it.
log "Installing vps-agent → ${AGENT_DST}…"
install -d -m 0755 "$AGENT_DST"
cp -r "$AGENT_SRC/." "$AGENT_DST/"
AGENT="${AGENT_DST}/vps_agent.py"

# ── 4. cert: wait for DNS, then issue via certbot HTTP-01 (NON-FATAL) ─────────
# The panel created the A record (clientN.<zone> -> VPS_IP) when the customer
# was added. The agent WAITS (bounded) for that to resolve to THIS VPS, then
# runs certbot --standalone (binds :80; accel-ppp owns 443, not 80). HTTP-01
# proves control. certbot --keep-until-expiring makes re-runs idempotent.
#
# IMPORTANT: cert failure is NON-FATAL. We never `die` here — accel-ppp stays
# installed; fix DNS / reachability and re-run (idempotent). The agent logs a
# precise, actionable reason.
log "Ensuring certificate for ${SUBDOMAIN} (waiting up to ${DNS_WAIT_TIMEOUT}s for DNS)…"
staging_flag=""
[[ "$CERTBOT_STAGING" == "1" ]] && staging_flag="--staging"
if [[ -f "$SSTP_CERT_FULLCHAIN" ]]; then
    log "  cert already present — certbot.timer handles renewal."
else
    if python3 "$AGENT" --ensure-cert \
            --subdomain "$SUBDOMAIN" --vps-ip "$VPS_IP" --email "$CERTBOT_EMAIL" \
            --timeout "$DNS_WAIT_TIMEOUT" --interval "$DNS_WAIT_INTERVAL" $staging_flag; then
        log "  certificate issued."
    else
        warn "certificate NOT issued yet (see message above). accel-ppp will be"
        warn "installed without SSTP TLS until you fix DNS/:80 and re-run this script"
        warn "(or wait for the next certbot.timer run)."
    fi
fi

# ── 5. auto-renew → reload accel-ppp ─────────────────────────────────────────
# certbot.timer (installed by the apt package) renews silently; this deploy
# hook makes accel-ppp pick up the fresh cert without a full restart. The
# reload logic lives in the agent (unit-tested) so the hook is a one-liner.
log "Installing certbot deploy hook → accel-ppp reload…"
install -d -m 0755 "$(dirname "$RELOAD_HOOK")"
cat > "$RELOAD_HOOK" <<HOOK
#!/usr/bin/env bash
# Reload accel-ppp after a successful cert renewal so SSTP serves the new chain.
set -e
python3 "${AGENT}" --reload-accel
HOOK
chmod 0755 "$RELOAD_HOOK"

cat > /etc/systemd/system/radius-vps-agent.service <<UNIT
[Unit]
Description=HobeRadius VPS agent (accel-ppp DATA connections)
After=network-online.target accel-ppp.service
Wants=network-online.target

[Service]
Type=simple
# !!! LAB-PENDING the agent daemon (--serve) loop is a skeleton stub.
ExecStart=/usr/bin/python3 ${AGENT} --serve --wg-iface ${WG_DATA_IFACE}
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
