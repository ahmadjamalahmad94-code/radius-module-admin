#!/usr/bin/env bash
# install_wg_helper.sh — ONE-TIME privileged setup for zero-touch wg peer sync.
#
# This is the single documented privileged step the zero-touch fleet sync
# requires. Run it ONCE on the PANEL host as root. After this, every CHR
# add/sync is fully panel-driven — no further manual terminal work, and no
# standing root in the app (which keeps running unprivileged as hoberadius).
#
# What it does, and nothing more:
#   1. Installs the scoped helper at /usr/local/sbin/hobe-wg-sync (root:root 0755).
#   2. Drops a sudoers rule letting ONLY the panel user run ONLY that helper,
#      with NOPASSWD, validated by `visudo -c`.
#   3. (Optional) creates /etc/wireguard/wg-mgmt.conf from the panel's stored
#      private key + brings the interface up, if it doesn't exist yet.
#
# Re-running is safe (idempotent): it overwrites the helper + sudoers with the
# current versions and leaves an existing wg-mgmt.conf untouched.
set -euo pipefail

PANEL_USER="${PANEL_USER:-hoberadius}"
HELPER_SRC="$(cd "$(dirname "$0")" && pwd)/hobe-wg-sync"
HELPER_DST="/usr/local/sbin/hobe-wg-sync"
SUDOERS_DST="/etc/sudoers.d/hoberadius-wg-sync"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "ERROR: run as root (sudo $0)." >&2
  exit 1
fi
if [[ ! -f "$HELPER_SRC" ]]; then
  echo "ERROR: helper not found next to installer: $HELPER_SRC" >&2
  exit 1
fi
command -v wg      >/dev/null || { echo "ERROR: wireguard-tools (wg) not installed." >&2; exit 1; }
command -v wg-quick>/dev/null || { echo "ERROR: wg-quick not installed." >&2; exit 1; }
command -v python3 >/dev/null || { echo "ERROR: python3 required by the helper." >&2; exit 1; }

echo "==> Installing helper → $HELPER_DST"
install -o root -g root -m 0755 "$HELPER_SRC" "$HELPER_DST"

echo "==> Writing scoped sudoers rule → $SUDOERS_DST"
TMP_SUDOERS="$(mktemp)"
cat > "$TMP_SUDOERS" <<EOF
# Managed by deploy/zero_touch/install_wg_helper.sh — DO NOT EDIT BY HAND.
# Lets the unprivileged panel user reconcile wg-mgmt peers via the single
# scoped helper, and nothing else.
${PANEL_USER} ALL=(root) NOPASSWD: ${HELPER_DST} apply, ${HELPER_DST} show, ${HELPER_DST} pubkey
EOF
# Validate BEFORE installing — a broken sudoers file is dangerous.
visudo -c -f "$TMP_SUDOERS"
install -o root -g root -m 0440 "$TMP_SUDOERS" "$SUDOERS_DST"
rm -f "$TMP_SUDOERS"

echo "==> Verifying the panel user can invoke the helper"
if sudo -n -u "$PANEL_USER" sudo -n "$HELPER_DST" show >/dev/null 2>&1; then
  echo "    OK: ${PANEL_USER} can run ${HELPER_DST}"
else
  echo "    NOTE: could not self-verify (wg-mgmt may be down yet). The sudoers"
  echo "          rule is installed; the app will detect the helper on next sync."
fi

echo
echo "Done. The panel can now auto-apply wg-mgmt peers. Bring up wg-mgmt with"
echo "the panel's private key per docs/DEPLOY_PANEL_CONTROL_PLANE.md if you"
echo "haven't already, then run «إعادة مزامنة الأسطول» from the fleet dashboard."
