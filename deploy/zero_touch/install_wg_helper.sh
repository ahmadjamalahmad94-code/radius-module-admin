#!/usr/bin/env bash
# install_wg_helper.sh — ONE-TIME privileged setup for zero-touch wg peer sync.
#
# This is the single documented privileged step the zero-touch fleet sync
# requires. Run it ONCE on the PANEL host as root. After this, every CHR
# add/sync is fully panel-driven — no further manual terminal work.
#
# What it does, in order:
#   1. AUTO-DETECTS the panel service user (so the same script works on
#      hosts that run the panel as `hoberadius`, `panel`, or `root`).
#      Detection order:
#        * env var PANEL_USER (explicit override)
#        * systemctl show hoberadius-license-panel -p User --value
#        * fall back to `root`
#   2. Installs the scoped helper at /usr/local/sbin/hobe-wg-sync
#      (root:root, mode 0755).
#   3. If the panel runs as a NON-root user → drops a sudoers rule
#      letting ONLY that user run ONLY that helper, NOPASSWD,
#      validated by `visudo -c`.
#      If the panel runs as ROOT → skips the sudoers grant entirely
#      (root already has the privilege; the wg sudo-helper Python
#      wrapper `_run_helper` does `sudo -n <helper>` which is a
#      transparent no-op when invoked by root).
#   4. Verifies the helper works (via `sudo -u <user>` for a named
#      user, OR directly when running as root).
#
# Re-running is safe (idempotent): it overwrites the helper + sudoers
# with the current versions and leaves an existing wg-mgmt.conf untouched.
set -euo pipefail

# ──────────────────────────────────────────────────────────────────────
# (1) Detect the panel service user
# ──────────────────────────────────────────────────────────────────────
# Resolution order:
#   * env var PANEL_USER (explicit operator override; empty string also
#     counts as override → "panel runs as root")
#   * systemctl show <UNIT> -p User --value, for each candidate unit
#   * default = "root"
#
# `User=` empty in systemd ⇒ unit runs as root; we treat that the same
# as "root" so the sudoers grant is skipped (root is passwordless).
detect_panel_user() {
  # Explicit operator override wins. Treat empty string as "root".
  if [[ -n "${PANEL_USER+x}" ]]; then
    if [[ -z "${PANEL_USER}" ]]; then
      printf 'root\n'; return
    fi
    printf '%s\n' "$PANEL_USER"; return
  fi

  # Try every reasonable unit name the panel may be deployed under.
  local unit candidate
  for unit in \
      hoberadius-license-panel \
      hoberadius-license-panel.service \
      hoberadius-panel \
      license-panel \
      hoberadius
  do
    if command -v systemctl >/dev/null 2>&1; then
      candidate="$(systemctl show "$unit" -p User --value 2>/dev/null || true)"
      if [[ -n "$candidate" ]]; then
        printf '%s\n' "$candidate"; return
      fi
    fi
  done

  # No systemd / no matching unit / unit has empty User= → root.
  printf 'root\n'
}

PANEL_USER_RESOLVED="$(detect_panel_user)"
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

echo "==> Panel service user (detected): ${PANEL_USER_RESOLVED}"

# ──────────────────────────────────────────────────────────────────────
# (2) Install the helper binary
# ──────────────────────────────────────────────────────────────────────
echo "==> Installing helper → $HELPER_DST"
install -o root -g root -m 0755 "$HELPER_SRC" "$HELPER_DST"

# ──────────────────────────────────────────────────────────────────────
# (3) Sudoers grant — only when the panel runs as a non-root user
# ──────────────────────────────────────────────────────────────────────
if [[ "${PANEL_USER_RESOLVED}" == "root" ]]; then
  echo "==> اللوحة تعمل بصلاحية root — لا حاجة لـsudoers؛ ستستخدم wg مباشرة."
  echo "    (panel runs as root → skipping sudoers grant; root already has the privilege)"
  # Remove any stale sudoers file from a previous non-root install so
  # we don't leave a dangling grant for a user that may not exist
  # anymore. Best-effort: a missing file is fine.
  if [[ -f "$SUDOERS_DST" ]]; then
    echo "    Removing stale sudoers file from a prior non-root install: $SUDOERS_DST"
    rm -f "$SUDOERS_DST"
  fi
else
  # Validate that the resolved user actually exists. If it doesn't, the
  # operator typo'd PANEL_USER or the systemd unit names a user that
  # was never created — fail loud rather than write a sudoers file for
  # a phantom user.
  if ! id -u "${PANEL_USER_RESOLVED}" >/dev/null 2>&1; then
    echo "ERROR: detected panel user '${PANEL_USER_RESOLVED}' does NOT exist on this host." >&2
    echo "       Pass PANEL_USER=<real-user> to this script, or run the panel as root." >&2
    exit 1
  fi
  echo "==> Writing scoped sudoers rule → $SUDOERS_DST"
  TMP_SUDOERS="$(mktemp)"
  cat > "$TMP_SUDOERS" <<EOF
# Managed by deploy/zero_touch/install_wg_helper.sh — DO NOT EDIT BY HAND.
# Lets the unprivileged panel user reconcile wg-mgmt peers via the single
# scoped helper, and nothing else.
${PANEL_USER_RESOLVED} ALL=(root) NOPASSWD: ${HELPER_DST} apply, ${HELPER_DST} show, ${HELPER_DST} pubkey
EOF
  # Validate BEFORE installing — a broken sudoers file is dangerous.
  visudo -c -f "$TMP_SUDOERS"
  install -o root -g root -m 0440 "$TMP_SUDOERS" "$SUDOERS_DST"
  rm -f "$TMP_SUDOERS"
fi

# ──────────────────────────────────────────────────────────────────────
# (4) Verify the helper works for the resolved user
# ──────────────────────────────────────────────────────────────────────
echo "==> Verifying the panel user can invoke the helper"
if [[ "${PANEL_USER_RESOLVED}" == "root" ]]; then
  # Root path: the panel process itself does `sudo -n <helper>` which is
  # a passwordless no-op for root. We mirror that exact invocation here
  # so the verify reflects the real call shape — NOT a direct `helper`
  # exec that would mask a `sudo` PATH issue.
  if sudo -n "$HELPER_DST" show >/dev/null 2>&1; then
    echo "    OK: root can run ${HELPER_DST} (verified via sudo -n)"
  else
    echo "    NOTE: could not self-verify (wg-mgmt may be down yet). The helper"
    echo "          is installed; the panel will detect it on next sync."
  fi
else
  if sudo -n -u "${PANEL_USER_RESOLVED}" sudo -n "$HELPER_DST" show >/dev/null 2>&1; then
    echo "    OK: ${PANEL_USER_RESOLVED} can run ${HELPER_DST}"
  else
    echo "    NOTE: could not self-verify (wg-mgmt may be down yet). The sudoers"
    echo "          rule is installed; the panel will detect the helper on next sync."
  fi
fi

echo
echo "Done. The panel can now auto-apply wg-mgmt peers."
echo "  * Live-key autosync runs every PANEL_WG_AUTOSYNC_INTERVAL (default 120s)"
echo "    — adopts a drifted control-server pubkey into the panel Settings."
echo "  * reconcile_panel_host() runs each tick — adds every CHR's wg-mgmt peer"
echo "    on the control server + persists to /etc/wireguard/wg-mgmt.conf."
echo
echo "Bring up wg-mgmt with the panel's private key per"
echo "docs/DEPLOY_PANEL_CONTROL_PLANE.md if you haven't already, then visit"
echo "the fleet dashboard — the next autosync tick will sweep the rest."
