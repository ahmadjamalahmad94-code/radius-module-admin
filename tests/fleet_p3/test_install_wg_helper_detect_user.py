"""fix/install-wg-helper-detect-user — installer adapts to the panel user.

Field incident: ``deploy/zero_touch/install_wg_helper.sh`` hardcoded
``PANEL_USER="${PANEL_USER:-hoberadius}"`` and verified with
``sudo -u "$PANEL_USER" ...``. On the owner's control host the panel
runs as ROOT (systemd unit has ``User=`` empty), so:
  * the sudoers grant pointed at a non-existent ``hoberadius`` user, OR
  * the verify failed because ``sudo -u hoberadius`` couldn't switch
    to a user that didn't exist.

Fix mirrors the proxy's setup-wg-sudoers approach: auto-detect the
panel service user from systemd, fall back to env override, and
treat empty/missing as root. When the panel runs as root, SKIP the
sudoers grant (root is passwordless for ``sudo -n``) and still
install the helper.

These tests pin the contract at the SOURCE level (the script does
real ``install``/``visudo``/``sudo`` calls that need root, so a
runtime test would need a dedicated sandbox).
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest


SCRIPT = Path("deploy/zero_touch/install_wg_helper.sh")


@pytest.fixture(scope="module")
def src() -> str:
    return SCRIPT.read_text(encoding="utf-8")


# ════════════════════════════════════════════════════════════════════════
# (1) Auto-detect function present + fallback chain
# ════════════════════════════════════════════════════════════════════════
class TestDetectPanelUser:

    def test_detect_function_defined(self, src):
        assert "detect_panel_user()" in src, (
            "installer must define a detect_panel_user shell function "
            "so the resolution chain is explicit + testable"
        )

    def test_env_override_wins(self, src):
        """PANEL_USER env wins over auto-detect."""
        # The detect function uses ${PANEL_USER+x} to distinguish
        # "unset" from "set to empty". An explicit empty string is
        # treated as ROOT (override).
        assert 'if [[ -n "${PANEL_USER+x}" ]]' in src
        assert 'if [[ -z "${PANEL_USER}" ]]' in src

    def test_systemctl_probe_with_value_flag(self, src):
        """The probe uses ``systemctl show -p User --value`` which prints
        just the value, no ``User=`` prefix — matches the proxy fix."""
        assert "systemctl show" in src
        assert "-p User --value" in src

    def test_probes_multiple_unit_names(self, src):
        """The panel ships under several common unit names depending
        on the deploy; the installer must try them all."""
        for unit in (
            "hoberadius-license-panel",
            "hoberadius-license-panel.service",
            "license-panel",
        ):
            assert unit in src, f"installer must probe systemd unit {unit!r}"

    def test_falls_back_to_root(self, src):
        """Empty systemd User= or no matching unit → 'root'."""
        # The function ends with `printf 'root\n'`.
        assert "printf 'root\\n'" in src


# ════════════════════════════════════════════════════════════════════════
# (2) Sudoers grant uses the RESOLVED user, not the hardcoded literal
# ════════════════════════════════════════════════════════════════════════
class TestSudoersUsesResolvedUser:

    def test_sudoers_line_uses_resolved_var(self, src):
        # The new variable name is PANEL_USER_RESOLVED.
        assert "${PANEL_USER_RESOLVED}" in src, (
            "sudoers grant must use the auto-detected user variable, "
            "not the raw PANEL_USER env-fallback default"
        )
        # And the sudoers grant still includes all three subcommands.
        assert "${HELPER_DST} apply" in src
        assert "${HELPER_DST} show" in src
        assert "${HELPER_DST} pubkey" in src

    def test_sudoers_validated_by_visudo(self, src):
        """A broken sudoers file is dangerous; visudo -c must validate
        BEFORE the install. Carried over from the original installer."""
        assert "visudo -c -f" in src


# ════════════════════════════════════════════════════════════════════════
# (3) Root case — skip sudoers, still install helper, verify directly
# ════════════════════════════════════════════════════════════════════════
class TestRootCase:

    def test_root_case_skips_sudoers(self, src):
        """When PANEL_USER_RESOLVED == 'root', the script must NOT
        write a per-user sudoers file (root already has the privilege;
        a sudoers grant for 'root' would be a no-op at best + an
        audit-noise at worst)."""
        # The condition + the Arabic explanation present.
        assert 'if [[ "${PANEL_USER_RESOLVED}" == "root" ]]' in src
        assert "اللوحة تعمل بصلاحية root" in src
        assert "skipping sudoers grant" in src

    def test_root_case_removes_stale_sudoers_from_prior_install(self, src):
        """If a previous run installed sudoers for a named user but the
        panel later switched to root, the stale grant must be cleaned
        up — otherwise it points at a possibly-deleted user."""
        assert "rm -f \"$SUDOERS_DST\"" in src or "rm -f $SUDOERS_DST" in src
        assert "stale sudoers file" in src

    def test_root_case_still_installs_helper(self, src):
        """The helper binary install runs BEFORE the sudoers branch so
        it always lands regardless of the user."""
        helper_install = src.index('install -o root -g root -m 0755 "$HELPER_SRC" "$HELPER_DST"')
        sudoers_branch = src.index('if [[ "${PANEL_USER_RESOLVED}" == "root" ]]')
        assert helper_install < sudoers_branch, (
            "helper binary install must run BEFORE the sudoers branch "
            "so the root case still installs the helper"
        )

    def test_root_case_verify_uses_sudo_n_directly(self, src):
        """The verify step in the root branch must mirror the panel
        process's real call shape: ``sudo -n <helper> show``. Calling
        the helper directly would mask a sudo PATH issue."""
        # Find the root-branch verify line.
        m = re.search(
            r'PANEL_USER_RESOLVED.*?root.*?'
            r'sudo -n "\$HELPER_DST" show',
            src, re.DOTALL,
        )
        assert m, "root-branch verify must use `sudo -n <helper> show`"


# ════════════════════════════════════════════════════════════════════════
# (4) Named-user case — sudoers + sudo -u <user> verify
# ════════════════════════════════════════════════════════════════════════
class TestNamedUserCase:

    def test_named_user_case_writes_sudoers(self, src):
        """When the detected user is NOT root, the original sudoers
        flow runs — the only change is the user name now comes from
        the resolved variable."""
        # The else branch contains the visudo + install steps.
        assert "else" in src
        assert "Writing scoped sudoers rule" in src

    def test_named_user_case_verify_uses_sudo_u(self, src):
        """Verify still uses ``sudo -n -u "${PANEL_USER_RESOLVED}" sudo -n <helper> show``
        — the double-sudo pattern that mirrors what the panel process
        would do."""
        assert 'sudo -n -u "${PANEL_USER_RESOLVED}" sudo -n "$HELPER_DST" show' in src

    def test_named_user_case_validates_user_exists(self, src):
        """Refuse to write a sudoers grant for a non-existent user —
        better a loud failure than a phantom grant. Pin the existence
        check."""
        assert 'id -u "${PANEL_USER_RESOLVED}"' in src
        assert "does NOT exist on this host" in src


# ════════════════════════════════════════════════════════════════════════
# (5) wg_apply._run_helper works as root — verified by source review
# ════════════════════════════════════════════════════════════════════════
class TestPanelWgApplyAsRoot:

    def test_helper_path_override_documented(self):
        """The Flask config key ZERO_TOUCH_WG_HELPER overrides the
        hardcoded /usr/local/sbin/hobe-wg-sync path — useful when the
        operator's distro restricts /usr/local/sbin or when running in
        a container with the helper at /opt/hobe/hobe-wg-sync."""
        body = Path("fleet/sync/wg_apply.py").read_text(encoding="utf-8")
        assert "ZERO_TOUCH_WG_HELPER" in body, (
            "wg_apply must support a config-level helper-path override "
            "so a non-standard install location works without code edits"
        )

    def test_run_helper_uses_sudo_n_which_works_for_root(self):
        """The panel process invokes ``sudo -n <helper>``. Under root,
        ``sudo -n`` is a passwordless no-op (root → root is always
        allowed), so the same code path works whether the panel runs
        as root OR as the hoberadius user. Pin the call shape at the
        source so a refactor doesn't accidentally drop the ``-n`` or
        switch to ``sudo -u <user>`` (which would FAIL as root)."""
        body = Path("fleet/sync/wg_apply.py").read_text(encoding="utf-8")
        assert 'argv = ["sudo", "-n", helper, action]' in body, (
            "wg_apply._run_helper must invoke `sudo -n <helper>` — that "
            "shape works both as root (passwordless no-op) AND as the "
            "hoberadius user (via the sudoers grant)"
        )


# ════════════════════════════════════════════════════════════════════════
# (6) Operator-facing footer documents the live-key autosync interval
# ════════════════════════════════════════════════════════════════════════
class TestInstallerFooterMentionsAutosync:

    def test_footer_explains_autosync(self, src):
        """The post-install footer must tell the operator that the
        live-key autosync + reconcile_panel_host are what now actually
        ship every CHR peer to the control server. Without this hint
        the operator runs the installer + sees nothing visible until
        the next autosync tick (≤2 min by default)."""
        assert "PANEL_WG_AUTOSYNC_INTERVAL" in src
        assert "reconcile_panel_host()" in src
