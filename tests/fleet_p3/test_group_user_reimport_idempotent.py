"""fix/chr-group-idempotent-no-remove — the §11 group + user block
must be safe to re-import even when the group already carries the
managed user.

Live incident on chr-vpn-3 (first re-import attempt):
    Script Error: failure: group has some users (/user/group/remove)

Root cause: the previous template did ``/user group remove [find
name="hobe-fleet-mgmt"]`` unconditionally. RouterOS REFUSES to drop
a group that still has members — on a fresh install the group is
empty so it works; on every re-import after that, ``hobe-panel`` is
in the group and remove fails → import halts.

Fix: ADD-OR-SET pattern. ``find-len = 0 ⇒ add``, else ``set`` the
group's policy + comment in place. The set doesn't need an empty
group, so re-imports work without touching members. Same pattern
for the user — never remove a row that could be in use; set the
group binding in place; NEVER rotate the password (the panel's
stored ciphertext from generate_keys is the source of truth).

Pinned here:

* No executable ``/user group … remove`` anywhere in the rendered
  script (covers the case-sensitive line + all whitespace forms).
* No executable ``/user remove`` on the managed user row — re-imports
  use ``set`` not ``remove``+``add``.
* The find-len guard is present for both the group and the user.
* The set branch carries the SAME policy as the add branch (drift
  guard — if a future edit forgot to update one side, the live re-
  import would have inconsistent policy after the second run).
* The user-set branch does NOT carry ``password=`` (preserves the
  panel-mints-panel-knows invariant — the script never rotates).
"""
from __future__ import annotations

import re

import pytest

from app.extensions import db
from fleet.registry.models_chr import FleetProvider
from fleet.registry.onboarding_service import OnboardingService


_BASE_CFG = {
    "PANEL_WG_PUBKEY": "PANEL_PUBKEY_BASE64_xxxxxxxxxxxxxxxxxxxxxxxx=",
    "PANEL_WG_ENDPOINT": "panel.example.com:51820",
    "PROXY_WG_PUBKEY": "PROXY_PUBKEY_BASE64_xxxxxxxxxxxxxxxxxxxxxxxx=",
    "PROXY_WG_ENDPOINT": "proxy.example.com:51821",
    "CHR_SHARED_SECRET": "central-shared-secret-from-panel-xxxxxxxx",
}


def _form() -> dict:
    return dict(
        name="chr-vpn-3", provider="contabo-de", cost_model="open",
        public_ip="1.1.1.3", max_sessions=500, link_speed_mbps=1000,
        router_username="admin", router_password="admin12345",
    )


@pytest.fixture()
def provider_app(app):
    p = FleetProvider(name="contabo-de", cost_model="open", price_per_tb=0)
    db.session.add(p); db.session.commit()
    return app


def _render(provider_app) -> str:
    svc = OnboardingService(config=dict(_BASE_CFG))
    job = svc.create_draft(_form(), auto_advance=False)
    svc.generate_keys(job)
    _, script = svc.render_script(job)
    return script


def _executable_lines(script: str) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    for i, ln in enumerate(script.splitlines(), 1):
        if ln.lstrip().startswith("#"):
            continue
        out.append((i, ln))
    return out


class TestGroupReimportSafe:

    def test_no_executable_user_group_remove(self, provider_app):
        """The original bug: ``/user group remove`` halts re-import
        because the group has members. This regression guard makes the
        bug uncatchable: walks every non-comment line and asserts no
        token sequence that would attempt to remove a /user group."""
        offenders = [
            (n, l) for n, l in _executable_lines(_render(provider_app))
            if "/user group" in l and "remove" in l
        ]
        assert not offenders, (
            "RouterOS refuses to remove a /user group with members "
            "(«failure: group has some users»). Use add-or-set instead. "
            "Offenders:\n  "
            + "\n  ".join(f"L{n}: {l!r}" for n, l in offenders)
        )

    def test_add_or_set_guard_present_for_group(self, provider_app):
        script = _render(provider_app)
        # The find-len guard wraps the add branch.
        assert (
            ':if ([:len [/user group find name="hobe-fleet-mgmt"]] = 0) do={'
            in script
        )
        # And the set branch updates the existing row in place.
        assert "/user group set [find name=" in script

    def test_set_branch_carries_same_policy_as_add_branch(self, provider_app):
        """Drift guard — if a future edit changes the granted policy
        on one branch but forgets the other, re-imports would leave
        the group with the wrong policy after the second run."""
        script = _render(provider_app)
        # Tolerant continuation join + strip comment-only lines so doc
        # comments like `/user group add policy=` don't false-match.
        flat = re.sub(r" \\\n\s*", " ", script)
        text = "\n".join(
            ln for ln in flat.splitlines()
            if not ln.lstrip().startswith("#")
        )
        policies = re.findall(
            r"/user group (?:add|set) [^\n]*?policy=(\S+)", text,
        )
        # Both branches present (add + set).
        assert len(policies) == 2, (
            f"expected exactly 2 policy= occurrences (add + set); "
            f"got {policies}"
        )
        # And they match.
        assert policies[0] == policies[1], (
            f"add branch policy != set branch policy: {policies}"
        )


class TestUserReimportSafe:

    def test_no_executable_user_remove_on_managed_row(self, provider_app):
        """The user provisioning also uses add-or-set so RouterOS never
        has to remove the currently-logged-in panel poller."""
        offenders = [
            (n, l) for n, l in _executable_lines(_render(provider_app))
            if l.lstrip().startswith("/user")
            and " remove" in l
            and "/user group" not in l
        ]
        assert not offenders, (
            "Don't remove the managed user row on re-import (a removed "
            "user can't accept the next REST poll). Use add-or-set. "
            "Offenders:\n  "
            + "\n  ".join(f"L{n}: {l!r}" for n, l in offenders)
        )

    def test_add_or_set_guard_present_for_user(self, provider_app):
        script = _render(provider_app)
        # First branch: ``find name=...`` length-0 → add a new row.
        assert ':if ([:len [/user find name="hobe-panel"]] = 0) do={' in script
        # Nested branch: row exists AND carries our managed comment →
        # set the group binding in place (NO password rotation).
        assert (
            ':if ([:len [/user find name="hobe-panel" '
            'comment="hobe-fleet-api-managed"]] > 0) do={'
            in script
        )
        assert (
            '/user set [find name="hobe-panel" comment="hobe-fleet-api-managed"]'
            in script
        )

    def test_user_set_branch_converges_password(self, provider_app):
        """fix/chr-rollback-wgdata-rest — REVERSED from the old contract.

        panel-mints-panel-knows means the panel IS the source of truth,
        so the script must CONVERGE the CHR password to the panel-known
        secret on EVERY import, in BOTH branches. The previous behavior
        (set branch omits password=) was the live root cause of «login
        failure for user hobe-panel via api»: a pre-existing hobe-panel
        row kept a STALE password ≠ the panel's REST secret, so REST
        auth on www-ssl:8443 was rejected. The set branch now carries
        password= so the on-CHR secret always matches what the panel
        dials with."""
        script = _render(provider_app)
        flat = script.replace(" \\\n        ", " ").replace(" \\\n    ", " ").replace(" \\\n", " ")
        # Find the /user set line (managed-comment branch).
        set_line = next(
            ln for ln in flat.splitlines()
            if "/user set [find name=" in ln
            and 'comment="hobe-fleet-api-managed"' in ln
        )
        assert "password=" in set_line, (
            "/user set on the managed row MUST include password= so the "
            "CHR secret converges to the panel-known value (fixes the "
            "via-api REST auth failure on a stale password). Got:\n"
            f"  {set_line!r}"
        )
        # And it must bind to the scoped group.
        assert 'group="hobe-fleet-mgmt"' in set_line
        # Determinism (same password every render) is covered by
        # TestSimulatedReimport.test_two_renders_emit_identical_user_blocks.


class TestSimulatedReimport:
    """A simulated re-import: render the script twice from the same
    node row and assert the user-add password ON BOTH RENDERS is
    identical (the second render is what would run on the CHR's second
    /import — the password must come from the row, not be re-rolled).
    """

    def test_two_renders_emit_identical_user_blocks(self, provider_app):
        svc = OnboardingService(config=dict(_BASE_CFG))
        job = svc.create_draft(_form(), auto_advance=False)
        svc.generate_keys(job)
        _, script_a = svc.render_script(job)
        # The «عرض السكربت» button uses _build_bindings; re-render via
        # the same surface.
        bindings_b = svc._build_bindings(job)
        from fleet.registry.script_render import render_from_bindings
        script_b = render_from_bindings(bindings_b)

        def _extract_user_block(s: str) -> str:
            lines = s.splitlines()
            i = next(
                j for j, l in enumerate(lines)
                if l.lstrip().startswith("/user")
                and not l.lstrip().startswith("/user group")
                and not l.lstrip().startswith("#")
            )
            k = next(
                j for j, l in enumerate(lines[i:], i)
                if "Self-signed PKI" in l
            )
            return "\n".join(lines[i:k])

        assert _extract_user_block(script_a) == _extract_user_block(script_b), (
            "re-render must produce a byte-identical user block "
            "(no silent password rotation between renders)."
        )
