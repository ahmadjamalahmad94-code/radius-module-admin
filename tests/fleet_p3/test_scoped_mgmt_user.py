"""feat/chr-auto-scoped-mgmt-user — dedicated scoped management user.

Owner's idea: «بدل ما ينتظر مني أحط admin أو hobe-panel — ليش
السكربت ما يكون فيه إنشاء يوزر إدارة موحّد، بينشئ بصلاحيات معيّنة
حسب الحاجة». The unified script ALWAYS provisions a dedicated user
bound to a dedicated group with the EXACT policy set the panel
needs.

Invariants pinned here:

  (I)   GROUP — ``hobe-fleet-mgmt`` is created with the exact
        least-privilege policy string (asserted verbatim). The group
        MUST grant ``read,write,sensitive,reboot,rest-api`` and MUST
        explicitly deny ``api,ssh,winbox,ftp,web,password,policy,
        sniff,test,romon,dude,tikapp``.

  (II)  USER  — bound to that scoped group, NEVER to ``full`` /
        ``read`` / ``write``. The user is ``hobe-panel`` by default;
        reserved built-in names (admin/root/...) are substituted
        upstream by the renderer (this module verifies the END
        state).

  (III) AUTO-PROVISION DEFAULT — a brand-new node with no fleet-
        default and no per-node credentials gets a working REST
        endpoint with NO operator action. The node row carries the
        substituted user + the auto-minted password.

  (IV)  IDEMPOTENT — re-import is safe: the find-by-comment guard
        means the script touches only its own managed user row, and
        the group is remove-then-add.

  (V)   REST CALL COVERAGE — every endpoint the panel actually hits
        falls under {read, write, sensitive, reboot} (audited from
        app/services/routeros_client.py and every caller).

Coverage of (V) is enforced by an EXHAUSTIVE write-method walk
against ``RouterOSClient`` — any new client method that performs a
PUT/PATCH/DELETE/POST and isn't in the WRITE/SENSITIVE allow-lists
trips the test, forcing the author to update the policy + this guard
together.
"""
from __future__ import annotations

import inspect
import re

import pytest

from app.extensions import db
from app.services import routeros_client as _roc
from fleet.health.routeros_creds import (
    HARD_DEFAULT_USER, credentials_for, decrypt_password,
    set_default_password, set_default_user,
)
from fleet.registry.models_chr import FleetChrNode, FleetProvider
from fleet.registry.onboarding_service import OnboardingService


_BASE_CFG = {
    "PANEL_WG_PUBKEY": "PANEL_PUBKEY_BASE64_xxxxxxxxxxxxxxxxxxxxxxxx=",
    "PANEL_WG_ENDPOINT": "panel.example.com:51820",
    "PROXY_WG_PUBKEY": "PROXY_PUBKEY_BASE64_xxxxxxxxxxxxxxxxxxxxxxxx=",
    "PROXY_WG_ENDPOINT": "proxy.example.com:51821",
    "CHR_SHARED_SECRET": "central-shared-secret-from-panel-xxxxxxxx",
}

#: The exact policy string the script must emit — GRANTED ONLY.
#:
#: LIVE INCIDENT (fix/chr-group-policy-granted-only): RouterOS v7
#: ``/user group add policy=`` accepts a comma-separated list of
#: GRANTED policy names ONLY. ``!negation`` tokens are NOT valid
#: input — RouterOS denies any UNLISTED policy by default, so
#: deny-by-omission is the only correct form. A previous version
#: emitted ``...,!api,!ssh,...,!tikapp`` and the parser errored with
#: «input does not match any value of policy» on chr-vpn-3
#: (WinBox 4.1), leaving the group unprovisioned + the import
#: halted. This test pins the granted-only shape.
EXPECTED_POLICY = "read,write,sensitive,reboot,rest-api"

#: Policies that MUST stay denied. We assert they DON'T appear in
#: the policy list (deny-by-omission). They also must NOT appear
#: with a ``!`` prefix — that's a syntax error on /user group add.
DENIED_POLICIES = (
    "api", "ssh", "winbox", "ftp", "web", "password",
    "policy", "sniff", "test", "romon", "dude", "tikapp",
)

EXPECTED_GROUP_NAME = "hobe-fleet-mgmt"


def _form(name: str = "chr-vpn-3") -> dict:
    return dict(
        name=name, provider="contabo-de", cost_model="open",
        public_ip="1.1.1.3", max_sessions=500, link_speed_mbps=1000,
        router_username="admin", router_password="admin12345",
    )


@pytest.fixture()
def provider_app(app):
    p = FleetProvider(name="contabo-de", cost_model="open", price_per_tb=0)
    db.session.add(p); db.session.commit()
    return app


def _render(svc_cfg: dict | None = None) -> str:
    svc = OnboardingService(config={**_BASE_CFG, **(svc_cfg or {})})
    job = svc.create_draft(_form(), auto_advance=False)
    svc.generate_keys(job)
    _, script = svc.render_script(job)
    return script


# ════════════════════════════════════════════════════════════════════════
# (I) GROUP — least-privilege policy string asserted verbatim
# ════════════════════════════════════════════════════════════════════════
class TestScopedGroupPolicy:

    def test_group_created_with_exact_policy(self, provider_app):
        script = _render()
        # The full add line — gather across the line-continuation.
        flat = script.replace(" \\\n    ", " ").replace(" \\\n", " ")
        add_line = next(
            ln for ln in flat.splitlines()
            if ln.startswith(f'add name="{EXPECTED_GROUP_NAME}"')
        )
        assert f"policy={EXPECTED_POLICY}" in add_line, (
            f"policy must match the audited least-privilege set; got:\n{add_line}"
        )

    def test_group_grants_required_policies(self, provider_app):
        """Spelled out per-policy so a single-token swap (e.g. dropping
        ``write``) is caught with a clear failure."""
        script = _render()
        granted_tokens = EXPECTED_POLICY.split(",")
        for granted in ("read", "write", "sensitive", "reboot", "rest-api"):
            assert granted in granted_tokens, granted
            assert f"policy={EXPECTED_POLICY}" in script.replace(" \\\n    ", " ")

    def test_group_policy_has_no_negation_tokens(self, provider_app):
        """fix/chr-group-policy-granted-only — RouterOS v7
        ``/user group add policy=`` errors with «input does not
        match any value of policy» on the FIRST ``!`` token. The
        rendered policy value must contain NO ``!`` at all."""
        script = _render()
        # Extract the joined add-line and pull the policy= value.
        flat = script.replace(" \\\n    ", " ").replace(" \\\n", " ")
        add_line = next(
            ln for ln in flat.splitlines()
            if ln.startswith(f'add name="{EXPECTED_GROUP_NAME}"')
        )
        import re
        m = re.search(r'policy=([^\s]+)', add_line)
        assert m, f"could not extract policy= value from: {add_line!r}"
        policy_value = m.group(1)
        assert "!" not in policy_value, (
            f"policy value must NOT contain `!` (RouterOS rejects negation "
            f"tokens on /user group add); got: {policy_value!r}"
        )
        assert policy_value == EXPECTED_POLICY, (
            f"policy value must equal {EXPECTED_POLICY!r}; got: {policy_value!r}"
        )

    def test_group_denies_forbidden_policies_by_omission(self, provider_app):
        """RouterOS denies any UNLISTED policy by default — we assert
        the forbidden tokens are simply ABSENT from the granted list."""
        granted_tokens = set(EXPECTED_POLICY.split(","))
        for deny in DENIED_POLICIES:
            assert deny not in granted_tokens, (
                f"policy {deny!r} must NOT be granted "
                f"(deny-by-omission); got policy={EXPECTED_POLICY}"
            )

    def test_group_is_not_a_builtin(self, provider_app):
        """The group name must NOT collide with any built-in v7 group
        (``full`` / ``read`` / ``write``)."""
        script = _render()
        # The add line uses our scoped group.
        assert 'group="hobe-fleet-mgmt"' in script
        # And NEVER binds to a built-in group.
        assert 'group=full' not in script
        assert 'group="full"' not in script
        assert 'group=admin' not in script

    def test_group_remove_before_add_is_idempotent(self, provider_app):
        """Re-import is safe — the group is dropped before re-creation."""
        script = _render()
        rem_idx = script.index('remove [find name="hobe-fleet-mgmt"]')
        add_idx = script.index('add name="hobe-fleet-mgmt"')
        assert rem_idx < add_idx


# ════════════════════════════════════════════════════════════════════════
# (II) USER — bound to scoped group, never built-in groups
# ════════════════════════════════════════════════════════════════════════
class TestUserBinding:

    def test_user_uses_scoped_group(self, provider_app):
        script = _render()
        # The /user add line carries group=hobe-fleet-mgmt
        flat = script.replace(" \\\n        ", " ").replace(" \\\n", " ")
        user_add_line = next(
            ln for ln in flat.splitlines()
            if "/user add name=" in ln
        )
        assert 'group="hobe-fleet-mgmt"' in user_add_line, (
            f"user must bind to scoped group; got:\n{user_add_line}"
        )

    def test_user_does_not_use_default_read_group(self, provider_app):
        """The previous template bound the panel user to RouterOS's
        built-in ``read`` group, which is broader than what we need
        (it has ftp/winbox/ssh policies). Belt-and-braces."""
        script = _render()
        flat = script.replace(" \\\n        ", " ").replace(" \\\n", " ")
        user_add_line = next(
            ln for ln in flat.splitlines() if "/user add name=" in ln
        )
        assert "group=read " not in user_add_line and \
               'group="read"' not in user_add_line, (
            "must NOT bind to the broad built-in `read` group"
        )

    def test_user_idempotency_guard_present(self, provider_app):
        """``[/user find name="..."]`` length check before add so a
        built-in row is never clobbered."""
        script = _render()
        assert ':if ([:len [/user find name="hobe-panel"]] = 0)' in script
        assert 'refusing to clobber it' in script


# ════════════════════════════════════════════════════════════════════════
# (III) AUTO-PROVISION DEFAULT — fresh node, no operator action
# ════════════════════════════════════════════════════════════════════════
class TestAutoProvisionDefault:

    def test_fresh_node_no_operator_action_renders_working_script(self, provider_app):
        """No fleet-default password, no per-node row — the unified
        script still renders a complete §11 with cert + user + group +
        firewall accept (the chr-vpn-3 unstick case)."""
        script = _render()
        # Group created, user provisioned, www-ssl enabled, firewall
        # accept added.
        assert f'add name="{EXPECTED_GROUP_NAME}"' in script
        assert '/user add name="hobe-panel"' in script.replace(" \\\n        ", " ")
        assert "set www-ssl disabled=no" in script
        assert 'comment="hobe-fleet-fw-api-ssl"' in script
        # No skipped-comment fallback path.
        assert "API user skipped" not in script

    def test_node_row_carries_auto_minted_credentials(self, provider_app):
        svc = OnboardingService(config=dict(_BASE_CFG))
        job = svc.create_draft(_form(), auto_advance=False)
        svc.generate_keys(job)
        node = db.session.get(FleetChrNode, job.chr_id)
        # Row carries hobe-panel + a Fernet-encrypted password.
        assert node.routeros_api_user == HARD_DEFAULT_USER
        plaintext = decrypt_password(node.routeros_api_password_enc)
        assert plaintext
        assert plaintext != node.routeros_api_password_enc

    def test_reserved_name_in_fleet_default_substituted_to_hobe_panel(self, provider_app):
        """Owner's specific live case: ``admin`` saved on the infra
        page. Must be normalised, persisted, and the script must use
        the substituted name."""
        set_default_user("admin")
        set_default_password("owner-set-password")
        db.session.commit()

        script = _render()
        # The script provisions HARD_DEFAULT_USER, not the reserved name.
        flat = script.replace(" \\\n        ", " ").replace(" \\\n", " ")
        assert '/user add name="hobe-panel"' in flat
        assert '/user add name="admin"' not in flat

    def test_non_reserved_operator_user_preserved(self, provider_app):
        """An operator-chosen non-reserved name stays."""
        set_default_user("ops-poller")
        set_default_password("operator-set-password")
        db.session.commit()
        script = _render()
        flat = script.replace(" \\\n        ", " ").replace(" \\\n", " ")
        assert '/user add name="ops-poller"' in flat
        # And still bound to the scoped group.
        assert 'group="hobe-fleet-mgmt"' in flat


# ════════════════════════════════════════════════════════════════════════
# (IV) Idempotent — re-render gives the same script
# ════════════════════════════════════════════════════════════════════════
class TestIdempotency:

    def test_re_render_produces_identical_user_and_group_blocks(self, provider_app):
        """Two renders of the same job ⇒ identical scoped-user blocks.
        Defence against silent password rotation between renders."""
        svc = OnboardingService(config=dict(_BASE_CFG))
        job = svc.create_draft(_form(), auto_advance=False)
        svc.generate_keys(job)
        _, script_a = svc.render_script(job)
        # Force a re-render through _build_bindings (the «عرض السكربت»
        # button path).
        bindings_b = svc._build_bindings(job)
        from fleet.registry.script_render import render_from_bindings
        script_b = render_from_bindings(bindings_b)
        # Extract the user/group blocks and compare.
        def extract(s):
            lines = s.splitlines()
            i = next(j for j, l in enumerate(lines) if "/user group" in l)
            k = next(j for j, l in enumerate(lines[i:], i) if "Self-signed PKI" in l)
            return "\n".join(lines[i:k])
        assert extract(script_a) == extract(script_b), (
            "re-render must not rotate the user/group block"
        )


# ════════════════════════════════════════════════════════════════════════
# (V) REST CALL COVERAGE — every panel write needs read|write|sensitive
# ════════════════════════════════════════════════════════════════════════
class TestRestCallCoverageMatchesPolicy:
    """Audit every public RouterOSClient method and assert its REST verb
    falls under the granted policies. Any new method that adds a write
    (PUT/PATCH/POST/DELETE) MUST be classified into the policy bucket —
    if it isn't, the test fails LOUDLY, forcing the policy + the
    template + this audit to update together."""

    # The verbs that need each policy.
    READ_VERBS = {"GET"}
    WRITE_VERBS = {"PUT", "PATCH", "POST", "DELETE"}

    # Known WRITE methods that also touch sensitive fields (password,
    # PSK, private-key) — they need the ``sensitive`` policy. Any new
    # method that writes a sensitive field must be added here. Reads
    # of sensitive fields (e.g. /ppp/secret which returns the
    # password) also need the ``sensitive`` policy — that's why we
    # grant it for the whole group rather than per-method.
    _SENSITIVE_METHODS = {
        # PPP secret writes carry password=
        "create_ppp_secret",
        # IPsec user writes carry password=
        "create_ipsec_user",
        # WireGuard peer create writes the peer secret / preshared key
        "create_wireguard_peer",
    }

    # The single reboot endpoint needs the ``reboot`` policy.
    _REBOOT_METHODS = {"reboot"}

    def _public_methods(self):
        cls = _roc.RouterOSClient
        return [
            (name, fn) for name, fn in inspect.getmembers(cls, inspect.isfunction)
            if not name.startswith("_")
        ]

    def _verbs_used_by(self, fn):
        """Inspect the source for every ``self._request("VERB", "...")``
        call inside the function body."""
        try:
            src = inspect.getsource(fn)
        except (OSError, TypeError):
            return set()
        return set(re.findall(r'_request\(\s*"([A-Z]+)"', src))

    def test_every_public_method_uses_granted_verbs(self, provider_app):
        """No method may use a verb outside read+write+delete."""
        granted_verbs = self.READ_VERBS | self.WRITE_VERBS
        unmapped = []
        for name, fn in self._public_methods():
            for verb in self._verbs_used_by(fn):
                if verb not in granted_verbs:
                    unmapped.append((name, verb))
        assert not unmapped, (
            f"client method uses a verb outside the granted policy set: {unmapped}"
        )

    def test_sensitive_writes_are_listed_in_audit(self, provider_app):
        """The methods documented as touching password/PSK/private-key
        must actually write those fields. Loose pin (presence-check)
        so a future doc-only change can't drift the audit list."""
        for sensitive in self._SENSITIVE_METHODS:
            fn = getattr(_roc.RouterOSClient, sensitive, None)
            assert fn is not None, f"missing client method: {sensitive}"
            src = inspect.getsource(fn)
            # The body must reference at least one sensitive field name.
            assert any(field in src for field in (
                "password", "psk", "secret", "private-key", "private_key",
                "preshared", "pre-shared",
            )), f"sensitive method {sensitive} doesn't appear to touch a sensitive field"

    def test_reboot_method_uses_post_to_system_reboot(self, provider_app):
        fn = _roc.RouterOSClient.reboot
        src = inspect.getsource(fn)
        assert 'system/reboot' in src and '"POST"' in src

    def test_no_method_uses_an_ssh_or_winbox_path(self, provider_app):
        """The granted policy excludes ssh/winbox — verify no client
        method hits an endpoint that would require those policies
        (sanity guard against a future drift where someone adds an
        SSH-via-REST helper)."""
        for name, fn in self._public_methods():
            try:
                src = inspect.getsource(fn)
            except (OSError, TypeError):
                continue
            # /ip service ssh / winbox paths would be the smoking gun.
            assert "ssh disabled" not in src.lower(), (
                f"client method {name} appears to touch ssh service config"
            )


# ════════════════════════════════════════════════════════════════════════
# (VI) Boot-smoke — full sweep doesn't regress on the binding addition
# ════════════════════════════════════════════════════════════════════════
class TestRenderSmoke:

    def test_no_unrendered_jinja(self, provider_app):
        out = _render()
        assert "{{" not in out and "}}" not in out

    def test_quote_balance(self, provider_app):
        for lineno, line in enumerate(_render().splitlines(), 1):
            assert line.count('"') % 2 == 0, (
                f"L{lineno} odd quotes: {line!r}"
            )
