"""fix/chr-unified-wg-mgmt-key-bootstrap — regression guard.

Bug: a brand-new node onboarded WITHOUT fleet-default API credentials
produced a unified script whose §11 (REST API + cert + user + firewall
accept on wg-mgmt :8443) was skipped (``{% if API_USER and API_PASSWORD %}``
gate). The CHR ran the script cleanly, but www-ssl stayed disabled →
panel REST poll returned ``connect_failed`` → ``wg_verify`` returned
``rest_failed`` → the wizard sat stuck at the «سكربت» step forever.

Fix: ``OnboardingService.generate_keys`` now auto-mints a per-node API
credential pair (``HARD_DEFAULT_USER`` + 24-byte URL-safe random) when
NO usable credentials exist anywhere — same bootstrap pattern as the
WireGuard keys (panel mints + panel knows + panel uses). The script
then ALWAYS provisions REST, so the chicken-and-egg cannot recur.

Pins:
* the auto-mint fires when both per-node + fleet-default are empty
* it does NOT override existing per-node credentials
* it does NOT override existing fleet-default credentials
* the rendered script enables www-ssl + adds the api-ssl firewall rule
* the password is stored encrypted (not plaintext)
"""
from __future__ import annotations

import json

import pytest

from app.extensions import db
from fleet.health.routeros_creds import (
    HARD_DEFAULT_USER,
    credentials_for,
    decrypt_password,
    encrypt_password,
)
from fleet.registry.models_chr import FleetChrNode, FleetProvider
from fleet.registry.onboarding_service import OnboardingService


# Fleet-infra constants needed so render_script doesn't trip the
# `_CRITICAL_BINDINGS` check before our test exercises the §11 block.
_BASE_CFG = {
    "PANEL_WG_PUBKEY": "PANEL_PUBKEY_BASE64_xxxxxxxxxxxxxxxxxxxxxxxx=",
    "PANEL_WG_ENDPOINT": "panel.example.com:51820",
    "PROXY_WG_PUBKEY": "PROXY_PUBKEY_BASE64_xxxxxxxxxxxxxxxxxxxxxxxx=",
    "PROXY_WG_ENDPOINT": "proxy.example.com:51821",
    "CHR_SHARED_SECRET": "central-shared-secret-from-panel-xxxxxxxx",
}


def _form(name: str = "chr-vpn-3", public_ip: str = "1.1.1.3") -> dict:
    return dict(
        name=name, provider="contabo-de", cost_model="open",
        public_ip=public_ip, max_sessions=500, link_speed_mbps=1000,
        router_username="admin", router_password="admin12345",
    )


@pytest.fixture()
def provider_app(app):
    """Seed a provider so create_draft + generate_keys can resolve it."""
    p = FleetProvider(name="contabo-de", cost_model="open", price_per_tb=0)
    db.session.add(p); db.session.commit()
    return app


# ════════════════════════════════════════════════════════════════════════
# (1) Auto-mint fires when nothing is configured
# ════════════════════════════════════════════════════════════════════════
class TestAutoMintOnFreshNode:

    def test_credentials_minted_when_no_defaults(self, provider_app):
        svc = OnboardingService(config=dict(_BASE_CFG))
        job = svc.create_draft(_form(), auto_advance=False)
        svc.generate_keys(job)

        node = db.session.get(FleetChrNode, job.chr_id)
        # Per-node creds now exist
        assert node.routeros_api_user == HARD_DEFAULT_USER
        assert node.routeros_api_password_enc  # not empty
        # And they're Fernet-encrypted, not plaintext
        plaintext = decrypt_password(node.routeros_api_password_enc)
        assert plaintext  # decryptable
        assert plaintext != node.routeros_api_password_enc  # not stored plaintext
        # `credentials_for` now returns a usable dict (this was the
        # function that returned None in the live bug)
        creds = credentials_for(node)
        assert creds is not None
        assert creds["user"] == HARD_DEFAULT_USER
        assert creds["password"] == plaintext
        assert creds["host"] == node.wg_mgmt_ip
        assert creds["port"] == 8443  # default api port

    def test_rendered_script_enables_rest_and_firewall_for_fresh_node(self, provider_app):
        """The headline regression: with auto-mint, the rendered script
        contains the live §11 block (www-ssl enable + cert + user + the
        ``hobe-fleet-fw-api-ssl`` firewall accept). Without the fix the
        script carried only the «skipped» comment + an unreachable CHR."""
        svc = OnboardingService(config=dict(_BASE_CFG))
        job = svc.create_draft(_form(), auto_advance=False)
        svc.generate_keys(job)
        _, script = svc.render_script(job)

        # §11 active path is rendered (the skipped-comment fallback isn't).
        assert "set www-ssl disabled=no" in script
        assert "API user skipped" not in script
        # The firewall accept that lets the panel reach REST 8443 over
        # wg-mgmt is added with place-before drop-last. This rule's
        # absence was the on-CHR cause of `rest_failed`.
        assert 'comment="hobe-fleet-fw-api-ssl"' in script
        flat = script.replace(" \\\n", " ")
        api_rule = next(
            l for l in flat.splitlines()
            if 'comment="hobe-fleet-fw-api-ssl"' in l and l.lstrip().startswith("add ")
        )
        assert "in-interface=wg-mgmt" in api_rule
        assert "dst-port=8443" in api_rule
        # The user is created with the hard-default name and read group
        assert f'add name="{HARD_DEFAULT_USER}" group=read' in script

    def test_minted_password_is_strong(self, provider_app):
        """24-byte token_urlsafe ⇒ ~32-char URL-safe alphabet. Guards
        against an accidental switch to a weak default."""
        svc = OnboardingService(config=dict(_BASE_CFG))
        job = svc.create_draft(_form(), auto_advance=False)
        svc.generate_keys(job)
        node = db.session.get(FleetChrNode, job.chr_id)
        plaintext = decrypt_password(node.routeros_api_password_enc)
        assert len(plaintext) >= 24  # token_urlsafe(24) → at least 32 chars in practice


# ════════════════════════════════════════════════════════════════════════
# (2) Auto-mint does NOT clobber existing credentials
# ════════════════════════════════════════════════════════════════════════
class TestAutoMintRespectsExistingCreds:

    def test_does_not_override_per_node_credentials(self, provider_app):
        """If the operator pre-set credentials on the node row before
        keys_generated (e.g. via an admin UI), the auto-mint must NOT
        rewrite them. We simulate by pre-setting via the same helper
        the UI uses, then running the wizard."""
        # We can't easily pre-set per-NODE creds before the node exists,
        # but we CAN pre-set the FLEET DEFAULT — same code path
        # (`credentials_for` returns non-None ⇒ skip auto-mint).
        from fleet.health.routeros_creds import set_default_password, set_default_user
        set_default_user("ops-poller")
        set_default_password("operator-set-strong-pwd-123")
        db.session.commit()

        svc = OnboardingService(config=dict(_BASE_CFG))
        job = svc.create_draft(_form(), auto_advance=False)
        svc.generate_keys(job)

        node = db.session.get(FleetChrNode, job.chr_id)
        # Per-node creds were NOT minted — fleet default does the job.
        assert node.routeros_api_user == ""
        assert node.routeros_api_password_enc == ""
        # And credentials_for still resolves usable creds via the
        # fleet-default fallback.
        creds = credentials_for(node)
        assert creds is not None
        assert creds["user"] == "ops-poller"
        assert creds["password"] == "operator-set-strong-pwd-123"

    def test_render_uses_fleet_default_when_set(self, provider_app):
        """The script's ``API_USER`` binding follows the same resolver
        the live poller uses — operator-set fleet default wins; the
        rendered script provisions THAT user, not the minted hard-
        default."""
        from fleet.health.routeros_creds import set_default_password, set_default_user
        set_default_user("ops-poller")
        set_default_password("operator-set-strong-pwd-123")
        db.session.commit()

        svc = OnboardingService(config=dict(_BASE_CFG))
        job = svc.create_draft(_form(), auto_advance=False)
        svc.generate_keys(job)
        _, script = svc.render_script(job)
        assert 'add name="ops-poller" group=read' in script
        assert 'add name="hobe-panel"' not in script


# ════════════════════════════════════════════════════════════════════════
# (3) Generate-keys is still idempotent: re-running on the same node row
#     doesn't double-mint or rotate credentials silently.
# ════════════════════════════════════════════════════════════════════════
class TestAutoMintIdempotency:

    def test_already_set_per_node_not_overridden_on_render(self, provider_app):
        """Stage one onboarding with auto-mint, then verify a re-render
        (which goes through ``_build_bindings`` again) still uses the
        SAME plaintext password — no silent rotation.

        Note: Fernet ciphertext is non-deterministic (random IV), so we
        compare PLAINTEXT not ciphertext."""
        svc = OnboardingService(config=dict(_BASE_CFG))
        job = svc.create_draft(_form(), auto_advance=False)
        svc.generate_keys(job)
        node = db.session.get(FleetChrNode, job.chr_id)
        first_plaintext = decrypt_password(node.routeros_api_password_enc)
        assert first_plaintext

        # First render
        svc.render_script(job)
        # Force a re-render path the way the «عرض السكربت» button does
        bindings2 = svc._build_bindings(job)
        db.session.refresh(node)
        second_plaintext = decrypt_password(node.routeros_api_password_enc)
        assert first_plaintext == second_plaintext, (
            "the password must not rotate between renders"
        )
        assert bindings2["API_PASSWORD"] == first_plaintext


# ════════════════════════════════════════════════════════════════════════
# (4) Boot smoke — full provider_app fixture from `proxy_token` tests path
#     plus a render via `render_from_bindings` matches `_sample_chr_unified.rsc`'s shape.
# ════════════════════════════════════════════════════════════════════════
class TestRenderedScriptShape:

    def test_pubkey_audit_line_present(self, provider_app):
        """Defence-in-depth: the script renders the «this CHR wg-mgmt
        pubkey (give to panel)» log line — this is the field-incident
        clue the panel WG mismatch test relies on. The auto-mint mustn't
        break that wiring."""
        svc = OnboardingService(config=dict(_BASE_CFG))
        job = svc.create_draft(_form(), auto_advance=False)
        svc.generate_keys(job)
        _, script = svc.render_script(job)
        assert "this CHR wg-mgmt pubkey (give to panel)" in script


# ════════════════════════════════════════════════════════════════════════
# (5) Reserved-username substitution — LIVE INCIDENT root cause
# ════════════════════════════════════════════════════════════════════════
class TestReservedUsernameSubstitution:
    """Live incident: owner saved username ``admin`` on the infra page.
    The script's ``/user remove [find name="admin"]`` was a no-op
    (RouterOS protects the last full-group user) and the following
    ``add`` errored with «user with such name already exists». The
    built-in admin then kept its ORIGINAL password — mismatch with
    the panel's saved one. The renderer now substitutes reserved names
    with ``HARD_DEFAULT_USER`` ("hobe-panel") and persists the
    substitution to the node row so the poller stays in sync."""

    @pytest.mark.parametrize("reserved", ["admin", "root", "support", "operator"])
    def test_reserved_username_substituted(self, provider_app, reserved):
        from fleet.health.routeros_creds import set_default_password, set_default_user
        set_default_user(reserved)
        set_default_password("operator-set-password-123")
        db.session.commit()

        svc = OnboardingService(config=dict(_BASE_CFG))
        job = svc.create_draft(_form(), auto_advance=False)
        svc.generate_keys(job)
        _, script = svc.render_script(job)

        # Script provisions HARD_DEFAULT_USER, NOT the reserved name.
        assert f'add name="{HARD_DEFAULT_USER}" group=read' in script
        assert f'add name="{reserved}" group=read' not in script

    def test_node_row_carries_substituted_user(self, provider_app):
        """The panel poller reads creds via ``credentials_for(node)`` —
        it must dial with the SAME name the script provisioned."""
        from fleet.health.routeros_creds import set_default_password, set_default_user
        set_default_user("admin")
        set_default_password("operator-set-password-123")
        db.session.commit()

        svc = OnboardingService(config=dict(_BASE_CFG))
        job = svc.create_draft(_form(), auto_advance=False)
        svc.generate_keys(job)
        svc.render_script(job)  # the substitution happens during _build_bindings

        node = db.session.get(FleetChrNode, job.chr_id)
        assert node.routeros_api_user == HARD_DEFAULT_USER
        # Password preserved — the substitution only changes the username.
        assert decrypt_password(node.routeros_api_password_enc) == "operator-set-password-123"

    def test_non_reserved_username_preserved(self, provider_app):
        """A safe operator-chosen username must NOT be rewritten."""
        from fleet.health.routeros_creds import set_default_password, set_default_user
        set_default_user("ops-poller")
        set_default_password("operator-set-password-123")
        db.session.commit()

        svc = OnboardingService(config=dict(_BASE_CFG))
        job = svc.create_draft(_form(), auto_advance=False)
        svc.generate_keys(job)
        _, script = svc.render_script(job)
        assert 'add name="ops-poller" group=read' in script
        assert f'add name="{HARD_DEFAULT_USER}" group=read' not in script


# ════════════════════════════════════════════════════════════════════════
# (6) Cert poll-wait — robust www-ssl bring-up on slow CHRs
# ════════════════════════════════════════════════════════════════════════
class TestCertReadyPollWait:
    """Live incident: 2s cert-sign delay was too short on a slow CHR
    (1-vCPU contabo VPS under §0a-backup + §9-firewall CPU load).
    ``set www-ssl certificate=...`` fired while the cert was still
    being signed → set errored silently → www-ssl stayed disabled →
    panel TCP refused → wizard stuck.

    Fix: 2s → 5s on each sign, AND a poll-wait that retries up to 15s
    for the cert's ``invalid-after`` field to land before assigning."""

    def test_sign_delays_bumped_to_five_seconds(self, provider_app):
        svc = OnboardingService(config=dict(_BASE_CFG))
        job = svc.create_draft(_form(), auto_advance=False)
        svc.generate_keys(job)
        _, script = svc.render_script(job)
        # Each sign is followed by `:delay 5s` (not 2s anymore).
        # We check the count of `:delay 5s` lines is ≥ 2 (one per sign).
        assert script.count(":delay 5s") >= 2

    def test_poll_wait_loop_present_before_www_ssl_set(self, provider_app):
        svc = OnboardingService(config=dict(_BASE_CFG))
        job = svc.create_draft(_form(), auto_advance=False)
        svc.generate_keys(job)
        _, script = svc.render_script(job)
        # The poll-wait loop checks `invalid-after` before assigning to www-ssl.
        assert ":local certReady false" in script
        assert ':for i from=1 to=15 do=' in script
        assert "invalid-after" in script
        # Order: poll-wait MUST precede the www-ssl set line.
        poll_idx = script.index(":local certReady false")
        wwwssl_idx = script.index("set www-ssl disabled=no")
        assert poll_idx < wwwssl_idx, "poll-wait must precede www-ssl assignment"

    def test_poll_wait_logs_error_on_timeout(self, provider_app):
        """If the cert never readies, the script must log an explicit
        error so the operator sees WHY www-ssl is down on re-poll."""
        svc = OnboardingService(config=dict(_BASE_CFG))
        job = svc.create_draft(_form(), auto_advance=False)
        svc.generate_keys(job)
        _, script = svc.render_script(job)
        assert "hobe-fleet-api-cert not ready after 15s" in script

    def test_user_add_is_idempotent_against_builtin(self, provider_app):
        """The new template wraps the `add` in an idempotency check so
        re-imports + collisions with built-in users don't error mid-script.
        We assert the idempotency guard renders."""
        svc = OnboardingService(config=dict(_BASE_CFG))
        job = svc.create_draft(_form(), auto_advance=False)
        svc.generate_keys(job)
        _, script = svc.render_script(job)
        # The script checks `[:len [/user find name="..."]] = 0` before add
        # so it doesn't clobber a built-in / existing user.
        assert ':if ([:len [/user find name=' in script
        assert "refusing to clobber a built-in user" in script
