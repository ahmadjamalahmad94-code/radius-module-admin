"""Live-metrics wire-bug regressions (fix/fleet-metrics-wire-bugs).

The first live CHR install hit a stacked failure on the «اقرأ المقاييس
الآن» button: panel got ``connect_failed`` because the unified CHR
script (a) enabled the wrong RouterOS service (binary ``api-ssl`` while
the panel collector speaks REST), (b) didn't assign a TLS certificate
(so the listener never bound), (c) set the service ACL to the CHR's
OWN IP (blocking the panel), and (d) addressed wg-mgmt as ``/32`` (so
the SYN-ACK had no return route back over wg-mgmt to the panel).

This module pins all four invariants down on a freshly rendered script
so we can't silently regress to the broken shapes. The matching diff
ships next to it in ``fleet/registry/templates/chr_unified.rsc.j2``
§11 and ``fleet/registry/onboarding_service.py:667-669``.
"""
from __future__ import annotations

import re

from fleet.registry.script_render import (
    ChrKeyMaterial,
    RouterosTemplateConfig,
    render_chr_script,
)


# ────────────────────────── fixtures ──────────────────────────


class _N:
    """Minimal FleetChrNode duck for the renderer."""
    name = "chr-vpn-1"
    public_ip = "178.105.244.112"


def _render_full() -> str:
    """A render with API_USER + API_PASSWORD set — exercises §11."""
    cfg = RouterosTemplateConfig(
        panel_wg_pubkey="P" * 43 + "=",
        panel_wg_endpoint="panel.hoberadius.com:51820",
        panel_wg_addr="10.99.0.1",
        proxy_wg_pubkey="Q" * 43 + "=",
        proxy_wg_endpoint="proxy.hoberadius.com:51821",
        proxy_wg_addr="10.98.0.1",
        chr_shared_secret="radsecret",
        api_user="hobe-panel",
        api_password="ApiP@ss!",
        api_port=8443,
    )
    keys = ChrKeyMaterial(
        mgmt_privkey="MGMT==",
        # /24 — the post-fix shape. Renderers / fixtures that still
        # pass /32 will fail this test's mask assertion below, which is
        # exactly the signal we want on a regression.
        mgmt_addr="10.99.0.11/24",
        data_privkey="DATA==",
        data_addr="10.98.0.11/24",
    )
    return render_chr_script(_N(), keys, cfg)


def _render_no_creds() -> str:
    """Same shape but with API_USER + API_PASSWORD blank — §11 is skipped."""
    cfg = RouterosTemplateConfig(
        panel_wg_pubkey="P" * 43 + "=",
        panel_wg_endpoint="panel.hoberadius.com:51820",
        panel_wg_addr="10.99.0.1",
        proxy_wg_pubkey="Q" * 43 + "=",
        proxy_wg_endpoint="proxy.hoberadius.com:51821",
        proxy_wg_addr="10.98.0.1",
        chr_shared_secret="radsecret",
        api_user="", api_password="", api_port=8443,
    )
    keys = ChrKeyMaterial(
        mgmt_privkey="MGMT==", mgmt_addr="10.99.0.11/24",
        data_privkey="DATA==", data_addr="10.98.0.11/24",
    )
    return render_chr_script(_N(), keys, cfg)


# ─────────────────── (a) wg-mgmt /24 — no /32 anywhere ───────────────────


def test_wg_mgmt_address_uses_slash_24_not_32():
    script = _render_full()
    assert "add interface=wg-mgmt address=10.99.0.11/24" in script
    # The /32 shape is the field-failing form: it must NOT appear on the
    # wg-mgmt address line. Allowed-address+ACL lines may still carry
    # /32 (those are filters, not interface addresses), so we anchor on
    # the `add interface=wg-mgmt address=` prefix.
    assert "add interface=wg-mgmt address=10.99.0.11/32" not in script


def test_wg_data_address_uses_slash_24_not_32():
    script = _render_full()
    assert "add interface=wg-data address=10.98.0.11/24" in script
    assert "add interface=wg-data address=10.98.0.11/32" not in script


# ─────────────────── (b) www-ssl is the service — NOT api-ssl ───────────────────


def test_metrics_service_is_www_ssl_not_api_ssl():
    """The panel collector speaks REST (https://host:port/rest/…); the
    matching RouterOS service is ``www-ssl``. ``api-ssl`` is the binary
    line-word protocol and is incompatible with the panel's urllib REST
    client.

    We assert against the active CONFIG LINES — substrings appear in
    the §11 explanatory comment block where they document the previous
    (buggy) shape for an operator reading the script.
    """
    script = _render_full()
    config_lines = [
        l for l in script.splitlines()
        if l.strip().startswith("set ") and not l.lstrip().startswith("#")
    ]
    # The www-ssl config line must enable the service.
    assert any(
        "set www-ssl disabled=no" in l for l in config_lines
    ), "www-ssl must be enabled as the live-metrics service"
    # Explicit kill switches on the three services we DO NOT use.
    assert any("set api " in l and "disabled=yes" in l for l in config_lines)
    assert any("set api-ssl " in l and "disabled=yes" in l for l in config_lines)
    assert any("set www " in l and "disabled=yes" in l for l in config_lines)
    # No CONFIG line enables api-ssl or api.
    assert not any(
        "set api-ssl" in l and "disabled=no" in l for l in config_lines
    ), "api-ssl must remain disabled (it's the binary protocol)"
    assert not any(
        re.match(r"\s*set api\s+disabled=no\b", l) for l in config_lines
    ), "binary api must remain disabled"


# ─────────────────── (c) certificate provisioned + assigned ───────────────────


def test_self_signed_certificate_is_provisioned():
    """RouterOS refuses to bind www-ssl without ``certificate=…``. The
    script must create + sign a self-signed cert so the listener opens."""
    script = _render_full()
    # Cleanup + create + sign — idempotent re-imports replace the cert.
    assert 'remove [find name="hobe-fleet-api-cert"]' in script
    assert "add name=hobe-fleet-api-cert" in script
    assert "common-name=hobe-fleet-api" in script
    assert "key-usage=tls-server" in script
    assert "sign hobe-fleet-api-cert" in script


def test_www_ssl_service_assigns_the_cert():
    script = _render_full()
    # The same /ip service line that enables www-ssl must reference the
    # cert; an enabled service with certificate=<empty> will not bind.
    line = next(
        l for l in script.splitlines() if "set www-ssl disabled=no" in l
    )
    # The set line may continue with backslash — pull both halves.
    idx = script.index(line)
    chunk = script[idx : idx + 400]
    assert "certificate=hobe-fleet-api-cert" in chunk


# ─────────────────── (d) ACL filters the PANEL IP, not the CHR's own ───────────────────


def test_service_address_acl_is_panel_ip_not_chr_ip():
    """``/ip service ... address=`` is a SOURCE-IP filter. Pre-fix it
    was set to the CHR's own wg-mgmt address (10.99.0.11/32) which
    filters every connection that did NOT come from the CHR itself —
    i.e. the panel at 10.99.0.1 was filtered out."""
    script = _render_full()
    line = next(
        l for l in script.splitlines() if "set www-ssl disabled=no" in l
    )
    idx = script.index(line)
    chunk = script[idx : idx + 400]
    # Correct: filter source = PANEL_WG_ADDR (10.99.0.1) /32.
    assert "address=10.99.0.1/32" in chunk
    # WRONG: the CHR's own wg-mgmt IP must NOT appear as the ACL value
    # on the www-ssl set-line.
    assert "address=10.99.0.11" not in chunk
    assert "address=10.99.0.11/32" not in script  # not anywhere on the ACL


# ─────────────────── §11 is correctly gated on creds ───────────────────


def test_section_11_skipped_cleanly_when_creds_blank():
    script = _render_no_creds()
    assert "hobe-fleet-api-readonly" not in script
    # The active "set www-ssl disabled=no port=..." config line is gone.
    # We deliberately don't search for the bare "disabled=no" substring
    # because the §11 header comment block reproduces config snippets in
    # text form for the operator audit trail.
    assert "set www-ssl disabled=no port=" not in script
    assert "add name=hobe-fleet-api-cert" not in script
    assert "sign hobe-fleet-api-cert" not in script
    # Operator hint preserved.
    assert "Live-metrics API user skipped" in script


# ─────────────────── firewall rule still scopes to wg-mgmt ───────────────────


def test_firewall_rule_only_accepts_on_wg_mgmt():
    script = _render_full()
    # The api-port firewall rule must be wg-mgmt-only — never on WAN.
    assert (
        "in-interface=wg-mgmt protocol=tcp dst-port=8443" in script
    )
    # And it carries its hobe-fleet comment so the idempotent remove
    # block strips it on re-import.
    assert 'comment="hobe-fleet-fw-api-ssl"' in script
