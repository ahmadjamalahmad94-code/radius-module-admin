"""fix/fleet-endpoint-resolve — assert the generated .rsc bootstraps DNS,
tags both WireGuard peers with stable comments, and explicitly :resolve's
each peer host into an IP literal that's then written back to the peer's
endpoint-address.

Field finding the script must close: even with the host-only endpoint-
address fix (fix/fleet-endpoint-and-idempotency), the wg-data peer on a
real CHR landed with ``current-endpoint-address=""`` and never handshaked
when given ``endpoint-address=proxy.hoberadius.com``. Replacing with the
resolved IP literal (``178.105.251.67``) handshaked instantly. RouterOS
does not always resolve peer hostnames at peer-add time. So the script
does the resolve itself, with retry, and writes the IP back.
"""
from __future__ import annotations

import re

from fleet.registry.script_render import render_from_bindings


_BINDINGS = {
    "ROUTER_IDENTITY":    "chr-vpn-1",
    "CHR_PUBLIC_IP":      "178.105.244.112",
    "WAN_IFACE":          "ether1",
    "WG_MGMT_PRIVKEY":    "MGMT_PRIVKEY_BASE64==",
    "WG_MGMT_ADDR":       "10.99.0.11/24",
    "WG_DATA_PRIVKEY":    "DATA_PRIVKEY_BASE64==",
    "WG_DATA_ADDR":       "10.98.0.11/24",
    "WG_DATA_ADDR_IP":    "10.98.0.11",
    "PANEL_WG_PUBKEY":    "PANELPUBKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "PANEL_WG_ENDPOINT":  "control.hoberadius.com:51820",
    "PANEL_WG_ADDR":      "10.99.0.1",
    "PROXY_WG_PUBKEY":    "PROXYPUBKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQM=",
    "PROXY_WG_ENDPOINT":  "proxy.hoberadius.com:51821",
    "PROXY_WG_ADDR":      "10.98.0.1",
    "CHR_SHARED_SECRET":  "kla0FAzDKNJGoGIXdpDaCKB4Q2ytm-txZZZ_strongsecret",
    "SSTP_CERT_NAME":     "vpn-cert",
    "IKE_CERT_NAME":      "ike-cert",
    "CLIENT_SUPERNET":    "10.0.0.0/8",
    "DNS_PUSH":           "1.1.1.1",
    "GW_LOCAL_ADDR":      "10.10.0.1",
}


def _render(**overrides):
    return render_from_bindings({**_BINDINGS, **overrides})


# ─── DNS bootstrap — set only if not already set ───────────────────────────

def test_dns_bootstrap_is_conditional_on_empty_list():
    """The script must NOT clobber operator-set DNS — only fill in when
    /ip dns get servers is empty."""
    script = _render()
    # The bootstrap line + its conditional must both be present.
    assert ":if ([:len [/ip dns get servers]] = 0)" in script, (
        "missing DNS-not-set conditional — script could clobber operator DNS"
    )
    assert "/ip dns set servers=1.1.1.1,8.8.8.8" in script, (
        "missing fallback DNS bootstrap"
    )
    # And the bootstrap must be guarded inside the conditional `do={ ... }`
    # block — not running unconditionally. Cheap check: the DNS set line
    # must follow the :if on a later line.
    lines = script.splitlines()
    if_idx = next(i for i, l in enumerate(lines) if ":if ([:len [/ip dns get servers]] = 0)" in l)
    set_idx = next(i for i, l in enumerate(lines) if "/ip dns set servers=" in l)
    assert set_idx > if_idx, (
        "DNS set must be inside the conditional, not before it"
    )


def test_dns_bootstrap_runs_before_resolve():
    """The DNS bootstrap MUST happen before :resolve is invoked, otherwise
    a fresh CHR with no DNS configured can't resolve the proxy host."""
    script = _render()
    dns_idx = script.index("/ip dns set servers=")
    # Match `[:resolve` — the executable form — to avoid matching the word
    # `:resolve` that appears in section-header comments.
    resolve_idx = script.index("[:resolve")
    assert dns_idx < resolve_idx, (
        "DNS bootstrap must precede :resolve calls"
    )


# ─── Peer comments — required so :resolve set [find comment=…] can target ──

def test_wg_mgmt_peer_carries_hobe_fleet_mgmt_comment():
    """The mgmt peer must carry ``comment="hobe-fleet-mgmt"`` so the
    resolve block can target it with `find comment="…"`."""
    script = _render()
    flat = script.replace(" \\\n", " ")
    line = next(l for l in flat.splitlines() if "add interface=wg-mgmt" in l)
    assert 'comment="hobe-fleet-mgmt"' in line, (
        f"wg-mgmt peer add is missing the comment tag: {line!r}"
    )


def test_wg_data_peer_carries_hobe_fleet_data_comment():
    """Same for the data peer."""
    script = _render()
    flat = script.replace(" \\\n", " ")
    line = next(l for l in flat.splitlines() if "add interface=wg-data" in l)
    assert 'comment="hobe-fleet-data"' in line, (
        f"wg-data peer add is missing the comment tag: {line!r}"
    )


# ─── :resolve override is present, has retry, targets both peers ───────────

def test_resolve_helper_with_retry_loop():
    """The script must define a resolver helper that retries on error and
    has a 2-second back-off — RouterOS can be slow to bring DNS up after
    boot and the import can race the WAN."""
    script = _render()
    # The helper definition and the retry loop with on-error + :delay.
    assert ":local hobeResolve do={" in script, "missing hobeResolve helper"
    assert ":for i from=1 to=5 do={" in script, "missing retry loop"
    assert "on-error={" in script, "missing on-error branch in retry"
    assert ":delay 2s" in script, "missing 2s back-off between retries"


def test_resolve_sets_endpoint_address_on_both_peers():
    """The script MUST set endpoint-address on BOTH peers using the
    resolved IP variables.

    Since fix/fleet-wireguard-provisioning (BUG A) the per-peer
    ``set`` is wrapped in a ``hobeSetEndpoint`` function so we never
    write an empty value -- a wrapper invocation per peer is the
    equivalent contract.
    """
    script = _render()
    # The wrapper invocation: $hobeSetEndpoint "<comment>" $ip <port> "<fallback>"
    assert '$hobeSetEndpoint "hobe-fleet-mgmt" $panelIP' in script, (
        "missing $hobeSetEndpoint wrapper for the wg-mgmt peer"
    )
    assert '$hobeSetEndpoint "hobe-fleet-data" $proxyIP' in script, (
        "missing $hobeSetEndpoint wrapper for the wg-data peer"
    )
    # And the wrapper itself MUST contain `endpoint-address=` somewhere
    # (else it isn't actually setting anything).
    assert "endpoint-address=$clean" in script, (
        "hobeSetEndpoint must set endpoint-address=$clean when resolve succeeds"
    )


def test_resolve_called_on_both_panel_and_proxy_hosts():
    """The resolver helper must be invoked once per peer host so each gets
    its own resolved IP variable."""
    script = _render(
        PANEL_WG_ENDPOINT="control.hoberadius.com:51820",
        PROXY_WG_ENDPOINT="proxy.hoberadius.com:51821",
    )
    assert ':local panelIP [$hobeResolve "control.hoberadius.com"]' in script, (
        "panel host not piped through hobeResolve"
    )
    assert ':local proxyIP [$hobeResolve "proxy.hoberadius.com"]' in script, (
        "proxy host not piped through hobeResolve"
    )


def test_resolve_uses_per_plane_port_in_set():
    """The wrapper invocation MUST pass the per-plane port (PANEL=51820 /
    PROXY=51821 or operator-chosen override) -- not a stale hardcoded
    value. The signature is `$hobeSetEndpoint "<comment>" $ip <port>
    "<fallback>"`, so we assert the port literal lands as the third
    argument on each call.
    """
    script = _render(
        PANEL_WG_ENDPOINT="control.hoberadius.com:9999",
        PROXY_WG_ENDPOINT="proxy.hoberadius.com:8888",
    )
    mgmt = next(
        l for l in script.splitlines()
        if '$hobeSetEndpoint "hobe-fleet-mgmt"' in l
    )
    data = next(
        l for l in script.splitlines()
        if '$hobeSetEndpoint "hobe-fleet-data"' in l
    )
    # arg-3 is the port (panelIP / proxyIP is arg-2).
    assert " 9999 " in mgmt, mgmt
    assert " 8888 " in data, data


# ─── Belt-and-braces ────────────────────────────────────────────────────────

def test_no_colon_port_anywhere_in_endpoint_address_even_after_resolve():
    """Belt-and-braces from the prior fix: no `endpoint-address` line in the
    script may carry a colon. The resolve `set` lines refer to $panelIP /
    $proxyIP variables which themselves are bare IPs from :resolve, so no
    colon should ever appear at render time."""
    script = _render()
    flat = script.replace(" \\\n", " ")
    for lineno, line in enumerate(flat.splitlines(), start=1):
        for m in re.finditer(r"endpoint-address=(\S+)", line):
            addr = m.group(1)
            assert ":" not in addr, (
                f"L{lineno}: endpoint-address contains colon: {addr!r}"
            )


def test_set_block_runs_after_both_peers_exist():
    """Logical order: both `add interface=wg-mgmt` and `add interface=wg-data`
    must appear before the `$hobeSetEndpoint` calls. Otherwise the
    wrapper's `find comment=...` returns empty and the set is a no-op.
    """
    script = _render()
    flat = script.replace(" \\\n", " ")
    lines = flat.splitlines()

    def first(needle: str) -> int:
        for i, l in enumerate(lines):
            if needle in l:
                return i
        return -1

    mgmt_add  = first('add interface=wg-mgmt ')
    data_add  = first('add interface=wg-data ')
    mgmt_set  = first('$hobeSetEndpoint "hobe-fleet-mgmt" $panelIP')
    data_set  = first('$hobeSetEndpoint "hobe-fleet-data" $proxyIP')

    assert mgmt_add >= 0 and data_add >= 0
    assert mgmt_set >= 0 and data_set >= 0
    assert mgmt_set > mgmt_add, (
        f"mgmt wrapper (line {mgmt_set}) must come after `add` (line {mgmt_add})"
    )
    assert data_set > data_add, (
        f"data wrapper (line {data_set}) must come after `add` (line {data_add})"
    )
