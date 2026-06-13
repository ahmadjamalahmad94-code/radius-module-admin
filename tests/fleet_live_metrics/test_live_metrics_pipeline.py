"""Fleet live-metrics pipeline — end-to-end without the network.

Walks the whole new pipeline against a mocked RouterOS client and asserts
the dashboard surfaces real numbers instead of «لا توجد قياسات»:

  1. Per-CHR API credentials store / retrieve / mask (encrypted at rest).
  2. ``routeros_collector.collect`` aggregates resource + sessions + WAN
     bytes into a single :class:`Sample`, skipping a missing field
     instead of crashing the call.
  3. ``metrics_poller.poll_all`` writes one ``fleet_chr_metrics`` row
     per node with ``source='control'`` AND degrades to "skip" when the
     node has no credentials yet.
  4. ``fleet.ui.dashboard_data.build_node_views`` PICKS the control
     metric for the load chips even when a more recent ``source='ping'``
     row exists (the live-deploy bug we're fixing).
  5. The unified RouterOS script provisions ``/user`` + ``/ip service
     api-ssl`` + a firewall rule on the wg-mgmt interface only when both
     API_USER and API_PASSWORD bindings are populated.
  6. The onboarding service writes the API user + encrypted password
     onto ``fleet_chr_nodes`` at ``script_generated`` time, so the
     poller can decrypt and use it next cycle.
"""
from __future__ import annotations

import dataclasses
from datetime import datetime, timedelta

import pytest

from app.extensions import db
from app.models import Setting

from fleet.health.metrics_poller import poll_all
from fleet.health.models_health import FleetChrMetric
from fleet.health.routeros_collector import Sample, collect
from fleet.health.routeros_creds import (
    DEFAULT_PASSWORD_SETTING_KEY,
    DEFAULT_USER_SETTING_KEY,
    HARD_DEFAULT_USER,
    credentials_for,
    decrypt_password,
    encrypt_password,
    set_credentials,
    set_default_password,
    set_default_user,
)
from fleet.registry.models_chr import FleetChrNode, FleetProvider
from fleet.registry.script_render import (
    RouterosTemplateConfig,
    ChrKeyMaterial,
    render_chr_script,
)
from fleet.ui.dashboard_data import build_node_views


# ════════════════════════════════════════════════════════════════════════
# Fixtures
# ════════════════════════════════════════════════════════════════════════


_NODE_SEQ: list[int] = [0]


def _provider() -> FleetProvider:
    p = FleetProvider.query.first()
    if p is not None:
        return p
    p = FleetProvider(
        name="acme-lm", cost_model="open", price_per_tb=0,
        overage_allowed=False, billing_cycle_day=1,
    )
    db.session.add(p); db.session.commit()
    return p


def _node(**overrides) -> FleetChrNode:
    _NODE_SEQ[0] += 1
    h = _NODE_SEQ[0]
    base = dict(
        provider_id=_provider().id,
        name=f"chr-lm-{h}",
        public_ip=f"178.105.244.{50 + h}",
        wg_mgmt_ip=f"10.99.0.{10 + h}",
        wg_mgmt_pubkey="x" * 44,
        routeros_api_port=8443,
        max_sessions=500, link_speed_mbps=1000,
        weight=1.0, enabled=True, drain=False,
        status="provisioning",
        cpu_pct=None, active_sessions=0,
    )
    base.update(overrides)
    n = FleetChrNode(**base)
    db.session.add(n); db.session.commit()
    return n


# ════════════════════════════════════════════════════════════════════════
# 1. Credentials store
# ════════════════════════════════════════════════════════════════════════


def test_set_credentials_encrypts_and_roundtrips(app):
    n = _node()
    set_credentials(n, username="hobe-panel", password="s3cret!live!")
    db.session.commit()
    # Encrypted at rest — plaintext is not on the row.
    assert "s3cret" not in (n.routeros_api_password_enc or "")
    creds = credentials_for(n)
    assert creds is not None
    assert creds["user"] == "hobe-panel"
    assert creds["password"] == "s3cret!live!"
    assert creds["host"] == n.wg_mgmt_ip
    assert creds["port"] == 8443


def test_credentials_none_when_no_password(app):
    n = _node()
    # No per-node password, no fleet default → poller skips.
    assert credentials_for(n) is None


def test_fleet_default_credentials_used_when_node_blank(app):
    set_default_user("fleet-default-user")
    set_default_password("fleet-default-pwd")
    db.session.commit()
    n = _node()
    creds = credentials_for(n)
    assert creds is not None
    assert creds["user"] == "fleet-default-user"
    assert creds["password"] == "fleet-default-pwd"


def test_per_node_override_beats_fleet_default(app):
    set_default_user("fleet-user")
    set_default_password("fleet-pwd")
    db.session.commit()
    n = _node()
    set_credentials(n, username="per-node-user", password="per-node-pwd")
    db.session.commit()
    creds = credentials_for(n)
    assert creds is not None
    assert creds["user"] == "per-node-user"
    assert creds["password"] == "per-node-pwd"


# ════════════════════════════════════════════════════════════════════════
# 2. Collector aggregates the RouterOS reads
# ════════════════════════════════════════════════════════════════════════


class _FakeClient:
    """Stub that returns scripted shapes that mirror RouterOS REST replies."""

    def __init__(self, *, resource: dict, ppp_active: list,
                 ipsec_active: list, interfaces: list):
        self._resource = resource
        self._ppp = ppp_active
        self._ipsec = ipsec_active
        self._ifaces = interfaces

    def system_resource(self):
        return self._resource

    def list_ppp_active(self):
        return list(self._ppp)

    def list_ipsec_active_peers(self):
        return list(self._ipsec)

    def list_interfaces(self):
        return list(self._ifaces)


def _factory(*, resource=None, ppp=None, ipsec=None, ifaces=None):
    def _make(*, host, port, user, password, timeout):
        return _FakeClient(
            resource=resource or {},
            ppp_active=ppp or [],
            ipsec_active=ipsec or [],
            interfaces=ifaces or [],
        )
    return _make


def test_collector_returns_full_sample(app):
    n = _node()
    set_credentials(n, username="hobe-panel", password="x"); db.session.commit()
    fact = _factory(
        resource={"cpu-load": "37",
                  "total-memory": 1_000_000_000,
                  "free-memory": 600_000_000,
                  "uptime": "1d2h3m"},
        ppp=[{"name": "u1"}, {"name": "u2"}],
        ipsec=[{"name": "u3"}],
        ifaces=[{"name": "ether1", "rx-byte": 12_345_678,
                 "tx-byte": 9_876_543}],
    )
    s = collect(n, client_factory=fact)
    assert s.ok
    assert s.cpu_pct == 37.0
    assert s.mem_pct == 40.0           # (1 - 0.6) * 100
    assert s.active_sessions == 3
    assert s.rx_bytes == 12_345_678
    assert s.tx_bytes == 9_876_543
    assert s.uptime == "1d2h3m"


def test_collector_no_credentials_returns_skip(app):
    n = _node()
    s = collect(n)
    assert not s.ok
    assert s.error == "no_credentials"


def test_collector_routeros_error_does_not_raise(app):
    n = _node()
    set_credentials(n, username="hobe-panel", password="x"); db.session.commit()

    def bad_factory(**kwargs):
        class _Broken:
            def system_resource(self):
                from app.services.routeros_client import RouterOSError
                raise RouterOSError("connect_failed", "down")
        return _Broken()
    s = collect(n, client_factory=bad_factory)
    assert not s.ok
    assert s.error == "connect_failed"


# ════════════════════════════════════════════════════════════════════════
# 3. Poller writes fleet_chr_metrics rows
# ════════════════════════════════════════════════════════════════════════


def test_poll_all_writes_control_metrics(app):
    n1 = _node(name="chr-poll-1")
    n2 = _node(name="chr-poll-2")
    set_credentials(n1, username="hobe-panel", password="x")
    set_credentials(n2, username="hobe-panel", password="x")
    db.session.commit()

    fact = _factory(
        resource={"cpu-load": "12", "total-memory": 100, "free-memory": 70},
        ppp=[{"name": "u"}],
        ipsec=[],
        ifaces=[{"name": "ether1", "rx-byte": 100, "tx-byte": 50}],
    )

    def collector(node):
        return collect(node, client_factory=fact)

    summary = poll_all(collector=collector)
    assert summary.checked == 2
    assert summary.ok_count == 2
    assert summary.error_count == 0

    rows = (
        FleetChrMetric.query
        .filter(FleetChrMetric.source == "control")
        .order_by(FleetChrMetric.chr_id.asc())
        .all()
    )
    assert {r.chr_id for r in rows} == {n1.id, n2.id}
    for r in rows:
        assert float(r.cpu_pct) == 12.0
        assert r.active_sessions == 1
        assert r.rx_bytes == 100
        assert r.tx_bytes == 50
        assert r.source == "control"


def test_poll_all_skips_nodes_without_credentials(app):
    creds_node = _node(name="chr-have-creds")
    nocreds_node = _node(name="chr-no-creds")
    set_credentials(creds_node, username="hobe-panel", password="x")
    db.session.commit()

    fact = _factory(
        resource={"cpu-load": "5"},
        ppp=[], ipsec=[], ifaces=[],
    )

    def collector(node):
        return collect(node, client_factory=fact)

    summary = poll_all(collector=collector)
    assert summary.checked == 2
    assert summary.ok_count == 1
    assert summary.skipped_count == 1
    # Only the credentialed node wrote a control row.
    rows = FleetChrMetric.query.filter_by(source="control").all()
    assert len(rows) == 1
    assert rows[0].chr_id == creds_node.id


def test_poll_all_records_error_but_continues(app):
    good = _node(name="chr-good")
    bad = _node(name="chr-bad")
    set_credentials(good, username="hobe-panel", password="x")
    set_credentials(bad, username="hobe-panel", password="x")
    db.session.commit()

    def collector(node):
        if node.name == "chr-bad":
            return Sample(error="connect_failed")
        return Sample(cpu_pct=20.0, mem_pct=33.0, active_sessions=5,
                      rx_bytes=10, tx_bytes=20)

    summary = poll_all(collector=collector)
    assert summary.ok_count == 1
    assert summary.error_count == 1
    assert ("chr-bad", "connect_failed") in summary.errors


# ════════════════════════════════════════════════════════════════════════
# 4. Dashboard prefers control metric over a fresher ping
# ════════════════════════════════════════════════════════════════════════


def test_dashboard_prefers_control_for_cpu_even_when_ping_is_newer(app):
    n = _node()
    ts_old = datetime(2026, 6, 10, 12, 0, 0)
    ts_new = datetime(2026, 6, 10, 12, 0, 30)
    # Control sample written earlier, ping sample written later.
    db.session.add(FleetChrMetric(
        chr_id=n.id, ts=ts_old, source="control",
        cpu_pct=42, mem_pct=20, active_sessions=8,
        rx_bytes=1000, tx_bytes=2000,
    ))
    db.session.add(FleetChrMetric(
        chr_id=n.id, ts=ts_new, source="ping",
        ping_rtt_ms=12.5, ping_loss_pct=0,
    ))
    db.session.commit()

    views = build_node_views([n])
    m = views[0].metric
    # CPU + sessions + bytes come from the control sample.
    assert m.cpu_pct == 42
    assert m.active_sessions == 8
    assert m.rx_bytes == 1000
    assert m.tx_bytes == 2000
    # Ping RTT comes from the absolute-latest row.
    assert m.ping_rtt_ms == 12.5
    # Timestamp + source reflect where the load chips came from.
    assert m.ts == ts_old
    assert m.source == "control"


def test_dashboard_falls_back_to_ping_only_when_no_control(app):
    n = _node()
    ts = datetime(2026, 6, 10, 13, 0, 0)
    db.session.add(FleetChrMetric(
        chr_id=n.id, ts=ts, source="ping",
        ping_rtt_ms=8.5, ping_loss_pct=0,
    )); db.session.commit()
    m = build_node_views([n])[0].metric
    # No control sample → load chips are None (will render «لا توجد قياسات»)
    # but RTT still surfaces.
    assert m.cpu_pct is None
    assert m.active_sessions is None
    assert m.ping_rtt_ms == 8.5
    assert m.source == "ping"


# ════════════════════════════════════════════════════════════════════════
# 5. The unified RouterOS script provisions the API user when bindings present
# ════════════════════════════════════════════════════════════════════════


def _render(api_user: str, api_password: str, api_port: int = 8443) -> str:
    cfg = RouterosTemplateConfig(
        api_user=api_user, api_password=api_password, api_port=api_port,
    )
    # /24 — the live-metrics wire fix (fix/fleet-metrics-wire-bugs). With
    # /32 the CHR had no connected route back to the panel at 10.99.0.1,
    # so the SYN-ACK from a panel REST call fell to the WAN default route
    # and never returned over wg-mgmt → connect_failed.
    keys = ChrKeyMaterial(
        mgmt_privkey="MGMT==", mgmt_addr="10.99.0.11/24",
        data_privkey="DATA==", data_addr="10.98.0.11/24",
    )

    class _N:
        name = "chr-vpn-1"
        public_ip = "178.105.244.112"
    return render_chr_script(_N(), keys, cfg)


def test_script_provisions_api_user_when_bindings_present():
    """§11 enables www-ssl (REST over HTTPS) — NOT api-ssl (binary).

    Three live-incident assertions baked in (fix/fleet-metrics-wire-bugs):
    1. www-ssl is the enabled service (matches the REST collector at
       app/services/routeros_client.py).
    2. A self-signed cert is created + assigned (RouterOS will not bind
       www-ssl without one).
    3. The source-IP ACL on the service equals the PANEL's wg-mgmt IP
       (10.99.0.1/32), NOT the CHR's own IP.
    """
    script = _render("hobe-panel", "TopSecretP@ss", 8443)
    assert '/user' in script
    assert 'name="hobe-panel"' in script
    # fix/chr-auto-scoped-mgmt-user — the user is no longer attached to
    # the broad built-in `read` group; instead a DEDICATED group
    # `hobe-fleet-mgmt` is provisioned with the exact policy set the
    # panel poller needs, and the user is in that group.
    assert 'group="hobe-fleet-mgmt"' in script
    assert 'password="TopSecretP@ss"' in script
    # Inspect actual CONFIG lines (substrings appear in the §11
    # explanatory comment that documents the previous bug shapes).
    config_lines = [
        l for l in script.splitlines()
        if l.strip().startswith("set ") and not l.lstrip().startswith("#")
    ]
    # (1) www-ssl is the listening service.
    assert any('set www-ssl disabled=no' in l for l in config_lines)
    assert 'port=8443' in script
    assert 'certificate=hobe-fleet-api-cert' in script
    # (2) Cert provisioning + signing — CA-then-leaf (fix/fleet-cert-self-sign).
    # Live bug on chr-vpn-2: `sign <leaf>` without ca= fails «CA not found»
    # on some v7 builds → www-ssl never bound. The leaf MUST be signed by
    # the local CA explicitly.
    assert 'add name=hobe-fleet-ca' in script
    assert 'sign hobe-fleet-ca' in script
    assert 'add name=hobe-fleet-api-cert' in script
    assert 'sign hobe-fleet-api-cert ca=hobe-fleet-ca' in script
    # (3) ACL points at the PANEL's wg-mgmt IP (10.99.0.1/32 default).
    assert 'address=10.99.0.1/32' in script
    # Every other service flavour is OFF — narrow the surface explicitly.
    assert any('set api ' in l and 'disabled=yes' in l for l in config_lines)
    assert any('set api-ssl ' in l and 'disabled=yes' in l for l in config_lines)
    assert any('set www ' in l and 'disabled=yes' in l for l in config_lines)
    # No active enable on api or api-ssl in the config lines.
    assert not any(
        'set api-ssl' in l and 'disabled=no' in l for l in config_lines
    )
    # Firewall rule still scoped to wg-mgmt interface only — the
    # feat/chr-unified-provisioning-complete branch tightened the rule
    # with an extra src-address=PANEL_WG_ADDR/32 ACL between the iface
    # and the dst-port, so we look at the joined-continuation line.
    flat = script.replace(" \\\n", " ")
    api_rule = next(
        (l for l in flat.splitlines()
         if 'comment="hobe-fleet-fw-api-ssl"' in l and l.lstrip().startswith("add ")),
        None,
    )
    assert api_rule, "api-ssl firewall rule missing from script"
    assert "in-interface=wg-mgmt" in api_rule
    assert "protocol=tcp" in api_rule
    assert "dst-port=8443" in api_rule


def test_script_skips_api_block_when_creds_blank():
    script = _render("", "", 8443)
    assert 'hobe-fleet-api-readonly' not in script
    # No live ACTIVE www-ssl enable when the block is skipped. We match
    # the actual config line shape (`set www-ssl disabled=no port=...`),
    # not the substring `disabled=no` which appears in unrelated comment
    # examples of the §11 header.
    assert 'set www-ssl disabled=no port=' not in script
    # Cert provisioning (CA + leaf) is also skipped.
    assert 'add name=hobe-fleet-api-cert' not in script
    assert 'add name=hobe-fleet-ca' not in script
    # The "skipped" comment is present so an operator inspecting the
    # script knows why and where to set the missing values.
    assert 'Live-metrics API user skipped' in script


def test_script_skips_api_block_when_password_blank():
    script = _render("hobe-panel", "", 8443)
    assert 'hobe-fleet-api-readonly' not in script


def test_script_api_user_block_is_idempotent():
    """Re-applying the script must converge for the same name="hobe-panel".

    fix/chr-group-idempotent-no-remove (chr-vpn-3): a `/user remove`
    before `/user add` would fail on a re-import because the row
    already exists AND is in use. The block was rewritten ADD-OR-SET:
    `add` if absent, `set` if present, never `remove`. So on re-import
    the script either creates the user or updates the existing row.
    Re-rendering with the same bindings yields a byte-identical script.
    """
    script = _render("hobe-panel", "x", 8443)
    user_section = script.split('/user', 1)[1]
    # ADD-OR-SET pattern present.
    assert 'add name="hobe-panel"' in user_section, (
        "missing /user add for hobe-panel"
    )
    assert 'set [find name="hobe-panel"' in user_section, (
        "missing /user set fall-through for re-import — without it the "
        "second-run /user add would fail on the duplicate name"
    )
    # And the script renders deterministically.
    assert script == _render("hobe-panel", "x", 8443)


def test_cert_block_is_ca_then_leaf_in_order(app):
    """fix/fleet-cert-self-sign — the exact §11 PKI sequence, in order:

      remove leaf → remove CA → add CA → sign CA → (delay) →
      add leaf → sign leaf ca=CA → (delay) → set www-ssl certificate=leaf

    Live failure on chr-vpn-2 (RouterOS v7): `sign <leaf>` without `ca=`
    errored «CA not found», leaving www-ssl pointed at an unsigned cert
    so the listener never bound. Order matters: the CA must be signed
    BEFORE the leaf references it, and www-ssl must be configured AFTER
    the leaf exists + is signed (the :delay guards async-ish sign builds).
    """
    script = _render("hobe-panel", "x", 8443)

    pos = {
        "rm_leaf": script.index('remove [find name="hobe-fleet-api-cert"]'),
        "rm_ca": script.index('remove [find name="hobe-fleet-ca"]'),
        "add_ca": script.index('add name=hobe-fleet-ca'),
        "sign_ca": script.index('sign hobe-fleet-ca'),
        "add_leaf": script.index('add name=hobe-fleet-api-cert'),
        "sign_leaf": script.index('sign hobe-fleet-api-cert ca=hobe-fleet-ca'),
        "set_wss": script.index('set www-ssl disabled=no'),
    }
    assert pos["rm_leaf"] < pos["rm_ca"] < pos["add_ca"] < pos["sign_ca"] \
        < pos["add_leaf"] < pos["sign_leaf"] < pos["set_wss"]

    # CA template carries CA key-usage; leaf carries a TLS-server profile.
    assert 'key-usage=key-cert-sign,crl-sign' in script
    assert 'key-usage=digital-signature,key-encipherment,tls-server' in script

    # A :delay follows EACH sign before the cert is consumed (async-sign
    # builds) — one between sign-CA and add-leaf, one between sign-leaf
    # and the www-ssl set.
    assert ':delay' in script[pos["sign_ca"]:pos["add_leaf"]]
    assert ':delay' in script[pos["sign_leaf"]:pos["set_wss"]]

    # www-ssl consumes the LEAF (never the CA).
    assert 'certificate=hobe-fleet-api-cert' in script
    assert 'certificate=hobe-fleet-ca' not in script


def test_firewall_rules_anchor_against_drop_last(app):
    """fix/chr-hardening-safe-firewall-order — the move-to-top hoist
    block is gone; the new shape uses a single `hobe-fleet-fw-drop-last`
    anchor added FIRST, and every subsequent accept add uses
    `place-before=[find comment="hobe-fleet-fw-drop-last"]` so the
    on-CHR rule ends up ABOVE the catch-all drop EVEN WHEN FOREIGN
    RULES INTERLEAVE between our adds (the chr-vpn-3 incident).

    This replaces the prior :do/on-error wrappers around `move` calls;
    place-before is idempotent and never errors on «already at the top».
    """
    script = _render("hobe-panel", "x", 8443)
    flat = script.replace(" \\\n", " ")
    # The legacy hoist block must be gone.
    assert "destination=0" not in flat or all(
        ln.lstrip().startswith("#") for ln in flat.splitlines() if "destination=0" in ln
    ), "legacy move-destination=0 hoist still present in code"
    # Every accept must anchor against drop-last via place-before.
    for c in ("hobe-fleet-fw-mgmt", "hobe-fleet-fw-coa", "hobe-fleet-fw-radius"):
        rule = next(
            (ln for ln in flat.splitlines()
             if ln.lstrip().startswith("add ") and f'comment="{c}"' in ln),
            None,
        )
        assert rule, f"missing add for {c}"
        assert 'place-before=[find comment="hobe-fleet-fw-drop-last"]' in rule, (
            f"{c} must anchor against drop-last via place-before "
            f"(otherwise interleaved foreign rules shadow it); got: {rule!r}"
        )


# ════════════════════════════════════════════════════════════════════════
# 6. Onboarding writes the encrypted password to the node row
# ════════════════════════════════════════════════════════════════════════


def test_onboarding_persists_api_password_at_script_generated(app):
    """When ``render_script`` runs with non-empty API bindings the
    plaintext password lands on the node row encrypted, so the poller
    can decrypt + use the very password the script just installed."""
    from fleet.registry.models_onboarding import OnboardingJob
    from fleet.registry.onboarding_service import OnboardingService

    n = _node()
    job = OnboardingJob(status="keys_generated", chr_id=n.id, form_input={})
    job.wg_keypair_ref = '{"mgmt_privkey_ref":"r1","data_privkey_ref":"r2"}'
    db.session.add(job); db.session.commit()

    # Seed the panel-side fleet-constant bindings the validator demands
    # so render_script doesn't bail before our hook runs. The Settings
    # layer's UI-side writer encrypts the shared secret + validates IP
    # shapes; we drop straight into the underlying _raw_set seam so the
    # test stays focused on the live-metrics path.
    from fleet.registry.infra_settings import _raw_set
    _raw_set("PANEL_WG_PUBKEY",  "P" * 44)
    _raw_set("PANEL_WG_ENDPOINT", "control.hoberadius.com:51820")
    _raw_set("PROXY_WG_PUBKEY",  "Q" * 44)
    _raw_set("PROXY_WG_ENDPOINT", "proxy.hoberadius.com:51821")
    # CHR_SHARED_SECRET is read after Fernet-decrypting the Setting; seed
    # an encrypted token through the same encrypt_password wrapper.
    from fleet.health.routeros_creds import encrypt_password
    _raw_set("CHR_SHARED_SECRET", encrypt_password("shared-secret-test"))
    # And the API credentials (the live-metrics defaults).
    set_default_user("hobe-panel")
    set_default_password("OnbProvisionedP@ss")
    db.session.commit()

    # Stub the vault layer so render_script can resolve the WG key refs
    # without standing up the real Fernet pipeline.
    class _StubVault:
        def fetch_secret(self, ref):
            return "VAULTED_KEY=="

    svc = OnboardingService(vault=_StubVault())
    job, script = svc.render_script(job)

    # The node row now carries the user + encrypted password the script
    # installed; the poller's credentials_for(node) returns plaintext.
    db.session.refresh(n)
    assert n.routeros_api_user == "hobe-panel"
    assert "OnbProvisionedP@ss" not in (n.routeros_api_password_enc or "")
    creds = credentials_for(n)
    assert creds is not None
    assert creds["user"] == "hobe-panel"
    assert creds["password"] == "OnbProvisionedP@ss"
    # And the rendered script carries the freshly-provisioned creds.
    assert 'name="hobe-panel"' in script
    assert 'password="OnbProvisionedP@ss"' in script
