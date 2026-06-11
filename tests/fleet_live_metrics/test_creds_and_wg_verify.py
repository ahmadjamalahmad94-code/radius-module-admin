"""Metrics-credential diagnostics + WireGuard key verification.

Field findings pinned (fix/fleet-deterministic-onboarding):

* «لا توجد بيانات اعتماد API لهذه العقدة» fired even though the node row
  held user + port + ciphertext — the ciphertext was encrypted under a
  DIFFERENT master key and ``decrypt_password`` collapsed the failure to
  ``""`` (indistinguishable from unset). ``credentials_diagnostics`` now
  keeps the failure modes apart: per-node decrypt-failed vs fleet-default
  decrypt-failed vs nothing-set, each with its own machine code and a
  precise Arabic message naming WHICH screen fixes it.

* A wrong panel public key on the CHR's wg-mgmt peer was invisible until
  everything downstream died. ``verify_node_wg_identity`` reads the CHR's
  actual peer + interface keys over REST and verdicts both directions.
"""
from __future__ import annotations

import pytest

from app.extensions import db
from app.models import Setting
from fleet.health import routeros_creds as rc
from fleet.health.wg_verify import verify_node_wg_identity
from fleet.registry.models_chr import FleetChrNode


# ── helpers ──────────────────────────────────────────────────────────────


def _node(**over) -> FleetChrNode:
    """Detached node instance — diagnostics never need a persisted row."""
    n = FleetChrNode()
    n.name = over.get("name", "chr-vpn-1")
    n.wg_mgmt_ip = over.get("wg_mgmt_ip", "10.99.0.11")
    n.wg_mgmt_pubkey = over.get("wg_mgmt_pubkey", "CHRKEY=")
    n.routeros_api_user = over.get("user", "")
    n.routeros_api_password_enc = over.get("password_enc", "")
    n.routeros_api_port = over.get("port", 8443)
    return n


def _set_fleet_default_password(app, plaintext: str | None, *, garbage: bool = False):
    value = "not-a-fernet-token" if garbage else (
        rc.encrypt_password(plaintext) if plaintext else ""
    )
    row = db.session.get(Setting, rc.DEFAULT_PASSWORD_SETTING_KEY)
    if row is None:
        row = Setting(key=rc.DEFAULT_PASSWORD_SETTING_KEY, value=value)
        db.session.add(row)
    else:
        row.value = value
    db.session.commit()


# ── credentials_diagnostics: source precedence + precise reasons ─────────


def test_diag_per_node_password_wins(app):
    with app.app_context():
        node = _node(user="admin", password_enc=rc.encrypt_password("pw1"))
        d = rc.credentials_diagnostics(node)
        assert d["ok"] is True
        assert d["source"] == "node"
        assert d["node_password_state"] == "ok"


def test_diag_fleet_default_used_when_node_unset(app):
    with app.app_context():
        _set_fleet_default_password(app, "fleetpw")
        node = _node()  # no per-node password
        d = rc.credentials_diagnostics(node)
        assert d["ok"] is True
        assert d["source"] == "fleet_default"
        assert d["fleet_password_state"] == "ok"
        # And credentials_for agrees (same resolution path).
        creds = rc.credentials_for(node)
        assert creds is not None and creds["password"] == "fleetpw"


def test_diag_node_decrypt_failure_is_named_not_silent(app):
    """THE field bug: garbage/foreign-key ciphertext on the node row must
    be reported as decrypt_failed — not as «no credentials»."""
    with app.app_context():
        node = _node(user="admin", password_enc="not-a-fernet-token")
        d = rc.credentials_diagnostics(node)
        assert d["ok"] is False
        assert d["reason_code"] == "node_decrypt_failed"
        assert d["node_password_state"] == "decrypt_failed"
        # The Arabic message points at the per-node creds screen.
        assert "العقدة" in d["message_ar"]


def test_diag_fleet_decrypt_failure_is_named(app):
    with app.app_context():
        _set_fleet_default_password(app, None, garbage=True)
        node = _node()
        d = rc.credentials_diagnostics(node)
        assert d["ok"] is False
        assert d["reason_code"] == "fleet_decrypt_failed"
        assert d["fleet_password_state"] == "decrypt_failed"


def test_diag_nothing_set_anywhere(app):
    with app.app_context():
        node = _node()
        d = rc.credentials_diagnostics(node)
        assert d["ok"] is False
        assert d["reason_code"] == "no_password_anywhere"


def test_diag_no_mgmt_ip(app):
    with app.app_context():
        node = _node(wg_mgmt_ip="")
        d = rc.credentials_diagnostics(node)
        assert d["ok"] is False
        assert d["reason_code"] == "no_mgmt_ip"


def test_diag_broken_node_creds_with_working_fleet_default_warns(app):
    """Fleet default saves the day but the broken per-node ciphertext is
    still flagged in the message so the operator cleans it up."""
    with app.app_context():
        _set_fleet_default_password(app, "fleetpw")
        node = _node(user="admin", password_enc="not-a-fernet-token")
        d = rc.credentials_diagnostics(node)
        assert d["ok"] is True
        assert d["source"] == "fleet_default"
        assert d["node_password_state"] == "decrypt_failed"
        assert "تعذّر فك تشفيرها" in d["message_ar"]


# ── verify_node_wg_identity ──────────────────────────────────────────────


class _FakeClient:
    def __init__(self, *, peer_key="PANELKEY=", iface_key="CHRKEY=",
                 peers=None, raise_rest=False):
        self._peer_key = peer_key
        self._iface_key = iface_key
        self._peers = peers
        self._raise = raise_rest

    def list_wireguard_peers(self, *, interface=None):
        if self._raise:
            from app.services.routeros_client import RouterOSError
            raise RouterOSError("connect_failed", "تعذّر الاتصال بمضيف CHR.")
        if self._peers is not None:
            return self._peers
        return [{
            "public-key": self._peer_key,
            "comment": "hobe-fleet-mgmt",
            "last-handshake": "12s",
            "rx": "1024", "tx": "2048",
        }]

    def find_wireguard_interface(self, name):
        return {"name": name, "public-key": self._iface_key}


@pytest.fixture()
def _wg_env(app, monkeypatch):
    """App ctx + panel pubkey + creds stubbed for verify tests."""
    with app.app_context():
        monkeypatch.setattr(
            "fleet.registry.infra_settings.panel_pubkey_for_display",
            lambda: "PANELKEY=",
        )
        monkeypatch.setattr(
            "fleet.health.wg_verify.credentials_for",
            lambda node: {"host": node.wg_mgmt_ip, "port": 8443,
                          "user": "hobe-panel", "password": "pw"},
        )
        yield


def _factory_for(client):
    return lambda **kw: client


def test_verify_ok_when_both_directions_match(app, _wg_env):
    node = _node(wg_mgmt_pubkey="CHRKEY=")
    r = verify_node_wg_identity(node, client_factory=_factory_for(_FakeClient()))
    assert r.ok and r.code == "ok"
    assert r.panel_pubkey_on_chr == "PANELKEY="
    assert r.chr_pubkey_actual == "CHRKEY="
    assert r.last_handshake == "12s"


def test_verify_flags_wrong_panel_key_on_chr(app, _wg_env):
    """The exact field incident: CHR peer trusts a STALE panel key."""
    node = _node(wg_mgmt_pubkey="CHRKEY=")
    client = _FakeClient(peer_key="OLD-STALE-KEY=")
    r = verify_node_wg_identity(node, client_factory=_factory_for(client))
    assert not r.ok
    assert r.code == "panel_key_mismatch"
    assert r.panel_pubkey_expected == "PANELKEY="
    assert r.panel_pubkey_on_chr == "OLD-STALE-KEY="


def test_verify_flags_chr_key_drift(app, _wg_env):
    """Panel's on-file CHR key differs from the CHR's real interface key."""
    node = _node(wg_mgmt_pubkey="WHAT-PANEL-THINKS=")
    client = _FakeClient(iface_key="ACTUAL-CHR-KEY=")
    r = verify_node_wg_identity(node, client_factory=_factory_for(client))
    assert not r.ok
    assert r.code == "chr_key_mismatch"


def test_verify_reports_missing_peer(app, _wg_env):
    node = _node()
    client = _FakeClient(peers=[])
    r = verify_node_wg_identity(node, client_factory=_factory_for(client))
    assert not r.ok and r.code == "peer_missing"


def test_verify_surfaces_rest_failure(app, _wg_env):
    node = _node()
    client = _FakeClient(raise_rest=True)
    r = verify_node_wg_identity(node, client_factory=_factory_for(client))
    assert not r.ok and r.code == "rest_failed"


def test_verify_requires_panel_key_generated(app, monkeypatch):
    with app.app_context():
        monkeypatch.setattr(
            "fleet.registry.infra_settings.panel_pubkey_for_display", lambda: "",
        )
        r = verify_node_wg_identity(_node())
        assert not r.ok and r.code == "panel_key_unset"
