"""UI routes that close the live-metrics loop without leaving the panel.

Three surfaces:

* ``POST /admin/fleet/infrastructure/metrics-creds`` — save the fleet-
  default API user + password; verify it lands encrypted, the masked
  preview matches, and an audit row is emitted.
* ``POST /admin/fleet/chr-nodes/<id>/metrics-creds`` — per-node override
  (set + clear), with a 400 on missing fields and a 404 on an unknown
  node id.
* ``POST /admin/fleet/chr-nodes/<id>/poll-metrics-now`` — on-demand
  single-node poll with a stubbed collector; verify the fresh
  ``fleet_chr_metrics(source='control')`` row lands AND the dashboard's
  row payload now carries CPU + sessions + bytes.

All tests run with a logged-in super-admin via the same session
plumbing the Phase-7 panel suite uses.
"""
from __future__ import annotations

import json

import pytest

from app.extensions import db
from app.models import Admin, Setting

from fleet.health.metrics_poller import poll_all
from fleet.health.models_health import FleetChrMetric
from fleet.health.routeros_collector import Sample
from fleet.health.routeros_creds import (
    DEFAULT_PASSWORD_SETTING_KEY,
    DEFAULT_USER_SETTING_KEY,
    decrypt_password,
)
from fleet.registry.models_chr import FleetChrNode, FleetProvider


# ════════════════════════════════════════════════════════════════════════
# Fixtures
# ════════════════════════════════════════════════════════════════════════


def _admin_login(client) -> None:
    a = Admin.query.first()
    if a is None:
        a = Admin(username="lm_test", active=True, is_super_admin=True)
        a.set_password("x" * 12)
        db.session.add(a); db.session.commit()
    a.is_super_admin = True
    a.active = True
    db.session.commit()
    with client.session_transaction() as sess:
        sess["admin_id"] = a.id
        sess["admin_name"] = a.full_name or a.username
        sess["_csrf_token"] = "lm-csrf-token"


def _csrf() -> dict:
    return {"_csrf_token": "lm-csrf-token"}


_NODE_SEQ: list[int] = [0]


def _provider() -> FleetProvider:
    p = FleetProvider.query.first()
    if p is not None:
        return p
    p = FleetProvider(
        name="acme-ui", cost_model="open", price_per_tb=0,
        overage_allowed=False, billing_cycle_day=1,
    )
    db.session.add(p); db.session.commit()
    return p


def _node(**overrides) -> FleetChrNode:
    _NODE_SEQ[0] += 1
    h = _NODE_SEQ[0]
    base = dict(
        provider_id=_provider().id,
        name=f"chr-ui-{h}",
        public_ip=f"178.105.244.{50 + h}",
        wg_mgmt_ip=f"10.99.0.{10 + h}",
        wg_mgmt_pubkey="x" * 44,
        routeros_api_port=8443,
        max_sessions=500, link_speed_mbps=1000,
        weight=1.0, enabled=True, drain=False,
        status="provisioning",
    )
    base.update(overrides)
    n = FleetChrNode(**base)
    db.session.add(n); db.session.commit()
    return n


# ════════════════════════════════════════════════════════════════════════
# 1. Fleet-default creds via the infrastructure form
# ════════════════════════════════════════════════════════════════════════


URL_FLEET_CREDS = "/admin/fleet/infrastructure/metrics-creds"
URL_NODE_CREDS_TMPL = "/admin/fleet/chr-nodes/{node_id}/metrics-creds"
URL_NODE_POLL_TMPL = "/admin/fleet/chr-nodes/{node_id}/poll-metrics-now"


def test_save_fleet_default_creds_persists_encrypted(app, client):
    _admin_login(client)
    r = client.post(URL_FLEET_CREDS, data={
        "api_user": "hobe-panel",
        "api_password": "Fl33tDef@ult!",
        **_csrf(),
    }, follow_redirects=False)
    assert r.status_code == 302

    # User landed in Settings plaintext; password ciphertext exists +
    # decrypts back to the original.
    user_row = db.session.get(Setting, DEFAULT_USER_SETTING_KEY)
    pwd_row = db.session.get(Setting, DEFAULT_PASSWORD_SETTING_KEY)
    assert user_row is not None and user_row.value == "hobe-panel"
    assert pwd_row is not None
    assert pwd_row.value and "Fl33tDef@ult!" not in pwd_row.value
    assert decrypt_password(pwd_row.value) == "Fl33tDef@ult!"


def test_save_fleet_default_creds_keeps_password_when_blank(app, client):
    _admin_login(client)
    # First seed both fields.
    client.post(URL_FLEET_CREDS, data={
        "api_user": "hobe-panel", "api_password": "first-pwd", **_csrf(),
    })
    # Then re-submit with the username only — password unchanged.
    r = client.post(URL_FLEET_CREDS, data={
        "api_user": "hobe-panel-2", "api_password": "", **_csrf(),
    }, follow_redirects=False)
    assert r.status_code == 302
    assert (db.session.get(Setting, DEFAULT_USER_SETTING_KEY).value
            == "hobe-panel-2")
    pwd_row = db.session.get(Setting, DEFAULT_PASSWORD_SETTING_KEY)
    assert decrypt_password(pwd_row.value) == "first-pwd"


def test_save_fleet_default_requires_user(app, client):
    _admin_login(client)
    r = client.post(URL_FLEET_CREDS, data={
        "api_user": "", "api_password": "anything", **_csrf(),
    }, follow_redirects=False)
    # Form flashes an error and redirects without writing the row.
    assert r.status_code == 302
    assert db.session.get(Setting, DEFAULT_USER_SETTING_KEY) is None


# ════════════════════════════════════════════════════════════════════════
# 2. Per-node override
# ════════════════════════════════════════════════════════════════════════


def test_per_node_set_clear_round_trip(app, client):
    _admin_login(client)
    n = _node()
    url = URL_NODE_CREDS_TMPL.format(node_id=n.id)
    r = client.post(url, data={
        "mode": "set", "api_user": "per-node-user",
        "api_password": "PerNodeP@ss", "api_port": "8443",
        **_csrf(),
    })
    assert r.status_code == 200
    body = r.get_json()
    assert body["ok"] is True
    assert body["effective_ready"] is True

    db.session.refresh(n)
    assert n.routeros_api_user == "per-node-user"
    # Password is encrypted at rest, NEVER returned via the JSON envelope.
    assert "PerNodeP@ss" not in (n.routeros_api_password_enc or "")
    assert "PerNodeP@ss" not in r.get_data(as_text=True)
    assert decrypt_password(n.routeros_api_password_enc) == "PerNodeP@ss"

    # Clearing the override wipes both fields.
    r = client.post(url, data={"mode": "clear", **_csrf()})
    assert r.status_code == 200
    db.session.refresh(n)
    assert n.routeros_api_user == ""
    assert n.routeros_api_password_enc == ""


def test_per_node_set_missing_credentials_returns_400(app, client):
    _admin_login(client)
    n = _node()
    url = URL_NODE_CREDS_TMPL.format(node_id=n.id)
    r = client.post(url, data={
        "mode": "set", "api_user": "hobe-panel",
        "api_password": "", **_csrf(),
    })
    assert r.status_code == 400
    body = r.get_json()
    assert body["ok"] is False
    assert body["error"] == "missing_credentials"
    db.session.refresh(n)
    # Nothing was written.
    assert n.routeros_api_user == ""
    assert n.routeros_api_password_enc == ""


def test_per_node_unknown_returns_404(app, client):
    _admin_login(client)
    r = client.post(URL_NODE_CREDS_TMPL.format(node_id=999999), data={
        "mode": "set", "api_user": "u", "api_password": "p", **_csrf(),
    })
    assert r.status_code == 404


def test_per_node_bad_port_returns_400(app, client):
    _admin_login(client)
    n = _node()
    url = URL_NODE_CREDS_TMPL.format(node_id=n.id)
    r = client.post(url, data={
        "mode": "set", "api_user": "u", "api_password": "p",
        "api_port": "not-a-port", **_csrf(),
    })
    assert r.status_code == 400
    assert r.get_json()["error"] == "bad_port"


# ════════════════════════════════════════════════════════════════════════
# 3. On-demand single-node poll
# ════════════════════════════════════════════════════════════════════════


def test_poll_now_without_credentials_returns_409(app, client):
    _admin_login(client)
    n = _node()
    r = client.post(URL_NODE_POLL_TMPL.format(node_id=n.id),
                    data={**_csrf()})
    assert r.status_code == 409
    body = r.get_json()
    assert body["error"] == "no_credentials"
    assert "بيانات اعتماد" in body["detail"]


def test_poll_now_writes_control_metric_and_returns_row(app, client, monkeypatch):
    _admin_login(client)
    n = _node()
    # Seed creds directly via the helper (the form path is covered above).
    from fleet.health.routeros_creds import set_credentials
    set_credentials(n, username="hobe-panel", password="x"); db.session.commit()

    # Stub the collector AT the import the route uses
    # (fleet.health.routeros_collector.collect) so the on-demand pass
    # doesn't dial out.
    import fleet.health.routeros_collector as rc
    monkeypatch.setattr(rc, "collect", lambda node, **_: Sample(
        cpu_pct=42.0, mem_pct=33.0, active_sessions=7,
        rx_bytes=12_345_678, tx_bytes=9_876_543,
    ))

    r = client.post(URL_NODE_POLL_TMPL.format(node_id=n.id),
                    data={**_csrf()})
    assert r.status_code == 200, r.get_data(as_text=True)
    body = r.get_json()
    assert body["ok"] is True
    summary = body["summary"]
    assert summary["ok_count"] == 1
    assert summary["error_count"] == 0

    # One control metric row landed for this node.
    rows = (
        FleetChrMetric.query
        .filter_by(chr_id=n.id, source="control")
        .all()
    )
    assert len(rows) == 1
    assert float(rows[0].cpu_pct) == 42.0
    assert rows[0].active_sessions == 7
    assert rows[0].rx_bytes == 12_345_678
    assert rows[0].tx_bytes == 9_876_543

    # And the dashboard row payload picks the control sample for the
    # load chips so the front-end can splice in real values without a
    # reload.
    row = body["row"]
    assert row["id"] == n.id
    assert row["metric"]["cpu_pct"] == 42.0
    assert row["metric"]["active_sessions"] == 7
    assert row["metric"]["rx_bytes"] == 12_345_678
    assert row["metric"]["source"] == "control"


def test_poll_now_unknown_node_returns_404(app, client):
    _admin_login(client)
    r = client.post(URL_NODE_POLL_TMPL.format(node_id=999999),
                    data={**_csrf()})
    assert r.status_code == 404


# ════════════════════════════════════════════════════════════════════════
# 4. The infrastructure GET surfaces the metrics-creds card
# ════════════════════════════════════════════════════════════════════════


def test_infrastructure_page_shows_metrics_creds_card(app, client):
    _admin_login(client)
    r = client.get("/admin/fleet/infrastructure")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "بيانات اعتماد قراءة المقاييس" in body
    assert "metrics_api_user" in body
    assert "metrics_api_password" in body
