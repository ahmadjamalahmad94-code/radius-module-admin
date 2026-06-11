"""feat/panel-live-data-5s — JSON shape contract the live poller consumes.

The admin pages render once via SSR; ``app/static/js/live_poll.js`` then
hits these endpoints every 5 seconds and updates the DOM in place. If the
shape drifts, the poller stops finding its bindings — these tests are the
guard.
"""
from __future__ import annotations

import pytest

from app.extensions import db
from app.models import Admin
from fleet.registry.models_chr import FleetChrNode, FleetProvider


def _login(client) -> None:
    a = Admin.query.first()
    if a is None:
        a = Admin(username="live_test", active=True, is_super_admin=True)
        a.set_password("x" * 12)
        db.session.add(a); db.session.commit()
    a.is_super_admin = True
    a.active = True
    db.session.commit()
    with client.session_transaction() as sess:
        sess["admin_id"] = a.id
        sess["admin_name"] = a.full_name or a.username


def _seed_a_node(name: str = "chr-live-1") -> FleetChrNode:
    """Create the minimal CHR row the dashboard payload needs."""
    prov = FleetProvider.query.first()
    if prov is None:
        prov = FleetProvider(name="hetzner", cost_model="metered",
                             price_per_tb=5, monthly_cap_tb=20,
                             overage_allowed=False)
        db.session.add(prov); db.session.flush()
    # FleetChrNode has NOT NULL wg_mgmt_pubkey — fill with a placeholder
    # base64-shaped string so the row is valid for the dashboard payload.
    node = FleetChrNode(
        name=name, provider_id=prov.id, public_ip="1.2.3.4",
        max_sessions=10, link_speed_mbps=1000, status="up",
        wg_mgmt_ip="10.99.0.11",
        wg_mgmt_pubkey="A" * 43 + "=",
    )
    db.session.add(node); db.session.commit()
    return node


# ────────────────────────────────────────────────────────────────────────
# /admin/fleet/live.json
# ────────────────────────────────────────────────────────────────────────


def test_fleet_live_json_requires_auth(client):
    """Anonymous fetch should redirect to login (302), not leak the JSON."""
    r = client.get("/admin/fleet/live.json", follow_redirects=False)
    assert r.status_code in (302, 401), f"expected redirect/401, got {r.status_code}"


def test_fleet_live_json_returns_stable_shape(app, client):
    """The contract every ``data-live-bind="..."`` in dashboard.html relies on."""
    with app.app_context():
        _seed_a_node()
        _login(client)
    r = client.get("/admin/fleet/live.json")
    assert r.status_code == 200, r.data[:200]
    j = r.get_json()
    assert j["ok"] is True
    assert "ts" in j and isinstance(j["ts"], str)

    # Top-level groups the template binds to:
    for key in ("totals", "by_status", "by_health", "overview", "nodes"):
        assert key in j, f"missing top-level key: {key}"

    # The bindings dashboard.html actually references — listed explicitly
    # so a future rename here trips this test instead of breaking the UI.
    REQUIRED_PATHS = [
        ("totals", "nodes"),
        ("totals", "providers"),
        ("totals", "pending_jobs"),
        ("by_health", "up"),
        ("by_health", "degraded"),
        ("by_health", "down"),
        ("by_health", "unknown"),
        ("overview", "sessions"),
        ("overview", "capacity"),
        ("overview", "util_pct"),
        ("overview", "eligible"),
        ("overview", "online_pct"),
        ("overview", "off_or_prov"),
    ]
    for group, leaf in REQUIRED_PATHS:
        assert leaf in j[group], f"{group}.{leaf} missing"
        v = j[group][leaf]
        assert isinstance(v, (int, float)), f"{group}.{leaf} not numeric: {v!r}"


def test_fleet_live_json_node_rows_match_payload_contract(app, client):
    """Per-node row shape — used by data-live-html / future row diffing."""
    with app.app_context():
        _seed_a_node("chr-live-A")
        _login(client)
    r = client.get("/admin/fleet/live.json")
    j = r.get_json()
    assert len(j["nodes"]) == 1
    n = j["nodes"][0]
    for k in (
        "id", "name", "state", "status", "cpu_pct", "mem_pct",
        "sessions", "max_sessions", "rtt_ms", "loss_pct",
        "rx_bytes", "tx_bytes", "last_seen_iso",
    ):
        assert k in n, f"node payload missing {k}"
    assert n["name"] == "chr-live-A"
    assert n["max_sessions"] == 10


def test_fleet_live_json_empty_fleet_is_well_formed(app, client):
    """With zero nodes the endpoint still returns 200 + zero-valued counters
    (no crashes from divide-by-zero or empty rankings)."""
    with app.app_context():
        _login(client)
    r = client.get("/admin/fleet/live.json")
    assert r.status_code == 200
    j = r.get_json()
    assert j["nodes"] == []
    assert j["overview"]["online_pct"] == 0   # no divide-by-zero
    assert j["overview"]["util_pct"]   == 0
    assert j["totals"]["nodes"] == 0


# ────────────────────────────────────────────────────────────────────────
# /admin/infra/system-health/live.json
# ────────────────────────────────────────────────────────────────────────


def test_system_health_live_json_requires_auth(client):
    r = client.get("/admin/infra/system-health/live.json", follow_redirects=False)
    assert r.status_code in (302, 401)


def test_system_health_live_json_returns_stable_shape(app, client):
    """Mirrors what health_new.html binds: cpu_pct / mem_pct / disk_pct +
    db ping + poller age."""
    with app.app_context():
        _login(client)
    r = client.get("/admin/infra/system-health/live.json")
    assert r.status_code == 200, r.data[:200]
    j = r.get_json()
    assert j["ok"] is True
    # Flattened keys the template binds to without ``health.resources.`` prefix.
    for key in ("cpu_pct", "mem_pct", "disk_pct", "db_ms", "db_ok",
                "poller_age_s", "poller_status", "health"):
        assert key in j, f"missing key: {key}"

    # And the nested `health` dict the SSR template also reads.
    assert "resources" in j["health"]
    for k in ("cpu_pct", "mem_pct", "disk_pct"):
        assert k in j["health"]["resources"]

    # status_cls map drives the live-class-map on per-block pills.
    assert "status_cls" in j
    for k in ("cpu", "mem", "disk", "srv", "db", "px", "wa"):
        assert k in j["status_cls"]
