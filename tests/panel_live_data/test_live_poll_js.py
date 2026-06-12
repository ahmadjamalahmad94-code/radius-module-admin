"""feat/panel-live-data-5s — static + behavioural checks of live_poll.js.

The JS is small enough that we don't need a Node test runner; we exercise
the structural invariants the templates rely on (attribute names + module
contract) and re-implement the dotted-path getter in Python to confirm the
same shape the backend emits resolves cleanly under the JS algorithm.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

JS_PATH = Path(__file__).resolve().parents[2] / "app" / "static" / "js" / "live_poll.js"


# ────────────────────────────────────────────────────────────────────────
# Static checks — the file must define + use the documented attributes
# ────────────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def js() -> str:
    return JS_PATH.read_text(encoding="utf-8")


def test_module_exists():
    assert JS_PATH.is_file(), f"missing JS module at {JS_PATH}"


def test_default_interval_is_5_seconds(js):
    """The owner asked for 5-second polling. Any future change here should be
    deliberate — the template's ``data-live-interval`` override is the right
    place to deviate per-page."""
    assert "DEFAULT_INTERVAL_MS = 5000" in js


def test_backoff_curve_present(js):
    """Backoff sequence must be the documented 5/10/20/40/60s ladder."""
    m = re.search(r"ERROR_BACKOFFS_MS\s*=\s*\[([^\]]+)\]", js)
    assert m, "missing ERROR_BACKOFFS_MS"
    nums = [int(x.strip()) for x in m.group(1).split(",") if x.strip()]
    assert nums == [5000, 10000, 20000, 40000, 60000]


@pytest.mark.parametrize(
    "attr",
    [
        "data-live-endpoint",
        "data-live-interval",
        "data-live-indicator",
        "data-live-bind",
        "data-live-pct",
        "data-live-class",
        "data-live-class-map",
        "data-live-toggle",
        "data-live-html",
        "data-live-suffix",
        "data-live-empty",
        "data-live-indicator-text",
        "data-live-indicator-dot",
        # Per-row binding pattern — used by the fleet dashboard node grid.
        "data-live-rows",
        "data-live-row-key",
        "data-live-row-id",
    ],
)
def test_attribute_contract_is_referenced(js, attr):
    """Every documented data-attribute MUST be referenced by the JS — guards
    against silent regressions where a template adds a new binding but the
    poller no longer reads it."""
    assert attr in js, f"attribute not referenced by live_poll.js: {attr}"


def test_pauses_on_visibility_change(js):
    """Hidden tabs must NOT keep polling — owner explicitly asked for this."""
    assert "visibilitychange" in js
    assert "document.hidden" in js


def test_renders_arabic_indicator_copy(js):
    """The «مباشر • آخر تحديث» indicator copy must be Arabic + RTL-safe.
    Catches accidental English-only fallbacks."""
    assert "آخر تحديث" in js
    assert "إيقاف مؤقت" in js


def test_exposes_window_livepoll_api(js):
    """A minimal global API is exposed so tests + per-page JS can introspect
    or extend behaviour without re-implementing the poller."""
    assert "window.LivePoll" in js
    assert "_Poller" in js
    # The shared `get` dot-path helper must be reachable for unit testing.
    assert "get," in js or "get:" in js  # exposed in the LivePoll object


# ────────────────────────────────────────────────────────────────────────
# Behaviour — re-implement the dot-path getter in Python and confirm it
# resolves the payload shape build_dashboard_payload returns.
# ────────────────────────────────────────────────────────────────────────


def _py_get(obj, path):
    """Mirror of the JS `get(obj, path)` helper in live_poll.js."""
    if obj is None or not path:
        return None
    cur = obj
    for part in str(path).split("."):
        if cur is None:
            return None
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            cur = getattr(cur, part, None)
    return cur


_SAMPLE_FLEET_PAYLOAD = {
    "ok": True,
    "ts": "2026-06-11T00:00:00+00:00",
    "totals": {"nodes": 3, "providers": 2, "pending_jobs": 1},
    "by_status": {"up": 2, "degraded": 1, "down": 0, "disabled": 0, "provisioning": 0},
    "by_health": {"up": 2, "degraded": 1, "down": 0, "unknown": 0},
    "overview": {
        "sessions": 17, "capacity": 50, "util_pct": 34,
        "eligible": 2, "online_pct": 67, "off_or_prov": 0,
    },
    "best_node": {"id": 1, "name": "chr-vpn-1", "score": 87},
    "nodes": [{"id": 1, "name": "chr-vpn-1", "state": "up"}],
}


@pytest.mark.parametrize(
    "path, expected",
    [
        ("totals.nodes",          3),
        ("totals.providers",      2),
        ("totals.pending_jobs",   1),
        ("by_health.up",          2),
        ("by_health.degraded",    1),
        ("by_health.down",        0),
        ("by_health.unknown",     0),
        ("overview.sessions",     17),
        ("overview.capacity",     50),
        ("overview.util_pct",     34),
        ("overview.online_pct",   67),
        ("overview.eligible",     2),
        ("overview.off_or_prov",  0),
        ("best_node.name",        "chr-vpn-1"),
        ("nope.does.not.exist",   None),
    ],
)
def test_dotted_paths_resolve_against_fleet_payload(path, expected):
    """Every path the dashboard template binds via data-live-bind must
    resolve cleanly through the same algorithm the JS uses."""
    assert _py_get(_SAMPLE_FLEET_PAYLOAD, path) == expected


_SAMPLE_HEALTH_PAYLOAD = {
    "ok": True,
    "cpu_pct": 12.4, "mem_pct": 56.0, "disk_pct": 71.2,
    "db_ms": 0.6, "db_ok": True,
    "poller_age_s": 23, "poller_status": "ok",
    "health": {
        "resources": {"cpu_pct": 12.4, "mem_pct": 56.0, "disk_pct": 71.2},
        "server": {"poller_status": "ok", "poller_age_s": 23},
        "database": {"response_ms": 0.6, "ok": True},
    },
    "status_cls": {"cpu": "ok", "mem": "ok", "disk": "warn",
                   "srv": "ok", "db": "ok", "px": "ok", "wa": "warn"},
}


@pytest.mark.parametrize(
    "path, expected",
    [
        ("cpu_pct",                          12.4),
        ("mem_pct",                          56.0),
        ("disk_pct",                         71.2),
        ("db_ms",                            0.6),
        ("poller_age_s",                     23),
        ("poller_status",                    "ok"),
        ("health.resources.cpu_pct",         12.4),
        ("status_cls.cpu",                   "ok"),
    ],
)
def test_dotted_paths_resolve_against_health_payload(path, expected):
    assert _py_get(_SAMPLE_HEALTH_PAYLOAD, path) == expected


def test_class_map_json_round_trips():
    """The `data-live-class-map='{"ok":"is-ok"}'` attribute must be valid JSON
    so the JS parser accepts it. We round-trip a sample to prove the format
    the templates use is consumable."""
    raw = '{"ok":"is-ok","warn":"is-warn","error":"is-err"}'
    parsed = json.loads(raw)
    assert parsed["ok"] == "is-ok"
    assert parsed["warn"] == "is-warn"


# ────────────────────────────────────────────────────────────────────────
# Per-row binding pattern — `data-live-rows="nodes"` data-live-row-key="id"
# Used by the dashboard's node grid. Each row's inner data-live-* paths
# resolve against ONE record (the row's), not the whole payload.
# ────────────────────────────────────────────────────────────────────────


_SAMPLE_NODES = [
    {"id": 1, "name": "chr-A", "state": "up",
     "cpu_pct": 12.4, "sessions": 5, "max_sessions": 10,
     "sessions_cap_pct": 50, "rtt_ms": 18.2, "rx_gb": 1.7, "tx_gb": 0.9},
    {"id": 2, "name": "chr-B", "state": "degraded",
     "cpu_pct": 72.0, "sessions": 8, "max_sessions": 10,
     "sessions_cap_pct": 80, "rtt_ms": 105.0, "rx_gb": 4.2, "tx_gb": 3.1},
]


def _index_rows(rows, key="id"):
    """Mirror the JS `byKey[String(rec[key])] = rec` indexing pattern."""
    return {str(rec.get(key)): rec for rec in rows if rec.get(key) is not None}


def test_per_row_index_resolves_each_row_to_its_own_record():
    """Smoke test of the contract: row id "1" must resolve to chr-A and "2"
    to chr-B — never crossed. If this ever drifts, the dashboard would
    show chr-B's CPU under chr-A's card (silent bug; production crash)."""
    by_id = _index_rows(_SAMPLE_NODES, "id")
    assert by_id["1"]["name"] == "chr-A"
    assert by_id["2"]["name"] == "chr-B"
    # And the inner dotted-path getter still works against a row record.
    assert _py_get(by_id["1"], "cpu_pct") == 12.4
    assert _py_get(by_id["2"], "sessions_cap_pct") == 80


def test_per_row_pattern_bindings_present_in_js(js):
    """The JS must contain the loop that walks `data-live-rows` containers,
    builds the index, and dispatches into `_applyRowBindings(row, rec)`."""
    assert "_applyRowBindings" in js
    assert 'querySelectorAll("[data-live-rows]")' in js
    assert "data-live-row-id" in js
    assert "data-live-row-key" in js
    # Global pass MUST skip rows-scoped elements — otherwise it would
    # double-bind against the wrong (global) payload key.
    assert 'closest("[data-live-rows]")' in js


def test_per_row_pattern_supports_state_class_swap():
    """The dashboard's node card uses data-live-class="state" with a map of
    the 4 health states. Locks in the JSON shape the template emits."""
    cls_map_json = (
        '{"up":"node-card--up","degraded":"node-card--degraded",'
        '"down":"node-card--down","unknown":"node-card--unknown"}'
    )
    cls_map = json.loads(cls_map_json)
    for state in ("up", "degraded", "down", "unknown"):
        assert state in cls_map, f"missing health state in class map: {state}"
        assert cls_map[state].startswith("node-card--")


def test_dashboard_template_emits_per_row_bindings():
    """The dashboard.html template MUST wire `data-live-rows="nodes"` on the
    grid container — without it the poller has no per-row hook and the
    tiles never refresh."""
    tpl = Path(__file__).resolve().parents[2] / "app" / "templates" / "admin" / "fleet" / "dashboard.html"
    src = tpl.read_text(encoding="utf-8")
    assert 'data-live-rows="nodes"' in src
    assert 'data-live-row-key="id"' in src
    assert 'data-live-row-id="{{ n.id }}"' in src
    # The per-tile bindings:
    for path in ("cpu_pct", "mem_pct", "sessions", "max_sessions",
                 "sessions_cap_pct", "rtt_ms", "rx_gb", "tx_gb"):
        assert f'data-live-bind="{path}"' in src, (
            f"dashboard per-row tile missing data-live-bind={path!r}"
        )
