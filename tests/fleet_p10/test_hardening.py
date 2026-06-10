"""Phase 10 hardening — config validation, schema completeness, and the
default-safe invariants every fleet phase relies on at boot.

Three test groups:

1. ``validate_config`` returns no errors on the canonical
   :class:`FleetConfig` and rejects every nonsense value we can mint by
   ``dataclasses.replace`` against a single field. Bounds parametrised
   so a future tunable that goes out of range fails LOUDLY in CI rather
   than silently misbehaving in prod.

2. ``db.create_all()`` from a CLEAN engine produces EVERY fleet table.
   This guards against the "I added a model but forgot to import it in
   app/__init__.py" regression — the fleet has thirteen tables and one
   missed import means a prod migration crashes on a foreign-key target.

3. The live-apply default-safe invariant: with NO setting row present,
   :func:`fleet.control.live_apply_settings.is_enabled` returns False
   AND the routing-table response carries ``live_apply_enabled: false``.
"""
from __future__ import annotations

import dataclasses
import hashlib
import hmac
import time

import pytest
from sqlalchemy import inspect

from app.extensions import db
from app.models import Setting

from fleet.config import (
    BrainConfig,
    CloudflareDnsConfig,
    CostModel,
    DnsConfig,
    FleetConfig,
    HealthConfig,
    OrchestratorConfig,
    PlacementConfig,
    ScoringWeights,
)
from fleet.control.live_apply_settings import (
    SETTING_KEY as LIVE_APPLY_KEY,
    is_enabled as live_apply_is_enabled,
)
from fleet.hardening import (
    assert_live_apply_default_safe,
    validate_config,
    validate_config_or_raise,
)


# ════════════════════════════════════════════════════════════════════════
# 1. validate_config
# ════════════════════════════════════════════════════════════════════════


def test_default_config_is_valid():
    assert validate_config(FleetConfig()) == []


def test_validate_config_or_raise_passes_on_defaults():
    validate_config_or_raise(FleetConfig())  # must not raise


@pytest.mark.parametrize("subname,field,bad", [
    # Negative weights are nonsense.
    ("scoring", "health", -0.1),
    # Out-of-band CPU threshold (>100%).
    ("health",  "cpu_shed_threshold_pct", 150.0),
    # Zero/negative durations.
    ("health",  "down_after", 0),
    ("placement", "score_interval", -1),
    # Margin out of [0,1].
    ("placement", "rebalance_margin", 1.5),
    # Empty Cloudflare zone id.
    ("dns",  "ttl", 0),
    # Negative cost.
    ("cost", "hourly_cost", -1.0),
    # Brain shed penalty out of [0,1].
    ("brain", "cpu_shed_penalty", 1.5),
    # Orchestrator caps.
    ("orchestrator", "max_moves_per_plan", 0),
    ("orchestrator", "target_min_free_pct", -5.0),
    ("orchestrator", "insufficient_capacity_pct", 200.0),
])
def test_validate_config_rejects_out_of_bounds(subname, field, bad):
    base = FleetConfig()
    sub = getattr(base, subname)
    bad_sub = dataclasses.replace(sub, **{field: bad})
    cfg = dataclasses.replace(base, **{subname: bad_sub})
    errors = validate_config(cfg)
    assert any(field in err for err in errors), \
        f"expected an error mentioning {field!r}; got {errors}"


def test_validate_rejects_non_monotonic_cost_anchors():
    """The cost piece-wise curve must have warn <= alarm <= drain."""
    bad_brain = dataclasses.replace(
        BrainConfig(),
        cost_metered_warn_ratio=0.9,
        cost_metered_alarm_ratio=0.5,   # < warn
        cost_metered_drain_ratio=1.0,
    )
    cfg = dataclasses.replace(FleetConfig(), brain=bad_brain)
    errors = validate_config(cfg)
    assert any("monotonic" in e for e in errors), errors


def test_validate_min_healthy_cannot_exceed_top_n():
    bad_dns = dataclasses.replace(DnsConfig(), top_n_cap=2, min_healthy=5)
    cfg = dataclasses.replace(FleetConfig(), dns=bad_dns)
    errors = validate_config(cfg)
    assert any("min_healthy" in e for e in errors), errors


def test_validate_config_or_raise_raises_on_bad():
    bad_orc = dataclasses.replace(OrchestratorConfig(),
                                  target_min_free_pct=-1.0)
    cfg = dataclasses.replace(FleetConfig(), orchestrator=bad_orc)
    with pytest.raises(ValueError):
        validate_config_or_raise(cfg)


# ════════════════════════════════════════════════════════════════════════
# 2. Schema completeness — db.create_all() must build every fleet table
# ════════════════════════════════════════════════════════════════════════


# Every fleet-owned table. Adding a new one means: add the model in its
# module + add the table here. Test catches the "forgot to import" bug.
EXPECTED_FLEET_TABLES: frozenset[str] = frozenset({
    "fleet_providers",
    "fleet_chr_nodes",
    "fleet_chr_metrics",
    "fleet_chr_health",
    "fleet_chr_secrets",
    "fleet_users",
    "fleet_sessions",
    "fleet_placement_decisions",
    "fleet_events",
    "fleet_alerts",
    "fleet_dns_records_state",
    "fleet_onboarding_jobs",
})


def test_create_all_builds_every_fleet_table(app):
    """Boot the app, run create_all, confirm every fleet table is present."""
    tables = set(inspect(db.engine).get_table_names())
    missing = EXPECTED_FLEET_TABLES - tables
    assert not missing, (
        f"db.create_all() did not build these fleet tables: {sorted(missing)} "
        f"— most likely a missing model import in app/__init__.py."
    )


# ════════════════════════════════════════════════════════════════════════
# 3. Live-apply default-safe invariant
# ════════════════════════════════════════════════════════════════════════


def test_live_apply_default_off_without_setting(app):
    """Fresh DB ⇒ no Setting row ⇒ live-apply is OFF."""
    assert db.session.get(Setting, LIVE_APPLY_KEY) is None
    assert live_apply_is_enabled() is False
    assert assert_live_apply_default_safe() is True


def test_routing_table_reports_live_apply_false_by_default(app, client):
    """The proxy's view of live-apply matches: missing row ⇒ false."""
    token = _valid_token(app)
    r = client.get("/api/proxy/routing-table",
                   headers={"X-Proxy-Token": token})
    assert r.status_code == 200
    body = r.get_json()
    assert "live_apply_enabled" in body
    assert body["live_apply_enabled"] is False


def test_live_apply_malformed_value_collapses_to_off(app):
    """A garbled Setting value (a 1-char typo, a stray quote) must read
    as OFF — the panel never crashes the proxy into 'on' on a parsing
    error."""
    db.session.add(Setting(key=LIVE_APPLY_KEY, value="totally bogus"))
    db.session.commit()
    assert live_apply_is_enabled() is False


# ════════════════════════════════════════════════════════════════════════
# Helpers
# ════════════════════════════════════════════════════════════════════════


def _valid_token(app) -> str:
    secret = app.config.get("RADIUS_PROXY_SHARED_SECRET", "")
    if not secret:
        secret = "test-shared-secret"
        app.config["RADIUS_PROXY_SHARED_SECRET"] = secret
    ts = int(time.time())
    nonce = f"p10-default-safe-{ts}-{id(app)}"
    mac = hmac.new(secret.encode(), f"{ts}:{nonce}".encode(),
                   hashlib.sha256).hexdigest()
    return f"{ts}:{nonce}:{mac}"
