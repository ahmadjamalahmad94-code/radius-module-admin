"""fleet.hardening — Phase 10 sanity checks across the fleet stack.

Two kinds of guards, both designed to surface at startup or in CI rather
than mid-incident:

1. :func:`validate_config` — bounds + sanity checks on every tunable in
   :class:`fleet.config.FleetConfig`. The frozen dataclasses already give
   us **type** safety; this layer gives us **value** safety so that, e.g.,
   ``OrchestratorConfig.target_min_free_pct = -1`` cannot ship.

   The function returns the list of complaints (one short string per
   problem). Callers in production wiring may choose to log + continue,
   or raise — the policy is up to them. The startup smoke calls it via
   :func:`validate_config_or_raise` so a misconfig fails fast on boot.

2. :func:`fleet_proxy_endpoints` — the canonical list of every
   panel-facing fleet endpoint that the proxy / external agents POST to.
   The Phase-10 auth-sweep test consumes this so a new endpoint can NEVER
   slip through without an X-Proxy-Token check: adding a fleet endpoint
   means adding a row here, and the test then enforces the 401-without-
   token invariant for free.

3. :func:`assert_live_apply_default_safe` — a one-shot probe a CI step
   can run on a fresh DB to confirm the safe default: no Setting row
   means the routing-table response carries
   ``live_apply_enabled: false``. The hook is the panel's promise that
   a degraded panel (no DB, no settings) leaves the proxy advisory-only.

The module is import-cheap (no Flask import at module load) so the
auth-sweep test can pull from it without standing up the app.
"""
from __future__ import annotations

import dataclasses
from typing import Iterable

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


# ════════════════════════════════════════════════════════════════════════
# 1. config validation
# ════════════════════════════════════════════════════════════════════════


def _pct(value: float, *, low: float = 0.0, high: float = 100.0) -> bool:
    return low <= float(value) <= high


def _ratio(value: float) -> bool:
    return 0.0 <= float(value) <= 1.0


def _positive(value: float) -> bool:
    return float(value) > 0.0


def _nonneg(value: float) -> bool:
    return float(value) >= 0.0


def validate_config(cfg: FleetConfig | None = None) -> list[str]:
    """Return a list of complaint strings; an empty list means OK.

    The checks here are intentionally CHEAP — each one is a single
    comparison. They cover the two failure modes that bite production
    silently:

    * A typo'd negative number ("5%" → -5 because a UI form glitched).
    * A unit confusion (300 seconds vs 300 minutes).
    """
    cfg = cfg or FleetConfig()
    out: list[str] = []

    sw = cfg.scoring
    for name in ("health", "cpu_headroom", "latency", "capacity",
                "session_headroom", "cost", "stickiness"):
        v = getattr(sw, name)
        if not _nonneg(v):
            out.append(f"scoring.{name} must be >= 0 (got {v!r})")

    h = cfg.health
    if not _pct(h.cpu_shed_threshold_pct):
        out.append(f"health.cpu_shed_threshold_pct must be in [0,100] (got {h.cpu_shed_threshold_pct})")
    for name in ("down_after", "up_after", "cooldown", "telemetry_stale_after"):
        v = getattr(h, name)
        if not _positive(v):
            out.append(f"health.{name} must be > 0 seconds (got {v})")

    p = cfg.placement
    if not _positive(p.score_interval):
        out.append(f"placement.score_interval must be > 0 (got {p.score_interval})")
    if not _ratio(p.rebalance_margin):
        out.append(f"placement.rebalance_margin must be in [0,1] (got {p.rebalance_margin})")
    if not _positive(p.max_moves_per_cycle):
        out.append(f"placement.max_moves_per_cycle must be > 0 (got {p.max_moves_per_cycle})")

    d = cfg.dns
    if not _positive(d.ttl):
        out.append(f"dns.ttl must be > 0 seconds (got {d.ttl})")
    if not _positive(d.top_n_cap):
        out.append(f"dns.top_n_cap must be > 0 (got {d.top_n_cap})")
    if not _positive(d.min_healthy):
        out.append(f"dns.min_healthy must be > 0 (got {d.min_healthy})")
    if d.min_healthy > d.top_n_cap:
        out.append(
            f"dns.min_healthy ({d.min_healthy}) cannot exceed dns.top_n_cap "
            f"({d.top_n_cap})"
        )

    cf = cfg.dns.cloudflare
    for name in ("zone_id", "account_id", "domain", "front_door",
                 "api_base", "pool_name", "lb_name"):
        if not getattr(cf, name):
            out.append(f"dns.cloudflare.{name} must be non-empty")
    if not _positive(cf.request_timeout_s):
        out.append(f"dns.cloudflare.request_timeout_s must be > 0 (got {cf.request_timeout_s})")

    c = cfg.cost
    for name in ("hourly_cost", "egress_cost_per_gb", "included_egress_gb"):
        v = getattr(c, name)
        if not _nonneg(v):
            out.append(f"cost.{name} must be >= 0 (got {v})")
    if not _positive(c.overage_penalty):
        out.append(f"cost.overage_penalty must be > 0 (got {c.overage_penalty})")

    b = cfg.brain
    if not _pct(b.cpu_shed_threshold_pct):
        out.append(f"brain.cpu_shed_threshold_pct must be in [0,100] (got {b.cpu_shed_threshold_pct})")
    if not _ratio(b.cpu_shed_penalty):
        out.append(f"brain.cpu_shed_penalty must be in [0,1] (got {b.cpu_shed_penalty})")
    for name in ("cost_open_score", "cost_metered_score_at_zero",
                 "cost_metered_score_at_warn", "cost_metered_score_at_alarm",
                 "cost_metered_score_at_drain"):
        v = getattr(b, name)
        if not _ratio(v):
            out.append(f"brain.{name} must be in [0,1] (got {v})")
    if not (b.cost_metered_warn_ratio <= b.cost_metered_alarm_ratio
            <= b.cost_metered_drain_ratio):
        out.append("brain.cost_metered_* ratios must be monotonic: warn <= alarm <= drain")
    if not _pct(b.fill_spill_headroom_pct):
        out.append(f"brain.fill_spill_headroom_pct must be in [0,100] (got {b.fill_spill_headroom_pct})")
    if not _positive(b.move_sustain_seconds):
        out.append(f"brain.move_sustain_seconds must be > 0 (got {b.move_sustain_seconds})")
    if not _positive(b.move_cooldown_seconds):
        out.append(f"brain.move_cooldown_seconds must be > 0 (got {b.move_cooldown_seconds})")

    o = cfg.orchestrator
    if not _positive(o.max_moves_per_plan):
        out.append(f"orchestrator.max_moves_per_plan must be > 0 (got {o.max_moves_per_plan})")
    if not _positive(o.max_moves_per_target_per_plan):
        out.append(f"orchestrator.max_moves_per_target_per_plan must be > 0 (got {o.max_moves_per_target_per_plan})")
    if not _pct(o.target_min_free_pct):
        out.append(f"orchestrator.target_min_free_pct must be in [0,100] (got {o.target_min_free_pct})")
    if not _pct(o.insufficient_capacity_pct):
        out.append(f"orchestrator.insufficient_capacity_pct must be in [0,100] (got {o.insufficient_capacity_pct})")

    return out


def validate_config_or_raise(cfg: FleetConfig | None = None) -> None:
    """Run :func:`validate_config`; raise ``ValueError`` if anything is wrong.

    Suitable to call from app startup so a misconfig fails the boot
    instead of corrupting state at the first scoring tick.
    """
    errs = validate_config(cfg)
    if errs:
        raise ValueError(
            "fleet.config validation failed:\n  - " + "\n  - ".join(errs)
        )


# ════════════════════════════════════════════════════════════════════════
# 2. canonical endpoint catalogue (the auth-sweep test reads this)
# ════════════════════════════════════════════════════════════════════════


@dataclasses.dataclass(frozen=True)
class FleetEndpoint:
    """One panel-facing fleet endpoint the proxy calls."""

    method: str          # "GET" | "POST"
    path: str            # absolute path (no host)
    purpose: str         # short documentation


#: Every endpoint that MUST require X-Proxy-Token. Adding a new fleet
#: endpoint = adding a row here. The Phase-10 auth-sweep test fails if
#: an entry returns anything other than 401 without the header.
def fleet_proxy_endpoints() -> tuple[FleetEndpoint, ...]:
    return (
        FleetEndpoint("GET",  "/api/proxy/routing-table",
                      "panel → proxy routing table + live_apply_enabled"),
        FleetEndpoint("POST", "/api/proxy/heartbeat",
                      "proxy → panel liveness + metrics"),
        FleetEndpoint("GET",  "/api/proxy/chr-nodes",
                      "panel → proxy: allowed CHR sources"),
        FleetEndpoint("POST", "/api/proxy/telemetry",
                      "proxy → panel: per-node telemetry sample (Phase 4)"),
        FleetEndpoint("GET",  "/api/proxy/placement-decision",
                      "panel → proxy: best target for a user (Phase 5)"),
        FleetEndpoint("POST", "/api/proxy/enforcement",
                      "proxy → panel: enforcement outcome (Phase 7)"),
    )


# ════════════════════════════════════════════════════════════════════════
# 3. default-safe live-apply invariant
# ════════════════════════════════════════════════════════════════════════


def assert_live_apply_default_safe() -> bool:
    """True iff ``fleet.control.live_apply_settings.is_enabled()`` is False
    when no Setting row exists. Callable from CI as a one-shot sanity check.
    """
    from fleet.control.live_apply_settings import is_enabled
    return is_enabled() is False


__all__ = [
    "FleetEndpoint",
    "validate_config",
    "validate_config_or_raise",
    "fleet_proxy_endpoints",
    "assert_live_apply_default_safe",
]
