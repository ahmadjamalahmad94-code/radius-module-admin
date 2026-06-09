"""fleet.config — central declaration of every CHR-fleet tunable with documented defaults.

Phase 1 deliverable: STRUCTURE + DOCSTRINGS ONLY. No behaviour reads these yet —
later phases (health/brain/dns/control) import from here so there is exactly one
place to tune the fleet. Values are conservative, production-sane defaults; any of
them may be overridden from app config / Settings UI in a later phase.

Conventions:
  * All durations are in **seconds** unless the name ends in ``_MS``.
  * All thresholds that represent a ratio are floats in ``[0.0, 1.0]`` unless the
    name ends in ``_PCT`` (then they are 0–100).
  * Dataclasses are frozen: they are declarative config, not mutable state.
"""
from __future__ import annotations

from dataclasses import dataclass, field


# ──────────────────────────────────────────────────────────────────────────────
# Scoring (fleet.brain)
# ──────────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class ScoringWeights:
    """Relative weights combined into a single node score (higher = better pick).

    The brain computes ``score = Σ(weight_i * normalised_metric_i)``. Weights are
    intentionally unnormalised here; the brain normalises so they need not sum to 1.
    Raise a weight to make that signal dominate placement.
    """

    cpu_headroom: float = 1.0
    """Favour nodes with more spare CPU (1 - cpu_util). Primary load signal."""

    latency: float = 0.8
    """Favour nodes with lower measured RADIUS/round-trip latency to the proxy."""

    session_headroom: float = 0.6
    """Favour nodes carrying fewer active sessions vs their declared capacity."""

    cost: float = 0.4
    """Penalise more expensive nodes (see CostModel). Keeps cheap capacity preferred."""

    stickiness: float = 0.3
    """Bias toward a user's CURRENT node to avoid needless churn (hysteresis)."""


# ──────────────────────────────────────────────────────────────────────────────
# Health state machine (fleet.health)
# ──────────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class HealthConfig:
    """Up/down flap-damping for the per-node telemetry state machine."""

    cpu_shed_threshold_pct: float = 70.0
    """At/above this CPU utilisation the brain starts SHEDDING new placements off
    the node (it stays UP and keeps existing sessions; it just stops attracting more)."""

    down_after: int = 300
    """A node must be unhealthy/silent for this many seconds before it is marked DOWN
    (~5 min). Damps transient blips so we don't evacuate on a single missed beat."""

    up_after: int = 300
    """A previously-DOWN node must be continuously healthy this long before it is
    marked UP again (~5 min). Prevents flapping back too eagerly."""

    cooldown: int = 300
    """Minimum seconds between consecutive state transitions for the same node
    (~5 min). Hard floor on flap frequency regardless of telemetry."""

    telemetry_stale_after: int = 90
    """If no telemetry sample has arrived within this window, treat the node as
    silent (feeds DOWN_AFTER). Should be a small multiple of the agent's push period."""


# ──────────────────────────────────────────────────────────────────────────────
# Placement / rebalance (fleet.brain)
# ──────────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class PlacementConfig:
    """When the brain re-scores and how aggressively it moves users."""

    score_interval: int = 30
    """How often (seconds) the brain recomputes scores and the top-N set."""

    rebalance_margin: float = 0.15
    """A user is only moved off their current node when an alternative scores at
    least this fraction better (0.15 = 15%). Hysteresis against thrashing."""

    per_user_movable_default: bool = True
    """Default for whether a user's live session may be relocated via CoA. Can be
    overridden per-user/per-plan later (some realms pin to a node)."""

    max_moves_per_cycle: int = 50
    """Safety cap on how many users the control layer will relocate in one cycle,
    so a big rebalance rolls out gradually instead of stampeding."""


# ──────────────────────────────────────────────────────────────────────────────
# DNS steering (fleet.dns)
# ──────────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class DnsConfig:
    """How the brain's decision is published as DNS for client steering."""

    ttl: int = 30
    """TTL (seconds) on published answers. Low so clients re-resolve quickly when
    the top-N set changes."""

    top_n_cap: int = 8
    """Maximum number of node IPs returned in a single answer set. Caps answer size
    and spreads load across at most N best nodes."""

    min_healthy: int = 1
    """Never publish fewer than this many nodes (as long as any are UP); avoids
    accidentally black-holing a realm when scores are close to threshold."""


# ──────────────────────────────────────────────────────────────────────────────
# Cost model (fleet.registry → consumed by fleet.brain scoring)
# ──────────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class CostModel:
    """Per-node cost inputs the scorer uses to prefer cheaper capacity.

    Stored per node in the registry; these are the DEFAULTS applied when a node
    does not declare its own. Units are nominal ("cost points") — only relative
    magnitudes matter to scoring.
    """

    hourly_cost: float = 0.0
    """Fixed cost to keep the node running for one hour (VPS/instance price)."""

    egress_cost_per_gb: float = 0.0
    """Marginal cost per GB of egress traffic through the node."""

    included_egress_gb: float = 0.0
    """Egress allowance before ``egress_cost_per_gb`` starts applying."""

    overage_penalty: float = 2.0
    """Multiplier applied to the cost signal once a node exceeds its included
    egress, to steer new placements away from nodes about to incur overage."""


# ──────────────────────────────────────────────────────────────────────────────
# Aggregate
# ──────────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class FleetConfig:
    """Single import surface for the whole fleet. Later phases do::

        from fleet.config import FLEET
        if cpu >= FLEET.health.cpu_shed_threshold_pct: ...
    """

    scoring: ScoringWeights = field(default_factory=ScoringWeights)
    health: HealthConfig = field(default_factory=HealthConfig)
    placement: PlacementConfig = field(default_factory=PlacementConfig)
    dns: DnsConfig = field(default_factory=DnsConfig)
    cost: CostModel = field(default_factory=CostModel)


# Canonical default instance. Import this; do not mutate (frozen).
FLEET = FleetConfig()
