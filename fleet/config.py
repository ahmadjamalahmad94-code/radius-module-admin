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

    The brain computes ``score = Σ(weight_i * factor_i)`` and then multiplies
    by ``node.weight`` for an operator override knob. Weights are intentionally
    unnormalised here; raising one makes that signal dominate placement.

    Phase 5 adds ``health`` and ``capacity`` to the explicit weight set so the
    Task-A scoring engine can document its full formula here, in ONE place.
    Older fields stay unchanged so any caller already importing them keeps
    working.
    """

    health: float = 2.0
    """Weight on the health factor (1.0 for 'up', 0.5 for 'degraded'/'unknown').
    The biggest single weight so a barely-healthy node never beats a fully-up
    one purely on cheap cost."""

    cpu_headroom: float = 1.0
    """Favour nodes with more spare CPU (1 - cpu_util). Primary load signal."""

    latency: float = 0.8
    """Favour nodes with lower measured RADIUS/round-trip latency to the proxy."""

    capacity: float = 0.8
    """Favour nodes with more free sessions vs their declared ``max_sessions``."""

    session_headroom: float = 0.6
    """Favour nodes carrying fewer active sessions vs their declared capacity.
    (Phase-1 alias kept for compatibility; ``capacity`` is the post-P5 name.)"""

    cost: float = 0.7
    """Weight on the bandwidth-cost factor. Pulled up from the Phase-1 default
    of 0.4 so the "fill unlimited first" preference holds at typical load."""

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
class CloudflareDnsConfig:
    """Cloudflare front-door driver identifiers (Phase 6 Task A).

    These are SAFE-IN-CONFIG identifiers — they live on the panel side, in
    every commit. The Cloudflare API TOKEN is the only secret; it is loaded
    from the fleet secrets vault at runtime via the
    ``(vault_owner, vault_purpose)`` lookup, NEVER hardcoded, NEVER logged.

    Two operating modes the driver supports:

    * **FREE** — plain A-records on ``front_door``. Cloudflare free DNS has
      no per-record weight, so the "weight" field in a desired origin
      collapses to include-or-exclude (drained / down origins are filtered
      out of the record set).
    * **PAID** — Cloudflare Load Balancing origin pools with TRUE graduated
      weights. The driver maintains ONE pool (``pool_name``) attached to
      ONE LB (``lb_name`` on the zone), origins one-per-CHR with their
      configured weight.

    Task C (UI) writes the token's VaultRef into the ``Setting`` row keyed
    by ``token_setting_key`` so a future operator rotation is one UPDATE
    plus one re-encryption — no code change.
    """

    zone_id: str = "8bc55c137bb3eeefef4348b0b51990c5"
    """Cloudflare zone the front-door FQDN lives in. PUBLIC IDENTIFIER."""

    account_id: str = "4db5e3f4c135474a8d26638ce5c9ede4"
    """Cloudflare account that owns the LB pool (PAID mode). PUBLIC IDENTIFIER."""

    domain: str = "hoberadius.com"
    """Apex domain — for docs / sanity checks only."""

    front_door: str = "vpn.hoberadius.com"
    """The FQDN clients resolve to reach the CHR fleet."""

    api_base: str = "https://api.cloudflare.com/client/v4"
    """Cloudflare API root. Overridable for staging / Cloudflare's API mirror."""

    token_setting_key: str = "cloudflare.dns.token_ref"
    """``Setting`` row whose value holds the VaultRef for the API token. When
    the row is missing or empty, the driver runs in DRY-RUN mode (compute the
    intended API calls, return them, but never send)."""

    vault_owner: str = "cloudflare:dns"
    """Vault ``owner`` slot the token lives under. Stable so Task C's UI knows
    exactly where to write."""

    vault_purpose: str = "api_token"
    """Vault ``purpose`` slot — distinguishes the API token from any future
    secrets the driver might park (e.g. a Webhook signing key)."""

    pool_name: str = "hoberadius-chr-fleet"
    """The PAID-mode LB pool name. Idempotency hinges on it: the driver
    upserts the pool of this exact name on every apply."""

    lb_name: str = "vpn.hoberadius.com"
    """The PAID-mode load balancer FQDN — same as ``front_door``. The two
    are kept as distinct fields so a deployment can split them in future."""

    request_timeout_s: float = 10.0
    """HTTP timeout per request. Cloudflare's 95th-percentile is well below
    1 s in practice; 10 s leaves wide headroom for retried requests."""


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

    cloudflare: CloudflareDnsConfig = field(default_factory=CloudflareDnsConfig)
    """Cloudflare-specific identifiers + vault keys (see :class:`CloudflareDnsConfig`)."""


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
# Brain — scoring thresholds + movement hysteresis (fleet.brain)
# ──────────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class BrainConfig:
    """Thresholds the Phase-5 scoring engine reads directly.

    Two clusters of knobs:

    1. **Scoring shape** — how each per-factor curve scales between 0.0 and 1.0,
       plus the CPU-shed escalation. These are floats kept here (NOT in
       ``ScoringWeights``) so the weights remain pure multipliers.

    2. **Movement hysteresis** — the rebalance-side ``should_move`` helper
       only signals a move when a user has been over-threshold for at least
       ``move_sustain_seconds`` AND no move has fired for that user within
       the last ``move_cooldown_seconds``. Together they make ping-pong
       impossible: a flap that drops back under the threshold within the
       sustain window never triggers a move at all.
    """

    # ── CPU penalty / shedding ──────────────────────────────────────────
    cpu_shed_threshold_pct: float = 70.0
    """Mirrors :attr:`HealthConfig.cpu_shed_threshold_pct` so the brain can be
    tuned without coupling the two configs. At/above this CPU% the node is
    SHEDDING — its CPU factor drops by ``cpu_shed_penalty`` so it stops
    attracting new placements (it stays eligible; it just falls in rank)."""

    cpu_shed_penalty: float = 0.85
    """Multiplicative penalty applied to the CPU factor once cpu_pct meets
    or exceeds ``cpu_shed_threshold_pct``. 0.85 ≈ "heavy" — a CPU-shedding
    node's CPU factor collapses by this fraction, dropping its overall score
    well below a similarly-loaded healthy peer's."""

    # ── Cost / bandwidth-cap curve ──────────────────────────────────────
    cost_open_score: float = 1.0
    """Cost factor for ``open`` / unlimited providers. Always the ceiling."""

    cost_metered_score_at_zero: float = 0.75
    """Cost factor for a metered provider with 0 GB used. Strictly less than
    ``cost_open_score`` so any healthy unlimited node out-scores a brand-new
    metered one on the cost axis (drives "fill unlimited first")."""

    cost_metered_warn_ratio: float = 0.5
    cost_metered_score_at_warn: float = 0.4
    """At 50% of the metered cap the cost factor is already deeply penalised."""

    cost_metered_alarm_ratio: float = 0.8
    cost_metered_score_at_alarm: float = 0.15
    """At 80% of the metered cap the cost factor is near zero — the brain
    will only place here when no unlimited node is eligible."""

    cost_metered_drain_ratio: float = 1.0
    """At ≥ this fraction of the metered cap the node is treated as DRAIN
    (eligible=False) — see :meth:`NodeScore.eligible`. ``overage_allowed``
    on the provider does NOT change this; an opt-in overage policy is a
    Phase-6+ concern."""

    cost_metered_score_at_drain: float = 0.0
    """Cost factor at the drain boundary. Reported for explainability even
    though the node is filtered out before its score is consumed."""

    # ── Fill-unlimited-first preference ─────────────────────────────────
    fill_unlimited_first: bool = True
    """When True, ``rank()`` uses a TWO-TIER ordering: any unlimited node
    with ≥ ``fill_spill_headroom_pct`` of session capacity free sits in
    Tier 0; everything else (including unlimited nodes that are NEARLY full
    and ALL metered nodes) drops to Tier 1. Within each tier, sort by
    score desc. Result: metered nodes never out-rank an unlimited node
    that still has room."""

    fill_spill_headroom_pct: float = 30.0
    """An unlimited node "still has room" iff its free-sessions ratio
    (``1 - active/max_sessions``) is ≥ this percentage. Below it, the
    unlimited node falls into Tier 1 alongside metered nodes — i.e. we
    "spill" only when the entire unlimited fleet is near-full."""

    # ── Movement hysteresis (for the rebalance path) ────────────────────
    move_sustain_seconds: int = 180
    """A user must stay over-threshold for this long (default 3 min) BEFORE
    a move is signalled. A flap that drops back under threshold within this
    window is suppressed entirely. The :func:`should_move` helper enforces
    this from a per-user state dataclass; new placements ignore it (they
    just pick best eligible)."""

    move_cooldown_seconds: int = 600
    """After a user is moved, no further move for that user can be signalled
    until this much time has passed (default 10 min). Caps ping-pong even
    if a flapping node keeps tripping the sustain window."""


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
    brain: BrainConfig = field(default_factory=BrainConfig)


# Canonical default instance. Import this; do not mutate (frozen).
FLEET = FleetConfig()
