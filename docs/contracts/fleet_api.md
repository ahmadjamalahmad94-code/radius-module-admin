# Fleet API — frozen contracts (Phase 1)

Status: **FROZEN** for Phase 1. Later phases implement against the shapes below.
Breaking changes require a contract bump + sign-off at the phase gate.

This document freezes:

1. **Ingest HTTP APIs** the `radius-proxy` agent / CHR nodes call on the panel:
   - `POST /api/proxy/telemetry` — per-node health/load samples.
   - `POST /api/proxy/placement` — placement-event feedback from the proxy.
2. **CoA / Disconnect** — the control-plane action the panel asks the proxy to apply.
3. **Internal `fleet/*` interface signatures** — the function/method contracts the
   panel-side packages expose to each other.

---

## 0. Authentication — `X-Proxy-Token` (reused, unchanged)

All ingest endpoints reuse the **existing** proxy HMAC scheme implemented in
[`app/api/proxy_api.py`](../../app/api/proxy_api.py) (`_verify_proxy_token`). No new
auth is introduced in Phase 1.

```
X-Proxy-Token: <timestamp>:<nonce>:<hmac>

  timestamp  integer unix seconds
  nonce      random string, unique within the TTL window (replay-protected)
  hmac       HMAC_SHA256( key = RADIUS_PROXY_SHARED_SECRET,
                          msg = f"{timestamp}:{nonce}" ).hexdigest()
```

- Acceptance window: `RADIUS_PROXY_TOKEN_TTL` seconds (default **60**).
- Replay protection: `(timestamp:nonce)` cached for the TTL; a repeat is rejected.
- Missing/empty `RADIUS_PROXY_SHARED_SECRET` ⇒ **deny all** (401).
- Auth failure response (all endpoints):

```json
{ "ok": false, "error": "unauthorized" }      // HTTP 401
```

### Common envelope

Every fleet ingest response uses the same envelope as the existing proxy API:

```json
{ "ok": true,  ... }                          // success
{ "ok": false, "error": "<machine_code>", "detail": "<human, optional>" }
```

Standard error codes: `unauthorized` (401), `bad_request` (400, malformed/missing
fields), `unknown_node` (404, node not enrolled), `rate_limited` (429),
`server_error` (500). Timestamps are ISO-8601 UTC with `Z` suffix.

---

## 1. Telemetry ingest — `POST /api/proxy/telemetry`

Per-node health + load sample. Pushed by the proxy/agent on each `SCORE_INTERVAL`
tick (or faster). Feeds `fleet.health` (state machine) and `fleet.brain` (scoring).

### Request

```json
{
  "node": "chr-exit-01",                  // required — registry node name (unique)
  "sampled_at": "2026-06-09T19:40:00Z",   // required — when the sample was taken
  "metrics": {
    "cpu_util": 0.62,                     // 0.0–1.0 — feeds cpu_shed_threshold + scoring
    "mem_util": 0.41,                     // 0.0–1.0
    "active_sessions": 1280,              // int    — current live sessions on the node
    "session_capacity": 4000,            // int    — declared max (for session_headroom)
    "latency_ms": 18.4,                   // float  — measured RTT proxy→node
    "egress_gbps": 0.74,                  // float  — instantaneous egress
    "egress_gb_period": 512.0,            // float  — egress used in the current cost period
    "uptime_seconds": 86400               // int
  },
  "agent_version": "1.0.0"                // optional — for compat gating
}
```

Notes:
- `node` MUST match an enrolled registry node; unknown ⇒ `unknown_node` (404).
- Any individual metric MAY be omitted; the scorer treats missing signals as
  neutral (does not penalise). `cpu_util` and `active_sessions` are STRONGLY
  recommended (health + shed depend on them).

### Response

```json
{
  "ok": true,
  "node": "chr-exit-01",
  "accepted_at": "2026-06-09T19:40:00Z",
  "health": "up",                         // up | shedding | down  (post-sample state)
  "directives": {                          // hints the node MAY act on; advisory only
    "shed": false,                         // true once cpu_util ≥ cpu_shed_threshold_pct
    "drain": false                         // true if the brain is evacuating this node
  }
}
```

---

## 2. Placement ingest — `POST /api/proxy/placement`

Feedback from the proxy reporting where a user/session was actually placed (or that
a requested move completed/failed). Closes the loop so `fleet.brain` knows the
realised state vs its intended decision.

### Request

```json
{
  "proxy_id": "proxy-01",                 // required
  "reported_at": "2026-06-09T19:40:05Z",  // required
  "placements": [                          // required — batch; 1..N items
    {
      "session_id": "a1b2c3",             // required — proxy/NAS session identifier
      "realm": "client5",                 // required
      "username": "user@client5",         // optional
      "node": "chr-exit-02",              // required — node the session is now on
      "previous_node": "chr-exit-01",     // optional — null on first placement
      "reason": "rebalance",              // new | rebalance | shed | failover | manual
      "result": "applied",               // applied | rejected | pending
      "detail": ""                         // optional — error text when rejected
    }
  ]
}
```

### Response

```json
{
  "ok": true,
  "received": 1,                          // count accepted from the batch
  "ack": {
    "proxy_id": "proxy-01",
    "server_time": "2026-06-09T19:40:05Z",
    "rejected": []                         // session_ids that failed validation, if any
  }
}
```

---

## 3. CoA / Disconnect (control plane)

The panel does NOT speak RADIUS CoA directly to NAS devices in Phase 1; it asks the
proxy to apply **RFC 5176** Change-of-Authorization / Disconnect-Request. This freezes
the *intent* shape `fleet.control` emits; transport (pull via routing-table vs push
endpoint) is finalised in a later phase. Both directions are listed so implementers
agree on the field set.

### 3a. Action object (emitted by `fleet.control`)

```json
{
  "action": "coa",                        // coa | disconnect
  "session_id": "a1b2c3",                 // required
  "realm": "client5",                     // required
  "target_node": "chr-exit-02",           // required for coa (where to move the session)
  "reason": "rebalance",                  // rebalance | shed | failover | manual | drain
  "attributes": {                          // RFC 5176 attrs the proxy should set on CoA
    "Tunnel-Server-Endpoint": "x.x.x.x"    // example — exact set finalised later phase
  },
  "issued_at": "2026-06-09T19:40:05Z",
  "deadline": "2026-06-09T19:40:35Z"       // best-effort apply-by; expires after
}
```

- `action: "disconnect"` omits `target_node`/`attributes` (it just tears the session
  down so the client re-resolves DNS and reconnects to a top-N node).
- Results flow back via **§2 placement ingest** (`reason` mirrors the action reason;
  `result` = `applied|rejected|pending`).

---

## 4. Internal `fleet/*` interface signatures (frozen)

Panel-side package contracts. Phase 1 declares the **signatures + semantics**;
bodies land in later phases. Types are illustrative (TypedDict/dataclass names are
not binding — field sets above are).

### 4.1 `fleet.registry` — node source of truth

```python
def list_nodes(*, status: str | None = None) -> list[Node]: ...
    # All enrolled nodes, optionally filtered by lifecycle status
    # ("active" | "draining" | "disabled").

def get_node(name: str) -> Node | None: ...
    # Single node by unique registry name; None if not enrolled.

def upsert_node(spec: NodeSpec) -> Node: ...
    # Enrol or update a node (capabilities, capacity, cost model). Idempotent on name.

def set_status(name: str, status: str) -> Node: ...
    # Lifecycle transition (active/draining/disabled). Raises if node unknown.

def cost_for(name: str) -> CostModel: ...
    # The node's effective cost model (its own, else fleet.config.CostModel default).
```

### 4.2 `fleet.health` — telemetry + state machine

```python
def ingest(node: str, sampled_at: datetime, metrics: dict) -> HealthState: ...
    # Apply one telemetry sample; returns post-sample state. Backs §1.

def state_of(node: str) -> HealthState: ...
    # Current state: "up" | "shedding" | "down" (+ since/last_sample timestamps).

def healthy_nodes() -> list[str]: ...
    # Names currently "up" (excludes shedding/down). Consumed by the brain/dns.

def evaluate(now: datetime) -> list[HealthTransition]: ...
    # Run DOWN_AFTER/UP_AFTER/cooldown timers; returns transitions that just fired
    # (drives fleet.notify). Idempotent within a cooldown window.
```

### 4.3 `fleet.brain` — scoring + placement

```python
def score(node: str) -> float: ...
    # Single-node score from current telemetry × ScoringWeights. Higher = better.

def rank(realm: str | None = None) -> list[ScoredNode]: ...
    # Healthy nodes sorted best-first (optionally constrained to a realm's allowed set).

def top_n(realm: str | None = None, n: int | None = None) -> list[str]: ...
    # Best up-to-N node names for DNS (n defaults to DnsConfig.top_n_cap).

def decide(now: datetime) -> list[PlacementDecision]: ...
    # Compute moves: shed (cpu ≥ threshold), failover (node down), rebalance
    # (alternative beats current by ≥ REBALANCE_MARGIN). Honours
    # per_user_movable + max_moves_per_cycle. Output feeds fleet.control.
```

### 4.4 `fleet.dns` — steering publication

```python
def publish(records: dict[str, list[str]]) -> PublishResult: ...
    # Publish realm/zone → ordered node IPs at DnsConfig.ttl. Backs DNS steering.

def current() -> dict[str, list[str]]: ...
    # Last published answer set (for diffing / introspection).

def reconcile(now: datetime) -> PublishResult: ...
    # Recompute top_n per zone and publish only if changed (min_healthy guard).
```

### 4.5 `fleet.control` — CoA / Disconnect application

```python
def apply(decisions: list[PlacementDecision]) -> list[ControlResult]: ...
    # Translate decisions into §3 action objects and dispatch via the proxy.

def disconnect(session_id: str, realm: str, reason: str = "manual") -> ControlResult: ...
    # Force a single session to re-resolve (tear down; client reconnects to top-N).

def record_feedback(placements: list[dict]) -> None: ...
    # Ingest §2 placement results; reconcile intended vs realised state.
```

### 4.6 `fleet.notify` — operator/customer notifications

```python
def on_transition(t: HealthTransition) -> None: ...
    # Node up/down/shedding crossed a threshold → notify operators via messaging layer.

def on_rebalance(summary: RebalanceSummary) -> None: ...
    # Summarise a rebalance cycle (counts moved, reasons) for the operator feed.

def on_capacity_alert(node: str, kind: str, detail: str) -> None: ...
    # CPU shed / egress overage / capacity-exhaustion alerts. kind ∈
    # {"cpu_shed","egress_overage","capacity"}.
```

---

## 5. Routing table — `GET /api/proxy/routing-table`

The proxy pulls its full routing table from the panel (auth: `X-Proxy-Token`, §0).
Implemented in `app/api/proxy_api.py`.

### Response

```json
{
  "ok": true,
  "generated_at": "2026-06-09T19:40:00Z",
  "route_count": 1,
  "routes": [
    {
      "realm": "client5",
      "customer_id": 3,
      "target_ip": "10.200.5.2",
      "auth_port": 1812,
      "acct_port": 1813,
      "secret": "<actual radius shared secret>",
      "allowed_chr_ips": ["x.x.x.x"]      // empty = all CHR nodes
    }
  ],
  "chr_nodes": [
    {
      "name": "chr-exit-01",              // registry node NAME — telemetry/placement key by this
      "public_ip": "x.x.x.x",
      "management_ip": "10.99.0.11",
      "status": "active",
      "enabled_services": ["sstp"]
    }
  ]
}
```

> **`chr_nodes[].name` (contract gap #1, Phase-4):** each entry MUST carry the
> registry node `name`. Telemetry (`POST /api/proxy/telemetry`, §1) and placement
> (`POST /api/proxy/placement`, §2) key by node name, so the proxy needs the name
> here to correlate a routing-table CHR with the node it reports telemetry for.
> `name` is **additive** — `public_ip` and the other fields are unchanged.

---

## 6. Placement-decision read — `GET /api/proxy/placement-decision`

The proxy's `resolve_decision` consults the panel for the brain's headline
placement choice + the top-N ranking. **Read-only and advisory**: it does not
move any session; the actuation contract is §2 placement ingest (proxy reports
back what it did) and §3 CoA / Disconnect (panel asks the proxy to act). This
endpoint closes contract gap #2 — the proxy was already calling it with a
local fallback while the panel side was unimplemented.

### Request

`GET /api/proxy/placement-decision?realm=<realm>&current_node=<name>&n=<int>`

| Param | Type | Default | Notes |
|---|---|---|---|
| `realm` | str (≤80 chars, `[A-Za-z0-9-_.@]`) | absent ⇒ global | Constrain the eligible set to nodes a realm is allowed to use. |
| `current_node` | str (≤120 chars) | absent | Node the realm is currently served from. **Audit-only** in Phase 5 — the proxy passes it so the recorded decision row carries `from_chr_id`. The brain MAY use it for stickiness in a later revision; the local stub ignores it. |
| `n` | int 1..32 | `3` | Size of the `top_n` array. |

Auth: `X-Proxy-Token` HMAC (§0). Missing/bad ⇒ 401.

### Response (success — HTTP 200)

```json
{
  "ok": true,
  "decision": "chr-exit-02",                // node NAME (or null when no eligible node)
  "top_n": [
    {
      "node": "chr-exit-02",                // registry name
      "score": 0.91,                        // higher = better; absolute scale is the brain's
      "reasons": {                          // free-form per-factor breakdown from the brain
        "cpu_headroom": 0.74,
        "session_headroom": 0.83,
        "cost": 0.40,
        "stickiness": 0.30
      }
    },
    {
      "node": "chr-exit-01",
      "score": 0.78,
      "reasons": { "...": "..." }
    }
  ]
}
```

### No eligible node

```json
{ "ok": true, "decision": null, "top_n": [] }       // HTTP 200 — empty fleet OR all draining
```

### Error envelope

```json
{ "ok": false, "error": "unauthorized" }           // HTTP 401 — bad/missing X-Proxy-Token
{ "ok": false, "error": "bad_request",
  "detail": "n must be in [1, 32]" }                // HTTP 400 — malformed query params
{ "ok": false, "error": "server_error",
  "detail": "placement decision persist failed" }   // HTTP 500 — only if persistence crashes
```

### Side effect — audit row

Every served response inserts one `fleet_placement_decisions` row with
`kind='new'`, `outcome='pending'` (the brain proposed; actuation is reported
back via §2). `from_chr_id` resolves `current_node`; `to_chr_id` resolves
`decision`. `reason_json` snapshots `realm`, `current_node`, `decision`, and
the full `top_n` so the proposal is fully reconstructible after the fact.
`username` is set to `f"realm:{realm}"` (or `"__proxy_realm_query__"` when
realm is absent) so audit-log greps can collapse them.

### Brain-API delegation

The endpoint is a thin shell over `fleet.brain.brain_adapter.best_node()` +
`top_n()`. The adapter consumes the frozen brain interface

```python
best_node(realm: str | None = None)        -> NodeScore | None
top_n   (realm: str | None = None, n: int) -> list[NodeScore]

@dataclass(frozen=True)
class NodeScore:
    name:    str             # fleet_chr_nodes.name
    score:   float           # higher = better
    reasons: dict[str, Any]  # per-factor breakdown
```

When the real brain module is available it is used as-is; otherwise the
adapter falls back to a local stub that ranks `fleet_chr_nodes` by their
denormalised `score` column over the eligible set (`status='up'`, `enabled`,
not `drain`) — same shape, lower fidelity. The wire contract is identical
either way; the dashboard inspects `fleet.brain.brain_adapter.BRAIN_BACKEND`
to show which is live.

---

## Change log

- **Phase 1** — initial freeze: telemetry ingest, placement ingest, CoA/Disconnect
  intent, and the six `fleet/*` interface signatures. Auth reuses `X-Proxy-Token`.
- **Phase 4** — documented `GET /api/proxy/routing-table` (§5); froze
  `chr_nodes[].name` (gap #1) so the proxy can correlate routing-table CHRs with
  telemetry/placement (which key by node name). Telemetry's `health` field now
  defers to the monitor's authoritative hysteresis state (`monitor.state_of`).
- **Phase 5** — froze `GET /api/proxy/placement-decision` (§6, contract gap #2):
  proxy-facing read endpoint that returns the brain's headline `decision` (a
  node name or `null`) plus the `top_n` ranking with `score` + `reasons` per
  node. Same `X-Proxy-Token` auth. Every served response is recorded into
  `fleet_placement_decisions` as `kind='new'`/`outcome='pending'` (advisory; the
  proxy still actuates via §2 placement ingest + §3 CoA). The endpoint is a
  thin shell over `fleet.brain.brain_adapter` which delegates to the real brain
  when available and falls back to a score-column stub otherwise; the wire
  shape is identical either way.
