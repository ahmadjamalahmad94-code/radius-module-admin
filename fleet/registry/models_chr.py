"""fleet.registry.models_chr — ORM models for the fleet registry core.

Tables (schema = docs/chr_fleet/02_DATA_MODEL.md §2.2–§2.3, owned by this panel):

  * ``fleet_providers``  — hosting companies + cost model (doc §2.2 "providers")
  * ``fleet_chr_nodes``  — each CHR exit node: identity, capacity, weights,
                           live snapshot (doc §2.3 "chr_nodes")

IMPORTANT — table naming. The blueprint calls these ``providers``/``chr_nodes``,
but this panel ALREADY owns a table named ``chr_nodes`` (the older CHR-console /
proxy registry: app.models.ChrNode, with ChrNodeMetric + ServiceAllocation FKs).
Reusing that name would clobber a live feature. The CHR Fleet is a distinct
subsystem, so its tables are namespaced with a ``fleet_`` prefix. Column semantics
match the doc exactly; only the table names are prefixed to avoid the collision.

Cross-dialect notes (the panel runs SQLite in tests, PostgreSQL in prod):
  * BIGSERIAL/BIGINT id  -> BigInteger with a SQLite Integer variant (so SQLite
    autoincrement / rowid-alias works; PostgreSQL still gets BIGINT).
  * INET                 -> String(45) (holds IPv4 + IPv6). Prod MAY later migrate
    to a native INET column; semantics are identical.
  * TIMESTAMPTZ          -> DateTime (naive UTC via models.utcnow()).
  * CHECK / UNIQUE / partial indexes are declared dialect-aware so both enforce them.

The idempotent table/view creation ("migration", in the panel's
db.create_all()/ensure_schema_compatibility style) lives in
``migrations/001_providers_chr_nodes.py``. This module is models ONLY.
"""
from __future__ import annotations

from app.extensions import db
from app.models import TimestampMixin, utcnow

# BIGSERIAL/BIGINT primary & foreign keys: BigInteger on PostgreSQL, Integer on
# SQLite (so AUTOINCREMENT / rowid-alias works there). One shared type instance is
# fine — SQLAlchemy types are not bound to a single column.
BigIntID = db.BigInteger().with_variant(db.Integer, "sqlite")

# Allowed-value vocabularies (kept here so models + callers share one source).
PROVIDER_COST_MODELS = ("open", "metered")
NODE_COST_MODELS = ("inherit", "open", "metered")
NODE_STATUSES = ("provisioning", "up", "degraded", "down", "disabled")


class FleetProvider(TimestampMixin, db.Model):
    """A hosting company and its bandwidth cost model (doc §2.2).

    ``cost_model`` / ``price_per_tb`` / ``monthly_cap_tb`` feed the cost penalty in
    the scoring brain. A node may inherit these or override them (see ChrNode).
    """

    __tablename__ = "fleet_providers"
    __table_args__ = (
        db.CheckConstraint(
            "cost_model IN ('open','metered')", name="ck_fleet_providers_cost_model"
        ),
    )

    id = db.Column(BigIntID, primary_key=True)
    name = db.Column(db.String(120), nullable=False, unique=True)  # "Contabo", "Hetzner"
    cost_model = db.Column(db.String(16), nullable=False)          # 'open' | 'metered'
    price_per_tb = db.Column(db.Numeric(10, 2), nullable=False, default=0)  # USD/TB (metered)
    monthly_cap_tb = db.Column(db.Numeric(12, 3))                  # NULL = unlimited (open)
    overage_allowed = db.Column(db.Boolean, nullable=False, default=False)  # may exceed cap (paid)?
    overage_price_per_tb = db.Column(db.Numeric(10, 2))           # price beyond cap
    billing_cycle_day = db.Column(db.SmallInteger, nullable=False, default=1)  # day cap resets
    api_creds_ref = db.Column(db.String(255))                     # vault key for provider API (optional)

    # Callable target (not a string): two "ChrNode" classes exist on this registry
    # (app.models.ChrNode + this one), so a string name would be ambiguous.
    nodes = db.relationship(
        lambda: FleetChrNode, back_populates="provider", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"<Provider {self.id} {self.name!r} {self.cost_model}>"


class FleetChrNode(TimestampMixin, db.Model):
    """A single CHR exit node — the heart of the registry (doc §2.3).

    Holds network identity, declared capacity (from the onboarding wizard),
    operator-tunable weights, and a denormalized live snapshot updated by the
    metrics loop. ``cost_model='inherit'`` means "use the provider's cost/cap";
    otherwise the node-level override wins (resolved by the fleet_chr_effective view).
    """

    __tablename__ = "fleet_chr_nodes"
    __table_args__ = (
        db.UniqueConstraint("provider_id", "name", name="uq_fleet_chr_nodes_provider_name"),
        db.CheckConstraint(
            "cost_model IN ('inherit','open','metered')", name="ck_fleet_chr_nodes_cost_model"
        ),
        db.CheckConstraint(
            "status IN ('provisioning','up','degraded','down','disabled')",
            name="ck_fleet_chr_nodes_status",
        ),
        # Only enabled nodes (drains are excluded from steering).
        db.Index(
            "idx_fleet_chr_status",
            "status",
            sqlite_where=db.text("enabled"),
            postgresql_where=db.text("enabled"),
        ),
        # Hot path for the brain's "best up node" lookup.
        db.Index(
            "idx_fleet_chr_score",
            "score",
            sqlite_where=db.text("status = 'up'"),
            postgresql_where=db.text("status = 'up'"),
        ),
    )

    id = db.Column(BigIntID, primary_key=True)
    provider_id = db.Column(BigIntID, db.ForeignKey("fleet_providers.id"), nullable=False)
    name = db.Column(db.String(120), nullable=False)              # owner-given label

    # ── network identity ──────────────────────────────────────────────────────
    public_ip = db.Column(db.String(45), nullable=False, unique=True)   # front-door + RADIUS source
    public_ipv6 = db.Column(db.String(45))                              # optional AAAA candidate
    wg_mgmt_ip = db.Column(db.String(45), nullable=False, unique=True)  # control-plane address
    wg_mgmt_pubkey = db.Column(db.Text, nullable=False)                 # CHR WireGuard public key
    # CHR's wg-DATA public key (RADIUS data plane → proxy). Denormalized here
    # (feat/fleet-zero-touch-sync) so the proxy wg-peers publisher and the
    # panel-host peer reconcile never have to reach back into the onboarding
    # job's wg_keypair_ref JSON. Written at generate_keys() time; backfilled
    # from job refs for pre-existing rows in ensure_schema_compatibility.
    # Empty string = unknown (older row whose job ref is gone) — the publisher
    # skips a node with no data pubkey rather than fabricate a peer.
    wg_data_pubkey = db.Column(db.Text, nullable=False, default="", server_default="")
    # Set TRUE whenever the panel's wg-mgmt pubkey changes (key drift) so the
    # script this node carries is known-stale and MUST be re-imported. The
    # zero-touch re-sync clears it once a freshly-rendered script (carrying the
    # CURRENT panel pubkey) is applied. This is the missing flag that let the
    # panel_key_mismatch incident go silent (see fleet/health/wg_verify.py).
    needs_reimport = db.Column(
        db.Boolean, nullable=False, default=False, server_default=db.text("FALSE")
    )
    # fix/fleet-wireguard-provisioning (BUG B): snapshot of the LIVE control-
    # server wg-mgmt pubkey and LIVE proxy wg-data pubkey that were embedded
    # into THIS node's last rendered script. Set by OnboardingService.render
    # using fleet.sync.wg_apply.read_live_panel_pubkey() (and the proxy-key
    # equivalent). Diverging from the panel's stored ``PANEL_WG_PUBKEY`` is
    # the chr-vpn-1/2 root-cause signal: the script the operator imported
    # trusted a stale key, so the CHR's wg-mgmt peer rejected the panel's
    # handshake forever. Empty string ⇒ never rendered yet (or helper was
    # absent and the renderer fell back to the stored key).
    control_wg_public_key_snapshot = db.Column(
        db.Text, nullable=False, default="", server_default=""
    )
    proxy_wg_public_key_snapshot = db.Column(
        db.Text, nullable=False, default="", server_default=""
    )
    # RouterOS REST API port we use for live metrics polling. Default 8443
    # because the production deploy occupies 443 with SSTP; the unified
    # provisioning script enables ``www-ssl`` on this port and binds it to
    # the wg-mgmt address (NOT WAN). Existing rows that defaulted to 8729
    # (the binary-API port — we use REST, not binary) keep working: the
    # poller treats this as authoritative per node.
    routeros_api_port = db.Column(db.Integer, nullable=False, default=8443)
    # Per-CHR API credentials for the live-metrics poller. Mirrors the
    # legacy ``app.models.ChrNode.routeros_password_enc`` storage pattern:
    # plaintext password is NEVER written to disk; the column holds a
    # Fernet ciphertext encrypted with the same panel master key the
    # customer vault uses (``WHATSAPP_FERNET_KEY``). Decryption goes
    # through :func:`fleet.health.routeros_creds.decrypt_password`.
    routeros_api_user = db.Column(db.String(80), nullable=False, default="",
                                  server_default="")
    routeros_api_password_enc = db.Column(db.Text, nullable=False, default="",
                                          server_default="")
    coa_port = db.Column(db.Integer, nullable=False, default=3799)

    # ── declared capacity (from onboarding wizard) ────────────────────────────
    max_sessions = db.Column(db.Integer, nullable=False)               # declared hard cap
    link_speed_mbps = db.Column(db.Integer, nullable=False)            # uplink speed
    bandwidth_cap_tb = db.Column(db.Numeric(12, 3))                    # NULL = inherit provider
    cost_model = db.Column(db.String(16), nullable=False, default="inherit")
    price_per_tb = db.Column(db.Numeric(10, 2))                        # override provider price
    overage_allowed = db.Column(db.Boolean)                           # override provider flag

    # ── operator-tunable weights ──────────────────────────────────────────────
    weight = db.Column(db.Numeric(5, 2), nullable=False, default=1.0)  # manual preference multiplier
    enabled = db.Column(db.Boolean, nullable=False, default=True)      # admin on/off (drains, not deletes)
    drain = db.Column(db.Boolean, nullable=False, default=False)       # accept no new sessions
    # CUSTOMER_RADIUS_TUNNEL_DESIGN §10 — node ROLES are a SET, not a
    # single value. A 1-Gbps VPS used only for RADIUS-transport (~5 M)
    # wastes capacity, so a single node may simultaneously host both
    # ``radius_transport`` AND one or more ``vpn_*`` roles. An empty
    # list means "all roles enabled" (back-compat with existing fleets);
    # narrowing the list is the operator's opt-in once §9 + §10 land
    # the dashboard's spare-capacity readout.
    roles_json = db.Column(db.Text, nullable=False, default="[]", server_default="[]")

    # ── live denormalized snapshot (updated by the metrics loop) ──────────────
    status = db.Column(db.String(16), nullable=False, default="provisioning")
    cpu_pct = db.Column(db.Numeric(5, 2))                             # latest CPU %
    active_sessions = db.Column(db.Integer, default=0)
    used_tb_cycle = db.Column(db.Numeric(12, 3), default=0)           # bandwidth used this cycle
    score = db.Column(db.Numeric(8, 3))                              # latest brain score (denormalized)
    last_seen_at = db.Column(db.DateTime)                            # last control-plane contact
    last_ping_ok_at = db.Column(db.DateTime)                         # last successful ICMP

    # Anchors the idempotent legacy→fleet migration. NULL for native fleet
    # rows (created via the onboarding wizard); set ONLY on rows that were
    # imported from the legacy ``chr_nodes`` table by
    # ``app.services.fleet_consolidation.run_migration``. Stays for the
    # lifetime of the consolidation; step 6 of docs/CONSOLIDATION.md drops
    # this column at the same time as the legacy tables.
    legacy_chr_node_id = db.Column(db.Integer, nullable=True, index=True)

    provider = db.relationship(lambda: FleetProvider, back_populates="nodes")

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"<ChrNode {self.id} {self.name!r} {self.status} score={self.score}>"


__all__ = [
    "FleetProvider",
    "FleetChrNode",
    "BigIntID",
    "PROVIDER_COST_MODELS",
    "NODE_COST_MODELS",
    "NODE_STATUSES",
]
