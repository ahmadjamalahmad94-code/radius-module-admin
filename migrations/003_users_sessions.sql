-- ─────────────────────────────────────────────────────────────────────────────
-- 003_users_sessions.sql — CHR Fleet Phase 2, task T3
--
-- Tables: fleet_users, fleet_sessions, fleet_placement_decisions.
-- Schema source: docs/chr_fleet/02_DATA_MODEL.md §§2.6–2.8 (Postgres dialect).
--
-- Idempotent: every CREATE uses IF NOT EXISTS so this script may be re-run
-- against a partially-migrated DB. Apply with:
--     psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/003_users_sessions.sql
--
-- The matching SQLAlchemy models live in fleet/brain/models_session.py and
-- carry the same column shape so db.create_all() (the panel's SQLite dev path)
-- yields a structurally compatible schema.
-- ─────────────────────────────────────────────────────────────────────────────

BEGIN;

-- ──────────────────────────── 2.6 users_fleet ────────────────────────────
-- Per-user fleet record keyed by the RADIUS identity (user@realm). The
-- `movable` flag governs NORMAL rebalancing only — forced failover ignores
-- it. `fixed_ip` is a READ-ONLY mirror of radius-module's authoritative
-- Framed-IP allocation, kept here for dedupe + UI visibility.
CREATE TABLE IF NOT EXISTS fleet_users (
  id            BIGSERIAL PRIMARY KEY,
  customer_id   BIGINT      NOT NULL,
  realm         TEXT        NOT NULL,
  username      TEXT        NOT NULL,
  movable       BOOLEAN     NOT NULL DEFAULT FALSE,
  fixed_ip      INET,
  pinned_chr_id BIGINT      REFERENCES fleet_chr_nodes(id),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT uq_users_fleet_username UNIQUE (username)
);
CREATE INDEX IF NOT EXISTS idx_users_fleet_customer ON fleet_users (customer_id);
CREATE INDEX IF NOT EXISTS idx_users_fleet_realm    ON fleet_users (realm);
-- Hot index for the rebalance planner — most users are immovable.
CREATE INDEX IF NOT EXISTS idx_users_movable
  ON fleet_users (movable) WHERE movable;


-- ──────────────────────────── 2.7 sessions ────────────────────────────
-- Ground-truth "which CHR is this user actually on" table. Populated from
-- proxy `POST /api/proxy/placement` on Acct-Start/Stop. The two partial
-- unique indexes are the DB-level enforcement of goal G2 (no duplicate
-- IP) and single-session-per-user — defense-in-depth against races.
CREATE TABLE IF NOT EXISTS fleet_sessions (
  id              BIGSERIAL PRIMARY KEY,
  username        TEXT        NOT NULL,
  realm           TEXT        NOT NULL,
  chr_id          BIGINT      NOT NULL REFERENCES fleet_chr_nodes(id),
  framed_ip       INET        NOT NULL,
  acct_session_id TEXT        NOT NULL,
  nas_ip          INET,
  state           TEXT        NOT NULL DEFAULT 'active'
                  CHECK (state IN ('active','closing','closed')),
  started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_acct_at    TIMESTAMPTZ,
  closed_at       TIMESTAMPTZ,
  bytes_in        BIGINT      NOT NULL DEFAULT 0,
  bytes_out       BIGINT      NOT NULL DEFAULT 0
);
-- Dedupe guard: at most ONE active session per username fleet-wide.
CREATE UNIQUE INDEX IF NOT EXISTS uq_active_session_per_user
  ON fleet_sessions (username) WHERE state = 'active';
-- Safety: a fixed IP must not be active twice (defense-in-depth vs G2).
CREATE UNIQUE INDEX IF NOT EXISTS uq_active_ip
  ON fleet_sessions (framed_ip) WHERE state = 'active';
CREATE INDEX IF NOT EXISTS idx_sessions_chr
  ON fleet_sessions (chr_id) WHERE state = 'active';
CREATE INDEX IF NOT EXISTS idx_sessions_user_started
  ON fleet_sessions (username, started_at DESC);


-- ──────────────────────────── 2.8 placement_decisions ────────────────
-- The brain's audit log: every move records the score-breakdown snapshot
-- that justified it ("moved off CHR-B because cost_penalty 0.7 + cpu 82%").
CREATE TABLE IF NOT EXISTS fleet_placement_decisions (
  id          BIGSERIAL PRIMARY KEY,
  username    TEXT        NOT NULL,
  decided_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  kind        TEXT        NOT NULL
              CHECK (kind IN ('new','rebalance','forced_failover','manual')),
  from_chr_id BIGINT      REFERENCES fleet_chr_nodes(id),
  to_chr_id   BIGINT      REFERENCES fleet_chr_nodes(id),
  reason      JSONB       NOT NULL DEFAULT '{}'::jsonb,
  outcome     TEXT        NOT NULL DEFAULT 'pending'
              CHECK (outcome IN ('pending','applied','failed','skipped'))
);
CREATE INDEX IF NOT EXISTS idx_pd_user
  ON fleet_placement_decisions (username, decided_at DESC);
CREATE INDEX IF NOT EXISTS idx_pd_kind_decided
  ON fleet_placement_decisions (kind, decided_at DESC);

COMMIT;
