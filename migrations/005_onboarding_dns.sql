-- ============================================================================
-- 005_onboarding_dns.sql — Phase 2, task T5
--
-- Tables introduced:
--   * fleet_onboarding_jobs  — wizard run + state machine record per CHR
--                          (state diagram: 06_ONBOARDING_WIZARD §6.2)
--   * fleet_dns_records_state — last-published front-door record set
--                          (DNS controller memoizes the healthy set here so
--                           it only calls the provider API on diffs; see
--                           03_FRONT_DOOR_DNS §3.5)
--
-- Both tables live in the panel DB (`radius-module-admin`). PostgreSQL dialect,
-- as documented in 02_DATA_MODEL.md. Migration files 001–004 introduce the
-- prerequisite tables (providers, chr_nodes, chr_metrics, chr_health,
-- users_fleet, sessions, placement_decisions, events, alerts) and are owned
-- by sibling Phase-2 tasks. We DO NOT redefine anything from those files; the
-- only outward dependency here is `fleet_onboarding_jobs.chr_id → fleet_chr_nodes(id)`,
-- which 001 establishes.
--
-- File ownership invariant: this is the only migration that creates these two
-- tables — no other Phase-2 task touches them.
-- ============================================================================

BEGIN;

-- ──────────────────────────────────────────────────────────────────────────
-- onboarding_jobs (02 §2.10)
-- ──────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS fleet_onboarding_jobs (
  id                   BIGSERIAL PRIMARY KEY,
  -- FK is nullable on purpose: the row is created in 'draft' BEFORE the
  -- chr_nodes row exists; we link them once provisioning produces the node.
  chr_id               BIGINT REFERENCES fleet_chr_nodes(id) ON DELETE SET NULL,
  status               TEXT   NOT NULL DEFAULT 'draft'
                       CHECK (status IN (
                         'draft',
                         'keys_generated',
                         'script_generated',
                         'pushed',
                         'verifying',
                         'active',
                         'failed'
                       )),
  form_input           JSONB  NOT NULL,
  -- Vault REFERENCES only — never plaintext. Carries the "never log secrets"
  -- invariant into the DB (02 §2.10).
  wg_keypair_ref       TEXT,
  generated_script_ref TEXT,
  verify_report        JSONB,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Most queries are "what jobs are in flight for which CHR" or "find me the
-- in-flight job for this CHR id"; index both axes.
CREATE INDEX IF NOT EXISTS idx_onboarding_jobs_status
  ON fleet_onboarding_jobs (status);

CREATE INDEX IF NOT EXISTS idx_onboarding_jobs_chr_id
  ON fleet_onboarding_jobs (chr_id);

-- Keep updated_at fresh on row updates (Postgres has no auto-onupdate hook).
CREATE OR REPLACE FUNCTION trg_onboarding_jobs_touch_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS onboarding_jobs_touch_updated_at ON fleet_onboarding_jobs;
CREATE TRIGGER onboarding_jobs_touch_updated_at
  BEFORE UPDATE ON fleet_onboarding_jobs
  FOR EACH ROW EXECUTE FUNCTION trg_onboarding_jobs_touch_updated_at();


-- ──────────────────────────────────────────────────────────────────────────
-- dns_records_state (02 §2.11)
-- ──────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS fleet_dns_records_state (
  id                 BIGSERIAL PRIMARY KEY,
  fqdn               TEXT NOT NULL,
  record_type        TEXT NOT NULL
                     CHECK (record_type IN ('A','AAAA')),
  published_ips      INET[] NOT NULL,
  ttl                INT  NOT NULL
                     CHECK (ttl > 0),
  provider_zone_id   TEXT,
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_change_reason TEXT
);

-- One row per (fqdn, record_type). The DNS controller upserts by this key so
-- it never publishes two competing record sets for the same hostname/type.
CREATE UNIQUE INDEX IF NOT EXISTS uq_dns_fqdn_type
  ON fleet_dns_records_state (fqdn, record_type);

CREATE OR REPLACE FUNCTION trg_dns_records_state_touch_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS dns_records_state_touch_updated_at ON fleet_dns_records_state;
CREATE TRIGGER dns_records_state_touch_updated_at
  BEFORE UPDATE ON fleet_dns_records_state
  FOR EACH ROW EXECUTE FUNCTION trg_dns_records_state_touch_updated_at();

COMMIT;


-- ============================================================================
-- DOWN migration (idempotent). Run between the `-- @DOWN` marker and EOF if
-- you need to roll back. Order is reverse of the up section.
-- ============================================================================
-- @DOWN
-- BEGIN;
--   DROP TRIGGER  IF EXISTS dns_records_state_touch_updated_at ON fleet_dns_records_state;
--   DROP FUNCTION IF EXISTS trg_dns_records_state_touch_updated_at();
--   DROP INDEX    IF EXISTS uq_dns_fqdn_type;
--   DROP TABLE    IF EXISTS fleet_dns_records_state;
--
--   DROP TRIGGER  IF EXISTS onboarding_jobs_touch_updated_at ON fleet_onboarding_jobs;
--   DROP FUNCTION IF EXISTS trg_onboarding_jobs_touch_updated_at();
--   DROP INDEX    IF EXISTS idx_onboarding_jobs_chr_id;
--   DROP INDEX    IF EXISTS idx_onboarding_jobs_status;
--   DROP TABLE    IF EXISTS fleet_onboarding_jobs;
-- COMMIT;
