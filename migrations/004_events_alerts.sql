-- ─────────────────────────────────────────────────────────────────────────────
-- 004_events_alerts.sql — CHR Fleet Phase 2, task T4
--
-- Tables: events, alerts.
-- Schema source: docs/chr_fleet/02_DATA_MODEL.md §2.9 (Postgres dialect).
--
-- Idempotent: every CREATE uses IF NOT EXISTS so this script may be re-run
-- against a partially-migrated DB. Apply with:
--     psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/004_events_alerts.sql
--
-- The matching SQLAlchemy models live in fleet/notify/models_alert.py and
-- carry the same column shape so db.create_all() (the panel's SQLite dev path)
-- yields a structurally compatible schema.
-- ─────────────────────────────────────────────────────────────────────────────

BEGIN;

-- ──────────────────────────── 2.9 events ────────────────────────────
-- Health / failover / move / onboarding event log. One row per discrete
-- transition or actuator call; the notifier consumes this stream and
-- materializes alerts according to alert_rules (Phase 9 P9-T3).
--
-- `kind` is intentionally a free-form TEXT — the catalog of known values
-- is enumerated in the docstring of fleet/notify/models_alert.py so the
-- catalog evolves with the code, not the schema.
CREATE TABLE IF NOT EXISTS events (
  id        BIGSERIAL PRIMARY KEY,
  ts        TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- chr_id NULL is allowed for fleet-wide events (e.g. 'dns_update',
  -- 'cap_warn' aggregated across providers).
  chr_id    BIGINT      REFERENCES chr_nodes(id),
  kind      TEXT        NOT NULL,
  severity  TEXT        NOT NULL DEFAULT 'info'
            CHECK (severity IN ('info','warn','crit')),
  detail    JSONB       NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_events_chr_ts ON events (chr_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_kind   ON events (kind, ts DESC);


-- ──────────────────────────── 2.9 alerts ────────────────────────────
-- Owner notifications + delivery status. `dedupe_key` + the partial-
-- unique index implement alert-storm suppression (one "CHR-7 down"
-- message, not 50). The notifier (built in radius-module-admin's
-- messaging layer) consumes queued rows.
CREATE TABLE IF NOT EXISTS alerts (
  id         BIGSERIAL PRIMARY KEY,
  event_id   BIGINT      REFERENCES events(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  channel    TEXT        NOT NULL
             CHECK (channel IN ('sms','whatsapp','telegram')),
  recipient  TEXT        NOT NULL,
  body       TEXT        NOT NULL,
  status     TEXT        NOT NULL DEFAULT 'queued'
             CHECK (status IN ('queued','sent','failed','suppressed')),
  sent_at    TIMESTAMPTZ,
  -- Per-event suppression key, e.g. 'chr:7:down'. NULL means "no
  -- dedupe" — allow always (used for one-off operator pushes).
  dedupe_key TEXT,
  retries    INTEGER     NOT NULL DEFAULT 0
);
-- Storm suppression: while a queued/sent row with the same dedupe_key
-- exists, no second row for the same key can be created.
CREATE UNIQUE INDEX IF NOT EXISTS uq_alert_dedupe
  ON alerts (dedupe_key) WHERE status IN ('queued','sent');
CREATE INDEX IF NOT EXISTS idx_alerts_status_created
  ON alerts (status, created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_channel_created
  ON alerts (channel, created_at DESC);

COMMIT;
