-- UP
CREATE TABLE IF NOT EXISTS campaigns (
  id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  identifier              TEXT NOT NULL,
  strategy_id             TEXT NOT NULL,
  campaign_type           TEXT NOT NULL,
  status                  TEXT NOT NULL DEFAULT 'active',
  source                  TEXT NOT NULL,
  confidence              DOUBLE PRECISION NOT NULL,
  peak_confidence         DOUBLE PRECISION NOT NULL,
  campaign_threat_level   TEXT NOT NULL,
  first_seen              TIMESTAMPTZ NOT NULL,
  last_seen               TIMESTAMPTZ NOT NULL,
  times_fired             INTEGER NOT NULL DEFAULT 1,
  contributing_ips        JSONB NOT NULL DEFAULT '[]',
  sample_paths_probed     JSONB NOT NULL DEFAULT '[]',
  sample_user_agents      JSONB NOT NULL DEFAULT '[]',
  related_strategy_tags   JSONB NOT NULL DEFAULT '[]',
  request_ids             JSONB NOT NULL DEFAULT '[]',
  evidence                JSONB NOT NULL,
  evidence_history        JSONB NOT NULL,
  extracted_entities      JSONB NOT NULL DEFAULT '[]',
  extracted_relationships JSONB NOT NULL DEFAULT '[]',
  created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  constraint campaigns_status_check
    CHECK (status IN ('active', 'dormant', 'closed')),
  constraint campaigns_source_check
    CHECK (source IN ('backtest', 'live')),
  constraint campaigns_threat_level_check
    CHECK (campaign_threat_level IN ('none', 'low', 'medium', 'high'))
);

-- Episode semantics: at most one open row per (identifier, source), so a
-- backtest run never merges into a live campaign; closed rows keep history
-- frozen. Doubles as the ON CONFLICT arbiter for the upsert.
CREATE UNIQUE INDEX IF NOT EXISTS campaigns_open_identifier_source
  ON campaigns (identifier, source) WHERE status != 'closed';

CREATE INDEX IF NOT EXISTS campaigns_status_last_seen
  ON campaigns (status, last_seen);


-- DOWN
DROP INDEX IF EXISTS campaigns_status_last_seen;
DROP INDEX IF EXISTS campaigns_open_identifier_source;
DROP TABLE IF EXISTS campaigns;
