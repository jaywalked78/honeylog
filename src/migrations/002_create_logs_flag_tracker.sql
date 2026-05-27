-- UP
CREATE TABLE IF NOT EXISTS logs_flag_tracker (
  id               BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  scope_type       TEXT NOT NULL,
  scope_value      TEXT NOT NULL,
  flag_name        TEXT NOT NULL,
  expires_at       TIMESTAMPTZ NOT NULL,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  constraint logs_flag_tracker_unique_flag
    UNIQUE (scope_type, scope_value, flag_name),
  constraint logs_flag_tracker_scope_type_check
    CHECK (scope_type IN ('ip', 'asn', 'asn_subnet'))
);

CREATE INDEX IF NOT EXISTS idx_logs_flag_tracker_expires_at
  ON logs_flag_tracker (expires_at);


-- DOWN
DROP INDEX IF EXISTS idx_logs_flag_tracker_expires_at;
DROP TABLE IF EXISTS logs_flag_tracker;
