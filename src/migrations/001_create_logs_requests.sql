-- UP

-- Request Logs Table
-- Stores every API request for monitoring, debugging, and security analysis.
-- Write-heavy table - indexes are minimal and targeted.
--
-- This consolidated migration represents the final schema as evolved over
-- a year in production. Columns added across multiple migrations have been
-- merged here so a fresh install lands on the current shape in one shot.

CREATE TABLE IF NOT EXISTS logs_requests (
  id               BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id          INTEGER,                                   -- Nullable: null for unauthenticated requests. No FK - logs survive user deletion.
  session_id       UUID,                                      -- Nullable: tracks requests across a session without auth.
  method           TEXT          NOT NULL,                    -- HTTP method: GET, POST, PUT, DELETE, etc.
  route            TEXT          NOT NULL,                    -- Matched route pattern: /api/users/:id
  full_url         TEXT          NOT NULL,                    -- Actual URL with params: /api/users/42?include=role
  status_code      SMALLINT      NOT NULL,                    -- Response HTTP status code (200, 404, 500, etc.)
  ip               INET          NOT NULL,                    -- Client IP address (IPv4 and IPv6 supported)
  user_agent       TEXT,                                      -- Raw User-Agent header
  source           TEXT          NOT NULL DEFAULT 'unknown',  -- Derived from user_agent: browser, curl, postman, bot, unknown, no-agent
  request_body     JSONB,                                     -- Request body (scrubbed of passwords/tokens). Null for GET.
  response_time_ms INTEGER       NOT NULL,                    -- Request duration in milliseconds.
  response_size    INTEGER,                                   -- Response body size in bytes.
  origin           TEXT,                                      -- Origin header: for CORS tracking.
  threat_level     TEXT          NOT NULL DEFAULT 'none',     -- none, low, medium, high - classified by honey middleware.
  threat_details   JSONB,                                     -- What triggered the classification (matched patterns, injection attempts).
  ip_location      JSONB,                                     -- Geo enrichment: { country, city, latitude, longitude, asn, org }
  error_message    TEXT,                                      -- Error message if request failed. Null on success.
  ip_type          VARCHAR(16),                               -- Classification: hosting, isp, corporate, government, education, unknown
  is_tor           BOOLEAN       DEFAULT FALSE,               -- True if source IP is a known Tor exit node.
  forwarding_chain JSONB,                                     -- X-Forwarded-For chain + Cloudflare headers + spoof flag (only set when interesting)
  created_at       TIMESTAMPTZ   NOT NULL DEFAULT NOW()       -- When the request was logged.
);

-- BRIN index on timestamp - tiny index, ideal for append-only time-series data
CREATE INDEX IF NOT EXISTS idx_logs_requests_created_at
  ON logs_requests USING BRIN (created_at);

-- Partial index on user_id - only indexes rows with authenticated users
CREATE INDEX IF NOT EXISTS idx_logs_requests_user_id
  ON logs_requests (user_id) WHERE user_id IS NOT NULL;

-- Partial index on threat_level - only indexes flagged requests for security queries
CREATE INDEX IF NOT EXISTS idx_logs_requests_threat
  ON logs_requests (threat_level, created_at) WHERE threat_level != 'none';

-- Partial index on slow requests - only indexes requests over 1 second
CREATE INDEX IF NOT EXISTS idx_logs_requests_slow
  ON logs_requests (response_time_ms) WHERE response_time_ms > 1000;

-- DOWN
DROP INDEX IF EXISTS idx_logs_requests_slow;
DROP INDEX IF EXISTS idx_logs_requests_threat;
DROP INDEX IF EXISTS idx_logs_requests_user_id;
DROP INDEX IF EXISTS idx_logs_requests_created_at;
DROP TABLE IF EXISTS logs_requests;
