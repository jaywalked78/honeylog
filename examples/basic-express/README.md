# honeylog - basic Express example

Minimal end-to-end demo of `honey` mounted on an Express app, writing to a
local Postgres.

## Prerequisites

- Node 18+.
- A running Postgres database you can write to.
- The migration in `../../migrations/001_create_logs_requests.sql` applied
  to that database.

## Setup

```bash
# 1. Copy the env template and edit DATABASE_URL with your real credentials
cp .env.example .env
# (then edit .env in your editor)

# 2. Apply the migration (using the DATABASE_URL from your .env)
psql "$(grep ^DATABASE_URL .env | cut -d= -f2-)" -f ../../migrations/001_create_logs_requests.sql

# 3. Install this example's deps
npm install

# 4. Run with env loaded - Node 20.6+:
node --env-file=.env app.js
# Or older Node:
# set -a; source .env; set +a && node app.js
```

## Why `db.js` is a separate module

The `pg.Pool` lives in its own `db.js` so your own routes can import the
same shared pool. honey isn't doing anything special here - it's the
standard Express + pg pattern. honey just accepts whatever pool you hand
it. One pool per process, shared by everything that talks to your
database.

## Generate Some Traffic

```bash
curl http://localhost:3000/                                     # benign
curl http://localhost:3000/.env                                 # high-severity (config probe)
curl http://localhost:3000/admin                                # high-severity (admin probe)
curl http://localhost:3000/wp-login.php                         # high-severity (WordPress probe)
curl 'http://localhost:3000/search?q=UNION+SELECT+*+FROM+users' # high-severity (SQLi in query)
curl -A 'sqlmap/1.0' http://localhost:3000/                     # bot source
curl -X PROPFIND http://localhost:3000/                         # medium (WebDAV)
```

## Inspect Logs

```sql
SELECT
  id, created_at, method, route, status_code,
  source, threat_level, ip_type, is_tor
FROM logs_requests
ORDER BY id DESC
LIMIT 20;

-- Just the suspicious stuff:
SELECT method, route, threat_level, threat_details
FROM logs_requests
WHERE threat_level IN ('medium', 'high')
ORDER BY created_at DESC;
```

## Notes

- `app.set("trust proxy", true)` is set so the example works behind a
  reverse proxy. In production, set this to the specific proxy hop count
  (e.g. `1` for Cloudflare-only, `2` for Cloudflare + nginx).
- JWT decode is commented out in `app.js`. Uncomment `cookieNames` and
  `jwtSecret`, then `npm install jsonwebtoken`, to enable it.
- GeoIP enrichment requires MaxMind GeoLite2 `.mmdb` files at a path the
  bundled `geoLookup.js` can find. Without them, geo enrichment is
  disabled but the middleware otherwise works fine.
