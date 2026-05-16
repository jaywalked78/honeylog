# honeylog

> Threat-detection and request-fingerprinting middleware for Express. Catches scanners, classifies attack patterns, and gives you a defensible audit log.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![npm version](https://img.shields.io/badge/npm-v0.1.0-blue.svg)](#)
[![Node](https://img.shields.io/badge/node-%3E%3D18-brightgreen.svg)](#)

honeylog is a single Express middleware that sits in front of your routes
and writes every request to Postgres - with detection, classification, and
enrichment baked in. It has been running in production on
[`thelogicloom.dev`](https://thelogicloom.dev) for a year. The pattern
library is derived from real observed traffic, not blog posts.

---

## What it does

- **Logs every request** to a single Postgres table (`logs_requests`) -
  method, route, status, IP, user-agent, body (PII-redacted), response
  time, response size.
- **Classifies the source** as `browser`, `curl`, `postman`, `insomnia`,
  `bot`, `unknown`, or `no-agent` - using a curated regex set that
  catches named scanners (sqlmap, nuclei, masscan, Censys, Shodan,
  GPTBot, ...) plus malformed-UA scanner signatures.
- **Detects threats** across four pattern categories - path, method,
  body, URL query. ~400 patterns shipping by default, tagged
  `low` / `medium` / `high`.
- **Enriches with geo** via MaxMind GeoLite2 (country, city, lat/lon,
  ASN, org).
- **Classifies the IP** as `hosting` / `isp` / `corporate` / `government`
  / `education` / `unknown` using a hand-curated ASN registry plus an
  org-name regex fallback.
- **Flags Tor exit nodes** against the Tor Project's bulk exit list.
- **Parses forwarding chains** - X-Forwarded-For + Cloudflare headers,
  with **spoof detection** when the client pre-loads XFF entries ahead
  of trusted proxies.
- **Writes asynchronously** in `res.on("finish")` so it never adds
  latency to your responses.
- **Optional JWT decode** from configurable cookie/header names so
  authenticated requests get attributed to a `user_id` / `session_id`.

## What it doesn't do

- **Not a WAF.** honeylog records, classifies, and lets you query. It
  does not block requests inline. Rate-limiting and blocking belong in
  front of it (Cloudflare, nginx, a real WAF, or your own middleware).
- **Not a dedicated honeypot host.** It runs inside your real app on
  your real routes. The "honey" is that every probe gets logged with
  full context whether the probed path exists or not.
- **Opinionated patterns.** Severity tags reflect one author's
  production experience. False positives happen. PRs welcome (see
  [`CONTRIBUTING.md`](./CONTRIBUTING.md)).
- **No cross-IP correlation yet.** That's the campaign detector,
  shipping in v0.2.

## Why it exists

Per-IP rate limiting fails against any attacker with more than one IP.
The interesting scanners in 2026 use Tor exit-node sprays, cloud-subnet
credential harvesters, and multi-week enumeration campaigns spread
across hundreds of source IPs. They each look fine in isolation. They
only become obvious when you can ask **"show me every request that
matched a credential-file pattern in the last 30 days, grouped by
ASN."**

honeylog is the substrate for that question. v0.1 captures the data with
classification and enrichment in place. v0.2 will ship the campaign
detector that reads from this table and clusters cross-IP behaviour into
named campaigns.

The patterns were not copied from a security blog. They are the set that
has been catching real traffic against a real production application for
a year. Every entry in `threatDefinitions.js` corresponds to something
that hit the logs.

---

## Quick start

honeylog is not on npm yet. To use it now, clone or vendor the repo:

```bash
# Will be available once published:
# npm install honeylog

# For now, peer deps:
npm install express pg
# JWT decode is optional:
npm install jsonwebtoken
```

Apply the migration:

```bash
psql $DATABASE_URL -f migrations/001_create_logs_requests.sql
```

Mount the middleware:

```js
import express from "express";
import pg from "pg";
import { honey } from "honeylog";

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
const app = express();

app.set("trust proxy", true);
app.use(express.json());

app.use(
  honey({
    pgPool: pool, // required
    skipPaths: ["/health"], // optional
    cookieNames: ["my-app-token"], // optional, JWT attribution
    jwtSecret: process.env.JWT_SECRET, // optional
  }),
);

app.get("/", (req, res) => res.send("hi"));
app.listen(3000);
```

That's it. Every request now flows through detection, body classification,
and async logging. See [`examples/basic-express/`](./examples/basic-express/)
for a complete runnable demo.

## Enabling enrichment (optional but recommended)

The middleware works without geo or Tor enrichment - those columns just stay
null. To turn them on, call the helpers at app startup, **before** mounting
honey.

### MaxMind GeoLite2 (country, city, ASN, org)

1. **Get a free license key** at [maxmind.com/en/geolite2/signup](https://www.maxmind.com/en/geolite2/signup).
2. **Download the databases** you want. honeylog uses two:
   - `GeoLite2-City.mmdb` (country, city, coordinates)
   - `GeoLite2-ASN.mmdb` (ASN number, organization)

   Easiest path is MaxMind's [`geoipupdate`](https://github.com/maxmind/geoipupdate)
   CLI run from cron - it handles the auto-refresh. Or download manually and
   refresh on whatever cadence you want; MaxMind publishes weekly.

3. **Initialize at startup**, passing absolute paths:

   ```js
   import { honey, initGeo } from "honeylog";
   import path from "path";

   await initGeo({
     cityPath: path.resolve("data/GeoLite2-City.mmdb"),
     asnPath: path.resolve("data/GeoLite2-ASN.mmdb"),
   });

   app.use(honey({ pgPool: pool }));
   ```

If either file fails to load, that dimension is silently disabled and the
middleware keeps working - you just get null in the corresponding fields.

### Tor exit-node classification

honeylog ships with a fetcher for the
[Tor Project's bulk exit list](https://check.torproject.org/torbulkexitlist).
No license, no download, no auth - it's a public endpoint that returns a
plain-text list of current exit IPs.

```js
import { honey, fetchTorExitNodes, startTorRefreshInterval } from "honeylog";

await fetchTorExitNodes(); // initial load - returns once IPs are in memory
startTorRefreshInterval(); // refresh every 12 hours
app.use(honey({ pgPool: pool }));
```

Without these calls, `is_tor` is `false` on every row. Tor's exit list
changes daily, so the refresh interval is worth keeping on. If you'd rather
manage refresh yourself (e.g. from cron triggering a webhook into your app),
call `fetchTorExitNodes()` whenever you want and skip the interval.

## Configuration

| Option        | Type       | Default                                                        | Description                                                                                                                                             |
| ------------- | ---------- | -------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pgPool`      | `pg.Pool`  | **(required)**                                                 | A pg Pool (or anything with a `.query(sql, args)` method). honeylog uses this for the INSERT.                                                           |
| `skipPaths`   | `string[]` | `[]`                                                           | Paths to bypass entirely. Match is exact (`req.path`).                                                                                                  |
| `cookieNames` | `string[]` | `[]`                                                           | Cookie/header names to try when decoding a JWT. Tried in order. Both this and `jwtSecret` must be set, AND `jsonwebtoken` installed, for decode to run. |
| `jwtSecret`   | `string`   | `null`                                                         | Secret/key for JWT verification.                                                                                                                        |
| `redactKeys`  | `RegExp`   | `/password\|token\|secret\|ssn\|credit.?card\|authorization/i` | Keys matching this regex have their value replaced with `"[REDACTED]"` before `request_body` is persisted.                                              |
| `logger`      | `object`   | `console`                                                      | Anything with `.error` / `.warn` / `.info`. Used for INSERT failures and JWT load warnings.                                                             |
| `tableName`   | `string`   | `"logs_requests"`                                              | Override target table name if you want it elsewhere.                                                                                                    |

## What's detected

Four categories of pattern, ~400 entries shipping by default. Full catalog
in [`docs/patterns.md`](./docs/patterns.md). Briefly:

- **`PATH_THREATS`** - config files (`.env`, `wp-config`, Spring Boot
  `application.yml`, Rails `credentials.yml.enc`, AWS / GCP / K8s
  credentials), admin panels, known CVE landing pages
  (ProxyShell, OFBiz XML-RPC, Spring Cloud Gateway, PHPUnit eval-stdin),
  phishing-kit asset fingerprinting, reconnaissance.
- **`METHOD_THREATS`** - `PROPFIND`, `TRACE`, `CONNECT`.
- **`BODY_THREATS`** (also scanned against URL query strings) - SQLi
  (boolean, UNION, time-based, destructive), XSS, path traversal,
  command injection, LFI (`/etc/passwd`, `/proc/*/environ`), known
  malware signatures (Androxgh0st, GNIXOER), cryptominer JSON-RPC
  abuse, type-confusion auth bypass.
- **`BOT_PATTERNS`** (user-agent classification) - generic bot
  identifiers, HTTP libraries (python-requests, axios, ...), named
  scanners (nmap, sqlmap, nuclei, ...), research platforms (Censys,
  Shodan, ...), production-derived signatures, malformed / impossible
  UAs.

## Architecture

The middleware registers a listener on `res.on("finish")` so detection,
enrichment, and the INSERT all run **after** the response has been
flushed. Zero latency added to your routes. The detection pipeline runs
in cheap-first order (path → method → body → URL → user-agent) and the
enrichment pipeline runs in dependency order (geo → IP type → Tor →
forwarding chain).

Full design notes in [`docs/architecture.md`](./docs/architecture.md).

## Roadmap

**v0.1** (this release, May 2026)

- [x] Request logging middleware with classification.
- [x] ~400 threat patterns derived from production traffic.
- [x] Forwarding-chain analysis with X-Forwarded-For spoof detection.
- [x] Geo and Tor enrichment.
- [x] PII-safe body logging with configurable redaction.
- [x] Source detection (browser / curl / postman / bot / no-agent).
- [x] Optional JWT user/session attribution.

**v0.2 - campaign detector**

Cross-IP behavioural clustering across ASN and subnet boundaries.
Designed against real production data:

- Tor exit-node `/24` sprays - same `/.env` variant from many exit IPs
  in a short window.
- Cloud-subnet credential harvesters - whole `/16`s probing the same
  path.
- Multi-week `.env` enumeration campaigns - slow, distributed, and
  invisible to any per-IP rate limiter.

The clusterer reads from `logs_requests` and writes to a new
`logs_campaigns` table. Purely additive on top of v0.1.

**v0.3 - threat-aware rate limiter** _(planned)_

Tiered rate limiting that **consults honey's classification before
deciding limits**. Most rate limiters operate blind to threat history -
they count requests, not intent. This one tightens automatically for
known-scanner UAs, IPs that have hit high-severity threats recently, and
ASNs flagged by the v0.2 campaign detector. Static per-IP limits cannot
do this; they have no classifier to read.

The integration point already exists: honey reads `req.rateLimitInfo` if
upstream middleware attaches it. v0.3 ships the middleware that attaches
it. Likely a companion package (`@honeylog/throttle`) rather than
bundled - rate limiting and logging are different concerns even when
they integrate cleanly.

**Later**

- Pluggable pattern packs (community-maintained add-on libraries).
- Storage adapters beyond Postgres (SQLite, ClickHouse, S3 archival).
- CLI for querying / replaying / exporting campaigns.
- AI-assisted campaign analysis - LLM summaries of detected clusters,
  natural-language queries over the log table.

## License

[MIT](./LICENSE). Built and maintained by Jay. If honeylog catches
something interesting in your logs, [open an
issue](https://github.com/jaywalked78/honeylog/issues) - it's
the highest-signal feedback this project can get.
