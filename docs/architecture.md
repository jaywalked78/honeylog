# Architecture

honeylog is a single Express middleware. There is no daemon, no sidecar, no
background worker. The middleware sits inline in your request pipeline and
writes asynchronously to a Postgres table.

## Middleware Lifecycle

```
request in
   │
   ▼
honey(req, res, next)         ── stamp captureStartTime, register listener, call next()
   │
   ▼
your routes run
   │
   ▼
response sent ──► res.on("finish") fires asynchronously
                       │
                       ▼
            detection + enrichment + INSERT
```

The work is done in `res.on("finish")`. The response has already been
flushed to the client at this point, so anything done here adds **zero**
latency to the user-visible request. If the INSERT fails, the failure is
logged via the configured logger and swallowed. The middleware is designed
to never break a request.

## Detection Pipeline

The order matters. Cheap signals come first:

1. **Path** - `req.originalUrl` is scanned against `PATH_THREATS`. This
   catches the bulk of scanner traffic (`/.env`, `/wp-login.php`, etc.) at
   the cost of one regex sweep over a short string.
2. **Method** - exact match against `METHOD_THREATS` (`PROPFIND`, `TRACE`,
   `CONNECT`).
3. **Body** - `req.body` is `JSON.stringify`'d and scanned against
   `BODY_THREATS`. Only runs when there is a non-empty body.
4. **URL** - the same `BODY_THREATS` set is run against the URL, since
   query-string injection looks identical to body injection.
5. **User agent** - if absent, a low-severity `no user agent` signal is
   added.

All signals are appended to a single array. The overall `threat_level` is
the max severity across all signals. If no signals match, the row is still
logged with `threat_level = "none"`.

## Enrichment Pipeline

After the detection sweep, each request is enriched with:

1. **Geo** - MaxMind GeoLite2-City + GeoLite2-ASN, looked up from `req.ip`.
   Returns `{ country, city, latitude, longitude, asn, org }` or `null` if
   the DB isn't loaded or the IP is local.
2. **IP type** - the ASN is matched against a hand-curated registry first
   (`hosting` / `isp` / `corporate` / `government` / `education`). If
   nothing matches, the org name falls through a regex registry. If that
   also misses, `unknown` is recorded so it can be triaged later.
3. **Tor exit** - a flat `Set` lookup against the Tor Project's bulk exit
   list (refreshed every 12h if you start the refresher).
4. **Forwarding chain** - the `X-Forwarded-For` chain plus any Cloudflare
   headers. A chain length greater than `TRUSTED_HOPS` (Cloudflare +
   reverse proxy = 2) implies the client pre-loaded XFF before reaching
   Cloudflare - the leftmost entries are attacker-supplied and the row is
   flagged `spoofed: true`. The chain is only persisted when there's
   actually something interesting in it.

## Why `res.on("finish")`?

Three reasons:

- The detection regex sweep is cheap but non-zero. Doing it after the
  response is flushed means it never appears in your p99.
- The Postgres INSERT cost is bounded by network round-trip to the DB. If
  the DB is slow, your routes don't slow down with it.
- It captures the **final** status code, which is what you actually want
  in the audit log. Earlier hooks see whatever the route set before any
  error handler overwrote it.

## Why JSONB for `threat_details` and `forwarding_chain`?

Both are sparse, polymorphic, and queryable:

- `threat_details` holds a variable-length array of signals, each with a
  different shape depending on category. JSONB lets us add new signal
  fields without a migration.
- `forwarding_chain` is `null` for the overwhelming majority of rows (most
  traffic has neither CF headers nor a multi-hop XFF chain). Storing it
  flat would mean a wide row with mostly-null columns.

Both columns are GIN-indexable if you start querying inside them at scale.

## v0.2 Preview: The Campaign Detector

`logs_requests` is the substrate. v0.2 introduces a separate background
job that reads from this table and clusters requests into **campaigns**:

- Cross-IP behavioural fingerprinting across ASN and /24 subnet
  boundaries.
- Tor exit-node sprays (multiple exit IPs hitting the same `/.env`
  variant within a window).
- Cloud-subnet credential harvesters (whole `/16`s probing the same
  path).
- Multi-week `.env` enumeration campaigns that any per-IP rate limiter
  would miss entirely.

The clusterer reads only from this table - it is purely additive on top
of v0.1's logging.
