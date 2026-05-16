/**
 * Basic honeylog example.
 *
 * Run:
 *   1. `cp .env.example .env` and edit DATABASE_URL with real credentials.
 *   2. Apply the migration in ../../migrations/001_create_logs_requests.sql
 *      against the database referenced in .env.
 *   3. `npm install` in this directory.
 *   4. Run with env loaded - on Node 20.6+:
 *        node --env-file=.env app.js
 *      Or on older Node:
 *        set -a; source .env; set +a && node app.js
 *   5. In another terminal:
 *        curl http://localhost:3000/
 *        curl http://localhost:3000/.env            # high-severity probe
 *        curl http://localhost:3000/admin           # high-severity probe
 *        curl 'http://localhost:3000/search?q=UNION+SELECT+*+FROM+users'
 *      Then query `SELECT method, route, threat_level, source FROM logs_requests;`
 */

import express from "express";
import path from "path";
import { honey, initGeo, fetchTorExitNodes, startTorRefreshInterval } from "honeylog";
import { pool } from "./db.js";

// Optional: load MaxMind GeoLite2 databases for geo + ASN enrichment.
// Without these, the ip_location column stays null. Get a free license
// at https://www.maxmind.com/en/geolite2/signup and drop the .mmdb files
// somewhere your app can read.
//
// await initGeo({
//   cityPath: path.resolve("data/GeoLite2-City.mmdb"),
//   asnPath: path.resolve("data/GeoLite2-ASN.mmdb"),
// });

// Optional: load the Tor exit-node list (public, no auth) so requests
// from Tor exits get flagged. Without these, is_tor stays false.
//
// await fetchTorExitNodes();
// startTorRefreshInterval();

const app = express();

// Trust your reverse proxy so req.ip resolves to the real client and the
// X-Forwarded-For chain is parsed correctly. Without this, every request
// looks like it came from your proxy.
app.set("trust proxy", true);

// JSON body parsing must run BEFORE honey so request_body is populated
// when the middleware reads it on res.finish.
app.use(express.json());

// Mount honey universally. Configure it with the options that match your
// stack - everything besides pgPool is optional.
app.use(
  honey({
    // REQUIRED: pg.Pool instance. honey calls pool.query() to write rows.
    pgPool: pool,

    // Optional: paths to skip entirely. Health checks and uptime probes
    // are the obvious candidates - they're frequent and noisy.
    skipPaths: ["/health", "/_status"],

    // Optional: enable JWT decode to attribute requests to a user.
    // Both options must be present for decode to run, and `jsonwebtoken`
    // must be installed as a peer dependency. Leave them off if you
    // don't need it.
    //
    // cookieNames: ["my-app-token", "my-app-guest-token"],
    // jwtSecret: process.env.JWT_SECRET,

    // Optional: override the default PII redaction regex. Anything
    // matching this regex on a key name will have its value replaced
    // with "[REDACTED]" before request_body is persisted.
    //
    // redactKeys: /password|token|secret|api[-_]?key/i,

    // Optional: override the logger used for INSERT failures. Pass any
    // object with .error / .warn / .info methods - winston, pino, etc.
    //
    // logger: pinoLogger,
  }),
);

app.get("/", (req, res) => {
  res.json({
    message: "honeylog example - try /admin, /.env, or /search?q=...",
  });
});

app.get("/search", (req, res) => {
  res.json({ query: req.query.q, results: [] });
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`honeylog example listening on http://localhost:${port}`);
  console.log(
    "Inspect rows with: SELECT method, route, threat_level, source, ip_type FROM logs_requests ORDER BY id DESC LIMIT 20;",
  );
});
