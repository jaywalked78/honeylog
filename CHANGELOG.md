# Changelog

All notable changes to honeylog are documented here. This project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-05-15

Initial public release. Extracted from a production Express app
(`thelogicloom.dev`) where it has been running for a year against real
hostile traffic.

### Added

- Request logging middleware with classification (`browser` / `curl` /
  `postman` / `insomnia` / `bot` / `unknown` / `no-agent`).
- ~400 threat patterns derived from production traffic, split into path,
  method, body, and URL categories with `low` / `medium` / `high` severity.
- Forwarding-chain analysis with X-Forwarded-For spoof detection (flags
  client-supplied XFF entries that arrive ahead of trusted proxies).
- Geo and Tor enrichment via MaxMind GeoLite2 + the Tor Project's bulk
  exit-node list.
- IP-type classification (`hosting` / `isp` / `corporate` / `government` /
  `education` / `unknown`) backed by a hand-curated ASN registry plus an
  org-name regex fallback.
- PII-safe body logging with configurable redaction (`password`, `token`,
  `secret`, `ssn`, `credit_card`, `authorization` by default).
- Source detection across the user-agent string, including malformed-UA
  signatures observed in the wild.
- Optional JWT decode from configurable cookie/header names for attributing
  authenticated requests to a `user_id` / `session_id`.

### Notes

- The campaign detector (cross-IP behavioural clustering) is intentionally
  out of scope for v0.1 and will ship in v0.2.
