# Threat Pattern Catalog

honeylog ships with ~400 patterns in `src/middleware/threatDefinitions.js`,
split into four categories. Each pattern is tagged `low`, `medium`, or
`high` severity. The overall request `threat_level` is the highest
severity seen across all matched signals.

## Severity Rationale

| Severity | Meaning                                                                                           | Examples                                                       |
| -------- | ------------------------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| `high`   | Direct exploit attempt, credential harvest, RCE probe, or known-malicious signature.              | `/.env`, `wp-config`, `phpinfo`, `eval-stdin.php`, Androxgh0st |
| `medium` | Reconnaissance with active exploit potential; framework / admin / debug probing.                  | `/actuator`, `/RDWeb`, `/_profiler`, swagger docs              |
| `low`    | Passive reconnaissance, fingerprinting, or weakly suspicious behaviour.                           | `/security.txt`, `/cdn-cgi/trace`, missing User-Agent          |
| `none`   | Pseudo-severity; emitted only when no signals fired. Stored so the audit table records every hit. | normal traffic                                                 |

The dividing line between `medium` and `high` is **whether a successful
match implies the attacker is one request away from a credential, a
config, or code execution**. A probe for `/admin` is medium - they're
mapping the surface. A probe for `/.env` is high - if it returns 200,
they've just taken your secrets.

## Categories

### `BOT_PATTERNS` - user-agent regex

Identifies clients as bots/scanners purely from the User-Agent string.
Matches are routed into the `source` column (`bot`) rather than into
threat signals. Examples:

- Generic identifiers: `bot`, `crawler`, `spider`, `scraper`.
- HTTP libraries: `python-requests`, `axios`, `node-fetch`, `Go-http-client`.
- Named scanners: `nmap`, `sqlmap`, `nuclei`, `masscan`, `Censys`, `Shodan`.
- Production-derived signatures: scanners that announce themselves with
  identifiable strings (added as they're observed).
- Malformed UAs: real browsers don't truncate mid-token; `\(KHTML$` and
  similar fragments are scanner spoofs.
- Impossible UAs: scanners claiming to be Android 2 or Windows XP.

### `PATH_THREATS` - request-path regex

The largest category. Catches:

- Config-file probes: `.env*`, `.git`, `wp-config.php`, `appsettings.json`,
  Spring Boot `application.yml`, Rails `credentials.yml.enc`, etc.
- Cloud / CI credential files: `.aws/credentials`, `.kube/config`,
  Terraform state, serverless.yml, Docker Compose.
- Admin panels: `/admin`, `/manager`, `/phpmyadmin`, `/wp-admin`.
- Framework debug surfaces: Laravel Telescope, Symfony Profiler, Spring
  Boot Actuator sensitive endpoints.
- Known CVE landing pages: ProxyLogon, ProxyShell, OFBiz XML-RPC,
  Ignition, PHPUnit eval-stdin, Spring Cloud Gateway, etc.
- Phishing-kit asset fingerprinting (yes, scanners check whether your
  server is hosting someone else's phishing kit).
- Recon and fingerprinting: robots.txt, security.txt, version endpoints.

### `METHOD_THREATS` - HTTP method

Rare and high-signal:

- `PROPFIND` - WebDAV scan.
- `TRACE` - XST attack vector.
- `CONNECT` - open-proxy test.

These should essentially never appear against a normal web app.

### `BODY_THREATS` - request body + URL query

Scanned against both the request body and the URL (since query-string
injection looks identical). Covers:

- SQL injection: boolean, UNION-based, destructive, time-based, comment.
- XSS: script tags, inline event handlers, `javascript:` URIs, `eval(`.
- Path traversal: `../`, encoded `..%2f`, null-byte injection, overlong
  UTF-8.
- Command injection / substitution: `; cat`, `$(...)`, backtick exec,
  pipe-to-shell.
- LFI: `/etc/passwd`, `/etc/shadow`, `/proc/*/environ`, `/proc/*/cmdline`.
- Named-malware signatures: Androxgh0st, GNIXOER, Xterminate, IoT botnet
  markers.
- Cryptominer abuse: ETH/Stratum JSON-RPC mining methods.
- Type-confusion auth bypass (array-typed `email` / `username` keys).
- CVE payload markers: PHP-CGI %AD bypass, Webmin RCE marker, PHPUnit
  eval-stdin.

## Adding Patterns

See [`CONTRIBUTING.md`](../CONTRIBUTING.md) for the PR process. The short
version:

1. Open `src/middleware/threatDefinitions.js`.
2. Add to the appropriate array with a severity and a description.
3. Above the entry, add a comment explaining what it catches, ideally with
   a sanitised log sample.
4. Open a PR.

Patterns derived from real traffic always beat blog-derived patterns. If
you've watched something hit your logs, your contribution is wanted.
