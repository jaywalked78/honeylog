# Contributing to honeylog

The most valuable contribution to honeylog is **new threat patterns sourced
from real traffic you've seen in production**. Blog-derived regex is fine
but always second-priority - patterns that have caught actual scanners win.

## Adding a Threat Pattern

1. Open `src/middleware/threatDefinitions.js`.
2. Add your entry to the correct category:
   - `BOT_PATTERNS` - regex against user-agent strings.
   - `PATH_THREATS` - regex against the request path/URL.
   - `METHOD_THREATS` - exact HTTP method match.
   - `BODY_THREATS` - regex against the serialised request body **and** the
     URL query string.
3. Pick a severity (`low` / `medium` / `high`) using the rationale in
   [`docs/patterns.md`](./docs/patterns.md).
4. Above the entry, add a comment explaining:
   - What the pattern catches.
   - Ideally a **sanitised** log sample showing the matched traffic.
     (Strip your own hostnames, internal IPs, customer data, etc.)
   - Any CVE reference if relevant.

Example:

```js
// HIGH - Spring Cloud Gateway RCE (CVE-2022-22947) - actuator endpoint
// allows SpEL injection via route definitions
// Sample: POST /actuator/gateway/routes with body containing #{T(java...
{ pattern: /\/actuator\/gateway\/(routes|refresh)/i, severity: "high", description: "Spring Cloud Gateway RCE probe (CVE-2022-22947)" },
```

## Reporting Bugs

Open an issue with:

- honeylog version.
- Node version and `pg` version.
- Minimal reproduction (route definition + sample request that triggers the
  bug).
- Expected vs actual behaviour.
- For false positives: the matched request, the pattern it hit, and why you
  believe it's a false positive.

## Code Style

honeylog matches the source app it was extracted from. Please follow:

- **ESM only** (`import` / `export`, never `require`).
- **Semicolons** at line ends.
- **Double quotes** for strings.
- **Descriptive names** - `parseForwardingChain` over `pfc`.
- **No new runtime dependencies** without discussion. The whole point of the
  middleware is that it has a thin footprint.
- Keep handlers inside `res.on("finish")` non-blocking - never `await`
  anything that can fail in a way that delays response delivery.

## Pull Request Process

1. Fork, branch, commit, open the PR.
2. Reference any related issue in the description.
3. For pattern additions, include the sanitised sample above in the diff
   comment.
4. Be patient - this is maintained alongside other work.

Thanks for contributing.
