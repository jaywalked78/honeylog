# Security Policy

Thanks for helping keep honeylog (and the apps using it) safe.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security problems.**

Email `security@thelogicloom.dev` with:

- A description of the issue and its impact.
- Steps to reproduce, ideally with a minimal request/payload sample.
- Any suggested mitigation, if you have one.

You should get an acknowledgement within **3 business days** and a status
update within **7 days**. Once a fix is ready, we'll coordinate disclosure
timing with you and credit you in the changelog (unless you'd rather stay
anonymous).

## Scope

In scope:

- The middleware itself (`src/middleware/honey.js`).
- The threat-pattern library (`src/middleware/threatDefinitions.js`) - false
  negatives that allow a known attack class to slip through, or false
  positives that could be weaponised to flood logs.
- The IP classifier and geo helpers.
- The SQL schema in `migrations/`.

Out of scope:

- Issues that require an attacker to already have application-level access
  (e.g. modifying the database directly).
- Performance characteristics under adversarial load - honeylog is a logger,
  not a WAF; rate-limiting belongs in front of it.

## Responsible Disclosure

We follow standard coordinated-disclosure practice: please give us a
reasonable window (typically 90 days) to ship a fix before publishing
details. We'll work with you on a faster track if the issue is being
actively exploited.
