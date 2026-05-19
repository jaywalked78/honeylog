/**
 * honey - Universal request logger + threat classifier for Express
 *
 * Drop this middleware on every route. For each request it captures:
 *   - timing, status, size, source (curl/postman/bot/browser/...)
 *   - threat signals across path, method, body, URL query, user-agent
 *   - geo + ASN enrichment, IP type (hosting/isp/...), Tor exit-node flag
 *   - X-Forwarded-For chain + Cloudflare headers, with spoof detection
 *
 * Designed to write asynchronously in `res.on("finish")` so it never adds
 * latency to the response path. Failures log and swallow - the middleware
 * must never break the request.
 *
 * PII SANITIZATION
 *   Keys matching password|token|secret|ssn|credit.?card|authorization are
 *   replaced with "[REDACTED]" before the body is persisted. The redaction
 *   pattern is configurable via the `redactKeys` option.
 *
 * FORWARDING CHAIN ANALYSIS
 *   Trusted hops: Cloudflare (sets CF-Connecting-IP) + a single reverse proxy
 *   (appends to X-Forwarded-For). A normal production chain has at most 2 XFF entries.
 *   More means the client pre-loaded the header before reaching Cloudflare -
 *   the leftmost entries are attacker-supplied. forwarding_chain is only
 *   persisted when there's something worth storing (multi-hop or CF headers).
 */

import { geoLookup } from "../helpers/geoLookup.js";
import { classifyIp, isTorExitNode } from "../helpers/ipClassifier.js";
import {
  BOT_PATTERNS,
  PATH_THREATS,
  METHOD_THREATS,
  BODY_THREATS,
} from "./threatDefinitions.js";

// === SHARED TYPES ===

/**
 * Optional payload attached by an upstream rate-limiter middleware. If
 * present, honey records it as a `rate_limit` signal and bumps the threat
 * level when severity exceeds existing signals.
 *
 * @typedef {Object} RateLimitInfo
 * @property {string} tier                     e.g. "auth", "probe", "write"
 * @property {"low"|"medium"|"high"} severity
 * @property {number} count
 * @property {number} limit
 */

// === SOURCE DETECTION ===

const detectSource = (userAgent) => {
  if (!userAgent) return "no-agent";
  if (/^curl\//i.test(userAgent)) return "curl";
  if (/postman/i.test(userAgent)) return "postman";
  if (/insomnia/i.test(userAgent)) return "insomnia";
  if (BOT_PATTERNS.some((pattern) => pattern.test(userAgent))) return "bot";
  if (/mozilla|chrome|safari|firefox|edge|opera/i.test(userAgent))
    return "browser";
  return "unknown";
};

// === THREAT DETECTION - Patterns imported from threatDefinitions.js ===

const SEVERITY_RANK = { none: 0, low: 1, medium: 2, high: 3 };

const detectThreats = (req) => {
  /** @type {Array<{category: string, severity: string, description: string, [key: string]: any}>} */
  const signals = [];

  // Path-based threats
  const fullPath = req.originalUrl || req.path;
  for (const threat of PATH_THREATS) {
    if (threat.pattern.test(fullPath)) {
      signals.push({
        category: "path",
        severity: threat.severity,
        description: threat.description,
        matched: fullPath,
      });
    }
  }

  // Method-based threats
  for (const threat of METHOD_THREATS) {
    if (req.method === threat.method) {
      signals.push({
        category: "method",
        severity: threat.severity,
        description: threat.description,
        matched: req.method,
      });
    }
  }

  // Body-based threats (stringify and scan)
  if (
    req.body &&
    typeof req.body === "object" &&
    Object.keys(req.body).length > 0
  ) {
    const bodyStr = JSON.stringify(req.body);
    for (const threat of BODY_THREATS) {
      if (threat.pattern.test(bodyStr)) {
        signals.push({
          category: "body",
          severity: threat.severity,
          description: threat.description,
        });
        threat.pattern.lastIndex = 0;
      }
    }
  }

  // Also scan the URL for injection (query string attacks)
  for (const threat of BODY_THREATS) {
    if (threat.pattern.test(fullPath)) {
      signals.push({
        category: "url",
        severity: threat.severity,
        description: threat.description,
      });
      threat.pattern.lastIndex = 0;
    }
  }

  // User agent - no-agent is suspicious
  if (!req.get("User-Agent")) {
    signals.push({
      category: "agent",
      severity: "low",
      description: "no user agent",
    });
  }

  if (signals.length === 0) return { level: "none", signals: null };

  const level = signals.reduce((highest, signal) => {
    return SEVERITY_RANK[signal.severity] > SEVERITY_RANK[highest]
      ? signal.severity
      : highest;
  }, "none");

  return { level, signals };
};

// === FORWARDING CHAIN ANALYSIS ===
const TRUSTED_HOPS = 2;

const parseForwardingChain = (req) => {
  const rawXff = req.headers["x-forwarded-for"];
  const cfConnectingIp = req.headers["cf-connecting-ip"] || null;
  const cfIpCountry = req.headers["cf-ipcountry"] || null;

  const chain = rawXff
    ? rawXff
        .split(",")
        .map((entry) => entry.trim())
        .filter(Boolean)
    : [];
  const hasCfHeaders = !!(cfConnectingIp || cfIpCountry);
  const hasChain = chain.length >= 2;

  if (!hasCfHeaders && !hasChain) return null;

  const result = {};
  if (chain.length > 0) result.chain = chain;
  if (cfConnectingIp) result.cf_connecting_ip = cfConnectingIp;
  if (cfIpCountry) result.cf_ip_country = cfIpCountry;

  if (chain.length > TRUSTED_HOPS) {
    result.spoofed = true;
    result.claimed_ip = chain[0];
  }

  return result;
};

// === PII REDACTION ===
const DEFAULT_SENSITIVE_KEYS =
  /password|token|secret|ssn|credit.?card|authorization/i;
const VALID_IP = /^[\d.:a-fA-F]+$/;

const buildRedactor = (sensitiveKeys) => {
  const re = sensitiveKeys || DEFAULT_SENSITIVE_KEYS;
  const redact = (obj) => {
    if (!obj || typeof obj !== "object") return obj;
    if (Array.isArray(obj)) return obj.map(redact);
    const cleaned = {};
    for (const [key, value] of Object.entries(obj)) {
      if (re.test(key)) {
        cleaned[key] = "[REDACTED]";
      } else if (typeof value === "object" && value !== null) {
        cleaned[key] = redact(value);
      } else {
        cleaned[key] = value;
      }
    }
    return cleaned;
  };
  return redact;
};

// === HONEY MIDDLEWARE CONFIGURATION ===

/**
 * Create the honey middleware. Mount once per Express app, after any cookie/body parsers and (optionally) rate-limiter.
 *
 * @param {Object} options
 * @param {{ query: Function }} options.pgPool - pg.Pool-compatible instance (anything with `.query(sql, params)`).
 * @param {string[]} [options.skipPaths=[]] - Exact paths to skip (e.g. `/health`, `/metrics`).
 * @param {string[]} [options.cookieNames=[]] - Cookie/header names to inspect for a JWT (first hit wins).
 * @param {string|null} [options.jwtSecret=null] - HMAC secret. Required to enable JWT-derived `user_id` / `session_id`.
 * @param {RegExp|null} [options.redactKeys=null] - Override the default PII key pattern (password|token|secret|...).
 * @param {{ info?: Function, warn?: Function, error?: Function }} [options.logger=console] - Logger for internal errors (DB write failures, JWT decode warnings).
 * @param {string} [options.tableName="logs_requests"] - The target table. Must already exist with the schema from migrations/.
 * @returns {(req: import("express").Request, res: import("express").Response, next: Function) => void} - The honey middleware itself.
 */
export function honey(options) {
  const {
    pgPool,
    skipPaths = [],
    cookieNames = [],
    jwtSecret = null,
    redactKeys = null,
    logger = console,
    tableName = "logs_requests",
  } = options;

  if (!pgPool || typeof pgPool.query !== "function") {
    throw new Error(
      "[honey] `pgPool` option is required and must be a pg.Pool instance (or anything with a .query() method).",
    );
  }

  const skipSet = new Set(skipPaths);
  const jwtEnabled = !!(jwtSecret && cookieNames.length > 0);
  const redactPII = buildRedactor(redactKeys);

  // Defer importing jsonwebtoken so it stays a truly optional peer dependency.
  // Requests that fire before it resolves will simply skip JWT decode.
  // Ideally we would have middleware to verify the token and pass it as a request header before it is passed to this honey middleware
  let jwtLib = null;
  if (jwtEnabled) {
    // @ts-ignore - jsonwebtoken is an optional peer dependency
    import("jsonwebtoken")
      .then((mod) => {
        jwtLib = mod.default || mod;
      })
      .catch(() => {
        logger.warn?.(
          "[honey] cookieNames + jwtSecret provided but `jsonwebtoken` is not installed - JWT decode disabled.",
        );
      });
  }

  const insertSql = `INSERT INTO ${tableName} (user_id, session_id, method, route, full_url, status_code, ip, user_agent, source, request_body, response_time_ms, response_size, origin, threat_level, threat_details, ip_location, error_message, ip_type, is_tor, forwarding_chain) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)`;

  return function honeyMiddleware(req, res, next) {
    if (skipSet.has(req.path)) return next();

    const captureStartTime = Date.now();

    res.on("finish", () => {
      let userId = null;
      let sessionId = null;
      if (jwtEnabled && jwtLib) {
        try {
          let token = null;
          for (const name of cookieNames) {
            const fromCookie = req.cookies?.[name];
            const fromHeader = req.headers?.[name.toLowerCase()];
            if (fromCookie || fromHeader) {
              token = fromCookie || fromHeader;
              break;
            }
          }
          if (token) {
            const decoded = jwtLib.verify(token, jwtSecret);
            userId = decoded.user_id ?? decoded.userId ?? null;
            sessionId = decoded.session_id ?? decoded.sessionId ?? null;
          }
        } catch {
          // Invalid/expired token - log as unauthenticated
        }
      }

      const userAgent = req.get("User-Agent");
      const rawIp = req.ip || "0.0.0.0";
      const ipSafe = VALID_IP.test(rawIp);
      const ip = ipSafe ? rawIp : "0.0.0.0";

      const threats = detectThreats(req); // Run threat detection across path, method, body, and URL

      // IP spoof overrides if detected (highest possible signal)
      if (!ipSafe) {
        threats.level = "high";
        threats.signals = (threats.signals || []).concat({
          category: "ip",
          severity: "high",
          description: "IP spoof via X-Forwarded-For",
          raw_xff: req.headers["x-forwarded-for"],
        });
      }

      // Reads optional rateLimitInfo set by an upstream rate-limiter middleware
      // not currently bundled with honey
      const rl = /** @type {RateLimitInfo | undefined} */ (
        /** @type {any} */ (req).rateLimitInfo
      );
      if (rl) {
        threats.signals = (threats.signals || []).concat({
          category: "rate_limit",
          tier: rl.tier,
          severity: rl.severity,
          description: `${rl.tier} rate limit exceeded (${rl.count}/${rl.limit})`,
          count: rl.count,
          limit: rl.limit,
        });
        if (SEVERITY_RANK[rl.severity] > SEVERITY_RANK[threats.level]) {
          threats.level = rl.severity;
        }
      }

      // IP Enrichment (Geo, Tor, Forwarding Chain)
      const geo = geoLookup(ip);
      const ipType = classifyIp(geo);
      const isTor = isTorExitNode(ip);
      const forwardingChain = parseForwardingChain(req);

      pgPool
        .query(insertSql, [
          userId,
          sessionId,
          req.method,
          req.path,
          req.originalUrl,
          res.statusCode,
          ip,
          userAgent,
          detectSource(userAgent),
          req.body ? JSON.stringify(redactPII(req.body)) : null,
          Date.now() - captureStartTime,
          res.getHeader("Content-Length") || null,
          req.get("Origin") || null,
          threats.level,
          threats.signals ? JSON.stringify(threats.signals) : null,
          geo ? JSON.stringify(geo) : null,
          null,
          ipType,
          isTor,
          forwardingChain ? JSON.stringify(forwardingChain) : null,
        ])
        .catch((error) =>
          (logger.error || console.error).call(
            logger,
            "[honey] Log failed:",
            error.message,
          ),
        );
    });

    next();
  };
}
