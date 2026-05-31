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

import type { Request, Response, NextFunction, RequestHandler } from "express";
import type { Pool } from "pg";
import { geoLookup } from "../helpers/geoLookup.js";
import { classifyIp, isTorExitNode } from "../helpers/ipClassifier.js";
import {
  BOT_PATTERNS,
  PATH_THREATS,
  METHOD_THREATS,
  BODY_THREATS,
  type Severity,
} from "./threatDefinitions.js";

// === SHARED TYPES ===

export type ThreatLevel = "none" | Severity;

export type Source =
  | "no-agent"
  | "curl"
  | "postman"
  | "insomnia"
  | "bot"
  | "browser"
  | "unknown";

// Optional payload attached by an upstream rate-limiter middleware. If
// present, honey records it as a `rate_limit` signal and bumps the threat
// level when severity exceeds existing signals.

export interface RateLimitInfo {
  tier: string;
  severity: Severity;
  count: number;
  limit: number;
}

export interface ThreatSignal {
  category: string;
  severity: Severity;
  description: string;
  [key: string]: unknown;
}

export interface ThreatResult {
  level: ThreatLevel;
  signals: ThreatSignal[] | null;
}

export interface ForwardingChain {
  chain?: string[];
  cf_connecting_ip?: string;
  cf_ip_country?: string;
  spoofed?: boolean;
  claimed_ip?: string;
}

export interface HoneyLogger {
  info?: (...args: unknown[]) => void;
  warn?: (...args: unknown[]) => void;
  error?: (...args: unknown[]) => void;
}

export interface HoneyOptions {
  /**  */
  pgPool: Pool; // postgres connection pool (anything with `.query(sql, params)`). Required.
  skipPaths?: string[]; // Exact paths to skip (e.g. `/health`, `/metrics`). Defaults to [].
  cookieNames?: string[]; // Cookie/header names to inspect for a JWT (first hit wins). Defaults to [].
  jwtSecret?: string | null; // HMAC secret. Required to enable JWT-derived `user_id` / `session_id`. Defaults to null.
  redactKeys?: RegExp | null; // Override the default PII key pattern (password|token|secret|...).
  logger?: HoneyLogger; // Logger for internal errors (DB write failures, JWT decode warnings). Defaults to console.
  tableName?: string; // The target table. Must already exist with the schema from migrations/. Defaults to "logs_requests".
}

// === SOURCE DETECTION ===

const detectSource = (userAgent: string | undefined): Source => {
  if (!userAgent) return "no-agent";
  if (/^curl\//i.test(userAgent)) return "curl";
  if (/postman/i.test(userAgent)) return "postman";
  if (/insomnia/i.test(userAgent)) return "insomnia";
  if (BOT_PATTERNS.some((pattern) => pattern.test(userAgent))) return "bot";
  if (/mozilla|chrome|safari|firefox|edge|opera/i.test(userAgent))
    return "browser";
  return "unknown";
};

// === THREAT DETECTION - Patterns imported from threatDefinitions.ts ===

export interface ThreatDetectionInput {
  url: string;
  method: string;
  body?: unknown;
  userAgent?: string | null;
}

const SEVERITY_RANK: Record<ThreatLevel, number> = {
  none: 0,
  low: 1,
  medium: 2,
  high: 3,
};

export const detectThreats = (input: ThreatDetectionInput): ThreatResult => {
  const signals: ThreatSignal[] = [];
  const { url, method, body, userAgent } = input;

  // Path-based threats
  for (const threat of PATH_THREATS) {
    if (threat.pattern.test(url)) {
      signals.push({
        category: "path",
        severity: threat.severity,
        description: threat.description,
        matched: url,
      });
    }
  }

  // Method-based threats
  for (const threat of METHOD_THREATS) {
    if (method === threat.method) {
      signals.push({
        category: "method",
        severity: threat.severity,
        description: threat.description,
        matched: method,
      });
    }
  }

  // Body-based threats (stringify and scan)
  if (body && typeof body === "object" && Object.keys(body).length > 0) {
    const bodyStr = JSON.stringify(body);
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
    if (threat.pattern.test(url)) {
      signals.push({
        category: "url",
        severity: threat.severity,
        description: threat.description,
      });
      threat.pattern.lastIndex = 0;
    }
  }

  // Also scan the method line - malformed methods carry malware signatures
  // (XMRig stratum JSON-RPC, Mirai/NjRAT |'|'| beacons) instead of GET/POST
  for (const threat of BODY_THREATS) {
    if (threat.pattern.test(method)) {
      signals.push({
        category: "method",
        severity: threat.severity,
        description: threat.description,
      });
      threat.pattern.lastIndex = 0;
    }
  }

  // User agent - no-agent is suspicious
  if (!userAgent) {
    signals.push({
      category: "agent",
      severity: "low",
      description: "no user agent",
    });
  }

  if (signals.length === 0) return { level: "none", signals: null };

  const level = signals.reduce<ThreatLevel>((highest, signal) => {
    return SEVERITY_RANK[signal.severity] > SEVERITY_RANK[highest]
      ? signal.severity
      : highest;
  }, "none");

  return { level, signals };
};

// === FORWARDING CHAIN ANALYSIS ===
const TRUSTED_HOPS = 2;

const parseForwardingChain = (req: Request): ForwardingChain | null => {
  const rawXff = req.headers["x-forwarded-for"];
  const cfConnectingIp = (req.headers["cf-connecting-ip"] as string) || null;
  const cfIpCountry = (req.headers["cf-ipcountry"] as string) || null;

  const xffString = Array.isArray(rawXff) ? rawXff.join(",") : rawXff;
  const chain: string[] = xffString
    ? xffString
        .split(",")
        .map((entry) => entry.trim())
        .filter(Boolean)
    : [];
  const hasCfHeaders = !!(cfConnectingIp || cfIpCountry);
  const hasChain = chain.length >= 2;

  if (!hasCfHeaders && !hasChain) return null;

  const result: ForwardingChain = {};
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

type Redactable = unknown;

const buildRedactor = (
  sensitiveKeys: RegExp | null,
): ((obj: Redactable) => Redactable) => {
  const re = sensitiveKeys || DEFAULT_SENSITIVE_KEYS;
  const redact = (obj: Redactable): Redactable => {
    if (!obj || typeof obj !== "object") return obj;
    if (Array.isArray(obj)) return obj.map(redact);
    const cleaned: Record<string, Redactable> = {};
    for (const [key, value] of Object.entries(
      obj as Record<string, Redactable>,
    )) {
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

export function honey(options: HoneyOptions): RequestHandler {
  const {
    pgPool,
    skipPaths = [],
    cookieNames = [],
    jwtSecret = null,
    redactKeys = null,
    logger = console as HoneyLogger,
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
  let jwtLib: any = null;
  if (jwtEnabled) {
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

  return function honeyMiddleware(
    req: Request,
    res: Response,
    next: NextFunction,
  ): void {
    if (skipSet.has(req.path)) return next();

    const captureStartTime = Date.now();

    res.on("finish", () => {
      let userId: string | number | null = null;
      let sessionId: string | number | null = null;
      if (jwtEnabled && jwtLib) {
        try {
          let token: string | null = null;
          for (const name of cookieNames) {
            const fromCookie = (
              req as Request & { cookies?: Record<string, string> }
            ).cookies?.[name];
            const fromHeader = req.headers?.[name.toLowerCase()];
            const candidate =
              fromCookie ||
              (Array.isArray(fromHeader) ? fromHeader[0] : fromHeader);
            if (candidate) {
              token = candidate;
              break;
            }
          }
          if (token && jwtSecret) {
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

      const threats = detectThreats({
        url: req.originalUrl || req.path,
        method: req.method,
        body: req.body,
        userAgent: userAgent,
      });

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
      const rl = (req as Request & { rateLimitInfo?: RateLimitInfo })
        .rateLimitInfo;
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
        .catch((error: Error) =>
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
