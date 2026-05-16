/**
 * honeylog - TypeScript declarations
 *
 * These declarations describe the public API of the library. The runtime
 * source is JavaScript; this `.d.ts` file exists so TypeScript consumers
 * get full editor support and compile-time type checking.
 *
 * Hand-written rather than emitted from .ts source - keeps the library
 * itself dependency-free of a build step, while still giving TS users a
 * first-class experience.
 */

import type { Pool } from "pg";
import type { RequestHandler } from "express";

export type Severity = "low" | "medium" | "high";

export interface ThreatLogger {
  error: (...args: unknown[]) => void;
  warn?: (...args: unknown[]) => void;
  info?: (...args: unknown[]) => void;
}

export interface HoneyOptions {
  /** A pg.Pool instance. honey calls pool.query() to write log rows. Required. */
  pgPool: Pool;

  /** Paths to bypass entirely (skip logging). Defaults to []. */
  skipPaths?: string[];

  /**
   * Cookie names to attempt JWT decode from. Requires `jwtSecret` to be set
   * AND `jsonwebtoken` to be installed as a peer dependency. Defaults to [].
   */
  cookieNames?: string[];

  /**
   * Secret for JWT decode. Required only if cookieNames is non-empty.
   * Pass null to disable JWT decode entirely. Defaults to null.
   */
  jwtSecret?: string | null;

  /**
   * Custom logger for internal errors (DB write failures, JWT decode warnings).
   * Defaults to console. Pass any object with at least an `.error()` method
   * (Pino, Winston, etc. all work).
   */
  logger?: ThreatLogger;

  /**
   * Regex matching request-body keys whose values should be redacted before
   * being persisted. Defaults to a conservative pattern covering password,
   * token, secret, ssn, credit_card, authorization.
   */
  redactKeys?: RegExp;

  /**
   * Override the table name used for INSERTs. Defaults to "logs_requests".
   * Useful for non-default schemas or multi-tenant table naming.
   */
  tableName?: string;
}

/**
 * Factory that returns the honey middleware configured for your app.
 *
 * @example
 * ```ts
 * import express from "express";
 * import { honey } from "honeylog";
 * import pg from "pg";
 *
 * const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
 * const app = express();
 *
 * app.set("trust proxy", true);
 * app.use(express.json());
 * app.use(honey({ pgPool: pool, skipPaths: ["/health"] }));
 * ```
 *
 * @throws {Error} if `pgPool` is missing or not pool-shaped at factory call time.
 */
export function honey(options: HoneyOptions): RequestHandler;

/** Regex patterns matching known scanner/bot user agents. */
export const BOT_PATTERNS: readonly RegExp[];

export interface PatternThreat {
  pattern: RegExp;
  severity: Severity;
  description: string;
}

export interface MethodThreat {
  method: string;
  severity: Severity;
  description: string;
}

/** Path-based threat patterns (config probes, exploit endpoints, CVE markers, etc.). */
export const PATH_THREATS: readonly PatternThreat[];

/** Method-based threats (TRACE, PROPFIND, CONNECT, etc.). */
export const METHOD_THREATS: readonly MethodThreat[];

/** Body- and query-string-based threats (SQLi, XSS, LFI, command injection, etc.). */
export const BODY_THREATS: readonly PatternThreat[];

// =============================================================================
// GEO ENRICHMENT
// =============================================================================

export interface InitGeoOptions {
  /** Absolute path to a GeoLite2-City.mmdb file. */
  cityPath?: string;
  /** Absolute path to a GeoLite2-ASN.mmdb file. */
  asnPath?: string;
  /** Logger (defaults to console). */
  logger?: ThreatLogger;
}

export interface GeoData {
  country: string | null;
  city: string | null;
  latitude: number | null;
  longitude: number | null;
  asn: number | null;
  org: string | null;
}

/**
 * Initialize MaxMind GeoLite2 databases. Call once at app startup, BEFORE
 * mounting `honey`. Returns true if at least one database loaded.
 * Without this, `ip_location` will be null on every logged row.
 */
export function initGeo(options?: InitGeoOptions): Promise<boolean>;

/** Look up geo data for an IP. Returns null if databases aren't initialized or IP is local. */
export function geoLookup(ip: string): GeoData | null;

// =============================================================================
// IP CLASSIFICATION (Tor + ASN type)
// =============================================================================

export type IpType = "hosting" | "isp" | "corporate" | "government" | "education" | "unknown" | null;

/**
 * Fetch the Tor exit-node list from torproject.org. Call once at app startup.
 * Without this, `is_tor` will be false on every logged row.
 */
export function fetchTorExitNodes(): Promise<void>;

/** Start a 12-hour interval to refresh the Tor exit-node list. */
export function startTorRefreshInterval(): void;

/** Check whether an IP is currently in the Tor exit-node list. */
export function isTorExitNode(ip: string): boolean;

/** Classify an IP by its ASN / org into hosting / isp / corporate / etc. Requires geo data. */
export function classifyIp(geoData: GeoData | null): IpType;
