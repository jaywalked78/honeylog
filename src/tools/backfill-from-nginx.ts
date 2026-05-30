import { geoLookup } from "../helpers/geoLookup.js";
import { classifyIp } from "../helpers/ipClassifier.js";
import type { IpLocation, IpType } from "../detector/types.js";
import {
  detectThreats,
  type ThreatLevel,
  type ThreatSignal,
} from "../middleware/honey.js";
import { BOT_PATTERNS } from "../middleware/threatDefinitions.js";
import { dbc } from "../helpers/database_connector.js";

export interface ParsedNginxLog {
  ip: string;
  remote_user: string | null;
  timestamp: Date;
  method: string;
  url: string;
  protocol: string;
  status: number;
  response_size: number | null;
  referer: string | null;
  user_agent: string | null;
}

const NGINX_COMBINED_LOG_FORMAT =
  /^(\S+) (\S+) (\S+) \[([^\]]+)\] "(\S+) (.+?) (\S+)" (\d+) (\d+|-) "([^"]*)" "([^"]*)"$/;

// Timestamp parser

const MONTHS: Record<string, number> = {
  Jan: 0,
  Feb: 1,
  Mar: 2,
  Apr: 3,
  May: 4,
  Jun: 5,
  Jul: 6,
  Aug: 7,
  Sep: 8,
  Oct: 9,
  Nov: 10,
  Dec: 11,
};

const NGINX_TIMESTAMP_FORMAT =
  /^(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-]\d{4})$/;

function parseNginxTimestamp(str: string): Date {
  const match = NGINX_TIMESTAMP_FORMAT.exec(str);
  if (!match) throw new Error(`Invalid timestamp: ${str}`);
  const [, day, month, year, hour, minute, second, timezone] = match;
  const isoTimezone = `${timezone.slice(0, 3)}:${timezone.slice(3)}`;
  return new Date(
    `${year}-${String(MONTHS[month] + 1).padStart(2, "0")}-${day}T${hour}:${minute}:${second}${isoTimezone}`,
  );
}

// Log parser
export function parseNginxLog(line: string): ParsedNginxLog | null {
  const match = NGINX_COMBINED_LOG_FORMAT.exec(line);
  if (!match) return null;

  const [
    ,
    ip,
    ,
    remoteUser,
    timestampString,
    method,
    url,
    protocol,
    status,
    responseSize,
    referer,
    userAgent,
  ] = match;

  return {
    ip,
    remote_user: remoteUser === "-" ? null : remoteUser,
    timestamp: parseNginxTimestamp(timestampString),
    method,
    url,
    protocol,
    status: parseInt(status, 10),
    response_size: responseSize === "-" ? null : parseInt(responseSize, 10),
    referer: referer === "-" ? null : referer,
    user_agent: userAgent === "-" || userAgent === "" ? null : userAgent,
  };
}

// IP enrichment
export interface IpEnrichment {
  ip_location: IpLocation | null;
  ip_type: IpType | null;
}

export function buildIpEnrichment(): (ip: string) => IpEnrichment {
  const geoCache = new Map<string, IpEnrichment>();

  return function (ip: string): IpEnrichment {
    const cached = geoCache.get(ip);
    if (cached) return cached;

    const ipLocation = geoLookup(ip);
    const ipType = classifyIp(ipLocation);
    const enrichment = { ip_location: ipLocation, ip_type: ipType };

    geoCache.set(ip, enrichment);
    return enrichment;
  };
}

function deriveSource(ua: string | null): string {
  if (!ua) return "no-agent";
  if (/^curl\//i.test(ua)) return "curl";
  if (/postman/i.test(ua)) return "postman";
  if (/insomnia/i.test(ua)) return "insomnia";
  if (BOT_PATTERNS.some((p) => p.test(ua))) return "bot";
  if (/mozilla|chrome|safari|firefox|edge|opera/i.test(ua)) return "browser";
  return "unknown";
}

export interface BackfilledRow {
  ip: string;
  method: string;
  route: string;
  full_url: string;
  status_code: number;
  user_agent: string | null;
  response_size: number | null;
  ip_location: IpLocation | null;
  ip_type: IpType | null;
  is_tor: null;
  threat_level: ThreatLevel;
  threat_details: ThreatSignal[] | null;
  forwarding_chain: null;
  created_at: Date;
}

export function enrichRequest(
  parsed: ParsedNginxLog,
  enrichIp: (ip: string) => IpEnrichment,
): BackfilledRow {
  const { ip_location, ip_type } = enrichIp(parsed.ip);

  const threats = detectThreats({
    url: parsed.url,
    method: parsed.method,
    userAgent: parsed.user_agent,
  });

  return {
    ip: parsed.ip,
    method: parsed.method,
    route: parsed.url,
    full_url: parsed.url,
    status_code: parsed.status,
    user_agent: parsed.user_agent,
    response_size: parsed.response_size,
    ip_location,
    ip_type,
    is_tor: null,
    threat_level: threats.level,
    threat_details: threats.signals,
    forwarding_chain: null,
    created_at: parsed.timestamp,
  };
}

// DB functions
export async function findLastRealRowTimestamp(): Promise<Date | null> {
  const result = await dbc.query<{ max: Date | null }>(
    `SELECT MAX(created_at) AS max FROM logs_requests WHERE is_tor IS NOT NULL`,
  );
  return result[0]?.max ?? null;
}

export async function countBackfilledRowsInWindow(
  fromDate: Date,
  toDate: Date,
): Promise<number> {
  const result = await dbc.query<{ count: string }>(
    `SELECT COUNT(*)::text AS count
     FROM logs_requests
     WHERE created_at >= $1 AND created_at < $2 AND is_tor IS NULL`,
    [fromDate, toDate],
  );
  return parseInt(result[0].count, 10);
}

const COLS_PER_ROW = 21;

export async function bulkInsertBackfilledRows(
  rows: BackfilledRow[],
): Promise<void> {
  if (rows.length === 0) return;

  const valuesClauses: string[] = [];
  const params: unknown[] = [];

  for (let i = 0; i < rows.length; i++) {
    const offset = i * COLS_PER_ROW;
    const placeholders = Array.from(
      { length: COLS_PER_ROW },
      (_, j) => `$${offset + j + 1}`,
    ).join(", ");
    valuesClauses.push(`(${placeholders})`);

    const r = rows[i];
    params.push(
      null, // user_id
      null, // session_id
      r.method,
      r.route,
      r.full_url,
      r.status_code,
      r.ip,
      r.user_agent,
      deriveSource(r.user_agent), //source
      null, // body
      0, // response_time_ms
      r.response_size,
      null, // origin
      r.threat_level,
      r.threat_details ? JSON.stringify(r.threat_details) : null,
      r.ip_location ? JSON.stringify(r.ip_location) : null,
      null, // error_message
      r.ip_type,
      r.is_tor, // null for backfilled
      r.forwarding_chain ? JSON.stringify(r.forwarding_chain) : null,
      r.created_at,
    );
  }

  const sql = `
    INSERT INTO logs_requests
      (user_id, session_id, method, route, full_url, status_code, ip, user_agent,
       source, request_body, response_time_ms, response_size, origin, threat_level,
       threat_details, ip_location, error_message, ip_type, is_tor, forwarding_chain,
       created_at)
    VALUES ${valuesClauses.join(", ")}
  `;

  await dbc.query(sql, params);
}
