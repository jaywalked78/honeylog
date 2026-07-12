import type {
  CampaignCandidateFromStrategy,
  HoneyRequest,
} from "../detector/types.js";

// Shared test fixtures. Lives under src/ so tests can import it with the same .js specifiers as source,
// but excluded from the build (tsconfig.build.json) so it never ships to dist.

let sequentialId = 0;

// Build a HoneyRequest with sensible defaults; pass overrides for the fields a test cares about.
// id auto-increments so request_id stays unique across a test without callers tracking it.
export function makeRequest(overrides: Partial<HoneyRequest> = {}): HoneyRequest {
  sequentialId += 1;
  return {
    id: BigInt(sequentialId),
    ip: "1.1.1.1",
    route: "/.env",
    method: "GET",
    user_agent: "ua",
    created_at: new Date("2026-06-12T03:00:00.000Z"),
    ip_location: {
      asn: 396982,
      org: "test",
      city: null,
      country: "US",
      latitude: null,
      longitude: null,
    },
    ip_type: "hosting",
    is_tor: false,
    forwarding_chain: null,
    threat_level: "high",
    threat_details: [],
    ...overrides,
  };
}

// Known-matching attack paths. Self-validated in strategyHelpers.test.ts so a future PATH_THREATS
// change that stops matching one of these fails loudly rather than silently weakening the spray tests.
export const ATTACK_POOL = [
  "/.env", "/.env.local", "/.env.production", "/.git/config", "/.aws/credentials",
  "/.ssh/id_rsa", "/wp-config.php", "/phpinfo.php", "/config.php", "/backup.sql",
  "/admin/.env", "/api/.env", "/staging/.env", "/laravel/.env", "/server/.env",
  "/actuator/env", "/actuator/heapdump", "/.svn/entries", "/.DS_Store", "/credentials.json",
  "/.env.dev", "/.env.staging", "/.env.bak", "/database.yml", "/secrets.yml",
];

export function makeCandidate(
  overrides: Partial<CampaignCandidateFromStrategy> = {},
): CampaignCandidateFromStrategy {
  return {
    strategy_id: "single-ip-burst",
    default_campaign_type: "generic-burst",
    identifier: "single-ip-burst|ip=203.0.113.7",
    confidence: 0.72,
    campaign_threat_level: "medium",
    evidence: { requestCount: 42, burstScore: 0.9 },
    related_strategy_tags: ["burst"],
    time_range: {
      first: new Date("2026-06-12T00:00:00.000Z"),
      last: new Date("2026-06-12T00:45:00.000Z"),
    },
    sample_paths_probed: ["/.env", "/wp-login.php"],
    sample_user_agents: ["Mozilla/5.0 zgrab/0.x"],
    contributing_ips: ["203.0.113.7"],
    ...overrides,
  };
}
