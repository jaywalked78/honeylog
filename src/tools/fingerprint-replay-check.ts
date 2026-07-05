import assert from "node:assert";
import { dbc } from "../helpers/database_connector.js";
import { compute } from "../detector/metrics/MetricsWithinWindow.js";
import { asnPathFingerprintCluster } from "../strategies/asnPathFingerprintCluster.js";
import { detectThreats } from "../middleware/honey.js";
import type { HoneyRequest, IpLocation, IpType } from "../detector/types.js";
import type { RequestObservationFromStrategy } from "../strategies/Strategy.js";

const KNOWN_ANSWER_CORPUS_START = "2026-06-12T00:00:00Z"; // append-only table: a pinned range replays identically every run
const KNOWN_ANSWER_CORPUS_END = "2026-06-28T00:00:00Z";
const MINED_CAMPAIGN_ASN = 396982;
const MIN_EXPECTED_CLUSTER_IPS = 3;

interface ReplayRow {
  id: string;
  ip: string;
  route: string;
  full_url: string;
  method: string;
  user_agent: string | null;
  created_at: Date;
  ip_location: IpLocation | null;
  ip_type: IpType | null;
  is_tor: boolean | null;
  request_body: unknown;
}

async function loadKnownAnswerCorpusReclassifiedWithCurrentPatterns(): Promise<HoneyRequest[]> {
  const rows = await dbc.query<ReplayRow>(
    `
    SELECT
      id, host(ip) AS ip, route, full_url, method, user_agent, created_at,
      ip_location, ip_type, is_tor, request_body
    FROM logs_requests
    WHERE created_at >= $1 AND created_at < $2
      AND family(ip) = 4
    ORDER BY created_at ASC
    `,
    [KNOWN_ANSWER_CORPUS_START, KNOWN_ANSWER_CORPUS_END],
  );

  // stored threat_level is stale (reflects the pattern version deployed when the row landed)
  return rows.map((row) => {
    const freshClassification = detectThreats({
      url: row.full_url,
      method: row.method,
      body: row.request_body ?? undefined,
      userAgent: row.user_agent ?? undefined,
    });
    return {
      id: BigInt(row.id),
      ip: row.ip,
      route: row.route,
      method: row.method,
      user_agent: row.user_agent,
      created_at: row.created_at,
      ip_location: row.ip_location,
      ip_type: row.ip_type,
      is_tor: row.is_tor ?? false,
      forwarding_chain: null,
      threat_level: freshClassification.level,
      threat_details: [],
    };
  });
}

async function main(): Promise<void> {
  const requests = await loadKnownAnswerCorpusReclassifiedWithCurrentPatterns();
  assert.ok(requests.length > 0, "known-answer corpus returned no rows - wrong DB or schema?");
  console.log(`Loaded ${requests.length} rows from known-answer corpus, re-classified`);

  const metrics = compute(requests);

  const observationsByAsn = new Map<number, RequestObservationFromStrategy[]>();
  for (const req of requests) {
    const observation = asnPathFingerprintCluster.observe(req, metrics);
    if (!observation) continue;
    const asn = observation.key as number;
    if (!observationsByAsn.has(asn)) observationsByAsn.set(asn, []);
    observationsByAsn.get(asn)!.push(observation);
  }

  const minedCampaignObservations = observationsByAsn.get(MINED_CAMPAIGN_ASN);
  assert.ok(minedCampaignObservations, "expected AS396982 observations");

  const result = asnPathFingerprintCluster.score(
    minedCampaignObservations,
    metrics,
    undefined as never,
  );
  assert.ok(result, "expected AS396982 to score a fingerprint cluster");
  assert.ok(
    (result.evidence.ipCount as number) >= MIN_EXPECTED_CLUSTER_IPS,
    `expected a >=${MIN_EXPECTED_CLUSTER_IPS}-IP cluster, got ${result.evidence.ipCount}`,
  );

  console.log("OK", {
    ipCount: result.evidence.ipCount,
    pathUnionSize: result.evidence.pathUnionSize,
    uaRotation: result.evidence.uaRotation,
    confidence: result.confidence,
    identifier: asnPathFingerprintCluster.identifier_from(MINED_CAMPAIGN_ASN, result),
  });
}

main()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(() => dbc.close());
