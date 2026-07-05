import { dbc } from "../helpers/database_connector.js";
import { InMemoryMarkerStore } from "../detector/MarkerSnapshot.js";
import { compute as computeMetrics } from "../detector/metrics/MetricsWithinWindow.js";
import { classifyConfidence } from "../utils/strategyHelpers.js";
import type {
  Strategy,
  StrategyScoreResult,
  RequestObservationFromStrategy,
} from "../strategies/Strategy.js";
import { singleIpBurst } from "../strategies/singleIpBurst.js";
import { subnetFingerprintOverlap } from "../strategies/subnetFingerprintOverlap.js";
import type {
  CampaignCandidateFromStrategy,
  HoneyRequest,
  IpLocation,
  IpType,
  ThreatLevel,
  ThreatDetail,
  ForwardingChain,
} from "../detector/types.js";

// Ordered pipeline: producers (coordinated-actor strategies) run first so the markers they write
// are visible to consumers (single-actor strategies) within the same epoch. Hand-ordered for alpha.
const ORDERED_STRATEGIES: Strategy[] = [subnetFingerprintOverlap, singleIpBurst];

export class CrossEpochCampaignDeduplicator {
  private map = new Map<string, number>();

  isDeduplicated(identifier: string, asOfMs: number): boolean {
    const expiresAt = this.map.get(identifier);
    if (expiresAt === undefined) return false;
    if (expiresAt <= asOfMs) return false;
    return true;
  }

  deduplicate(identifier: string, asOfMs: number, cooldownInMs: number): void {
    this.map.set(identifier, asOfMs + cooldownInMs);
  }
}

async function resolveScanRange(
  fromDate: Date | null,
  toDate: Date | null,
): Promise<[Date, Date]> {
  const scanTo = toDate ?? new Date(); // default to now
  let scanFrom: Date;
  if (fromDate !== null) {
    scanFrom = fromDate;
  } else {
    const [firstRow] = await dbc.query<{ min: Date | null }>(
      `SELECT MIN(created_at) AS min FROM logs_requests`,
    );
    const earliest = firstRow?.min;
    if (earliest == null) {
      throw new Error("No rows found in logs_requests");
    }
    scanFrom = earliest;
  }
  if (scanFrom > scanTo) {
    throw new Error(
      "scan range is invalid: from date is after to date" +
        `(${scanFrom.toISOString()} > ${scanTo.toISOString()})`,
    );
  }
  return [scanFrom, scanTo];
}

function generateEpochs(
  fromDate: Date,
  toDate: Date,
  windowInMs: number,
  stepInMs: number,
): [Date, Date][] {
  const epochs: [Date, Date][] = [];
  const endMs = toDate.getTime();
  for (let startMs = fromDate.getTime(); startMs < endMs; startMs += stepInMs) {
    const windowEndMs = Math.min(startMs + windowInMs, endMs);
    epochs.push([new Date(startMs), new Date(windowEndMs)]);
  }
  return epochs;
}

interface RequestRow {
  id: string;
  ip: string;
  route: string;
  method: string;
  user_agent: string | null;
  created_at: Date;
  ip_location: IpLocation | null;
  ip_type: IpType | null;
  is_tor: boolean | null;
  forwarding_chain: ForwardingChain | null;
  threat_level: ThreatLevel;
  threat_details: ThreatDetail[] | null;
}

// IPv4 only for alpha: subnet24() requires four dot-octets (xxx.xxx.xxx.xxx), so IPv6 rows would throw.
async function loadRequests(
  epochStart: Date,
  epochEnd: Date,
): Promise<HoneyRequest[]> {
  const rows = await dbc.query<RequestRow>(
    `
    SELECT
      id, host(ip) AS ip, route, method, user_agent, created_at,
      ip_location, ip_type, is_tor, forwarding_chain, threat_level, threat_details
    FROM logs_requests
    WHERE created_at >= $1 AND created_at < $2
      AND family(ip) = 4
    ORDER BY created_at ASC
    `,
    [epochStart, epochEnd],
  );

  return rows.map((row) => ({
    id: BigInt(row.id),
    ip: row.ip,
    route: row.route,
    method: row.method,
    user_agent: row.user_agent,
    created_at: row.created_at,
    ip_location: row.ip_location,
    ip_type: row.ip_type,
    is_tor: row.is_tor ?? false,
    forwarding_chain: row.forwarding_chain,
    threat_level: row.threat_level,
    threat_details: row.threat_details ?? [],
  }));
}

function groupObservationsByKey(
  observations: RequestObservationFromStrategy[],
): Map<string, RequestObservationFromStrategy[]> {
  const groups = new Map<string, RequestObservationFromStrategy[]>();
  for (const observation of observations) {
    const key = String(observation.key);
    const group = groups.get(key);
    if (group) {
      group.push(observation);
    } else {
      groups.set(key, [observation]);
    }
  }
  return groups;
}

function buildCandidate(
  strategy: Strategy,
  identifier: string,
  scoreResult: StrategyScoreResult,
  observations: RequestObservationFromStrategy[],
): CampaignCandidateFromStrategy {
  const requests = observations.map((obs) => obs.value as HoneyRequest);
  const uniquePaths = [...new Set(requests.map((req) => req.route))];
  const uniqueUserAgents = [
    ...new Set(
      requests
        .map((req) => req.user_agent)
        .filter((ua): ua is string => ua !== null),
    ),
  ];
  const sorted = [...requests].sort(
    (a, b) => a.created_at.getTime() - b.created_at.getTime(),
  );

  return {
    strategy_id: strategy.id,
    default_campaign_type: strategy.default_campaign_type,
    identifier,
    confidence: scoreResult.confidence,
    campaign_threat_level: classifyConfidence(scoreResult.confidence),
    evidence: scoreResult.evidence,
    related_strategy_tags: strategy.related_strategy_tags,
    time_range: {
      first: sorted[0].created_at,
      last: sorted[sorted.length - 1].created_at,
    },
    sample_paths_probed: uniquePaths.slice(0, 10),
    sample_user_agents: uniqueUserAgents.slice(0, 5),
    contributing_ips: [...new Set(requests.map((req) => req.ip))],
  };
}

async function runEpoch(
  markerStore: InMemoryMarkerStore,
  deduplicator: CrossEpochCampaignDeduplicator,
  strategies: Strategy[],
  epochStart: Date,
  epochEnd: Date,
  minConfidence: number,
): Promise<CampaignCandidateFromStrategy[]> {
  const requests = await loadRequests(epochStart, epochEnd);
  if (requests.length === 0) return [];

  const metrics = computeMetrics(requests);
  const candidates: CampaignCandidateFromStrategy[] = [];

  for (const strategy of strategies) {
    // Fresh snapshot per strategy: a consumer sees the markers any earlier producer wrote this epoch.
    const markerSnapshot = markerStore.snapshotMarkers(epochEnd);

    const observations = requests
      .map((req) => strategy.observe(req, metrics))
      .filter((obs): obs is RequestObservationFromStrategy => obs !== null);

    const grouped = groupObservationsByKey(observations);
    for (const [, group] of grouped) {
      const scoreResult = strategy.score(group, metrics, markerSnapshot);
      if (scoreResult === null || scoreResult.confidence < minConfidence) {
        continue;
      }

      const identifier = strategy.identifier_from(group[0].key, scoreResult);
      if (deduplicator.isDeduplicated(identifier, epochEnd.getTime())) {
        continue;
      }

      candidates.push(buildCandidate(strategy, identifier, scoreResult, group));
      deduplicator.deduplicate(
        identifier,
        epochEnd.getTime(),
        strategy.default_suppress_for_ms,
      );

      // Record this strategy's markers (scope_value = the group key) so later strategies on the same
      // actor read them and stand down this epoch.
      const expiresAtMs = epochEnd.getTime() + strategy.default_suppress_for_ms;
      for (const marker of strategy.markers_observed) {
        markerStore.recordMarker(
          marker.scope_type,
          group[0].key,
          marker.marker_name,
          expiresAtMs,
        );
      }
    }
  }

  return candidates;
}

function jsonReplacerForNonFinite(_key: string, value: unknown): unknown {
  if (typeof value === "number" && !Number.isFinite(value)) {
    if (Number.isNaN(value)) return "NaN";
    return value > 0 ? "Infinity" : "-Infinity";
  }
  return value;
}

function formatEvidenceValue(value: unknown): string {
  if (typeof value === "number") {
    return Number.isInteger(value) ? String(value) : value.toFixed(3);
  }
  return String(value);
}

function renderOutput(
  candidates: CampaignCandidateFromStrategy[],
  format: string,
): void {
  if (candidates.length === 0) {
    console.log("No candidates emitted.");
    return;
  }

  const sorted = [...candidates].sort((a, b) => b.confidence - a.confidence);

  if (format === "jsonl") {
    for (const candidate of sorted) {
      console.log(JSON.stringify(candidate, jsonReplacerForNonFinite));
    }
    return;
  }

  console.log(`\n${sorted.length} candidate(s):\n`);
  for (const candidate of sorted) {
    const evidence = Object.entries(candidate.evidence)
      .map(([key, value]) => `${key}=${formatEvidenceValue(value)}`)
      .join(" ");
    console.log(
      `${candidate.confidence.toFixed(3)}  ${candidate.identifier}\n` +
        `        ${evidence}\n` +
        `        ${candidate.time_range.first.toISOString()} -> ${candidate.time_range.last.toISOString()}\n` +
        `        paths: ${candidate.sample_paths_probed.slice(0, 3).join(", ")}`,
    );
  }
}

function getArgValue(args: string[], name: string): string | undefined {
  return args.find((arg) => arg.startsWith(`--${name}=`))?.split("=")[1];
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  // Optional output filter. All strategies still RUN (producers must run for suppression to happen);
  // this only limits which candidates get printed.
  const strategyFilter = getArgValue(args, "strategy");
  const knownIds = ORDERED_STRATEGIES.map((strategy) => strategy.id);
  if (strategyFilter !== undefined && !knownIds.includes(strategyFilter)) {
    console.error(
      `Unknown --strategy "${strategyFilter}". Known: ${knownIds.join(", ")}`,
    );
    process.exit(1);
  }

  const fromArgValue = getArgValue(args, "from");
  const fromDate = fromArgValue ? new Date(fromArgValue) : null;
  const toArgValue = getArgValue(args, "to");
  const toDate = toArgValue ? new Date(toArgValue) : null;

  const windowInMsArg = parseInt(getArgValue(args, "windowInMs") ?? "");
  const windowInMs = isNaN(windowInMsArg) ? 21600000 : windowInMsArg; // 6h default
  const stepInMsArg = parseInt(getArgValue(args, "stepInMs") ?? "");
  const stepInMs = isNaN(stepInMsArg) ? windowInMs : stepInMsArg; // tumbling default

  const minConfidenceArg = parseFloat(getArgValue(args, "minConfidence") ?? "");
  const minConfidence = isNaN(minConfidenceArg) ? 0.5 : minConfidenceArg;

  const outputFormat = getArgValue(args, "output") ?? "table";

  const markerStore = new InMemoryMarkerStore();
  const deduplicator = new CrossEpochCampaignDeduplicator();

  try {
    const [scanFrom, scanTo] = await resolveScanRange(fromDate, toDate);
    console.log(
      `Scanning ${knownIds.join(" -> ")} from ${scanFrom.toISOString()} to ${scanTo.toISOString()}`,
    );

    const epochs = generateEpochs(scanFrom, scanTo, windowInMs, stepInMs);
    console.log(
      `Generated ${epochs.length} epoch(s) (window=${windowInMs}ms step=${stepInMs}ms)`,
    );

    const allCandidates: CampaignCandidateFromStrategy[] = [];
    for (const [epochStart, epochEnd] of epochs) {
      const epochCandidates = await runEpoch(
        markerStore,
        deduplicator,
        ORDERED_STRATEGIES,
        epochStart,
        epochEnd,
        minConfidence,
      );
      allCandidates.push(...epochCandidates);
    }

    const toRender =
      strategyFilter === undefined
        ? allCandidates
        : allCandidates.filter(
            (candidate) => candidate.strategy_id === strategyFilter,
          );
    renderOutput(toRender, outputFormat);
  } catch (error) {
    console.error(error);
    process.exit(1);
  } finally {
    await dbc.close();
  }
}

await main();
