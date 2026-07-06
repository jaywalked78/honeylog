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
import { asnPathFingerprintCluster } from "../strategies/asnPathFingerprintCluster.js";
import { uaReputation } from "../strategies/uaReputation.js";
import type {
  CampaignCandidateFromStrategy,
  HoneyRequest,
  IpLocation,
  IpType,
  ThreatLevel,
  ThreatDetail,
  ForwardingChain,
} from "../detector/types.js";
import type { CampaignRecordStore } from "../detector/persistence/campaignRecordStore.js";
import { InMemoryCampaignRecordStore } from "../detector/persistence/InMemoryCampaignRecordStore.js";
import { PostgresCampaignRecordStore } from "../detector/persistence/PostgresCampaignRecordStore.js";
import { jsonReplacerForNonFinite } from "../detector/persistence/campaignRecordStore.js";

// Ordered pipeline: producers (coordinated-actor strategies) run first so the markers they write
// are visible to consumers (single-actor strategies) within the same epoch. Hand-ordered for alpha.
const ORDERED_STRATEGIES: Strategy[] = [
  subnetFingerprintOverlap,
  asnPathFingerprintCluster,
  uaReputation,
  singleIpBurst,
];

interface CandidateUpsertReport {
  candidate: CampaignCandidateFromStrategy;
  outcome: "inserted" | "updated";
  times_fired: number;
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
  store: CampaignRecordStore,
  strategies: Strategy[],
  epochStart: Date,
  epochEnd: Date,
  minConfidence: number,
): Promise<CandidateUpsertReport[]> {
  const requests = await loadRequests(epochStart, epochEnd);
  if (requests.length === 0) return [];

  const metrics = computeMetrics(requests);
  const reports: CandidateUpsertReport[] = [];

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
      const candidate = buildCandidate(strategy, identifier, scoreResult, group);
      const upsertResult = await store.upsertCandidate(candidate, "backtest");
      reports.push({
        candidate,
        outcome: upsertResult.outcome,
        times_fired: upsertResult.campaign.times_fired,
      });

      // Record this strategy's markers (scope_value = the group key) so later strategies on the same
      // actor read them and stand down this epoch. Re-fires re-extend expiry: active actors stay marked.
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

  return reports;
}

function formatEvidenceValue(value: unknown): string {
  if (typeof value === "number") {
    return Number.isInteger(value) ? String(value) : value.toFixed(3);
  }
  return String(value);
}

function renderOutput(reports: CandidateUpsertReport[], format: string): void {
  if (reports.length === 0) {
    console.log("No candidates emitted.");
    return;
  }

  const sorted = [...reports].sort(
    (a, b) => b.candidate.confidence - a.candidate.confidence,
  );

  if (format === "jsonl") {
    for (const report of sorted) {
      console.log(
        JSON.stringify(
          {
            ...report.candidate,
            outcome: report.outcome,
            times_fired: report.times_fired,
          },
          jsonReplacerForNonFinite,
        ),
      );
    }
    return;
  }

  console.log(`\n${sorted.length} candidate fire(s):\n`);
  for (const { candidate, outcome, times_fired } of sorted) {
    if (outcome === "updated") {
      console.log(
        `${candidate.confidence.toFixed(3)}  ${candidate.identifier}  (re-fire #${times_fired})`,
      );
      continue;
    }
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

async function renderActiveSummary(
  store: CampaignRecordStore,
): Promise<void> {
  const active = await store.listByStatus("active");
  if (active.length === 0) return;
  console.log(`\nActive campaigns (${active.length}):\n`);
  for (const row of active) {
    console.log(
      `${row.peak_confidence.toFixed(3)}  ${row.identifier}\n` +
        `        fired ${row.times_fired}x  latest ${row.confidence.toFixed(3)}  ` +
        `${row.first_seen.toISOString()} -> ${row.last_seen.toISOString()}`,
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

  const persist = args.includes("--persist");
  const markerStore = new InMemoryMarkerStore();
  const store: CampaignRecordStore = persist
    ? new PostgresCampaignRecordStore(dbc.getPool())
    : new InMemoryCampaignRecordStore();

  try {
    const [scanFrom, scanTo] = await resolveScanRange(fromDate, toDate);
    console.log(
      `Scanning ${knownIds.join(" -> ")} from ${scanFrom.toISOString()} to ${scanTo.toISOString()}`,
    );
    if (persist) {
      console.log("Persisting candidates to campaigns (source=backtest)");
    }

    const epochs = generateEpochs(scanFrom, scanTo, windowInMs, stepInMs);
    console.log(
      `Generated ${epochs.length} epoch(s) (window=${windowInMs}ms step=${stepInMs}ms)`,
    );

    const allReports: CandidateUpsertReport[] = [];
    for (const [epochStart, epochEnd] of epochs) {
      const epochReports = await runEpoch(
        markerStore,
        store,
        ORDERED_STRATEGIES,
        epochStart,
        epochEnd,
        minConfidence,
      );
      allReports.push(...epochReports);
    }

    const toRender =
      strategyFilter === undefined
        ? allReports
        : allReports.filter(
            (report) => report.candidate.strategy_id === strategyFilter,
          );
    renderOutput(toRender, outputFormat);
    if (outputFormat !== "jsonl") {
      await renderActiveSummary(store);
    }
  } catch (error) {
    console.error(error);
    process.exit(1);
  } finally {
    await dbc.close();
  }
}

await main();
