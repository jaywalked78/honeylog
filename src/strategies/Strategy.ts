import type { MetricsWithinWindow } from "../detector/metrics/MetricsWithinWindow.js";
import type { HoneyRequest } from "../detector/types.js";
import type { IpAsnFlagTracker } from "../detector/IpAsnFlagTracker.js";

export interface RequestObservationFromStrategy {
  stream: string; // strategy id
  key: string | number; // grouping key per strategy
  value: unknown;
  request_id: bigint; // for deduplication
}

export interface StrategyScoreResult {
  confidence: number; // 0..1
  evidence: Record<string, unknown>;
}

export interface Strategy {
  id: string;
  related_strategy_tags: string[]; // for cross-strategy group correlation (e.g. volume_anomaly, credential_harvester_family)
  default_campaign_type: string; // matches a catalog entry by id
  default_suppress_for_ms: number; // how long until the same identifer re-fires (Zeek SumStats style)
  metrics_required: readonly (keyof MetricsWithinWindow)[];
  flags_observed: readonly string[];
  flags_consumed: readonly string[];
  // called once per request, returns a request observation or null if the strategy doesn't apply
  observe(
    req: HoneyRequest,
    metrics: MetricsWithinWindow,
  ): RequestObservationFromStrategy | null;
  // called per unique request observation, returns a confidence score and evidence
  score(
    requestObservations: RequestObservationFromStrategy[],
    metrics: MetricsWithinWindow,
    ipAsnFlagTracker: IpAsnFlagTracker,
  ): StrategyScoreResult | null;
  // used by routing policy to group strategies by identifer e.g. "single-ip-burst|ip=XX.XX.XX.XX"
  identifier_from(
    key: string | number,
    scoreResult: StrategyScoreResult,
  ): string;
}
