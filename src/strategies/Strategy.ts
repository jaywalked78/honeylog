import type { MetricsWithinWindow } from "../detector/metrics/MetricsWithinWindow.js";
import type { HoneyRequest } from "../detector/types.js";
import type { MarkerSnapshot, MarkerScope } from "../detector/MarkerSnapshot.js";

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

export interface ProducedMarker {
  scope_type: MarkerScope;
  marker_name: string;
}

export interface Strategy {
  id: string;
  related_strategy_tags: string[]; // for cross-strategy group correlation (e.g. volume_anomaly, credential_harvester_family)
  default_campaign_type: string; // matches a catalog entry by id
  default_suppress_for_ms: number; // how long until the same identifer re-fires (Zeek SumStats style)
  metrics_required: readonly (keyof MetricsWithinWindow)[];
  // Markers this strategy leaves when it fires - recorded against the group key, so a later strategy
  // on the same ground reads them and stays out. Every declared marker fires whenever the strategy
  // does; a content-conditional marker (only when env paths were hit, say) needs a per-marker
  // predicate added here before it can be expressed.
  markers_observed: readonly ProducedMarker[];
  markers_consumed: readonly string[];
  // called once per request, returns a request observation or null if the strategy doesn't apply
  observe(
    req: HoneyRequest,
    metrics: MetricsWithinWindow,
  ): RequestObservationFromStrategy | null;
  // called per unique request observation, returns a confidence score and evidence
  score(
    requestObservations: RequestObservationFromStrategy[],
    metrics: MetricsWithinWindow,
    markerSnapshotInstance: MarkerSnapshot,
  ): StrategyScoreResult | null;
  // used by routing policy to group strategies by identifer e.g. "single-ip-burst|ip=XX.XX.XX.XX"
  identifier_from(
    key: string | number,
    scoreResult: StrategyScoreResult,
  ): string;
}
