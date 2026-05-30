import type { Strategy, StrategyScoreResult } from "./Strategy.js";
import { sigmoid, subnet24 } from "../utils/strategyHelpers.js";
import type { HoneyRequest } from "../detector/types.js";

export const singleIpBurst: Strategy = {
  id: "single-ip-burst",
  related_strategy_tags: ["volume_anomaly", "credential_harvester_family"],
  default_campaign_type: "comprehensive-credential-harvester",
  default_suppress_for_ms: 8 * 60 * 60 * 1000, // 8 hours
  metrics_required: [
    "per_ip_volume",
    "per_ip_unique_paths",
    "per_ip_time_burst_sec",
  ],
  markers_observed: ["recent_env_probe", "recent_credential_probe"],
  markers_consumed: ["seen_in_subnet_spray", "seen_in_tor_distributed_scan"],

  observe(req, metrics) {
    if (req.threat_level === "none") return null;
    return {
      stream: "single-ip-burst",
      key: req.ip,
      value: req,
      request_id: req.id,
    };
  },
  score(
    requestObservations,
    metrics,
    markerSnapshotInstance,
  ): StrategyScoreResult | null {
    const firstObs = requestObservations[0];
    const ip = String(firstObs.key);
    if (ip.includes(":")) return null;
    const req = firstObs.value as HoneyRequest;
    const asn = req.ip_location?.asn;

    const volume = metrics.per_ip_volume.get(ip) ?? 0;
    const uniquePaths = metrics.per_ip_unique_paths.get(ip) ?? 0;
    const burstSec =
      metrics.per_ip_time_burst_sec.get(ip) ?? Number.POSITIVE_INFINITY;

    // suppress if already converted to a campaign
    if (
      markerSnapshotInstance.hasMarker(
        "asn_subnet",
        subnet24(ip),
        "seen_in_subnet_spray",
      )
    ) {
      return null;
    }
    if (
      asn != null &&
      markerSnapshotInstance.hasMarker("asn", asn, "seen_in_tor_distributed_scan")
    ) {
      return null;
    }

    // weighted scoring (low end = low confidence, mid-range = questionable, high end = high confidence)
    const volumeScore = sigmoid((volume - 100) / 50); // .5 at volume = 100, approx 1 at volume = 250
    const diversityScore = sigmoid((uniquePaths - 80) / 40); // .5 at uniquePaths = 80, approx .95 at uniquePaths = 200
    const burstScore =
      burstSec < 60 ? 1 : Math.max(0, 1 - (burstSec - 60) / 540); // 1 if <60s, decays to 0 at 10 min
    const confidence =
      volumeScore * 0.4 + diversityScore * 0.4 + burstScore * 0.2;

    return {
      confidence,
      evidence: {
        volume,
        uniquePaths,
        burstSec,
        volumeScore,
        diversityScore,
        burstScore,
      },
    };
  },

  identifier_from(
    key: string | number,
    scoreResult: StrategyScoreResult,
  ): string {
    return `single-ip-burst|ip=${key}`;
  },
};
