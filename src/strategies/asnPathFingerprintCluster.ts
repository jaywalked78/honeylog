import type { Strategy, StrategyScoreResult } from "./Strategy.js";
import { sigmoid, mean } from "../utils/strategyHelpers.js";

const REFIRE_SUPPRESSION_WINDOW_MS = 8 * 60 * 60 * 1000;
const MIN_IPS_FOR_NON_COINCIDENTAL_CLUSTER = 3;
const MIN_PATH_UNION_TO_RULE_OUT_SINGLE_PATH_CENSUS = 2;

// Production UA diversity is bimodal (per-request rotators ~0.9+, single-UA clients ~0.01), so a
// steep sigmoid centered at 0.8 cleanly separates the two populations.
const UA_ROTATION_MIDPOINT = 0.8;
const UA_ROTATION_STEEPNESS = 0.1;
const CLUSTER_SIZE_MIDPOINT_IPS = 5;
const CLUSTER_SIZE_STEEPNESS = 2;
const PATH_BREADTH_MIDPOINT_PATHS = 20;
const PATH_BREADTH_STEEPNESS = 10;

// Cross-/24 complement to subnetFingerprintOverlap: that strategy catches a wordlist divided across
// one /24; this one catches the same wordlist replayed whole from IPs scattered across an ASN.
export const asnPathFingerprintCluster: Strategy = {
  id: "asn-path-fingerprint-cluster",
  related_strategy_tags: ["coordinated_scan", "volume_anomaly"],
  default_campaign_type: "asn-path-fingerprint-cluster",
  default_suppress_for_ms: REFIRE_SUPPRESSION_WINDOW_MS,
  metrics_required: ["per_asn_fingerprint_clusters", "per_ip_useragent_diversity"],
  markers_observed: [],
  markers_consumed: [],

  observe(req, metrics) {
    if (req.threat_level === "none") return null;
    const asn = req.ip_location?.asn;
    if (asn == null) return null;
    // membership filter: the driver builds candidate fields (contributing_ips, samples, time_range)
    // from the observation group, so only the scored cluster's own requests may enter it
    const dominantCluster = metrics.per_asn_fingerprint_clusters.get(asn);
    if (!dominantCluster || !dominantCluster.ips.includes(req.ip)) return null;
    return {
      stream: "asn-path-fingerprint-cluster",
      key: asn,
      value: req,
      request_id: req.id,
    };
  },

  score(requestObservations, metrics): StrategyScoreResult | null {
    const asn = Number(requestObservations[0].key);
    const dominantCluster = metrics.per_asn_fingerprint_clusters.get(asn);
    if (!dominantCluster) return null;
    if (dominantCluster.ipCount < MIN_IPS_FOR_NON_COINCIDENTAL_CLUSTER) return null;
    if (dominantCluster.pathUnionSize < MIN_PATH_UNION_TO_RULE_OUT_SINGLE_PATH_CENSUS) return null;

    const meanUaDiversityAcrossClusterIps = mean(
      dominantCluster.ips.map((ip) => metrics.per_ip_useragent_diversity.get(ip) ?? 0),
    );

    const rotationScore = sigmoid(
      (meanUaDiversityAcrossClusterIps - UA_ROTATION_MIDPOINT) / UA_ROTATION_STEEPNESS,
    );
    const clusterSizeScore = sigmoid(
      (dominantCluster.ipCount - CLUSTER_SIZE_MIDPOINT_IPS) / CLUSTER_SIZE_STEEPNESS,
    );
    const breadthScore = sigmoid(
      (dominantCluster.pathUnionSize - PATH_BREADTH_MIDPOINT_PATHS) / PATH_BREADTH_STEEPNESS,
    );
    const confidence = rotationScore * 0.5 + clusterSizeScore * 0.3 + breadthScore * 0.2;

    return {
      confidence,
      evidence: {
        fingerprint: dominantCluster.fingerprint,
        ipCount: dominantCluster.ipCount,
        pathUnionSize: dominantCluster.pathUnionSize,
        uaRotation: meanUaDiversityAcrossClusterIps,
        rotationScore,
        clusterSizeScore,
        breadthScore,
      },
    };
  },

  identifier_from(key, scoreResult): string {
    return `asn-path-fingerprint-cluster|asn=${key}|fp=${scoreResult.evidence.fingerprint}`;
  },
};
