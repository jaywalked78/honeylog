import { HoneyRequest } from "../detector/types.js";
import { Strategy, StrategyScoreResult } from "./Strategy.js";
import { sigmoid, subnet24 } from "../utils/strategyHelpers.js";

// Detection gates - a /24 must clear BOTH before it can fire (and write the suppression marker).
const MIN_CLUSTER_IPS = 3; // distinct IPs in the /24 (one-line knob for the future 2-IP tier)
const MIN_COHESION = 0.2; // cohesion floor: minimum average route-set overlap before IPs count as coordinated

export const subnetFingerprintOverlap: Strategy = {
  id: "subnet-fingerprint-overlap",
  related_strategy_tags: ["coordinated_scan", "credential_harvester_family"],
  default_campaign_type: "asn-subnet-env-spray",
  default_suppress_for_ms: 8 * 60 * 60 * 1000, // 8 hours
  metrics_required: ["per_asn_subnet_cohesion"],
  markers_observed: [{ scope_type: "asn_subnet", marker_name: "seen_in_subnet_spray" }],
  markers_consumed: [],

  observe(req, metrics) {
    if (req.threat_level === "none") return null;
    return {
      stream: "subnet-fingerprint-overlap",
      key: subnet24(req.ip),
      value: req,
      request_id: req.id,
    };
  },

  score(requestObservations, metrics): StrategyScoreResult | null {
    const subnet = String(requestObservations[0].key);
    const requests = requestObservations.map(
      (obs) => obs.value as HoneyRequest,
    );
    const asn = requests[0].ip_location?.asn;
    if (asn == null) return null;

    // gate 1: enough distinct IPs in THIS /24 to be a cluster (from the group, not the ASN-wide count)
    const distinctIpsInSubnet = new Set(requests.map((req) => req.ip)).size;
    if (distinctIpsInSubnet < MIN_CLUSTER_IPS) return null;

    // gate 2: the IPs' route sets actually overlap (precomputed + threat-scoped in compute())
    const cohesion = metrics.per_asn_subnet_cohesion.get(asn)?.get(subnet) ?? 0;
    if (cohesion < MIN_COHESION) return null;

    // breadth: distinct paths this cluster probed collectively (its own /24 union, from the group)
    const pathUnionSize = new Set(requests.map((req) => req.route)).size;

    const cohesionScore = sigmoid((cohesion - 0.4) / 0.12); // S-curve midpoint at 0.40 cohesion
    const clusterSizeScore = sigmoid((distinctIpsInSubnet - 5) / 2); // S-curve midpoint at 5 IPs
    const breadthScore = sigmoid((pathUnionSize - 20) / 10); // S-curve midpoint at 20 paths
    // weighted blend: cohesion dominates, then cluster size, then breadth
    const confidence =
      cohesionScore * 0.5 + clusterSizeScore * 0.3 + breadthScore * 0.2;

    return {
      confidence,
      evidence: {
        cohesion,
        distinctIpsInSubnet,
        pathUnionSize,
        cohesionScore,
        clusterSizeScore,
        breadthScore,
      },
    };
  },

  identifier_from(key, scoreResult) {
    return `${this.id}|subnet=${key}`;
  },
};
