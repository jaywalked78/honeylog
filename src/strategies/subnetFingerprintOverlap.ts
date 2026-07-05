import { HoneyRequest } from "../detector/types.js";
import { Strategy, StrategyScoreResult } from "./Strategy.js";
import { sigmoid, subnet24, isAttackPath } from "../utils/strategyHelpers.js";

// Detection gate: enough distinct IPs in the /24 to be a cluster (one-line knob for the future 2-IP tier).
// The old MIN_COHESION floor is gone - maxOR exists precisely because breadth-led sprays have cohesion ~= 0;
// the attack-path gate in score() replaces it.
const MIN_CLUSTER_IPS = 3;

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
    if (req.is_tor) return null; // hand the Tor pool to tor-distributed-scan; it is incoherent noise here
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

    // gate 2 (replaces the old cohesion floor): the cluster must collectively probe at least one
    // PATH_THREATS-matched route. breadth = distinct attack paths across the /24.
    const attackPathCount = new Set(
      requests.filter((req) => isAttackPath(req.route)).map((req) => req.route),
    ).size;
    if (attackPathCount < 1) return null;

    // gate 3 (ONVIF guard): a single shared canonical path is a census, not a spray (min_unique_paths > 1).
    const pathUnionSize = new Set(requests.map((req) => req.route)).size;
    if (pathUnionSize < 2) return null;

    // cohesion is precomputed attack-scoped + Tor-excluded in compute()
    const cohesion = metrics.per_asn_subnet_cohesion.get(asn)?.get(subnet) ?? 0;

    const sizeScore = sigmoid((distinctIpsInSubnet - 5) / 2); // midpoint 5 IPs
    const cohesionScore = sigmoid((cohesion - 0.4) / 0.12); // S-curve midpoint at 0.40 cohesion
    const breadthScore = sigmoid((attackPathCount - 8) / 5); // midpoint 8 attack paths
    // maxOR: tight overlap (cohesion) OR broad enumeration (breadth). The two archetypes are
    // anti-correlated, so ORing them catches both convergent cred clusters and divided bursts.
    const confidence = sizeScore * 0.4 + Math.max(cohesionScore, breadthScore) * 0.6;

    return {
      confidence,
      evidence: {
        cohesion,
        distinctIpsInSubnet,
        attackPathCount,
        pathUnionSize,
        sizeScore,
        cohesionScore,
        breadthScore,
      },
    };
  },

  identifier_from(key, scoreResult) {
    return `${this.id}|subnet=${key}`;
  },
};
