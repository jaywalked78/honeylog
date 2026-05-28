import type { HoneyRequest } from "../types.js";

export type CfHeaderConsistency =
  | "legit"
  | "absent"
  | "forged"
  | "integer_encoded";

export interface MetricsWithinWindow {
  // Per-request (keyed by request id)
  forged_cf_internal_ip: Map<bigint, boolean>;
  cf_header_consistency: Map<bigint, CfHeaderConsistency>;
  path_basename: Map<bigint, string>;
  path_parent_dir: Map<bigint, string>;
  path_extension: Map<bigint, string>;

  // Per-IP (keyed by IP string)
  per_ip_volume: Map<string, number>;
  per_ip_unique_paths: Map<string, number>;
  per_ip_useragent_diversity: Map<string, number>;
  per_ip_basename_to_prefix_ratio: Map<string, number>;
  per_ip_time_burst_sec: Map<string, number>;
  per_ip_get_post_pairing_rate: Map<string, number>;
  per_ip_encoded_dot_ratio: Map<string, number>;
  per_ip_same_basename_extension_count: Map<string, number>;

  // Per-ASN (keyed by ASN number)
  per_asn_distinct_ips: Map<number, number>;
  per_asn_tor_concentration: Map<number, number>;
  per_asn_path_union_size: Map<number, number>;
  per_asn_subnet_cohesion: Map<number, Map<string, number>>; // asn -> /24 -> Jaccard

  // Window-global
  method_global_rarity: Map<string, number>; // method -> fraction of all traffic in window
}

function computeBurstSec(reqs: HoneyRequest[]): number {
  if (reqs.length < 2) return Number.POSITIVE_INFINITY;
  let min = Infinity;
  let max = -Infinity;
  for (const req of reqs) {
    const time = req.created_at.getTime();
    if (time < min) min = time;
    if (time > max) max = time;
  }
  return (max - min) / 1000;
}

export function compute(requests: HoneyRequest[]): MetricsWithinWindow {
  const metrics: MetricsWithinWindow = {
    forged_cf_internal_ip: new Map(),
    cf_header_consistency: new Map(),
    path_basename: new Map(),
    path_parent_dir: new Map(),
    path_extension: new Map(),
    per_ip_volume: new Map(),
    per_ip_unique_paths: new Map(),
    per_ip_useragent_diversity: new Map(),
    per_ip_basename_to_prefix_ratio: new Map(),
    per_ip_time_burst_sec: new Map(),
    per_ip_get_post_pairing_rate: new Map(),
    per_ip_encoded_dot_ratio: new Map(),
    per_ip_same_basename_extension_count: new Map(),
    per_asn_distinct_ips: new Map(),
    per_asn_tor_concentration: new Map(),
    per_asn_path_union_size: new Map(),
    per_asn_subnet_cohesion: new Map(),
    method_global_rarity: new Map(),
  };

  const ipBuckets = new Map<string, HoneyRequest[]>();
  for (const req of requests) {
    if (!ipBuckets.has(req.ip)) ipBuckets.set(req.ip, []);
    ipBuckets.get(req.ip)!.push(req);
  }

  for (const [ip, reqs] of ipBuckets) {
    metrics.per_ip_volume.set(ip, reqs.length);
    metrics.per_ip_unique_paths.set(ip, new Set(reqs.map((r) => r.route)).size);
    metrics.per_ip_time_burst_sec.set(ip, computeBurstSec(reqs));
  }

  return metrics;
}
