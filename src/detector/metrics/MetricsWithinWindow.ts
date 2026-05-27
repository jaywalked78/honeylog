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
