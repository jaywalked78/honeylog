import type { HoneyRequest } from "../types.js";
import { jaccard, subnet24 } from "../../utils/strategyHelpers.js";

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

// Cohesion of a /24: average Jaccard overlap across every combination of the IPs' route sets.
// Fewer than 2 sets means no pair to compare, so there is no overlap to measure: 0.
function averageJaccardBetweenSets(routeSets: Set<string>[]): number {
  if (routeSets.length < 2) return 0;
  let total = 0;
  let comparisons = 0;
  for (let i = 0; i < routeSets.length; i++) {
    for (let j = i + 1; j < routeSets.length; j++) {
      total += jaccard(routeSets[i], routeSets[j]);
      comparisons++;
    }
  }
  return total / comparisons;
}

// The per-ASN route data is a 4-level nested Map. The levels are named after a filing cabinet so
// the nesting stays readable: a Cabinet holds Drawers (one per ASN), a Drawer holds Folders (one
// per /24), a Folder holds Tabs (one per IP), and each Tab holds the route Slips that IP probed.
type RouteSlips = Set<string>; // one IP's tab: the routes it probed
type SubnetFolder = Map<string, RouteSlips>; // a /24 folder: each IP tab -> its route slips
type AsnDrawer = Map<string, SubnetFolder>; // an ASN drawer: each /24 -> its folder
type AsnCabinet = Map<number, AsnDrawer>; // the whole cabinet: each ASN -> its drawer

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

  // === Per-ASN coordinated-scan metrics ===
  // Route sets are scoped to threat-bearing requests only. Benign paths (/, /favicon.ico) are
  // shared by everyone and would manufacture phantom cohesion between otherwise unrelated IPs.
  const routeCabinet: AsnCabinet = new Map();
  for (const req of requests) {
    if (req.threat_level === "none") continue;
    const asn = req.ip_location?.asn;
    if (asn == null) continue;
    const subnet = subnet24(req.ip);

    let drawer = routeCabinet.get(asn);
    if (!drawer) {
      drawer = new Map();
      routeCabinet.set(asn, drawer);
    }
    let folder = drawer.get(subnet);
    if (!folder) {
      folder = new Map();
      drawer.set(subnet, folder);
    }
    let tab = folder.get(req.ip);
    if (!tab) {
      tab = new Set();
      folder.set(req.ip, tab);
    }
    tab.add(req.route); // file this route slip under this IP's tab
  }

  for (const [asn, drawer] of routeCabinet) {
    const distinctIps = new Set<string>();
    const pathUnion = new Set<string>();
    const cohesionBySubnet = new Map<string, number>();

    for (const [subnet, folder] of drawer) {
      const tabsInFolder: RouteSlips[] = [];
      for (const [ip, tab] of folder) {
        distinctIps.add(ip);
        for (const route of tab) pathUnion.add(route);
        tabsInFolder.push(tab);
      }
      cohesionBySubnet.set(subnet, averageJaccardBetweenSets(tabsInFolder));
    }

    metrics.per_asn_distinct_ips.set(asn, distinctIps.size);
    metrics.per_asn_path_union_size.set(asn, pathUnion.size);
    metrics.per_asn_subnet_cohesion.set(asn, cohesionBySubnet);
  }

  return metrics;
}
