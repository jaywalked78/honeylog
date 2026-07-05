// Weekly mining prep: replay every row in the latest personal/ export through the
// CURRENT detectThreats and cluster the traffic, so subagents can crawl for net-new
// threatDefinitions patterns and detectedCampaigns entries.
//
// Stored threat_level/threat_details are stale (reflect the prod pattern set at
// capture time), so a row marked "none" in the dump is often already caught - we
// re-classify against the live code and only surface rows that are STILL "none".
//
// Usage:
//   npm run mine:export                 -- uses the newest personal/logs_requests_*.json
//   npm run mine:export -- --file personal/logs_requests_202607050106.json
//
// Writes, alongside the export:
//   <export>-uncaught.json  -- unique still-uncaught request shapes, count desc
//   <export>-clusters.json  -- traffic grouped by IP, /24 subnet, and ASN
import fs from "fs";
import { detectThreats } from "../middleware/honey.js";
import {
  requireLatestExportFile,
  loadExportRows,
  type ExportRow,
} from "./latestExport.js";

function getArg(name: string): string | null {
  const idx = process.argv.indexOf(name);
  return idx !== -1 && idx + 1 < process.argv.length
    ? process.argv[idx + 1]
    : null;
}

type Level = "none" | "low" | "medium" | "high";
interface ReplayedRow extends ExportRow {
  _current_level: Level;
}

// === REPLAY THROUGH CURRENT detectThreats ===
function replay(rows: ExportRow[]): {
  replayed: ReplayedRow[];
  levelCounts: Record<Level, number>;
} {
  const levelCounts: Record<Level, number> = {
    none: 0,
    low: 0,
    medium: 0,
    high: 0,
  };
  const replayed = rows.map((row) => {
    const result = detectThreats({
      url: row.full_url,
      method: row.method,
      body: row.request_body,
      userAgent: row.user_agent,
    });
    levelCounts[result.level as Level]++;
    return { ...row, _current_level: result.level as Level };
  });
  return { replayed, levelCounts };
}

function buildUncaughtShapes(replayed: ReplayedRow[]) {
  const byShape = new Map<
    string,
    {
      method: string;
      full_url: string;
      count: number;
      sample_ids: number[];
      user_agents: Set<string>;
      ips: Set<string>;
      status_codes: Set<number>;
      stored_levels: Set<string>;
      request_bodies: Set<string>;
    }
  >();

  for (const row of replayed) {
    if (row._current_level !== "none") continue;
    const shape = `${row.method} ${row.full_url}`;
    if (!byShape.has(shape)) {
      byShape.set(shape, {
        method: row.method,
        full_url: row.full_url,
        count: 0,
        sample_ids: [],
        user_agents: new Set(),
        ips: new Set(),
        status_codes: new Set(),
        stored_levels: new Set(),
        request_bodies: new Set(),
      });
    }
    const entry = byShape.get(shape)!;
    entry.count++;
    if (entry.sample_ids.length < 5) entry.sample_ids.push(row.id);
    if (row.user_agent) entry.user_agents.add(row.user_agent.slice(0, 160));
    entry.ips.add(row.ip);
    entry.status_codes.add(row.status_code);
    entry.stored_levels.add(row.threat_level);
    if (row.request_body && row.request_body !== "{}") {
      entry.request_bodies.add(row.request_body.slice(0, 300));
    }
  }

  return [...byShape.values()]
    .map((entry) => ({
      method: entry.method,
      full_url: entry.full_url,
      count: entry.count,
      sample_ids: entry.sample_ids,
      user_agents: [...entry.user_agents].slice(0, 5),
      ips: [...entry.ips].slice(0, 10),
      ip_count: entry.ips.size,
      status_codes: [...entry.status_codes],
      stored_levels: [...entry.stored_levels],
      request_bodies: [...entry.request_bodies].slice(0, 3),
    }))
    .sort((a, b) => b.count - a.count);
}

// === CAMPAIGN CLUSTERS ===
function parseLoc(row: ExportRow): { asn?: number; org?: string } {
  if (!row.ip_location) return {};
  try {
    return JSON.parse(row.ip_location);
  } catch {
    return {};
  }
}

interface Cluster {
  request_count: number;
  ips: Set<string>;
  paths: Map<string, number>;
  user_agents: Set<string>;
  methods: Set<string>;
  asns: Set<number>;
  orgs: Set<string>;
  ip_types: Set<string>;
  tor_count: number;
  threat_levels: Record<Level, number>;
  first_seen: string | null;
  last_seen: string | null;
}

function makeCluster(): Cluster {
  return {
    request_count: 0,
    ips: new Set(),
    paths: new Map(),
    user_agents: new Set(),
    methods: new Set(),
    asns: new Set(),
    orgs: new Set(),
    ip_types: new Set(),
    tor_count: 0,
    threat_levels: { none: 0, low: 0, medium: 0, high: 0 },
    first_seen: null,
    last_seen: null,
  };
}

function feedCluster(
  cluster: Cluster,
  row: ReplayedRow,
  loc: { asn?: number; org?: string },
): void {
  cluster.request_count++;
  cluster.ips.add(row.ip);
  cluster.paths.set(row.full_url, (cluster.paths.get(row.full_url) ?? 0) + 1);
  if (row.user_agent) cluster.user_agents.add(row.user_agent.slice(0, 160));
  cluster.methods.add(row.method);
  if (loc.asn) cluster.asns.add(loc.asn);
  if (loc.org) cluster.orgs.add(loc.org);
  const ipType = row.ip_type as string | null;
  if (ipType) cluster.ip_types.add(ipType);
  if (row.is_tor) cluster.tor_count++;
  cluster.threat_levels[row._current_level]++;
  if (!cluster.first_seen || row.created_at < cluster.first_seen)
    cluster.first_seen = row.created_at;
  if (!cluster.last_seen || row.created_at > cluster.last_seen)
    cluster.last_seen = row.created_at;
}

function finalizeCluster([key, cluster]: [string, Cluster]) {
  const sortedPaths = [...cluster.paths.entries()].sort((a, b) => b[1] - a[1]);
  return {
    key,
    request_count: cluster.request_count,
    unique_ips: cluster.ips.size,
    ips: [...cluster.ips].slice(0, 15),
    unique_paths: cluster.paths.size,
    top_paths: sortedPaths.slice(0, 40).map(([p, c]) => `${c}x ${p}`),
    user_agents: [...cluster.user_agents].slice(0, 8),
    ua_count: cluster.user_agents.size,
    methods: [...cluster.methods],
    asns: [...cluster.asns],
    orgs: [...cluster.orgs].slice(0, 5),
    ip_types: [...cluster.ip_types],
    tor_count: cluster.tor_count,
    threat_levels: cluster.threat_levels,
    first_seen: cluster.first_seen,
    last_seen: cluster.last_seen,
  };
}

function buildClusters(replayed: ReplayedRow[], exportFile: string) {
  const byIp = new Map<string, Cluster>();
  const bySubnet = new Map<string, Cluster>();
  const byAsn = new Map<string, Cluster>();

  for (const row of replayed) {
    const loc = parseLoc(row);
    if (!byIp.has(row.ip)) byIp.set(row.ip, makeCluster());
    feedCluster(byIp.get(row.ip)!, row, loc);

    const subnetMatch = row.ip.match(/^(\d+\.\d+\.\d+)\.\d+$/);
    if (subnetMatch) {
      const subnet = `${subnetMatch[1]}.0/24`;
      if (!bySubnet.has(subnet)) bySubnet.set(subnet, makeCluster());
      feedCluster(bySubnet.get(subnet)!, row, loc);
    }

    if (loc.asn) {
      const asnKey = `AS${loc.asn} ${loc.org ?? ""}`;
      if (!byAsn.has(asnKey)) byAsn.set(asnKey, makeCluster());
      feedCluster(byAsn.get(asnKey)!, row, loc);
    }
  }

  return {
    export_file: exportFile,
    row_count: replayed.length,
    time_range: {
      first: replayed[0]?.created_at ?? null,
      last: replayed[replayed.length - 1]?.created_at ?? null,
    },
    by_ip: [...byIp.entries()]
      .filter(([, c]) => c.request_count >= 10 || c.paths.size >= 5)
      .map(finalizeCluster)
      .sort((a, b) => b.request_count - a.request_count),
    by_subnet: [...bySubnet.entries()]
      .filter(
        ([, c]) => c.ips.size >= 2 && (c.request_count >= 10 || c.paths.size >= 3),
      )
      .map(finalizeCluster)
      .sort((a, b) => b.request_count - a.request_count),
    by_asn: [...byAsn.entries()]
      .filter(([, c]) => c.ips.size >= 3 && c.paths.size >= 3)
      .map(finalizeCluster)
      .sort((a, b) => b.request_count - a.request_count),
  };
}

function main(): void {
  const fileArg = getArg("--file");
  const exportFile = fileArg ?? requireLatestExportFile();
  const rows = loadExportRows(exportFile);
  console.log(`Loaded ${rows.length} rows from ${exportFile}`);

  const { replayed, levelCounts } = replay(rows);
  console.log("Current-code verdicts:", levelCounts);

  const uncaught = buildUncaughtShapes(replayed);
  const clusters = buildClusters(replayed, exportFile);

  const base = exportFile.replace(/\.json$/, "");
  const uncaughtPath = `${base}-uncaught.json`;
  const clustersPath = `${base}-clusters.json`;
  fs.writeFileSync(
    uncaughtPath,
    JSON.stringify({ level_counts: levelCounts, shapes: uncaught }, null, 1),
  );
  fs.writeFileSync(clustersPath, JSON.stringify(clusters, null, 1));

  console.log(`Uncaught unique shapes: ${uncaught.length}`);
  console.log(
    `Clusters: ${clusters.by_ip.length} IPs, ${clusters.by_subnet.length} subnets, ${clusters.by_asn.length} ASNs`,
  );
  console.log(`Wrote ${uncaughtPath}`);
  console.log(`Wrote ${clustersPath}`);
}

main();
