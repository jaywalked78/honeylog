// Throwaway tuning harness: for every structurally-qualifying /24 cluster, compute the raw signals
// and run all candidate scoring methods side by side, so we choose a scoring design from real data.
import { dbc } from "../helpers/database_connector.js";
import { PATH_THREATS } from "../middleware/threatDefinitions.js";
import { jaccard, sigmoid, subnet24 } from "../utils/strategyHelpers.js";

interface Row {
  ip: string;
  route: string;
  created_at: Date;
}

const SEV_RANK: Record<string, number> = { none: 0, low: 1, medium: 2, high: 3 };

// Attack-path = path matching a current PATH_THREATS pattern. Adaptable: grows as patterns are added.
function pathSeverity(route: string): string {
  let sev = "none";
  for (const threat of PATH_THREATS) {
    if (threat.pattern.test(route) && SEV_RANK[threat.severity] > SEV_RANK[sev]) {
      sev = threat.severity;
    }
  }
  return sev;
}

function averageJaccard(sets: Set<string>[]): number {
  if (sets.length < 2) return 0;
  let total = 0;
  let pairs = 0;
  for (let i = 0; i < sets.length; i++) {
    for (let j = i + 1; j < sets.length; j++) {
      total += jaccard(sets[i], sets[j]);
      pairs++;
    }
  }
  return total / pairs;
}

const WINDOW_MS = 6 * 60 * 60 * 1000;
const MIN_IPS = 3;

const KNOWN: Record<string, string> = {
  "195.178.110.0/24": "AWS-enum (Techoff)",
  "78.153.140.0/24": "env-spray",
  "77.83.39.0/24": "env/git-spray",
  "87.236.176.0/24": "Driftnet scanner",
  "69.5.169.0/24": "onvif IoT",
  "45.86.202.0/24": "FNS subnet-spray",
  "104.234.32.0/24": "FNS subnet-spray",
  "181.215.65.0/24": "Datacamp spray",
};

interface Cluster {
  subnet: string;
  windowStart: Date;
  distinctIps: number;
  cohesionAll: number; // over all threat-scoped paths (old behavior)
  cohesionAttack: number; // over attack paths only (new behavior)
  attackPathCount: number;
  unionSize: number;
  maxSeverity: string;
}

function classify(score: number): string {
  if (score >= 0.75) return "HIGH";
  if (score >= 0.55) return "MED";
  if (score >= 0.4) return "LOW";
  return "none";
}

function scoreMethods(c: Cluster): Record<string, number> {
  const sizeScore = sigmoid((c.distinctIps - 5) / 2);
  const cohesionScore = sigmoid((c.cohesionAttack - 0.4) / 0.12);
  const breadthScore = sigmoid((c.attackPathCount - 8) / 5);
  return {
    // M1 - current weighted sum (cohesion-dominant)
    baseline: cohesionScore * 0.5 + sizeScore * 0.3 + breadthScore * 0.2,
    // M2 - OR via max: tight overlap OR broad enumeration
    maxOR: sizeScore * 0.4 + Math.max(cohesionScore, breadthScore) * 0.6,
    // M3 - rebalanced weighted sum, breadth up-weighted
    weighted: sizeScore * 0.3 + cohesionScore * 0.3 + breadthScore * 0.4,
    // M4 - OR via capped sum (softer than max)
    sumCap: sizeScore * 0.34 + Math.min(1, cohesionScore + breadthScore) * 0.66,
  };
}

async function main(): Promise<void> {
  const rows = await dbc.query<Row>(
    `SELECT host(ip) AS ip, route, created_at
     FROM logs_requests
     WHERE family(ip) = 4 AND threat_level <> 'none' AND is_tor IS NOT TRUE
     ORDER BY created_at ASC`,
  );
  if (rows.length === 0) {
    console.log("no threat-bearing rows");
    return;
  }

  const startMs = rows[0].created_at.getTime();
  const endMs = rows[rows.length - 1].created_at.getTime();

  // bestPerSubnet keeps the highest-maxOR window instance per /24 (collapse repeats across windows)
  const bestPerSubnet = new Map<string, Cluster>();

  for (let wStart = startMs; wStart < endMs; wStart += WINDOW_MS) {
    const wEnd = wStart + WINDOW_MS;
    const windowRows = rows.filter((r) => {
      const t = r.created_at.getTime();
      return t >= wStart && t < wEnd;
    });

    // /24 -> ip -> all routes / attack routes
    const subnets = new Map<string, Map<string, { all: Set<string>; attack: Set<string> }>>();
    for (const row of windowRows) {
      const subnet = subnet24(row.ip);
      let ips = subnets.get(subnet);
      if (!ips) {
        ips = new Map();
        subnets.set(subnet, ips);
      }
      let sets = ips.get(row.ip);
      if (!sets) {
        sets = { all: new Set(), attack: new Set() };
        ips.set(row.ip, sets);
      }
      sets.all.add(row.route);
      if (pathSeverity(row.route) !== "none") sets.attack.add(row.route);
    }

    for (const [subnet, ips] of subnets) {
      if (ips.size < MIN_IPS) continue;
      const allSets: Set<string>[] = [];
      const attackSets: Set<string>[] = [];
      const attackUnion = new Set<string>();
      const fullUnion = new Set<string>();
      let maxSev = "none";
      for (const [, sets] of ips) {
        allSets.push(sets.all);
        attackSets.push(sets.attack);
        for (const p of sets.all) fullUnion.add(p);
        for (const p of sets.attack) {
          attackUnion.add(p);
          const sev = pathSeverity(p);
          if (SEV_RANK[sev] > SEV_RANK[maxSev]) maxSev = sev;
        }
      }
      if (attackUnion.size < 1) continue; // dynamic gate: needs >=1 matched attack path

      const cluster: Cluster = {
        subnet,
        windowStart: new Date(wStart),
        distinctIps: ips.size,
        cohesionAll: averageJaccard(allSets),
        cohesionAttack: averageJaccard(attackSets),
        attackPathCount: attackUnion.size,
        unionSize: fullUnion.size,
        maxSeverity: maxSev,
      };

      const prev = bestPerSubnet.get(subnet);
      if (!prev || scoreMethods(cluster).maxOR > scoreMethods(prev).maxOR) {
        bestPerSubnet.set(subnet, cluster);
      }
    }
  }

  const clusters = [...bestPerSubnet.values()].sort(
    (a, b) => scoreMethods(b).maxOR - scoreMethods(a).maxOR,
  );

  console.log(
    `\n${clusters.length} qualifying /24 clusters (>=${MIN_IPS} IPs, >=1 attack path)\n`,
  );
  const header =
    "subnet".padEnd(20) +
    "IPs".padStart(4) +
    "coh".padStart(6) +
    "atk".padStart(5) +
    "/uni".padStart(5) +
    "sev".padStart(5) +
    "  baseline    maxOR     weighted   sumCap     label";
  console.log(header);
  console.log("-".repeat(header.length));
  for (const c of clusters) {
    const m = scoreMethods(c);
    const cell = (v: number) => `${v.toFixed(2)} ${classify(v).padEnd(5)}`;
    console.log(
      c.subnet.padEnd(20) +
        String(c.distinctIps).padStart(4) +
        c.cohesionAttack.toFixed(2).padStart(6) +
        String(c.attackPathCount).padStart(5) +
        String(c.unionSize).padStart(5) +
        c.maxSeverity.padStart(5) +
        "  " +
        cell(m.baseline) +
        " " +
        cell(m.maxOR) +
        " " +
        cell(m.weighted) +
        " " +
        cell(m.sumCap) +
        "  " +
        (KNOWN[c.subnet] ?? ""),
    );
  }
}

try {
  await main();
} finally {
  await dbc.close();
}
