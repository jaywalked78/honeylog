// Validate proposed threatDefinitions regexes against the latest personal/ export
// before adding them: reports how many still-uncaught shapes each pattern would
// newly catch, and flags any hit on a known-legitimate route (false positive).
//
// The proposals file is a JSON array of:
//   { "name": "...", "pattern": "<js regex source>", "flags"?: "i",
//     "target"?: "PATH_THREATS" | "BODY_THREATS" }
// BODY_THREATS patterns are tested against the request body AND the URL (honey
// runs them against both), everything else against the URL only.
//
// Usage:
//   npm run validate:patterns -- proposals.json
//   npm run validate:patterns -- proposals.json --file personal/logs_requests_202607050106.json
import fs from "fs";
import { detectThreats } from "../middleware/honey.js";
import { requireLatestExportFile, loadExportRows } from "./latestExport.js";

// Legit TLL-Fuzzy routes + generic static/browser noise. A pattern that matches
// any of these is over-broad and must be tightened before it ships.
const LEGIT_FIXTURE = [
  "/",
  "/cart",
  "/cart/checkout",
  "/api/inventory",
  "/api/inventory?category=potions",
  "/api/auth/me",
  "/api/lux/state",
  "/api/lux/trigger",
  "/api/sidequests/active",
  "/api/sidequests/complete",
  "/favicon.ico",
  "/robots.txt",
  "/sitemap.xml",
  "/.well-known/security.txt",
  "/assets/index-Bx2f.js",
  "/assets/index-Cq1a.css",
  "/static/js/main.chunk.js",
  "/images/logo.png",
  "/fonts/inter.woff2",
  "/manifest.json",
  "/index.html",
];

interface Proposal {
  name: string;
  pattern: string;
  flags?: string;
  target?: "PATH_THREATS" | "BODY_THREATS" | "METHOD_THREATS";
}

function getArg(name: string): string | null {
  const idx = process.argv.indexOf(name);
  return idx !== -1 && idx + 1 < process.argv.length
    ? process.argv[idx + 1]
    : null;
}

function main(): void {
  const positional = process.argv
    .slice(2)
    .find((arg) => !arg.startsWith("--") && arg.endsWith(".json"));
  if (!positional) {
    console.error(
      "usage: npm run validate:patterns -- <proposals.json> [--file <export.json>]",
    );
    process.exit(1);
  }

  const proposals: Proposal[] = JSON.parse(fs.readFileSync(positional, "utf8"));
  const exportFile = getArg("--file") ?? requireLatestExportFile();
  const rows = loadExportRows(exportFile);

  const currentLevel = rows.map(
    (row) =>
      detectThreats({
        url: row.full_url,
        method: row.method,
        body: row.request_body,
        userAgent: row.user_agent,
      }).level,
  );

  console.log(`Validating ${proposals.length} proposals against ${exportFile}\n`);

  for (const proposal of proposals) {
    const regex = new RegExp(proposal.pattern, proposal.flags ?? "i");
    const target = proposal.target ?? "PATH_THREATS";
    const caught = new Map<string, { total: number; uncaught: number }>();

    rows.forEach((row, index) => {
      const haystacks =
        target === "BODY_THREATS"
          ? [row.request_body ?? "", row.full_url]
          : [row.full_url];
      if (!haystacks.some((h) => regex.test(h))) return;

      const key = `${row.method} ${row.full_url}`;
      if (!caught.has(key)) caught.set(key, { total: 0, uncaught: 0 });
      caught.get(key)!.total++;
      if (currentLevel[index] === "none") caught.get(key)!.uncaught++;
    });

    const fixtureHits = LEGIT_FIXTURE.filter((url) => regex.test(url));
    const newlyCaught = [...caught.entries()].filter(([, v]) => v.uncaught > 0);
    const rowsNewlyCaught = newlyCaught.reduce((sum, [, v]) => sum + v.uncaught, 0);

    console.log(`=== ${proposal.name} (${target}) /${proposal.pattern}/`);
    if (fixtureHits.length > 0) {
      console.log(`  !! FIXTURE HITS (over-broad): ${fixtureHits.join(", ")}`);
    }
    console.log(
      `  shapes hit: ${caught.size}, newly caught shapes: ${newlyCaught.length}, rows newly caught: ${rowsNewlyCaught}`,
    );
    for (const [key] of newlyCaught.slice(0, 8)) console.log(`    + ${key}`);
    console.log("");
  }
}

main();
