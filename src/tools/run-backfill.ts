import fs from "fs";
import path from "path";
import readline from "readline";
import zlib from "zlib";
import { initGeo } from "../helpers/geoLookup.js";
import { dbc } from "../helpers/database_connector.js";
import {
  parseNginxLog,
  buildIpEnrichment,
  enrichRequest,
  findLastRealRowTimestamp,
  countBackfilledRowsInWindow,
  bulkInsertBackfilledRows,
  type BackfilledRow,
} from "./backfill-from-nginx.js";

const NGINX_LOG_DIR = process.env.NGINX_LOG_DIR ?? "/var/log/nginx";
const BATCH_SIZE = 500;
const DRY_RUN = process.argv.includes("--dry-run");

function getArg(name: string): string | null {
  const idx = process.argv.indexOf(name);
  return idx !== -1 && idx + 1 < process.argv.length
    ? process.argv[idx + 1]
    : null;
}

async function main(): Promise<void> {
  if (DRY_RUN) {
    console.log("=== DRY RUN: no rows will be inserted ===\n");
  }

  if (!process.env.GEO_CITY_DB_PATH || !process.env.GEO_ASN_DB_PATH) {
    console.error("GEO_CITY_DB_PATH and GEO_ASN_DB_PATH must be set in .env");
    process.exit(1);
  }

  await initGeo({
    cityPath: process.env.GEO_CITY_DB_PATH,
    asnPath: process.env.GEO_ASN_DB_PATH,
  });

  // Window discovery
  const fromArg = getArg("--from");
  const toArg = getArg("--to");

  let startOfGap: Date;
  let endOfGap: Date;

  if (fromArg && toArg) {
    startOfGap = new Date(fromArg);
    endOfGap = new Date(toArg);
    if (isNaN(startOfGap.getTime()) || isNaN(endOfGap.getTime())) {
      console.error(
        "Invalid --from or --to date. Use ISO format: 2026-05-23T16:19:16Z",
      );
      process.exit(1);
    }
  } else {
    const detected = await findLastRealRowTimestamp();
    if (!detected) {
      console.error(
        "No existing rows in logs_requests - nothing to backfill against",
      );
      process.exit(1);
    }
    startOfGap = detected;
    endOfGap = new Date();
    console.warn(
      "WARN: Using auto-detected window. If app is currently writing rows, this is likely wrong.",
    );
    console.warn("      Use --from <iso> --to <iso> for explicit control.\n");
  }

  console.log(
    `Gap window: ${startOfGap.toISOString()}  ->  ${endOfGap.toISOString()}`,
  );

  const existing = await countBackfilledRowsInWindow(startOfGap, endOfGap);
  if (existing > 0) {
    if (DRY_RUN) {
      console.warn(
        `Note: ${existing} backfilled rows already exist - a real run would abort here.\n`,
      );
    } else {
      console.error(
        `Aborting: ${existing} backfilled rows already exist in this window.\n` +
          `Delete them first to re-run:\n` +
          `  DELETE FROM logs_requests WHERE created_at >= '${startOfGap.toISOString()}' AND is_tor IS NULL;`,
      );
      process.exit(1);
    }
  }

  // Log scan
  if (!fs.existsSync(NGINX_LOG_DIR)) {
    console.error(`Nginx log directory not found: ${NGINX_LOG_DIR}`);
    process.exit(1);
  }

  const files = fs
    .readdirSync(NGINX_LOG_DIR)
    .filter((f) => f.startsWith("access.log"))
    .sort();

  console.log(
    `Found ${files.length} nginx log files to scan in ${NGINX_LOG_DIR}`,
  );

  const enrichIp = buildIpEnrichment();
  const allRows: BackfilledRow[] = [];
  let totalLines = 0;
  let skippedUnparseable = 0;
  let outsideWindow = 0;

  for (const file of files) {
    const fullPath = path.join(NGINX_LOG_DIR, file);
    const stream = file.endsWith(".gz")
      ? fs.createReadStream(fullPath).pipe(zlib.createGunzip())
      : fs.createReadStream(fullPath);

    const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });

    let fileLines = 0;
    let fileInWindow = 0;

    for await (const line of rl) {
      totalLines++;
      fileLines++;

      const parsed = parseNginxLog(line);
      if (!parsed) {
        skippedUnparseable++;
        continue;
      }

      if (parsed.timestamp <= startOfGap || parsed.timestamp > endOfGap) {
        outsideWindow++;
        continue;
      }

      allRows.push(enrichRequest(parsed, enrichIp));
      fileInWindow++;
    }

    console.log(`  ${file}: ${fileLines} lines, ${fileInWindow} in window`);
  }

  console.log(
    `\nParsed ${totalLines} total lines | ${skippedUnparseable} unparseable | ${outsideWindow} outside window | ${allRows.length} to insert\n`,
  );

  if (allRows.length === 0) {
    console.log("Nothing to insert.");
    await dbc.close();
    return;
  }

  if (DRY_RUN) {
    console.log("Sample of first 3 rows that would be inserted:\n");
    for (const row of allRows.slice(0, 3)) {
      console.log(JSON.stringify(row, null, 2));
      console.log("---");
    }
    const threatBreakdown = allRows.reduce<Record<string, number>>((acc, r) => {
      acc[r.threat_level] = (acc[r.threat_level] ?? 0) + 1;
      return acc;
    }, {});
    console.log(`\nThreat level breakdown: ${JSON.stringify(threatBreakdown)}`);
    console.log(
      `\nDry run complete. ${allRows.length} rows would be inserted. Re-run without --dry-run to commit.`,
    );
    await dbc.close();
    return;
  }

  // Bulk insert
  for (let i = 0; i < allRows.length; i += BATCH_SIZE) {
    const batch = allRows.slice(i, i + BATCH_SIZE);
    await bulkInsertBackfilledRows(batch);
    console.log(
      `  inserted ${Math.min(i + BATCH_SIZE, allRows.length)}/${allRows.length}`,
    );
  }

  console.log(
    `\nDone. ${allRows.length} backfilled rows written to logs_requests.`,
  );
  await dbc.close();
}

main().catch(async (err) => {
  console.error("Backfill error:", err);
  await dbc.close().catch(() => {});
  process.exit(1);
});
