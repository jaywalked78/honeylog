// Exports logs_requests rows newer than the last dated JSON dump in personal/.
// Finds the latest personal/logs_requests_<YYYYMMDDHHMM>.json, reads its max id,
// pulls every row with a higher id over the existing dbc connection, and writes
// a new dump in the same DBeaver-compatible shape (JSONB columns as strings).
//
// Usage:
//   npm run export:new-rows              -- baseline from latest dump in personal/
//   npm run export:new-rows -- --since-id 67828
import fs from "fs";
import path from "path";
import { dbc } from "../helpers/database_connector.js";
import { PERSONAL_DIR, findLatestExportFile } from "./latestExport.js";

const JSONB_COLUMNS = [
  "request_body",
  "threat_details",
  "ip_location",
  "forwarding_chain",
];

function getArg(name: string): string | null {
  const idx = process.argv.indexOf(name);
  return idx !== -1 && idx + 1 < process.argv.length
    ? process.argv[idx + 1]
    : null;
}

function maxIdInExportFile(filePath: string): number {
  const parsed = JSON.parse(fs.readFileSync(filePath, "utf8"));
  const rows: Array<{ id: number }> = parsed.logs_requests;
  if (!Array.isArray(rows) || rows.length === 0) {
    console.error(`No logs_requests rows found in ${filePath}`);
    process.exit(1);
  }
  return rows.reduce((max, row) => Math.max(max, row.id), 0);
}

function localTimestamp(): string {
  const now = new Date();
  const pad = (n: number) => String(n).padStart(2, "0");
  return (
    `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}` +
    `${pad(now.getHours())}${pad(now.getMinutes())}`
  );
}

function serializeRow(row: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = { ...row };
  out.id = Number(out.id);
  for (const column of JSONB_COLUMNS) {
    if (out[column] !== null && out[column] !== undefined) {
      out[column] = JSON.stringify(out[column]);
    }
  }
  if (out.created_at instanceof Date) {
    out.created_at = out.created_at.toISOString();
  }
  return out;
}

async function main(): Promise<void> {
  const sinceIdArg = getArg("--since-id");
  let sinceId: number;

  if (sinceIdArg !== null) {
    sinceId = Number(sinceIdArg);
    if (!Number.isInteger(sinceId) || sinceId < 0) {
      console.error(`Invalid --since-id: ${sinceIdArg}`);
      process.exit(1);
    }
    console.log(`Baseline id ${sinceId} (from --since-id)`);
  } else {
    const latestFile = findLatestExportFile();
    if (latestFile === null) {
      console.error(
        `No logs_requests_*.json found in ${PERSONAL_DIR} - pass --since-id to set a baseline`,
      );
      process.exit(1);
    }
    sinceId = maxIdInExportFile(latestFile);
    console.log(`Baseline id ${sinceId} (from ${path.basename(latestFile)})`);
  }

  const rows = await dbc.query(
    "SELECT * FROM logs_requests WHERE id > $1 ORDER BY id ASC",
    [sinceId],
  );
  await dbc.close();

  if (rows.length === 0) {
    console.log(`No new rows since id ${sinceId} - nothing written.`);
    return;
  }

  const outputPath = path.join(
    PERSONAL_DIR,
    `logs_requests_${localTimestamp()}.json`,
  );
  const payload = { logs_requests: rows.map(serializeRow) };
  fs.writeFileSync(outputPath, JSON.stringify(payload, null, 1) + "\n");

  console.log(
    `Wrote ${rows.length} rows (id ${rows[0].id} - ${rows[rows.length - 1].id}) to ${outputPath}`,
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
