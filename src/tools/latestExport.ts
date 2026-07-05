// Shared helpers for the weekly log-export mining tools (export-new-rows,
// mine-export, validate-patterns). Locates the newest dated DBeaver-style dump
// in personal/ so each tool picks up the current window without a hardcoded path.
import fs from "fs";
import path from "path";

export const PERSONAL_DIR = path.resolve(import.meta.dirname, "../../personal");
export const EXPORT_FILENAME_PATTERN = /^logs_requests_(\d{12})\.json$/;

// Newest export by the timestamp embedded in the filename (not mtime), or null
// if personal/ holds no matching dump.
export function findLatestExportFile(): string | null {
  const candidates = fs
    .readdirSync(PERSONAL_DIR)
    .filter((filename) => EXPORT_FILENAME_PATTERN.test(filename))
    .sort();
  return candidates.length > 0
    ? path.join(PERSONAL_DIR, candidates[candidates.length - 1])
    : null;
}

// Latest export path or a hard error - the mining tools cannot run without one.
export function requireLatestExportFile(): string {
  const latest = findLatestExportFile();
  if (latest === null) {
    console.error(
      `No logs_requests_*.json found in ${PERSONAL_DIR} - run "npm run export:new-rows" first`,
    );
    process.exit(1);
  }
  return latest;
}

export interface ExportRow {
  id: number;
  ip: string;
  method: string;
  full_url: string;
  user_agent: string | null;
  request_body: string | null;
  status_code: number;
  threat_level: string;
  ip_location: string | null;
  is_tor: boolean | null;
  created_at: string;
  [column: string]: unknown;
}

export function loadExportRows(filePath: string): ExportRow[] {
  const parsed = JSON.parse(fs.readFileSync(filePath, "utf8"));
  const rows = parsed.logs_requests;
  if (!Array.isArray(rows)) {
    console.error(`No logs_requests array in ${filePath}`);
    process.exit(1);
  }
  return rows;
}
