/**
 * Migration Runner - zero-dependency, tracked up/down migrations
 *
 * Usage:
 *   node server/migrate.js up              Apply all pending migrations
 *   node server/migrate.js up --to 003     Apply pending up through 003, stop there
 *   node server/migrate.js down            Rollback last migration (default: 1)
 *   node server/migrate.js down 3          Rollback last 3 migrations
 *   node server/migrate.js down --to 003   Rollback from latest down through 003
 *   node server/migrate.js status          Show applied/pending status
 *   node server/migrate.js reset           Drop tll schema and recreate (interactive)
 */

import { dbc } from "./helpers/database_connector.js";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import readline from "readline";
import type { PoolClient } from "pg";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const MIGRATIONS_DIR = path.join(__dirname, "migrations");
const SCHEMA = process.env.PSQL_SCHEMA || "tll";
if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(SCHEMA)) {
  console.error(
    `Invalid PSQL_SCHEMA: "${SCHEMA}". Must match [a-zA-Z_][a-zA-Z0-9_]*`,
  );
  process.exit(1);
}

interface Migration {
  name: string;
  upSql: string;
  downSql: string;
}

interface AppliedMigration {
  name: string;
  applied_at: Date;
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

// ==========================================================================
// CONSOLE FORMATTING
// ==========================================================================
const green = (s: string) => `\x1b[32m${s}\x1b[0m`;
const red = (s: string) => `\x1b[31m${s}\x1b[0m`;
const yellow = (s: string) => `\x1b[33m${s}\x1b[0m`;
const dim = (s: string) => `\x1b[2m${s}\x1b[0m`;
const bold = (s: string) => `\x1b[1m${s}\x1b[0m`;

// ==========================================================================
// TRACKING TABLE
// ==========================================================================
async function ensureSchema(client: PoolClient) {
  await client.query(`CREATE SCHEMA IF NOT EXISTS ${SCHEMA}`);
}

async function ensureTrackingTable(client: PoolClient) {
  await client.query(`
    CREATE TABLE IF NOT EXISTS _migrations (
      id          SERIAL PRIMARY KEY,
      name        VARCHAR(255) UNIQUE NOT NULL,
      applied_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
}

// ==========================================================================
// FILE PARSING
// ==========================================================================
function loadMigrations(): Migration[] {
  const files = fs
    .readdirSync(MIGRATIONS_DIR)
    .filter((f) => f.endsWith(".sql"))
    .sort();

  return files
    .map((filename) => {
      const content = fs.readFileSync(
        path.join(MIGRATIONS_DIR, filename),
        "utf-8",
      );
      const parts = content.split(/^-- DOWN$/m);

      if (parts.length < 2) {
        console.warn(yellow(`  ⚠ ${filename} has no -- DOWN marker, skipping`));
        return null;
      }

      const upSql = parts[0].replace(/^-- UP$/m, "").trim();
      const downSql = parts[1].trim();

      return { name: filename, upSql, downSql };
    })
    .filter((m): m is Migration => m !== null);
}

async function getApplied(client: PoolClient): Promise<AppliedMigration[]> {
  const result = await client.query<AppliedMigration>(
    "SELECT name, applied_at FROM _migrations ORDER BY id",
  );
  return result.rows;
}

// ==========================================================================
// TARGET RESOLUTION - match a prefix like "003" to a migration filename
// ==========================================================================
function resolveTarget(prefix: string, migrations: Migration[]): string {
  const matches = migrations.filter((m) => m.name.startsWith(prefix));
  if (matches.length === 0) {
    console.error(red(`  ✗ No migration found matching "${prefix}"`));
    process.exit(1);
  }
  if (matches.length > 1) {
    console.error(
      red(`  ✗ Ambiguous prefix "${prefix}" matches ${matches.length} files:`),
    );
    matches.forEach((m) => console.error(`    ${m.name}`));
    process.exit(1);
  }
  return matches[0].name;
}

// ==========================================================================
// UP - apply pending migrations (all, or up through --to target)
// ==========================================================================
async function up(target: string | null): Promise<void> {
  const client = await dbc.connect();
  try {
    await ensureSchema(client);
    await ensureTrackingTable(client);
    const applied = await getApplied(client);
    const appliedNames = new Set(applied.map((r) => r.name));
    const migrations = loadMigrations();
    let pending = migrations.filter((m) => !appliedNames.has(m.name));

    // If --to target, only apply up through that migration
    if (target) {
      const targetName = resolveTarget(target, migrations);
      const targetIndex = pending.findIndex((m) => m.name === targetName);
      if (targetIndex === -1) {
        console.log(green(`  ✓ ${targetName} already applied`));
        return;
      }
      pending = pending.slice(0, targetIndex + 1);
    }

    if (pending.length === 0) {
      console.log(green("  ✓ All migrations already applied"));
      return;
    }

    console.log(
      bold(
        `\nApplying ${pending.length} migration${pending.length > 1 ? "s" : ""}...\n`,
      ),
    );

    for (const migration of pending) {
      try {
        await client.query("BEGIN");
        await client.query(migration.upSql);
        await client.query("INSERT INTO _migrations (name) VALUES ($1)", [
          migration.name,
        ]);
        await client.query("COMMIT");
        console.log(green("  ↑ applied") + `  ${migration.name}`);
      } catch (err) {
        await client.query("ROLLBACK");
        console.error(red("  ✗ failed") + `  ${migration.name}`);
        console.error(`    ${errorMessage(err)}`);
        break;
      }
    }
    console.log();
  } finally {
    client.release();
  }
}

// ==========================================================================
// DOWN - rollback migrations (last N, or down through --to target)
// ==========================================================================
async function down(count = 1, target: string | null): Promise<void> {
  const client = await dbc.connect();
  try {
    await ensureSchema(client);
    await ensureTrackingTable(client);
    const applied = await getApplied(client);

    if (applied.length === 0) {
      console.log(yellow("  No migrations to roll back"));
      return;
    }

    const migrations = loadMigrations();
    const migrationMap = Object.fromEntries(migrations.map((m) => [m.name, m]));

    let toRollback;

    if (target) {
      // --to mode: rollback from latest down through the target (inclusive)
      const targetName = resolveTarget(target, migrations);
      const targetIndex = applied.findIndex((r) => r.name === targetName);
      if (targetIndex === -1) {
        console.log(yellow(`  ${targetName} is not currently applied`));
        return;
      }
      toRollback = applied.slice(targetIndex).reverse();
    } else {
      // Count mode: rollback last N applied
      toRollback = applied.slice(-count).reverse();
    }

    console.log(
      bold(
        `\nRolling back ${toRollback.length} migration${toRollback.length > 1 ? "s" : ""}...\n`,
      ),
    );

    for (const record of toRollback) {
      const migration = migrationMap[record.name];
      if (!migration) {
        console.error(
          red("  ✗ missing") + `  ${record.name} - file not found, skipping`,
        );
        continue;
      }

      try {
        await client.query("BEGIN");
        await client.query(migration.downSql);
        await client.query("DELETE FROM _migrations WHERE name = $1", [
          migration.name,
        ]);
        await client.query("COMMIT");
        console.log(red("  ↓ rolled back") + `  ${migration.name}`);
      } catch (err) {
        await client.query("ROLLBACK");
        console.error(red("  ✗ failed") + `  ${migration.name}`);
        console.error(`    ${errorMessage(err)}`);
        break;
      }
    }
    console.log();
  } finally {
    client.release();
  }
}

// ==========================================================================
// STATUS - show applied/pending for each migration file
// ==========================================================================
async function status() {
  const client = await dbc.connect();
  try {
    await ensureSchema(client);
    await ensureTrackingTable(client);
    const applied = await getApplied(client);
    const appliedMap = Object.fromEntries(
      applied.map((r) => [r.name, r.applied_at]),
    );
    const migrations = loadMigrations();

    console.log(bold("\nMigration Status\n"));

    for (const migration of migrations) {
      const appliedAt = appliedMap[migration.name];
      if (appliedAt) {
        const ts = new Date(appliedAt)
          .toISOString()
          .replace("T", " ")
          .slice(0, 19);
        console.log(green("  ● applied") + `  ${migration.name}  ${dim(ts)}`);
      } else {
        console.log(yellow("  ○ pending") + `  ${migration.name}`);
      }
    }
    console.log();
  } finally {
    client.release();
  }
}

// ==========================================================================
// RESET - rollback all applied migrations + drop tracking table
// ==========================================================================
function confirm(prompt: string): Promise<string> {
  if (!process.stdin.isTTY) {
    console.error(red("\n  ✗ reset requires an interactive terminal\n"));
    process.exit(1);
  }

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  return new Promise<string>((resolve) => {
    rl.question(prompt, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

async function reset() {
  console.log(
    yellow(
      `\n  ⚠ This will DROP the entire ${SCHEMA} schema and all its data.\n`,
    ),
  );
  const answer = await confirm(`  Type "drop ${SCHEMA}" to confirm: `);

  if (answer !== `drop ${SCHEMA}`) {
    console.log("\n  Aborted.\n");
    return;
  }

  const client = await dbc.connect();
  try {
    await client.query(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`);
    console.log(red("\n  ✗ dropped") + `  ${SCHEMA} schema (cascade)`);
    await client.query(`CREATE SCHEMA ${SCHEMA}`);
    console.log(green("  ✓ recreated") + `  ${SCHEMA} schema`);
    console.log(green("\n  ✓ Reset complete - run 'up' to apply migrations\n"));
  } finally {
    client.release();
  }
}

// ==========================================================================
// CLI - parse command, --to flag, and positional args
// ==========================================================================
function getArgValue(args: string[], name: string): string | null {
  const equalsForm = args.find((arg) => arg.startsWith(`--${name}=`));
  if (equalsForm !== undefined) return equalsForm.slice(`--${name}=`.length);
  const spaceIndex = args.indexOf(`--${name}`);
  if (spaceIndex !== -1) return args[spaceIndex + 1] ?? null;
  return null;
}

const args = process.argv.slice(2);
const command = args[0];
const toTarget = getArgValue(args, "to");
const positionalArg =
  args[1] && args[1] !== "--to" && !args[1].startsWith("--to=")
    ? args[1]
    : null;

if (positionalArg !== null && toTarget !== null) {
  console.error(
    "Cannot combine count and --to arguments. Use one or the other.",
  );
  process.exit(1);
}

try {
  switch (command) {
    case "up":
      await up(toTarget);
      break;
    case "down":
      await down(positionalArg ? parseInt(positionalArg, 10) : 1, toTarget);
      break;
    case "status":
      await status();
      break;
    case "reset":
      await reset();
      break;
    default:
      console.log(`
Usage: node src/migrate.js <command>

Commands:
  up                Apply all pending migrations
  up --to 003       Apply pending migrations up through 003
  down              Rollback last migration
  down 3            Rollback last 3 migrations
  down --to 003     Rollback from latest down through 003
  status            Show migration status
  reset             Drop ${SCHEMA} schema and recreate (interactive)
`);
  }
} catch (err) {
  console.error(red("Migration error:"), errorMessage(err));
  process.exit(1);
} finally {
  await dbc.close();
}
