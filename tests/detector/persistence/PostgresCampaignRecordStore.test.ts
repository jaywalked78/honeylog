import "dotenv/config";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, it, expect, afterAll } from "vitest";
import pg from "pg";
import { PostgresCampaignRecordStore } from "../../../src/detector/persistence/PostgresCampaignRecordStore.js";
import { describeCampaignRecordStoreContract } from "../../../src/test-support/campaignRecordStoreContract.js";
import { makeCandidate } from "../../../src/test-support/factories.js";

const runDatabaseTests = process.env.RUN_DB_TESTS === "1";

const SCRATCH_SCHEMA = "honeylog_campaigns_contract_test";

if (!runDatabaseTests) {
  describe.skip("PostgresCampaignRecordStore (set RUN_DB_TESTS=1 with the tunnel up)", () => {
    it("skipped", () => {});
  });
} else {
  const { Pool } = pg;
  const pool = new Pool({
    host: process.env.PSQL_HOST,
    user: process.env.PSQL_USER,
    password: process.env.PSQL_PASSWORD,
    database: process.env.PSQL_DATABASE,
    port: Number(process.env.PSQL_PORT) || 5432,
    options: `-c search_path=${SCRATCH_SCHEMA}`,
    max: 2,
  });

  const migrationUrl = new URL(
    "../../../src/migrations/003_create_campaigns.sql",
    import.meta.url,
  );
  const upSql = fs
    .readFileSync(fileURLToPath(migrationUrl), "utf-8")
    .split(/^-- DOWN$/m)[0]
    .replace(/^-- UP$/m, "")
    .trim();

  async function resetScratchSchema(): Promise<PostgresCampaignRecordStore> {
    await pool.query(`DROP SCHEMA IF EXISTS ${SCRATCH_SCHEMA} CASCADE`);
    await pool.query(`CREATE SCHEMA ${SCRATCH_SCHEMA}`);
    await pool.query(upSql);
    return new PostgresCampaignRecordStore(pool);
  }

  afterAll(async () => {
    await pool.query(`DROP SCHEMA IF EXISTS ${SCRATCH_SCHEMA} CASCADE`);
    await pool.end();
  });

  describeCampaignRecordStoreContract(
    "PostgresCampaignRecordStore",
    resetScratchSchema,
  );

  describe("PostgresCampaignRecordStore episode semantics", () => {
    it("inserts a fresh row when the identifier re-fires after closure", async () => {
      const store = await resetScratchSchema();
      await store.upsertCandidate(makeCandidate(), "backtest");
      await pool.query(`UPDATE campaigns SET status = 'closed'`);

      const result = await store.upsertCandidate(makeCandidate(), "backtest");

      expect(result.outcome).toBe("inserted");
      const { rows } = await pool.query<{ count: number }>(
        `SELECT count(*)::int AS count FROM campaigns`,
      );
      expect(rows[0].count).toBe(2);
    });

    it("rejects an invalid tableName", () => {
      expect(
        () => new PostgresCampaignRecordStore(pool, { tableName: "bad;drop" }),
      ).toThrow(/Invalid tableName/);
    });
  });
}
