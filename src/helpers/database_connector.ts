import dotenv from "dotenv";
dotenv.config({ path: "./.env", quiet: true });

import pg from "pg";
const { Pool } = pg;
import type { PoolConfig, QueryResultRow, PoolClient } from "pg";

//-----------DATABASE CONFIG-----------\\
class Database {
  private pool: pg.Pool;

  constructor(config: PoolConfig) {
    this.pool = new Pool(config);

    this.pool.on("error", (err) => {
      console.error("Unexpected error on idle client", err);
    });
  }

  async connect(): Promise<PoolClient> {
    return this.pool.connect();
  }

  async query<Type extends QueryResultRow = QueryResultRow>(
    sql: string,
    args: unknown[] = [],
  ): Promise<Type[]> {
    try {
      const result = await this.pool.query<Type>(sql, args);
      return result.rows;
    } catch (err) {
      console.error("Database query error:", err);
      throw err;
    }
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}

export const dbc = new Database({
  host: process.env.PSQL_HOST,
  user: process.env.PSQL_USER,
  password: process.env.PSQL_PASSWORD,
  database: process.env.PSQL_DATABASE,
  port: Number(process.env.PSQL_PORT) || 5432,
  options: `-c search_path=${process.env.PSQL_SCHEMA || "tll"}`,
  ssl: process.env.PSQL_SSL === "true" ? { rejectUnauthorized: false } : false,
  max: 20,
  idleTimeoutMillis: 60000,
  connectionTimeoutMillis: 1000,
});
