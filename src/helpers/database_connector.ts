import "dotenv/config";
import pg from "pg";
const { Pool } = pg;
import type { QueryResultRow, PoolClient } from "pg";

class Database {
  private _pool: pg.Pool | null = null;

  private get pool(): pg.Pool {
    if (this._pool === null) {
      this._pool = new Pool({
        host: process.env.PSQL_HOST,
        user: process.env.PSQL_USER,
        password: process.env.PSQL_PASSWORD,
        database: process.env.PSQL_DATABASE,
        port: Number(process.env.PSQL_PORT) || 5432,
        options: `-c search_path=${process.env.PSQL_SCHEMA || "tll"}`,
        max: 20,
        idleTimeoutMillis: 60000,
        connectionTimeoutMillis: 1000,
      });
      this._pool.on("error", (err) => {
        console.error("Unexpected error on idle client", err);
      });
    }
    return this._pool;
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
    if (this._pool !== null) {
      await this._pool.end();
      this._pool = null;
    }
  }
}

export const dbc = new Database();
