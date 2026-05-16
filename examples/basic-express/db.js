import pg from "pg";

const { Pool } = pg;

/**
 * Shared pg.Pool for the example app.
 *
 * In a real app, your routes and any other DB-touching middleware would
 * import this same `pool` - one pool per process. honey does NOT manage
 * the connection; it accepts whatever pool you hand it. That keeps you
 * in full control of pooling, lifecycle, and retry semantics.
 */
export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 10,
  idleTimeoutMillis: 30000,
});

// Graceful shutdown - close the pool on process exit so connections don't leak across restarts during development.
const shutdown = async () => {
  await pool.end();
  process.exit(0);
};
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
