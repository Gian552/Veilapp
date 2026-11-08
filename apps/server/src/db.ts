// Minimal database abstraction over node-postgres (production) and PGlite
// (embedded Postgres for tests and local development). Both speak the same SQL.
// Binary columns are always returned as plain Uint8Array.

import { PGlite } from '@electric-sql/pglite';
import pg from 'pg';
import { migrate } from './migrations.js';

export type Row = Record<string, unknown>;

export interface QueryResult<T> {
  rows: T[];
  rowCount: number;
}

export interface Db {
  query<T = Row>(sql: string, params?: unknown[]): Promise<QueryResult<T>>;
  /** Multi-statement SQL without parameters (migrations). */
  exec(sql: string): Promise<void>;
  /** Runs `fn` inside one transaction; nested calls reuse the outer transaction. */
  transaction<T>(fn: (tx: Db) => Promise<T>): Promise<T>;
  close(): Promise<void>;
}

function normaliseValue(v: unknown): unknown {
  if (Buffer.isBuffer(v)) return new Uint8Array(v.buffer.slice(v.byteOffset, v.byteOffset + v.length));
  return v;
}

function normaliseRows<T>(rows: Row[]): T[] {
  for (const row of rows) for (const k of Object.keys(row)) row[k] = normaliseValue(row[k]);
  return rows as T[];
}

function pgParams(params: unknown[] | undefined): unknown[] | undefined {
  return params?.map((p) => (p instanceof Uint8Array && !Buffer.isBuffer(p) ? Buffer.from(p.buffer, p.byteOffset, p.length) : p));
}

// ---------------------------------------------------------------- PGlite

type PGliteLike = Pick<PGlite, 'query' | 'exec'>;

class PGliteDb implements Db {
  constructor(
    private readonly conn: PGliteLike,
    private readonly root: PGlite | null,
  ) {}

  async query<T = Row>(sql: string, params?: unknown[]): Promise<QueryResult<T>> {
    const r = await this.conn.query<Row>(sql, params ?? []);
    // PGlite reports affectedRows = 0 for SELECT; rows.length covers SELECT and RETURNING.
    return { rows: normaliseRows<T>(r.rows), rowCount: Math.max(r.affectedRows ?? 0, r.rows.length) };
  }

  async exec(sql: string): Promise<void> {
    await this.conn.exec(sql);
  }

  async transaction<T>(fn: (tx: Db) => Promise<T>): Promise<T> {
    if (!this.root) return fn(this);
    return this.root.transaction(async (tx) => fn(new PGliteDb(tx as unknown as PGliteLike, null)));
  }

  async close(): Promise<void> {
    if (this.root && !this.root.closed) await this.root.close();
  }
}

export async function createPGliteDb(dataDir?: string): Promise<Db> {
  const instance = dataDir ? new PGlite(dataDir) : new PGlite();
  await instance.waitReady;
  const db = new PGliteDb(instance, instance);
  await migrate(db);
  return db;
}

/** In-memory PGlite with all migrations applied. */
export async function createMemoryDb(): Promise<Db> {
  return createPGliteDb();
}

// ---------------------------------------------------------------- node-postgres

type Queryable = Pick<pg.PoolClient, 'query'>;

class PgDb implements Db {
  constructor(
    private readonly conn: Queryable,
    private readonly pool: pg.Pool | null,
  ) {}

  async query<T = Row>(sql: string, params?: unknown[]): Promise<QueryResult<T>> {
    const r = await this.conn.query(sql, pgParams(params));
    return { rows: normaliseRows<T>(r.rows), rowCount: r.rowCount ?? r.rows.length };
  }

  async exec(sql: string): Promise<void> {
    await this.conn.query(sql);
  }

  async transaction<T>(fn: (tx: Db) => Promise<T>): Promise<T> {
    if (!this.pool) return fn(this);
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const out = await fn(new PgDb(client, null));
      await client.query('COMMIT');
      return out;
    } catch (e) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw e;
    } finally {
      client.release();
    }
  }

  async close(): Promise<void> {
    if (this.pool) await this.pool.end();
  }
}

export async function createPostgresDb(connectionString: string): Promise<Db> {
  // int8 (bigint) columns come back as strings by default; all our bigints are < 2^53.
  pg.types.setTypeParser(20, (v) => Number(v));
  const pool = new pg.Pool({ connectionString, max: 10, application_name: 'veil' });
  const db = new PgDb(pool, pool);
  await migrate(db);
  return db;
}

/** Builds `$n, $n+1, ...` placeholders for an IN list starting at parameter index `start`. */
export function placeholders(count: number, start: number): string {
  return Array.from({ length: count }, (_, i) => `$${start + i}`).join(', ');
}
