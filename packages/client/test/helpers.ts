import { createMemoryDb, createServer, MemoryBlobStore, type VeilServer } from '@veil/server';
import { randomBytes } from '@veil/crypto';
import { MemoryStorage, VeilClient, type ResetReport, type StorageBackend } from '../src/index.js';

export const TINY_KDF = { memoryKiB: 64, iterations: 1, parallelism: 1 };
export const PASSWORD = 'correct horse battery staple';

export interface Harness {
  server: VeilServer;
  url: string;
  logs: unknown[];
  blobs: MemoryBlobStore;
  client(opts?: { storage?: StorageBackend; fetch?: typeof fetch }): VeilClient;
  close(): Promise<void>;
}

export async function startHarness(): Promise<Harness> {
  const logs: unknown[] = [];
  const blobs = new MemoryBlobStore();
  const server = await createServer({
    db: await createMemoryDb(),
    blobStore: blobs,
    log: (e) => logs.push(e),
    sweepIntervalMs: 0,
    config: {
      serverSecret: randomBytes(32),
      powDifficulty: 4,
      minimumKdf: TINY_KDF,
      recommendedKdf: TINY_KDF,
      serverArgon2: { memoryCost: 1024, timeCost: 1, parallelism: 1 },
      rateLimit: { enabled: false },
    },
  });
  const url = await server.listen({ host: '127.0.0.1', port: 0 });
  const clients: VeilClient[] = [];
  return {
    server,
    url,
    logs,
    blobs,
    client(opts = {}) {
      const c = new VeilClient({
        baseUrl: url,
        storage: opts.storage ?? new MemoryStorage(),
        minimumKdf: TINY_KDF,
        realtime: false,
        ...(opts.fetch ? { fetch: opts.fetch } : {}),
      });
      clients.push(c);
      return c;
    },
    async close() {
      for (const c of clients) await c.lock().catch(() => {});
      await server.close();
    },
  };
}

export async function registered(h: Harness, opts: { recovery?: boolean; storage?: StorageBackend } = {}) {
  const storage = opts.storage ?? new MemoryStorage();
  const client = h.client({ storage });
  await client.init();
  const s = await client.suggestUsername();
  const res = await client.register({ reservation: s.reservation, password: PASSWORD, enableRecovery: !!opts.recovery });
  return { client, storage, username: res.username, recoveryKey: res.recoveryKey };
}

/** Lets each client process its mailbox (tests run without the WebSocket). */
export async function sync(...clients: VeilClient[]) {
  for (let i = 0; i < 2; i++) for (const c of clients) await c.drain();
}

export function texts(c: VeilClient, peer: string) {
  return c.messages(peer).filter((m) => m.direction !== 'system').map((m) => `${m.direction}:${m.text}`);
}

export async function dumpDatabase(server: VeilServer): Promise<string> {
  const tables = await server.db.query<{ table_schema: string; table_name: string }>(
    `SELECT table_schema, table_name FROM information_schema.tables
     WHERE table_schema IN ('identity','auth','keys','mailbox','media','ops') ORDER BY 1, 2`,
  );
  let out = '';
  for (const t of tables.rows) {
    const rows = await server.db.query(`SELECT * FROM "${t.table_schema}"."${t.table_name}"`);
    for (const r of rows.rows as Record<string, unknown>[]) {
      for (const v of Object.values(r)) {
        if (v instanceof Uint8Array) out += Buffer.from(v).toString('latin1') + '\n' + Buffer.from(v).toString('hex') + '\n';
        else out += String(v) + '\n';
      }
    }
  }
  return out;
}

export function storageDump(storage: MemoryStorage): string {
  return storage.dump().map((b) => Buffer.from(b).toString('latin1')).join('\n');
}

export async function collectReset(run: (onProgress: (r: ResetReport) => void) => Promise<ResetReport>) {
  const phases: string[] = [];
  const report = await run((r) => {
    if (phases[phases.length - 1] !== r.phase) phases.push(r.phase);
  });
  return { report, phases };
}
