// Runs core flows against a real PostgreSQL server (node-postgres code path).
// Skipped unless VEIL_TEST_DATABASE_URL points at a server where the user may
// CREATE DATABASE, e.g.:
//   docker run --rm -d -e POSTGRES_PASSWORD=pw -p 55432:5432 postgres:17
//   VEIL_TEST_DATABASE_URL=postgres://postgres:pw@127.0.0.1:55432/postgres npx vitest run apps/server/test/postgres.test.ts
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { randomBytes, toB64, toHex } from '@veil/crypto';
import { createPostgresDb, deriveServerKeys, replayDeletions } from '../src/index.js';
import type { Db } from '../src/db.js';
import { migrate } from '../src/migrations.js';
import { type Harness, countRows, envelope, linkNewDevice, register, startHarness } from './helpers.js';

const ADMIN_URL = process.env.VEIL_TEST_DATABASE_URL;
const dbName = `veil_test_${toHex(randomBytes(6))}`;

describe.skipIf(!ADMIN_URL)('PostgreSQL backend', () => {
  let db: Db;
  let h: Harness;

  beforeAll(async () => {
    const admin = new pg.Client({ connectionString: ADMIN_URL });
    await admin.connect();
    await admin.query(`CREATE DATABASE ${dbName}`);
    await admin.end();
    const url = new URL(ADMIN_URL!);
    url.pathname = `/${dbName}`;
    db = await createPostgresDb(url.toString());
    h = await startHarness({ db });
  });

  afterAll(async () => {
    await h?.close();
    await db?.close();
    const admin = new pg.Client({ connectionString: ADMIN_URL });
    await admin.connect();
    await admin.query(`DROP DATABASE IF EXISTS ${dbName}`);
    await admin.end();
  });

  it('migrations are idempotent and bytea values round-trip as Uint8Array', async () => {
    await migrate(db);
    const r = await db.query<{ b: Uint8Array; n: number }>('SELECT $1::bytea AS b, 9007199254740991::bigint AS n', [new Uint8Array([1, 2, 255])]);
    expect(r.rows[0]!.b).toEqual(new Uint8Array([1, 2, 255]));
    expect(r.rows[0]!.b.constructor).toBe(Uint8Array);
    expect(r.rows[0]!.n).toBe(Number.MAX_SAFE_INTEGER);
  });

  it('registers, links, relays concurrently with per-device ordering, and resets atomically', async () => {
    const alice = await register(h, { recovery: true });
    const bob = await register(h, { otkCount: 30 });
    await linkNewDevice(h, alice);

    const bundles = await Promise.all(Array.from({ length: 30 }, () => h.call('POST', '/v1/keys/bundles', { token: alice.token, body: { username: bob.username } })));
    expect(new Set(bundles.map((b) => b.json.bundles[0].oneTimePreKey?.keyId)).size).toBe(30);

    const target = bob.devices[0]!.keys.deviceId;
    const sends = await Promise.all(Array.from({ length: 40 }, (_, i) => h.call('POST', '/v1/messages', { token: alice.token, body: { envelopes: [envelope(target, new Uint8Array([i + 1]))] } })));
    expect(sends.every((s) => s.json.accepted === 1)).toBe(true);
    const seqs = (await db.query<{ seq: number }>('SELECT seq FROM mailbox.envelopes WHERE device_id = $1 ORDER BY seq', [target])).rows.map((r) => r.seq);
    expect(seqs).toEqual(Array.from({ length: 40 }, (_, i) => i + 1));

    const body = { jobId: toB64(randomBytes(16)), jobSecret: toB64(randomBytes(32)), attachments: [] };
    const [r1, r2] = await Promise.all([
      h.call('POST', '/v1/reset', { token: alice.token, body }),
      h.call('POST', '/v1/reset', { token: alice.devices[1]!.session!.accessToken, body }),
    ]);
    expect([r1.status, r2.status]).toEqual([200, 200]);
    const counts = await countRows(db);
    expect(counts['identity.accounts']).toBe(1);
    expect(counts['keys.devices']).toBe(1);
    expect(counts['auth.recovery']).toBe(0);
    expect((await replayDeletions(db, deriveServerKeys(h.server.config.serverSecret))).accountsDeleted).toBe(0);
  });
});
