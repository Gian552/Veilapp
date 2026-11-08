// Panic Reset: atomic server-side deletion, idempotency under retries and
// interruption, partial blob-deletion failures, old-session lockout, username
// retirement, WebSocket revocation and backup-restore replay.
import { afterEach, describe, expect, it } from 'vitest';
import WebSocket from 'ws';
import { encodeLinkRequest, generateDeviceKeys, generateLinkSecret, randomBytes, toB64, x25519KeyPair } from '@veil/crypto';
import { MemoryBlobStore, replayDeletions, deriveServerKeys } from '../src/index.js';
import type { Db } from '../src/db.js';
import { generateUsername } from '../src/routes/auth.js';
import {
  ALL_TABLES,
  FailingBlobStore,
  type Harness,
  type TestAccount,
  countRows,
  envelope,
  linkNewDevice,
  login,
  register,
  startHarness,
} from './helpers.js';

let h: Harness;
afterEach(async () => {
  await h?.close();
});

async function populated(harness: Harness) {
  const alice = await register(harness, { recovery: true });
  const bob = await register(harness);
  await linkNewDevice(harness, alice);
  await harness.call('PUT', '/v1/profile', { token: alice.token, body: { profile: toB64(randomBytes(64)) } });
  // Mail both ways, a pending link request, and two attachments uploaded by Alice.
  await harness.call('POST', '/v1/messages', { token: bob.token, body: { envelopes: alice.devices.map((d) => envelope(d.keys.deviceId)) } });
  await harness.call('POST', '/v1/messages', { token: alice.token, body: { envelopes: [envelope(bob.devices[0]!.keys.deviceId)] } });
  const link = await login(harness, alice);
  await harness.call('POST', '/v1/link/requests', { token: link.json.accessToken, body: { request: toB64(linkRequestBytes()) } });
  const uploads = [];
  for (let i = 0; i < 2; i++) {
    const up = await harness.call('POST', '/v1/attachments?downloads=3', {
      token: alice.token,
      raw: Buffer.from(randomBytes(200)),
      headers: { 'content-type': 'application/octet-stream' },
    });
    uploads.push(up.json as { attachmentId: string; deleteToken: string });
  }
  return { alice, bob, uploads, linkToken: link.json.accessToken as string };
}

function linkRequestBytes(): Uint8Array {
  const k = generateDeviceKeys();
  return encodeLinkRequest({ deviceId: k.deviceId, signingKey: k.signing.publicKey, dhKey: k.dh.publicKey, provisioningKey: x25519KeyPair().publicKey }, generateLinkSecret());
}

function resetBody(uploads: { attachmentId: string; deleteToken: string }[]) {
  return { jobId: toB64(randomBytes(16)), jobSecret: toB64(randomBytes(32)), attachments: uploads };
}

async function accountRowsFor(db: Db, acct: TestAccount): Promise<number> {
  const r = await db.query<{ n: number }>('SELECT count(*)::int AS n FROM identity.accounts WHERE username = $1', [acct.username]);
  return Number(r.rows[0]!.n);
}

describe('Panic Reset', () => {
  it('deletes every server-side record of the account in one step and leaves other accounts intact', async () => {
    h = await startHarness();
    const { alice, bob, uploads } = await populated(h);
    const before = await countRows(h.db);
    const res = await h.call('POST', '/v1/reset', { token: alice.token, body: resetBody(uploads) });
    expect(res.status).toBe(200);
    expect(res.json).toMatchObject({ state: 'completed', accountRecordsDeleted: true, attachmentsDeleted: 2, attachmentsPending: 0, attachmentsNotFound: 0 });
    expect(res.json.backupRetentionDays).toBe(7);

    const after = await countRows(h.db);
    expect(after['identity.accounts']).toBe(1);
    expect(after['auth.credentials']).toBe(1);
    expect(after['auth.recovery']).toBe(0);
    expect(after['auth.sessions']).toBe(1); // Bob's only
    expect(after['keys.devices']).toBe(1);
    expect(after['keys.signed_prekeys']).toBe(1);
    expect(after['keys.one_time_prekeys']).toBe(before['keys.one_time_prekeys']! - 5 - 3);
    expect(after['keys.link_requests']).toBe(0);
    expect(after['mailbox.envelopes']).toBe(1); // the envelope queued for Bob
    expect(after['media.attachments']).toBe(0);
    expect(after['identity.retired_usernames']).toBe(1);
    expect(after['ops.deletion_ledger']).toBe(1);
    expect(after['ops.reset_jobs']).toBe(1);
    expect(after['ops.pending_blob_deletions']).toBe(0);
    expect((h.blobs as MemoryBlobStore).blobs.size).toBe(0);
    // No remaining row anywhere references the old identity key or username.
    const dump = JSON.stringify(
      await Promise.all(ALL_TABLES.map(async (t) => (await h.db.query(`SELECT * FROM ${t}`)).rows)),
      (_k, v) => (v instanceof Uint8Array ? toB64(v) : v),
    );
    expect(dump).not.toContain(toB64(alice.aik.publicKey));
    expect(dump).not.toContain(alice.username);
    for (const d of alice.devices) expect(dump).not.toContain(toB64(d.keys.deviceId));
    // Bob is unaffected.
    expect((await h.call('GET', '/v1/account', { token: bob.token })).status).toBe(200);
    // The retired name now resolves to a decoy: same shape as any account, but none of Alice's keys.
    const decoy = await h.call('GET', `/v1/directory/${alice.username}`, { token: bob.token });
    expect(decoy.status).toBe(200);
    expect(decoy.json.identityKey).not.toBe(toB64(alice.aik.publicKey));
  });

  it('old access tokens, refresh tokens, link sessions and passwords stop working immediately', async () => {
    h = await startHarness();
    const { alice, linkToken } = await populated(h);
    await h.call('POST', '/v1/reset', { token: alice.token, body: resetBody([]) });
    for (const d of alice.devices) expect((await h.call('GET', '/v1/account', { token: d.session!.accessToken })).status).toBe(401);
    expect((await h.call('GET', '/v1/account', { token: linkToken })).status).toBe(401);
    expect((await h.call('POST', '/v1/auth/refresh', { body: { refreshToken: alice.refreshToken } })).status).toBe(401);
    expect((await login(h, alice)).status).toBe(401);
    expect((await login(h, alice, alice.devices[0]!.keys)).status).toBe(401);
  });

  it('is idempotent: a retried request (lost response) returns the same job status without a session', async () => {
    h = await startHarness();
    const { alice, uploads } = await populated(h);
    const body = resetBody(uploads);
    const first = await h.call('POST', '/v1/reset', { token: alice.token, body });
    // The client never saw `first` (network drop) and retries; its token is already dead.
    const retry = await h.call('POST', '/v1/reset', { token: alice.token, body });
    expect(retry.status).toBe(200);
    expect(retry.json).toEqual(first.json);
    const status = await h.call('POST', '/v1/reset/status', { body: { jobId: body.jobId, jobSecret: body.jobSecret } });
    expect(status.json).toEqual(first.json);
    // The job secret is required.
    const wrong = await h.call('POST', '/v1/reset/status', { body: { jobId: body.jobId, jobSecret: toB64(randomBytes(32)) } });
    expect(wrong.status).toBe(404);
    expect((await h.call('POST', '/v1/reset', { body: { ...body, jobSecret: toB64(randomBytes(32)) } })).status).toBe(404);
  });

  it('handles two concurrent requests for the same job (double submit)', async () => {
    h = await startHarness();
    const { alice } = await populated(h);
    const body = resetBody([]);
    const [a, b] = await Promise.all([
      h.call('POST', '/v1/reset', { token: alice.token, body }),
      h.call('POST', '/v1/reset', { token: alice.devices[1]!.session!.accessToken, body }),
    ]);
    expect([a.status, b.status]).toEqual([200, 200]);
    expect(Number((await h.db.query<{ n: number }>('SELECT count(*)::int AS n FROM ops.reset_jobs')).rows[0]!.n)).toBe(1);
  });

  it('a request that never reached the server leaves everything intact and can simply be retried', async () => {
    h = await startHarness();
    const { alice } = await populated(h);
    const body = resetBody([]);
    const unknown = await h.call('POST', '/v1/reset/status', { body: { jobId: body.jobId, jobSecret: body.jobSecret } });
    expect(unknown.status).toBe(404); // client learns: not started
    expect(await accountRowsFor(h.db, alice)).toBe(1);
    expect((await h.call('POST', '/v1/reset', { token: alice.token, body })).status).toBe(200);
    expect(await accountRowsFor(h.db, alice)).toBe(0);
  });

  it('reports partial completion when blob deletion fails and completes once storage recovers', async () => {
    const store = new FailingBlobStore();
    store.failDeletes = false;
    h = await startHarness({ blobs: store });
    const { alice, uploads } = await populated(h);
    store.failDeletes = true;
    const body = resetBody([...uploads, { attachmentId: toB64(randomBytes(16)), deleteToken: toB64(randomBytes(32)) }]);
    const res = await h.call('POST', '/v1/reset', { token: alice.token, body });
    expect(res.json).toMatchObject({ state: 'partial', accountRecordsDeleted: true, attachmentsDeleted: 0, attachmentsPending: 2, attachmentsNotFound: 1 });
    expect(await accountRowsFor(h.db, alice)).toBe(0);
    expect(store.blobs.size).toBe(2);
    // Status polling retries but storage is still down.
    expect((await h.call('POST', '/v1/reset/status', { body: { jobId: body.jobId, jobSecret: body.jobSecret } })).json.state).toBe('partial');
    store.failDeletes = false;
    await h.server.sweep();
    const done = await h.call('POST', '/v1/reset/status', { body: { jobId: body.jobId, jobSecret: body.jobSecret } });
    expect(done.json).toMatchObject({ state: 'completed', attachmentsDeleted: 2, attachmentsPending: 0 });
    expect(store.blobs.size).toBe(0);
  });

  it('retires the username so it is never issued again', async () => {
    h = await startHarness();
    const alice = await register(h);
    await h.call('POST', '/v1/reset', { token: alice.token, body: resetBody([]) });
    const retired = await h.db.query('SELECT 1 FROM identity.retired_usernames');
    expect(retired.rowCount).toBe(1);
    // generateUsername skips retired names: force the generator to see only that name.
    const words = await import('@veil/shared');
    const adj = alice.username.match(/^[A-Z][a-z]+/)![0];
    const noun = alice.username.slice(adj.length);
    const origA = [...words.ADJECTIVES];
    const origN = [...words.NOUNS];
    (words.ADJECTIVES as string[]).splice(0, origA.length, adj);
    (words.NOUNS as string[]).splice(0, origN.length, noun);
    try {
      const ctxLike = { db: h.db, keys: deriveServerKeys(h.server.config.serverSecret) } as never;
      await expect(generateUsername(ctxLike)).rejects.toThrow();
    } finally {
      (words.ADJECTIVES as string[]).splice(0, 1, ...origA);
      (words.NOUNS as string[]).splice(0, 1, ...origN);
    }
    expect(words.ADJECTIVES.length).toBe(origA.length);
  });

  it('notifies and closes the WebSockets of every old session', async () => {
    h = await startHarness();
    const url = (await h.server.listen({ host: '127.0.0.1', port: 0 })).replace('http', 'ws');
    const alice = await register(h);
    const ws = new WebSocket(`${url}/v1/ws`);
    const frames: unknown[] = [];
    const closed = new Promise<number>((resolve) => ws.on('close', (c) => resolve(c)));
    await new Promise<void>((resolve) => {
      ws.on('open', () => ws.send(JSON.stringify({ type: 'auth', accessToken: alice.token })));
      ws.on('message', (m) => {
        frames.push(JSON.parse(m.toString()));
        resolve();
      });
    });
    await h.call('POST', '/v1/reset', { token: alice.token, body: resetBody([]) });
    expect(await closed).toBe(4001);
    expect(frames).toContainEqual({ type: 'revoked' });
  });

  it('a link session (password only) can reset, e.g. after losing every device', async () => {
    h = await startHarness();
    const alice = await register(h);
    const link = await login(h, alice);
    const res = await h.call('POST', '/v1/reset', { token: link.json.accessToken, body: resetBody([]) });
    expect(res.status).toBe(200);
    expect(await accountRowsFor(h.db, alice)).toBe(0);
  });
});

describe('backups and replica retention', () => {
  const DATA_TABLES = ALL_TABLES.filter((t) => !t.startsWith('ops.'));
  const INSERT_ORDER = [
    'identity.accounts',
    'identity.retired_usernames',
    'auth.credentials',
    'auth.recovery',
    'keys.devices',
    'auth.sessions',
    'keys.signed_prekeys',
    'keys.one_time_prekeys',
    'keys.link_requests',
    'mailbox.envelopes',
    'media.attachments',
  ];

  async function snapshot(db: Db) {
    const out: Record<string, Record<string, unknown>[]> = {};
    for (const t of DATA_TABLES) out[t] = (await db.query<Record<string, unknown>>(`SELECT * FROM ${t}`)).rows;
    return out;
  }

  async function restore(db: Db, snap: Record<string, Record<string, unknown>[]>) {
    // Simulates restoring the data schemas from a backup; ops is left as is.
    await db.transaction(async (tx) => {
      await tx.query('DELETE FROM identity.accounts');
      await tx.query('DELETE FROM identity.retired_usernames');
      await tx.query('DELETE FROM media.attachments');
      for (const t of INSERT_ORDER) {
        for (const row of snap[t]!) {
          const cols = Object.keys(row);
          await tx.query(`INSERT INTO ${t} (${cols.join(', ')}) VALUES (${cols.map((_, i) => `$${i + 1}`).join(', ')})`, cols.map((c) => row[c]));
        }
      }
    });
  }

  it('replay-deletions removes accounts resurrected by restoring an older backup', async () => {
    h = await startHarness();
    const { alice, bob } = await populated(h);
    const backup = await snapshot(h.db); // nightly backup taken before the reset
    await h.call('POST', '/v1/reset', { token: alice.token, body: resetBody([]) });
    await restore(h.db, backup); // disaster recovery restores yesterday's data
    expect(await accountRowsFor(h.db, alice)).toBe(1); // resurrected!
    const r = await replayDeletions(h.db, deriveServerKeys(h.server.config.serverSecret));
    expect(r.accountsDeleted).toBe(1);
    expect(await accountRowsFor(h.db, alice)).toBe(0);
    expect(await accountRowsFor(h.db, bob)).toBe(1);
    expect((await h.db.query('SELECT 1 FROM identity.retired_usernames')).rowCount).toBe(1);
    expect((await h.db.query('SELECT 1 FROM keys.devices')).rowCount).toBe(1);
    // Idempotent.
    expect((await replayDeletions(h.db, deriveServerKeys(h.server.config.serverSecret))).accountsDeleted).toBe(0);
  });

  it('ledger and job records expire after the backup window; the ledger holds no username or id in clear', async () => {
    h = await startHarness();
    const alice = await register(h);
    const body = resetBody([]);
    await h.call('POST', '/v1/reset', { token: alice.token, body });
    const ledger = (await h.db.query<{ account_tag: Uint8Array; username_tag: Uint8Array }>('SELECT * FROM ops.deletion_ledger')).rows[0]!;
    expect(ledger.account_tag).toHaveLength(32);
    expect(Buffer.from(ledger.username_tag).toString('latin1')).not.toContain(alice.username);
    h.clock.t += 7 * 86_400_000;
    await h.server.sweep();
    expect((await h.db.query('SELECT 1 FROM ops.deletion_ledger')).rowCount).toBe(1);
    h.clock.t += 2 * 86_400_000;
    await h.server.sweep();
    expect((await h.db.query('SELECT 1 FROM ops.deletion_ledger')).rowCount).toBe(0);
    expect((await h.db.query('SELECT 1 FROM ops.reset_jobs')).rowCount).toBe(0);
    // Retired usernames persist (they protect contacts from impersonation).
    expect((await h.db.query('SELECT 1 FROM identity.retired_usernames')).rowCount).toBe(1);
  });
});
