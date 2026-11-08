import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import WebSocket from 'ws';
import { randomBytes, toB64 } from '@veil/crypto';
import { type Harness, envelope, register, startHarness } from './helpers.js';

let h: Harness;
beforeEach(async () => {
  h = await startHarness();
});
afterEach(async () => {
  await h.close();
});

describe('prekey bundles', () => {
  it('hands out each one-time prekey at most once and then falls back to the signed prekey', async () => {
    const alice = await register(h);
    const bob = await register(h, { otkCount: 2 });
    const seen = new Set<number>();
    for (let i = 0; i < 3; i++) {
      const r = await h.call('POST', '/v1/keys/bundles', { token: alice.token, body: { username: bob.username.toLowerCase() } });
      expect(r.status).toBe(200);
      expect(r.json.username).toBe(bob.username);
      const b = r.json.bundles[0];
      expect(b.signedPreKey.keyId).toBe(1);
      if (i < 2) {
        expect(seen.has(b.oneTimePreKey.keyId)).toBe(false);
        seen.add(b.oneTimePreKey.keyId);
      } else {
        expect(b.oneTimePreKey).toBeNull();
      }
    }
    expect((await h.call('GET', '/v1/keys/status', { token: bob.token })).json.oneTimePreKeys).toBe(0);
    // An unassigned name gets a decoy bundle, never a 404 (see decoy.test.ts).
    expect((await h.call('POST', '/v1/keys/bundles', { token: alice.token, body: { username: 'QuietOtter' } })).status).toBe(200);
    expect((await h.call('POST', '/v1/keys/bundles', { token: alice.token, body: { username: 'NotAWordName' } })).status).toBe(404);
  });

  it('concurrent bundle fetches never hand out the same one-time prekey twice', async () => {
    const alice = await register(h);
    const bob = await register(h, { otkCount: 20 });
    const results = await Promise.all(
      Array.from({ length: 20 }, () => h.call('POST', '/v1/keys/bundles', { token: alice.token, body: { username: bob.username } })),
    );
    const ids = results.map((r) => r.json.bundles[0].oneTimePreKey?.keyId);
    expect(new Set(ids).size).toBe(20);
  });

  it('rejects signed prekeys not signed by the device key and accepts valid replacements', async () => {
    const alice = await register(h);
    const bob = await register(h);
    const { generateSignedPreKey } = await import('@veil/crypto');
    const foreign = generateSignedPreKey(bob.devices[0]!.keys, 7);
    const bad = await h.call('PUT', '/v1/keys/signed-prekey', {
      token: alice.token,
      body: { keyId: 7, publicKey: toB64(foreign.keyPair.publicKey), signature: toB64(foreign.signature) },
    });
    expect(bad.status).toBe(400);
    const own = generateSignedPreKey(alice.devices[0]!.keys, 8);
    const ok = await h.call('PUT', '/v1/keys/signed-prekey', {
      token: alice.token,
      body: { keyId: 8, publicKey: toB64(own.keyPair.publicKey), signature: toB64(own.signature) },
    });
    expect(ok.status).toBe(204);
    expect((await h.call('GET', '/v1/keys/status', { token: alice.token })).json.signedPreKeyId).toBe(8);
    const up = await h.call('POST', '/v1/keys/one-time', { token: alice.token, body: { preKeys: [{ keyId: 900, publicKey: toB64(randomBytes(32)) }] } });
    expect(up.json.oneTimePreKeys).toBe(6);
  });
});

describe('message relay', () => {
  it('stores no sender: the envelope row contains only recipient device, ids, payload and coarse expiry', async () => {
    const alice = await register(h);
    const bob = await register(h);
    await h.call('POST', '/v1/messages', { token: alice.token, body: { envelopes: [envelope(bob.devices[0]!.keys.deviceId)] } });
    const cols = await h.db.query<{ column_name: string }>(
      "SELECT column_name FROM information_schema.columns WHERE table_schema = 'mailbox' AND table_name = 'envelopes' ORDER BY column_name",
    );
    expect(cols.rows.map((c) => c.column_name)).toEqual(['device_id', 'envelope_id', 'expires_day', 'payload', 'seq']);
    const row = (await h.db.query<Record<string, unknown>>('SELECT * FROM mailbox.envelopes')).rows[0]!;
    expect(toB64(row.device_id as Uint8Array)).toBe(toB64(bob.devices[0]!.keys.deviceId));
  });

  it('concurrent submissions get unique per-device sequence numbers and are delivered in order', async () => {
    const alice = await register(h);
    const carol = await register(h);
    const bob = await register(h);
    const target = bob.devices[0]!.keys.deviceId;
    const sends = Array.from({ length: 50 }, (_, i) => {
      const token = i % 2 ? alice.token : carol.token;
      return h.call('POST', '/v1/messages', { token, body: { envelopes: [envelope(target, new Uint8Array([i + 1]))] } });
    });
    const results = await Promise.all(sends);
    expect(results.every((r) => r.status === 200 && r.json.accepted === 1)).toBe(true);
    const seqs = (await h.db.query<{ seq: number }>('SELECT seq FROM mailbox.envelopes ORDER BY seq')).rows.map((r) => Number(r.seq));
    expect(seqs).toEqual(Array.from({ length: 50 }, (_, i) => i + 1));
    const box = await h.call('GET', '/v1/mailbox?limit=500', { token: bob.token });
    expect(box.json.envelopes).toHaveLength(50);
    expect(box.json.more).toBe(false);
  });

  it('per-device sequences are independent (no global counter)', async () => {
    const alice = await register(h);
    const bob = await register(h);
    const carol = await register(h);
    await h.call('POST', '/v1/messages', { token: alice.token, body: { envelopes: [envelope(bob.devices[0]!.keys.deviceId)] } });
    await h.call('POST', '/v1/messages', { token: alice.token, body: { envelopes: [envelope(carol.devices[0]!.keys.deviceId)] } });
    const seqs = (await h.db.query<{ seq: number }>('SELECT seq FROM mailbox.envelopes')).rows.map((r) => Number(r.seq));
    expect(seqs).toEqual([1, 1]);
  });

  it('retries with the same envelope id are idempotent', async () => {
    const alice = await register(h);
    const bob = await register(h);
    const env = envelope(bob.devices[0]!.keys.deviceId);
    const first = await h.call('POST', '/v1/messages', { token: alice.token, body: { envelopes: [env] } });
    const again = await Promise.all([1, 2, 3].map(() => h.call('POST', '/v1/messages', { token: alice.token, body: { envelopes: [env] } })));
    expect(first.json.accepted).toBe(1);
    for (const r of again) expect(r.json.accepted).toBe(1);
    expect((await h.call('GET', '/v1/mailbox', { token: bob.token })).json.envelopes).toHaveLength(1);
  });

  it('delivers in order, pages with `more`, and deletes on acknowledgement', async () => {
    const alice = await register(h);
    const bob = await register(h);
    const envs = [1, 2, 3, 4, 5].map((i) => envelope(bob.devices[0]!.keys.deviceId, new Uint8Array([i])));
    for (const e of envs) await h.call('POST', '/v1/messages', { token: alice.token, body: { envelopes: [e] } });
    const page = await h.call('GET', '/v1/mailbox?limit=3', { token: bob.token });
    expect(page.json.envelopes.map((e: { envelopeId: string }) => e.envelopeId)).toEqual(envs.slice(0, 3).map((e) => e.envelopeId));
    expect(page.json.more).toBe(true);
    await h.call('POST', '/v1/mailbox/ack', { token: bob.token, body: { envelopeIds: envs.slice(0, 3).map((e) => e.envelopeId) } });
    const rest = await h.call('GET', '/v1/mailbox', { token: bob.token });
    expect(rest.json.envelopes.map((e: { envelopeId: string }) => e.envelopeId)).toEqual(envs.slice(3).map((e) => e.envelopeId));
  });

  it('undelivered envelopes expire after the retention period', async () => {
    const alice = await register(h);
    const bob = await register(h);
    await h.call('POST', '/v1/messages', { token: alice.token, body: { envelopes: [envelope(bob.devices[0]!.keys.deviceId)] } });
    h.clock.t += 31 * 86_400_000;
    await h.server.sweep();
    expect(Number((await h.db.query<{ n: number }>('SELECT count(*)::int AS n FROM mailbox.envelopes')).rows[0]!.n)).toBe(0);
  });
});

describe('websocket notifications', () => {
  it('requires auth as the first frame, pushes `mail` hints, and carries no content', async () => {
    const url = (await h.server.listen({ host: '127.0.0.1', port: 0 })).replace('http', 'ws');
    const alice = await register(h);
    const bob = await register(h);
    const bad = new WebSocket(`${url}/v1/ws`);
    const badClose = await new Promise<number>((resolve) => {
      bad.on('open', () => bad.send(JSON.stringify({ type: 'auth', accessToken: 'nope' })));
      bad.on('close', (code) => resolve(code));
    });
    expect(badClose).toBe(4001);

    const ws = new WebSocket(`${url}/v1/ws`);
    const frames: string[] = [];
    await new Promise<void>((resolve) => {
      ws.on('open', () => ws.send(JSON.stringify({ type: 'auth', accessToken: bob.token })));
      ws.on('message', (m) => {
        frames.push(m.toString());
        if (frames.length === 1) resolve();
      });
    });
    expect(JSON.parse(frames[0]!)).toEqual({ type: 'ready' });
    const env = envelope(bob.devices[0]!.keys.deviceId);
    await h.call('POST', '/v1/messages', { token: alice.token, body: { envelopes: [env] } });
    await new Promise((r) => setTimeout(r, 100));
    expect(frames.map((f) => JSON.parse(f))).toContainEqual({ type: 'mail' });
    expect(frames.join('')).not.toContain(env.payload);
    ws.close();
  });
});

describe('attachments', () => {
  it('enforces the download budget, has no owner column and supports deletion by token', async () => {
    const alice = await register(h);
    const bob = await register(h);
    const blob = Buffer.from(randomBytes(1000));
    const up = await h.call('POST', '/v1/attachments?downloads=2', { token: alice.token, raw: blob, headers: { 'content-type': 'application/octet-stream' } });
    expect(up.status).toBe(200);
    const id = up.json.attachmentId;
    const d1 = await h.call('GET', `/v1/attachments/${id}`, { token: bob.token });
    expect(d1.status).toBe(200);
    expect(Buffer.compare(d1.raw.rawPayload, blob)).toBe(0);
    expect((await h.call('GET', `/v1/attachments/${id}`, { token: alice.token })).status).toBe(200);
    expect((await h.call('GET', `/v1/attachments/${id}`, { token: bob.token })).status).toBe(404);
    expect(await h.blobs.get(Buffer.from(id, 'base64url'))).toBeNull();

    const cols = (await h.db.query<{ column_name: string }>(
      "SELECT column_name FROM information_schema.columns WHERE table_schema = 'media' ORDER BY column_name",
    )).rows.map((c) => c.column_name);
    expect(cols).toEqual(['delete_token_hash', 'expires_day', 'id', 'remaining_downloads', 'size']);

    const up2 = await h.call('POST', '/v1/attachments?downloads=5', { token: alice.token, raw: blob, headers: { 'content-type': 'application/octet-stream' } });
    const wrong = await h.call('POST', `/v1/attachments/${up2.json.attachmentId}/delete`, { token: bob.token, body: { deleteToken: toB64(randomBytes(32)) } });
    expect(wrong.status).toBe(404);
    const del = await h.call('POST', `/v1/attachments/${up2.json.attachmentId}/delete`, { token: bob.token, body: { deleteToken: up2.json.deleteToken } });
    expect(del.status).toBe(204);
    expect((await h.call('GET', `/v1/attachments/${up2.json.attachmentId}`, { token: bob.token })).status).toBe(404);
  });

  it('rejects oversized uploads and invalid download budgets; attachments expire', async () => {
    await h.close();
    h = await startHarness({ config: { attachmentMaxBytes: 2048 } });
    const alice = await register(h);
    const big = await h.call('POST', '/v1/attachments', { token: alice.token, raw: Buffer.alloc(4096), headers: { 'content-type': 'application/octet-stream' } });
    expect(big.status).toBe(413);
    const budget = await h.call('POST', '/v1/attachments?downloads=0', { token: alice.token, raw: Buffer.alloc(10), headers: { 'content-type': 'application/octet-stream' } });
    expect(budget.status).toBe(400);
    const ok = await h.call('POST', '/v1/attachments?downloads=1', { token: alice.token, raw: Buffer.alloc(10, 1), headers: { 'content-type': 'application/octet-stream' } });
    h.clock.t += 31 * 86_400_000;
    await h.server.sweep();
    expect(await h.blobs.get(Buffer.from(ok.json.attachmentId, 'base64url'))).toBeNull();
  });
});
