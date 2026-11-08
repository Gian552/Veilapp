// Metadata and secret leakage: run a realistic scenario (with a trusted proxy
// forwarding a client IP, rate limiting on, an induced internal error) and
// then scan every log line and every database row for things that must
// never be persisted.
import { afterEach, describe, expect, it } from 'vitest';
import {
  deriveMasterKey,
  randomBytes,
  sealToPublicKey,
  splitMasterKey,
  toB64,
  toHex,
  utf8,
} from '@veil/crypto';
import { MemoryBlobStore } from '../src/blobstore.js';
import { type Harness, buildRegistration, dumpDatabase, envelope, login, startHarness, TEST_KDF } from './helpers.js';

const PASSWORD = 'correct horse battery staple 42';
const MARKER = 'PLAINTEXT-MARKER-umbrella-7781';
const CLIENT_IP = '203.0.113.77';

class FlakyUploads extends MemoryBlobStore {
  fail = false;
  override async put(id: Uint8Array, data: Uint8Array): Promise<void> {
    if (this.fail) throw new Error(`disk full while writing ${MARKER}`);
    return super.put(id, data);
  }
}

let h: Harness;
afterEach(async () => {
  await h?.close();
});

describe('logs and database contain no secrets or prohibited metadata', () => {
  it('after a full scenario', async () => {
    const blobs = new FlakyUploads();
    h = await startHarness({ blobs, config: { trustProxy: true, rateLimit: { enabled: true } } });
    const xff = { 'x-forwarded-for': CLIENT_IP, 'user-agent': 'LeakTestBrowser/1.0' };
    const call = (m: string, u: string, o: Parameters<Harness['call']>[2] = {}) => h.call(m, u, { ...o, headers: { ...xff, ...(o.headers ?? {}) } });

    // Real client-side derivation from a password.
    const clientSalt = randomBytes(16);
    const master = await deriveMasterKey(PASSWORD, clientSalt, TEST_KDF);
    const { authKey, vaultKek } = splitMasterKey(master);
    const reg = await buildRegistration(h, { authKey });
    reg.body.clientSalt = toB64(clientSalt);
    const aliceRes = await call('POST', '/v1/auth/register', { body: reg.body });
    expect(aliceRes.status).toBe(201);
    const bobReg = await buildRegistration(h);
    const bobRes = await call('POST', '/v1/auth/register', { body: bobReg.body });

    const tokens = [aliceRes.json.accessToken, aliceRes.json.refreshToken, bobRes.json.accessToken, bobRes.json.refreshToken];
    const refreshed = await call('POST', '/v1/auth/refresh', { body: { refreshToken: aliceRes.json.refreshToken } });
    tokens.push(refreshed.json.accessToken, refreshed.json.refreshToken);
    const alice = refreshed.json.accessToken;

    // Login attempts, good and bad.
    const acct = { username: reg.username, authKey, clientSalt } as never;
    await login(h, acct);
    await login(h, { ...(acct as object), authKey: randomBytes(32) } as never);

    // An end-to-end encrypted message (sealed to Bob's device key).
    const sealed = sealToPublicKey(bobReg.device.dh.publicKey, utf8(MARKER), 'VEIL/v1/sealed-envelope', bobReg.device.deviceId);
    await call('POST', '/v1/messages', { token: alice, body: { envelopes: [envelope(bobReg.device.deviceId, sealed)] } });
    await call('GET', '/v1/mailbox', { token: bobRes.json.accessToken });

    // Induce an internal error whose message contains the marker.
    blobs.fail = true;
    const err = await call('POST', '/v1/attachments', { token: alice, raw: Buffer.from('x'), headers: { 'content-type': 'application/octet-stream' } });
    expect(err.status).toBe(500);
    expect(err.raw.body).not.toContain(MARKER);
    expect(h.logs.length).toBeGreaterThan(0);

    // Panic reset for Alice too (exercises ledger/job tables).
    await call('POST', '/v1/reset', { token: alice, body: { jobId: toB64(randomBytes(16)), jobSecret: toB64(randomBytes(32)), attachments: [] } });

    const logText = JSON.stringify(h.logs);
    const dbText = await dumpDatabase(h.db);
    const forbidden = [
      PASSWORD,
      MARKER,
      toB64(authKey),
      toHex(authKey),
      toB64(vaultKek),
      toHex(vaultKek),
      toB64(master),
      CLIENT_IP,
      '127.0.0.1',
      'LeakTestBrowser',
      ...tokens,
      ...tokens.map((t: string) => t.split('.').pop()!), // token secret / MAC parts
    ];
    for (const needle of forbidden) {
      expect(logText, `log contains ${needle}`).not.toContain(needle);
      expect(dbText, `db contains ${needle}`).not.toContain(needle);
    }
    // Log entries only have the documented fields.
    for (const e of h.logs) for (const k of Object.keys(e)) expect(['level', 'event', 'route', 'code']).toContain(k);
    expect(h.logs.find((e) => e.event === 'unhandled_error')?.route).toBe('/v1/attachments');
  });
});
