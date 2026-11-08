import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { checkProofOfWork, randomBytes, toB64, toHex, utf8 } from '@veil/crypto';
import { isValidUsername } from '@veil/shared';
import { DAY_MS } from '../src/context.js';
import { makeToken } from '../src/tokens.js';
import { type Harness, buildRegistration, login, prelogin, register, startHarness } from './helpers.js';

let h: Harness;
beforeEach(async () => {
  h = await startHarness();
});
afterEach(async () => {
  await h.close();
});

describe('registration', () => {
  it('creates an account with a random two-word username and a device session', async () => {
    const acct = await register(h);
    expect(isValidUsername(acct.username)).toBe(true);
    const s = acct.devices[0]!.session!;
    expect(s.kind).toBe('device');
    expect(s.deviceId).toBe(toB64(acct.devices[0]!.keys.deviceId));
    const me = await h.call('GET', '/v1/account', { token: acct.token });
    expect(me.status).toBe(200);
    expect(me.json.username).toBe(acct.username);
    expect(me.json.recoveryEnabled).toBe(false);
  });

  it('stores an Argon2id PHC verifier of the auth key, never the key, with unique salts', async () => {
    const a = await register(h);
    const b = await register(h, { authKey: a.authKey }); // same auth key on purpose
    const rows = (await h.db.query<{ verifier: string; client_salt: Uint8Array }>('SELECT verifier, client_salt FROM auth.credentials')).rows;
    expect(rows).toHaveLength(2);
    for (const r of rows) {
      expect(r.verifier).toMatch(/^\$argon2id\$v=19\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$/);
      expect(r.verifier).not.toContain(toB64(a.authKey));
      expect(r.verifier).not.toContain(toHex(a.authKey));
    }
    const saltOf = (v: string) => v.split('$')[4];
    expect(saltOf(rows[0]!.verifier)).not.toBe(saltOf(rows[1]!.verifier));
    expect(rows[0]!.verifier).not.toBe(rows[1]!.verifier);
    expect(toHex(rows[0]!.client_salt)).not.toBe(toHex(rows[1]!.client_salt));
    expect(b.username).not.toBe(a.username);
  });

  it('requires a valid proof of work and rejects replayed challenges', async () => {
    const r = await buildRegistration(h);
    let bad = 0;
    while (checkProofOfWork(utf8(r.body.pow.challenge), bad, 4)) bad++;
    const wrong = await h.call('POST', '/v1/auth/register', { body: { ...r.body, pow: { ...r.body.pow, nonce: bad } } });
    expect(wrong.status).toBe(400);
    const forged = await h.call('POST', '/v1/auth/register', {
      body: { ...r.body, pow: { challenge: makeToken('c1', randomBytes(32), randomBytes(21)), nonce: 0 } },
    });
    expect(forged.status).toBe(400);
    const ok = await h.call('POST', '/v1/auth/register', { body: r.body });
    expect(ok.status).toBe(201);
    const r2 = await buildRegistration(h);
    const replay = await h.call('POST', '/v1/auth/register', { body: { ...r2.body, pow: r.body.pow } });
    expect(replay.status).toBe(400);
  });

  it('rejects forged or expired username reservations and custom usernames', async () => {
    const r = await buildRegistration(h);
    const forged = await h.call('POST', '/v1/auth/register', { body: { ...r.body, reservation: r.body.reservation.slice(0, -2) + 'AA' } });
    expect(forged.status).toBe(400);
    const custom = await h.call('POST', '/v1/auth/register', {
      body: { ...r.body, reservation: makeToken('r1', randomBytes(32), utf8('JohnSmith')) },
    });
    expect(custom.status).toBe(400);
    h.clock.t += 31 * 60 * 1000;
    const expired = await h.call('POST', '/v1/auth/register', { body: { ...r.body, pow: (await buildRegistration(h)).body.pow } });
    expect(expired.status).toBe(400);
  });

  it('rejects client KDF parameters below the configured minimum and inconsistent device lists', async () => {
    const r = await buildRegistration(h);
    const weak = await h.call('POST', '/v1/auth/register', { body: { ...r.body, kdf: { memoryKiB: 8, iterations: 1, parallelism: 1 } } });
    expect(weak.status).toBe(400);
    const other = await buildRegistration(h);
    const mismatch = await h.call('POST', '/v1/auth/register', { body: { ...r.body, deviceList: other.body.deviceList } });
    expect(mismatch.status).toBe(400);
    const extra = await h.call('POST', '/v1/auth/register', { body: { ...r.body, email: 'a@b.c' } });
    expect(extra.status).toBe(400);
  });
});

describe('login and enumeration resistance', () => {
  it('password alone yields a link session; password + device proof yields a device session', async () => {
    const acct = await register(h);
    const link = await login(h, acct);
    expect(link.status).toBe(200);
    expect(link.json.kind).toBe('link');
    expect(link.json.deviceId).toBeNull();
    const dev = await login(h, acct, acct.devices[0]!.keys);
    expect(dev.json.kind).toBe('device');
    // The device's previous session was replaced (one session per device).
    expect((await h.call('GET', '/v1/account', { token: acct.token })).status).toBe(401);
    expect((await h.call('GET', '/v1/account', { token: dev.json.accessToken })).status).toBe(200);
  });

  it('a device proof for another account or with a bad signature fails generically', async () => {
    const a = await register(h);
    const b = await register(h);
    const r = await login(h, a, b.devices[0]!.keys);
    expect(r.status).toBe(401);
    expect(r.json.error.message).toBe('Invalid username or password.');
  });

  it('prelogin responses for unknown users are indistinguishable in shape and deterministic', async () => {
    const acct = await register(h);
    const known = await prelogin(h, acct.username);
    const unknown1 = await prelogin(h, 'QuietOtter');
    const unknown2 = await prelogin(h, 'quietotter');
    expect(Object.keys(unknown1).sort()).toEqual(Object.keys(known).sort());
    expect(unknown1.clientSalt).toBe(unknown2.clientSalt);
    expect(unknown1.clientSalt).toHaveLength(known.clientSalt.length);
    expect(unknown1.nonce).not.toBe(unknown2.nonce);
    expect(known.clientSalt).toBe(toB64(acct.clientSalt));
  });

  it('wrong password and unknown user produce identical status and body', async () => {
    const acct = await register(h);
    const wrong = await login(h, acct, undefined, randomBytes(32));
    const unknown = await login(h, { ...acct, username: 'QuietOtter' });
    expect(wrong.status).toBe(401);
    expect(unknown.status).toBe(401);
    expect(unknown.json).toEqual(wrong.json);
  });

  it('accepts the username case-insensitively and returns the canonical form', async () => {
    const acct = await register(h);
    const r = await login(h, { ...acct, username: acct.username.toLowerCase() });
    expect(r.status).toBe(200);
    expect(r.json.username).toBe(acct.username);
  });

  it('login nonces are single-use and expire', async () => {
    const acct = await register(h);
    const pre = await prelogin(h, acct.username);
    const body = { username: acct.username, authKey: toB64(acct.authKey), nonce: pre.nonce };
    expect((await h.call('POST', '/v1/auth/login', { body })).status).toBe(200);
    expect((await h.call('POST', '/v1/auth/login', { body })).status).toBe(401);
    const pre2 = await prelogin(h, acct.username);
    h.clock.t += 5 * 60 * 1000;
    expect((await h.call('POST', '/v1/auth/login', { body: { ...body, nonce: pre2.nonce } })).status).toBe(401);
  });
});

describe('sessions', () => {
  it('rotates refresh tokens and revokes the session when an old one is reused', async () => {
    const acct = await register(h);
    const r1 = await h.call('POST', '/v1/auth/refresh', { body: { refreshToken: acct.refreshToken } });
    expect(r1.status).toBe(200);
    expect(r1.json.refreshToken).not.toBe(acct.refreshToken);
    // Old access token is invalidated by the generation bump.
    expect((await h.call('GET', '/v1/account', { token: acct.token })).status).toBe(401);
    expect((await h.call('GET', '/v1/account', { token: r1.json.accessToken })).status).toBe(200);
    // Reuse of the rotated-out token: theft assumed, session killed.
    const reuse = await h.call('POST', '/v1/auth/refresh', { body: { refreshToken: acct.refreshToken } });
    expect(reuse.status).toBe(401);
    expect((await h.call('GET', '/v1/account', { token: r1.json.accessToken })).status).toBe(401);
    expect((await h.call('POST', '/v1/auth/refresh', { body: { refreshToken: r1.json.refreshToken } })).status).toBe(401);
  });

  it('access tokens expire after their TTL and sessions after their absolute lifetime', async () => {
    const acct = await register(h);
    h.clock.t += 601 * 1000;
    expect((await h.call('GET', '/v1/account', { token: acct.token })).status).toBe(401);
    const fresh = await h.call('POST', '/v1/auth/refresh', { body: { refreshToken: acct.refreshToken } });
    expect(fresh.status).toBe(200);
    h.clock.t += 31 * DAY_MS;
    expect((await h.call('POST', '/v1/auth/refresh', { body: { refreshToken: fresh.json.refreshToken } })).status).toBe(401);
    await h.server.sweep();
    expect(Number((await h.db.query<{ n: number }>('SELECT count(*)::int AS n FROM auth.sessions')).rows[0]!.n)).toBe(0);
  });

  it('revoking a session takes effect immediately; logout ends the current session', async () => {
    const acct = await register(h);
    const link = await login(h, acct);
    const list = await h.call('GET', '/v1/sessions', { token: acct.token });
    expect(list.json.sessions).toHaveLength(2);
    const other = list.json.sessions.find((s: { current: boolean }) => !s.current);
    expect((await h.call('DELETE', `/v1/sessions/${other.sessionId}`, { token: acct.token })).status).toBe(204);
    expect((await h.call('GET', '/v1/account', { token: link.json.accessToken })).status).toBe(401);
    expect((await h.call('POST', '/v1/auth/logout', { token: acct.token })).status).toBe(204);
    expect((await h.call('GET', '/v1/account', { token: acct.token })).status).toBe(401);
    expect((await h.call('POST', '/v1/auth/refresh', { body: { refreshToken: acct.refreshToken } })).status).toBe(401);
  });

  it('password change requires the current key, rotates the verifier and revokes all other sessions', async () => {
    const acct = await register(h);
    const link = await login(h, acct);
    const newKey = randomBytes(32);
    const body = { currentAuthKey: toB64(randomBytes(32)), newClientSalt: toB64(randomBytes(16)), newKdf: { memoryKiB: 64, iterations: 1, parallelism: 1 }, newAuthKey: toB64(newKey) };
    expect((await h.call('POST', '/v1/auth/password', { token: acct.token, body })).status).toBe(401);
    const ok = await h.call('POST', '/v1/auth/password', { token: acct.token, body: { ...body, currentAuthKey: toB64(acct.authKey) } });
    expect(ok.status).toBe(200);
    expect((await h.call('GET', '/v1/account', { token: link.json.accessToken })).status).toBe(401);
    expect((await h.call('GET', '/v1/account', { token: ok.json.accessToken })).status).toBe(200);
    expect((await login(h, acct)).status).toBe(401);
    expect((await login(h, { ...acct, authKey: newKey })).status).toBe(200);
  });
});

describe('recovery', () => {
  it('recovers with the recovery key only: new password, all sessions revoked, link session + backup returned', async () => {
    const acct = await register(h, { recovery: true });
    const newKey = randomBytes(32);
    const base = { username: acct.username, newClientSalt: toB64(randomBytes(16)), newKdf: { memoryKiB: 64, iterations: 1, parallelism: 1 }, newAuthKey: toB64(newKey) };
    const bad = await h.call('POST', '/v1/auth/recover', { body: { ...base, recoveryKey: toB64(randomBytes(32)) } });
    expect(bad.status).toBe(401);
    const unknown = await h.call('POST', '/v1/auth/recover', { body: { ...base, username: 'QuietOtter', recoveryKey: toB64(randomBytes(32)) } });
    expect(unknown.json).toEqual(bad.json);
    const ok = await h.call('POST', '/v1/auth/recover', { body: { ...base, recoveryKey: toB64(acct.recoveryKey!) } });
    expect(ok.status).toBe(200);
    expect(ok.json.session.kind).toBe('link');
    expect(ok.json.backup.length).toBeGreaterThan(10);
    expect((await h.call('GET', '/v1/account', { token: acct.token })).status).toBe(401);
    expect((await login(h, { ...acct, authKey: newKey })).status).toBe(200);
  });

  it('manages the recovery blob', async () => {
    const acct = await register(h);
    expect((await h.call('GET', '/v1/recovery/backup', { token: acct.token })).status).toBe(404);
    const blob = toB64(randomBytes(80));
    expect((await h.call('PUT', '/v1/recovery', { token: acct.token, body: { verifierKey: toB64(randomBytes(32)), backup: blob } })).status).toBe(204);
    expect((await h.call('GET', '/v1/recovery/backup', { token: acct.token })).json.backup).toBe(blob);
    const blob2 = toB64(randomBytes(90));
    expect((await h.call('PUT', '/v1/recovery/backup', { token: acct.token, body: { backup: blob2 } })).status).toBe(204);
    const link = await login(h, acct);
    expect((await h.call('GET', '/v1/recovery/backup', { token: link.json.accessToken })).json.backup).toBe(blob2);
    expect((await h.call('DELETE', '/v1/recovery', { token: acct.token })).status).toBe(204);
    expect((await h.call('GET', '/v1/account', { token: acct.token })).json.recoveryEnabled).toBe(false);
  });
});

describe('rate limiting', () => {
  it('backs off logins per username identically for existing and unknown usernames, with Retry-After', async () => {
    await h.close();
    h = await startHarness({ config: { rateLimit: { enabled: true } } });
    const acct = await register(h);
    const statuses = async (username: string) => {
      const out: number[] = [];
      for (let i = 0; i < 7; i++) out.push((await login(h, { ...acct, username }, undefined, randomBytes(32))).status);
      return out;
    };
    const known = await statuses(acct.username);
    const unknown = await statuses('QuietOtter');
    expect(known).toEqual(unknown);
    expect(known.slice(0, 5)).toEqual([401, 401, 401, 401, 401]);
    expect(known[6]).toBe(429);
    const blocked = await login(h, acct);
    expect(blocked.status).toBe(429);
    expect(Number(blocked.headers['retry-after'])).toBeGreaterThan(0);
    h.clock.t += 20 * 60 * 1000;
    expect((await login(h, acct)).status).toBe(200);
  });

  it('limits registrations per (hashed, in-memory) client address', async () => {
    await h.close();
    h = await startHarness({ config: { rateLimit: { enabled: true } } });
    const results: number[] = [];
    for (let i = 0; i < 6; i++) {
      const r = await buildRegistration(h);
      results.push((await h.call('POST', '/v1/auth/register', { body: r.body })).status);
    }
    expect(results.slice(0, 5)).toEqual([201, 201, 201, 201, 201]);
    expect(results[5]).toBe(429);
  });
});
