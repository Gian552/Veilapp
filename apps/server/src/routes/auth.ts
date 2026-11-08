// Authentication: registration (PoW + signed username reservation), prelogin
// (enumeration-resistant salt lookup), login (password + optional device proof),
// refresh rotation with reuse detection, logout, password change, recovery.

import { randomInt } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import {
  argon2ParamsAtLeast,
  checkProofOfWork,
  constantTimeEqual,
  fromB64,
  toB64,
  utf8,
  verifyDeviceList,
  verifyDeviceLogin,
  verifySignedPreKey,
} from '@veil/crypto';
import {
  ADJECTIVES,
  ChangePasswordRequest,
  type ChallengeResponse,
  LoginRequest,
  NOUNS,
  PreloginRequest,
  type PreloginResponse,
  RecoverRequest,
  type RecoverResponse,
  RefreshRequest,
  RegisterRequest,
  type UsernameSuggestion,
  isValidUsername,
} from '@veil/shared';
import {
  type Ctx,
  createSession,
  isUniqueViolation,
  limitByAddress,
  nowSeconds,
  requireDevice,
  requireSession,
  rotateSession,
  sessionResponse,
  today,
} from '../context.js';
import { Errors, parse } from '../errors.js';
import {
  fakeClientSalt,
  issueExpiring,
  issueReservation,
  parseRefreshToken,
  readExpiring,
  readReservation,
  retiredUsernameTag,
} from '../tokens.js';

const RESERVATION_TTL_S = 30 * 60;
const CHALLENGE_TTL_S = 5 * 60;
const NONCE_TTL_S = 120;

interface CredentialRow {
  account_id: string;
  username: string;
  client_salt: Uint8Array;
  kdf_memory: number;
  kdf_iterations: number;
  kdf_parallelism: number;
  verifier: string;
}

async function findCredentials(ctx: Ctx, username: string): Promise<CredentialRow | null> {
  if (!/^[A-Za-z]{6,18}$/.test(username)) return null;
  const r = await ctx.db.query<CredentialRow>(
    `SELECT a.id AS account_id, a.username, c.client_salt, c.kdf_memory, c.kdf_iterations, c.kdf_parallelism, c.verifier
     FROM identity.accounts a JOIN auth.credentials c ON c.account_id = a.id
     WHERE lower(a.username) = lower($1)`,
    [username],
  );
  return r.rows[0] ?? null;
}

function usernameGate(ctx: Ctx, username: string): string {
  const tag = ctx.limiter.tag('user', username.toLowerCase());
  const wait = ctx.limiter.loginBlockedFor(tag);
  if (wait > 0) throw Errors.rateLimited(wait);
  return tag;
}

export async function generateUsername(ctx: Ctx): Promise<string> {
  for (let attempt = 0; attempt < 32; attempt++) {
    const name = ADJECTIVES[randomInt(ADJECTIVES.length)]! + NOUNS[randomInt(NOUNS.length)]!;
    const taken = await ctx.db.query(
      `SELECT 1 FROM identity.accounts WHERE lower(username) = lower($1)
       UNION ALL SELECT 1 FROM identity.retired_usernames WHERE tag = $2`,
      [name, retiredUsernameTag(ctx.keys, name)],
    );
    if (taken.rowCount === 0) return name;
  }
  throw Errors.conflict('No username available, try again.');
}

export function registerAuthRoutes(app: FastifyInstance, ctx: Ctx): void {
  app.post('/v1/auth/challenge', async (req): Promise<ChallengeResponse> => {
    limitByAddress(req, ctx, 'auth');
    const difficulty = ctx.config.powDifficulty;
    const challenge = issueExpiring('c1', ctx.keys.pow, nowSeconds(ctx) + CHALLENGE_TTL_S, new Uint8Array([difficulty]));
    return { challenge, difficulty };
  });

  app.post('/v1/auth/username', async (req): Promise<UsernameSuggestion> => {
    limitByAddress(req, ctx, 'auth');
    const username = await generateUsername(ctx);
    return { username, reservation: issueReservation(ctx.keys, username, nowSeconds(ctx) + RESERVATION_TTL_S) };
  });

  app.post('/v1/auth/register', async (req, reply) => {
    limitByAddress(req, ctx, 'register');
    const body = parse(RegisterRequest, req.body);

    const username = readReservation(ctx.keys, body.reservation, nowSeconds(ctx));
    if (!username || !isValidUsername(username)) throw Errors.badRequest();

    const challenge = readExpiring('c1', ctx.keys.pow, body.pow.challenge, nowSeconds(ctx));
    const difficulty = challenge?.extra[0] ?? -1;
    if (!challenge || difficulty < ctx.config.powDifficulty) throw Errors.badRequest();
    if (!checkProofOfWork(utf8(body.pow.challenge), body.pow.nonce, difficulty)) throw Errors.badRequest();
    if (!ctx.usedChallenges.add(body.pow.challenge, challenge.exp * 1000)) throw Errors.badRequest();

    if (!argon2ParamsAtLeast(body.kdf, ctx.config.minimumKdf)) throw Errors.badRequest();

    const identityKey = fromB64(body.identityKey);
    const deviceId = fromB64(body.device.deviceId);
    const signingKey = fromB64(body.device.signingKey);
    const dhKey = fromB64(body.device.dhKey);
    let list;
    try {
      list = verifyDeviceList({ body: fromB64(body.deviceList.body), signature: fromB64(body.deviceList.signature) }, identityKey);
    } catch {
      throw Errors.badRequest();
    }
    const only = list.devices[0];
    if (
      list.devices.length !== 1 ||
      !only!.primary ||
      !constantTimeEqual(only!.deviceId, deviceId) ||
      !constantTimeEqual(only!.signingKey, signingKey) ||
      !constantTimeEqual(only!.dhKey, dhKey)
    ) {
      throw Errors.badRequest();
    }
    const spk = body.signedPreKey;
    if (!verifySignedPreKey(signingKey, deviceId, spk.keyId, fromB64(spk.publicKey), fromB64(spk.signature))) throw Errors.badRequest();
    if (new Set(body.oneTimePreKeys.map((k) => k.keyId)).size !== body.oneTimePreKeys.length) throw Errors.badRequest();

    const verifier = await ctx.passwords.hash(fromB64(body.authKey));
    const recoveryVerifier = body.recovery ? await ctx.passwords.hash(fromB64(body.recovery.verifierKey)) : null;
    const accountId = crypto.randomUUID();

    try {
      const out = await ctx.db.transaction(async (tx) => {
        const retired = await tx.query('SELECT 1 FROM identity.retired_usernames WHERE tag = $1', [retiredUsernameTag(ctx.keys, username)]);
        if (retired.rowCount > 0) throw Errors.conflict('Username unavailable.');
        await tx.query(
          `INSERT INTO identity.accounts (id, username, identity_key, device_list, device_list_sig, device_list_version, profile)
           VALUES ($1, $2, $3, $4, $5, $6, NULL)`,
          [accountId, username, identityKey, fromB64(body.deviceList.body), fromB64(body.deviceList.signature), list.version],
        );
        await tx.query(
          `INSERT INTO auth.credentials (account_id, client_salt, kdf_memory, kdf_iterations, kdf_parallelism, verifier)
           VALUES ($1, $2, $3, $4, $5, $6)`,
          [accountId, fromB64(body.clientSalt), body.kdf.memoryKiB, body.kdf.iterations, body.kdf.parallelism, verifier],
        );
        await tx.query('INSERT INTO keys.devices (id, account_id, signing_key, dh_key) VALUES ($1, $2, $3, $4)', [
          deviceId,
          accountId,
          signingKey,
          dhKey,
        ]);
        await tx.query('INSERT INTO keys.signed_prekeys (device_id, key_id, public_key, signature) VALUES ($1, $2, $3, $4)', [
          deviceId,
          spk.keyId,
          fromB64(spk.publicKey),
          fromB64(spk.signature),
        ]);
        for (const k of body.oneTimePreKeys) {
          await tx.query('INSERT INTO keys.one_time_prekeys (device_id, key_id, public_key) VALUES ($1, $2, $3)', [
            deviceId,
            k.keyId,
            fromB64(k.publicKey),
          ]);
        }
        if (body.recovery && recoveryVerifier) {
          await tx.query('INSERT INTO auth.recovery (account_id, verifier, backup) VALUES ($1, $2, $3)', [
            accountId,
            recoveryVerifier,
            fromB64(body.recovery.backup),
          ]);
        }
        return createSession(tx, ctx, accountId, deviceId);
      });
      reply.code(201);
      return sessionResponse(ctx, out, username, deviceId);
    } catch (e) {
      if (isUniqueViolation(e)) throw Errors.conflict('Username or device already registered.');
      throw e;
    }
  });

  app.post('/v1/auth/prelogin', async (req): Promise<PreloginResponse> => {
    limitByAddress(req, ctx, 'auth');
    const { username } = parse(PreloginRequest, req.body);
    const cred = await findCredentials(ctx, username);
    const nonce = issueExpiring('n1', ctx.keys.loginNonce, nowSeconds(ctx) + NONCE_TTL_S);
    if (cred) {
      return {
        clientSalt: toB64(cred.client_salt),
        kdf: { memoryKiB: Number(cred.kdf_memory), iterations: Number(cred.kdf_iterations), parallelism: Number(cred.kdf_parallelism) },
        nonce,
      };
    }
    // Deterministic per username, so repeated probing sees a stable "account".
    return { clientSalt: toB64(fakeClientSalt(ctx.keys, username)), kdf: { ...ctx.config.recommendedKdf }, nonce };
  });

  app.post('/v1/auth/login', async (req) => {
    limitByAddress(req, ctx, 'auth');
    const body = parse(LoginRequest, req.body);
    const tag = usernameGate(ctx, body.username);

    const nonce = readExpiring('n1', ctx.keys.loginNonce, body.nonce, nowSeconds(ctx));
    const cred = await findCredentials(ctx, body.username);
    const passwordOk = await ctx.passwords.verify(cred?.verifier ?? null, fromB64(body.authKey));
    let deviceId: Uint8Array | null = null;
    let ok = passwordOk && !!nonce && !!cred;
    if (ok && body.device) {
      const d = await ctx.db.query<{ signing_key: Uint8Array }>('SELECT signing_key FROM keys.devices WHERE id = $1 AND account_id = $2', [
        fromB64(body.device.deviceId),
        cred!.account_id,
      ]);
      const row = d.rows[0];
      ok = !!row && verifyDeviceLogin(row.signing_key, body.nonce, body.username, fromB64(body.device.signature));
      deviceId = ok ? fromB64(body.device.deviceId) : null;
    }
    if (ok && !ctx.usedNonces.add(body.nonce, nonce!.exp * 1000)) ok = false;
    if (!ok) {
      ctx.limiter.loginFailed(tag);
      throw Errors.invalidCredentials();
    }
    ctx.limiter.loginSucceeded(tag);
    const out = await ctx.db.transaction((tx) => createSession(tx, ctx, cred!.account_id, deviceId));
    ctx.hub.revokeSessions(out.replaced);
    return sessionResponse(ctx, out, cred!.username, deviceId);
  });

  app.post('/v1/auth/refresh', async (req) => {
    limitByAddress(req, ctx, 'auth');
    const { refreshToken } = parse(RefreshRequest, req.body);
    const parsed = parseRefreshToken(refreshToken);
    if (!parsed) throw Errors.unauthorized();
    const outcome = await ctx.db.transaction(async (tx) => {
      const r = await tx.query<{ refresh_hash: Uint8Array; prev_refresh_hash: Uint8Array | null; expires_day: number; device_id: Uint8Array | null; username: string }>(
        `SELECT s.refresh_hash, s.prev_refresh_hash, s.expires_day, s.device_id, a.username
         FROM auth.sessions s JOIN identity.accounts a ON a.id = s.account_id WHERE s.id = $1 FOR UPDATE OF s`,
        [parsed.sessionId],
      );
      const row = r.rows[0];
      if (!row || Number(row.expires_day) < today(ctx)) return 'invalid' as const;
      if (!constantTimeEqual(row.refresh_hash, parsed.hash)) {
        if (row.prev_refresh_hash && constantTimeEqual(row.prev_refresh_hash, parsed.hash)) {
          // A rotated-out token was presented again: assume theft and kill the session.
          await tx.query('DELETE FROM auth.sessions WHERE id = $1', [parsed.sessionId]);
          return 'reused' as const;
        }
        return 'invalid' as const;
      }
      const tokens = await rotateSession(tx, ctx, parsed.sessionId, parsed.hash);
      return sessionResponse(ctx, tokens, row.username, row.device_id);
    });
    if (outcome === 'reused') ctx.hub.revokeSessions([parsed.sessionId]);
    if (typeof outcome === 'string') throw Errors.unauthorized();
    return outcome;
  });

  app.post('/v1/auth/logout', async (req, reply) => {
    const s = await requireSession(req, ctx);
    await ctx.db.query('DELETE FROM auth.sessions WHERE id = $1', [s.sessionId]);
    ctx.hub.revokeSessions([s.sessionId]);
    reply.code(204);
  });

  app.post('/v1/auth/password', async (req) => {
    const s = await requireDevice(req, ctx);
    const body = parse(ChangePasswordRequest, req.body);
    if (!argon2ParamsAtLeast(body.newKdf, ctx.config.minimumKdf)) throw Errors.badRequest();
    const cur = await ctx.db.query<{ verifier: string; username: string }>(
      'SELECT c.verifier, a.username FROM auth.credentials c JOIN identity.accounts a ON a.id = c.account_id WHERE c.account_id = $1',
      [s.accountId],
    );
    const row = cur.rows[0];
    const tag = usernameGate(ctx, row?.username ?? '');
    if (!row || !(await ctx.passwords.verify(row.verifier, fromB64(body.currentAuthKey)))) {
      ctx.limiter.loginFailed(tag);
      throw Errors.invalidCredentials();
    }
    const verifier = await ctx.passwords.hash(fromB64(body.newAuthKey));
    const { tokens, revoked } = await ctx.db.transaction(async (tx) => {
      await tx.query(
        `UPDATE auth.credentials SET client_salt = $2, kdf_memory = $3, kdf_iterations = $4, kdf_parallelism = $5, verifier = $6
         WHERE account_id = $1`,
        [s.accountId, fromB64(body.newClientSalt), body.newKdf.memoryKiB, body.newKdf.iterations, body.newKdf.parallelism, verifier],
      );
      const others = await tx.query<{ id: Uint8Array }>('DELETE FROM auth.sessions WHERE account_id = $1 AND id <> $2 RETURNING id', [
        s.accountId,
        s.sessionId,
      ]);
      return { tokens: await rotateSession(tx, ctx, s.sessionId, null), revoked: others.rows.map((r) => r.id) };
    });
    ctx.hub.revokeSessions(revoked);
    return sessionResponse(ctx, tokens, row.username, s.deviceId);
  });

  app.post('/v1/auth/recover', async (req): Promise<RecoverResponse> => {
    limitByAddress(req, ctx, 'auth');
    const body = parse(RecoverRequest, req.body);
    const tag = usernameGate(ctx, body.username);
    const r = await ctx.db.query<{ account_id: string; username: string; verifier: string; backup: Uint8Array }>(
      `SELECT a.id AS account_id, a.username, r.verifier, r.backup
       FROM identity.accounts a JOIN auth.recovery r ON r.account_id = a.id WHERE lower(a.username) = lower($1)`,
      [body.username],
    );
    const row = r.rows[0] ?? null;
    const ok = await ctx.passwords.verify(row?.verifier ?? null, fromB64(body.recoveryKey));
    if (!ok || !row) {
      ctx.limiter.loginFailed(tag);
      throw Errors.invalidCredentials();
    }
    if (!argon2ParamsAtLeast(body.newKdf, ctx.config.minimumKdf)) throw Errors.badRequest();
    ctx.limiter.loginSucceeded(tag);
    const verifier = await ctx.passwords.hash(fromB64(body.newAuthKey));
    const { session, revoked } = await ctx.db.transaction(async (tx) => {
      await tx.query(
        `UPDATE auth.credentials SET client_salt = $2, kdf_memory = $3, kdf_iterations = $4, kdf_parallelism = $5, verifier = $6
         WHERE account_id = $1`,
        [row.account_id, fromB64(body.newClientSalt), body.newKdf.memoryKiB, body.newKdf.iterations, body.newKdf.parallelism, verifier],
      );
      const old = await tx.query<{ id: Uint8Array }>('DELETE FROM auth.sessions WHERE account_id = $1 RETURNING id', [row.account_id]);
      return { session: await createSession(tx, ctx, row.account_id, null), revoked: old.rows.map((x) => x.id) };
    });
    ctx.hub.revokeSessions(revoked);
    return { session: sessionResponse(ctx, session, row.username, null), backup: toB64(row.backup) };
  });
}
