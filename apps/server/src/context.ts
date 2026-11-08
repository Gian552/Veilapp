// Shared request-handling context: dependencies, clock helpers, password
// hashing and session management.

import { hash as argonHash, verify as argonVerify, type Algorithm } from '@node-rs/argon2';
import type { FastifyRequest } from 'fastify';
import { type Bytes, randomBytes, toB64 } from '@veil/crypto';
import type { SessionResponse } from '@veil/shared';
import type { BlobStore } from './blobstore.js';
import type { ServerConfig } from './config.js';
import type { Db } from './db.js';
import { ApiError, Errors } from './errors.js';
import type { Hub } from './hub.js';
import { type ExpiringSet, type LimitName, RateLimiter } from './ratelimit.js';
import { type ServerKeys, issueAccessToken, issueRefreshToken, verifyAccessToken } from './tokens.js';

export interface LogEntry {
  level: 'info' | 'warn' | 'error';
  /** Stable event name, e.g. "unhandled_error", "blob_delete_failed". */
  event: string;
  /** Route template (e.g. "/v1/messages"), never the concrete URL. */
  route?: string;
  /** Error class/code, never an error message that could embed request data. */
  code?: string;
}

export interface Ctx {
  db: Db;
  config: ServerConfig;
  keys: ServerKeys;
  blobs: BlobStore;
  hub: Hub;
  limiter: RateLimiter;
  usedChallenges: ExpiringSet;
  usedNonces: ExpiringSet;
  passwords: PasswordHasher;
  now(): number;
  log(e: LogEntry): void;
}

export const DAY_MS = 86_400_000;

export function today(ctx: Ctx): number {
  return Math.floor(ctx.now() / DAY_MS);
}

export function nowSeconds(ctx: Ctx): number {
  return Math.floor(ctx.now() / 1000);
}

// ---------------------------------------------------------------- password hashing

const ARGON2ID = 2 as Algorithm;

export class PasswordHasher {
  private dummy: Promise<string>;

  constructor(private readonly params: ServerConfig['serverArgon2']) {
    // A verifier for a random key nobody knows; checked against for unknown users
    // so that "no such user" costs the same as "wrong password".
    this.dummy = this.hash(randomBytes(32));
  }

  // @node-rs/argon2 decodes the password as UTF-8 during verify, so the 256-bit
  // key is passed in its (lossless, ASCII) base64url encoding.
  hash(secret: Bytes): Promise<string> {
    return argonHash(toB64(secret), {
      algorithm: ARGON2ID,
      memoryCost: this.params.memoryCost,
      timeCost: this.params.timeCost,
      parallelism: this.params.parallelism,
      outputLen: 32,
    });
  }

  async verify(verifier: string | null, secret: Bytes): Promise<boolean> {
    const target = verifier ?? (await this.dummy);
    let ok = false;
    try {
      ok = await argonVerify(target, toB64(secret));
    } catch {
      ok = false;
    }
    return verifier !== null && ok;
  }
}

// ---------------------------------------------------------------- rate limiting helpers

export function clientAddress(req: FastifyRequest, ctx: Ctx): string {
  // Used only to derive an in-memory HMAC tag; never stored or logged.
  return (ctx.config.trustProxy ? req.ip : req.socket.remoteAddress) ?? 'unknown';
}

export function limitByAddress(req: FastifyRequest, ctx: Ctx, limit: LimitName): void {
  if (!ctx.limiter.enabled) return;
  const wait = ctx.limiter.take(limit, ctx.limiter.tag('addr', clientAddress(req, ctx)));
  if (wait > 0) throw Errors.rateLimited(wait);
}

export function limitByAccount(ctx: Ctx, accountId: string, limit: LimitName): void {
  if (!ctx.limiter.enabled) return;
  const wait = ctx.limiter.take(limit, ctx.limiter.tag('acct', accountId));
  if (wait > 0) throw Errors.rateLimited(wait);
}

// ---------------------------------------------------------------- sessions

export interface AuthSession {
  sessionId: Bytes;
  accountId: string;
  deviceId: Bytes | null;
  kind: 'device' | 'link';
  generation: number;
}

interface SessionRow {
  id: Uint8Array;
  account_id: string;
  device_id: Uint8Array | null;
  kind: 'device' | 'link';
  generation: number;
  expires_day: number;
}

export async function authenticate(req: FastifyRequest, ctx: Ctx): Promise<AuthSession | null> {
  const header = req.headers.authorization;
  if (typeof header !== 'string' || !header.startsWith('Bearer ')) return null;
  return authenticateToken(header.slice(7).trim(), ctx);
}

export async function authenticateToken(token: string, ctx: Ctx): Promise<AuthSession | null> {
  const claims = verifyAccessToken(ctx.keys, token, nowSeconds(ctx));
  if (!claims) return null;
  const r = await ctx.db.query<SessionRow>(
    'SELECT id, account_id, device_id, kind, generation, expires_day FROM auth.sessions WHERE id = $1',
    [claims.sessionId],
  );
  const row = r.rows[0];
  if (!row || Number(row.generation) !== claims.generation || Number(row.expires_day) < today(ctx)) return null;
  return { sessionId: row.id, accountId: String(row.account_id), deviceId: row.device_id, kind: row.kind, generation: Number(row.generation) };
}

export async function requireSession(req: FastifyRequest, ctx: Ctx): Promise<AuthSession> {
  const s = await authenticate(req, ctx);
  if (!s) throw Errors.unauthorized();
  return s;
}

export async function requireDevice(req: FastifyRequest, ctx: Ctx): Promise<AuthSession & { deviceId: Bytes }> {
  const s = await requireSession(req, ctx);
  if (s.kind !== 'device' || !s.deviceId) throw Errors.forbidden('This action requires an enrolled device.');
  return s as AuthSession & { deviceId: Bytes };
}

export async function requireLink(req: FastifyRequest, ctx: Ctx): Promise<AuthSession> {
  const s = await requireSession(req, ctx);
  if (s.kind !== 'link') throw Errors.forbidden('This action is only available while enrolling a device.');
  return s;
}

/**
 * Creates a session. Device sessions replace any previous session of the same
 * device (one session per device). Must run inside the caller's transaction.
 */
export async function createSession(
  tx: Db,
  ctx: Ctx,
  accountId: string,
  deviceId: Bytes | null,
): Promise<{ sessionId: Bytes; refreshToken: string; accessToken: string; replaced: Bytes[] }> {
  const replaced: Bytes[] = [];
  if (deviceId) {
    const old = await tx.query<{ id: Uint8Array }>('DELETE FROM auth.sessions WHERE device_id = $1 RETURNING id', [deviceId]);
    for (const r of old.rows) replaced.push(r.id);
  }
  const sessionId = randomBytes(16);
  const refresh = issueRefreshToken(sessionId);
  const days = deviceId ? ctx.config.retention.sessionDays : ctx.config.retention.linkSessionDays;
  await tx.query(
    `INSERT INTO auth.sessions (id, account_id, device_id, kind, refresh_hash, prev_refresh_hash, generation, expires_day)
     VALUES ($1, $2, $3, $4, $5, NULL, 1, $6)`,
    [sessionId, accountId, deviceId, deviceId ? 'device' : 'link', refresh.hash, today(ctx) + days],
  );
  const accessToken = issueAccessToken(ctx.keys, { sessionId, generation: 1, exp: nowSeconds(ctx) + ctx.config.accessTokenTtlSeconds });
  return { sessionId, refreshToken: refresh.token, accessToken, replaced };
}

/** Rotates refresh token and generation of an existing session (invalidates older access tokens). */
export async function rotateSession(tx: Db, ctx: Ctx, sessionId: Bytes, currentHash: Bytes | null): Promise<{ accessToken: string; refreshToken: string }> {
  const refresh = issueRefreshToken(sessionId);
  const r = await tx.query<{ generation: number }>(
    `UPDATE auth.sessions SET refresh_hash = $2, prev_refresh_hash = COALESCE($3, refresh_hash), generation = generation + 1
     WHERE id = $1 RETURNING generation`,
    [sessionId, refresh.hash, currentHash],
  );
  if (r.rowCount === 0) throw Errors.unauthorized();
  const generation = Number(r.rows[0]!.generation);
  const accessToken = issueAccessToken(ctx.keys, { sessionId, generation, exp: nowSeconds(ctx) + ctx.config.accessTokenTtlSeconds });
  return { accessToken, refreshToken: refresh.token };
}

export function sessionResponse(
  ctx: Ctx,
  tokens: { accessToken: string; refreshToken: string },
  username: string,
  deviceId: Bytes | null,
): SessionResponse {
  return {
    accessToken: tokens.accessToken,
    refreshToken: tokens.refreshToken,
    accessExpiresIn: ctx.config.accessTokenTtlSeconds,
    kind: deviceId ? 'device' : 'link',
    username,
    deviceId: deviceId ? toB64(deviceId) : null,
  };
}

export function isUniqueViolation(e: unknown): boolean {
  return typeof e === 'object' && e !== null && (e as { code?: string }).code === '23505';
}

export { ApiError, RateLimiter };
