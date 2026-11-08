// Server-side MAC keys and stateless tokens (docs/ARCHITECTURE.md §3).
//
// Every purpose has its own HKDF-derived key, so a token of one kind can never
// be accepted as another. Token layout: `<prefix>.<b64 payload>.<b64 HMAC>`
// where the HMAC covers `<prefix>.<b64 payload>`.

import {
  type Bytes,
  Reader,
  Writer,
  concat,
  constantTimeEqual,
  fromB64,
  hkdf,
  hmacSha256,
  randomBytes,
  sha256,
  toB64,
  utf8,
} from '@veil/crypto';

export interface ServerKeys {
  accessToken: Bytes;
  fakeSalt: Bytes;
  loginNonce: Bytes;
  pow: Bytes;
  reservation: Bytes;
  ledger: Bytes;
  retiredUsername: Bytes;
  decoy: Bytes;
}

export function deriveServerKeys(secret: Bytes): ServerKeys {
  const k = (label: string) => hkdf(secret, undefined, `veil-server/v1/${label}`, 32);
  return {
    accessToken: k('access-token'),
    fakeSalt: k('prelogin-fake-salt'),
    loginNonce: k('login-nonce'),
    pow: k('pow-challenge'),
    reservation: k('username-reservation'),
    ledger: k('deletion-ledger'),
    retiredUsername: k('retired-username'),
    decoy: k('decoy-accounts'),
  };
}

function mac(key: Bytes, signed: string): string {
  return toB64(hmacSha256(key, utf8(signed)));
}

export function makeToken(prefix: string, key: Bytes, payload: Bytes): string {
  const signed = `${prefix}.${toB64(payload)}`;
  return `${signed}.${mac(key, signed)}`;
}

/** Returns the payload if the token has the prefix and a valid MAC, else null. */
export function readToken(prefix: string, key: Bytes, token: string): Bytes | null {
  if (typeof token !== 'string' || token.length > 1024) return null;
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== prefix) return null;
  try {
    const expected = fromB64(mac(key, `${parts[0]}.${parts[1]}`));
    const given = fromB64(parts[2]!);
    if (!constantTimeEqual(expected, given)) return null;
    return fromB64(parts[1]!);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------- access tokens

export interface AccessClaims {
  sessionId: Bytes;
  generation: number;
  exp: number; // unix seconds
}

export function issueAccessToken(keys: ServerKeys, claims: AccessClaims): string {
  return makeToken('va1', keys.accessToken, new Writer().fixed(claims.sessionId, 16).u32(claims.generation).u32(claims.exp).finish());
}

export function verifyAccessToken(keys: ServerKeys, token: string, nowSeconds: number): AccessClaims | null {
  const payload = readToken('va1', keys.accessToken, token);
  if (!payload) return null;
  try {
    const r = new Reader(payload);
    const claims = { sessionId: r.fixed(16), generation: r.u32(), exp: r.u32() };
    r.end();
    return claims.exp > nowSeconds ? claims : null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------- refresh tokens

export function issueRefreshToken(sessionId: Bytes): { token: string; hash: Bytes } {
  const secret = randomBytes(32);
  return { token: `vr1.${toB64(sessionId)}.${toB64(secret)}`, hash: sha256(secret) };
}

export function parseRefreshToken(token: string): { sessionId: Bytes; hash: Bytes } | null {
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== 'vr1') return null;
  try {
    const sessionId = fromB64(parts[1]!);
    const secret = fromB64(parts[2]!);
    if (sessionId.length !== 16 || secret.length !== 32) return null;
    return { sessionId, hash: sha256(secret) };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------- short-lived challenges

/** Random nonce with expiry; used for login (device proof) and as PoW challenge. */
export function issueExpiring(prefix: string, key: Bytes, expSeconds: number, extra: Bytes = new Uint8Array(0)): string {
  return makeToken(prefix, key, concat(randomBytes(16), new Writer().u32(expSeconds).finish(), extra));
}

export function readExpiring(prefix: string, key: Bytes, token: string, nowSeconds: number): { exp: number; extra: Bytes } | null {
  const payload = readToken(prefix, key, token);
  if (!payload || payload.length < 20) return null;
  const exp = new Reader(payload.subarray(16, 20)).u32();
  if (exp <= nowSeconds) return null;
  return { exp, extra: payload.slice(20) };
}

export function issueReservation(keys: ServerKeys, username: string, expSeconds: number): string {
  return makeToken('r1', keys.reservation, new Writer().u32(expSeconds).string(username).finish());
}

export function readReservation(keys: ServerKeys, token: string, nowSeconds: number): string | null {
  const payload = readToken('r1', keys.reservation, token);
  if (!payload) return null;
  try {
    const r = new Reader(payload);
    const exp = r.u32();
    const username = r.string(64);
    r.end();
    return exp > nowSeconds ? username : null;
  } catch {
    return null;
  }
}

export function fakeClientSalt(keys: ServerKeys, username: string): Bytes {
  return hmacSha256(keys.fakeSalt, utf8(username.toLowerCase())).slice(0, 16);
}

export function retiredUsernameTag(keys: ServerKeys, username: string): Bytes {
  return hmacSha256(keys.retiredUsername, utf8(username.toLowerCase()));
}

export function ledgerAccountTag(keys: ServerKeys, accountId: string): Bytes {
  return hmacSha256(keys.ledger, utf8(accountId));
}
