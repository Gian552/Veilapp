// In-memory abuse prevention that does not require tracking anyone durably.
//
//  - Client addresses are never stored: buckets are keyed by HMAC(ephemeralKey, ip)
//    where the key lives only in memory and is replaced every 24 h (all buckets
//    are dropped at the same time).
//  - Login back-off is keyed by HMAC(ephemeralKey, lower(username)) and applies
//    identically to existing and non-existing usernames (no enumeration signal).
//  - Nothing here is persisted; a restart forgets everything. In multi-instance
//    deployments limits are per instance (documented in DEPLOYMENT.md).

import { hmacSha256, randomBytes, toB64, utf8 } from '@veil/crypto';

export interface BucketSpec {
  capacity: number;
  refillPerSecond: number;
}

export const LIMITS = {
  global: { capacity: 600, refillPerSecond: 10 },
  auth: { capacity: 30, refillPerSecond: 0.5 },
  register: { capacity: 5, refillPerSecond: 5 / 3600 },
  bundles: { capacity: 120, refillPerSecond: 120 / 3600 },
  directory: { capacity: 300, refillPerSecond: 300 / 3600 },
  send: { capacity: 600, refillPerSecond: 10 },
  upload: { capacity: 60, refillPerSecond: 60 / 3600 },
  linkRequests: { capacity: 10, refillPerSecond: 10 / 3600 },
} satisfies Record<string, BucketSpec>;

export type LimitName = keyof typeof LIMITS;

const ROTATE_MS = 24 * 3600 * 1000;
const LOGIN_FREE_FAILURES = 5;
const LOGIN_MAX_BACKOFF_S = 15 * 60;

export class RateLimiter {
  private key = randomBytes(32);
  private keyBorn: number;
  private buckets = new Map<string, { tokens: number; last: number }>();
  private failures = new Map<string, { count: number; until: number; last: number }>();

  constructor(
    private readonly now: () => number,
    readonly enabled: boolean,
  ) {
    this.keyBorn = now();
  }

  private rotate(): void {
    const t = this.now();
    if (t - this.keyBorn < ROTATE_MS) return;
    this.key.fill(0);
    this.key = randomBytes(32);
    this.keyBorn = t;
    this.buckets.clear();
    this.failures.clear();
  }

  /** Opaque, unlinkable-across-rotations tag; the raw value is never stored. */
  tag(kind: string, value: string): string {
    this.rotate();
    return toB64(hmacSha256(this.key, utf8(`${kind}:${value}`)));
  }

  /** Returns 0 if allowed, else the number of seconds to wait. */
  take(limit: LimitName, subject: string, cost = 1): number {
    if (!this.enabled) return 0;
    const spec = LIMITS[limit];
    const key = `${limit}:${subject}`;
    const t = this.now() / 1000;
    const b = this.buckets.get(key) ?? { tokens: spec.capacity, last: t };
    b.tokens = Math.min(spec.capacity, b.tokens + (t - b.last) * spec.refillPerSecond);
    b.last = t;
    if (b.tokens < cost) {
      this.buckets.set(key, b);
      return Math.max(1, Math.ceil((cost - b.tokens) / spec.refillPerSecond));
    }
    b.tokens -= cost;
    this.buckets.set(key, b);
    if (this.buckets.size > 100_000) this.prune();
    return 0;
  }

  /** Seconds the given username tag must still wait before another login attempt. */
  loginBlockedFor(usernameTag: string): number {
    if (!this.enabled) return 0;
    const f = this.failures.get(usernameTag);
    if (!f) return 0;
    const wait = Math.ceil((f.until - this.now()) / 1000);
    return wait > 0 ? wait : 0;
  }

  loginFailed(usernameTag: string): void {
    if (!this.enabled) return;
    const f = this.failures.get(usernameTag) ?? { count: 0, until: 0, last: 0 };
    f.count += 1;
    f.last = this.now();
    if (f.count >= LOGIN_FREE_FAILURES) {
      const backoff = Math.min(LOGIN_MAX_BACKOFF_S, 2 ** (f.count - LOGIN_FREE_FAILURES));
      f.until = this.now() + backoff * 1000;
    }
    this.failures.set(usernameTag, f);
  }

  loginSucceeded(usernameTag: string): void {
    this.failures.delete(usernameTag);
  }

  private prune(): void {
    const t = this.now() / 1000;
    for (const [k, b] of this.buckets) if (t - b.last > 3600) this.buckets.delete(k);
    for (const [k, f] of this.failures) if (this.now() - f.last > LOGIN_MAX_BACKOFF_S * 2000) this.failures.delete(k);
  }
}

/** Set of single-use values that forget themselves after expiry (PoW challenges, login nonces). */
export class ExpiringSet {
  private items = new Map<string, number>();

  constructor(private readonly now: () => number) {}

  /** Adds `value`; returns false if it was already present (i.e. a replay). */
  add(value: string, expMs: number): boolean {
    const t = this.now();
    if (this.items.size > 10_000) for (const [k, e] of this.items) if (e <= t) this.items.delete(k);
    const existing = this.items.get(value);
    if (existing !== undefined && existing > t) return false;
    this.items.set(value, expMs);
    return true;
  }
}
