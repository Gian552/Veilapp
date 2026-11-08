// Server configuration. Defaults follow docs/ARCHITECTURE.md §8; every value
// can be overridden programmatically (tests) or via environment (production).

import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { CLIENT_ARGON2_DEFAULT, CLIENT_ARGON2_MINIMUM, type Argon2Params, fromB64, randomBytes } from '@veil/crypto';

export interface RetentionConfig {
  undeliveredMessageDays: number;
  attachmentDays: number;
  sessionDays: number;
  /** Absolute lifetime of password-only "link" sessions. */
  linkSessionDays: number;
  backupDays: number;
  resetJobDays: number;
}

export interface ServerConfig {
  /** ≥32 random bytes; every server MAC key is HKDF-derived from it with a distinct label. */
  serverSecret: Uint8Array;
  powDifficulty: number;
  minimumKdf: Argon2Params;
  recommendedKdf: Argon2Params;
  /** Server-side Argon2id applied to the client's authKey (OWASP baseline by default). */
  serverArgon2: { memoryCost: number; timeCost: number; parallelism: number };
  retention: RetentionConfig;
  accessTokenTtlSeconds: number;
  linkRequestTtlSeconds: number;
  trustProxy: boolean;
  webDist?: string | undefined;
  dataDir: string;
  rateLimit: { enabled: boolean };
  mailboxMaxPerDevice: number;
  attachmentMaxBytes: number;
  maxOneTimePreKeysPerDevice: number;
  maxPendingLinkRequests: number;
  host: string;
  port: number;
}

export function defaultConfig(): ServerConfig {
  return {
    serverSecret: randomBytes(32),
    powDifficulty: 18,
    minimumKdf: { ...CLIENT_ARGON2_MINIMUM },
    recommendedKdf: { ...CLIENT_ARGON2_DEFAULT },
    serverArgon2: { memoryCost: 19 * 1024, timeCost: 2, parallelism: 1 },
    retention: {
      undeliveredMessageDays: 30,
      attachmentDays: 30,
      sessionDays: 30,
      linkSessionDays: 1,
      backupDays: 7,
      resetJobDays: 7,
    },
    accessTokenTtlSeconds: 600,
    linkRequestTtlSeconds: 600,
    trustProxy: false,
    webDist: undefined,
    dataDir: resolve('.veil-data'),
    rateLimit: { enabled: true },
    mailboxMaxPerDevice: 5000,
    attachmentMaxBytes: 10 * 1024 * 1024 + 64,
    maxOneTimePreKeysPerDevice: 1000,
    maxPendingLinkRequests: 5,
    host: '127.0.0.1',
    port: 8787,
  };
}

export function mergeConfig(base: ServerConfig, patch: Partial<ServerConfig> = {}): ServerConfig {
  return {
    ...base,
    ...patch,
    retention: { ...base.retention, ...(patch.retention ?? {}) },
    rateLimit: { ...base.rateLimit, ...(patch.rateLimit ?? {}) },
    serverArgon2: { ...base.serverArgon2, ...(patch.serverArgon2 ?? {}) },
  };
}

function intEnv(env: NodeJS.ProcessEnv, name: string, fallback: number): number {
  const v = env[name];
  if (v === undefined || v === '') return fallback;
  const n = Number(v);
  if (!Number.isInteger(n) || n < 0) throw new Error(`${name} must be a non-negative integer`);
  return n;
}

export interface EnvConfig {
  config: ServerConfig;
  databaseUrl: string | undefined;
  /** True when VEIL_SERVER_SECRET was missing and an ephemeral one was generated. */
  ephemeralSecret: boolean;
}

export function loadConfigFromEnv(env: NodeJS.ProcessEnv = process.env): EnvConfig {
  const base = defaultConfig();
  const production = env.NODE_ENV === 'production';
  let ephemeralSecret = false;
  let serverSecret: Uint8Array;
  if (env.VEIL_SERVER_SECRET) {
    serverSecret = fromB64(env.VEIL_SERVER_SECRET.trim());
    if (serverSecret.length < 32) throw new Error('VEIL_SERVER_SECRET must decode to at least 32 bytes (base64url)');
  } else if (production) {
    throw new Error('VEIL_SERVER_SECRET is required when NODE_ENV=production');
  } else {
    serverSecret = randomBytes(32);
    ephemeralSecret = true;
  }
  // Development convenience only: production always enforces rate limits.
  const rateLimitOff = env.VEIL_RATE_LIMIT === 'off';
  if (rateLimitOff && production) throw new Error('VEIL_RATE_LIMIT=off is not allowed when NODE_ENV=production');
  const dataDir = resolve(env.VEIL_DATA_DIR || base.dataDir);
  let webDist = env.VEIL_WEB_DIST ? resolve(env.VEIL_WEB_DIST) : undefined;
  if (!webDist) {
    const guess = resolve('apps/web/dist');
    if (existsSync(resolve(guess, 'index.html'))) webDist = guess;
  }
  const config = mergeConfig(base, {
    serverSecret,
    dataDir,
    webDist,
    host: env.HOST || base.host,
    port: intEnv(env, 'PORT', base.port),
    trustProxy: env.VEIL_TRUST_PROXY === 'true',
    powDifficulty: intEnv(env, 'VEIL_POW_DIFFICULTY', base.powDifficulty),
    retention: { ...base.retention, backupDays: intEnv(env, 'VEIL_BACKUP_RETENTION_DAYS', base.retention.backupDays) },
    rateLimit: { enabled: !rateLimitOff },
  });
  return { config, databaseUrl: env.DATABASE_URL || undefined, ephemeralSecret };
}
