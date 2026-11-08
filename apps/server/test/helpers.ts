// Test harness: an in-memory server with a controllable clock, plus a tiny
// "client" that produces genuine key material with @veil/crypto.

import type { LightMyRequestResponse } from 'fastify';
import {
  type DeviceKeys,
  type KeyPair,
  deviceEntryFor,
  encodeLinkRequest,
  generateLinkSecret,
  generateAccountIdentity,
  generateDeviceKeys,
  generateOneTimePreKeys,
  generateSignedPreKey,
  randomBytes,
  signDeviceList,
  signDeviceLogin,
  solveProofOfWork,
  toB64,
  utf8,
  x25519KeyPair,
  type DeviceEntry,
} from '@veil/crypto';
import type { SessionResponse } from '@veil/shared';
import { type LogEntry, type ServerConfig, type VeilServer, MemoryBlobStore, createMemoryDb, createServer } from '../src/index.js';
import type { BlobStore } from '../src/blobstore.js';
import type { Db } from '../src/db.js';

export const TEST_KDF = { memoryKiB: 64, iterations: 1, parallelism: 1 };
export const START = Date.UTC(2026, 9, 24, 12, 0, 0);

export interface Harness {
  server: VeilServer;
  db: Db;
  clock: { t: number };
  logs: LogEntry[];
  blobs: BlobStore;
  call(method: string, url: string, opts?: { body?: unknown; token?: string; headers?: Record<string, string>; raw?: Buffer }): Promise<Res>;
  close(): Promise<void>;
}

export interface Res {
  status: number;
  json: any;
  headers: LightMyRequestResponse['headers'];
  raw: LightMyRequestResponse;
}

export async function startHarness(o: { config?: Partial<ServerConfig>; blobs?: BlobStore; db?: Db } = {}): Promise<Harness> {
  const clock = { t: START };
  const logs: LogEntry[] = [];
  const blobs = o.blobs ?? new MemoryBlobStore();
  const db = o.db ?? (await createMemoryDb());
  const server = await createServer({
    db,
    blobStore: blobs,
    now: () => clock.t,
    log: (e) => logs.push(e),
    sweepIntervalMs: 0,
    config: {
      serverSecret: randomBytes(32),
      powDifficulty: 4,
      minimumKdf: TEST_KDF,
      serverArgon2: { memoryCost: 256, timeCost: 1, parallelism: 1 },
      rateLimit: { enabled: false },
      ...o.config,
    },
  });
  const call: Harness['call'] = async (method, url, opts = {}) => {
    const headers: Record<string, string> = { ...(opts.headers ?? {}) };
    if (opts.token) headers.authorization = `Bearer ${opts.token}`;
    const raw = await server.app.inject({
      method: method as 'GET',
      url,
      headers,
      ...(opts.raw ? { payload: opts.raw } : opts.body !== undefined ? { payload: opts.body as object } : {}),
    });
    let json: any = null;
    try {
      json = raw.body ? JSON.parse(raw.body) : null;
    } catch {
      json = null;
    }
    return { status: raw.statusCode, json, headers: raw.headers, raw };
  };
  return { server, db, clock, logs, blobs, call, close: () => server.close() };
}

// ---------------------------------------------------------------- simulated client

export interface TestDevice {
  keys: DeviceKeys;
  primary: boolean;
  session: SessionResponse | null;
}

export interface TestAccount {
  username: string;
  authKey: Uint8Array;
  clientSalt: Uint8Array;
  aik: KeyPair;
  listVersion: number;
  devices: TestDevice[];
  recoveryKey: Uint8Array | null;
  /** Convenience: access token of the first device. */
  token: string;
  refreshToken: string;
}

export function signList(acct: { aik: KeyPair }, version: number, devices: DeviceEntry[]) {
  const s = signDeviceList(acct.aik.privateKey, { identityKey: acct.aik.publicKey, version, devices });
  return { body: toB64(s.body), signature: toB64(s.signature) };
}

export function publicDevice(d: DeviceKeys) {
  return { deviceId: toB64(d.deviceId), signingKey: toB64(d.signing.publicKey), dhKey: toB64(d.dh.publicKey) };
}

export function prekeysFor(d: DeviceKeys, otkStart = 1, otkCount = 5) {
  const spk = generateSignedPreKey(d, 1);
  return {
    signedPreKey: { keyId: spk.keyId, publicKey: toB64(spk.keyPair.publicKey), signature: toB64(spk.signature) },
    oneTimePreKeys: generateOneTimePreKeys(otkStart, otkCount).map((k) => ({ keyId: k.keyId, publicKey: toB64(k.keyPair.publicKey) })),
  };
}

export async function solveChallenge(h: Harness): Promise<{ challenge: string; nonce: number }> {
  const c = await h.call('POST', '/v1/auth/challenge');
  return { challenge: c.json.challenge, nonce: await solveProofOfWork(utf8(c.json.challenge), c.json.difficulty) };
}

export async function buildRegistration(h: Harness, opts: { recovery?: boolean; authKey?: Uint8Array; otkCount?: number } = {}) {
  const u = await h.call('POST', '/v1/auth/username');
  const aik = generateAccountIdentity();
  const device = generateDeviceKeys();
  const authKey = opts.authKey ?? randomBytes(32);
  const clientSalt = randomBytes(16);
  const recoveryKey = opts.recovery ? randomBytes(32) : null;
  const body = {
    reservation: u.json.reservation,
    pow: await solveChallenge(h),
    clientSalt: toB64(clientSalt),
    kdf: TEST_KDF,
    authKey: toB64(authKey),
    identityKey: toB64(aik.publicKey),
    deviceList: signList({ aik }, 1, [deviceEntryFor(device, true)]),
    device: publicDevice(device),
    ...prekeysFor(device, 1, opts.otkCount ?? 5),
    ...(recoveryKey ? { recovery: { verifierKey: toB64(recoveryKey), backup: toB64(randomBytes(64)) } } : {}),
  };
  return { body, username: u.json.username as string, aik, device, authKey, clientSalt, recoveryKey };
}

export async function register(h: Harness, opts: { recovery?: boolean; authKey?: Uint8Array; otkCount?: number } = {}): Promise<TestAccount> {
  const r = await buildRegistration(h, opts);
  const res = await h.call('POST', '/v1/auth/register', { body: r.body });
  if (res.status !== 201) throw new Error(`register failed: ${res.status} ${JSON.stringify(res.json)}`);
  return {
    username: r.username,
    authKey: r.authKey,
    clientSalt: r.clientSalt,
    aik: r.aik,
    listVersion: 1,
    devices: [{ keys: r.device, primary: true, session: res.json }],
    recoveryKey: r.recoveryKey,
    token: res.json.accessToken,
    refreshToken: res.json.refreshToken,
  };
}

export async function prelogin(h: Harness, username: string) {
  return (await h.call('POST', '/v1/auth/prelogin', { body: { username } })).json;
}

export async function login(h: Harness, acct: TestAccount, device?: DeviceKeys, authKey = acct.authKey): Promise<Res> {
  const pre = await prelogin(h, acct.username);
  const body: Record<string, unknown> = { username: acct.username, authKey: toB64(authKey), nonce: pre.nonce };
  if (device) body.device = { deviceId: toB64(device.deviceId), signature: toB64(signDeviceLogin(device.signing.privateKey, pre.nonce, acct.username)) };
  return h.call('POST', '/v1/auth/login', { body });
}

/** Full link flow: password login on a new device, primary approves, new device enrolls. */
export async function linkNewDevice(h: Harness, acct: TestAccount): Promise<TestDevice> {
  const linkLogin = await login(h, acct);
  if (linkLogin.json.kind !== 'link') throw new Error('expected link session');
  const keys = generateDeviceKeys();
  const prov = x25519KeyPair();
  const request = encodeLinkRequest({ deviceId: keys.deviceId, signingKey: keys.signing.publicKey, dhKey: keys.dh.publicKey, provisioningKey: prov.publicKey }, generateLinkSecret());
  const created = await h.call('POST', '/v1/link/requests', { token: linkLogin.json.accessToken, body: { request: toB64(request) } });
  if (created.status !== 200) throw new Error(`link request failed ${created.status}`);
  const pending = await h.call('GET', '/v1/link/requests', { token: acct.token });
  const linkId = pending.json.requests[0].linkId;
  const resp = await h.call('POST', `/v1/link/requests/${linkId}/response`, { token: acct.token, body: { payload: toB64(randomBytes(100)) } });
  if (resp.status !== 204) throw new Error(`link response failed ${resp.status}`);
  const status = await h.call('GET', `/v1/link/requests/${linkId}`, { token: linkLogin.json.accessToken });
  if (status.json.status !== 'approved') throw new Error('not approved');
  const version = acct.listVersion + 1;
  const entries = [...acct.devices.map((d) => deviceEntryFor(d.keys, d.primary)), deviceEntryFor(keys, false)];
  const enroll = await h.call('POST', '/v1/devices/enroll', {
    token: linkLogin.json.accessToken,
    body: { deviceList: signList(acct, version, entries), device: publicDevice(keys), ...prekeysFor(keys, 1, 3), linkId },
  });
  if (enroll.status !== 200) throw new Error(`enroll failed ${enroll.status} ${JSON.stringify(enroll.json)}`);
  acct.listVersion = version;
  const dev = { keys, primary: false, session: enroll.json };
  acct.devices.push(dev);
  return dev;
}

export function envelope(deviceId: Uint8Array, payload = randomBytes(48), envelopeId = randomBytes(16)) {
  return { deviceId: toB64(deviceId), envelopeId: toB64(envelopeId), payload: toB64(payload) };
}

/** Every application table, for whole-database assertions. */
export const ALL_TABLES = [
  'identity.accounts',
  'identity.retired_usernames',
  'auth.credentials',
  'auth.recovery',
  'auth.sessions',
  'keys.devices',
  'keys.signed_prekeys',
  'keys.one_time_prekeys',
  'keys.link_requests',
  'mailbox.envelopes',
  'media.attachments',
  'ops.reset_jobs',
  'ops.pending_blob_deletions',
  'ops.deletion_ledger',
  'ops.schema_migrations',
];

export async function countRows(db: Db): Promise<Record<string, number>> {
  const out: Record<string, number> = {};
  for (const t of ALL_TABLES) out[t] = Number((await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM ${t}`)).rows[0]!.n);
  return out;
}

/** Text rendering of every row of every table (bytea as hex and as latin1), for leak scans. */
export async function dumpDatabase(db: Db): Promise<string> {
  const parts: string[] = [];
  for (const t of ALL_TABLES) {
    const r = await db.query(`SELECT * FROM ${t}`);
    for (const row of r.rows) {
      for (const [k, v] of Object.entries(row)) {
        if (v instanceof Uint8Array) parts.push(`${t}.${k}=${Buffer.from(v).toString('hex')}|${Buffer.from(v).toString('latin1')}|${toB64(v)}`);
        else parts.push(`${t}.${k}=${String(v)}`);
      }
    }
  }
  return parts.join('\n');
}

export class FailingBlobStore extends MemoryBlobStore {
  failDeletes = true;
  override async delete(id: Uint8Array): Promise<void> {
    if (this.failDeletes) throw new Error('storage unavailable');
    return super.delete(id);
  }
}
