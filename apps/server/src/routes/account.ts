// Sessions, account view/export, profile, directory, device lists and linking.

import type { FastifyInstance } from 'fastify';
import {
  type DeviceList,
  constantTimeEqual,
  decodeDeviceList,
  decodeLinkRequest,
  fromB64,
  randomBytes,
  toB64,
  verifyDeviceList,
  verifySignedPreKey,
} from '@veil/crypto';
import {
  type AccountExport,
  type AccountResponse,
  canonicalUsername,
  CreateLinkRequest,
  DeviceListUpdate,
  type DirectoryEntry,
  EnrollRequest,
  Id16,
  LinkResponseUpload,
  type LinkStatus,
  ProfileUpdate,
  type SignedDeviceListJson,
} from '@veil/shared';
import { decoyFor } from '../decoy.js';
import {
  type AuthSession,
  type Ctx,
  createSession,
  isUniqueViolation,
  limitByAccount,
  nowSeconds,
  requireDevice,
  requireLink,
  requireSession,
  sessionResponse,
} from '../context.js';
import type { Db } from '../db.js';
import { Errors, parse } from '../errors.js';

interface AccountRow {
  id: string;
  username: string;
  identity_key: Uint8Array;
  device_list: Uint8Array;
  device_list_sig: Uint8Array;
  device_list_version: number;
  profile: Uint8Array | null;
}

async function loadAccount(db: Db, accountId: string, forUpdate = false): Promise<AccountRow> {
  const r = await db.query<AccountRow>(
    `SELECT id, username, identity_key, device_list, device_list_sig, device_list_version, profile
     FROM identity.accounts WHERE id = $1${forUpdate ? ' FOR UPDATE' : ''}`,
    [accountId],
  );
  if (!r.rows[0]) throw Errors.unauthorized();
  return r.rows[0];
}

function listJson(a: AccountRow): SignedDeviceListJson {
  return { body: toB64(a.device_list), signature: toB64(a.device_list_sig) };
}

/** True if `deviceId` is flagged primary in the account's current signed device list. */
function isPrimaryDevice(a: AccountRow, deviceId: Uint8Array): boolean {
  try {
    const list = decodeDeviceList(a.device_list);
    return list.devices.some((d) => d.primary && constantTimeEqual(d.deviceId, deviceId));
  } catch {
    return false;
  }
}

function verifyNewList(a: AccountRow, json: SignedDeviceListJson): DeviceList {
  let list: DeviceList;
  try {
    list = verifyDeviceList({ body: fromB64(json.body), signature: fromB64(json.signature) }, a.identity_key);
  } catch {
    throw Errors.badRequest();
  }
  if (list.version <= Number(a.device_list_version)) throw Errors.conflict('Device list version must increase.');
  return list;
}

interface DeviceRow {
  id: Uint8Array;
  signing_key: Uint8Array;
  dh_key: Uint8Array;
}

async function accountDevices(db: Db, accountId: string): Promise<DeviceRow[]> {
  return (await db.query<DeviceRow>('SELECT id, signing_key, dh_key FROM keys.devices WHERE account_id = $1', [accountId])).rows;
}

function sameDevice(row: DeviceRow, e: { deviceId: Uint8Array; signingKey: Uint8Array; dhKey: Uint8Array }): boolean {
  return constantTimeEqual(row.id, e.deviceId) && constantTimeEqual(row.signing_key, e.signingKey) && constantTimeEqual(row.dh_key, e.dhKey);
}

async function deleteDevices(tx: Db, ids: Uint8Array[]): Promise<void> {
  for (const id of ids) await tx.query('DELETE FROM keys.devices WHERE id = $1', [id]);
}

function idParam(value: unknown): Uint8Array {
  return fromB64(parse(Id16, value));
}

export function registerAccountRoutes(app: FastifyInstance, ctx: Ctx): void {
  // ------------------------------------------------------------ sessions
  app.get('/v1/sessions', async (req) => {
    const s = await requireSession(req, ctx);
    const r = await ctx.db.query<{ id: Uint8Array; kind: 'device' | 'link'; device_id: Uint8Array | null }>(
      'SELECT id, kind, device_id FROM auth.sessions WHERE account_id = $1 ORDER BY id',
      [s.accountId],
    );
    return {
      sessions: r.rows.map((x) => ({
        sessionId: toB64(x.id),
        kind: x.kind,
        deviceId: x.device_id ? toB64(x.device_id) : null,
        current: constantTimeEqual(x.id, s.sessionId),
      })),
    };
  });

  app.delete('/v1/sessions/:sessionId', async (req, reply) => {
    const s = await requireSession(req, ctx);
    const target = idParam((req.params as { sessionId: string }).sessionId);
    // Link sessions may end only themselves; device sessions any session of the same account.
    if (s.kind !== 'device' && !constantTimeEqual(target, s.sessionId)) throw Errors.notFound();
    const r = await ctx.db.query('DELETE FROM auth.sessions WHERE id = $1 AND account_id = $2', [target, s.accountId]);
    if (r.rowCount === 0) throw Errors.notFound();
    ctx.hub.revokeSessions([target]);
    reply.code(204);
  });

  // ------------------------------------------------------------ account
  app.get('/v1/account', async (req): Promise<AccountResponse> => {
    const s = await requireSession(req, ctx);
    const a = await loadAccount(ctx.db, s.accountId);
    const rec = await ctx.db.query('SELECT 1 FROM auth.recovery WHERE account_id = $1', [s.accountId]);
    return {
      username: a.username,
      identityKey: toB64(a.identity_key),
      deviceList: listJson(a),
      recoveryEnabled: rec.rowCount > 0,
      profile: a.profile ? toB64(a.profile) : null,
    };
  });

  app.get('/v1/account/export', async (req): Promise<AccountExport> => {
    const s = await requireDevice(req, ctx);
    const a = await loadAccount(ctx.db, s.accountId);
    const devices = await ctx.db.query<{ id: Uint8Array; signing_key: Uint8Array; dh_key: Uint8Array; otk: number; spk: number | null; queued: number }>(
      `SELECT d.id, d.signing_key, d.dh_key,
         (SELECT count(*) FROM keys.one_time_prekeys o WHERE o.device_id = d.id)::int AS otk,
         (SELECT key_id FROM keys.signed_prekeys p WHERE p.device_id = d.id) AS spk,
         (SELECT count(*) FROM mailbox.envelopes e WHERE e.device_id = d.id)::int AS queued
       FROM keys.devices d WHERE d.account_id = $1 ORDER BY d.id`,
      [s.accountId],
    );
    const sessions = await ctx.db.query<{ id: Uint8Array; kind: 'device' | 'link'; device_id: Uint8Array | null; expires_day: number }>(
      'SELECT id, kind, device_id, expires_day FROM auth.sessions WHERE account_id = $1 ORDER BY id',
      [s.accountId],
    );
    const rec = await ctx.db.query<{ n: number }>('SELECT octet_length(backup) AS n FROM auth.recovery WHERE account_id = $1', [s.accountId]);
    const links = await ctx.db.query<{ n: number }>('SELECT count(*)::int AS n FROM keys.link_requests WHERE account_id = $1', [s.accountId]);
    return {
      username: a.username,
      identityKey: toB64(a.identity_key),
      deviceList: listJson(a),
      devices: devices.rows.map((d) => ({
        deviceId: toB64(d.id),
        signingKey: toB64(d.signing_key),
        dhKey: toB64(d.dh_key),
        oneTimePreKeys: Number(d.otk),
        signedPreKeyId: d.spk === null ? null : Number(d.spk),
        queuedEnvelopes: Number(d.queued),
      })),
      sessions: sessions.rows.map((x) => ({
        sessionId: toB64(x.id),
        kind: x.kind,
        deviceId: x.device_id ? toB64(x.device_id) : null,
        expiresDay: Number(x.expires_day),
      })),
      recovery: { enabled: rec.rowCount > 0, backupBytes: rec.rows[0] ? Number(rec.rows[0].n) : 0 },
      profile: { present: !!a.profile, bytes: a.profile?.length ?? 0 },
      pendingLinkRequests: Number(links.rows[0]?.n ?? 0),
      notStored: [
        'real name, email address or phone number',
        'password (only an Argon2id verifier of a key derived from it on your device)',
        'private keys or message plaintext',
        'who sent the messages queued for your devices',
        'IP addresses, user agents, login times or activity history',
        'contact lists or conversation lists',
      ],
    };
  });

  app.put('/v1/profile', async (req, reply) => {
    const s = await requireDevice(req, ctx);
    const { profile } = parse(ProfileUpdate, req.body);
    await ctx.db.query('UPDATE identity.accounts SET profile = $2 WHERE id = $1', [s.accountId, profile ? fromB64(profile) : null]);
    reply.code(204);
  });

  // ------------------------------------------------------------ directory
  app.get('/v1/directory/:username', async (req): Promise<DirectoryEntry> => {
    const s = await requireDevice(req, ctx);
    limitByAccount(ctx, s.accountId, 'directory');
    // Only malformed names (not two words from the public lists) are refused.
    const name = canonicalUsername(String((req.params as { username: string }).username ?? ''));
    if (!name) throw Errors.notFound();
    const r = await ctx.db.query<AccountRow>(
      `SELECT id, username, identity_key, device_list, device_list_sig, device_list_version, profile
       FROM identity.accounts WHERE lower(username) = lower($1)`,
      [name],
    );
    const a = r.rows[0];
    if (!a) {
      // Unassigned or retired: answer with a decoy, never with "does not exist".
      const d = decoyFor(ctx.keys.decoy, name);
      return { username: d.username, identityKey: toB64(d.identityKey), deviceList: { body: toB64(d.deviceList.body), signature: toB64(d.deviceList.signature) }, profile: null };
    }
    return { username: a.username, identityKey: toB64(a.identity_key), deviceList: listJson(a), profile: a.profile ? toB64(a.profile) : null };
  });

  // ------------------------------------------------------------ device list maintenance
  app.put('/v1/devices/list', async (req, reply) => {
    const s = await requireDevice(req, ctx);
    const body = parse(DeviceListUpdate, req.body);
    const removed = await ctx.db.transaction(async (tx) => {
      const a = await loadAccount(tx, s.accountId, true);
      const list = verifyNewList(a, body.deviceList);
      const rows = await accountDevices(tx, s.accountId);
      // Only removals: every listed device must already exist with identical keys.
      for (const e of list.devices) if (!rows.some((r) => sameDevice(r, e))) throw Errors.badRequest();
      if (!list.devices.some((e) => constantTimeEqual(e.deviceId, s.deviceId))) throw Errors.badRequest();
      const gone = rows.filter((r) => !list.devices.some((e) => constantTimeEqual(e.deviceId, r.id))).map((r) => r.id);
      await deleteDevices(tx, gone);
      await tx.query('UPDATE identity.accounts SET device_list = $2, device_list_sig = $3, device_list_version = $4 WHERE id = $1', [
        s.accountId,
        fromB64(body.deviceList.body),
        fromB64(body.deviceList.signature),
        list.version,
      ]);
      return gone;
    });
    ctx.hub.revokeDevices(removed);
    reply.code(204);
  });

  app.delete('/v1/devices/self', async (req, reply) => {
    const s = await requireDevice(req, ctx);
    const a = await loadAccount(ctx.db, s.accountId);
    if (isPrimaryDevice(a, s.deviceId)) throw Errors.conflict('The primary device cannot remove itself.');
    await ctx.db.query('DELETE FROM keys.devices WHERE id = $1 AND account_id = $2', [s.deviceId, s.accountId]);
    ctx.hub.revokeDevices([s.deviceId]);
    reply.code(204);
  });

  app.post('/v1/devices/enroll', async (req) => {
    const s = await requireLink(req, ctx);
    const body = parse(EnrollRequest, req.body);
    const deviceId = fromB64(body.device.deviceId);
    const signingKey = fromB64(body.device.signingKey);
    const dhKey = fromB64(body.device.dhKey);
    const spk = body.signedPreKey;
    if (!verifySignedPreKey(signingKey, deviceId, spk.keyId, fromB64(spk.publicKey), fromB64(spk.signature))) throw Errors.badRequest();
    if (new Set(body.oneTimePreKeys.map((k) => k.keyId)).size !== body.oneTimePreKeys.length) throw Errors.badRequest();
    try {
      const out = await ctx.db.transaction(async (tx) => {
        const a = await loadAccount(tx, s.accountId, true);
        const list = verifyNewList(a, body.deviceList);
        const rows = await accountDevices(tx, s.accountId);
        const self = { deviceId, signingKey, dhKey };
        let sawSelf = false;
        for (const e of list.devices) {
          if (constantTimeEqual(e.deviceId, deviceId)) {
            if (!constantTimeEqual(e.signingKey, signingKey) || !constantTimeEqual(e.dhKey, dhKey)) throw Errors.badRequest();
            sawSelf = true;
          } else if (!rows.some((r) => sameDevice(r, e))) {
            throw Errors.badRequest(); // only the enrolling device may be new
          }
        }
        if (!sawSelf || rows.some((r) => constantTimeEqual(r.id, deviceId))) throw Errors.badRequest();
        const gone = rows.filter((r) => !list.devices.some((e) => constantTimeEqual(e.deviceId, r.id))).map((r) => r.id);
        await deleteDevices(tx, gone);
        await tx.query('INSERT INTO keys.devices (id, account_id, signing_key, dh_key) VALUES ($1, $2, $3, $4)', [
          self.deviceId,
          s.accountId,
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
          await tx.query('INSERT INTO keys.one_time_prekeys (device_id, key_id, public_key) VALUES ($1, $2, $3)', [deviceId, k.keyId, fromB64(k.publicKey)]);
        }
        await tx.query('UPDATE identity.accounts SET device_list = $2, device_list_sig = $3, device_list_version = $4 WHERE id = $1', [
          s.accountId,
          fromB64(body.deviceList.body),
          fromB64(body.deviceList.signature),
          list.version,
        ]);
        if (body.linkId) await tx.query('DELETE FROM keys.link_requests WHERE id = $1 AND account_id = $2', [fromB64(body.linkId), s.accountId]);
        await tx.query('DELETE FROM auth.sessions WHERE id = $1', [s.sessionId]);
        const session = await createSession(tx, ctx, s.accountId, deviceId);
        return { session, gone, username: a.username };
      });
      ctx.hub.revokeDevices(out.gone);
      ctx.hub.revokeSessions([s.sessionId]);
      return sessionResponse(ctx, out.session, out.username, deviceId);
    } catch (e) {
      if (isUniqueViolation(e)) throw Errors.conflict('Device already registered.');
      throw e;
    }
  });

  // ------------------------------------------------------------ linking
  app.post('/v1/link/requests', async (req) => {
    const s = await requireLink(req, ctx);
    limitByAccount(ctx, s.accountId, 'linkRequests');
    const { request } = parse(CreateLinkRequest, req.body);
    const bytes = fromB64(request);
    try {
      decodeLinkRequest(bytes);
    } catch {
      throw Errors.badRequest();
    }
    const linkId = randomBytes(16);
    await ctx.db.transaction(async (tx) => {
      const pending = await tx.query<{ n: number }>('SELECT count(*)::int AS n FROM keys.link_requests WHERE account_id = $1 AND expires_at > $2', [
        s.accountId,
        nowSeconds(ctx),
      ]);
      if (Number(pending.rows[0]!.n) >= ctx.config.maxPendingLinkRequests) throw Errors.rateLimited(ctx.config.linkRequestTtlSeconds);
      await tx.query('INSERT INTO keys.link_requests (id, account_id, session_id, request, response, expires_at) VALUES ($1, $2, $3, $4, NULL, $5)', [
        linkId,
        s.accountId,
        s.sessionId,
        bytes,
        nowSeconds(ctx) + ctx.config.linkRequestTtlSeconds,
      ]);
    });
    ctx.hub.notifyAccountDevices(s.accountId, { type: 'link' });
    return { linkId: toB64(linkId) };
  });

  app.get('/v1/link/requests', async (req) => {
    const s = await requireDevice(req, ctx);
    const r = await ctx.db.query<{ id: Uint8Array; request: Uint8Array }>(
      'SELECT id, request FROM keys.link_requests WHERE account_id = $1 AND response IS NULL AND expires_at > $2 ORDER BY id',
      [s.accountId, nowSeconds(ctx)],
    );
    return { requests: r.rows.map((x) => ({ linkId: toB64(x.id), request: toB64(x.request) })) };
  });

  app.get('/v1/link/requests/:linkId', async (req): Promise<LinkStatus> => {
    const s = await requireLink(req, ctx);
    const linkId = idParam((req.params as { linkId: string }).linkId);
    const r = await ctx.db.query<{ response: Uint8Array | null }>(
      'SELECT response FROM keys.link_requests WHERE id = $1 AND session_id = $2 AND expires_at > $3',
      [linkId, s.sessionId, nowSeconds(ctx)],
    );
    const row = r.rows[0];
    if (!row) throw Errors.notFound();
    return row.response ? { status: 'approved', payload: toB64(row.response) } : { status: 'pending', payload: null };
  });

  app.post('/v1/link/requests/:linkId/response', async (req, reply) => {
    const s = await requireDevice(req, ctx);
    const linkId = idParam((req.params as { linkId: string }).linkId);
    const { payload } = parse(LinkResponseUpload, req.body);
    const a = await loadAccount(ctx.db, s.accountId);
    if (!isPrimaryDevice(a, s.deviceId)) throw Errors.forbidden('Only a primary device can approve new devices.');
    const r = await ctx.db.query(
      'UPDATE keys.link_requests SET response = $3 WHERE id = $1 AND account_id = $2 AND response IS NULL AND expires_at > $4',
      [linkId, s.accountId, fromB64(payload), nowSeconds(ctx)],
    );
    if (r.rowCount === 0) throw Errors.notFound();
    reply.code(204);
  });

  app.delete('/v1/link/requests/:linkId', async (req, reply) => {
    const s: AuthSession = await requireSession(req, ctx);
    const linkId = idParam((req.params as { linkId: string }).linkId);
    const r =
      s.kind === 'device'
        ? await ctx.db.query('DELETE FROM keys.link_requests WHERE id = $1 AND account_id = $2', [linkId, s.accountId])
        : await ctx.db.query('DELETE FROM keys.link_requests WHERE id = $1 AND session_id = $2', [linkId, s.sessionId]);
    if (r.rowCount === 0) throw Errors.notFound();
    reply.code(204);
  });
}
