// Prekeys, sealed-sender message relay, mailbox, attachments and recovery blobs.

import type { FastifyInstance } from 'fastify';
import { constantTimeEqual, fromB64, randomBytes, sha256, toB64, verifySignedPreKey } from '@veil/crypto';
import {
  AckRequest,
  AttachmentDelete,
  BundleRequest,
  type BundleResponse,
  type DeviceBundle,
  Id16,
  type KeyStatus,
  type MailboxResponse,
  OneTimePreKeyUpload,
  RecoveryBackupUpdate,
  RecoverySetup,
  SendRequest,
  canonicalUsername,
  type SendResponse,
  SignedPreKeyJson,
} from '@veil/shared';
import { decoyFor, decoyOneTimePreKey, isDecoyDeviceId } from '../decoy.js';
import { type Ctx, limitByAccount, requireDevice, requireSession, today } from '../context.js';
import { type Db, placeholders } from '../db.js';
import { ApiError, Errors, parse } from '../errors.js';

async function keyStatus(db: Db, deviceId: Uint8Array): Promise<KeyStatus> {
  const r = await db.query<{ n: number; spk: number | null }>(
    `SELECT (SELECT count(*) FROM keys.one_time_prekeys WHERE device_id = $1)::int AS n,
            (SELECT key_id FROM keys.signed_prekeys WHERE device_id = $1) AS spk`,
    [deviceId],
  );
  const row = r.rows[0]!;
  return { oneTimePreKeys: Number(row.n), signedPreKeyId: row.spk === null ? null : Number(row.spk) };
}

export function registerMessagingRoutes(app: FastifyInstance, ctx: Ctx): void {
  // ------------------------------------------------------------ prekeys
  app.put('/v1/keys/signed-prekey', async (req, reply) => {
    const s = await requireDevice(req, ctx);
    const spk = parse(SignedPreKeyJson, req.body);
    const d = await ctx.db.query<{ signing_key: Uint8Array }>('SELECT signing_key FROM keys.devices WHERE id = $1', [s.deviceId]);
    if (!d.rows[0] || !verifySignedPreKey(d.rows[0].signing_key, s.deviceId, spk.keyId, fromB64(spk.publicKey), fromB64(spk.signature))) {
      throw Errors.badRequest();
    }
    await ctx.db.query(
      `INSERT INTO keys.signed_prekeys (device_id, key_id, public_key, signature) VALUES ($1, $2, $3, $4)
       ON CONFLICT (device_id) DO UPDATE SET key_id = EXCLUDED.key_id, public_key = EXCLUDED.public_key, signature = EXCLUDED.signature`,
      [s.deviceId, spk.keyId, fromB64(spk.publicKey), fromB64(spk.signature)],
    );
    reply.code(204);
  });

  app.post('/v1/keys/one-time', async (req): Promise<KeyStatus> => {
    const s = await requireDevice(req, ctx);
    const { preKeys } = parse(OneTimePreKeyUpload, req.body);
    return ctx.db.transaction(async (tx) => {
      const current = await keyStatus(tx, s.deviceId);
      if (current.oneTimePreKeys + preKeys.length > ctx.config.maxOneTimePreKeysPerDevice) throw Errors.conflict('Too many prekeys.');
      for (const k of preKeys) {
        await tx.query('INSERT INTO keys.one_time_prekeys (device_id, key_id, public_key) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING', [
          s.deviceId,
          k.keyId,
          fromB64(k.publicKey),
        ]);
      }
      return keyStatus(tx, s.deviceId);
    });
  });

  app.get('/v1/keys/status', async (req): Promise<KeyStatus> => {
    const s = await requireDevice(req, ctx);
    return keyStatus(ctx.db, s.deviceId);
  });

  app.post('/v1/keys/bundles', async (req): Promise<BundleResponse> => {
    const s = await requireDevice(req, ctx);
    limitByAccount(ctx, s.accountId, 'bundles');
    const body = parse(BundleRequest, req.body);
    const name = canonicalUsername(body.username);
    if (!name) throw Errors.notFound();
    return ctx.db.transaction(async (tx) => {
      const a = await tx.query<{ id: string; username: string; identity_key: Uint8Array; device_list: Uint8Array; device_list_sig: Uint8Array }>(
        'SELECT id, username, identity_key, device_list, device_list_sig FROM identity.accounts WHERE lower(username) = lower($1)',
        [name],
      );
      const acct = a.rows[0];
      if (!acct) {
        // Decoy (see decoy.ts): indistinguishable from a quiet one-device account.
        const d = decoyFor(ctx.keys.decoy, name);
        const wanted = body.deviceIds?.map((x) => fromB64(x));
        const include = !wanted || wanted.some((w) => constantTimeEqual(w, d.deviceId));
        return {
          username: d.username,
          identityKey: toB64(d.identityKey),
          deviceList: { body: toB64(d.deviceList.body), signature: toB64(d.deviceList.signature) },
          bundles: include
            ? [
                {
                  deviceId: toB64(d.deviceId),
                  signedPreKey: { keyId: d.signedPreKey.keyId, publicKey: toB64(d.signedPreKey.publicKey), signature: toB64(d.signedPreKey.signature) },
                  oneTimePreKey: ((o) => ({ keyId: o.keyId, publicKey: toB64(o.publicKey) }))(decoyOneTimePreKey()),
                },
              ]
            : [],
        };
      }
      const devices = await tx.query<{ id: Uint8Array; key_id: number; public_key: Uint8Array; signature: Uint8Array }>(
        `SELECT d.id, p.key_id, p.public_key, p.signature FROM keys.devices d
         JOIN keys.signed_prekeys p ON p.device_id = d.id WHERE d.account_id = $1 ORDER BY d.id`,
        [acct.id],
      );
      const wanted = body.deviceIds?.map((d) => fromB64(d));
      const bundles: DeviceBundle[] = [];
      for (const d of devices.rows) {
        if (wanted && !wanted.some((w) => constantTimeEqual(w, d.id))) continue;
        // Atomically consume one one-time prekey (each is handed out at most once).
        const otk = await tx.query<{ key_id: number; public_key: Uint8Array }>(
          `DELETE FROM keys.one_time_prekeys WHERE device_id = $1 AND key_id = (
             SELECT key_id FROM keys.one_time_prekeys WHERE device_id = $1 ORDER BY key_id LIMIT 1 FOR UPDATE SKIP LOCKED)
           RETURNING key_id, public_key`,
          [d.id],
        );
        const o = otk.rows[0];
        bundles.push({
          deviceId: toB64(d.id),
          signedPreKey: { keyId: Number(d.key_id), publicKey: toB64(d.public_key), signature: toB64(d.signature) },
          oneTimePreKey: o ? { keyId: Number(o.key_id), publicKey: toB64(o.public_key) } : null,
        });
      }
      return {
        username: acct.username,
        identityKey: toB64(acct.identity_key),
        deviceList: { body: toB64(acct.device_list), signature: toB64(acct.device_list_sig) },
        bundles,
      };
    });
  });

  // ------------------------------------------------------------ messages
  app.post('/v1/messages', { bodyLimit: 64 * 360 * 1024 }, async (req): Promise<SendResponse> => {
    const s = await requireDevice(req, ctx);
    const { envelopes } = parse(SendRequest, req.body);
    limitByAccount(ctx, s.accountId, 'send');
    const expires = today(ctx) + ctx.config.retention.undeliveredMessageDays;
    const result = await ctx.db.transaction(async (tx) => {
      let accepted = 0;
      const unknown: string[] = [];
      const notify: Uint8Array[] = [];
      // Lock recipient devices in a stable order to avoid deadlocks between concurrent senders.
      const sorted = [...envelopes].sort((a, b) => (a.deviceId < b.deviceId ? -1 : a.deviceId > b.deviceId ? 1 : 0));
      for (const env of sorted) {
        const deviceId = fromB64(env.deviceId);
        const envelopeId = fromB64(env.envelopeId);
        const dup = await tx.query('SELECT 1 FROM mailbox.envelopes WHERE device_id = $1 AND envelope_id = $2', [deviceId, envelopeId]);
        if (dup.rowCount > 0) {
          accepted++; // idempotent retry
          continue;
        }
        const count = await tx.query<{ n: number }>('SELECT count(*)::int AS n FROM mailbox.envelopes WHERE device_id = $1', [deviceId]);
        if (Number(count.rows[0]!.n) >= ctx.config.mailboxMaxPerDevice) throw new ApiError('rate_limited', 'Recipient mailbox is full.', 3600);
        const seq = await tx.query<{ mailbox_seq: number }>(
          'UPDATE keys.devices SET mailbox_seq = mailbox_seq + 1 WHERE id = $1 RETURNING mailbox_seq',
          [deviceId],
        );
        if (seq.rowCount === 0) {
          // Envelopes for decoy devices are accepted and discarded, exactly like a
          // successful send, so sending never reveals whether an account exists.
          if (isDecoyDeviceId(ctx.keys.decoy, deviceId)) accepted++;
          else unknown.push(env.deviceId);
          continue;
        }
        const ins = await tx.query(
          `INSERT INTO mailbox.envelopes (device_id, envelope_id, seq, payload, expires_day) VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT (device_id, envelope_id) DO NOTHING`,
          [deviceId, envelopeId, Number(seq.rows[0]!.mailbox_seq), fromB64(env.payload), expires],
        );
        accepted++;
        if (ins.rowCount > 0) notify.push(deviceId);
      }
      return { accepted, unknown, notify };
    });
    if (result.notify.length) ctx.hub.notifyDevices(result.notify, { type: 'mail' });
    return { accepted: result.accepted, unknownDevices: result.unknown };
  });

  app.get('/v1/mailbox', async (req): Promise<MailboxResponse> => {
    const s = await requireDevice(req, ctx);
    const raw = Number((req.query as { limit?: string }).limit ?? 100);
    const limit = Number.isInteger(raw) && raw > 0 ? Math.min(raw, 500) : 100;
    const r = await ctx.db.query<{ envelope_id: Uint8Array; payload: Uint8Array }>(
      'SELECT envelope_id, payload FROM mailbox.envelopes WHERE device_id = $1 ORDER BY seq LIMIT $2',
      [s.deviceId, limit + 1],
    );
    const rows = r.rows.slice(0, limit);
    return { envelopes: rows.map((x) => ({ envelopeId: toB64(x.envelope_id), payload: toB64(x.payload) })), more: r.rows.length > limit };
  });

  app.post('/v1/mailbox/ack', async (req, reply) => {
    const s = await requireDevice(req, ctx);
    const { envelopeIds } = parse(AckRequest, req.body);
    const ids = envelopeIds.map((x) => fromB64(x));
    await ctx.db.query(`DELETE FROM mailbox.envelopes WHERE device_id = $1 AND envelope_id IN (${placeholders(ids.length, 2)})`, [s.deviceId, ...ids]);
    reply.code(204);
  });

  // ------------------------------------------------------------ attachments
  app.post('/v1/attachments', { bodyLimit: ctx.config.attachmentMaxBytes }, async (req) => {
    const s = await requireDevice(req, ctx);
    limitByAccount(ctx, s.accountId, 'upload');
    const downloads = Number((req.query as { downloads?: string }).downloads ?? 1);
    if (!Number.isInteger(downloads) || downloads < 1 || downloads > 64) throw Errors.badRequest();
    const body = req.body;
    if (!(body instanceof Uint8Array) || body.length === 0) throw Errors.badRequest();
    const id = randomBytes(16);
    const deleteToken = randomBytes(32);
    await ctx.blobs.put(id, body);
    try {
      await ctx.db.query(
        'INSERT INTO media.attachments (id, delete_token_hash, remaining_downloads, size, expires_day) VALUES ($1, $2, $3, $4, $5)',
        [id, sha256(deleteToken), downloads, body.length, today(ctx) + ctx.config.retention.attachmentDays],
      );
    } catch (e) {
      await ctx.blobs.delete(id).catch(() => undefined);
      throw e;
    }
    return { attachmentId: toB64(id), deleteToken: toB64(deleteToken) };
  });

  app.get('/v1/attachments/:id', async (req, reply) => {
    await requireDevice(req, ctx);
    const id = fromB64(parse(Id16, (req.params as { id: string }).id));
    const r = await ctx.db.query<{ remaining_downloads: number }>(
      `UPDATE media.attachments SET remaining_downloads = remaining_downloads - 1
       WHERE id = $1 AND remaining_downloads > 0 AND expires_day >= $2 RETURNING remaining_downloads`,
      [id, today(ctx)],
    );
    if (r.rowCount === 0) throw Errors.notFound();
    const blob = await ctx.blobs.get(id);
    if (Number(r.rows[0]!.remaining_downloads) === 0) await deleteAttachment(ctx, id);
    if (!blob) throw Errors.notFound();
    reply.header('content-type', 'application/octet-stream');
    return reply.send(Buffer.from(blob.buffer, blob.byteOffset, blob.length));
  });

  app.post('/v1/attachments/:id/delete', async (req, reply) => {
    await requireDevice(req, ctx);
    const id = fromB64(parse(Id16, (req.params as { id: string }).id));
    const { deleteToken } = parse(AttachmentDelete, req.body);
    const r = await ctx.db.query<{ delete_token_hash: Uint8Array }>('SELECT delete_token_hash FROM media.attachments WHERE id = $1', [id]);
    if (!r.rows[0] || !constantTimeEqual(r.rows[0].delete_token_hash, sha256(fromB64(deleteToken)))) throw Errors.notFound();
    await deleteAttachment(ctx, id);
    reply.code(204);
  });

  // ------------------------------------------------------------ recovery
  app.put('/v1/recovery', async (req, reply) => {
    const s = await requireDevice(req, ctx);
    const body = parse(RecoverySetup, req.body);
    const verifier = await ctx.passwords.hash(fromB64(body.verifierKey));
    await ctx.db.query(
      `INSERT INTO auth.recovery (account_id, verifier, backup) VALUES ($1, $2, $3)
       ON CONFLICT (account_id) DO UPDATE SET verifier = EXCLUDED.verifier, backup = EXCLUDED.backup`,
      [s.accountId, verifier, fromB64(body.backup)],
    );
    reply.code(204);
  });

  app.put('/v1/recovery/backup', async (req, reply) => {
    const s = await requireDevice(req, ctx);
    const { backup } = parse(RecoveryBackupUpdate, req.body);
    const r = await ctx.db.query('UPDATE auth.recovery SET backup = $2 WHERE account_id = $1', [s.accountId, fromB64(backup)]);
    if (r.rowCount === 0) throw Errors.notFound();
    reply.code(204);
  });

  app.delete('/v1/recovery', async (req, reply) => {
    const s = await requireDevice(req, ctx);
    await ctx.db.query('DELETE FROM auth.recovery WHERE account_id = $1', [s.accountId]);
    reply.code(204);
  });

  app.get('/v1/recovery/backup', async (req) => {
    const s = await requireSession(req, ctx);
    const r = await ctx.db.query<{ backup: Uint8Array }>('SELECT backup FROM auth.recovery WHERE account_id = $1', [s.accountId]);
    if (!r.rows[0]) throw Errors.notFound();
    return { backup: toB64(r.rows[0].backup) };
  });
}

/** Deletes the row, then the blob; a failed blob delete is queued for the sweeper. */
export async function deleteAttachment(ctx: Ctx, id: Uint8Array): Promise<void> {
  await ctx.db.query('DELETE FROM media.attachments WHERE id = $1', [id]);
  try {
    await ctx.blobs.delete(id);
  } catch {
    await ctx.db.query('INSERT INTO ops.pending_blob_deletions (blob_id, job_id) VALUES ($1, NULL) ON CONFLICT DO NOTHING', [id]);
    ctx.log({ level: 'warn', event: 'blob_delete_failed' });
  }
}
