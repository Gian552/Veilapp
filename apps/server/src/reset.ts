// Panic Reset (docs/ARCHITECTURE.md §6, docs/PANIC_RESET.md), backup-restore
// deletion replay, and the retention sweeper.

import type { FastifyInstance } from 'fastify';
import { constantTimeEqual, fromB64, sha256, toB64 } from '@veil/crypto';
import { ResetRequest, type ResetStatus, ResetStatusRequest } from '@veil/shared';
import { type Ctx, authenticate, nowSeconds, today } from './context.js';
import type { Db } from './db.js';
import { Errors, parse } from './errors.js';
import { type ServerKeys, ledgerAccountTag, retiredUsernameTag } from './tokens.js';

interface JobRow {
  id: Uint8Array;
  secret_hash: Uint8Array;
  state: 'account_deleted' | 'completed' | 'partial';
  deleted: number;
  pending: number;
  not_found: number;
}

async function loadJob(db: Db, jobId: Uint8Array): Promise<JobRow | null> {
  const r = await db.query<JobRow>('SELECT id, secret_hash, state, deleted, pending, not_found FROM ops.reset_jobs WHERE id = $1', [jobId]);
  return r.rows[0] ?? null;
}

function statusOf(ctx: Ctx, job: JobRow): ResetStatus {
  return {
    jobId: toB64(job.id),
    state: job.state,
    accountRecordsDeleted: true,
    attachmentsDeleted: Number(job.deleted),
    attachmentsPending: Number(job.pending),
    attachmentsNotFound: Number(job.not_found),
    backupRetentionDays: ctx.config.retention.backupDays,
    attachmentRetentionDays: ctx.config.retention.attachmentDays,
  };
}

/**
 * Tries to delete every queued blob (optionally only those of one job) and
 * refreshes the per-job counters. Failures stay queued for the next attempt.
 */
export async function processPendingBlobDeletions(ctx: Ctx, jobId?: Uint8Array): Promise<void> {
  const r = jobId
    ? await ctx.db.query<{ blob_id: Uint8Array; job_id: Uint8Array | null }>('SELECT blob_id, job_id FROM ops.pending_blob_deletions WHERE job_id = $1', [jobId])
    : await ctx.db.query<{ blob_id: Uint8Array; job_id: Uint8Array | null }>('SELECT blob_id, job_id FROM ops.pending_blob_deletions');
  const touchedJobs = new Map<string, Uint8Array>();
  for (const row of r.rows) {
    try {
      await ctx.blobs.delete(row.blob_id);
      await ctx.db.query('DELETE FROM ops.pending_blob_deletions WHERE blob_id = $1', [row.blob_id]);
      if (row.job_id) {
        await ctx.db.query('UPDATE ops.reset_jobs SET deleted = deleted + 1 WHERE id = $1', [row.job_id]);
      }
    } catch {
      ctx.log({ level: 'warn', event: 'blob_delete_failed' });
    }
    if (row.job_id) touchedJobs.set(toB64(row.job_id), row.job_id);
  }
  if (jobId) touchedJobs.set(toB64(jobId), jobId);
  for (const id of touchedJobs.values()) {
    await ctx.db.query(
      `UPDATE ops.reset_jobs SET
         pending = (SELECT count(*) FROM ops.pending_blob_deletions WHERE job_id = $1),
         state = CASE WHEN (SELECT count(*) FROM ops.pending_blob_deletions WHERE job_id = $1) = 0 THEN 'completed' ELSE 'partial' END
       WHERE id = $1`,
      [id],
    );
  }
}

async function existingJobStatus(ctx: Ctx, jobId: Uint8Array, secret: Uint8Array): Promise<ResetStatus | null> {
  const job = await loadJob(ctx.db, jobId);
  if (!job) return null;
  if (!constantTimeEqual(job.secret_hash, sha256(secret))) throw Errors.notFound();
  if (Number(job.pending) > 0 || job.state !== 'completed') await processPendingBlobDeletions(ctx, jobId);
  return statusOf(ctx, (await loadJob(ctx.db, jobId))!);
}

export function registerResetRoutes(app: FastifyInstance, ctx: Ctx): void {
  app.post('/v1/reset', async (req) => {
    const body = parse(ResetRequest, req.body);
    const jobId = fromB64(body.jobId);
    const secret = fromB64(body.jobSecret);

    // Idempotency: a retry after the account is already gone only needs the job secret.
    const existing = await existingJobStatus(ctx, jobId, secret);
    if (existing) return existing;

    const session = await authenticate(req, ctx);
    if (!session) throw Errors.unauthorized();

    const revoked = await ctx.db.transaction(async (tx) => {
      const acct = await tx.query<{ id: string; username: string }>('SELECT id, username FROM identity.accounts WHERE id = $1 FOR UPDATE', [
        session.accountId,
      ]);
      const account = acct.rows[0];
      if (!account) return null; // a concurrent request with the same job won the race
      const sessions = await tx.query<{ id: Uint8Array }>('SELECT id FROM auth.sessions WHERE account_id = $1', [account.id]);

      let pending = 0;
      let notFound = 0;
      for (const a of body.attachments) {
        const id = fromB64(a.attachmentId);
        const row = await tx.query<{ delete_token_hash: Uint8Array }>('SELECT delete_token_hash FROM media.attachments WHERE id = $1', [id]);
        if (!row.rows[0] || !constantTimeEqual(row.rows[0].delete_token_hash, sha256(fromB64(a.deleteToken)))) {
          notFound++;
          continue;
        }
        await tx.query('DELETE FROM media.attachments WHERE id = $1', [id]);
        const q = await tx.query('INSERT INTO ops.pending_blob_deletions (blob_id, job_id) VALUES ($1, $2) ON CONFLICT DO NOTHING', [id, jobId]);
        pending += q.rowCount;
      }

      await tx.query(
        `INSERT INTO ops.deletion_ledger (account_tag, username_tag, expires_day) VALUES ($1, $2, $3)
         ON CONFLICT (account_tag) DO NOTHING`,
        [ledgerAccountTag(ctx.keys, account.id), retiredUsernameTag(ctx.keys, account.username), today(ctx) + ctx.config.retention.backupDays + 1],
      );
      await tx.query('INSERT INTO identity.retired_usernames (tag) VALUES ($1) ON CONFLICT DO NOTHING', [
        retiredUsernameTag(ctx.keys, account.username),
      ]);
      // One statement removes everything else: credentials, recovery, sessions,
      // devices, prekeys, mailboxes, link requests and profile all cascade.
      await tx.query('DELETE FROM identity.accounts WHERE id = $1', [account.id]);
      await tx.query(
        `INSERT INTO ops.reset_jobs (id, secret_hash, state, deleted, pending, not_found, expires_day)
         VALUES ($1, $2, 'account_deleted', 0, $3, $4, $5)`,
        [jobId, sha256(secret), pending, notFound, today(ctx) + ctx.config.retention.resetJobDays],
      );
      return sessions.rows.map((r) => r.id);
    });

    if (revoked === null) {
      const after = await existingJobStatus(ctx, jobId, secret);
      if (after) return after;
      throw Errors.unauthorized();
    }
    ctx.hub.revokeSessions(revoked);
    await processPendingBlobDeletions(ctx, jobId);
    return statusOf(ctx, (await loadJob(ctx.db, jobId))!);
  });

  app.post('/v1/reset/status', async (req) => {
    const body = parse(ResetStatusRequest, req.body);
    const status = await existingJobStatus(ctx, fromB64(body.jobId), fromB64(body.jobSecret));
    if (!status) throw Errors.notFound();
    return status;
  });
}

/**
 * Re-applies Panic Reset deletions after data schemas were restored from a
 * backup (the ops schema, which holds the ledger, is never restored).
 */
export async function replayDeletions(db: Db, keys: ServerKeys): Promise<{ accountsDeleted: number; usernamesRetired: number }> {
  const ledger = await db.query<{ account_tag: Uint8Array; username_tag: Uint8Array }>('SELECT account_tag, username_tag FROM ops.deletion_ledger');
  if (ledger.rowCount === 0) return { accountsDeleted: 0, usernamesRetired: 0 };
  const tags = new Set(ledger.rows.map((r) => toB64(r.account_tag)));
  let accountsDeleted = 0;
  let usernamesRetired = 0;
  await db.transaction(async (tx) => {
    const accounts = await tx.query<{ id: string }>('SELECT id FROM identity.accounts');
    for (const a of accounts.rows) {
      if (tags.has(toB64(ledgerAccountTag(keys, String(a.id))))) {
        await tx.query('DELETE FROM identity.accounts WHERE id = $1', [a.id]);
        accountsDeleted++;
      }
    }
    for (const r of ledger.rows) {
      const q = await tx.query('INSERT INTO identity.retired_usernames (tag) VALUES ($1) ON CONFLICT DO NOTHING', [r.username_tag]);
      usernamesRetired += q.rowCount;
    }
  });
  return { accountsDeleted, usernamesRetired };
}

/** Enforces every retention rule. Safe to run at any time and concurrently with traffic. */
export async function sweep(ctx: Ctx): Promise<void> {
  const day = today(ctx);
  await ctx.db.query('DELETE FROM mailbox.envelopes WHERE expires_day < $1', [day]);
  await ctx.db.query('DELETE FROM auth.sessions WHERE expires_day < $1', [day]);
  await ctx.db.query('DELETE FROM keys.link_requests WHERE expires_at <= $1', [nowSeconds(ctx)]);
  const expired = await ctx.db.query<{ id: Uint8Array }>('DELETE FROM media.attachments WHERE expires_day < $1 RETURNING id', [day]);
  for (const r of expired.rows) {
    await ctx.db.query('INSERT INTO ops.pending_blob_deletions (blob_id, job_id) VALUES ($1, NULL) ON CONFLICT DO NOTHING', [r.id]);
  }
  await processPendingBlobDeletions(ctx);
  await ctx.db.query('DELETE FROM ops.reset_jobs WHERE expires_day < $1', [day]);
  await ctx.db.query('DELETE FROM ops.deletion_ledger WHERE expires_day < $1', [day]);
}
