// Database schema / migration integrity and HTTP surface hardening.
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { randomBytes } from '@veil/crypto';
import { MIGRATIONS, migrate } from '../src/migrations.js';
import { CONTENT_SECURITY_POLICY } from '../src/index.js';
import { ALL_TABLES, type Harness, register, startHarness } from './helpers.js';

const SCHEMAS = ['identity', 'auth', 'keys', 'mailbox', 'media', 'ops'];
let h: Harness;
afterEach(async () => {
  await h?.close();
});

describe('schema and migrations', () => {
  it('has exactly the documented tables', async () => {
    h = await startHarness();
    const r = await h.db.query<{ t: string }>(
      `SELECT table_schema || '.' || table_name AS t FROM information_schema.tables
       WHERE table_schema = ANY($1) ORDER BY 1`,
      [SCHEMAS],
    );
    expect(r.rows.map((x) => x.t).sort()).toEqual([...ALL_TABLES].sort());
  });

  it('stores no timestamps, IP addresses, user agents or other activity columns', async () => {
    h = await startHarness();
    const r = await h.db.query<{ c: string; data_type: string }>(
      `SELECT table_schema || '.' || table_name || '.' || column_name AS c, data_type FROM information_schema.columns
       WHERE table_schema = ANY($1)`,
      [SCHEMAS],
    );
    for (const { c, data_type } of r.rows) {
      const col = c.split('.').pop()!;
      expect(col, c).not.toMatch(/time|created|updated|modified|seen|login|ip|addr|agent|email|phone|name_real|sender|owner/);
      expect(data_type, c).not.toMatch(/timestamp|date|inet|cidr|interval/);
    }
  });

  it('uses no sequences (no global ordering) and only random primary keys', async () => {
    h = await startHarness();
    const seqs = await h.db.query(`SELECT 1 FROM information_schema.sequences WHERE sequence_schema = ANY($1)`, [SCHEMAS]);
    expect(seqs.rowCount).toBe(0);
    const defaults = await h.db.query<{ c: string }>(
      `SELECT column_name AS c FROM information_schema.columns WHERE table_schema = ANY($1) AND column_default LIKE 'nextval%'`,
      [SCHEMAS],
    );
    expect(defaults.rows).toEqual([]);
  });

  it('every foreign key cascades on delete, and everything account-related is reachable from identity.accounts', async () => {
    h = await startHarness();
    const fks = await h.db.query<{ child: string; parent: string; delete_rule: string }>(
      `SELECT tc.table_schema || '.' || tc.table_name AS child, ccu.table_schema || '.' || ccu.table_name AS parent, rc.delete_rule
       FROM information_schema.table_constraints tc
       JOIN information_schema.referential_constraints rc ON rc.constraint_name = tc.constraint_name AND rc.constraint_schema = tc.table_schema
       JOIN information_schema.constraint_column_usage ccu ON ccu.constraint_name = tc.constraint_name AND ccu.constraint_schema = tc.table_schema
       WHERE tc.constraint_type = 'FOREIGN KEY'`,
    );
    expect(fks.rows.length).toBeGreaterThan(5);
    for (const fk of fks.rows) expect(fk.delete_rule, `${fk.child} -> ${fk.parent}`).toBe('CASCADE');
    const reach = new Set(['identity.accounts']);
    let grew = true;
    while (grew) {
      grew = false;
      for (const fk of fks.rows) if (reach.has(fk.parent) && !reach.has(fk.child)) reach.add(fk.child), (grew = true);
    }
    for (const t of ['auth.credentials', 'auth.recovery', 'auth.sessions', 'keys.devices', 'keys.signed_prekeys', 'keys.one_time_prekeys', 'keys.link_requests', 'mailbox.envelopes']) {
      expect(reach.has(t), t).toBe(true);
    }
    // Deliberately unlinked tables (no owner): attachments, retired usernames, ops.*.
    for (const t of ['media.attachments', 'identity.retired_usernames', 'ops.reset_jobs', 'ops.deletion_ledger']) expect(reach.has(t), t).toBe(false);
  });

  it('migrations are recorded by version only and re-running them is a no-op', async () => {
    h = await startHarness();
    await migrate(h.db);
    await migrate(h.db);
    const v = await h.db.query<{ version: number }>('SELECT version FROM ops.schema_migrations ORDER BY version');
    expect(v.rows.map((r) => Number(r.version))).toEqual(MIGRATIONS.map((m) => m.version));
    const cols = await h.db.query("SELECT 1 FROM information_schema.columns WHERE table_schema = 'ops' AND table_name = 'schema_migrations'");
    expect(cols.rowCount).toBe(1);
  });

  it('database constraints reject malformed data even if application checks were bypassed', async () => {
    h = await startHarness();
    const bad = [
      `INSERT INTO identity.accounts (id, username, identity_key, device_list, device_list_sig, device_list_version) VALUES (gen_random_uuid(), 'john.smith@example.com', '\\x00', '\\x00', '\\x00', 0)`,
      `INSERT INTO media.attachments (id, delete_token_hash, remaining_downloads, size, expires_day) VALUES ('\\x00', '\\x00', 1, 1, 1)`,
      `INSERT INTO ops.reset_jobs (id, secret_hash, state, expires_day) VALUES ('\\x00112233445566778899aabbccddeeff', '\\x00', 'weird', 1)`,
    ];
    for (const sql of bad) await expect(h.db.query(sql)).rejects.toThrow();
    const acct = await register(h);
    // One device session per device.
    const s = await h.db.query<{ device_id: Uint8Array; account_id: string }>('SELECT device_id, account_id FROM auth.sessions');
    await expect(
      h.db.query(
        `INSERT INTO auth.sessions (id, account_id, device_id, kind, refresh_hash, generation, expires_day) VALUES ($1, $2, $3, 'device', $4, 1, 1)`,
        [randomBytes(16), s.rows[0]!.account_id, s.rows[0]!.device_id, randomBytes(32)],
      ),
    ).rejects.toThrow();
    void acct;
  });
});

describe('HTTP surface', () => {
  it('health check reveals nothing and every response carries security headers', async () => {
    h = await startHarness();
    const r = await h.call('GET', '/healthz');
    expect(r.json).toEqual({ ok: true });
    for (const res of [r, await h.call('GET', '/v1/config'), await h.call('GET', '/v1/nope')]) {
      expect(res.headers['content-security-policy']).toBe(CONTENT_SECURITY_POLICY);
      expect(res.headers['x-frame-options']).toBe('DENY');
      expect(res.headers['referrer-policy']).toBe('no-referrer');
      expect(res.headers['x-content-type-options']).toBe('nosniff');
      expect(res.headers['cache-control']).toBe('no-store');
      expect(res.headers['permissions-policy']).toContain('camera=()');
      expect(res.headers['x-powered-by']).toBeUndefined();
    }
    expect(CONTENT_SECURITY_POLICY).toContain("frame-ancestors 'none'");
    expect(CONTENT_SECURITY_POLICY).not.toContain('unsafe-inline');
  });

  it('publishes its retention policy', async () => {
    h = await startHarness();
    const r = await h.call('GET', '/v1/config');
    expect(r.json.retention).toEqual({ undeliveredMessageDays: 30, attachmentDays: 30, sessionDays: 30, backupDays: 7, resetJobDays: 7 });
  });

  it('returns generic errors: unknown routes, unknown fields, malformed JSON, oversized bodies', async () => {
    h = await startHarness();
    expect((await h.call('GET', '/v1/nope')).json).toEqual({ error: { code: 'not_found', message: 'Not found.' } });
    const extra = await h.call('POST', '/v1/auth/prelogin', { body: { username: 'QuietOtter', phone: '123' } });
    expect(extra.json).toEqual({ error: { code: 'bad_request', message: 'Invalid request.' } });
    const malformed = await h.call('POST', '/v1/auth/prelogin', { raw: Buffer.from('{"username":'), headers: { 'content-type': 'application/json' } });
    expect(malformed.status).toBe(400);
    expect(malformed.json.error.message).toBe('Invalid request.');
    const huge = await h.call('POST', '/v1/auth/prelogin', { raw: Buffer.from(JSON.stringify({ username: 'x'.repeat(2 * 1024 * 1024) })), headers: { 'content-type': 'application/json' } });
    expect(huge.status).toBe(413);
  });

  it('serves the web app with SPA fallback but never for API paths', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'veil-web-'));
    writeFileSync(join(dir, 'index.html'), '<!doctype html><title>VEIL</title>');
    writeFileSync(join(dir, 'app.js'), 'console.log(1)');
    try {
      h = await startHarness({ config: { webDist: dir } });
      const root = await h.call('GET', '/');
      expect(root.status).toBe(200);
      expect(root.raw.body).toContain('<title>VEIL</title>');
      expect(root.headers['content-security-policy']).toBe(CONTENT_SECURITY_POLICY);
      expect((await h.call('GET', '/settings/privacy')).raw.body).toContain('<title>VEIL</title>');
      expect((await h.call('GET', '/app.js')).headers['cache-control']).toContain('immutable');
      expect((await h.call('GET', '/v1/unknown')).json.error.code).toBe('not_found');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
