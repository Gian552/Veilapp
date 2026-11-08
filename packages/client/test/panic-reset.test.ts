// Panic Reset end to end, including the failure modes the workflow must
// survive: network interruption, a lost response after the server committed,
// a crash between server deletion and local wipe, and an unreachable server.
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { MemoryStorage, VeilError } from '../src/index.js';
import { PASSWORD, collectReset, dumpDatabase, registered, startHarness, sync, type Harness } from './helpers.js';

let h: Harness;
beforeEach(async () => {
  h = await startHarness();
});
afterEach(async () => {
  await h.close();
});

async function accountRows() {
  const r = await h.server.db.query<{ n: number }>('SELECT count(*)::int AS n FROM identity.accounts');
  return r.rows[0]!.n;
}

/** A fetch that fails on matching requests a given number of times. */
function flakyFetch(match: (url: string) => boolean, mode: 'before' | 'after', failures: number) {
  let remaining = failures;
  const f: typeof fetch = async (input, init) => {
    const url = String(input);
    if (match(url) && remaining > 0) {
      remaining--;
      if (mode === 'before') throw new TypeError('network down');
      await fetch(input, init); // server processes it...
      throw new TypeError('connection reset'); // ...but the response is lost
    }
    return fetch(input, init);
  };
  return f;
}

describe('Panic Reset', () => {
  it('deletes the account everywhere, wipes the device and creates a distinct new identity', async () => {
    const a = await registered(h, { recovery: true });
    const b = await registered(h);
    await a.client.startConversation(b.username);
    await a.client.sendText(b.username, 'before reset');
    await a.client.sendAttachment(b.username, { name: 'x.bin', mime: 'application/octet-stream', bytes: new Uint8Array(1000).fill(7) });
    await sync(b.client);
    const oldSafety = b.client.safetyNumber(a.username);
    const oldIdentityHex = (await h.server.db.query<{ k: Uint8Array }>('SELECT identity_key AS k FROM identity.accounts WHERE username = $1', [a.username])).rows[0]!.k;

    const { report, phases } = await collectReset((p) => a.client.panicReset({ createNewIdentity: true, newPassword: 'a fresh new password', enableRecovery: true }, p));
    expect(phases).toEqual(['initiated', 'server-deleting', 'server-deleted', 'local-wiped', 'new-identity', 'completed']);
    expect(report.server!.accountRecordsDeleted).toBe(true);
    expect(report.server!.attachmentsDeleted).toBe(1);
    expect(report.localWiped).toBe(true);
    expect(report.newIdentity!.distinctFromOld).toBe(true);
    expect(report.newIdentity!.username).not.toBe(a.username);
    expect(report.newIdentity!.recoveryKey).toMatch(/^[0-9A-Z-]+$/);

    // The old account is gone from every table; the new one shares nothing with it.
    expect(await accountRows()).toBe(2);
    const dump = await dumpDatabase(h.server);
    expect(dump).not.toContain(Buffer.from(oldIdentityHex).toString('hex'));
    const newRow = await h.server.db.query<{ k: Uint8Array }>('SELECT identity_key AS k FROM identity.accounts WHERE username = $1', [report.newIdentity!.username]);
    expect(Buffer.from(newRow.rows[0]!.k).equals(Buffer.from(oldIdentityHex))).toBe(false);
    expect(h.blobs.blobs.size).toBe(0);

    // Local state contains only the new identity.
    expect(a.client.snapshot().username).toBe(report.newIdentity!.username);
    expect(a.client.snapshot().conversations).toEqual([]);
    expect(a.client.messages(b.username)).toEqual([]);

    // The old identity cannot be signed into, and contacts learn it is gone.
    const probe = h.client();
    await probe.init();
    await expect(probe.signIn({ username: a.username, password: PASSWORD })).rejects.toMatchObject({ code: 'invalid_credentials' });
    await b.client.refreshContact(a.username);
    // The server never confirms deletion (existence is hidden): Bob sees a safety-number change
    // to a decoy identity and cannot send until he reviews it.
    expect(b.client.snapshot().conversations.find((c) => c.peer === a.username)!.verification).toBe('key-changed');
    await expect(b.client.sendText(a.username, 'hello?')).rejects.toMatchObject({ code: 'key_changed' });
    // Bob keeps what was already delivered (documented: no retroactive erasure on recipients).
    expect(b.client.messages(a.username).some((m) => m.text === 'before reset')).toBe(true);
    expect(oldSafety).not.toBe('');
    // The old username is retired and never reissued.
    const retired = await h.server.db.query<{ n: number }>('SELECT count(*)::int AS n FROM identity.retired_usernames');
    expect(retired.rows[0]!.n).toBe(1);
  });

  it('network interruption before the server is reached: nothing deleted, resumable later', async () => {
    const storage = new MemoryStorage();
    const flaky = flakyFetch((u) => u.includes('/v1/reset'), 'before', 100);
    const client = h.client({ storage, fetch: flaky });
    await client.init();
    const s = await client.suggestUsername();
    const { username } = await client.register({ reservation: s.reservation, password: PASSWORD, enableRecovery: false });

    const { report, phases } = await collectReset((p) => client.panicReset({ createNewIdentity: false }, p));
    expect(report.phase).toBe('failed');
    expect(phases).not.toContain('server-deleted');
    expect(report.localWiped).toBe(false);
    expect(report.problems.join(' ')).toMatch(/Nothing has been deleted/);
    expect(await accountRows()).toBe(1);

    // App restarts with a working network: the interrupted reset is detected and resumed.
    const restarted = h.client({ storage });
    await restarted.init();
    expect(restarted.snapshot().status).toBe('reset-pending');
    const resumed = await collectReset((p) => restarted.resumeReset(PASSWORD, p));
    expect(resumed.report.server!.accountRecordsDeleted).toBe(true);
    expect(resumed.report.localWiped).toBe(true);
    expect(resumed.report.phase).toBe('completed');
    expect(await accountRows()).toBe(0);
    expect(restarted.snapshot().status).toBe('no-vault');
    expect(await storage.keys('records')).toEqual([]);
    expect(await storage.keys('meta')).toEqual([]);
    void username;
  });

  it('a response lost after the server committed is recovered idempotently via the job id', async () => {
    const storage = new MemoryStorage();
    const flaky = flakyFetch((u) => u.endsWith('/v1/reset'), 'after', 1);
    const client = h.client({ storage, fetch: flaky });
    await client.init();
    const s = await client.suggestUsername();
    await client.register({ reservation: s.reservation, password: PASSWORD, enableRecovery: false });
    const { report } = await collectReset((p) => client.panicReset({ createNewIdentity: false }, p));
    expect(report.phase).toBe('completed');
    expect(report.server!.accountRecordsDeleted).toBe(true);
    const jobs = await h.server.db.query<{ n: number }>('SELECT count(*)::int AS n FROM ops.reset_jobs');
    expect(jobs.rows[0]!.n).toBe(1); // one job, not two
    expect(await accountRows()).toBe(0);
  });

  it('a crash after server deletion but before the local wipe is completed on next start', async () => {
    const inner = new MemoryStorage();
    let crash = true;
    const storage = Object.assign(Object.create(Object.getPrototypeOf(inner)), inner, {
      destroy: async () => {
        if (crash) {
          crash = false;
          throw new Error('simulated crash');
        }
        return inner.destroy();
      },
    }) as MemoryStorage;
    const client = h.client({ storage });
    await client.init();
    const s = await client.suggestUsername();
    await client.register({ reservation: s.reservation, password: PASSWORD, enableRecovery: false });
    await expect(client.panicReset({ createNewIdentity: false }, () => {})).rejects.toThrow('simulated crash');
    expect(await accountRows()).toBe(0); // server part done
    expect((await storage.keys('records')).length).toBeGreaterThan(0); // local part not

    const restarted = h.client({ storage });
    await restarted.init();
    expect(restarted.snapshot().status).toBe('reset-pending');
    const { report } = await collectReset((p) => restarted.resumeReset(PASSWORD, p));
    expect(report.phase).toBe('completed');
    expect(report.server!.accountRecordsDeleted).toBe(true);
    expect(await storage.keys('records')).toEqual([]);
  });

  it('server unreachable + "wipe anyway": device wiped, report says server data still exists', async () => {
    const storage = new MemoryStorage();
    const client = h.client({ storage, fetch: flakyFetch((u) => u.includes('/v1/reset'), 'before', 100) });
    await client.init();
    const s = await client.suggestUsername();
    await client.register({ reservation: s.reservation, password: PASSWORD, enableRecovery: false });
    const { report } = await collectReset((p) => client.panicReset({ createNewIdentity: false, wipeLocallyIfServerUnreachable: true }, p));
    expect(report.phase).toBe('partial');
    expect(report.localWiped).toBe(true);
    expect(report.server).toBeNull();
    expect(report.problems.join(' ')).toMatch(/STILL EXIST/);
    expect(await accountRows()).toBe(1); // honest: nothing was deleted server-side
  });

  it('other devices of the reset account are locked out and can erase themselves', async () => {
    const a = await registered(h);
    const a2Storage = new MemoryStorage();
    const a2 = h.client({ storage: a2Storage });
    await a2.init();
    await a2.signIn({ username: a.username, password: PASSWORD });
    const { code } = await a2.requestLink();
    const [p] = await a.client.pendingLinks();
    const waiting = a2.waitForLinkApproval();
    await a.client.approveLink(p!.linkId, code);
    await waiting;
    await a.client.panicReset({ createNewIdentity: false }, () => {});
    // a2's session was revoked by the reset.
    await expect(a2.drain()).rejects.toBeInstanceOf(VeilError);
    await a2.lock();
    await expect(a2.signIn({ username: a.username, password: PASSWORD })).rejects.toBeInstanceOf(VeilError);
    await a2.eraseLocalData();
    expect(a2.snapshot().status).toBe('no-vault');
    expect(await a2Storage.keys('records')).toEqual([]);
  });

  it('a partial blob deletion failure is reported as partial, not as completed', async () => {
    const a = await registered(h);
    const b = await registered(h);
    await a.client.startConversation(b.username);
    await a.client.sendAttachment(b.username, { name: 'f', mime: 'application/octet-stream', bytes: new Uint8Array(10) });
    const realDelete = h.blobs.delete.bind(h.blobs);
    h.blobs.delete = async () => {
      throw new Error('storage outage');
    };
    const { report } = await collectReset((p) => a.client.panicReset({ createNewIdentity: false }, p));
    expect(report.phase).toBe('partial');
    expect(report.server!.state).toBe('partial');
    expect(report.server!.attachmentsPending).toBe(1);
    expect(report.problems.join(' ')).toMatch(/could not be deleted yet/);
    h.blobs.delete = realDelete;
    await h.server.sweep();
    expect(h.blobs.blobs.size).toBe(0);
  });
});
