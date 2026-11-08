// End-to-end tests: real client engine against the real server (in-process,
// PGlite database). These validate protocol behaviour across the network
// boundary and what actually ends up stored on both sides.
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { MemoryStorage, VeilClient, VeilError } from '../src/index.js';
import { PASSWORD, TINY_KDF, dumpDatabase, registered, startHarness, storageDump, sync, texts, type Harness } from './helpers.js';

let h: Harness;
beforeEach(async () => {
  h = await startHarness();
});
afterEach(async () => {
  await h.close();
});

describe('account creation and sign-in', () => {
  it('registers with a random two-word username and signs in again after locking', async () => {
    const a = await registered(h);
    expect(a.username).toMatch(/^[A-Z][a-z]+[A-Z][a-z]+$/);
    expect(a.client.snapshot().status).toBe('ready');
    expect(a.client.snapshot().isPrimary).toBe(true);
    await a.client.lock();
    expect(a.client.snapshot().status).toBe('locked');
    expect(await a.client.signIn({ username: a.username, password: PASSWORD })).toBe('ready');
  });

  it('wrong password and unknown username produce the same generic error', async () => {
    const a = await registered(h);
    const fresh = h.client();
    await fresh.init();
    const e1 = await fresh.signIn({ username: a.username, password: 'wrong password!!' }).catch((e) => e);
    const e2 = await fresh.signIn({ username: 'QuietOtter', password: PASSWORD }).catch((e) => e);
    expect(e1).toBeInstanceOf(VeilError);
    expect(e2).toBeInstanceOf(VeilError);
    expect([e1.code, e1.message]).toEqual([e2.code, e2.message]);
    expect(e1.code).toBe('invalid_credentials');
  });

  it('a wrong password cannot unlock the local vault', async () => {
    const a = await registered(h);
    await a.client.lock();
    await expect(a.client.signIn({ username: a.username, password: 'nope nope nope' })).rejects.toMatchObject({ code: 'invalid_credentials' });
  });

  it('refuses server-supplied Argon2 parameters below the client floor (downgrade protection)', async () => {
    const strict = new VeilClient({ baseUrl: h.url, storage: new MemoryStorage(), realtime: false, minimumKdf: { ...TINY_KDF, memoryKiB: 65536 } });
    await strict.init();
    const s = await strict.suggestUsername();
    await expect(strict.register({ reservation: s.reservation, password: PASSWORD, enableRecovery: false })).rejects.toMatchObject({ code: 'crypto' });
  });
});

describe('end-to-end messaging', () => {
  it('delivers in both directions and orders by logical clock, without timestamps', async () => {
    const a = await registered(h);
    const b = await registered(h);
    await a.client.startConversation(b.username);
    await a.client.sendText(b.username, 'hello bob');
    await sync(b.client);
    expect(texts(b.client, a.username)).toEqual(['in:hello bob']);
    await b.client.sendText(a.username, 'hi alice');
    await sync(a.client); // causal: A has seen B's reply before answering
    await a.client.sendText(b.username, 'how are you');
    await sync(a.client, b.client);
    expect(texts(a.client, b.username)).toEqual(['out:hello bob', 'in:hi alice', 'out:how are you']);
    expect(texts(b.client, a.username)).toEqual(['in:hello bob', 'out:hi alice', 'in:how are you']);
    const msg = a.client.messages(b.username).find((m) => m.text === 'hi alice')!;
    expect(Object.keys(msg)).not.toContain('timestamp');
    expect(msg.clock).toBeGreaterThan(0);
  });

  it('concurrent sends from both sides converge to the same total order on both devices', async () => {
    const a = await registered(h);
    const b = await registered(h);
    await a.client.startConversation(b.username);
    await a.client.sendText(b.username, 'start');
    await sync(b.client);
    await Promise.all([
      a.client.sendText(b.username, 'a1'),
      b.client.sendText(a.username, 'b1'),
      a.client.sendText(b.username, 'a2'),
      b.client.sendText(a.username, 'b2'),
    ]);
    await sync(a.client, b.client);
    const orderA = a.client.messages(b.username).filter((m) => m.direction !== 'system').map((m) => m.id);
    const orderB = b.client.messages(a.username).filter((m) => m.direction !== 'system').map((m) => m.id);
    expect(orderA).toHaveLength(5);
    expect(orderA).toEqual(orderB);
  });

  it('messages persist only encrypted on the device and on the server', async () => {
    const a = await registered(h);
    const b = await registered(h);
    await a.client.startConversation(b.username);
    const secret = 'PLAINTEXT-CANARY-7f3a';
    await a.client.sendText(b.username, secret);
    const serverDump = await dumpDatabase(h.server);
    expect(serverDump).not.toContain(secret);
    expect(serverDump).not.toContain(PASSWORD);
    await sync(b.client);
    expect(texts(b.client, a.username)).toEqual([`in:${secret}`]);
    for (const s of [a.storage, b.storage] as MemoryStorage[]) {
      const dump = storageDump(s);
      expect(dump).not.toContain(secret);
      expect(dump).not.toContain(PASSWORD);
      expect(dump).not.toContain(a.username); // even record names are HMACed
      expect(dump).not.toContain(b.username);
    }
    // Delivered envelopes are deleted from the server once acknowledged.
    const left = await h.server.db.query('SELECT count(*)::int AS n FROM mailbox.envelopes');
    expect((left.rows[0] as { n: number }).n).toBe(0);
    expect(JSON.stringify(h.logs)).not.toContain(secret);
  });

  it('ignores a replayed envelope and survives a tampered one', async () => {
    const a = await registered(h);
    const b = await registered(h);
    await a.client.startConversation(b.username);
    await a.client.sendText(b.username, 'once');
    const captured = await h.server.db.query<{ device_id: Uint8Array; envelope_id: Uint8Array; seq: string; payload: Uint8Array; expires_day: number }>(
      'SELECT device_id, envelope_id, seq, payload, expires_day FROM mailbox.envelopes',
    );
    const env = captured.rows[0]!;
    await sync(b.client);
    // Replay: re-insert the exact envelope with a fresh id.
    const reinsert = async (payload: Uint8Array) => {
      const seq = await h.server.db.query<{ s: string }>('UPDATE keys.devices SET mailbox_seq = mailbox_seq + 1 WHERE id = $1 RETURNING mailbox_seq::text AS s', [env.device_id]);
      await h.server.db.query('INSERT INTO mailbox.envelopes (device_id, envelope_id, seq, payload, expires_day) VALUES ($1, $2, $3, $4, $5)', [
        env.device_id,
        crypto.getRandomValues(new Uint8Array(16)),
        seq.rows[0]!.s,
        payload,
        env.expires_day,
      ]);
    };
    await reinsert(env.payload);
    const tampered = env.payload.slice();
    tampered[tampered.length - 5]! ^= 0x01;
    await reinsert(tampered);
    await sync(b.client);
    expect(texts(b.client, a.username)).toEqual(['in:once']);
    // The session still works afterwards.
    await a.client.sendText(b.username, 'twice');
    await sync(b.client);
    expect(texts(b.client, a.username)).toEqual(['in:once', 'in:twice']);
  });

  it('encrypted attachments round-trip and the server only holds ciphertext', async () => {
    const a = await registered(h);
    const b = await registered(h);
    await a.client.startConversation(b.username);
    const bytes = new TextEncoder().encode('ATTACHMENT-CANARY '.repeat(100));
    await a.client.sendAttachment(b.username, { name: 'notes.txt', mime: 'text/plain', bytes });
    expect([...h.blobs.blobs.values()].some((blob) => Buffer.from(blob).includes(Buffer.from('ATTACHMENT-CANARY')))).toBe(false);
    await sync(b.client);
    const m = b.client.messages(a.username).find((x) => x.attachments.length)!;
    const file = await b.client.downloadAttachment(a.username, m.id, m.attachments[0]!.attachmentId);
    expect(file.name).toBe('notes.txt');
    expect(Buffer.from(file.bytes).equals(Buffer.from(bytes))).toBe(true);
    // Cached locally; second open does not need the (now exhausted) server copy.
    const again = await b.client.downloadAttachment(a.username, m.id, m.attachments[0]!.attachmentId);
    expect(again.bytes.length).toBe(bytes.length);
  });

  it('read receipts and profile names are opt-in', async () => {
    const a = await registered(h);
    const b = await registered(h);
    await a.client.startConversation(b.username);
    await a.client.sendText(b.username, 'read me');
    await sync(b.client);
    await b.client.markRead(a.username);
    await sync(a.client);
    expect(a.client.messages(b.username).find((m) => m.text === 'read me')!.readByPeer).toBe(false);

    await a.client.updateSettings({ readReceipts: true });
    await b.client.updateSettings({ readReceipts: true, shareProfile: true, displayName: 'Bob' });
    await a.client.sendText(b.username, 'read me too');
    await sync(b.client);
    await b.client.markRead(a.username);
    await sync(a.client);
    expect(a.client.messages(b.username).find((m) => m.text === 'read me too')!.readByPeer).toBe(true);
    expect(a.client.snapshot().conversations.find((c) => c.peer === b.username)!.displayName).toBe('Bob');
  });
});

describe('account existence is never revealed', () => {
  it('starting a conversation with an unassigned name and sending looks exactly like a real, quiet contact', async () => {
    const a = await registered(h);
    const b = await registered(h);
    const ghost = 'QuietOtter';
    for (const peer of [b.username, ghost]) {
      await a.client.startConversation(peer);
      await a.client.sendText(peer, 'hello?');
    }
    const view = (peer: string) => {
      const conv = a.client.snapshot().conversations.find((c) => c.peer === peer)!;
      const msgs = a.client.messages(peer).map((m) => ({ direction: m.direction, status: m.status, notice: m.notice ?? null }));
      return { verification: conv.verification, accountGone: conv.accountGone, msgs };
    };
    expect(view(ghost)).toEqual(view(b.username));
    expect(a.client.messages(ghost).find((m) => m.notice === 'session-started')!.text).toMatch(/^If this person exists/);
    // Only malformed names can be refused, and that is decided locally from the public word lists.
    await expect(a.client.startConversation('NotAWordName')).rejects.toMatchObject({ code: 'invalid_input' });
  });
});

describe('malicious-server detection', () => {
  it('detects an identity key substitution and blocks sending until the user accepts', async () => {
    const a = await registered(h);
    const b = await registered(h);
    const mallory = await registered(h);
    await a.client.startConversation(b.username);
    await a.client.sendText(b.username, 'before');
    const safetyBefore = a.client.safetyNumber(b.username);
    // The server swaps Bob's identity for Mallory's keys under Bob's name.
    await h.server.db.query(
      `UPDATE identity.accounts SET identity_key = m.identity_key, device_list = m.device_list, device_list_sig = m.device_list_sig, device_list_version = m.device_list_version
       FROM identity.accounts m WHERE identity.accounts.username = $1 AND m.username = $2`,
      [b.username, mallory.username],
    );
    await a.client.refreshContact(b.username);
    const conv = a.client.snapshot().conversations.find((c) => c.peer === b.username)!;
    expect(conv.verification).toBe('key-changed');
    expect(a.client.safetyNumber(b.username)).not.toBe(safetyBefore);
    await expect(a.client.sendText(b.username, 'after')).rejects.toMatchObject({ code: 'key_changed' });
    expect(a.client.messages(b.username).some((m) => m.notice === 'key-changed')).toBe(true);
  });

  it('rejects a device the server injects into a contact without a valid signature', async () => {
    const a = await registered(h);
    const b = await registered(h);
    await a.client.startConversation(b.username);
    const row = await h.server.db.query<{ device_list: Uint8Array }>('SELECT device_list FROM identity.accounts WHERE username = $1', [b.username]);
    const forged = row.rows[0]!.device_list.slice();
    forged[forged.length - 3]! ^= 0xff; // modify a device key byte
    await h.server.db.query('UPDATE identity.accounts SET device_list = $1, device_list_version = device_list_version + 1 WHERE username = $2', [forged, b.username]);
    await expect(a.client.refreshContact(b.username)).rejects.toThrow();
  });
});

describe('multi-device', () => {
  it('links a second device by code comparison and syncs messages across all devices', async () => {
    const a = await registered(h);
    const b = await registered(h);
    const a2 = h.client();
    await a2.init();
    expect(await a2.signIn({ username: a.username, password: PASSWORD })).toBe('needs-link');
    const { code } = await a2.requestLink();
    const pending = await a.client.pendingLinks();
    expect(pending).toHaveLength(1);
    // A wrong code is refused before anything is signed or sent.
    await expect(a.client.approveLink(pending[0]!.linkId, '0000-0000-0000-0000')).rejects.toMatchObject({ code: 'crypto' });
    const waiting = a2.waitForLinkApproval();
    await a.client.approveLink(pending[0]!.linkId, code);
    await waiting;
    expect(a2.snapshot().status).toBe('ready');
    expect(a2.snapshot().isPrimary).toBe(false);
    expect((await a.client.devices()).length).toBe(2);

    await a.client.startConversation(b.username);
    await a.client.sendText(b.username, 'from a1');
    await sync(a2, b.client);
    expect(texts(a2, b.username)).toEqual(['out:from a1']);
    await b.client.sendText(a.username, 'to both');
    await sync(a.client, a2);
    expect(texts(a.client, b.username)).toEqual(['out:from a1', 'in:to both']);
    expect(texts(a2, b.username)).toEqual(['out:from a1', 'in:to both']);
    await a2.sendText(b.username, 'from a2');
    await sync(a.client, b.client);
    expect(texts(b.client, a.username)).toEqual(['in:from a1', 'out:to both', 'in:from a2']);
    expect(texts(a.client, b.username)).toEqual(['out:from a1', 'in:to both', 'out:from a2']);
  });

  it('a removed device loses access and its local data on next sign-in', async () => {
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
    const a2Id = a2.snapshot().deviceId!;
    await a.client.removeDevice(a2Id);
    await expect(a2.drain()).rejects.toBeInstanceOf(VeilError);
    await a2.lock();
    expect(await a2.signIn({ username: a.username, password: PASSWORD })).toBe('needs-link');
    expect((await a2Storage.keys('records')).length).toBe(0);
  });
});

describe('password change and recovery', () => {
  it('password change re-wraps the vault; the old password stops working', async () => {
    const a = await registered(h);
    await a.client.changePassword(PASSWORD, 'a brand new passphrase');
    await a.client.lock();
    await expect(a.client.signIn({ username: a.username, password: PASSWORD })).rejects.toMatchObject({ code: 'invalid_credentials' });
    expect(await a.client.signIn({ username: a.username, password: 'a brand new passphrase' })).toBe('ready');
  });

  it('restores the identity on a new device from the recovery key, keeping contacts and safety numbers', async () => {
    const a = await registered(h, { recovery: true });
    const b = await registered(h);
    await a.client.startConversation(b.username);
    await a.client.sendText(b.username, 'hi');
    await sync(b.client);
    const safety = b.client.safetyNumber(a.username);
    const fresh = h.client();
    await fresh.init();
    await fresh.signIn({ username: a.username, password: PASSWORD });
    await fresh.restoreWithRecoveryKey(a.recoveryKey!);
    expect(fresh.snapshot().isPrimary).toBe(true);
    expect(fresh.snapshot().conversations.map((c) => c.peer)).toEqual([b.username]);
    await fresh.sendText(b.username, 'restored');
    await sync(b.client);
    expect(texts(b.client, a.username)).toEqual(['in:hi', 'in:restored']);
    expect(b.client.safetyNumber(a.username)).toBe(safety); // identity unchanged: no key-change warning
  });

  it('a forgotten password is recoverable only with the recovery key', async () => {
    const a = await registered(h, { recovery: true });
    const other = h.client();
    await expect(other.recoverAccount({ username: a.username, recoveryKey: '0000-0000-0000-0000-0000-0000-0000-0000-0000-0000-0000-0000-0000', newPassword: 'new password 123' })).rejects.toBeInstanceOf(VeilError);
    await other.recoverAccount({ username: a.username, recoveryKey: a.recoveryKey!, newPassword: 'new password 123' });
    expect(other.snapshot().status).toBe('ready');
    await other.lock();
    expect(await other.signIn({ username: a.username, password: 'new password 123' })).toBe('ready');
    // The old device was signed out everywhere by the reset; its password no longer works on the server.
    await a.client.lock();
    await expect(a.client.signIn({ username: a.username, password: PASSWORD })).rejects.toBeInstanceOf(VeilError);
  });
});
