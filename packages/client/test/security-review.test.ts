// Independent security review: adversarial end-to-end tests of the client
// engine against the real server (in-process). Tests marked `// FINDING n`
// demonstrate a defect: they FAIL on the reviewed code and pass once fixed.
// Tests marked `// PROPERTY` check guarantees that hold today.
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  concat,
  decodeDeviceList,
  decodeLinkRequest,
  deviceEntryFor,
  fromB64,
  fromUtf8,
  generateAccountIdentity,
  generateDeviceKeys,
  initRatchetInitiator,
  open,
  openEnvelope,
  randomBytes,
  ratchetEncrypt,
  sealEnvelope,
  sealToPublicKey,
  signDeviceList,
  toB64,
  utf8,
  verifyDeviceList,
  x25519KeyPair,
  x3dhInitiate,
  type SignedDeviceList,
} from '@veil/crypto';
import { BundleResponse, SendResponse } from '@veil/shared';
import { MemoryStorage, type VeilClient } from '../src/index.js';
import { pad } from '../src/content.js';
import { PASSWORD, registered, startHarness, sync, texts, type Harness } from './helpers.js';

let h: Harness;
beforeEach(async () => {
  h = await startHarness();
});
afterEach(async () => {
  await h.close();
});

// ---------------------------------------------------------------- helpers

/* eslint-disable @typescript-eslint/no-explicit-any */
type Internals = { api: { json: (...args: unknown[]) => Promise<any> }; state: any; mutex: { run: (fn: () => Promise<unknown>) => Promise<unknown> }; sendContent: (...args: unknown[]) => Promise<void> };
const internals = (c: VeilClient) => c as unknown as Internals;

const jsonResponse = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
const listJson = (l: SignedDeviceList) => ({ body: toB64(l.body), signature: toB64(l.signature) });
const settle = () => new Promise((r) => setTimeout(r, 50));

async function registerWith(fetchImpl: typeof fetch, opts: { recovery?: boolean } = {}) {
  const storage = new MemoryStorage();
  const client = h.client({ storage, fetch: fetchImpl });
  await client.init();
  const s = await client.suggestUsername();
  const res = await client.register({ reservation: s.reservation, password: PASSWORD, enableRecovery: !!opts.recovery });
  return { client, storage, username: res.username, recoveryKey: res.recoveryKey };
}

async function linkDevice(primary: VeilClient, username: string) {
  const d = h.client();
  await d.init();
  await d.signIn({ username, password: PASSWORD });
  const { code } = await d.requestLink();
  const [p] = await primary.pendingLinks();
  const waiting = d.waitForLinkApproval();
  await primary.approveLink(p!.linkId, code);
  await waiting;
  return d;
}

async function devicesOf(username: string) {
  const r = await h.server.db.query<{ id: Uint8Array; dh_key: Uint8Array }>(
    'SELECT d.id, d.dh_key FROM keys.devices d JOIN identity.accounts a ON a.id = d.account_id WHERE a.username = $1',
    [username],
  );
  return r.rows;
}

/** Any registered user may submit arbitrary sealed envelopes to any device id. */
async function sendRaw(from: VeilClient, deviceId: Uint8Array, payload: Uint8Array) {
  await internals(from).api.json(
    'POST',
    '/v1/messages',
    { envelopes: [{ deviceId: toB64(deviceId), envelopeId: toB64(randomBytes(16)), payload: toB64(payload) }] },
    SendResponse,
  );
}

/** A sealed envelope with an arbitrary claimed sender and an undecryptable inner message. */
function junkEnvelope(device: { id: Uint8Array; dh_key: Uint8Array }, senderUsername: string) {
  return sealEnvelope(device.id, device.dh_key, {
    senderUsername,
    senderDeviceId: randomBytes(16),
    inner: { kind: 'ratchet', message: { header: { dh: x25519KeyPair().publicKey, pn: 0, n: 0 }, ciphertext: randomBytes(64) } },
  });
}

const conv = (c: VeilClient, peer: string) => c.snapshot().conversations.find((x) => x.peer === peer);

/** Records an attacker can read: anything sealed under the all-zero record key / index key. */
async function zeroKeyPlaintexts(storage: MemoryStorage): Promise<string[]> {
  const zero = new Uint8Array(32);
  const out: string[] = [];
  for (const name of await storage.keys('records')) {
    const value = (await storage.get('records', name))!;
    try {
      out.push(fromUtf8(open(zero, value, concat(utf8('VEIL/v1/vault-record'), utf8(name)))));
    } catch {
      // properly encrypted record
    }
  }
  return out;
}

async function swapIdentity(victim: string, attacker: string) {
  await h.server.db.query(
    `UPDATE identity.accounts SET identity_key = m.identity_key, device_list = m.device_list, device_list_sig = m.device_list_sig, device_list_version = m.device_list_version
     FROM identity.accounts m WHERE identity.accounts.username = $1 AND m.username = $2`,
    [victim, attacker],
  );
}

// ================================================================ findings

describe('FINDING 1: the vault keeps accepting writes after lock()/Panic Reset, sealed under an all-zero key', () => {
  // FINDING 1
  it('a lock() while a send is in flight writes the conversation plaintext under a publicly known key', async () => {
    let armed = false;
    let victim: VeilClient | null = null;
    const f: typeof fetch = async (input, init) => {
      if (armed && String(input).endsWith('/v1/messages') && init?.method === 'POST') {
        armed = false;
        void victim!.lock(); // auto-lock, a WS 'revoked' frame or onSessionLost firing mid-request
      }
      return fetch(input, init);
    };
    const a = await registerWith(f);
    victim = a.client;
    const b = await registered(h);
    await a.client.startConversation(b.username);
    armed = true;
    await a.client.sendText(b.username, 'ZERO-KEY-CANARY').catch(() => {});
    await settle();
    const readable = await zeroKeyPlaintexts(a.storage);
    expect(readable.filter((p) => p.includes('ZERO-KEY-CANARY'))).toEqual([]);
    expect(readable).toEqual([]);
  });

  // FINDING 1
  it('Panic Reset reports a verified local wipe, then an in-flight receive re-creates readable records', async () => {
    let block = false;
    let release!: () => void;
    let reached!: () => void;
    const reachedP = new Promise<void>((r) => (reached = r));
    const f: typeof fetch = async (input, init) => {
      if (block && String(input).includes('/v1/directory/')) {
        block = false;
        const res = await fetch(input, init); // the server answers before the reset...
        reached();
        await new Promise<void>((r) => (release = r)); // ...but the response is slow to arrive
        return res;
      }
      return fetch(input, init);
    };
    const a = await registerWith(f);
    const b = await registered(h);
    await b.client.startConversation(a.username);
    await b.client.sendText(a.username, 'RESET-RACE-CANARY');
    block = true;
    const draining = a.client.drain().catch(() => {});
    await reachedP;
    const report = await a.client.panicReset({ createNewIdentity: false }, () => {});
    expect(report.phase).toBe('completed');
    expect(report.localWiped).toBe(true);
    release();
    await draining;
    await settle();
    expect({ records: (await a.storage.keys('records')).length, readable: await zeroKeyPlaintexts(a.storage) }).toEqual({ records: 0, readable: [] });
  });
});

describe('FINDING 2: provisioning payloads are not authenticated to the new device', () => {
  // FINDING 2
  it('a malicious server enrolls a new device under its own identity key with forged "verified" contacts, without any approval', async () => {
    const a = await registered(h);
    const b = await registered(h);
    const attackerAik = generateAccountIdentity();
    const fakeBobAik = generateAccountIdentity();
    const fakeBobList = signDeviceList(fakeBobAik.privateKey, { identityKey: fakeBobAik.publicKey, version: 1, devices: [deviceEntryFor(generateDeviceKeys(), true)] });
    let request: Uint8Array | null = null;
    let forgedList: { body: string; signature: string } | null = null;
    const evil: typeof fetch = async (input, init) => {
      const p = new URL(String(input)).pathname;
      const method = init?.method ?? 'GET';
      if (method === 'POST' && p === '/v1/link/requests') {
        request = fromB64(JSON.parse(String(init!.body)).request as string);
        const r = decodeLinkRequest(request);
        forgedList = listJson(
          signDeviceList(attackerAik.privateKey, { identityKey: attackerAik.publicKey, version: 1, devices: [{ deviceId: r.deviceId, signingKey: r.signingKey, dhKey: r.dhKey, primary: false }] }),
        );
        return fetch(input, init);
      }
      if (!request) return fetch(input, init);
      // From here on the server answers the new device with forged data. It only needs the
      // link request it relayed: the provisioning box is a sealed box to a key it knows.
      if (method === 'GET' && p.startsWith('/v1/link/requests/')) {
        const payload = {
          v: 1,
          username: a.username,
          identityKey: toB64(attackerAik.publicKey),
          deviceList: forgedList,
          profileKey: toB64(randomBytes(32)),
          contacts: [{ username: b.username, identityKey: toB64(fakeBobAik.publicKey), verified: true, clock: 0 }],
          settings: { readReceipts: false, shareProfile: false, displayName: '' },
        };
        // The server does not know the code shown on the new device; its best attempt
        // is to seal to the provisioning key and append a MAC under a guessed code.
        const sealed = sealToPublicKey(decodeLinkRequest(request).provisioningKey, utf8(JSON.stringify(payload)), 'VEIL/v1/provisioning', request);
        return jsonResponse(200, { status: 'approved', payload: toB64(concat(sealed, randomBytes(32))) });
      }
      if (p === '/v1/account') return jsonResponse(200, { username: a.username, identityKey: toB64(attackerAik.publicKey), deviceList: forgedList, recoveryEnabled: false, profile: null });
      if (p === '/v1/devices/enroll') {
        const body = JSON.parse(String(init!.body));
        return jsonResponse(200, { accessToken: 'x', refreshToken: 'y', accessExpiresIn: 600, kind: 'device', username: a.username, deviceId: body.device.deviceId });
      }
      if (p === `/v1/directory/${b.username}`) return jsonResponse(200, { username: b.username, identityKey: toB64(fakeBobAik.publicKey), deviceList: listJson(fakeBobList), profile: null });
      if (p === '/v1/keys/status') return jsonResponse(200, { oneTimePreKeys: 100, signedPreKeyId: 1 });
      if (p === '/v1/mailbox') return jsonResponse(200, { envelopes: [], more: false });
      return fetch(input, init);
    };
    const n = h.client({ fetch: evil });
    await n.init();
    expect(await n.signIn({ username: a.username, password: PASSWORD })).toBe('needs-link');
    await n.requestLink();
    // Nobody approves anything on the primary device.
    const outcome = await n.waitForLinkApproval().then(
      () => `enrolled; ${b.username} pinned to the attacker's key and shown as ${conv(n, b.username)?.verification}`,
      () => 'rejected',
    );
    expect(outcome).toBe('rejected');
  });
});

describe('FINDING 3: unauthenticated sender names create or overwrite pinned contacts before any decryption', () => {
  // FINDING 3
  it('a third party resets a verified contact to unverified with one junk envelope (case-variant username)', async () => {
    const a = await registered(h);
    const b = await registered(h);
    const mallory = await registered(h);
    await a.client.startConversation(b.username);
    await a.client.setVerified(b.username, true);
    const [dev] = await devicesOf(a.username);
    await sendRaw(mallory.client, dev!.id, junkEnvelope(dev!, b.username.toLowerCase()));
    await sync(a.client);
    expect(conv(a.client, b.username)!.verification).toBe('verified');
  });

  // FINDING 3
  it('the same trick silently re-pins a substituted identity key and lifts the key-change send block', async () => {
    const a = await registered(h);
    const b = await registered(h);
    const mallory = await registered(h);
    await a.client.startConversation(b.username);
    await a.client.sendText(b.username, 'before');
    await swapIdentity(b.username, mallory.username); // malicious server substitutes Bob's identity
    await a.client.refreshContact(b.username);
    expect(conv(a.client, b.username)!.verification).toBe('key-changed');
    const [dev] = await devicesOf(a.username);
    await sendRaw(mallory.client, dev!.id, junkEnvelope(dev!, b.username.toLowerCase()));
    await sync(a.client);
    expect(conv(a.client, b.username)!.verification).toBe('key-changed');
  });

  // FINDING 3
  it('an envelope merely claiming to come from a stranger creates a conversation with that stranger', async () => {
    const a = await registered(h);
    const carol = await registered(h);
    const mallory = await registered(h);
    const [dev] = await devicesOf(a.username);
    await sendRaw(mallory.client, dev!.id, junkEnvelope(dev!, carol.username));
    await sync(a.client);
    expect(a.client.snapshot().conversations.map((c) => c.peer)).not.toContain(carol.username);
  });
});

describe('FINDING 4: transient failures while resolving a sender drop the envelope and acknowledge it', () => {
  // FINDING 4
  it('a rate-limited directory lookup permanently loses the first message from a new contact', async () => {
    let failDirectory = false;
    const f: typeof fetch = async (input, init) => {
      if (failDirectory && String(input).includes('/v1/directory/')) return jsonResponse(429, { error: { code: 'rate_limited', message: 'slow down' } });
      return fetch(input, init);
    };
    const a = await registerWith(f);
    const b = await registered(h);
    await b.client.startConversation(a.username);
    await b.client.sendText(a.username, 'first contact');
    failDirectory = true; // e.g. after a flood of forged envelopes burned the 300/h directory budget
    await a.client.drain().catch(() => {});
    failDirectory = false;
    await sync(a.client);
    expect(texts(a.client, b.username)).toEqual(['in:first contact']);
  });
});

describe('FINDING 5: a contact-chosen Lamport clock breaks recovery and device linking', () => {
  // FINDING 5
  it('after a contact sends clock > 2^50, the recovery backup no longer restores', async () => {
    const a = await registered(h, { recovery: true });
    const b = await registered(h);
    await a.client.startConversation(b.username);
    await a.client.sendText(b.username, 'hi');
    await sync(b.client);
    // Bob's client is malicious: a clock that the Content schema accepts (<= 2^53-1) but ContactSnapshot does not (<= 2^50).
    internals(b.client).state.contacts.get(a.username).clock = 2 ** 51;
    await b.client.sendText(a.username, 'tick');
    await sync(a.client);
    await a.client.setVerified(b.username, true); // any action that refreshes the recovery backup
    const fresh = h.client();
    await fresh.init();
    await fresh.signIn({ username: a.username, password: PASSWORD });
    const outcome = await fresh.restoreWithRecoveryKey(a.recoveryKey!).then(
      () => 'restored',
      (e) => `failed: ${(e as Error).message}`,
    );
    expect(outcome).toBe('restored');
  });
});

describe('FINDING 6: device-list rollback through recovery, and equal-version forks', () => {
  // FINDING 6
  it('restoring from the recovery key against a rolled-back list re-certifies a removed (stolen) device', async () => {
    const a = await registered(h, { recovery: true });
    const a2 = await linkDevice(a.client, a.username);
    const stolenId = a2.snapshot().deviceId!;
    const stale = (await h.server.db.query<{ device_list: Uint8Array; device_list_sig: Uint8Array }>('SELECT device_list, device_list_sig FROM identity.accounts WHERE username = $1', [a.username])).rows[0]!;
    await a.client.removeDevice(stolenId);
    let certified: string[] | null = null;
    const f: typeof fetch = async (input, init) => {
      const p = new URL(String(input)).pathname;
      if (p === '/v1/account' && (init?.method ?? 'GET') === 'GET') {
        const body = await (await fetch(input, init)).json();
        body.deviceList = { body: toB64(stale.device_list), signature: toB64(stale.device_list_sig) }; // rollback
        return jsonResponse(200, body);
      }
      if (p === '/v1/devices/enroll') {
        certified = decodeDeviceList(fromB64(JSON.parse(String(init!.body)).deviceList.body)).devices.map((d) => toB64(d.deviceId));
      }
      return fetch(input, init);
    };
    const r = h.client({ fetch: f });
    await r.init();
    await r.signIn({ username: a.username, password: PASSWORD });
    await r.restoreWithRecoveryKey(a.recoveryKey!).catch(() => {});
    expect(certified ?? []).not.toContain(stolenId);
  });

  // FINDING 6
  it('a contact accepts a different device list with the same version (fork) and adds its device', async () => {
    const a = await registered(h);
    const b = await registered(h);
    await a.client.startConversation(b.username);
    const bi = internals(b.client).state.identity;
    const current = verifyDeviceList({ body: fromB64(bi.deviceList.body), signature: fromB64(bi.deviceList.signature) }, fromB64(bi.identityKey));
    const fork = signDeviceList(fromB64(bi.identityPrivateKey), {
      identityKey: current.identityKey,
      version: current.version,
      devices: [...current.devices, deviceEntryFor(generateDeviceKeys(), false)],
    });
    await h.server.db.query('UPDATE identity.accounts SET device_list = $1, device_list_sig = $2 WHERE username = $3', [fork.body, fork.signature, b.username]);
    await a.client.refreshContact(b.username).catch(() => {});
    expect(a.client.messages(b.username).filter((m) => m.notice === 'device-added')).toEqual([]);
  });
});

describe('FINDING 7: Panic Reset is unavailable from a password-only session', () => {
  // FINDING 7
  it('a user whose devices are gone cannot delete the account from a new device, as the docs and reset report promise', async () => {
    const a = await registered(h);
    const n = h.client();
    await n.init();
    expect(await n.signIn({ username: a.username, password: PASSWORD })).toBe('needs-link');
    const outcome = await n.panicReset({ createNewIdentity: false }, () => {}).then(
      (r) => r.phase,
      (e) => `threw ${(e as { code?: string }).code}`,
    );
    expect(outcome).toBe('completed');
  });
});

describe('FINDING 8: deleting a conversation silently black-holes the contact', () => {
  // FINDING 8
  it('messages sent after the recipient deleted the conversation are dropped without any error', async () => {
    const a = await registered(h);
    const b = await registered(h);
    await a.client.startConversation(b.username);
    await a.client.sendText(b.username, 'hi');
    await sync(b.client);
    await b.client.sendText(a.username, 'hey');
    await sync(a.client);
    await b.client.deleteConversation(a.username);
    await a.client.sendText(b.username, 'are you there?'); // reported as 'sent' to Alice
    await sync(b.client);
    expect(texts(b.client, a.username)).toContain('in:are you there?');
  });
});

describe('FINDING 9: an own-device contact sync can leave a device stuck in key-changed', () => {
  // FINDING 9
  it('after accepting a key change on one device, the other device can never send again', async () => {
    const a = await registered(h);
    const a2 = await linkDevice(a.client, a.username);
    const b = await registered(h);
    const mallory = await registered(h);
    // approveLink() leaves the primary's own list stale and syncContactToOwnDevices() does not refresh it,
    // so without this the new contact would never be synced to a2.
    await a.client.devices();
    await a.client.startConversation(b.username);
    await sync(a2);
    await swapIdentity(b.username, mallory.username);
    await a.client.refreshContact(b.username);
    await a2.refreshContact(b.username);
    expect(conv(a2, b.username)!.verification).toBe('key-changed');
    await a.client.acceptKeyChange(b.username);
    await sync(a2);
    await a2.acceptKeyChange(b.username); // a no-op: pendingIdentityKey was cleared by the sync
    expect(conv(a2, b.username)!.verification).toBe(conv(a.client, b.username)!.verification);
  });
});

describe('FINDING 10: resumeReset claims completion without server evidence', () => {
  // FINDING 10
  it('a reset flag without vault metadata yields phase "completed" although the account still exists', async () => {
    const a = await registered(h);
    await a.client.lock();
    await a.storage.delete('meta', 'vault');
    await a.storage.put('meta', 'reset-pending', new Uint8Array([1]));
    const c = h.client({ storage: a.storage });
    await c.init();
    expect(c.snapshot().status).toBe('reset-pending');
    const report = await c.resumeReset(PASSWORD, () => {});
    const still = (await h.server.db.query<{ n: number }>('SELECT count(*)::int AS n FROM identity.accounts WHERE username = $1', [a.username])).rows[0]!.n;
    expect(still).toBe(1);
    expect(report.phase).not.toBe('completed');
  });
});

// ================================================================ properties that hold

describe('properties', () => {
  // PROPERTY
  it("'contact' and 'sent' sync content from a contact (not an own device) is ignored", async () => {
    const a = await registered(h);
    const b = await registered(h);
    const carol = await registered(h);
    await a.client.startConversation(b.username);
    await a.client.sendText(b.username, 'hi');
    await sync(b.client);
    const bi = internals(b.client);
    const contactA = bi.state.contacts.get(a.username);
    await bi.sendContent(bi.state, contactA, { v: 1, t: 'contact', username: carol.username, identityKey: toB64(randomBytes(32)), verified: true }, null);
    await bi.sendContent(bi.state, contactA, { v: 1, t: 'sent', to: carol.username, id: toB64(randomBytes(16)), clock: 5, text: 'forged transcript', att: [] }, null);
    await sync(a.client);
    expect(a.client.snapshot().conversations.map((c) => c.peer)).toEqual([b.username]);
  });

  // PROPERTY
  it('a replayed initial message without a one-time prekey is rejected and creates no second session', async () => {
    const a = await registered(h);
    const b = await registered(h);
    await internals(b.client).mutex.run(async () => {}); // let prekey maintenance finish
    await h.server.db.query(
      'DELETE FROM keys.one_time_prekeys WHERE device_id IN (SELECT d.id FROM keys.devices d JOIN identity.accounts x ON x.id = d.account_id WHERE x.username = $1)',
      [b.username],
    );
    await a.client.startConversation(b.username);
    await a.client.sendText(b.username, 'no otk');
    const env = (await h.server.db.query<{ device_id: Uint8Array; payload: Uint8Array; expires_day: number }>('SELECT device_id, payload, expires_day FROM mailbox.envelopes')).rows[0]!;
    const bDev = internals(b.client).state.identity.device;
    const opened = openEnvelope(fromB64(bDev.id), { publicKey: fromB64(bDev.dhPub), privateKey: fromB64(bDev.dhPriv) }, env.payload);
    expect(opened.inner.kind === 'prekey' && opened.inner.prekey.oneTimePreKeyId).toBe(undefined);
    await sync(b.client);
    const seq = await h.server.db.query<{ s: string }>('UPDATE keys.devices SET mailbox_seq = mailbox_seq + 1 WHERE id = $1 RETURNING mailbox_seq::text AS s', [env.device_id]);
    await h.server.db.query('INSERT INTO mailbox.envelopes (device_id, envelope_id, seq, payload, expires_day) VALUES ($1, $2, $3, $4, $5)', [
      env.device_id,
      randomBytes(16),
      seq.rows[0]!.s,
      env.payload,
      env.expires_day,
    ]);
    await sync(b.client);
    const rec = internals(b.client).state.sessions.get(`${a.username}/${a.client.snapshot().deviceId}`);
    expect(rec.previous).toHaveLength(0);
    expect(texts(b.client, a.username)).toEqual(['in:no otk']);
  });

  // PROPERTY
  it("a contact cannot pose as one of the user's own devices to inject a 'sent' transcript", async () => {
    const a = await registered(h);
    const a2 = await linkDevice(a.client, a.username);
    const b = await registered(h);
    await a.client.startConversation(b.username);
    await a.client.devices(); // a1 learns the list that includes a2
    const a1Id = a.client.snapshot().deviceId!;
    const a2Id = a2.snapshot().deviceId!;
    const bundle = await internals(b.client).api.json('POST', '/v1/keys/bundles', { username: a.username, deviceIds: [a1Id] }, BundleResponse);
    const aik = fromB64(bundle.identityKey);
    const list = verifyDeviceList({ body: fromB64(bundle.deviceList.body), signature: fromB64(bundle.deviceList.signature) }, aik);
    const a1 = list.devices.find((d) => toB64(d.deviceId) === a1Id)!;
    const a2Entry = list.devices.find((d) => toB64(d.deviceId) === a2Id)!;
    const bb = bundle.bundles[0]!;
    // Bob claims a2's public identity but can only use his own private key.
    const init = x3dhInitiate(
      { identityKey: aik, deviceId: a2Entry.deviceId, dh: { publicKey: a2Entry.dhKey, privateKey: x25519KeyPair().privateKey } },
      {
        identityKey: aik,
        deviceId: a1.deviceId,
        deviceSigningKey: a1.signingKey,
        deviceDhKey: a1.dhKey,
        signedPreKey: { keyId: bb.signedPreKey.keyId, publicKey: fromB64(bb.signedPreKey.publicKey), signature: fromB64(bb.signedPreKey.signature) },
        oneTimePreKey: bb.oneTimePreKey ? { keyId: bb.oneTimePreKey.keyId, publicKey: fromB64(bb.oneTimePreKey.publicKey) } : undefined,
      },
    );
    const ratchet = initRatchetInitiator(init.sharedKey, init.remoteSignedPreKey, init.associatedData);
    const message = ratchetEncrypt(ratchet, pad({ v: 1, t: 'sent', to: b.username, id: toB64(randomBytes(16)), clock: 99, text: 'FORGED-OWN', att: [] }));
    const env = sealEnvelope(a1.deviceId, a1.dhKey, {
      senderUsername: a.username,
      senderDeviceId: a2Entry.deviceId,
      inner: { kind: 'prekey', prekey: { senderIdentityKey: aik, senderDhKey: a2Entry.dhKey, baseKey: init.baseKey, signedPreKeyId: init.signedPreKeyId, oneTimePreKeyId: init.oneTimePreKeyId, message } },
    });
    await sendRaw(b.client, a1.deviceId, env);
    await sync(a.client);
    expect(texts(a.client, b.username)).not.toContain('out:FORGED-OWN');
  });

  // PROPERTY
  it('tokens and plaintext never reach the meta store', async () => {
    const a = await registered(h);
    const b = await registered(h);
    await a.client.startConversation(b.username);
    await a.client.sendText(b.username, 'META-CANARY');
    const metaKeys = await a.storage.keys('meta');
    expect(metaKeys.sort()).toEqual(['vault']);
    const meta = JSON.parse(fromUtf8((await a.storage.get('meta', 'vault'))!));
    expect(Object.keys(meta).sort()).toEqual(['clientSalt', 'kdf', 'v', 'wrappedDek']);
  });
});
