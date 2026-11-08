// Authorization and cross-account isolation: every protected resource must
// be reachable only by the account (and session kind) it belongs to.
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { deviceEntryFor, encodeLinkRequest, generateAccountIdentity, generateLinkSecret, generateDeviceKeys, randomBytes, toB64, x25519KeyPair } from '@veil/crypto';
import { type Harness, envelope, linkNewDevice, login, prekeysFor, publicDevice, register, signList, startHarness } from './helpers.js';

let h: Harness;
beforeEach(async () => {
  h = await startHarness();
});
afterEach(async () => {
  await h.close();
});

describe('cross-account isolation', () => {
  it('a device can only read and acknowledge its own mailbox', async () => {
    const alice = await register(h);
    const bob = await register(h);
    const env = envelope(bob.devices[0]!.keys.deviceId);
    expect((await h.call('POST', '/v1/messages', { token: alice.token, body: { envelopes: [env] } })).json.accepted).toBe(1);
    // Alice's mailbox is empty; she cannot see or ack Bob's envelope.
    expect((await h.call('GET', '/v1/mailbox', { token: alice.token })).json.envelopes).toEqual([]);
    expect((await h.call('POST', '/v1/mailbox/ack', { token: alice.token, body: { envelopeIds: [env.envelopeId] } })).status).toBe(204);
    const bobBox = await h.call('GET', '/v1/mailbox', { token: bob.token });
    expect(bobBox.json.envelopes).toHaveLength(1);
    expect(bobBox.json.envelopes[0].payload).toBe(env.payload);
  });

  it('sessions of other accounts cannot be listed or deleted', async () => {
    const alice = await register(h);
    const bob = await register(h);
    const bobSessions = await h.call('GET', '/v1/sessions', { token: bob.token });
    const target = bobSessions.json.sessions[0].sessionId;
    expect((await h.call('GET', '/v1/sessions', { token: alice.token })).json.sessions).toHaveLength(1);
    expect((await h.call('DELETE', `/v1/sessions/${target}`, { token: alice.token })).status).toBe(404);
    expect((await h.call('GET', '/v1/account', { token: bob.token })).status).toBe(200);
  });

  it('link requests of another account cannot be seen, answered, read or deleted', async () => {
    const alice = await register(h);
    const bob = await register(h);
    const link = await login(h, bob);
    const keys = generateDeviceKeys();
    const req = encodeLinkRequest({ deviceId: keys.deviceId, signingKey: keys.signing.publicKey, dhKey: keys.dh.publicKey, provisioningKey: x25519KeyPair().publicKey }, generateLinkSecret());
    const created = await h.call('POST', '/v1/link/requests', { token: link.json.accessToken, body: { request: toB64(req) } });
    const linkId = created.json.linkId;
    expect((await h.call('GET', '/v1/link/requests', { token: alice.token })).json.requests).toEqual([]);
    expect((await h.call('POST', `/v1/link/requests/${linkId}/response`, { token: alice.token, body: { payload: toB64(randomBytes(10)) } })).status).toBe(404);
    expect((await h.call('DELETE', `/v1/link/requests/${linkId}`, { token: alice.token })).status).toBe(404);
    const aliceLink = await login(h, alice);
    expect((await h.call('GET', `/v1/link/requests/${linkId}`, { token: aliceLink.json.accessToken })).status).toBe(404);
    expect((await h.call('GET', `/v1/link/requests/${linkId}`, { token: link.json.accessToken })).json.status).toBe('pending');
  });

  it('cannot enroll a device into another account or with a list signed by another identity', async () => {
    const alice = await register(h);
    const bob = await register(h);
    const aliceLink = await login(h, alice);
    const keys = generateDeviceKeys();
    // Signed by Alice's own key, but includes Bob's devices → rejected (Bob's identity key is not Alice's).
    const forBob = signList(bob, 2, [deviceEntryFor(bob.devices[0]!.keys, true), deviceEntryFor(keys, false)]);
    const r1 = await h.call('POST', '/v1/devices/enroll', { token: aliceLink.json.accessToken, body: { deviceList: forBob, device: publicDevice(keys), ...prekeysFor(keys) } });
    expect(r1.status).toBe(400);
    // Attacker identity signing a list for Alice's account → rejected.
    const evil = generateAccountIdentity();
    const forged = signList({ aik: evil }, 2, [deviceEntryFor(alice.devices[0]!.keys, true), deviceEntryFor(keys, false)]);
    const r2 = await h.call('POST', '/v1/devices/enroll', { token: aliceLink.json.accessToken, body: { deviceList: forged, device: publicDevice(keys), ...prekeysFor(keys) } });
    expect(r2.status).toBe(400);
    // Device sessions cannot enroll (only link sessions).
    const valid = signList(alice, 2, [deviceEntryFor(alice.devices[0]!.keys, true), deviceEntryFor(keys, false)]);
    const r3 = await h.call('POST', '/v1/devices/enroll', { token: alice.token, body: { deviceList: valid, device: publicDevice(keys), ...prekeysFor(keys) } });
    expect(r3.status).toBe(403);
  });

  it("cannot replace another account's device list; forged signatures and rollbacks are rejected", async () => {
    const alice = await register(h);
    const bob = await register(h);
    await linkNewDevice(h, alice); // version 2
    const primary = alice.devices[0]!.keys;
    // Bob submits Alice's validly signed list to his own account: identity key mismatch.
    const aliceList = signList(alice, 3, [deviceEntryFor(primary, true)]);
    expect((await h.call('PUT', '/v1/devices/list', { token: bob.token, body: { deviceList: aliceList } })).status).toBe(400);
    // Forged signature.
    const evil = signList({ aik: generateAccountIdentity() }, 3, [deviceEntryFor(primary, true)]);
    expect((await h.call('PUT', '/v1/devices/list', { token: alice.token, body: { deviceList: evil } })).status).toBe(400);
    // Version rollback / replay.
    const old = signList(alice, 2, [deviceEntryFor(primary, true)]);
    expect((await h.call('PUT', '/v1/devices/list', { token: alice.token, body: { deviceList: old } })).status).toBe(409);
    // Adding a device via PUT is not allowed (only removals).
    const extra = generateDeviceKeys();
    const add = signList(alice, 3, [deviceEntryFor(primary, true), deviceEntryFor(alice.devices[1]!.keys, false), deviceEntryFor(extra, false)]);
    expect((await h.call('PUT', '/v1/devices/list', { token: alice.token, body: { deviceList: add } })).status).toBe(400);
  });
});

describe('session kind scoping', () => {
  it('a password-only link session cannot read mailboxes, send, fetch keys or change devices', async () => {
    const alice = await register(h);
    const bob = await register(h);
    const link = (await login(h, alice)).json.accessToken;
    const forbidden = [
      await h.call('GET', '/v1/mailbox', { token: link }),
      await h.call('POST', '/v1/messages', { token: link, body: { envelopes: [envelope(bob.devices[0]!.keys.deviceId)] } }),
      await h.call('POST', '/v1/keys/bundles', { token: link, body: { username: bob.username } }),
      await h.call('GET', `/v1/directory/${bob.username}`, { token: link }),
      await h.call('PUT', '/v1/devices/list', { token: link, body: { deviceList: signList(alice, 2, [deviceEntryFor(alice.devices[0]!.keys, true)]) } }),
      await h.call('GET', '/v1/account/export', { token: link }),
      await h.call('PUT', '/v1/recovery', { token: link, body: { verifierKey: toB64(randomBytes(32)), backup: toB64(randomBytes(8)) } }),
    ];
    for (const r of forbidden) expect(r.status).toBe(403);
    // Allowed for link sessions:
    expect((await h.call('GET', '/v1/account', { token: link })).status).toBe(200);
    expect((await h.call('GET', '/v1/sessions', { token: link })).status).toBe(200);
  });

  it('device sessions cannot create link requests and unauthenticated calls are rejected', async () => {
    const alice = await register(h);
    expect((await h.call('POST', '/v1/link/requests', { token: alice.token, body: { request: toB64(randomBytes(10)) } })).status).toBe(403);
    expect((await h.call('GET', '/v1/mailbox')).status).toBe(401);
    expect((await h.call('GET', '/v1/mailbox', { token: 'va1.garbage.garbage' })).status).toBe(401);
  });
});

describe('device linking', () => {
  it('links a device end to end; only the primary may approve; secondary can self-remove', async () => {
    const alice = await register(h);
    const second = await linkNewDevice(h, alice);
    expect(second.session!.kind).toBe('device');
    const acct = await h.call('GET', '/v1/account', { token: alice.token });
    expect(acct.json.deviceList.body).toBeTruthy();
    expect((await h.call('GET', '/v1/link/requests', { token: alice.token })).json.requests).toEqual([]);

    // A secondary device cannot approve link requests.
    const link = await login(h, alice);
    const keys = generateDeviceKeys();
    const req = encodeLinkRequest({ deviceId: keys.deviceId, signingKey: keys.signing.publicKey, dhKey: keys.dh.publicKey, provisioningKey: x25519KeyPair().publicKey }, generateLinkSecret());
    const created = await h.call('POST', '/v1/link/requests', { token: link.json.accessToken, body: { request: toB64(req) } });
    const r = await h.call('POST', `/v1/link/requests/${created.json.linkId}/response`, { token: second.session!.accessToken, body: { payload: toB64(randomBytes(10)) } });
    expect(r.status).toBe(403);

    // The primary cannot remove itself; the secondary can.
    expect((await h.call('DELETE', '/v1/devices/self', { token: alice.token })).status).toBe(409);
    expect((await h.call('DELETE', '/v1/devices/self', { token: second.session!.accessToken })).status).toBe(204);
    expect((await h.call('GET', '/v1/mailbox', { token: second.session!.accessToken })).status).toBe(401);
  });

  it('removing a device via a newer signed list deletes it and its sessions', async () => {
    const alice = await register(h);
    const second = await linkNewDevice(h, alice);
    await h.call('POST', '/v1/messages', { token: alice.token, body: { envelopes: [envelope(second.keys.deviceId)] } });
    const list = signList(alice, alice.listVersion + 1, [deviceEntryFor(alice.devices[0]!.keys, true)]);
    expect((await h.call('PUT', '/v1/devices/list', { token: alice.token, body: { deviceList: list } })).status).toBe(204);
    expect((await h.call('GET', '/v1/mailbox', { token: second.session!.accessToken })).status).toBe(401);
    const left = await h.db.query<{ n: number }>('SELECT count(*)::int AS n FROM mailbox.envelopes');
    expect(Number(left.rows[0]!.n)).toBe(0);
    // Sending to the removed device reports it as unknown.
    const send = await h.call('POST', '/v1/messages', { token: alice.token, body: { envelopes: [envelope(second.keys.deviceId)] } });
    expect(send.json.unknownDevices).toEqual([toB64(second.keys.deviceId)]);
  });

  it('link requests expire after their short lifetime', async () => {
    const alice = await register(h);
    const link = await login(h, alice);
    const keys = generateDeviceKeys();
    const req = encodeLinkRequest({ deviceId: keys.deviceId, signingKey: keys.signing.publicKey, dhKey: keys.dh.publicKey, provisioningKey: x25519KeyPair().publicKey }, generateLinkSecret());
    const created = await h.call('POST', '/v1/link/requests', { token: link.json.accessToken, body: { request: toB64(req) } });
    h.clock.t += 11 * 60 * 1000;
    const fresh = await h.call('POST', '/v1/auth/refresh', { body: { refreshToken: alice.refreshToken } });
    expect((await h.call('GET', '/v1/link/requests', { token: fresh.json.accessToken })).json.requests).toEqual([]);
    await h.server.sweep();
    expect(Number((await h.db.query<{ n: number }>('SELECT count(*)::int AS n FROM keys.link_requests')).rows[0]!.n)).toBe(0);
    void created;
  });
});
