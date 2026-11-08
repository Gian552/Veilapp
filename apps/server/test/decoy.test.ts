// Account-existence hiding: for any well-formed username, the directory, the
// prekey-bundle endpoint and the send endpoint behave the same whether or not
// an account exists. Unassigned names are served deterministic decoys.
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { fromB64, randomBytes, toB64, verifyDeviceList, verifySignedPreKey } from '@veil/crypto';
import { type Harness, envelope, register, startHarness } from './helpers.js';

let h: Harness;
beforeEach(async () => {
  h = await startHarness();
});
afterEach(async () => {
  await h.close();
});

/** Structural fingerprint of a JSON value: keys and value types/lengths, no contents. */
function shape(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(shape);
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).sort().map(([k, x]) => [k, shape(x)]));
  if (typeof v === 'string') return `string:${v.length}`;
  return typeof v;
}

describe('decoy accounts', () => {
  it('directory answers for unassigned names exactly like for a real one-device account', async () => {
    const alice = await register(h);
    const bob = await register(h);
    const real = await h.call('GET', `/v1/directory/${bob.username}`, { token: alice.token });
    const decoy = await h.call('GET', '/v1/directory/QuietOtter', { token: alice.token });
    expect(real.status).toBe(200);
    expect(decoy.status).toBe(200);
    // Usernames differ in length by nature; everything else must have the same shape.
    expect(shape({ ...decoy.json, username: '' })).toEqual(shape({ ...real.json, username: '' }));
    expect(decoy.json.username).toBe('QuietOtter');
    // Real, correctly signed keys: a client cannot tell them apart by verifying.
    const list = verifyDeviceList({ body: fromB64(decoy.json.deviceList.body), signature: fromB64(decoy.json.deviceList.signature) }, fromB64(decoy.json.identityKey));
    expect(list.devices).toHaveLength(1);
    expect(list.version).toBe(1);
  });

  it('is deterministic per name, case-insensitive, and differs between names', async () => {
    const alice = await register(h);
    const a1 = await h.call('GET', '/v1/directory/QuietOtter', { token: alice.token });
    const a2 = await h.call('GET', '/v1/directory/quietotter', { token: alice.token });
    const b = await h.call('GET', '/v1/directory/SilentComet', { token: alice.token });
    expect(a2.json).toEqual(a1.json);
    expect(b.json.identityKey).not.toBe(a1.json.identityKey);
  });

  it('only malformed names (not two words from the public lists) are refused', async () => {
    const alice = await register(h);
    expect((await h.call('GET', '/v1/directory/NotAWordName', { token: alice.token })).status).toBe(404);
    expect((await h.call('GET', '/v1/directory/x', { token: alice.token })).status).toBe(404);
  });

  it('decoy prekey bundles verify like real ones', async () => {
    const alice = await register(h);
    const r = await h.call('POST', '/v1/keys/bundles', { token: alice.token, body: { username: 'QuietOtter' } });
    expect(r.status).toBe(200);
    const list = verifyDeviceList({ body: fromB64(r.json.deviceList.body), signature: fromB64(r.json.deviceList.signature) }, fromB64(r.json.identityKey));
    const dev = list.devices[0]!;
    const b = r.json.bundles[0];
    expect(b.deviceId).toBe(toB64(dev.deviceId));
    expect(verifySignedPreKey(dev.signingKey, dev.deviceId, b.signedPreKey.keyId, fromB64(b.signedPreKey.publicKey), fromB64(b.signedPreKey.signature))).toBe(true);
    expect(b.oneTimePreKey).not.toBeNull();
  });

  it('sending to a decoy device looks like a successful send and stores nothing', async () => {
    const alice = await register(h);
    const bob = await register(h);
    const decoy = await h.call('GET', '/v1/directory/QuietOtter', { token: alice.token });
    const list = verifyDeviceList({ body: fromB64(decoy.json.deviceList.body), signature: fromB64(decoy.json.deviceList.signature) }, fromB64(decoy.json.identityKey));
    const decoyDevice = list.devices[0]!.deviceId;
    const toDecoy = await h.call('POST', '/v1/messages', { token: alice.token, body: { envelopes: [envelope(decoyDevice)] } });
    const toReal = await h.call('POST', '/v1/messages', { token: alice.token, body: { envelopes: [envelope(bob.devices[0]!.keys.deviceId)] } });
    expect(toDecoy.status).toBe(toReal.status);
    expect(toDecoy.json).toEqual(toReal.json);
    expect(toDecoy.json).toEqual({ accepted: 1, unknownDevices: [] });
    const stored = await h.db.query<{ n: number }>('SELECT count(*)::int AS n FROM mailbox.envelopes');
    expect(stored.rows[0]!.n).toBe(1); // only the envelope for Bob
    // A random (non-decoy) unknown device is still reported, so clients can drop removed devices.
    const random = await h.call('POST', '/v1/messages', { token: alice.token, body: { envelopes: [envelope(randomBytes(16))] } });
    expect(random.json.unknownDevices).toHaveLength(1);
  });
});
