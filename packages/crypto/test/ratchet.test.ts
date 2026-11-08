// End-to-end properties of X3DH + Double Ratchet. These test protocol
// behaviour (ordering, replay, tampering, state isolation), not merely that
// decrypt(encrypt(x)) == x.
import { describe, expect, it } from 'vitest';
import {
  type DeviceKeys,
  type RatchetState,
  MAX_SKIP,
  cloneState,
  decodeRatchetMessage,
  deserializeState,
  encodeRatchetMessage,
  fromUtf8,
  generateAccountIdentity,
  generateDeviceKeys,
  generateOneTimePreKeys,
  generateSignedPreKey,
  initRatchetInitiator,
  initRatchetResponder,
  ratchetDecrypt,
  ratchetEncrypt,
  serializeState,
  toHex,
  utf8,
  x3dhInitiate,
  x3dhRespond,
} from '../src/index.js';

function party() {
  const aik = generateAccountIdentity();
  const device: DeviceKeys = generateDeviceKeys();
  const spk = generateSignedPreKey(device, 1);
  const [opk] = generateOneTimePreKeys(100, 1);
  return { aik, device, spk, opk: opk! };
}

function establish(withOneTimeKey = true) {
  const alice = party();
  const bob = party();
  const init = x3dhInitiate(
    { identityKey: alice.aik.publicKey, deviceId: alice.device.deviceId, dh: alice.device.dh },
    {
      identityKey: bob.aik.publicKey,
      deviceId: bob.device.deviceId,
      deviceSigningKey: bob.device.signing.publicKey,
      deviceDhKey: bob.device.dh.publicKey,
      signedPreKey: { keyId: bob.spk.keyId, publicKey: bob.spk.keyPair.publicKey, signature: bob.spk.signature },
      oneTimePreKey: withOneTimeKey ? { keyId: bob.opk.keyId, publicKey: bob.opk.keyPair.publicKey } : undefined,
    },
  );
  const resp = x3dhRespond({
    local: { identityKey: bob.aik.publicKey, deviceId: bob.device.deviceId, dh: bob.device.dh },
    signedPreKey: bob.spk.keyPair,
    oneTimePreKey: withOneTimeKey ? bob.opk.keyPair : undefined,
    remote: {
      identityKey: alice.aik.publicKey,
      deviceId: alice.device.deviceId,
      dhKey: alice.device.dh.publicKey,
      baseKey: init.baseKey,
    },
  });
  const a = initRatchetInitiator(init.sharedKey, init.remoteSignedPreKey, init.associatedData);
  const b = initRatchetResponder(resp.sharedKey, bob.spk.keyPair, resp.associatedData);
  return { alice, bob, init, resp, a, b };
}

function recv(state: { s: RatchetState }, msg: ReturnType<typeof ratchetEncrypt>): string {
  const out = ratchetDecrypt(state.s, msg);
  state.s = out.state;
  return fromUtf8(out.plaintext);
}

describe('X3DH', () => {
  it('both sides derive the same key and AD, with and without a one-time prekey', () => {
    for (const otk of [true, false]) {
      const { init, resp } = establish(otk);
      expect(toHex(init.sharedKey)).toBe(toHex(resp.sharedKey));
      expect(toHex(init.associatedData)).toBe(toHex(resp.associatedData));
    }
  });

  it('rejects a signed prekey whose signature does not verify', () => {
    const alice = party();
    const bob = party();
    const forged = generateSignedPreKey(generateDeviceKeys(), 1); // signed by someone else
    expect(() =>
      x3dhInitiate(
        { identityKey: alice.aik.publicKey, deviceId: alice.device.deviceId, dh: alice.device.dh },
        {
          identityKey: bob.aik.publicKey,
          deviceId: bob.device.deviceId,
          deviceSigningKey: bob.device.signing.publicKey,
          deviceDhKey: bob.device.dh.publicKey,
          signedPreKey: { keyId: 1, publicKey: forged.keyPair.publicKey, signature: forged.signature },
        },
      ),
    ).toThrow('signed prekey signature invalid');
  });

  it('a responder using the wrong one-time prekey derives a different key', () => {
    const { bob, init, alice } = establish(true);
    const [wrong] = generateOneTimePreKeys(5, 1);
    const resp = x3dhRespond({
      local: { identityKey: bob.aik.publicKey, deviceId: bob.device.deviceId, dh: bob.device.dh },
      signedPreKey: bob.spk.keyPair,
      oneTimePreKey: wrong!.keyPair,
      remote: { identityKey: alice.aik.publicKey, deviceId: alice.device.deviceId, dhKey: alice.device.dh.publicKey, baseKey: init.baseKey },
    });
    expect(toHex(resp.sharedKey)).not.toBe(toHex(init.sharedKey));
  });
});

describe('Double Ratchet', () => {
  it('exchanges messages in both directions across many DH ratchet steps', () => {
    const { a, b } = establish();
    const A = { s: a };
    const B = { s: b };
    for (let round = 0; round < 20; round++) {
      const m1 = ratchetEncrypt(A.s, utf8(`a${round}`));
      const m2 = ratchetEncrypt(A.s, utf8(`a${round}'`));
      expect(recv(B, m1)).toBe(`a${round}`);
      expect(recv(B, m2)).toBe(`a${round}'`);
      const r = ratchetEncrypt(B.s, utf8(`b${round}`));
      expect(recv(A, r)).toBe(`b${round}`);
    }
  });

  it('handles out-of-order delivery including across a DH ratchet step', () => {
    const { a, b } = establish();
    const A = { s: a };
    const B = { s: b };
    const first = [0, 1, 2, 3].map((i) => ratchetEncrypt(A.s, utf8(`m${i}`)));
    expect(recv(B, first[0]!)).toBe('m0');
    expect(recv(A, ratchetEncrypt(B.s, utf8('reply')))).toBe('reply');
    const second = ratchetEncrypt(A.s, utf8('after-ratchet'));
    // Deliver the new-chain message before the old chain's stragglers.
    expect(recv(B, second)).toBe('after-ratchet');
    expect(recv(B, first[3]!)).toBe('m3');
    expect(recv(B, first[1]!)).toBe('m1');
    expect(recv(B, first[2]!)).toBe('m2');
  });

  it('rejects a replayed message, both in-chain and from the skipped-key store', () => {
    const { a, b } = establish();
    const A = { s: a };
    const B = { s: b };
    const m0 = ratchetEncrypt(A.s, utf8('zero'));
    const m1 = ratchetEncrypt(A.s, utf8('one'));
    expect(recv(B, m1)).toBe('one'); // m0's key now skipped
    expect(recv(B, m0)).toBe('zero'); // consumes the skipped key
    expect(() => ratchetDecrypt(B.s, m0)).toThrow();
    expect(() => ratchetDecrypt(B.s, m1)).toThrow();
  });

  it('rejects tampered ciphertext, header and associated data, without mutating state', () => {
    const { a, b } = establish();
    const A = { s: a };
    const msg = ratchetEncrypt(A.s, utf8('secret'));
    const before = JSON.stringify(serializeState(b));

    const flippedCt = { ...msg, ciphertext: msg.ciphertext.slice() };
    flippedCt.ciphertext[3]! ^= 0x40;
    expect(() => ratchetDecrypt(b, flippedCt)).toThrow('decryption failed');

    const badCounter = { header: { ...msg.header, pn: msg.header.pn + 1 }, ciphertext: msg.ciphertext };
    expect(() => ratchetDecrypt(b, badCounter)).toThrow();

    const wrongAd = cloneState(b);
    wrongAd.ad = utf8('some other conversation');
    expect(() => ratchetDecrypt(wrongAd, msg)).toThrow('decryption failed');

    // Failed attempts must not have advanced or corrupted the real state.
    expect(JSON.stringify(serializeState(b))).toBe(before);
    expect(fromUtf8(ratchetDecrypt(b, msg).plaintext)).toBe('secret');
  });

  it('refuses to skip more than MAX_SKIP message keys', () => {
    const { a, b } = establish();
    const A = { s: a };
    let last;
    for (let i = 0; i <= MAX_SKIP + 1; i++) last = ratchetEncrypt(A.s, utf8('x'));
    expect(() => ratchetDecrypt(b, last!)).toThrow('too many skipped messages');
  });

  it('forward secrecy: a later state snapshot cannot decrypt earlier delivered messages', () => {
    const { a, b } = establish();
    const A = { s: a };
    const B = { s: b };
    const early = ratchetEncrypt(A.s, utf8('early'));
    expect(recv(B, early)).toBe('early');
    for (let i = 0; i < 3; i++) {
      recv(A, ratchetEncrypt(B.s, utf8('ping')));
      recv(B, ratchetEncrypt(A.s, utf8('pong')));
    }
    // Attacker steals Bob's complete current state:
    const stolen = cloneState(B.s);
    expect(() => ratchetDecrypt(stolen, early)).toThrow();
    // ...and it contains no key material from the old chain.
    const serialized = JSON.stringify(serializeState(stolen));
    expect(serialized).not.toContain(Buffer.from(early.header.dh).toString('base64url'));
  });

  it('serialises and restores state, and the wire format round-trips', () => {
    const { a, b } = establish();
    const A = { s: a };
    const msg = ratchetEncrypt(A.s, utf8('persist me'));
    const restored = deserializeState(JSON.parse(JSON.stringify(serializeState(b))));
    const wire = decodeRatchetMessage(encodeRatchetMessage(msg));
    expect(fromUtf8(ratchetDecrypt(restored, wire).plaintext)).toBe('persist me');
  });

  it('a third party with a different session cannot decrypt', () => {
    const one = establish();
    const two = establish();
    const msg = ratchetEncrypt(one.a, utf8('for bob only'));
    expect(() => ratchetDecrypt(two.b, msg)).toThrow();
  });
});
