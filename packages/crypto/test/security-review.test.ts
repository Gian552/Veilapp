// Independent security review: adversarial tests for @veil/crypto.
//
// Tests labelled "property" check security properties that hold today.
// Tests labelled "characterisation" pin down behaviour that is correct for the
// primitive in isolation but that the client must compensate for; each refers
// to the FINDING in packages/client/test/security-review.test.ts that depends on it.
import { describe, expect, it } from 'vitest';
import {
  CryptoError,
  MAX_SKIPPED_TOTAL,
  cloneState,
  concat,
  deviceEntryFor,
  encodeLinkRequest,
  formatRecoveryKey,
  fromUtf8,
  generateAccountIdentity,
  generateDeviceKeys,
  generateOneTimePreKeys,
  generateRecoverySecret,
  generateSignedPreKey,
  initRatchetInitiator,
  initRatchetResponder,
  generateLinkSecret,
  formatLinkCode,
  parseLinkCode,
  verifyLinkRequest,
  sealToPublicKey,
  openEnvelope,
  openProvisioning,
  parseRecoveryKey,
  randomBytes,
  ratchetDecrypt,
  ratchetEncrypt,
  sealEnvelope,
  sealProvisioning,
  signDeviceList,
  utf8,
  verifyDeviceList,
  x25519KeyPair,
  x3dhInitiate,
  x3dhRespond,
  type RatchetState,
} from '../src/index.js';

function establish() {
  const a = { aik: generateAccountIdentity(), device: generateDeviceKeys() };
  const b = { aik: generateAccountIdentity(), device: generateDeviceKeys() };
  const spk = generateSignedPreKey(b.device, 1);
  const [otk] = generateOneTimePreKeys(1, 1);
  const init = x3dhInitiate(
    { identityKey: a.aik.publicKey, deviceId: a.device.deviceId, dh: a.device.dh },
    {
      identityKey: b.aik.publicKey,
      deviceId: b.device.deviceId,
      deviceSigningKey: b.device.signing.publicKey,
      deviceDhKey: b.device.dh.publicKey,
      signedPreKey: { keyId: spk.keyId, publicKey: spk.keyPair.publicKey, signature: spk.signature },
      oneTimePreKey: { keyId: otk!.keyId, publicKey: otk!.keyPair.publicKey },
    },
  );
  return { a, b, spk, otk: otk!, init };
}

function pair(): { alice: RatchetState; bob: RatchetState } {
  const { a, b, spk, otk, init } = establish();
  const resp = x3dhRespond({
    local: { identityKey: b.aik.publicKey, deviceId: b.device.deviceId, dh: b.device.dh },
    signedPreKey: spk.keyPair,
    oneTimePreKey: otk.keyPair,
    remote: { identityKey: a.aik.publicKey, deviceId: a.device.deviceId, dhKey: a.device.dh.publicKey, baseKey: init.baseKey },
  });
  return {
    alice: initRatchetInitiator(init.sharedKey.slice(), init.remoteSignedPreKey, init.associatedData),
    bob: initRatchetResponder(resp.sharedKey, spk.keyPair, resp.associatedData),
  };
}

const xor = (x: Uint8Array, y: Uint8Array) => x.map((v, i) => v ^ y[i]!);

describe('ratchet: deterministic nonces make state rollback catastrophic (characterisation, see FINDING 1)', () => {
  it('re-encrypting from a rolled-back state reuses key AND nonce: c1 XOR c2 == p1 XOR p2', () => {
    const { alice } = pair();
    const snapshot = cloneState(alice); // e.g. an older copy of the vault record restored by an attacker
    const p1 = utf8('attack at dawn!!');
    const p2 = utf8('retreat at noon!');
    const m1 = ratchetEncrypt(alice, p1);
    const m2 = ratchetEncrypt(snapshot, p2);
    expect(m1.header.n).toBe(m2.header.n);
    // Same keystream: the XOR of the ciphertext bodies (without the 16-byte tag) leaks the XOR of the plaintexts.
    expect(xor(m1.ciphertext.subarray(0, 16), m2.ciphertext.subarray(0, 16))).toEqual(xor(p1, p2));
  });
});

describe('ratchet: transactional decryption and bounds (property)', () => {
  it('a message carrying a stale/unknown ratchet key fails without mutating state', () => {
    const { alice, bob } = pair();
    const m = ratchetEncrypt(alice, utf8('one'));
    const r = ratchetDecrypt(bob, m);
    const bobState = r.state;
    const before = JSON.stringify([...bobState.skipped.keys(), bobState.nr, bobState.ns, Array.from(bobState.rk)]);
    const forged = { header: { dh: x25519KeyPair().publicKey, pn: 5, n: 7 }, ciphertext: randomBytes(48) };
    expect(() => ratchetDecrypt(bobState, forged)).toThrow(CryptoError);
    expect(JSON.stringify([...bobState.skipped.keys(), bobState.nr, bobState.ns, Array.from(bobState.rk)])).toBe(before);
  });

  it('the skipped-key store stays bounded across many chains', () => {
    let { alice, bob } = pair();
    for (let round = 0; round < 4; round++) {
      let last;
      for (let i = 0; i < 900; i++) last = ratchetEncrypt(alice, utf8('x'));
      bob = ratchetDecrypt(bob, last!).state; // skips 899 keys in this chain
      const reply = ratchetEncrypt(bob, utf8('ack'));
      alice = ratchetDecrypt(alice, reply).state;
    }
    expect(bob.skipped.size).toBeLessThanOrEqual(MAX_SKIPPED_TOTAL);
  });
});

describe('x3dh: binding (property)', () => {
  it('the responder derives a different AD (so decryption fails) if the claimed initiator device id differs', () => {
    const { a, b, spk, otk, init } = establish();
    const resp = x3dhRespond({
      local: { identityKey: b.aik.publicKey, deviceId: b.device.deviceId, dh: b.device.dh },
      signedPreKey: spk.keyPair,
      oneTimePreKey: otk.keyPair,
      remote: { identityKey: a.aik.publicKey, deviceId: randomBytes(16), dhKey: a.device.dh.publicKey, baseKey: init.baseKey },
    });
    const alice = initRatchetInitiator(init.sharedKey.slice(), init.remoteSignedPreKey, init.associatedData);
    const bob = initRatchetResponder(resp.sharedKey, spk.keyPair, resp.associatedData);
    expect(() => ratchetDecrypt(bob, ratchetEncrypt(alice, utf8('hi')))).toThrow(CryptoError);
  });

  it('rejects a low-order base key in a prekey message', () => {
    const { a, b, spk, otk } = establish();
    expect(() =>
      x3dhRespond({
        local: { identityKey: b.aik.publicKey, deviceId: b.device.deviceId, dh: b.device.dh },
        signedPreKey: spk.keyPair,
        oneTimePreKey: otk.keyPair,
        remote: { identityKey: a.aik.publicKey, deviceId: a.device.deviceId, dhKey: a.device.dh.publicKey, baseKey: new Uint8Array(32) },
      }),
    ).toThrow(CryptoError);
  });
});

describe('sealed sender: sender fields are unauthenticated (characterisation, see FINDING 3)', () => {
  it('anyone holding the recipient public key can claim any sender username and device', () => {
    const recipient = generateDeviceKeys();
    const sealed = sealEnvelope(recipient.deviceId, recipient.dh.publicKey, {
      senderUsername: 'velvetfalcon', // not even the canonical case of a real username
      senderDeviceId: randomBytes(16),
      inner: { kind: 'ratchet', message: { header: { dh: x25519KeyPair().publicKey, pn: 0, n: 0 }, ciphertext: randomBytes(40) } },
    });
    const opened = openEnvelope(recipient.deviceId, recipient.dh, sealed);
    expect(opened.senderUsername).toBe('velvetfalcon');
  });
});

describe('device linking primitives (regression for FINDING 2)', () => {
  it('a relaying party that knows the request but not the code cannot forge an approval or a request', () => {
    const device = generateDeviceKeys();
    const prov = x25519KeyPair();
    const secret = generateLinkSecret();
    const core = { deviceId: device.deviceId, signingKey: device.signing.publicKey, dhKey: device.dh.publicKey, provisioningKey: prov.publicKey };
    const request = encodeLinkRequest(core, secret);
    // The server can seal to the provisioning key, but cannot produce the code-derived MAC.
    const forged = concat(sealToPublicKey(prov.publicKey, utf8('{"forged":true}'), 'VEIL/v1/provisioning', request), randomBytes(32));
    expect(() => openProvisioning(request, secret, prov, forged)).toThrow(CryptoError);
    // A substituted request (attacker's keys) does not match the code the user types.
    const attacker = encodeLinkRequest({ ...core, provisioningKey: x25519KeyPair().publicKey }, generateLinkSecret());
    expect(verifyLinkRequest(attacker, secret)).toBe(false);
    expect(() => sealProvisioning(attacker, secret, utf8('x'))).toThrow(CryptoError);
    // The genuine path works, and the code round-trips through its display form.
    expect(parseLinkCode(formatLinkCode(secret))).toEqual(secret);
    const real = sealProvisioning(request, secret, utf8('{"ok":true}'));
    expect(fromUtf8(openProvisioning(request, secret, prov, real))).toBe('{"ok":true}');
  });

  it('two different device lists with the same version both verify (a fork is not detectable from the list alone)', () => {
    const aik = generateAccountIdentity();
    const d1 = generateDeviceKeys();
    const d2 = generateDeviceKeys();
    const l1 = signDeviceList(aik.privateKey, { identityKey: aik.publicKey, version: 3, devices: [deviceEntryFor(d1, true)] });
    const l2 = signDeviceList(aik.privateKey, { identityKey: aik.publicKey, version: 3, devices: [deviceEntryFor(d1, true), deviceEntryFor(d2, false)] });
    expect(verifyDeviceList(l1, aik.publicKey).version).toBe(verifyDeviceList(l2, aik.publicKey).version);
  });
});

describe('recovery key parsing (info)', () => {
  it('rejects trailing characters after the 52 significant ones', () => {
    const secret = generateRecoverySecret();
    const text = formatRecoveryKey(secret);
    expect(() => parseRecoveryKey(text + '-ZZZZ')).toThrow(CryptoError);
  });

  it('the checksum still rejects a single-character typo', () => {
    const secret = generateRecoverySecret();
    const text = formatRecoveryKey(secret);
    const typo = (text[0] === '0' ? '1' : '0') + text.slice(1);
    expect(() => parseRecoveryKey(typo)).toThrow(CryptoError);
  });
});

describe('domain separation of sealed boxes (property)', () => {
  it('a provisioning box cannot be opened as an envelope and vice versa', () => {
    const device = generateDeviceKeys();
    const secret = generateLinkSecret();
    const request = encodeLinkRequest({ deviceId: device.deviceId, signingKey: device.signing.publicKey, dhKey: device.dh.publicKey, provisioningKey: device.dh.publicKey }, secret);
    const box = sealProvisioning(request, secret, concat(utf8('x')));
    expect(() => openEnvelope(device.deviceId, device.dh, box)).toThrow(CryptoError);
  });
});
