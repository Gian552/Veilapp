import { describe, expect, it } from 'vitest';
import {
  CLIENT_SALT_LEN,
  VaultCipher,
  checkProofOfWork,
  decryptAttachment,
  deriveRecoveryKeys,
  deviceEntryFor,
  encryptAttachment,
  formatRecoveryKey,
  generateAccountIdentity,
  generateDeviceKeys,
  generateRecoverySecret,
  formatLinkCode,
  generateLinkSecret,
  newClientSalt,
  newVaultDek,
  openEnvelope,
  openWithPrivateKey,
  parseRecoveryKey,
  safetyNumber,
  sealEnvelope,
  sealToPublicKey,
  signDeviceList,
  solveProofOfWork,
  splitMasterKey,
  toHex,
  unwrapDek,
  utf8,
  verifyDeviceList,
  wrapDek,
  x25519KeyPair,
  randomBytes,
  fromUtf8,
} from '../src/index.js';

describe('device lists', () => {
  const aik = generateAccountIdentity();
  const d1 = generateDeviceKeys();
  const d2 = generateDeviceKeys();
  const list = { identityKey: aik.publicKey, version: 3, devices: [deviceEntryFor(d1, true), deviceEntryFor(d2, false)] };

  it('verifies against the pinned identity key and preserves contents', () => {
    const signed = signDeviceList(aik.privateKey, list);
    const out = verifyDeviceList(signed, aik.publicKey);
    expect(out.version).toBe(3);
    expect(out.devices).toHaveLength(2);
    expect(out.devices.find((d) => d.primary)!.deviceId).toEqual(d1.deviceId);
  });

  it('rejects a list signed by another identity, a modified body, and duplicate devices', () => {
    const other = generateAccountIdentity();
    const forged = signDeviceList(other.privateKey, { ...list, identityKey: other.publicKey });
    expect(() => verifyDeviceList(forged, aik.publicKey)).toThrow();

    const signed = signDeviceList(aik.privateKey, list);
    const tampered = { body: signed.body.slice(), signature: signed.signature };
    tampered.body[tampered.body.length - 2]! ^= 1;
    expect(() => verifyDeviceList(tampered, aik.publicKey)).toThrow();

    expect(() => signDeviceList(aik.privateKey, { ...list, devices: [deviceEntryFor(d1, true), deviceEntryFor(d1, true)] })).toThrow();
  });
});

describe('verification codes', () => {
  it('safety numbers are symmetric, 60 digits, and change when a key changes', () => {
    const a = { identityKey: generateAccountIdentity().publicKey, username: 'VelvetFalcon' };
    const b = { identityKey: generateAccountIdentity().publicKey, username: 'SilentComet' };
    const ab = safetyNumber(a, b);
    expect(ab).toBe(safetyNumber(b, a));
    expect(ab.replace(/ /g, '')).toMatch(/^\d{60}$/);
    const b2 = { ...b, identityKey: generateAccountIdentity().publicKey };
    expect(safetyNumber(a, b2)).not.toBe(ab);
  });

  it('link codes are 16 characters and differ between devices', () => {
    const c1 = formatLinkCode(generateLinkSecret());
    const c2 = formatLinkCode(generateLinkSecret());
    expect(c1).toMatch(/^[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$/);
    expect(c1).not.toBe(c2);
  });
});

describe('password and recovery derivations', () => {
  it('auth key and vault key are independent (domain separation)', () => {
    const master = randomBytes(32);
    const { authKey, vaultKek } = splitMasterKey(master);
    expect(toHex(authKey)).not.toBe(toHex(vaultKek));
    expect(toHex(authKey)).not.toBe(toHex(master));
    expect(newClientSalt()).toHaveLength(CLIENT_SALT_LEN);
  });

  it('recovery keys round-trip, tolerate formatting and detect typos', () => {
    const secret = generateRecoverySecret();
    const text = formatRecoveryKey(secret);
    expect(text).toMatch(/^([0-9A-Z]{4}-){12}[0-9A-Z]{4}$/);
    expect(toHex(parseRecoveryKey(text.toLowerCase().replace(/-/g, ' ')))).toBe(toHex(secret));
    const typo = (text[0] === '7' ? '8' : '7') + text.slice(1);
    expect(() => parseRecoveryKey(typo)).toThrow();
    const keys = deriveRecoveryKeys(secret);
    expect(toHex(keys.backupKey)).not.toBe(toHex(keys.recoveryAuthKey));
  });
});

describe('sealed boxes and envelopes', () => {
  it('only the recipient key opens a sealed box, and AD is bound', () => {
    const r = x25519KeyPair();
    const box = sealToPublicKey(r.publicKey, utf8('hi'), 'CTX', utf8('ad'));
    expect(fromUtf8(openWithPrivateKey(r, box, 'CTX', utf8('ad')))).toBe('hi');
    expect(() => openWithPrivateKey(r, box, 'CTX', utf8('other'))).toThrow();
    expect(() => openWithPrivateKey(r, box, 'OTHER', utf8('ad'))).toThrow();
    expect(() => openWithPrivateKey(x25519KeyPair(), box, 'CTX', utf8('ad'))).toThrow();
  });

  it('envelopes hide the sender and are bound to the recipient device id', () => {
    const recipient = generateDeviceKeys();
    const sender = generateDeviceKeys();
    const contents = {
      senderUsername: 'QuantumMango',
      senderDeviceId: sender.deviceId,
      inner: { kind: 'ratchet' as const, message: { header: { dh: randomBytes(32), pn: 1, n: 2 }, ciphertext: randomBytes(40) } },
    };
    const sealed = sealEnvelope(recipient.deviceId, recipient.dh.publicKey, contents);
    expect(Buffer.from(sealed).includes(Buffer.from('QuantumMango'))).toBe(false);
    expect(Buffer.from(sealed).includes(Buffer.from(sender.deviceId))).toBe(false);
    const opened = openEnvelope(recipient.deviceId, recipient.dh, sealed);
    expect(opened.senderUsername).toBe('QuantumMango');
    expect(opened.senderDeviceId).toEqual(sender.deviceId);
    expect(() => openEnvelope(generateDeviceKeys().deviceId, recipient.dh, sealed)).toThrow();
  });
});

describe('local vault', () => {
  it('wraps the DEK under the password key and binds records to their names', () => {
    const kek = randomBytes(32);
    const dek = newVaultDek();
    const wrapped = wrapDek(kek, dek);
    expect(toHex(unwrapDek(kek, wrapped))).toBe(toHex(dek));
    expect(() => unwrapDek(randomBytes(32), wrapped)).toThrow();

    const v = new VaultCipher(dek);
    const nameA = v.storageName('session:VelvetFalcon');
    const nameB = v.storageName('session:SilentComet');
    expect(nameA).not.toContain('Velvet');
    const recA = v.encrypt(nameA, utf8('A'));
    expect(fromUtf8(v.decrypt(nameA, recA))).toBe('A');
    expect(() => v.decrypt(nameB, recA)).toThrow(); // record swapping detected
  });
});

describe('attachments', () => {
  it('detects blob substitution via digest and decrypts the original', () => {
    const a = encryptAttachment(utf8('file contents'));
    expect(fromUtf8(decryptAttachment(a.blob, a.key, a.digest))).toBe('file contents');
    const other = encryptAttachment(utf8('other'));
    expect(() => decryptAttachment(other.blob, a.key, a.digest)).toThrow('digest');
  });
});

describe('proof of work', () => {
  it('solutions verify and wrong nonces do not', async () => {
    const challenge = randomBytes(16);
    const nonce = await solveProofOfWork(challenge, 10);
    expect(checkProofOfWork(challenge, nonce, 10)).toBe(true);
    expect(checkProofOfWork(randomBytes(16), nonce, 24)).toBe(false);
  });
});
