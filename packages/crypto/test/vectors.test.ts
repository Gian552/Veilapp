// Known-answer tests against published vectors. These pin the primitives that
// every higher-level construction in @veil/crypto is built on.
import { describe, expect, it } from 'vitest';
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { argon2id as nobleArgon2id } from '@noble/hashes/argon2.js';
import { argon2id as wasmArgon2id } from 'hash-wasm';
import {
  concat,
  deriveMasterKey,
  dh,
  fromB64,
  fromHex,
  hkdf,
  openWithNonce,
  sealWithNonce,
  sign,
  toB64,
  toHex,
  utf8,
  verify,
} from '../src/index.js';

describe('RFC 7748 X25519 (section 6.1)', () => {
  const alicePriv = fromHex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a');
  const alicePub = fromHex('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a');
  const bobPriv = fromHex('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb');
  const bobPub = fromHex('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f');
  const shared = '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742';

  it('derives public keys', () => {
    expect(toHex(x25519.getPublicKey(alicePriv))).toBe(toHex(alicePub));
    expect(toHex(x25519.getPublicKey(bobPriv))).toBe(toHex(bobPub));
  });

  it('computes the shared secret through our dh() wrapper in both directions', () => {
    expect(toHex(dh(alicePriv, bobPub))).toBe(shared);
    expect(toHex(dh(bobPriv, alicePub))).toBe(shared);
  });

  it('rejects the all-zero (low-order) public key', () => {
    expect(() => dh(alicePriv, new Uint8Array(32))).toThrow();
  });
});

describe('RFC 8032 Ed25519 (section 7.1, TEST 1)', () => {
  const secret = fromHex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60');
  const pub = fromHex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a');
  const sig =
    'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b';

  it('matches the published signature', () => {
    expect(toHex(ed25519.getPublicKey(secret))).toBe(toHex(pub));
    expect(toHex(ed25519.sign(new Uint8Array(0), secret))).toBe(sig);
  });

  it('our context-separated sign() is Ed25519 over context || 0x00 || message', () => {
    const msg = utf8('hello');
    const ours = sign(secret, 'CTX', msg);
    expect(toHex(ours)).toBe(toHex(ed25519.sign(concat(utf8('CTX'), new Uint8Array([0]), msg), secret)));
    expect(verify(pub, 'CTX', msg, ours)).toBe(true);
    expect(verify(pub, 'OTHER', msg, ours)).toBe(false);
  });
});

describe('RFC 5869 HKDF-SHA-256 (Test Case 1)', () => {
  it('produces the published OKM', () => {
    const okm = hkdf(fromHex('0b'.repeat(22)), fromHex('000102030405060708090a0b0c'), fromHex('f0f1f2f3f4f5f6f7f8f9'), 42);
    expect(toHex(okm)).toBe('3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865');
  });
});

describe('draft-irtf-cfrg-xchacha-03 A.3.1 AEAD_XCHACHA20_POLY1305', () => {
  const plaintext = fromHex(
    '4c616469657320616e642047656e746c656d656e206f662074686520636c6173' +
      '73206f66202739393a204966204920636f756c64206f6666657220796f75206f' +
      '6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73' +
      '637265656e20776f756c642062652069742e',
  );
  const aad = fromHex('50515253c0c1c2c3c4c5c6c7');
  const key = fromHex('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f');
  const nonce = fromHex('404142434445464748494a4b4c4d4e4f5051525354555657');
  const ciphertext =
    'bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb' +
    '731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452' +
    '2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9' +
    '21f9664c97637da9768812f615c68b13b52e';
  const tag = 'c0875924c1c7987947deafd8780acf49';

  it('encrypts to the published ciphertext and tag', () => {
    expect(toHex(sealWithNonce(key, nonce, plaintext, aad))).toBe(ciphertext + tag);
  });

  it('decrypts, and rejects a flipped tag bit and wrong AAD', () => {
    const ct = fromHex(ciphertext + tag);
    expect(toHex(openWithNonce(key, nonce, ct, aad))).toBe(toHex(plaintext));
    const bad = ct.slice();
    bad[bad.length - 1]! ^= 1;
    expect(() => openWithNonce(key, nonce, bad, aad)).toThrow('decryption failed');
    expect(() => openWithNonce(key, nonce, ct, fromHex('00'))).toThrow('decryption failed');
  });
});

describe('RFC 9106 Argon2id (section 5.3)', () => {
  it('noble argon2id reproduces the published tag (with secret and associated data)', () => {
    const tag = nobleArgon2id(new Uint8Array(32).fill(1), new Uint8Array(16).fill(2), {
      t: 3,
      m: 32,
      p: 4,
      dkLen: 32,
      key: new Uint8Array(8).fill(3),
      personalization: new Uint8Array(12).fill(4),
    });
    expect(toHex(tag)).toBe('0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659');
  });

  it('hash-wasm (used by deriveMasterKey) agrees with the RFC-validated implementation', async () => {
    const password = utf8('correct horse battery staple');
    const salt = fromHex('000102030405060708090a0b0c0d0e0f');
    const reference = nobleArgon2id(password, salt, { t: 2, m: 256, p: 2, dkLen: 32 });
    const wasm = await wasmArgon2id({
      password,
      salt,
      iterations: 2,
      memorySize: 256,
      parallelism: 2,
      hashLength: 32,
      outputType: 'binary',
    });
    expect(toHex(wasm)).toBe(toHex(reference));
    const viaWrapper = await deriveMasterKey('correct horse battery staple', salt, { memoryKiB: 256, iterations: 2, parallelism: 2 });
    expect(toHex(viaWrapper)).toBe(toHex(reference));
  });
});

describe('base64url', () => {
  it('round-trips all lengths and rejects non-canonical input', () => {
    for (let n = 0; n < 40; n++) {
      const b = new Uint8Array(n).map((_, i) => (i * 37 + n) & 0xff);
      expect(toHex(fromB64(toB64(b)))).toBe(toHex(b));
    }
    expect(toB64(fromHex('fbff'))).toBe('-_8');
    expect(() => fromB64('-_9')).toThrow();
    expect(() => fromB64('a+b/')).toThrow();
  });
});
