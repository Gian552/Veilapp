// Thin, typed wrappers around audited primitives (@noble/*). Every protocol
// module goes through these so that algorithm choices live in exactly one place.
//
//   DH:        X25519 (RFC 7748)
//   Signature: Ed25519 (RFC 8032)
//   KDF:       HKDF-SHA-256 (RFC 5869)
//   MAC/hash:  HMAC-SHA-256, SHA-256, SHA-512
//   AEAD:      XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha)

import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { hkdf as nobleHkdf } from '@noble/hashes/hkdf.js';
import { hmac as nobleHmac } from '@noble/hashes/hmac.js';
import { sha256 as nobleSha256, sha512 as nobleSha512 } from '@noble/hashes/sha2.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { type Bytes, concat, randomBytes, utf8 } from './bytes.js';

export const KEY_LEN = 32;
export const AEAD_NONCE_LEN = 24;
export const AEAD_TAG_LEN = 16;

export class CryptoError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CryptoError';
  }
}

export interface KeyPair {
  publicKey: Bytes;
  privateKey: Bytes;
}

// ---------------------------------------------------------------- hashing

export function sha256(data: Bytes): Bytes {
  return nobleSha256(data);
}

export function sha512(data: Bytes): Bytes {
  return nobleSha512(data);
}

export function hmacSha256(key: Bytes, data: Bytes): Bytes {
  return nobleHmac(nobleSha256, key, data);
}

/**
 * HKDF-SHA-256. `info` is always a versioned, protocol-specific label so that
 * no two purposes can ever share derived key material (domain separation).
 */
export function hkdf(ikm: Bytes, salt: Bytes | undefined, info: string | Bytes, length: number): Bytes {
  const infoBytes = typeof info === 'string' ? utf8(info) : info;
  return nobleHkdf(nobleSha256, ikm, salt, infoBytes, length);
}

// ---------------------------------------------------------------- X25519

export function x25519KeyPair(): KeyPair {
  const privateKey = x25519.utils.randomSecretKey();
  return { privateKey, publicKey: x25519.getPublicKey(privateKey) };
}

export function x25519PublicFromPrivate(privateKey: Bytes): Bytes {
  return x25519.getPublicKey(privateKey);
}

/**
 * X25519 shared secret. noble rejects low-order points (all-zero output);
 * we re-check defensively because accepting a zero secret would silently
 * collapse the key agreement.
 */
export function dh(privateKey: Bytes, publicKey: Bytes): Bytes {
  if (publicKey.length !== 32 || privateKey.length !== 32) throw new CryptoError('invalid X25519 key length');
  let shared: Bytes;
  try {
    shared = x25519.getSharedSecret(privateKey, publicKey);
  } catch {
    throw new CryptoError('invalid X25519 public key');
  }
  let acc = 0;
  for (const b of shared) acc |= b;
  if (acc === 0) throw new CryptoError('low-order X25519 point');
  return shared;
}

// ---------------------------------------------------------------- Ed25519

export function ed25519KeyPair(): KeyPair {
  const privateKey = ed25519.utils.randomSecretKey();
  return { privateKey, publicKey: ed25519.getPublicKey(privateKey) };
}

export function ed25519PublicFromPrivate(privateKey: Bytes): Bytes {
  return ed25519.getPublicKey(privateKey);
}

/** Signs `context || 0x00 || message` so signatures cannot be replayed across purposes. */
export function sign(privateKey: Bytes, context: string, message: Bytes): Bytes {
  return ed25519.sign(concat(utf8(context), new Uint8Array([0]), message), privateKey);
}

export function verify(publicKey: Bytes, context: string, message: Bytes, signature: Bytes): boolean {
  if (publicKey.length !== 32 || signature.length !== 64) return false;
  try {
    // zip215: false => strict RFC 8032 verification (rejects malleable / non-canonical encodings).
    return ed25519.verify(signature, concat(utf8(context), new Uint8Array([0]), message), publicKey, { zip215: false });
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------- AEAD

/**
 * XChaCha20-Poly1305 with a fresh random 192-bit nonce, output `nonce || ct || tag`.
 * Random nonces are safe at this size (collision probability negligible).
 */
export function seal(key: Bytes, plaintext: Bytes, associatedData: Bytes = new Uint8Array(0)): Bytes {
  if (key.length !== KEY_LEN) throw new CryptoError('invalid AEAD key length');
  const nonce = randomBytes(AEAD_NONCE_LEN);
  const ct = xchacha20poly1305(key, nonce, associatedData).encrypt(plaintext);
  return concat(nonce, ct);
}

export function open(key: Bytes, sealed: Bytes, associatedData: Bytes = new Uint8Array(0)): Bytes {
  if (key.length !== KEY_LEN) throw new CryptoError('invalid AEAD key length');
  if (sealed.length < AEAD_NONCE_LEN + AEAD_TAG_LEN) throw new CryptoError('ciphertext too short');
  const nonce = sealed.subarray(0, AEAD_NONCE_LEN);
  try {
    return xchacha20poly1305(key, nonce, associatedData).decrypt(sealed.subarray(AEAD_NONCE_LEN));
  } catch {
    // Uniform error: never reveal whether tag, AD or nonce was the problem.
    throw new CryptoError('decryption failed');
  }
}

/** AEAD with an explicit nonce; only for keys that are used exactly once (ratchet message keys). */
export function sealWithNonce(key: Bytes, nonce: Bytes, plaintext: Bytes, associatedData: Bytes): Bytes {
  return xchacha20poly1305(key, nonce, associatedData).encrypt(plaintext);
}

export function openWithNonce(key: Bytes, nonce: Bytes, ciphertext: Bytes, associatedData: Bytes): Bytes {
  try {
    return xchacha20poly1305(key, nonce, associatedData).decrypt(ciphertext);
  } catch {
    throw new CryptoError('decryption failed');
  }
}
