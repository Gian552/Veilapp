// Attachments are encrypted once with a fresh random key; the key, digest and
// metadata travel inside the end-to-end encrypted message, the server stores
// only the opaque blob under a random id.

import { type Bytes, constantTimeEqual, randomBytes, utf8 } from './bytes.js';
import { CryptoError, open, seal, sha256 } from './primitives.js';

const ATTACHMENT_AD = utf8('VEIL/v1/attachment');
export const MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024;

export interface EncryptedAttachment {
  key: Bytes;
  digest: Bytes; // SHA-256 of the ciphertext blob
  blob: Bytes;
}

export function encryptAttachment(plaintext: Bytes): EncryptedAttachment {
  if (plaintext.length > MAX_ATTACHMENT_BYTES) throw new CryptoError('attachment too large');
  const key = randomBytes(32);
  const blob = seal(key, plaintext, ATTACHMENT_AD);
  return { key, digest: sha256(blob), blob };
}

export function decryptAttachment(blob: Bytes, key: Bytes, digest: Bytes): Bytes {
  if (!constantTimeEqual(sha256(blob), digest)) throw new CryptoError('attachment digest mismatch');
  return open(key, blob, ATTACHMENT_AD);
}
