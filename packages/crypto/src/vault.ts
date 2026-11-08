// Local at-rest encryption for device storage (IndexedDB in the browser).
//
// A random data-encryption key (DEK) protects every record. The DEK is stored
// only in wrapped form, sealed under a key-encryption key derived from the
// user's password (see kdf.ts). Record *names* are HMACed so the storage layer
// does not reveal which contacts or conversations exist.
//
// Destroying the wrapped DEK is the cryptographic-erasure step of Panic Reset:
// once it is gone, leftover ciphertext records on disk are unreadable even if
// the password is later disclosed.

import { type Bytes, concat, randomBytes, toB64, utf8 } from './bytes.js';
import { CryptoError, hkdf, hmacSha256, open, seal } from './primitives.js';

const DEK_AD = utf8('VEIL/v1/vault-dek');
const RECORD_AD = utf8('VEIL/v1/vault-record');

export function newVaultDek(): Bytes {
  return randomBytes(32);
}

export function wrapDek(kek: Bytes, dek: Bytes): Bytes {
  return seal(kek, dek, DEK_AD);
}

export function unwrapDek(kek: Bytes, wrapped: Bytes): Bytes {
  return open(kek, wrapped, DEK_AD);
}

export class VaultCipher {
  private readonly recordKey: Bytes;
  private readonly indexKey: Bytes;
  private destroyed = false;

  constructor(dek: Bytes) {
    this.recordKey = hkdf(dek, undefined, 'VEIL/v1/vault-record-key', 32);
    this.indexKey = hkdf(dek, undefined, 'VEIL/v1/vault-index-key', 32);
  }

  /** Opaque storage name for a logical key such as `session:VelvetFalcon:abcd`. */
  storageName(logicalKey: string): string {
    this.assertUsable();
    return toB64(hmacSha256(this.indexKey, utf8(logicalKey)));
  }

  /** The storage name is bound as associated data so records cannot be swapped. */
  encrypt(storageName: string, plaintext: Bytes): Bytes {
    this.assertUsable();
    return seal(this.recordKey, plaintext, concat(RECORD_AD, utf8(storageName)));
  }

  decrypt(storageName: string, sealed: Bytes): Bytes {
    this.assertUsable();
    return open(this.recordKey, sealed, concat(RECORD_AD, utf8(storageName)));
  }

  /** Zeroises the keys and makes every further call throw (never encrypt under a zero key). */
  destroy(): void {
    this.destroyed = true;
    this.recordKey.fill(0);
    this.indexKey.fill(0);
  }

  private assertUsable(): void {
    if (this.destroyed) throw new CryptoError('vault is closed');
  }
}
