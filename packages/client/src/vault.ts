// Encrypted local vault (see @veil/crypto vault.ts for the construction).
// Plaintext `meta` holds only: the wrapped DEK, the client salt and Argon2
// parameters (all non-secret), and a reset-pending flag.

import {
  type Argon2Params,
  VaultCipher,
  fromB64,
  fromUtf8,
  newVaultDek,
  toB64,
  unwrapDek,
  utf8,
  wipe,
  wrapDek,
} from '@veil/crypto';
import type { StorageBackend } from './types.js';

export interface VaultMeta {
  v: 1;
  wrappedDek: string;
  clientSalt: string;
  kdf: Argon2Params;
}

const META_KEY = 'vault';
const RESET_FLAG = 'reset-pending';

export class LocalVault {
  private closed = false;

  private constructor(
    private readonly storage: StorageBackend,
    private cipher: VaultCipher,
    private dek: Uint8Array,
  ) {}

  static async readMeta(storage: StorageBackend): Promise<VaultMeta | null> {
    const raw = await storage.get('meta', META_KEY);
    if (!raw) return null;
    try {
      const m = JSON.parse(fromUtf8(raw)) as VaultMeta;
      return m.v === 1 ? m : null;
    } catch {
      return null;
    }
  }

  static async create(storage: StorageBackend, kek: Uint8Array, clientSalt: Uint8Array, kdf: Argon2Params): Promise<LocalVault> {
    const dek = newVaultDek();
    const meta: VaultMeta = { v: 1, wrappedDek: toB64(wrapDek(kek, dek)), clientSalt: toB64(clientSalt), kdf };
    await storage.put('meta', META_KEY, utf8(JSON.stringify(meta)));
    return new LocalVault(storage, new VaultCipher(dek), dek);
  }

  /** Throws CryptoError if the key-encryption key is wrong. */
  static async unlock(storage: StorageBackend, kek: Uint8Array): Promise<LocalVault> {
    const meta = await LocalVault.readMeta(storage);
    if (!meta) throw new Error('no vault');
    const dek = unwrapDek(kek, fromB64(meta.wrappedDek));
    return new LocalVault(storage, new VaultCipher(dek), dek);
  }

  static async setResetPending(storage: StorageBackend, pending: boolean) {
    if (pending) await storage.put('meta', RESET_FLAG, new Uint8Array([1]));
    else await storage.delete('meta', RESET_FLAG);
  }

  static async isResetPending(storage: StorageBackend): Promise<boolean> {
    return (await storage.get('meta', RESET_FLAG)) !== undefined;
  }

  async get<T>(logicalKey: string): Promise<T | undefined> {
    this.assertOpen();
    const name = this.cipher.storageName(logicalKey);
    const sealed = await this.storage.get('records', name);
    if (!sealed) return undefined;
    return JSON.parse(fromUtf8(this.cipher.decrypt(name, sealed))) as T;
  }

  async put(logicalKey: string, value: unknown): Promise<void> {
    this.assertOpen();
    const name = this.cipher.storageName(logicalKey);
    await this.storage.put('records', name, this.cipher.encrypt(name, utf8(JSON.stringify(value))));
  }

  async delete(logicalKey: string): Promise<void> {
    this.assertOpen();
    await this.storage.delete('records', this.cipher.storageName(logicalKey));
  }

  /** Re-wraps the DEK under a new password-derived key (password change). */
  async rewrap(kek: Uint8Array, clientSalt: Uint8Array, kdf: Argon2Params): Promise<void> {
    this.assertOpen();
    const meta: VaultMeta = { v: 1, wrappedDek: toB64(wrapDek(kek, this.dek)), clientSalt: toB64(clientSalt), kdf };
    await this.storage.put('meta', META_KEY, utf8(JSON.stringify(meta)));
  }

  /** After close, every operation throws: in-flight work can never write under wiped keys. */
  close(): void {
    this.closed = true;
    this.cipher.destroy();
    wipe(this.dek);
  }

  get isClosed(): boolean {
    return this.closed;
  }

  private assertOpen(): void {
    if (this.closed) throw new Error('vault is closed');
  }
}
