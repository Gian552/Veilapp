// Storage for opaque attachment ciphertext. Blob names are the random
// attachment ids (hex); nothing else about the uploader is recorded.

import { mkdir, readFile, rm, writeFile, rename } from 'node:fs/promises';
import { join } from 'node:path';
import { randomBytes, toHex } from '@veil/crypto';

export interface BlobStore {
  put(id: Uint8Array, data: Uint8Array): Promise<void>;
  get(id: Uint8Array): Promise<Uint8Array | null>;
  /** Idempotent: deleting a missing blob succeeds. Throws only on real failures. */
  delete(id: Uint8Array): Promise<void>;
}

export class FsBlobStore implements BlobStore {
  constructor(private readonly dir: string) {}

  private path(id: Uint8Array): string {
    if (id.length !== 16) throw new Error('invalid blob id');
    return join(this.dir, toHex(id));
  }

  async put(id: Uint8Array, data: Uint8Array): Promise<void> {
    await mkdir(this.dir, { recursive: true, mode: 0o700 });
    const tmp = join(this.dir, `.tmp-${toHex(randomBytes(8))}`);
    await writeFile(tmp, data, { mode: 0o600 });
    await rename(tmp, this.path(id));
  }

  async get(id: Uint8Array): Promise<Uint8Array | null> {
    try {
      return new Uint8Array(await readFile(this.path(id)));
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === 'ENOENT') return null;
      throw e;
    }
  }

  async delete(id: Uint8Array): Promise<void> {
    await rm(this.path(id), { force: true });
  }
}

export class MemoryBlobStore implements BlobStore {
  readonly blobs = new Map<string, Uint8Array>();

  async put(id: Uint8Array, data: Uint8Array): Promise<void> {
    this.blobs.set(toHex(id), data.slice());
  }

  async get(id: Uint8Array): Promise<Uint8Array | null> {
    return this.blobs.get(toHex(id)) ?? null;
  }

  async delete(id: Uint8Array): Promise<void> {
    this.blobs.delete(toHex(id));
  }
}
