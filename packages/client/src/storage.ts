// Storage backends. Values are opaque bytes: the vault layer encrypts every
// record before it reaches storage, so these classes never see plaintext.

import type { StorageBackend } from './types.js';

type StoreName = 'meta' | 'records';

export class MemoryStorage implements StorageBackend {
  private stores: Record<StoreName, Map<string, Uint8Array>> = { meta: new Map(), records: new Map() };

  async get(store: StoreName, key: string) {
    const v = this.stores[store].get(key);
    return v ? v.slice() : undefined;
  }

  async put(store: StoreName, key: string, value: Uint8Array) {
    this.stores[store].set(key, value.slice());
  }

  async delete(store: StoreName, key: string) {
    this.stores[store].delete(key);
  }

  async keys(store: StoreName) {
    return [...this.stores[store].keys()];
  }

  async destroy() {
    for (const s of Object.values(this.stores)) {
      for (const v of s.values()) v.fill(0);
      s.clear();
    }
  }

  /** Test helper: every byte currently persisted (to scan for leaked plaintext). */
  dump(): Uint8Array[] {
    return [...this.stores.meta.values(), ...this.stores.records.values()];
  }
}

function req<T>(r: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error ?? new Error('IndexedDB request failed'));
  });
}

/**
 * IndexedDB backend for browsers. `destroy()` deletes the whole database.
 * Note: browsers and SSDs may retain deleted pages physically; that is why the
 * vault DEK is destroyed first (cryptographic erasure), see docs/PANIC_RESET.md.
 */
export class IndexedDbStorage implements StorageBackend {
  private dbPromise: Promise<IDBDatabase> | null = null;

  constructor(
    private readonly name = 'veil',
    private readonly factory: IDBFactory = globalThis.indexedDB,
  ) {}

  private db(): Promise<IDBDatabase> {
    if (!this.dbPromise) {
      this.dbPromise = new Promise((resolve, reject) => {
        const open = this.factory.open(this.name, 1);
        open.onupgradeneeded = () => {
          open.result.createObjectStore('meta');
          open.result.createObjectStore('records');
        };
        open.onsuccess = () => resolve(open.result);
        open.onerror = () => reject(open.error ?? new Error('IndexedDB open failed'));
        open.onblocked = () => reject(new Error('IndexedDB blocked'));
      });
    }
    return this.dbPromise;
  }

  private async tx(store: StoreName, mode: IDBTransactionMode) {
    return (await this.db()).transaction(store, mode).objectStore(store);
  }

  async get(store: StoreName, key: string) {
    const v = await req((await this.tx(store, 'readonly')).get(key));
    return v instanceof Uint8Array ? v : v ? new Uint8Array(v as ArrayBuffer) : undefined;
  }

  async put(store: StoreName, key: string, value: Uint8Array) {
    await req((await this.tx(store, 'readwrite')).put(value, key));
  }

  async delete(store: StoreName, key: string) {
    await req((await this.tx(store, 'readwrite')).delete(key));
  }

  async keys(store: StoreName) {
    return (await req((await this.tx(store, 'readonly')).getAllKeys())).map(String);
  }

  async destroy() {
    if (this.dbPromise) {
      try {
        const db = await this.dbPromise;
        // Overwrite then clear before deleting, so the wrapped DEK is gone even
        // if deleteDatabase is delayed by another open tab.
        for (const store of ['meta', 'records'] as const) {
          const os = db.transaction(store, 'readwrite').objectStore(store);
          await req(os.clear());
        }
        db.close();
      } catch {
        // fall through to deleteDatabase
      }
      this.dbPromise = null;
    }
    await new Promise<void>((resolve, reject) => {
      const r = this.factory.deleteDatabase(this.name);
      r.onsuccess = () => resolve();
      r.onerror = () => reject(r.error ?? new Error('IndexedDB delete failed'));
      r.onblocked = () => resolve(); // completes once other tabs close; data already cleared above
    });
  }
}
