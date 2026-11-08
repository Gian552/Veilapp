// Byte helpers shared by every protocol module. Nothing in here is secret-aware
// except `wipe` and `constantTimeEqual`; callers decide what to zero.

import { randomBytes as nobleRandomBytes } from '@noble/hashes/utils.js';

export type Bytes = Uint8Array;

/** CSPRNG bytes (crypto.getRandomValues under the hood, in browsers and Node). */
export function randomBytes(length: number): Bytes {
  return nobleRandomBytes(length);
}

export function concat(...parts: Bytes[]): Bytes {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

export function utf8(text: string): Bytes {
  return encoder.encode(text);
}

export function fromUtf8(bytes: Bytes): string {
  return decoder.decode(bytes);
}

/** Compare without early exit. Length is not secret in any of our call sites. */
export function constantTimeEqual(a: Bytes, b: Bytes): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/**
 * Best-effort zeroisation. JavaScript engines may have copied the buffer
 * elsewhere (GC moves, string conversions), so this reduces but does not
 * eliminate the lifetime of secrets in memory. Documented in docs/CRYPTOGRAPHY.md.
 */
export function wipe(...buffers: (Bytes | undefined | null)[]): void {
  for (const b of buffers) if (b) b.fill(0);
}

const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const B64URL_LOOKUP = (() => {
  const t = new Int16Array(128).fill(-1);
  for (let i = 0; i < B64URL.length; i++) t[B64URL.charCodeAt(i)] = i;
  return t;
})();

/** Unpadded base64url. */
export function toB64(bytes: Bytes): string {
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8) | bytes[i + 2]!;
    out += B64URL[(n >> 18) & 63]! + B64URL[(n >> 12) & 63]! + B64URL[(n >> 6) & 63]! + B64URL[n & 63]!;
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const n = bytes[i]! << 16;
    out += B64URL[(n >> 18) & 63]! + B64URL[(n >> 12) & 63]!;
  } else if (rest === 2) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8);
    out += B64URL[(n >> 18) & 63]! + B64URL[(n >> 12) & 63]! + B64URL[(n >> 6) & 63]!;
  }
  return out;
}

export function fromB64(text: string): Bytes {
  if (text.length % 4 === 1) throw new Error('invalid base64url length');
  const out = new Uint8Array(Math.floor((text.length * 3) / 4));
  let buffer = 0;
  let bits = 0;
  let o = 0;
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    const v = code < 128 ? B64URL_LOOKUP[code]! : -1;
    if (v < 0) throw new Error('invalid base64url character');
    buffer = (buffer << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (buffer >> bits) & 0xff;
    }
  }
  // Reject non-canonical encodings (non-zero trailing bits).
  if (bits > 0 && (buffer & ((1 << bits) - 1)) !== 0) throw new Error('non-canonical base64url');
  return out;
}

export function toHex(bytes: Bytes): string {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

export function fromHex(hex: string): Bytes {
  const clean = hex.replace(/\s+/g, '');
  if (clean.length % 2 !== 0 || /[^0-9a-fA-F]/.test(clean)) throw new Error('invalid hex');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function u32be(n: number): Bytes {
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) throw new Error('u32 out of range');
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

export function u64be(n: number): Bytes {
  if (!Number.isSafeInteger(n) || n < 0) throw new Error('u64 out of range');
  const hi = Math.floor(n / 0x100000000);
  const lo = n >>> 0;
  return concat(u32be(hi), u32be(lo));
}
