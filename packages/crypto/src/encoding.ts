// Deterministic length-prefixed binary encoding for anything that is signed,
// MACed or used as associated data. JSON is never signed directly because its
// serialisation is not canonical across implementations.

import { type Bytes, concat, fromUtf8, u32be, utf8 } from './bytes.js';
import { CryptoError } from './primitives.js';

export class Writer {
  private parts: Bytes[] = [];

  u8(n: number): this {
    if (!Number.isInteger(n) || n < 0 || n > 255) throw new CryptoError('u8 out of range');
    this.parts.push(new Uint8Array([n]));
    return this;
  }

  u32(n: number): this {
    this.parts.push(u32be(n));
    return this;
  }

  /** Unsigned integer up to 2^53-1, encoded as 8 bytes. */
  u64(n: number): this {
    if (!Number.isSafeInteger(n) || n < 0) throw new CryptoError('u64 out of range');
    this.parts.push(u32be(Math.floor(n / 0x100000000)), u32be(n >>> 0));
    return this;
  }

  bytes(b: Bytes): this {
    this.parts.push(u32be(b.length), b);
    return this;
  }

  /** Fixed-length field: length is implied by the format and checked here. */
  fixed(b: Bytes, length: number): this {
    if (b.length !== length) throw new CryptoError(`expected ${length} bytes`);
    this.parts.push(b);
    return this;
  }

  string(s: string): this {
    return this.bytes(utf8(s));
  }

  finish(): Bytes {
    return concat(...this.parts);
  }
}

export class Reader {
  private offset = 0;

  constructor(private readonly buf: Bytes) {}

  private take(n: number): Bytes {
    if (n < 0 || this.offset + n > this.buf.length) throw new CryptoError('truncated input');
    const out = this.buf.subarray(this.offset, this.offset + n);
    this.offset += n;
    return out;
  }

  u8(): number {
    return this.take(1)[0]!;
  }

  u32(): number {
    const b = this.take(4);
    return ((b[0]! << 24) >>> 0) + (b[1]! << 16) + (b[2]! << 8) + b[3]!;
  }

  u64(): number {
    const hi = this.u32();
    const lo = this.u32();
    const n = hi * 0x100000000 + lo;
    if (!Number.isSafeInteger(n)) throw new CryptoError('u64 exceeds safe integer range');
    return n;
  }

  bytes(maxLength = 1 << 24): Bytes {
    const len = this.u32();
    if (len > maxLength) throw new CryptoError('field too long');
    return this.take(len).slice();
  }

  fixed(length: number): Bytes {
    return this.take(length).slice();
  }

  string(maxLength = 4096): string {
    return fromUtf8(this.bytes(maxLength));
  }

  /** Throws unless every byte was consumed: no trailing garbage in signed data. */
  end(): void {
    if (this.offset !== this.buf.length) throw new CryptoError('trailing bytes');
  }
}
