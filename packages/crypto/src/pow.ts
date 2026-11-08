// Hashcash-style proof of work used to slow automated registration without
// tracking anyone: the server issues a MACed challenge, the client finds a
// nonce such that SHA-256(challenge || nonce) has `difficulty` leading zero bits.

import { type Bytes, concat, u32be } from './bytes.js';
import { sha256 } from './primitives.js';

export function leadingZeroBits(hash: Bytes): number {
  let bits = 0;
  for (const byte of hash) {
    if (byte === 0) {
      bits += 8;
      continue;
    }
    return bits + Math.clz32(byte) - 24;
  }
  return bits;
}

export function checkProofOfWork(challenge: Bytes, nonce: number, difficulty: number): boolean {
  if (!Number.isInteger(nonce) || nonce < 0 || nonce > 0xffffffff) return false;
  return leadingZeroBits(sha256(concat(challenge, u32be(nonce)))) >= difficulty;
}

/** Solves in chunks, yielding to the event loop so the UI stays responsive. */
export async function solveProofOfWork(challenge: Bytes, difficulty: number, signal?: AbortSignal): Promise<number> {
  for (let nonce = 0; nonce <= 0xffffffff; nonce++) {
    if (checkProofOfWork(challenge, nonce, difficulty)) return nonce;
    if ((nonce & 0x3fff) === 0) {
      if (signal?.aborted) throw new Error('aborted');
      await new Promise((r) => setTimeout(r, 0));
    }
  }
  throw new Error('proof of work not found');
}
