// Double Ratchet, following "The Double Ratchet Algorithm" (Perrin &
// Marlinspike, Signal, revision 1, 2016), section 3 (no header encryption).
//
//   KDF_RK: HKDF-SHA-256(salt = RK, ikm = DH output, info = "VEIL_DR_RK_v1") -> RK', CK
//   KDF_CK: MK = HMAC-SHA-256(CK, 0x01), CK' = HMAC-SHA-256(CK, 0x02)
//   ENCRYPT: HKDF(MK) -> 32-byte key + 24-byte nonce, XChaCha20-Poly1305,
//            associated data = AD || encoded header
//
// Decryption is transactional: it works on a copy of the state and only the
// caller's commit of the returned state makes changes durable, as the spec
// requires ("if an exception is raised ... discard any changes to the state").

import { type Bytes, concat, constantTimeEqual, fromB64, toB64, wipe } from './bytes.js';
import { Reader, Writer } from './encoding.js';
import { CryptoError, type KeyPair, dh, hkdf, hmacSha256, openWithNonce, sealWithNonce, x25519KeyPair } from './primitives.js';

/** Max message keys skipped within one chain (spec: MAX_SKIP). */
export const MAX_SKIP = 1000;
/** Max skipped keys retained in total; oldest are evicted first. */
export const MAX_SKIPPED_TOTAL = 2000;

const RK_INFO = 'VEIL_DR_RK_v1';
const MSG_INFO = 'VEIL_DR_MSG_v1';
const ZERO_SALT = new Uint8Array(32);

export interface RatchetHeader {
  dh: Bytes;
  pn: number;
  n: number;
}

export interface RatchetMessage {
  header: RatchetHeader;
  ciphertext: Bytes;
}

export interface RatchetState {
  dhs: KeyPair;
  dhr: Bytes | null;
  rk: Bytes;
  cks: Bytes | null;
  ckr: Bytes | null;
  ns: number;
  nr: number;
  pn: number;
  /** Skipped message keys, insertion-ordered. Key: `${b64(dh)}:${n}`. */
  skipped: Map<string, Bytes>;
  ad: Bytes;
}

function kdfRk(rk: Bytes, dhOut: Bytes): [Bytes, Bytes] {
  const out = hkdf(dhOut, rk, RK_INFO, 64);
  wipe(dhOut);
  return [out.slice(0, 32), out.slice(32, 64)];
}

function kdfCk(ck: Bytes): [Bytes, Bytes] {
  return [hmacSha256(ck, new Uint8Array([0x02])), hmacSha256(ck, new Uint8Array([0x01]))];
}

function messageKeyMaterial(mk: Bytes): { key: Bytes; nonce: Bytes } {
  const out = hkdf(mk, ZERO_SALT, MSG_INFO, 56);
  return { key: out.slice(0, 32), nonce: out.slice(32, 56) };
}

export function encodeHeader(h: RatchetHeader): Bytes {
  return new Writer().fixed(h.dh, 32).u32(h.pn).u32(h.n).finish();
}

export function encodeRatchetMessage(m: RatchetMessage): Bytes {
  return new Writer().fixed(m.header.dh, 32).u32(m.header.pn).u32(m.header.n).bytes(m.ciphertext).finish();
}

export function decodeRatchetMessage(bytes: Bytes): RatchetMessage {
  const r = new Reader(bytes);
  const header = { dh: r.fixed(32), pn: r.u32(), n: r.u32() };
  const ciphertext = r.bytes(1 << 26);
  r.end();
  return { header, ciphertext };
}

/** Initiator ("Alice") after X3DH: the responder's signed prekey is the first DHr. */
export function initRatchetInitiator(sharedKey: Bytes, remoteRatchetKey: Bytes, ad: Bytes): RatchetState {
  const dhs = x25519KeyPair();
  const [rk, cks] = kdfRk(sharedKey, dh(dhs.privateKey, remoteRatchetKey));
  return { dhs, dhr: remoteRatchetKey, rk, cks, ckr: null, ns: 0, nr: 0, pn: 0, skipped: new Map(), ad };
}

/** Responder ("Bob") after X3DH: the signed prekey pair is the first DHs. */
export function initRatchetResponder(sharedKey: Bytes, signedPreKey: KeyPair, ad: Bytes): RatchetState {
  return {
    dhs: { publicKey: signedPreKey.publicKey.slice(), privateKey: signedPreKey.privateKey.slice() },
    dhr: null,
    rk: sharedKey.slice(),
    cks: null,
    ckr: null,
    ns: 0,
    nr: 0,
    pn: 0,
    skipped: new Map(),
    ad,
  };
}

export function cloneState(s: RatchetState): RatchetState {
  return {
    dhs: { publicKey: s.dhs.publicKey.slice(), privateKey: s.dhs.privateKey.slice() },
    dhr: s.dhr ? s.dhr.slice() : null,
    rk: s.rk.slice(),
    cks: s.cks ? s.cks.slice() : null,
    ckr: s.ckr ? s.ckr.slice() : null,
    ns: s.ns,
    nr: s.nr,
    pn: s.pn,
    skipped: new Map([...s.skipped].map(([k, v]) => [k, v.slice()])),
    ad: s.ad.slice(),
  };
}

/** Encrypts and advances the sending chain. Mutates and returns `state`. */
export function ratchetEncrypt(state: RatchetState, plaintext: Bytes): RatchetMessage {
  if (!state.cks) throw new CryptoError('sending chain not initialised');
  const [nextCk, mk] = kdfCk(state.cks);
  wipe(state.cks);
  state.cks = nextCk;
  const header: RatchetHeader = { dh: state.dhs.publicKey, pn: state.pn, n: state.ns };
  state.ns += 1;
  const { key, nonce } = messageKeyMaterial(mk);
  const ciphertext = sealWithNonce(key, nonce, plaintext, concat(state.ad, encodeHeader(header)));
  wipe(mk, key);
  return { header, ciphertext };
}

function skippedId(dhPub: Bytes, n: number): string {
  return `${toB64(dhPub)}:${n}`;
}

function skipMessageKeys(state: RatchetState, until: number): void {
  if (state.nr + MAX_SKIP < until) throw new CryptoError('too many skipped messages');
  if (!state.ckr || !state.dhr) return;
  while (state.nr < until) {
    const [nextCk, mk] = kdfCk(state.ckr);
    state.ckr = nextCk;
    state.skipped.set(skippedId(state.dhr, state.nr), mk);
    state.nr += 1;
  }
  while (state.skipped.size > MAX_SKIPPED_TOTAL) {
    const oldest = state.skipped.keys().next().value as string;
    wipe(state.skipped.get(oldest));
    state.skipped.delete(oldest);
  }
}

function dhRatchet(state: RatchetState, header: RatchetHeader): void {
  state.pn = state.ns;
  state.ns = 0;
  state.nr = 0;
  state.dhr = header.dh.slice();
  [state.rk, state.ckr] = kdfRk(state.rk, dh(state.dhs.privateKey, state.dhr));
  wipe(state.dhs.privateKey);
  state.dhs = x25519KeyPair();
  [state.rk, state.cks] = kdfRk(state.rk, dh(state.dhs.privateKey, state.dhr));
}

function decryptWith(mk: Bytes, msg: RatchetMessage, ad: Bytes): Bytes {
  const { key, nonce } = messageKeyMaterial(mk);
  try {
    return openWithNonce(key, nonce, msg.ciphertext, concat(ad, encodeHeader(msg.header)));
  } finally {
    wipe(key);
  }
}

/**
 * Decrypts without touching `state`; returns the plaintext and the successor
 * state to persist. A replayed message finds no key (its key was deleted after
 * first use, or its counter is behind the chain) and fails.
 */
export function ratchetDecrypt(state: RatchetState, msg: RatchetMessage): { plaintext: Bytes; state: RatchetState } {
  if (msg.header.dh.length !== 32) throw new CryptoError('invalid header');
  const next = cloneState(state);
  const id = skippedId(msg.header.dh, msg.header.n);
  const skippedKey = next.skipped.get(id);
  if (skippedKey) {
    const plaintext = decryptWith(skippedKey, msg, next.ad);
    wipe(skippedKey);
    next.skipped.delete(id);
    return { plaintext, state: next };
  }
  if (!next.dhr || !constantTimeEqual(msg.header.dh, next.dhr)) {
    skipMessageKeys(next, msg.header.pn);
    dhRatchet(next, msg.header);
  }
  if (msg.header.n < next.nr) throw new CryptoError('duplicate or expired message');
  skipMessageKeys(next, msg.header.n);
  const [nextCk, mk] = kdfCk(next.ckr!);
  next.ckr = nextCk;
  next.nr += 1;
  const plaintext = decryptWith(mk, msg, next.ad);
  wipe(mk);
  return { plaintext, state: next };
}

// ---------------------------------------------------------------- persistence

export interface SerializedRatchetState {
  v: 1;
  dhsPub: string;
  dhsPriv: string;
  dhr: string | null;
  rk: string;
  cks: string | null;
  ckr: string | null;
  ns: number;
  nr: number;
  pn: number;
  skipped: [string, string][];
  ad: string;
}

export function serializeState(s: RatchetState): SerializedRatchetState {
  return {
    v: 1,
    dhsPub: toB64(s.dhs.publicKey),
    dhsPriv: toB64(s.dhs.privateKey),
    dhr: s.dhr ? toB64(s.dhr) : null,
    rk: toB64(s.rk),
    cks: s.cks ? toB64(s.cks) : null,
    ckr: s.ckr ? toB64(s.ckr) : null,
    ns: s.ns,
    nr: s.nr,
    pn: s.pn,
    skipped: [...s.skipped].map(([k, v]) => [k, toB64(v)]),
    ad: toB64(s.ad),
  };
}

export function deserializeState(j: SerializedRatchetState): RatchetState {
  if (j.v !== 1) throw new CryptoError('unknown ratchet state version');
  return {
    dhs: { publicKey: fromB64(j.dhsPub), privateKey: fromB64(j.dhsPriv) },
    dhr: j.dhr ? fromB64(j.dhr) : null,
    rk: fromB64(j.rk),
    cks: j.cks ? fromB64(j.cks) : null,
    ckr: j.ckr ? fromB64(j.ckr) : null,
    ns: j.ns,
    nr: j.nr,
    pn: j.pn,
    skipped: new Map(j.skipped.map(([k, v]) => [k, fromB64(v)])),
    ad: fromB64(j.ad),
  };
}

export function destroyState(s: RatchetState): void {
  wipe(s.dhs.privateKey, s.rk, s.cks, s.ckr);
  for (const v of s.skipped.values()) wipe(v);
  s.skipped.clear();
}
