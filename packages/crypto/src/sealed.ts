// Public-key "sealed box" (ECIES-style: ephemeral X25519 + HKDF-SHA-256 +
// XChaCha20-Poly1305, analogous to libsodium crypto_box_seal) and the
// sealed-sender message envelope built on it.
//
// The sealed box provides confidentiality towards the recipient key only; it
// does NOT authenticate the sender. Sender authenticity of messages comes from
// the inner Double Ratchet / X3DH layer, which binds both identity keys.

import { type Bytes, concat, utf8 } from './bytes.js';
import { Reader, Writer } from './encoding.js';
import { DEVICE_ID_LEN } from './identity.js';
import { CryptoError, dh, hkdf, open, seal, x25519KeyPair } from './primitives.js';
import { type RatchetMessage, decodeRatchetMessage, encodeRatchetMessage } from './ratchet.js';

export function sealToPublicKey(recipientPublicKey: Bytes, plaintext: Bytes, context: string, ad: Bytes): Bytes {
  const eph = x25519KeyPair();
  const shared = dh(eph.privateKey, recipientPublicKey);
  const key = hkdf(shared, concat(eph.publicKey, recipientPublicKey), context, 32);
  const sealed = seal(key, plaintext, concat(utf8(context), ad));
  shared.fill(0);
  key.fill(0);
  eph.privateKey.fill(0);
  return concat(eph.publicKey, sealed);
}

export function openWithPrivateKey(recipient: { publicKey: Bytes; privateKey: Bytes }, sealed: Bytes, context: string, ad: Bytes): Bytes {
  if (sealed.length < 32) throw new CryptoError('ciphertext too short');
  const ephPub = sealed.subarray(0, 32);
  const shared = dh(recipient.privateKey, ephPub);
  const key = hkdf(shared, concat(ephPub, recipient.publicKey), context, 32);
  try {
    return open(key, sealed.subarray(32), concat(utf8(context), ad));
  } finally {
    shared.fill(0);
    key.fill(0);
  }
}

// ---------------------------------------------------------------- envelopes

const ENVELOPE_CONTEXT = 'VEIL/v1/sealed-envelope';

export interface PreKeyMessage {
  senderIdentityKey: Bytes; // sender AIK (Ed25519)
  senderDhKey: Bytes; // sender device IK (X25519)
  baseKey: Bytes; // EK_A
  signedPreKeyId: number;
  oneTimePreKeyId: number | undefined;
  message: RatchetMessage;
}

export type InnerMessage = { kind: 'prekey'; prekey: PreKeyMessage } | { kind: 'ratchet'; message: RatchetMessage };

export interface EnvelopeContents {
  senderUsername: string;
  senderDeviceId: Bytes;
  inner: InnerMessage;
}

function encodeInner(inner: InnerMessage): Bytes {
  if (inner.kind === 'ratchet') return new Writer().u8(2).bytes(encodeRatchetMessage(inner.message)).finish();
  const p = inner.prekey;
  return new Writer()
    .u8(1)
    .fixed(p.senderIdentityKey, 32)
    .fixed(p.senderDhKey, 32)
    .fixed(p.baseKey, 32)
    .u32(p.signedPreKeyId)
    .u8(p.oneTimePreKeyId === undefined ? 0 : 1)
    .u32(p.oneTimePreKeyId ?? 0)
    .bytes(encodeRatchetMessage(p.message))
    .finish();
}

function decodeInner(r: Reader): InnerMessage {
  const kind = r.u8();
  if (kind === 2) return { kind: 'ratchet', message: decodeRatchetMessage(r.bytes(1 << 26)) };
  if (kind !== 1) throw new CryptoError('unknown inner message kind');
  const senderIdentityKey = r.fixed(32);
  const senderDhKey = r.fixed(32);
  const baseKey = r.fixed(32);
  const signedPreKeyId = r.u32();
  const hasOtk = r.u8();
  const otk = r.u32();
  if (hasOtk > 1) throw new CryptoError('invalid flag');
  const message = decodeRatchetMessage(r.bytes(1 << 26));
  return {
    kind: 'prekey',
    prekey: { senderIdentityKey, senderDhKey, baseKey, signedPreKeyId, oneTimePreKeyId: hasOtk ? otk : undefined, message },
  };
}

function envelopeAd(recipientDeviceId: Bytes): Bytes {
  if (recipientDeviceId.length !== DEVICE_ID_LEN) throw new CryptoError('invalid device id');
  return recipientDeviceId;
}

/**
 * Seals routing information (who sent it, from which device) together with
 * the ratchet message, so the server stores only `recipientDeviceId -> blob`.
 */
export function sealEnvelope(recipientDeviceId: Bytes, recipientDhKey: Bytes, contents: EnvelopeContents): Bytes {
  const body = new Writer()
    .u8(1)
    .string(contents.senderUsername)
    .fixed(contents.senderDeviceId, DEVICE_ID_LEN)
    .bytes(encodeInner(contents.inner))
    .finish();
  return sealToPublicKey(recipientDhKey, body, ENVELOPE_CONTEXT, envelopeAd(recipientDeviceId));
}

export function openEnvelope(recipientDeviceId: Bytes, recipientDh: { publicKey: Bytes; privateKey: Bytes }, sealed: Bytes): EnvelopeContents {
  const body = openWithPrivateKey(recipientDh, sealed, ENVELOPE_CONTEXT, envelopeAd(recipientDeviceId));
  const r = new Reader(body);
  if (r.u8() !== 1) throw new CryptoError('unknown envelope version');
  const senderUsername = r.string(64);
  const senderDeviceId = r.fixed(DEVICE_ID_LEN);
  const inner = decodeInner(new Reader(r.bytes(1 << 26)));
  r.end();
  return { senderUsername, senderDeviceId, inner };
}
