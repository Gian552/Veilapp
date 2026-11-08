// Decoy accounts: the directory never reveals whether a username exists.
//
// For any well-formed username that is not assigned (never registered, or
// retired by Panic Reset) the server answers with a deterministic decoy: an
// identity key, a signed one-device list and a signed prekey, all derived from
// the server secret and the name. They are real, correctly signed keys, so a
// client cannot tell a decoy from a quiet account. Envelopes sent to a decoy
// device are accepted and silently discarded; nobody holds the private keys.
//
// Decoy device ids are self-authenticating (second half is a MAC of the first),
// so the send route recognises them without a lookup table.
//
// Limits (docs/METADATA.md): decoys never reply, never change devices, and a
// decoy's keys change if the name is later assigned to a real account.

import {
  type Bytes,
  type SignedDeviceList,
  concat,
  constantTimeEqual,
  ed25519PublicFromPrivate,
  hkdf,
  hmacSha256,
  randomBytes,
  signDeviceList,
  signSignedPreKey,
  toB64,
  utf8,
  x25519PublicFromPrivate,
} from '@veil/crypto';

export interface Decoy {
  username: string;
  identityKey: Bytes;
  deviceList: SignedDeviceList;
  deviceId: Bytes;
  signedPreKey: { keyId: number; publicKey: Bytes; signature: Bytes };
}

const CACHE_MAX = 1024;
const cache = new Map<string, Decoy>();

function seed(key: Bytes, label: string, name: string): Bytes {
  return hkdf(key, undefined, `veil-decoy/v1/${label}/${name.toLowerCase()}`, 32);
}

export function decoyDeviceId(key: Bytes, name: string): Bytes {
  const head = hmacSha256(key, utf8(`device-id/${name.toLowerCase()}`)).subarray(0, 8);
  return concat(head, hmacSha256(key, concat(utf8('device-tag/'), head)).subarray(0, 8));
}

export function isDecoyDeviceId(key: Bytes, id: Bytes): boolean {
  if (id.length !== 16) return false;
  const tag = hmacSha256(key, concat(utf8('device-tag/'), id.subarray(0, 8))).subarray(0, 8);
  return constantTimeEqual(tag, id.subarray(8));
}

/** `canonical` must already be the canonical username (see canonicalUsername). */
export function decoyFor(key: Bytes, canonical: string): Decoy {
  // Keyed by server key as well as name: a decoy must never outlive the key it was derived from.
  const cacheKey = `${toB64(hmacSha256(key, utf8('decoy-cache'))).slice(0, 16)}:${canonical.toLowerCase()}`;
  const hit = cache.get(cacheKey);
  if (hit) return hit;
  const aikPriv = seed(key, 'identity', canonical);
  const signingPriv = seed(key, 'device-signing', canonical);
  const dhPriv = seed(key, 'device-dh', canonical);
  const spkPriv = seed(key, 'signed-prekey', canonical);
  const identityKey = ed25519PublicFromPrivate(aikPriv);
  const deviceId = decoyDeviceId(key, canonical);
  const signingKey = ed25519PublicFromPrivate(signingPriv);
  const deviceList = signDeviceList(aikPriv, {
    identityKey,
    version: 1,
    devices: [{ deviceId, signingKey, dhKey: x25519PublicFromPrivate(dhPriv), primary: true }],
  });
  // Real devices rotate their signed prekey weekly; vary the id a little.
  const keyId = 1 + (seed(key, 'signed-prekey-id', canonical)[0]! % 12);
  const spkPub = x25519PublicFromPrivate(spkPriv);
  const decoy: Decoy = {
    username: canonical,
    identityKey,
    deviceList,
    deviceId,
    signedPreKey: { keyId, publicKey: spkPub, signature: signSignedPreKey(signingPriv, deviceId, keyId, spkPub) },
  };
  for (const b of [aikPriv, signingPriv, dhPriv, spkPriv]) b.fill(0);
  if (cache.size >= CACHE_MAX) cache.delete(cache.keys().next().value as string);
  cache.set(cacheKey, decoy);
  return decoy;
}

/** A fresh one-time prekey, as a real device with plenty of them would hand out. */
export function decoyOneTimePreKey(): { keyId: number; publicKey: Bytes } {
  const r = randomBytes(4);
  return { keyId: 1 + (((r[0]! << 8) | r[1]!) % 4000), publicKey: x25519PublicFromPrivate(randomBytes(32)) };
}
