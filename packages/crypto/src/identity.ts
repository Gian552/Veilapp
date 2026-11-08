// Account identity, device certification and prekeys.
//
// Trust hierarchy (see docs/CRYPTOGRAPHY.md):
//
//   Account Identity Key (AIK, Ed25519)        <- what contacts verify (safety number)
//     signs DeviceList { version, devices[] }
//       each device: deviceId, signing key (Ed25519), DH identity key (X25519)
//         device signing key signs its Signed PreKey (X25519)
//
// Only devices holding the AIK private key ("primary" devices) can add or
// remove devices, so the server cannot silently insert a device: any device
// not in a list signed by the pinned AIK is rejected by clients.

import { type Bytes, concat, constantTimeEqual, randomBytes, toB64, utf8 } from './bytes.js';
import { Reader, Writer } from './encoding.js';
import {
  CryptoError,
  type KeyPair,
  ed25519KeyPair,
  sha512,
  sign,
  verify,
  x25519KeyPair,
} from './primitives.js';

export const DEVICE_ID_LEN = 16;
const DEVICE_LIST_CONTEXT = 'VEIL/v1/device-list';
const SIGNED_PREKEY_CONTEXT = 'VEIL/v1/signed-prekey';
const MAX_DEVICES = 16;

export interface DeviceKeys {
  deviceId: Bytes;
  signing: KeyPair; // Ed25519
  dh: KeyPair; // X25519 identity key used in X3DH
}

export interface DeviceEntry {
  deviceId: Bytes;
  signingKey: Bytes;
  dhKey: Bytes;
  /** True if this device holds the account identity private key. */
  primary: boolean;
}

export interface DeviceList {
  identityKey: Bytes;
  version: number;
  devices: DeviceEntry[];
}

export interface SignedDeviceList {
  body: Bytes;
  signature: Bytes;
}

export function generateAccountIdentity(): KeyPair {
  return ed25519KeyPair();
}

export function generateDeviceKeys(): DeviceKeys {
  return { deviceId: randomBytes(DEVICE_ID_LEN), signing: ed25519KeyPair(), dh: x25519KeyPair() };
}

export function deviceEntryFor(keys: DeviceKeys, primary: boolean): DeviceEntry {
  return { deviceId: keys.deviceId, signingKey: keys.signing.publicKey, dhKey: keys.dh.publicKey, primary };
}

function compareBytes(a: Bytes, b: Bytes): number {
  for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i]! - b[i]!;
  return a.length - b.length;
}

export function encodeDeviceList(list: DeviceList): Bytes {
  if (list.devices.length === 0 || list.devices.length > MAX_DEVICES) throw new CryptoError('invalid device count');
  const devices = [...list.devices].sort((a, b) => compareBytes(a.deviceId, b.deviceId));
  for (let i = 1; i < devices.length; i++) {
    if (constantTimeEqual(devices[i - 1]!.deviceId, devices[i]!.deviceId)) throw new CryptoError('duplicate device id');
  }
  const w = new Writer().string('VEIL-device-list').u8(1).fixed(list.identityKey, 32).u64(list.version).u32(devices.length);
  for (const d of devices) {
    w.fixed(d.deviceId, DEVICE_ID_LEN).fixed(d.signingKey, 32).fixed(d.dhKey, 32).u8(d.primary ? 1 : 0);
  }
  return w.finish();
}

export function decodeDeviceList(body: Bytes): DeviceList {
  const r = new Reader(body);
  if (r.string(64) !== 'VEIL-device-list' || r.u8() !== 1) throw new CryptoError('unknown device list format');
  const identityKey = r.fixed(32);
  const version = r.u64();
  const count = r.u32();
  if (count === 0 || count > MAX_DEVICES) throw new CryptoError('invalid device count');
  const devices: DeviceEntry[] = [];
  for (let i = 0; i < count; i++) {
    const deviceId = r.fixed(DEVICE_ID_LEN);
    const signingKey = r.fixed(32);
    const dhKey = r.fixed(32);
    const flag = r.u8();
    if (flag > 1) throw new CryptoError('invalid device flag');
    devices.push({ deviceId, signingKey, dhKey, primary: flag === 1 });
  }
  r.end();
  // Canonical form only: re-encoding must reproduce the exact bytes (sorted, no duplicates).
  if (!constantTimeEqual(encodeDeviceList({ identityKey, version, devices }), body)) {
    throw new CryptoError('non-canonical device list');
  }
  return { identityKey, version, devices };
}

export function signDeviceList(identityPrivateKey: Bytes, list: DeviceList): SignedDeviceList {
  const body = encodeDeviceList(list);
  return { body, signature: sign(identityPrivateKey, DEVICE_LIST_CONTEXT, body) };
}

/**
 * Verifies the signature against the *expected* identity key (pinned by the
 * verifier), not against the key embedded in the list, and returns the list.
 */
export function verifyDeviceList(signed: SignedDeviceList, expectedIdentityKey: Bytes): DeviceList {
  if (!verify(expectedIdentityKey, DEVICE_LIST_CONTEXT, signed.body, signed.signature)) {
    throw new CryptoError('device list signature invalid');
  }
  const list = decodeDeviceList(signed.body);
  if (!constantTimeEqual(list.identityKey, expectedIdentityKey)) throw new CryptoError('device list identity mismatch');
  return list;
}

/** Reads the identity key out of a list without trusting it (for first contact / TOFU). */
export function peekDeviceListIdentity(body: Bytes): Bytes {
  return decodeDeviceList(body).identityKey;
}

// ---------------------------------------------------------------- prekeys

export interface SignedPreKey {
  keyId: number;
  keyPair: KeyPair;
  signature: Bytes;
}

export interface OneTimePreKey {
  keyId: number;
  keyPair: KeyPair;
}

function signedPrekeyBody(deviceId: Bytes, keyId: number, publicKey: Bytes): Bytes {
  return new Writer().fixed(deviceId, DEVICE_ID_LEN).u32(keyId).fixed(publicKey, 32).finish();
}

/** Signs an existing X25519 prekey with a device signing key (deterministic: Ed25519). */
export function signSignedPreKey(deviceSigningPrivateKey: Bytes, deviceId: Bytes, keyId: number, publicKey: Bytes): Bytes {
  return sign(deviceSigningPrivateKey, SIGNED_PREKEY_CONTEXT, signedPrekeyBody(deviceId, keyId, publicKey));
}

export function generateSignedPreKey(device: DeviceKeys, keyId: number): SignedPreKey {
  const keyPair = x25519KeyPair();
  const signature = sign(device.signing.privateKey, SIGNED_PREKEY_CONTEXT, signedPrekeyBody(device.deviceId, keyId, keyPair.publicKey));
  return { keyId, keyPair, signature };
}

export function verifySignedPreKey(
  deviceSigningKey: Bytes,
  deviceId: Bytes,
  keyId: number,
  publicKey: Bytes,
  signature: Bytes,
): boolean {
  return verify(deviceSigningKey, SIGNED_PREKEY_CONTEXT, signedPrekeyBody(deviceId, keyId, publicKey), signature);
}

export function generateOneTimePreKeys(startId: number, count: number): OneTimePreKey[] {
  const out: OneTimePreKey[] = [];
  for (let i = 0; i < count; i++) out.push({ keyId: (startId + i) >>> 0, keyPair: x25519KeyPair() });
  return out;
}

// ---------------------------------------------------------------- verification codes

const FINGERPRINT_ITERATIONS = 5200;

/**
 * Per-party fingerprint following Signal's NumericFingerprintGenerator (v1):
 * iterated SHA-512 over (version || key || stable identifier), then 30 bytes
 * rendered as six 5-digit groups.
 */
function partyFingerprint(identityKey: Bytes, stableId: string): string {
  const key = concat(utf8('VEIL-ed25519:'), identityKey);
  let hash = sha512(concat(new Uint8Array([0, 0]), key, utf8(stableId)));
  for (let i = 0; i < FINGERPRINT_ITERATIONS; i++) hash = sha512(concat(hash, key));
  let digits = '';
  for (let i = 0; i < 6; i++) {
    const c = hash.subarray(i * 5, i * 5 + 5);
    const n = c[0]! * 2 ** 32 + c[1]! * 2 ** 24 + c[2]! * 2 ** 16 + c[3]! * 2 ** 8 + c[4]!;
    digits += String(n % 100000).padStart(5, '0');
  }
  return digits;
}

/**
 * 60-digit safety number shared by two parties. Both sides compute the same
 * value (halves are sorted), so users compare it in person or over a trusted channel.
 */
export function safetyNumber(
  local: { identityKey: Bytes; username: string },
  remote: { identityKey: Bytes; username: string },
): string {
  const a = partyFingerprint(local.identityKey, local.username);
  const b = partyFingerprint(remote.identityKey, remote.username);
  const joined = a < b ? a + b : b + a;
  return joined.match(/.{5}/g)!.join(' ');
}

export function deviceIdString(deviceId: Bytes): string {
  return toB64(deviceId);
}
