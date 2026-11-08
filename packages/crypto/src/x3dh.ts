// X3DH key agreement, following "The X3DH Key Agreement Protocol"
// (Marlinspike & Perrin, Signal, 2016), with X25519 + SHA-256 + HKDF.
//
// Deviation from the spec text (documented in docs/CRYPTOGRAPHY.md):
//  - The X25519 identity key IK is a per-device key certified by the account
//    identity key (Ed25519) via the signed device list, instead of using XEdDSA
//    to sign with the DH key itself.
//  - AD additionally binds both account identity keys and device ids.

import { type Bytes, concat, wipe } from './bytes.js';
import { Writer } from './encoding.js';
import { DEVICE_ID_LEN, verifySignedPreKey } from './identity.js';
import { CryptoError, type KeyPair, dh, hkdf, x25519KeyPair } from './primitives.js';

const X3DH_INFO = 'VEIL_X3DH_v1';
const F = new Uint8Array(32).fill(0xff);
const ZERO_SALT = new Uint8Array(32);

export interface PreKeyBundle {
  identityKey: Bytes; // remote AIK (Ed25519), already verified against the pinned key
  deviceId: Bytes;
  deviceSigningKey: Bytes;
  deviceDhKey: Bytes; // IK_B
  signedPreKey: { keyId: number; publicKey: Bytes; signature: Bytes };
  oneTimePreKey?: { keyId: number; publicKey: Bytes } | undefined;
}

export interface LocalDeviceIdentity {
  identityKey: Bytes; // own AIK public
  deviceId: Bytes;
  dh: KeyPair; // IK_A
}

export interface X3DHInitiation {
  sharedKey: Bytes;
  associatedData: Bytes;
  baseKey: Bytes; // EK_A public, sent to the responder
  signedPreKeyId: number;
  oneTimePreKeyId: number | undefined;
  remoteSignedPreKey: Bytes; // initial DHr for the Double Ratchet
}

export function x3dhAssociatedData(
  initiator: { identityKey: Bytes; deviceId: Bytes; dhKey: Bytes },
  responder: { identityKey: Bytes; deviceId: Bytes; dhKey: Bytes },
): Bytes {
  return new Writer()
    .string('VEIL-X3DH-AD')
    .fixed(initiator.identityKey, 32)
    .fixed(initiator.deviceId, DEVICE_ID_LEN)
    .fixed(initiator.dhKey, 32)
    .fixed(responder.identityKey, 32)
    .fixed(responder.deviceId, DEVICE_ID_LEN)
    .fixed(responder.dhKey, 32)
    .finish();
}

function kdf(dhs: Bytes[]): Bytes {
  const ikm = concat(F, ...dhs);
  try {
    return hkdf(ikm, ZERO_SALT, X3DH_INFO, 32);
  } finally {
    wipe(ikm, ...dhs);
  }
}

export function x3dhInitiate(local: LocalDeviceIdentity, bundle: PreKeyBundle): X3DHInitiation {
  const spk = bundle.signedPreKey;
  if (!verifySignedPreKey(bundle.deviceSigningKey, bundle.deviceId, spk.keyId, spk.publicKey, spk.signature)) {
    throw new CryptoError('signed prekey signature invalid');
  }
  const ek = x25519KeyPair();
  const dhs = [dh(local.dh.privateKey, spk.publicKey), dh(ek.privateKey, bundle.deviceDhKey), dh(ek.privateKey, spk.publicKey)];
  if (bundle.oneTimePreKey) dhs.push(dh(ek.privateKey, bundle.oneTimePreKey.publicKey));
  const sharedKey = kdf(dhs);
  wipe(ek.privateKey);
  return {
    sharedKey,
    associatedData: x3dhAssociatedData(
      { identityKey: local.identityKey, deviceId: local.deviceId, dhKey: local.dh.publicKey },
      { identityKey: bundle.identityKey, deviceId: bundle.deviceId, dhKey: bundle.deviceDhKey },
    ),
    baseKey: ek.publicKey,
    signedPreKeyId: spk.keyId,
    oneTimePreKeyId: bundle.oneTimePreKey?.keyId,
    remoteSignedPreKey: spk.publicKey,
  };
}

export interface X3DHResponderInput {
  local: LocalDeviceIdentity;
  signedPreKey: KeyPair;
  oneTimePreKey?: KeyPair | undefined;
  remote: { identityKey: Bytes; deviceId: Bytes; dhKey: Bytes; baseKey: Bytes };
}

export function x3dhRespond(input: X3DHResponderInput): { sharedKey: Bytes; associatedData: Bytes } {
  const { local, signedPreKey, oneTimePreKey, remote } = input;
  const dhs = [
    dh(signedPreKey.privateKey, remote.dhKey),
    dh(local.dh.privateKey, remote.baseKey),
    dh(signedPreKey.privateKey, remote.baseKey),
  ];
  if (oneTimePreKey) dhs.push(dh(oneTimePreKey.privateKey, remote.baseKey));
  return {
    sharedKey: kdf(dhs),
    associatedData: x3dhAssociatedData(
      { identityKey: remote.identityKey, deviceId: remote.deviceId, dhKey: remote.dhKey },
      { identityKey: local.identityKey, deviceId: local.deviceId, dhKey: local.dh.publicKey },
    ),
  };
}
