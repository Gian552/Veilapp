// Device login proof and device-linking (provisioning) encodings.
//
// Linking flow (docs/CRYPTOGRAPHY.md §Device linking):
//  1. New device N (password-authenticated "link" session) generates device keys,
//     an ephemeral X25519 provisioning key, and a random 80-bit link code C. It
//     uploads a LinkRequest carrying only a commitment to C, and displays C.
//  2. The user types C on the primary device P. P checks the commitment, which
//     authenticates the request: the server never sees C and cannot produce a
//     matching commitment for a substituted request.
//  3. P signs a new device list containing N, seals a provisioning payload to N's
//     provisioning key and MACs the result with a key derived from C. N verifies
//     the MAC before opening anything, so the server cannot forge an approval.

import { type Bytes, concat, constantTimeEqual, randomBytes } from './bytes.js';
import { Reader, Writer } from './encoding.js';
import { DEVICE_ID_LEN } from './identity.js';
import { openWithPrivateKey, sealToPublicKey } from './sealed.js';
import { CryptoError, hkdf, hmacSha256, sign, verify } from './primitives.js';

const LOGIN_CONTEXT = 'VEIL/v1/device-login';
const PROVISIONING_CONTEXT = 'VEIL/v1/provisioning';
const LINK_SECRET_LEN = 10; // 80 bits
const MAC_LEN = 32;
const CODE_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

export function deviceLoginMessage(nonce: string, username: string): Bytes {
  return new Writer().string(nonce).string(username).finish();
}

export function signDeviceLogin(deviceSigningPrivateKey: Bytes, nonce: string, username: string): Bytes {
  return sign(deviceSigningPrivateKey, LOGIN_CONTEXT, deviceLoginMessage(nonce, username));
}

export function verifyDeviceLogin(deviceSigningKey: Bytes, nonce: string, username: string, signature: Bytes): boolean {
  return verify(deviceSigningKey, LOGIN_CONTEXT, deviceLoginMessage(nonce, username), signature);
}

// ---------------------------------------------------------------- link code

export function generateLinkSecret(): Bytes {
  return randomBytes(LINK_SECRET_LEN);
}

/** 16 Crockford base32 characters in groups of four, e.g. `7K2M-QX9P-…`. */
export function formatLinkCode(secret: Bytes): string {
  if (secret.length !== LINK_SECRET_LEN) throw new CryptoError('invalid link secret');
  let bits = 0;
  let value = 0;
  let out = '';
  for (const b of secret) {
    value = ((value << 8) | b) & 0xffff;
    bits += 8;
    while (bits >= 5) {
      out += CODE_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  return out.match(/.{4}/g)!.join('-');
}

export function parseLinkCode(text: string): Bytes {
  const s = text.toUpperCase().replace(/[\s-]/g, '').replace(/O/g, '0').replace(/[IL]/g, '1');
  if (s.length !== 16) throw new CryptoError('invalid link code');
  const out = new Uint8Array(LINK_SECRET_LEN);
  let bits = 0;
  let value = 0;
  let o = 0;
  for (const ch of s) {
    const idx = CODE_ALPHABET.indexOf(ch);
    if (idx < 0) throw new CryptoError('invalid link code');
    value = ((value << 5) | idx) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (value >>> bits) & 0xff;
    }
  }
  return out;
}

// ---------------------------------------------------------------- link request

export interface LinkRequestCore {
  deviceId: Bytes;
  signingKey: Bytes;
  dhKey: Bytes;
  provisioningKey: Bytes;
}

export interface LinkRequest extends LinkRequestCore {
  /** HMAC(HKDF(code), core): binds the request to the code shown on the new device. */
  commitment: Bytes;
}

function encodeCore(r: LinkRequestCore): Bytes {
  return new Writer()
    .string('VEIL-link-request')
    .u8(2)
    .fixed(r.deviceId, DEVICE_ID_LEN)
    .fixed(r.signingKey, 32)
    .fixed(r.dhKey, 32)
    .fixed(r.provisioningKey, 32)
    .finish();
}

function commitKey(secret: Bytes): Bytes {
  return hkdf(secret, undefined, 'VEIL/v1/link-commit', 32);
}

function macKey(secret: Bytes): Bytes {
  return hkdf(secret, undefined, 'VEIL/v1/link-mac', 32);
}

export function encodeLinkRequest(core: LinkRequestCore, secret: Bytes): Bytes {
  const body = encodeCore(core);
  return concat(body, hmacSha256(commitKey(secret), body));
}

export function decodeLinkRequest(bytes: Bytes): LinkRequest {
  if (bytes.length < MAC_LEN) throw new CryptoError('invalid link request');
  const body = bytes.subarray(0, bytes.length - MAC_LEN);
  const rd = new Reader(body);
  if (rd.string(64) !== 'VEIL-link-request' || rd.u8() !== 2) throw new CryptoError('unknown link request format');
  const out = {
    deviceId: rd.fixed(DEVICE_ID_LEN),
    signingKey: rd.fixed(32),
    dhKey: rd.fixed(32),
    provisioningKey: rd.fixed(32),
    commitment: bytes.slice(bytes.length - MAC_LEN),
  };
  rd.end();
  return out;
}

/** True only if `secret` (the code the user typed) is the one this request committed to. */
export function verifyLinkRequest(request: Bytes, secret: Bytes): boolean {
  const r = decodeLinkRequest(request);
  const body = request.subarray(0, request.length - MAC_LEN);
  return constantTimeEqual(hmacSha256(commitKey(secret), body), r.commitment);
}

/**
 * Seals the provisioning payload to the request's provisioning key and appends
 * HMAC(HKDF(code), request ‖ sealed). Refuses requests that don't match the code.
 */
export function sealProvisioning(request: Bytes, secret: Bytes, plaintext: Bytes): Bytes {
  if (!verifyLinkRequest(request, secret)) throw new CryptoError('link code does not match this request');
  const sealed = sealToPublicKey(decodeLinkRequest(request).provisioningKey, plaintext, PROVISIONING_CONTEXT, request);
  return concat(sealed, hmacSha256(macKey(secret), concat(request, sealed)));
}

/** Verifies the code-derived MAC before decrypting: an unapproved (forged) payload is rejected. */
export function openProvisioning(request: Bytes, secret: Bytes, provisioningKey: { publicKey: Bytes; privateKey: Bytes }, data: Bytes): Bytes {
  if (data.length < MAC_LEN + 32) throw new CryptoError('invalid provisioning payload');
  const sealed = data.subarray(0, data.length - MAC_LEN);
  const mac = data.subarray(data.length - MAC_LEN);
  if (!constantTimeEqual(hmacSha256(macKey(secret), concat(request, sealed)), mac)) {
    throw new CryptoError('provisioning payload not approved with this link code');
  }
  return openWithPrivateKey(provisioningKey, sealed, PROVISIONING_CONTEXT, request);
}
