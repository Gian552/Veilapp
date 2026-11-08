// Password- and recovery-key-based derivations.
//
//   password --Argon2id(clientSalt)--> master
//       master --HKDF "VEIL/v1/auth-key"--------> authKey   (sent to server, which Argon2id-hashes it again)
//       master --HKDF "VEIL/v1/local-vault-kek"--> vaultKek  (never leaves the device)
//
//   recoveryKey (240 random bits)
//       --HKDF "VEIL/v1/recovery-auth"--> recoveryAuthKey (server stores an Argon2id verifier of it)
//       --HKDF "VEIL/v1/recovery-backup"-> backupKey     (encrypts the identity backup; never sent)
//
// The server only ever sees authKey / recoveryAuthKey. Because HKDF outputs with
// different labels are independent, knowledge of authKey gives no information
// about vaultKek or backupKey. A server-side password reset therefore cannot
// restore access to any encrypted data.

import { argon2id } from 'hash-wasm';
import { type Bytes, constantTimeEqual, randomBytes, utf8, wipe } from './bytes.js';
import { CryptoError, hkdf, sha256 } from './primitives.js';

export interface Argon2Params {
  /** Memory in KiB. */
  memoryKiB: number;
  iterations: number;
  parallelism: number;
}

/**
 * RFC 9106 §4, second recommended option (64 MiB, t=3, p=4), used for the
 * client-side password stretch. Parameters are stored per account so they can
 * be raised later without breaking existing logins.
 */
export const CLIENT_ARGON2_DEFAULT: Argon2Params = { memoryKiB: 64 * 1024, iterations: 3, parallelism: 4 };

/** Lower bound the server accepts at registration. Tests use their own explicit params. */
export const CLIENT_ARGON2_MINIMUM: Argon2Params = { memoryKiB: 19 * 1024, iterations: 2, parallelism: 1 };

export const CLIENT_SALT_LEN = 16;

export function newClientSalt(): Bytes {
  return randomBytes(CLIENT_SALT_LEN);
}

export function argon2ParamsAtLeast(p: Argon2Params, min: Argon2Params): boolean {
  return p.memoryKiB >= min.memoryKiB && p.iterations >= min.iterations && p.parallelism >= min.parallelism;
}

/** Unicode-normalise so the same password typed on different platforms derives the same key. */
export function normalisePassword(password: string): Bytes {
  return utf8(password.normalize('NFKC'));
}

export async function deriveMasterKey(password: string, clientSalt: Bytes, params: Argon2Params): Promise<Bytes> {
  if (clientSalt.length !== CLIENT_SALT_LEN) throw new CryptoError('invalid client salt');
  const pw = normalisePassword(password);
  try {
    const out = await argon2id({
      password: pw,
      salt: clientSalt,
      iterations: params.iterations,
      parallelism: params.parallelism,
      memorySize: params.memoryKiB,
      hashLength: 32,
      outputType: 'binary',
    });
    return out;
  } finally {
    wipe(pw);
  }
}

export interface PasswordKeys {
  authKey: Bytes;
  vaultKek: Bytes;
}

export function splitMasterKey(master: Bytes): PasswordKeys {
  return {
    authKey: hkdf(master, undefined, 'VEIL/v1/auth-key', 32),
    vaultKek: hkdf(master, undefined, 'VEIL/v1/local-vault-kek', 32),
  };
}

export async function derivePasswordKeys(password: string, clientSalt: Bytes, params: Argon2Params): Promise<PasswordKeys> {
  const master = await deriveMasterKey(password, clientSalt, params);
  try {
    return splitMasterKey(master);
  } finally {
    wipe(master);
  }
}

// ---------------------------------------------------------------- recovery key

/** Crockford base32: no I, L, O, U; decoding tolerates the common confusions. */
const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const RECOVERY_SECRET_LEN = 30; // 240 bits of entropy
const RECOVERY_CHECKSUM_LEN = 2;

export interface RecoveryKeys {
  recoveryAuthKey: Bytes;
  backupKey: Bytes;
}

export function generateRecoverySecret(): Bytes {
  return randomBytes(RECOVERY_SECRET_LEN);
}

function base32Encode(bytes: Bytes): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += CROCKFORD[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += CROCKFORD[(value << (5 - bits)) & 31];
  return out;
}

function base32Decode(text: string, byteLength: number): Bytes {
  const out = new Uint8Array(byteLength);
  let bits = 0;
  let value = 0;
  let o = 0;
  for (const ch of text) {
    const idx = CROCKFORD.indexOf(ch);
    if (idx < 0) throw new CryptoError('invalid recovery key character');
    value = ((value << 5) | idx) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      if (o < byteLength) out[o++] = (value >>> bits) & 0xff;
    }
  }
  if (o !== byteLength) throw new CryptoError('invalid recovery key length');
  return out;
}

/** Human-readable form: 13 groups of 4 characters, last 16 bits are a typo checksum. */
export function formatRecoveryKey(secret: Bytes): string {
  if (secret.length !== RECOVERY_SECRET_LEN) throw new CryptoError('invalid recovery secret');
  const checksum = sha256(secret).subarray(0, RECOVERY_CHECKSUM_LEN);
  const full = new Uint8Array(RECOVERY_SECRET_LEN + RECOVERY_CHECKSUM_LEN);
  full.set(secret);
  full.set(checksum, RECOVERY_SECRET_LEN);
  const encoded = base32Encode(full);
  return encoded.match(/.{1,4}/g)!.join('-');
}

export function parseRecoveryKey(text: string): Bytes {
  const normalised = text
    .toUpperCase()
    .replace(/[\s-]/g, '')
    .replace(/O/g, '0')
    .replace(/[IL]/g, '1');
  // Exactly 52 characters: trailing garbage is rejected rather than ignored.
  if (normalised.length !== Math.ceil(((RECOVERY_SECRET_LEN + RECOVERY_CHECKSUM_LEN) * 8) / 5)) {
    throw new CryptoError('invalid recovery key length');
  }
  const full = base32Decode(normalised, RECOVERY_SECRET_LEN + RECOVERY_CHECKSUM_LEN);
  const secret = full.slice(0, RECOVERY_SECRET_LEN);
  const expected = sha256(secret).subarray(0, RECOVERY_CHECKSUM_LEN);
  if (!constantTimeEqual(expected, full.subarray(RECOVERY_SECRET_LEN))) {
    throw new CryptoError('recovery key checksum mismatch');
  }
  return secret;
}

export function deriveRecoveryKeys(secret: Bytes): RecoveryKeys {
  if (secret.length !== RECOVERY_SECRET_LEN) throw new CryptoError('invalid recovery secret');
  return {
    recoveryAuthKey: hkdf(secret, undefined, 'VEIL/v1/recovery-auth', 32),
    backupKey: hkdf(secret, undefined, 'VEIL/v1/recovery-backup', 32),
  };
}

export const RECOVERY_BACKUP_AD = utf8('VEIL/v1/recovery-backup-blob');
