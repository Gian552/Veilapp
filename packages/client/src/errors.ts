// Errors surfaced to the UI. `message` is always safe to display: it never
// contains key material, tokens, ciphertext or server internals.

export type VeilErrorCode =
  | 'network' // server unreachable
  | 'invalid_credentials' // generic: wrong username or password (never says which)
  | 'rate_limited'
  | 'not_found' // e.g. username does not exist
  | 'conflict' // e.g. username taken during registration race
  | 'unauthorized' // session expired or revoked
  | 'forbidden' // e.g. action requires the primary device
  | 'key_changed' // contact identity key changed; user must accept before sending
  | 'account_gone' // contact account no longer exists
  | 'invalid_input'
  | 'crypto' // verification / decryption failed
  | 'locked' // vault locked
  | 'internal';

export class VeilError extends Error {
  constructor(
    readonly code: VeilErrorCode,
    message: string,
    readonly retryAfterSeconds?: number,
  ) {
    super(message);
    this.name = 'VeilError';
  }
}
