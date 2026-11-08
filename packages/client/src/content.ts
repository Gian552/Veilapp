// Plaintext formats that only ever exist inside end-to-end encryption.
// Everything decrypted is validated before use: a malicious contact must not
// be able to crash or confuse the client with malformed content.

import { b64Fixed, b64Max, z } from '@veil/shared';
import { fromUtf8, utf8 } from '@veil/crypto';

/** Upper bound for Lamport clocks in messages. */
export const MAX_CLOCK = 2 ** 40;

const Id = b64Fixed(16);
const Key = b64Fixed(32);
const Name = z.string().min(6).max(18);

export const AttachmentPointer = z
  .object({
    id: Id,
    key: Key,
    digest: Key,
    name: z.string().max(255),
    mime: z.string().max(127),
    size: z.number().int().min(0).max(10 * 1024 * 1024),
  })
  .strict();
export type AttachmentPointer = z.infer<typeof AttachmentPointer>;

const Body = {
  id: Id,
  // Bounded so a contact cannot push clocks past what snapshots (backup,
  // provisioning) accept: 2^40 leaves room for the restore jump below 2^50.
  clock: z.number().int().min(1).max(MAX_CLOCK),
  text: z.string().max(16_000),
  att: z.array(AttachmentPointer).max(8),
};

export const Content = z.discriminatedUnion('t', [
  /** A message from the sender to the recipient. */
  z.object({ v: z.literal(1), t: z.literal('msg'), ...Body }).strict(),
  /** Transcript of a message one of *my* devices sent to `to` (own-device sync). */
  z.object({ v: z.literal(1), t: z.literal('sent'), to: Name, ...Body }).strict(),
  /** Opt-in read receipt. */
  z.object({ v: z.literal(1), t: z.literal('read'), ids: z.array(Id).min(1).max(500) }).strict(),
  /** Profile key so the contact can decrypt my optional display name. */
  z.object({ v: z.literal(1), t: z.literal('profile'), key: Key.nullable() }).strict(),
  /** Own-device sync of a contact's pinned identity key and verification state. */
  z.object({ v: z.literal(1), t: z.literal('contact'), username: Name, identityKey: Key, verified: z.boolean() }).strict(),
]);
export type Content = z.infer<typeof Content>;

export const ContactSnapshot = z
  .object({
    username: Name,
    identityKey: Key,
    verified: z.boolean(),
    /** Last known Lamport clock of the conversation, so a new device orders after existing history. */
    clock: z.number().int().min(0).max(2 ** 50).optional(),
  })
  .strict();
export type ContactSnapshot = z.infer<typeof ContactSnapshot>;

const SettingsSchema = z.object({ readReceipts: z.boolean(), shareProfile: z.boolean(), displayName: z.string().max(64) }).strict();

/** Sent from the primary device to a newly linked device (sealed to its provisioning key). */
export const ProvisioningPayload = z
  .object({
    v: z.literal(1),
    username: Name,
    identityKey: Key,
    deviceList: z.object({ body: b64Max(4096), signature: b64Fixed(64) }).strict(),
    profileKey: Key,
    contacts: z.array(ContactSnapshot).max(10_000),
    settings: SettingsSchema,
  })
  .strict();
export type ProvisioningPayload = z.infer<typeof ProvisioningPayload>;

/** Encrypted with the recovery-derived backup key and stored on the server. */
export const RecoveryBackup = z
  .object({
    v: z.literal(1),
    /** Newest device-list version confirmed when the backup was written (rollback protection). */
    deviceListVersion: z.number().int().min(0).max(2 ** 50).optional(),
    identityPrivateKey: Key,
    profileKey: Key,
    contacts: z.array(ContactSnapshot).max(10_000),
  })
  .strict();
export type RecoveryBackup = z.infer<typeof RecoveryBackup>;

export const Profile = z.object({ v: z.literal(1), displayName: z.string().max(64) }).strict();

// ---------------------------------------------------------------- padding

const PAD_BLOCK = 256;

/**
 * ISO/IEC 7816-4 padding to a multiple of 256 bytes (0x80 then zeros), so
 * ciphertext length reveals only a coarse size bucket, as in Signal.
 */
export function pad(content: Content): Uint8Array {
  const raw = utf8(JSON.stringify(content));
  const total = Math.ceil((raw.length + 1) / PAD_BLOCK) * PAD_BLOCK;
  const out = new Uint8Array(total);
  out.set(raw);
  out[raw.length] = 0x80;
  return out;
}

export function unpad(bytes: Uint8Array): Content {
  let end = bytes.length - 1;
  while (end >= 0 && bytes[end] === 0) end--;
  if (end < 0 || bytes[end] !== 0x80) throw new Error('invalid padding');
  return Content.parse(JSON.parse(fromUtf8(bytes.subarray(0, end))));
}

export function encodeJson(value: unknown): Uint8Array {
  return utf8(JSON.stringify(value));
}

export function decodeJson(bytes: Uint8Array): unknown {
  return JSON.parse(fromUtf8(bytes));
}

