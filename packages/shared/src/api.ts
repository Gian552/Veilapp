// VEIL HTTP/WebSocket API contract. The server validates every request body
// with these schemas (strict: unknown fields are rejected) and the client
// validates every response. All binary values are unpadded base64url strings.
//
// Endpoint summary (all under /v1, JSON unless noted):
//
//   auth      POST auth/challenge, auth/username, auth/register, auth/prelogin,
//                  auth/login, auth/refresh, auth/logout, auth/password, auth/recover
//   sessions  GET sessions, DELETE sessions/:sessionId
//   account   GET account, GET account/export, PUT profile
//   directory GET directory/:username
//   devices   PUT devices/list, DELETE devices/self, POST devices/enroll
//   linking   POST link/requests, GET link/requests, GET link/requests/:linkId,
//             POST link/requests/:linkId/response, DELETE link/requests/:linkId
//   keys      PUT keys/signed-prekey, POST keys/one-time, GET keys/status, POST keys/bundles
//   messages  POST messages, GET mailbox, POST mailbox/ack, GET ws (WebSocket)
//   media     POST attachments (octet-stream), GET attachments/:id, POST attachments/:id/delete
//   recovery  PUT recovery, PUT recovery/backup, DELETE recovery, GET recovery/backup
//   reset     POST reset, POST reset/status
//   public    GET config, GET /healthz
//
// Authentication: `Authorization: Bearer <accessToken>`. Tokens never appear in URLs.

import { z } from 'zod';
import { ADJECTIVES, NOUNS } from './words.js';

// ---------------------------------------------------------------- primitives

const B64_RE = /^[A-Za-z0-9_-]*$/;

/** base64url of exactly `bytes` bytes. */
export const b64Fixed = (bytes: number) =>
  z
    .string()
    .length(Math.ceil((bytes * 4) / 3))
    .regex(B64_RE);

/** base64url of at most `maxBytes` bytes (and at least `minBytes`). */
export const b64Max = (maxBytes: number, minBytes = 1) =>
  z
    .string()
    .min(Math.ceil((minBytes * 4) / 3))
    .max(Math.ceil((maxBytes * 4) / 3))
    .regex(B64_RE);

export const Key32 = b64Fixed(32);
export const Sig64 = b64Fixed(64);
export const Id16 = b64Fixed(16);
export const KeyId = z.number().int().min(0).max(0xffffffff);

const ADJ = new Set(ADJECTIVES);
const NOUN = new Set(NOUNS);

/** Two capitalised words, first from ADJECTIVES, second from NOUNS. */
export function isValidUsername(name: string): boolean {
  const m = /^([A-Z][a-z]{2,8})([A-Z][a-z]{2,8})$/.exec(name);
  return !!m && ADJ.has(m[1]!) && NOUN.has(m[2]!);
}

export const Username = z.string().min(6).max(18).refine(isValidUsername, 'invalid username');

/**
 * Canonical capitalisation of a username typed in any case (`velvetfalcon` →
 * `VelvetFalcon`), or null if it is not two words from the lists. Works purely
 * on the public word lists, so it reveals nothing about which accounts exist.
 */
export function canonicalUsername(input: string): string | null {
  const lower = input.trim().toLowerCase();
  if (!/^[a-z]{6,18}$/.test(lower)) return null;
  const cap = (w: string) => w.charAt(0).toUpperCase() + w.slice(1);
  for (let i = 3; i <= lower.length - 3; i++) {
    const a = cap(lower.slice(0, i));
    const b = cap(lower.slice(i));
    if (ADJ.has(a) && NOUN.has(b)) return a + b;
  }
  return null;
}

export const KdfParams = z
  .object({
    memoryKiB: z.number().int().min(8).max(1024 * 1024),
    iterations: z.number().int().min(1).max(64),
    parallelism: z.number().int().min(1).max(16),
  })
  .strict();
export type KdfParams = z.infer<typeof KdfParams>;

export const SignedDeviceListJson = z.object({ body: b64Max(16 + 64 + 16 * 81 + 64), signature: Sig64 }).strict();
export type SignedDeviceListJson = z.infer<typeof SignedDeviceListJson>;

export const DevicePublic = z.object({ deviceId: Id16, signingKey: Key32, dhKey: Key32 }).strict();
export type DevicePublic = z.infer<typeof DevicePublic>;

export const SignedPreKeyJson = z.object({ keyId: KeyId, publicKey: Key32, signature: Sig64 }).strict();
export type SignedPreKeyJson = z.infer<typeof SignedPreKeyJson>;

export const OneTimePreKeyJson = z.object({ keyId: KeyId, publicKey: Key32 }).strict();
export type OneTimePreKeyJson = z.infer<typeof OneTimePreKeyJson>;

export const MAX_ONE_TIME_PREKEYS_PER_UPLOAD = 200;
export const MAX_RECOVERY_BACKUP_BYTES = 256 * 1024;
export const MAX_PROFILE_BYTES = 4096;
export const MAX_ENVELOPE_BYTES = 256 * 1024;
export const MAX_ENVELOPES_PER_SEND = 64;
export const MAX_ATTACHMENT_BLOB_BYTES = 10 * 1024 * 1024 + 64;
export const MAX_LINK_REQUEST_BYTES = 1024;
export const MAX_PROVISIONING_BYTES = 512 * 1024;

// ---------------------------------------------------------------- errors

export const ErrorCode = z.enum([
  'bad_request',
  'unauthorized',
  'forbidden',
  'not_found',
  'conflict',
  'rate_limited',
  'payload_too_large',
  'internal',
]);
export type ErrorCode = z.infer<typeof ErrorCode>;
export const ErrorResponse = z.object({ error: z.object({ code: ErrorCode, message: z.string() }) });
export type ErrorResponse = z.infer<typeof ErrorResponse>;

// ---------------------------------------------------------------- auth

export const SessionKind = z.enum(['device', 'link']);
export type SessionKind = z.infer<typeof SessionKind>;

export const SessionResponse = z.object({
  accessToken: z.string(),
  refreshToken: z.string(),
  accessExpiresIn: z.number().int(),
  kind: SessionKind,
  username: Username,
  /** Present for device sessions. */
  deviceId: Id16.nullable(),
});
export type SessionResponse = z.infer<typeof SessionResponse>;

export const ChallengeResponse = z.object({ challenge: z.string().max(256), difficulty: z.number().int().min(0).max(32) });
export type ChallengeResponse = z.infer<typeof ChallengeResponse>;

export const UsernameSuggestion = z.object({ username: Username, reservation: z.string().max(512) });
export type UsernameSuggestion = z.infer<typeof UsernameSuggestion>;

export const RegisterRequest = z
  .object({
    reservation: z.string().max(512),
    pow: z.object({ challenge: z.string().max(256), nonce: z.number().int().min(0).max(0xffffffff) }).strict(),
    clientSalt: b64Fixed(16),
    kdf: KdfParams,
    authKey: Key32,
    identityKey: Key32,
    deviceList: SignedDeviceListJson,
    device: DevicePublic,
    signedPreKey: SignedPreKeyJson,
    oneTimePreKeys: z.array(OneTimePreKeyJson).max(MAX_ONE_TIME_PREKEYS_PER_UPLOAD),
    recovery: z.object({ verifierKey: Key32, backup: b64Max(MAX_RECOVERY_BACKUP_BYTES) }).strict().optional(),
  })
  .strict();
export type RegisterRequest = z.infer<typeof RegisterRequest>;

export const PreloginRequest = z.object({ username: z.string().max(64) }).strict();
export const PreloginResponse = z.object({ clientSalt: b64Fixed(16), kdf: KdfParams, nonce: z.string().max(256) });
export type PreloginResponse = z.infer<typeof PreloginResponse>;

export const LoginRequest = z
  .object({
    username: z.string().max(64),
    authKey: Key32,
    nonce: z.string().max(256),
    /** Proof of possession of an enrolled device: Ed25519 over deviceLoginMessage(nonce, username). */
    device: z.object({ deviceId: Id16, signature: Sig64 }).strict().optional(),
  })
  .strict();
export type LoginRequest = z.infer<typeof LoginRequest>;

export const RefreshRequest = z.object({ refreshToken: z.string().max(256) }).strict();

export const ChangePasswordRequest = z
  .object({ currentAuthKey: Key32, newClientSalt: b64Fixed(16), newKdf: KdfParams, newAuthKey: Key32 })
  .strict();
export type ChangePasswordRequest = z.infer<typeof ChangePasswordRequest>;

export const RecoverRequest = z
  .object({
    username: z.string().max(64),
    recoveryKey: Key32, // recoveryAuthKey derived from the recovery secret, never the secret itself
    newClientSalt: b64Fixed(16),
    newKdf: KdfParams,
    newAuthKey: Key32,
  })
  .strict();
export type RecoverRequest = z.infer<typeof RecoverRequest>;
export const RecoverResponse = z.object({ session: SessionResponse, backup: b64Max(MAX_RECOVERY_BACKUP_BYTES) });
export type RecoverResponse = z.infer<typeof RecoverResponse>;

// ---------------------------------------------------------------- sessions & account

export const SessionInfo = z.object({ sessionId: Id16, kind: SessionKind, deviceId: Id16.nullable(), current: z.boolean() });
export type SessionInfo = z.infer<typeof SessionInfo>;
export const SessionsResponse = z.object({ sessions: z.array(SessionInfo) });

export const AccountResponse = z.object({
  username: Username,
  identityKey: Key32,
  deviceList: SignedDeviceListJson,
  recoveryEnabled: z.boolean(),
  profile: b64Max(MAX_PROFILE_BYTES).nullable(),
});
export type AccountResponse = z.infer<typeof AccountResponse>;

/** Everything the server stores about the caller's account (data-access transparency). */
export const AccountExport = z.object({
  username: Username,
  identityKey: Key32,
  deviceList: SignedDeviceListJson,
  devices: z.array(z.object({ deviceId: Id16, signingKey: Key32, dhKey: Key32, oneTimePreKeys: z.number(), signedPreKeyId: z.number().nullable(), queuedEnvelopes: z.number() })),
  sessions: z.array(z.object({ sessionId: Id16, kind: SessionKind, deviceId: Id16.nullable(), expiresDay: z.number() })),
  recovery: z.object({ enabled: z.boolean(), backupBytes: z.number() }),
  profile: z.object({ present: z.boolean(), bytes: z.number() }),
  pendingLinkRequests: z.number(),
  notStored: z.array(z.string()),
});
export type AccountExport = z.infer<typeof AccountExport>;

export const ProfileUpdate = z.object({ profile: b64Max(MAX_PROFILE_BYTES).nullable() }).strict();

export const DirectoryEntry = z.object({
  username: Username,
  identityKey: Key32,
  deviceList: SignedDeviceListJson,
  profile: b64Max(MAX_PROFILE_BYTES).nullable(),
});
export type DirectoryEntry = z.infer<typeof DirectoryEntry>;

// ---------------------------------------------------------------- devices & linking

export const DeviceListUpdate = z.object({ deviceList: SignedDeviceListJson }).strict();

export const EnrollRequest = z
  .object({
    deviceList: SignedDeviceListJson,
    device: DevicePublic,
    signedPreKey: SignedPreKeyJson,
    oneTimePreKeys: z.array(OneTimePreKeyJson).max(MAX_ONE_TIME_PREKEYS_PER_UPLOAD),
    linkId: Id16.optional(),
  })
  .strict();
export type EnrollRequest = z.infer<typeof EnrollRequest>;

export const CreateLinkRequest = z.object({ request: b64Max(MAX_LINK_REQUEST_BYTES) }).strict();
export const CreateLinkResponse = z.object({ linkId: Id16 });
export const PendingLinkRequests = z.object({ requests: z.array(z.object({ linkId: Id16, request: b64Max(MAX_LINK_REQUEST_BYTES) })) });
export const LinkResponseUpload = z.object({ payload: b64Max(MAX_PROVISIONING_BYTES) }).strict();
export const LinkStatus = z.object({ status: z.enum(['pending', 'approved']), payload: b64Max(MAX_PROVISIONING_BYTES).nullable() });
export type LinkStatus = z.infer<typeof LinkStatus>;

// ---------------------------------------------------------------- prekeys

export const OneTimePreKeyUpload = z.object({ preKeys: z.array(OneTimePreKeyJson).min(1).max(MAX_ONE_TIME_PREKEYS_PER_UPLOAD) }).strict();
export const KeyStatus = z.object({ oneTimePreKeys: z.number().int(), signedPreKeyId: KeyId.nullable() });
export type KeyStatus = z.infer<typeof KeyStatus>;

export const BundleRequest = z.object({ username: z.string().max(64), deviceIds: z.array(Id16).max(16).optional() }).strict();
export const DeviceBundle = z.object({ deviceId: Id16, signedPreKey: SignedPreKeyJson, oneTimePreKey: OneTimePreKeyJson.nullable() });
export type DeviceBundle = z.infer<typeof DeviceBundle>;
export const BundleResponse = z.object({
  username: Username,
  identityKey: Key32,
  deviceList: SignedDeviceListJson,
  bundles: z.array(DeviceBundle),
});
export type BundleResponse = z.infer<typeof BundleResponse>;

// ---------------------------------------------------------------- messages

export const OutgoingEnvelope = z.object({ deviceId: Id16, envelopeId: Id16, payload: b64Max(MAX_ENVELOPE_BYTES) }).strict();
export type OutgoingEnvelope = z.infer<typeof OutgoingEnvelope>;
export const SendRequest = z.object({ envelopes: z.array(OutgoingEnvelope).min(1).max(MAX_ENVELOPES_PER_SEND) }).strict();
export const SendResponse = z.object({ accepted: z.number().int(), unknownDevices: z.array(Id16) });
export type SendResponse = z.infer<typeof SendResponse>;

export const MailboxResponse = z.object({ envelopes: z.array(z.object({ envelopeId: Id16, payload: b64Max(MAX_ENVELOPE_BYTES) })), more: z.boolean() });
export type MailboxResponse = z.infer<typeof MailboxResponse>;
export const AckRequest = z.object({ envelopeIds: z.array(Id16).min(1).max(500) }).strict();

/** WebSocket frames. The socket carries notifications only, never message content. */
export const WsClientFrame = z.discriminatedUnion('type', [
  z.object({ type: z.literal('auth'), accessToken: z.string().max(512) }).strict(),
  z.object({ type: z.literal('ping') }).strict(),
]);
export type WsClientFrame = z.infer<typeof WsClientFrame>;
export const WsServerFrame = z.discriminatedUnion('type', [
  z.object({ type: z.literal('ready') }),
  z.object({ type: z.literal('mail') }),
  z.object({ type: z.literal('link') }),
  z.object({ type: z.literal('revoked') }),
  z.object({ type: z.literal('pong') }),
]);
export type WsServerFrame = z.infer<typeof WsServerFrame>;

// ---------------------------------------------------------------- attachments

export const AttachmentUploadResponse = z.object({ attachmentId: Id16, deleteToken: Key32 });
export type AttachmentUploadResponse = z.infer<typeof AttachmentUploadResponse>;
export const AttachmentDelete = z.object({ deleteToken: Key32 }).strict();

// ---------------------------------------------------------------- recovery

export const RecoverySetup = z.object({ verifierKey: Key32, backup: b64Max(MAX_RECOVERY_BACKUP_BYTES) }).strict();
export const RecoveryBackupUpdate = z.object({ backup: b64Max(MAX_RECOVERY_BACKUP_BYTES) }).strict();
export const RecoveryBackupResponse = z.object({ backup: b64Max(MAX_RECOVERY_BACKUP_BYTES) });

// ---------------------------------------------------------------- panic reset

export const ResetRequest = z
  .object({
    jobId: Id16,
    jobSecret: Key32,
    attachments: z.array(z.object({ attachmentId: Id16, deleteToken: Key32 }).strict()).max(5000),
  })
  .strict();
export type ResetRequest = z.infer<typeof ResetRequest>;
export const ResetStatusRequest = z.object({ jobId: Id16, jobSecret: Key32 }).strict();

export const ResetState = z.enum(['account_deleted', 'completed', 'partial']);
export const ResetStatus = z.object({
  jobId: Id16,
  state: ResetState,
  /** True once the single transaction deleting all account rows has committed. */
  accountRecordsDeleted: z.boolean(),
  attachmentsDeleted: z.number().int(),
  attachmentsPending: z.number().int(),
  attachmentsNotFound: z.number().int(),
  /** Days until database backups containing the old account have rotated out. */
  backupRetentionDays: z.number().int(),
  /** Days until undeliverable / unreferenced attachment blobs expire regardless. */
  attachmentRetentionDays: z.number().int(),
});
export type ResetStatus = z.infer<typeof ResetStatus>;

// ---------------------------------------------------------------- public config

export const PublicConfig = z.object({
  registrationPowDifficulty: z.number().int(),
  minimumKdf: KdfParams,
  recommendedKdf: KdfParams,
  attachmentMaxBytes: z.number().int(),
  retention: z.object({
    undeliveredMessageDays: z.number().int(),
    attachmentDays: z.number().int(),
    sessionDays: z.number().int(),
    backupDays: z.number().int(),
    resetJobDays: z.number().int(),
  }),
});
export type PublicConfig = z.infer<typeof PublicConfig>;
