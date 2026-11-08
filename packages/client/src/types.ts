// Public types of the headless VEIL client engine. The web UI depends only on
// these types and on the VeilClient class; it never touches keys directly.

import type { AccountExport, PublicConfig, ResetStatus } from '@veil/shared';

/** Persistent storage. `meta` holds non-secret bootstrap data; `records` holds vault ciphertext. */
export interface StorageBackend {
  get(store: 'meta' | 'records', key: string): Promise<Uint8Array | undefined>;
  put(store: 'meta' | 'records', key: string, value: Uint8Array): Promise<void>;
  delete(store: 'meta' | 'records', key: string): Promise<void>;
  keys(store: 'meta' | 'records'): Promise<string[]>;
  /** Irreversibly removes the whole local database. */
  destroy(): Promise<void>;
}

export type ClientStatus =
  | 'no-vault' // nothing on this device: onboarding or sign-in
  | 'locked' // an encrypted vault exists, password needed
  | 'needs-link' // signed in with password but this device is not enrolled yet
  | 'ready'
  | 'reset-pending'; // a Panic Reset was interrupted and must be resumed

export type ConnectionState = 'offline' | 'connecting' | 'online';

export type Verification = 'unverified' | 'verified' | 'key-changed';

export interface ConversationSummary {
  peer: string; // the contact's username
  displayName: string | null; // only if the contact shares a profile
  preview: string | null; // last message text, decrypted locally
  unread: number;
  verification: Verification;
  accountGone: boolean; // the contact's account no longer exists (e.g. they used Panic Reset)
}

export interface AttachmentRef {
  attachmentId: string;
  name: string;
  mime: string;
  size: number;
}

export type SystemNotice = 'key-changed' | 'device-added' | 'device-removed' | 'verified' | 'unverified' | 'account-gone' | 'session-started';

export interface ChatMessage {
  id: string;
  peer: string;
  direction: 'in' | 'out' | 'system';
  /** Logical ordering (Lamport clock); not a wall-clock time. */
  clock: number;
  text: string;
  attachments: AttachmentRef[];
  status: 'sending' | 'sent' | 'failed' | 'received';
  /** Only populated when read receipts are enabled on both sides. */
  readByPeer: boolean;
  notice?: SystemNotice;
}

export interface DeviceInfo {
  deviceId: string;
  primary: boolean;
  current: boolean;
  /** Short human-comparable fingerprint of the device keys. */
  fingerprint: string;
}

export interface SessionSummary {
  sessionId: string;
  kind: 'device' | 'link';
  deviceId: string | null;
  current: boolean;
}

export interface PendingLink {
  linkId: string;
}

export interface PrivacySettings {
  /** Opt-in: send read receipts (reveals when you read messages to the sender). */
  readReceipts: boolean;
  /** Opt-in: share an encrypted display name with contacts. */
  shareProfile: boolean;
  displayName: string;
}

export interface ClientSnapshot {
  status: ClientStatus;
  connection: ConnectionState;
  username: string | null;
  deviceId: string | null;
  isPrimary: boolean;
  recoveryEnabled: boolean;
  conversations: ConversationSummary[];
  settings: PrivacySettings;
  /** Set while a link request from this (new) device is awaiting approval. */
  linkCode: string | null;
}

export type ResetPhase =
  | 'initiated' // user confirmed, journal written
  | 'server-deleting' // request sent / retrying
  | 'server-deleted' // server confirmed account rows deleted
  | 'local-wiped' // local vault destroyed
  | 'new-identity' // replacement identity registered
  | 'completed'
  | 'partial' // some step could not be confirmed; see report
  | 'failed';

export interface ResetReport {
  phase: ResetPhase;
  server: ResetStatus | null;
  localWiped: boolean;
  newIdentity: { username: string; distinctFromOld: boolean; recoveryKey: string | null } | null;
  /** Human-readable explanation of anything not confirmed. Empty when everything was confirmed. */
  problems: string[];
  /** Inherent limits that apply even to a fully completed reset (backups, recipients' copies). */
  notes: string[];
}

export interface ResetOptions {
  /** Register a replacement identity right away (otherwise the app returns to onboarding). */
  createNewIdentity: boolean;
  newPassword?: string;
  enableRecovery?: boolean;
  /** Wipe this device even if the server cannot be reached. */
  wipeLocallyIfServerUnreachable?: boolean;
}

export interface ExportedServerData {
  server: AccountExport;
}

export type { AccountExport, PublicConfig, ResetStatus };

/**
 * The surface the UI uses. Every method that talks to the server can reject
 * with a VeilError (see errors.ts) whose `code` is safe to show to users.
 */
export interface VeilClientApi {
  snapshot(): ClientSnapshot;
  subscribe(listener: (s: ClientSnapshot) => void): () => void;
  /** Fires when messages of a conversation change (new message, status, receipt). */
  onConversation(listener: (peer: string) => void): () => void;

  /** Reads local bootstrap data and sets status to no-vault / locked / reset-pending. */
  init(): Promise<void>;
  publicConfig(): Promise<PublicConfig>;

  // onboarding & sign-in
  suggestUsername(): Promise<{ username: string; reservation: string }>;
  register(input: { reservation: string; password: string; enableRecovery: boolean; onProgress?: (step: string) => void }): Promise<{ username: string; recoveryKey: string | null }>;
  /** Unlocks the local vault (if any) and signs in. Generic error on bad credentials. */
  /**
   * `previousPassword` is only needed when the password was changed on another
   * device: this device's vault is still sealed with the old one.
   */
  signIn(input: { username: string; password: string; previousPassword?: string; onProgress?: (step: string) => void }): Promise<ClientStatus>;
  lock(): Promise<void>;
  /**
   * Irreversibly erases everything VEIL stored on this device (user-confirmed).
   * Offered when this device can no longer sign in, e.g. after Panic Reset on another device.
   */
  eraseLocalData(): Promise<void>;
  /** Signs out and removes this device from the account (non-primary) or just ends the session (primary). */
  signOut(): Promise<void>;

  // new-device enrollment (status === 'needs-link')
  requestLink(): Promise<{ code: string }>;
  /** Resolves once the primary device approved and this device is enrolled. */
  waitForLinkApproval(signal?: AbortSignal): Promise<void>;
  /** Restore the identity from a recovery key; this device becomes the primary device. */
  restoreWithRecoveryKey(recoveryKey: string): Promise<void>;
  /** Forgotten password: requires the recovery key, sets a new password, restores identity. */
  recoverAccount(input: { username: string; recoveryKey: string; newPassword: string }): Promise<void>;

  // linking from the primary device
  pendingLinks(): Promise<PendingLink[]>;
  /** `code` is what the new device displays; the user types it here. It authenticates both directions. */
  approveLink(linkId: string, code: string): Promise<void>;
  rejectLink(linkId: string): Promise<void>;

  // conversations
  startConversation(username: string): Promise<void>;
  messages(peer: string): ChatMessage[];
  sendText(peer: string, text: string): Promise<void>;
  sendAttachment(peer: string, file: { name: string; mime: string; bytes: Uint8Array }): Promise<void>;
  downloadAttachment(peer: string, messageId: string, attachmentId: string): Promise<{ name: string; mime: string; bytes: Uint8Array }>;
  markRead(peer: string): Promise<void>;
  deleteConversation(peer: string): Promise<void>;
  safetyNumber(peer: string): string;
  setVerified(peer: string, verified: boolean): Promise<void>;
  /** Accept a changed identity key after the user has been warned. Resets verification. */
  acceptKeyChange(peer: string): Promise<void>;
  /** Re-fetch keys of a contact (detects key changes / gone accounts). */
  refreshContact(peer: string): Promise<void>;

  // settings
  updateSettings(patch: Partial<PrivacySettings>): Promise<void>;
  devices(): Promise<DeviceInfo[]>;
  removeDevice(deviceId: string): Promise<void>;
  sessions(): Promise<SessionSummary[]>;
  revokeSession(sessionId: string): Promise<void>;
  changePassword(currentPassword: string, newPassword: string): Promise<void>;
  /** Creates (or replaces) the recovery key; returns it once for the user to write down. */
  enableRecovery(): Promise<string>;
  disableRecovery(): Promise<void>;
  exportServerData(): Promise<AccountExport>;
  /** Local plaintext export of conversations on this device (user-initiated download). */
  exportLocalData(): Promise<unknown>;

  // panic reset
  panicReset(options: ResetOptions, onProgress: (report: ResetReport) => void): Promise<ResetReport>;
  /** Continues a reset that was interrupted (status === 'reset-pending'). Needs the password to unlock. */
  resumeReset(password: string, onProgress: (report: ResetReport) => void): Promise<ResetReport>;
}
