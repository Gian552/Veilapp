// VeilClient: the headless client engine. Owns all key material (in memory
// only while unlocked, encrypted in the local vault otherwise), talks to the
// server exclusively through ciphertext, and orchestrates linking, recovery
// and Panic Reset. The UI only ever sees the VeilClientApi surface.

import {
  type Argon2Params,
  type Bytes,
  CLIENT_ARGON2_MINIMUM,
  CryptoError,
  type DeviceEntry,
  type DeviceList,
  type KeyPair,
  RECOVERY_BACKUP_AD,
  argon2ParamsAtLeast,
  constantTimeEqual,
  decodeLinkRequest,
  decryptAttachment,
  derivePasswordKeys,
  deriveRecoveryKeys,
  deviceEntryFor,
  ed25519PublicFromPrivate,
  encodeLinkRequest,
  encryptAttachment,
  formatRecoveryKey,
  fromB64,
  generateAccountIdentity,
  generateDeviceKeys,
  generateOneTimePreKeys,
  generateRecoverySecret,
  generateSignedPreKey,
  formatLinkCode,
  generateLinkSecret,
  parseLinkCode,
  newClientSalt,
  open,
  openEnvelope,
  openProvisioning,
  parseRecoveryKey,
  randomBytes,
  safetyNumber as computeSafetyNumber,
  seal,
  sealEnvelope,
  sealProvisioning,
  verifyLinkRequest,
  sha256,
  signDeviceList,
  signDeviceLogin,
  solveProofOfWork,
  toB64,
  utf8,
  verifyDeviceList,
  wipe,
  x25519KeyPair,
} from '@veil/crypto';
import {
  AccountExport,
  canonicalUsername,
  AccountResponse,
  AttachmentUploadResponse,
  BundleResponse,
  ChallengeResponse,
  CreateLinkResponse,
  DirectoryEntry,
  KeyStatus,
  LinkStatus,
  MailboxResponse,
  PendingLinkRequests,
  PreloginResponse,
  PublicConfig,
  RecoverResponse,
  RecoveryBackupResponse,
  ResetStatus,
  SendResponse,
  SessionResponse,
  SessionsResponse,
  UsernameSuggestion,
  WsServerFrame,
  z,
  type OutgoingEnvelope,
  type SignedDeviceListJson,
} from '@veil/shared';
import { type AttachmentPointer, type Content, type ContactSnapshot, MAX_CLOCK, Profile, ProvisioningPayload, RecoveryBackup, decodeJson, encodeJson, pad, unpad } from './content.js';
import { VeilError } from './errors.js';
import { Api } from './http.js';
import { type LocalIdentity, type SessionRecord, decryptExisting, encryptWith, initiateSession, respondToPreKey, withNewCurrent } from './sessions.js';
import type {
  ChatMessage,
  ClientSnapshot,
  ClientStatus,
  ConnectionState,
  ConversationSummary,
  DeviceInfo,
  PendingLink,
  PrivacySettings,
  ResetOptions,
  ResetReport,
  SessionSummary,
  StorageBackend,
  SystemNotice,
  VeilClientApi,
  Verification,
} from './types.js';
import { LocalVault } from './vault.js';

// ---------------------------------------------------------------- persisted records

interface IdentityRecord {
  username: string;
  identityKey: string;
  /** Account identity private key: present only on primary devices. */
  identityPrivateKey: string | null;
  device: { id: string; signingPub: string; signingPriv: string; dhPub: string; dhPriv: string };
  deviceList: SignedDeviceListJson;
  profileKey: string;
  recoveryBackupKey: string | null;
}

interface PrekeyRecord {
  signed: { keyId: number; pub: string; priv: string; signature: string; day: number }[];
  oneTime: Record<string, { pub: string; priv: string }>;
  nextOneTimeId: number;
  nextSignedId: number;
  seenBaseKeys: string[];
}

interface DeviceRef {
  deviceId: string;
  signingKey: string;
  dhKey: string;
}

interface ContactRecord {
  username: string;
  identityKey: string;
  pendingIdentityKey: string | null;
  verification: Verification;
  devices: DeviceRef[];
  deviceListVersion: number;
  accountGone: boolean;
  profileKey: string | null;
  displayName: string | null;
  /** We have sent our profile key to this contact. */
  profileShared: boolean;
  /** Conversation deleted by the user; shown again on the next message. */
  hidden?: boolean;
  clock: number;
  unread: number;
  preview: string | null;
}

interface StoredMessage extends ChatMessage {
  sortKey: string;
  pointers: AttachmentPointer[];
  receiptSent: boolean;
}

interface ResetJournal {
  jobId: string;
  jobSecret: string;
  attachments: { attachmentId: string; deleteToken: string }[];
  old: { username: string; identityKey: string; deviceIds: string[] };
}

interface Upload {
  attachmentId: string;
  deleteToken: string;
}

const DEFAULT_SETTINGS: PrivacySettings = { readReceipts: false, shareProfile: false, displayName: '' };
const ONE_TIME_PREKEY_BATCH = 100;
const ONE_TIME_PREKEY_LOW_WATER = 25;
const SIGNED_PREKEY_ROTATE_DAYS = 7;
const MAX_SEEN_BASE_KEYS = 2000;
const MAX_UPLOAD_RECORDS = 5000;
const RESTORE_CLOCK_JUMP = 2 ** 20;
const START_NOTICE =
  'If this person exists, they will receive your messages. VEIL never reveals whether an account exists, not even to you. Compare safety numbers to verify who you are talking to.';
const PROFILE_AD = utf8('VEIL/v1/profile');

const today = () => Math.floor(Date.now() / 86_400_000);

class Mutex {
  private tail: Promise<unknown> = Promise.resolve();
  run<T>(fn: () => Promise<T>): Promise<T> {
    const next = this.tail.then(fn, fn);
    this.tail = next.catch(() => undefined);
    return next;
  }
}

export interface VeilClientOptions {
  baseUrl: string;
  storage: StorageBackend;
  fetch?: typeof fetch;
  WebSocket?: typeof WebSocket;
  /**
   * Floor for Argon2id parameters the client accepts from the server. Protects
   * against a malicious server downgrading the password stretch.
   */
  minimumKdf?: Argon2Params;
  /** Connect the notification WebSocket (default true). Tests may poll instead. */
  realtime?: boolean;
}

/** Unlocked in-memory state. Dropped entirely on lock. */
interface Unlocked {
  vault: LocalVault;
  identity: IdentityRecord;
  prekeys: PrekeyRecord;
  contacts: Map<string, ContactRecord>;
  conversations: Map<string, StoredMessage[]>;
  sessions: Map<string, SessionRecord>;
  settings: PrivacySettings;
  uploads: Upload[];
  /** Contacts whose device lists were refreshed during this unlock. */
  fresh: Set<string>;
  ownListStale: boolean;
}

export class VeilClient implements VeilClientApi {
  private readonly api: Api;
  private readonly storage: StorageBackend;
  private readonly minimumKdf: Argon2Params;
  private readonly WS: typeof WebSocket | undefined;
  private readonly realtime: boolean;
  private readonly mutex = new Mutex();

  private status: ClientStatus = 'no-vault';
  private connection: ConnectionState = 'offline';
  private state: Unlocked | null = null;
  private recoveryEnabled = false;
  private linkCode: string | null = null;
  /** Password-derived material retained only between a link-session sign-in and enrollment. */
  private pendingPassword: { vaultKek: Bytes; clientSalt: Bytes; kdf: Argon2Params; username: string } | null = null;
  private pendingLink: { linkId: string; request: Bytes; secret: Bytes; device: ReturnType<typeof generateDeviceKeys>; provisioning: KeyPair } | null = null;
  private linkRequests = new Map<string, Bytes>();
  private config: PublicConfig | null = null;

  private ws: WebSocket | null = null;
  private wsRetry = 0;
  private wsTimer: ReturnType<typeof setTimeout> | null = null;
  private draining = false;
  private drainAgain = false;

  private listeners = new Set<(s: ClientSnapshot) => void>();
  private cachedSnapshot: ClientSnapshot | null = null;
  private convListeners = new Set<(peer: string) => void>();

  constructor(opts: VeilClientOptions) {
    this.api = new Api(opts.baseUrl.replace(/\/$/, ''), opts.fetch);
    this.storage = opts.storage;
    this.minimumKdf = opts.minimumKdf ?? CLIENT_ARGON2_MINIMUM;
    this.WS = opts.WebSocket ?? (globalThis as { WebSocket?: typeof WebSocket }).WebSocket;
    this.realtime = opts.realtime ?? true;
    this.api.onSessionLost = () => {
      if (this.status === 'ready') void this.lock();
    };
  }

  // ================================================================ observation

  /** Stable between changes (required by React's useSyncExternalStore). */
  snapshot(): ClientSnapshot {
    if (!this.cachedSnapshot) this.cachedSnapshot = this.buildSnapshot();
    return this.cachedSnapshot;
  }

  private buildSnapshot(): ClientSnapshot {
    const s = this.state;
    return {
      status: this.status,
      connection: this.connection,
      username: s?.identity.username ?? null,
      deviceId: s?.identity.device.id ?? null,
      isPrimary: !!s?.identity.identityPrivateKey,
      recoveryEnabled: this.recoveryEnabled,
      conversations: s ? this.summaries(s) : [],
      settings: s ? { ...s.settings } : { ...DEFAULT_SETTINGS },
      linkCode: this.linkCode,
    };
  }

  subscribe(listener: (s: ClientSnapshot) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  onConversation(listener: (peer: string) => void): () => void {
    this.convListeners.add(listener);
    return () => this.convListeners.delete(listener);
  }

  private emit() {
    this.cachedSnapshot = null;
    const snap = this.snapshot();
    for (const l of this.listeners) l(snap);
  }

  private emitConversation(peer: string) {
    for (const l of this.convListeners) l(peer);
  }

  private summaries(s: Unlocked): ConversationSummary[] {
    return [...s.contacts.values()]
      .filter((c) => !c.hidden)
      .map((c) => ({
        peer: c.username,
        displayName: c.displayName,
        preview: c.preview,
        unread: c.unread,
        verification: c.verification,
        accountGone: c.accountGone,
        clock: c.clock,
      }))
      .sort((a, b) => b.clock - a.clock || a.peer.localeCompare(b.peer))
      .map(({ clock: _clock, ...rest }) => rest);
  }

  private setStatus(status: ClientStatus) {
    this.status = status;
    this.emit();
  }

  private setConnection(c: ConnectionState) {
    if (this.connection !== c) {
      this.connection = c;
      this.emit();
    }
  }

  private requireReady(): Unlocked {
    if (this.status !== 'ready' || !this.state) throw new VeilError('locked', 'Unlock VEIL first.');
    return this.state;
  }

  // ================================================================ bootstrap

  async init(): Promise<void> {
    if (await LocalVault.isResetPending(this.storage)) this.status = 'reset-pending';
    else this.status = (await LocalVault.readMeta(this.storage)) ? 'locked' : 'no-vault';
    this.emit();
  }

  async publicConfig(): Promise<PublicConfig> {
    if (!this.config) this.config = await this.api.json('GET', '/v1/config', undefined, PublicConfig, { auth: false });
    return this.config;
  }

  private checkKdf(kdf: Argon2Params) {
    if (!argon2ParamsAtLeast(kdf, this.minimumKdf)) {
      throw new VeilError('crypto', 'The server requested unsafe password-hashing parameters. Refusing to continue.');
    }
  }

  // ================================================================ registration

  async suggestUsername() {
    return this.api.json('POST', '/v1/auth/username', {}, UsernameSuggestion, { auth: false });
  }

  async register(input: { reservation: string; password: string; enableRecovery: boolean; onProgress?: (step: string) => void }) {
    const progress = input.onProgress ?? (() => {});
    const config = await this.publicConfig();
    const kdf = config.recommendedKdf;
    this.checkKdf(kdf);

    progress('Solving anti-abuse puzzle');
    const challenge = await this.api.json('POST', '/v1/auth/challenge', {}, ChallengeResponse, { auth: false });
    const nonce = await solveProofOfWork(utf8(challenge.challenge), challenge.difficulty);

    progress('Deriving keys from your password (Argon2id)');
    const clientSalt = newClientSalt();
    const pw = await derivePasswordKeys(input.password, clientSalt, kdf);

    progress('Generating identity and device keys');
    const aik = generateAccountIdentity();
    const device = generateDeviceKeys();
    const list: DeviceList = { identityKey: aik.publicKey, version: 1, devices: [deviceEntryFor(device, true)] };
    const signedList = signDeviceList(aik.privateKey, list);
    const spk = generateSignedPreKey(device, 1);
    const otks = generateOneTimePreKeys(1, ONE_TIME_PREKEY_BATCH);
    const profileKey = randomBytes(32);

    let recoveryText: string | null = null;
    let recovery: { verifierKey: string; backup: string } | undefined;
    let backupKey: Bytes | null = null;
    if (input.enableRecovery) {
      const secret = generateRecoverySecret();
      const rk = deriveRecoveryKeys(secret);
      backupKey = rk.backupKey;
      const backup: RecoveryBackup = { v: 1, deviceListVersion: 1, identityPrivateKey: toB64(aik.privateKey), profileKey: toB64(profileKey), contacts: [] };
      recovery = { verifierKey: toB64(rk.recoveryAuthKey), backup: toB64(seal(rk.backupKey, encodeJson(backup), RECOVERY_BACKUP_AD)) };
      recoveryText = formatRecoveryKey(secret);
      wipe(secret);
    }

    progress('Creating your account');
    const session = await this.api.json(
      'POST',
      '/v1/auth/register',
      {
        reservation: input.reservation,
        pow: { challenge: challenge.challenge, nonce },
        clientSalt: toB64(clientSalt),
        kdf,
        authKey: toB64(pw.authKey),
        identityKey: toB64(aik.publicKey),
        deviceList: { body: toB64(signedList.body), signature: toB64(signedList.signature) },
        device: { deviceId: toB64(device.deviceId), signingKey: toB64(device.signing.publicKey), dhKey: toB64(device.dh.publicKey) },
        signedPreKey: { keyId: spk.keyId, publicKey: toB64(spk.keyPair.publicKey), signature: toB64(spk.signature) },
        oneTimePreKeys: otks.map((k) => ({ keyId: k.keyId, publicKey: toB64(k.keyPair.publicKey) })),
        ...(recovery ? { recovery } : {}),
      },
      SessionResponse,
      { auth: false },
    );
    wipe(pw.authKey);
    this.api.setTokens({ accessToken: session.accessToken, refreshToken: session.refreshToken });

    progress('Encrypting local storage');
    const vault = await LocalVault.create(this.storage, pw.vaultKek, clientSalt, kdf);
    wipe(pw.vaultKek);
    const identity: IdentityRecord = {
      username: session.username,
      identityKey: toB64(aik.publicKey),
      identityPrivateKey: toB64(aik.privateKey),
      device: {
        id: toB64(device.deviceId),
        signingPub: toB64(device.signing.publicKey),
        signingPriv: toB64(device.signing.privateKey),
        dhPub: toB64(device.dh.publicKey),
        dhPriv: toB64(device.dh.privateKey),
      },
      deviceList: { body: toB64(signedList.body), signature: toB64(signedList.signature) },
      profileKey: toB64(profileKey),
      recoveryBackupKey: backupKey ? toB64(backupKey) : null,
    };
    const prekeys: PrekeyRecord = {
      signed: [{ keyId: spk.keyId, pub: toB64(spk.keyPair.publicKey), priv: toB64(spk.keyPair.privateKey), signature: toB64(spk.signature), day: today() }],
      oneTime: Object.fromEntries(otks.map((k) => [String(k.keyId), { pub: toB64(k.keyPair.publicKey), priv: toB64(k.keyPair.privateKey) }])),
      nextOneTimeId: ONE_TIME_PREKEY_BATCH + 1,
      nextSignedId: 2,
      seenBaseKeys: [],
    };
    wipe(aik.privateKey, device.signing.privateKey, device.dh.privateKey, spk.keyPair.privateKey);
    await this.adoptVault(vault, identity, prekeys, [], { ...DEFAULT_SETTINGS });
    this.recoveryEnabled = input.enableRecovery;
    this.becomeReady();
    return { username: session.username, recoveryKey: recoveryText };
  }

  /** Persists a fresh identity into a new vault and loads it into memory. */
  private async adoptVault(
    vault: LocalVault,
    identity: IdentityRecord,
    prekeys: PrekeyRecord,
    contacts: ContactSnapshot[],
    settings: PrivacySettings,
    clockJump = 0,
  ) {
    await vault.put('identity', identity);
    await vault.put('prekeys', prekeys);
    await vault.put('settings', settings);
    await vault.put('uploads', []);
    const contactMap = new Map<string, ContactRecord>();
    for (const c of contacts) {
      const contact = newContact(c.username, c.identityKey, c.verified ? 'verified' : 'unverified');
      contact.clock = (c.clock ?? 0) + clockJump;
      contactMap.set(c.username, contact);
    }
    await vault.put('contacts', [...contactMap.values()]);
    this.state = {
      vault,
      identity,
      prekeys,
      contacts: contactMap,
      conversations: new Map(),
      sessions: new Map(),
      settings,
      uploads: [],
      fresh: new Set(),
      ownListStale: false,
    };
  }

  private async loadVault(vault: LocalVault): Promise<Unlocked> {
    const identity = await vault.get<IdentityRecord>('identity');
    const prekeys = await vault.get<PrekeyRecord>('prekeys');
    if (!identity || !prekeys) throw new VeilError('internal', 'Local data is incomplete.');
    const contacts = new Map((await vault.get<ContactRecord[]>('contacts') ?? []).map((c) => [c.username, c]));
    const conversations = new Map<string, StoredMessage[]>();
    const sessions = new Map<string, SessionRecord>();
    for (const name of [...contacts.keys(), identity.username]) {
      const msgs = await vault.get<StoredMessage[]>(`conv:${name}`);
      if (msgs) conversations.set(name, msgs);
      const sess = await vault.get<Record<string, SessionRecord>>(`sessions:${name}`);
      if (sess) for (const [dev, rec] of Object.entries(sess)) sessions.set(`${name}/${dev}`, rec);
    }
    return {
      vault,
      identity,
      prekeys,
      contacts,
      conversations,
      sessions,
      settings: (await vault.get<PrivacySettings>('settings')) ?? { ...DEFAULT_SETTINGS },
      uploads: (await vault.get<Upload[]>('uploads')) ?? [],
      fresh: new Set(),
      ownListStale: false,
    };
  }

  // ================================================================ sign-in / lock

  private async prelogin(username: string) {
    const pre = await this.api.json('POST', '/v1/auth/prelogin', { username }, PreloginResponse, { auth: false });
    this.checkKdf(pre.kdf);
    return pre;
  }

  private async login(username: string, authKey: Bytes, nonce: string, device?: { id: string; signingPriv: string }) {
    const body: Record<string, unknown> = { username, authKey: toB64(authKey), nonce };
    if (device) {
      const priv = fromB64(device.signingPriv);
      body.device = { deviceId: device.id, signature: toB64(signDeviceLogin(priv, nonce, username)) };
      wipe(priv);
    }
    try {
      const s = await this.api.json('POST', '/v1/auth/login', body, SessionResponse, { auth: false });
      this.api.setTokens({ accessToken: s.accessToken, refreshToken: s.refreshToken });
      return s;
    } catch (e) {
      if (e instanceof VeilError && (e.code === 'unauthorized' || e.code === 'invalid_input')) {
        throw new VeilError('invalid_credentials', 'Incorrect username or password.');
      }
      throw e;
    }
  }

  async signIn(input: { username: string; password: string; previousPassword?: string; onProgress?: (step: string) => void }): Promise<ClientStatus> {
    const progress = input.onProgress ?? (() => {});
    const username = input.username.trim();
    const meta = await LocalVault.readMeta(this.storage);

    if (!meta) {
      // Fresh device: password-only sign-in yields a link session.
      progress('Deriving keys (Argon2id)');
      const pre = await this.prelogin(username);
      const salt = fromB64(pre.clientSalt);
      const pw = await derivePasswordKeys(input.password, salt, pre.kdf);
      const s = await this.login(username, pw.authKey, pre.nonce);
      wipe(pw.authKey);
      this.pendingPassword = { vaultKek: pw.vaultKek, clientSalt: salt, kdf: pre.kdf, username: s.username };
      this.setStatus('needs-link');
      return this.status;
    }

    progress('Unlocking this device (Argon2id)');
    const localSalt = fromB64(meta.clientSalt);
    const local = await derivePasswordKeys(input.password, localSalt, meta.kdf);
    let vault: LocalVault | null = null;
    let needsRewrap = false;
    try {
      vault = await LocalVault.unlock(this.storage, local.vaultKek);
    } catch {
      if (input.previousPassword) {
        const prev = await derivePasswordKeys(input.previousPassword, localSalt, meta.kdf);
        try {
          vault = await LocalVault.unlock(this.storage, prev.vaultKek);
          needsRewrap = true;
        } catch {
          // fall through
        } finally {
          wipe(prev.authKey, prev.vaultKek);
        }
      }
    }
    if (!vault) {
      wipe(local.authKey, local.vaultKek);
      const pre = await this.prelogin(username).catch(() => null);
      if (pre && pre.clientSalt !== meta.clientSalt && !input.previousPassword) {
        throw new VeilError(
          'invalid_credentials',
          'Could not unlock this device. If you changed your password on another device, also enter your previous password.',
        );
      }
      throw new VeilError('invalid_credentials', 'Incorrect username or password.');
    }

    const st = await this.loadVault(vault);
    if (st.identity.username.toLowerCase() !== username.toLowerCase()) {
      vault.close();
      throw new VeilError('invalid_credentials', 'Incorrect username or password.');
    }
    const journal = await vault.get<ResetJournal>('reset-journal');
    if (journal) {
      this.state = st;
      this.setStatus('reset-pending');
      return this.status;
    }

    progress('Signing in');
    const pre = await this.prelogin(username);
    const saltChanged = pre.clientSalt !== meta.clientSalt;
    const server = saltChanged ? await derivePasswordKeys(input.password, fromB64(pre.clientSalt), pre.kdf) : local;
    try {
      await this.login(username, server.authKey, pre.nonce, st.identity.device);
    } catch (e) {
      if (!(e instanceof VeilError) || e.code !== 'invalid_credentials') {
        vault.close();
        throw e;
      }
      // The password unlocked this vault but the server refused the device.
      // prelogin deliberately hides whether an account exists, so "deleted"
      // and "password changed elsewhere" look identical here; we never erase
      // local data on such ambiguous evidence (see eraseLocalData()).
      const pre2 = await this.prelogin(username);
      try {
        await this.login(username, server.authKey, pre2.nonce);
      } catch (e2) {
        vault.close();
        if (e2 instanceof VeilError && e2.code === 'invalid_credentials') {
          throw new VeilError(
            'unauthorized',
            'This device could not sign in. If your password was changed on another device, enter it together with your previous password. If you used Panic Reset elsewhere, you can erase this device.',
          );
        }
        throw e2;
      }
      // Password-only sign-in worked, so the account exists. Wipe only if the
      // device list signed by our own identity key proves this device was removed.
      const account = await this.api.json('GET', '/v1/account', undefined, AccountResponse);
      let removed = false;
      try {
        const signed = verifyDeviceList({ body: fromB64(account.deviceList.body), signature: fromB64(account.deviceList.signature) }, fromB64(st.identity.identityKey));
        const known = verifyDeviceList({ body: fromB64(st.identity.deviceList.body), signature: fromB64(st.identity.deviceList.signature) }, fromB64(st.identity.identityKey));
        removed = signed.version >= known.version && !signed.devices.some((d) => toB64(d.deviceId) === st.identity.device.id);
      } catch {
        removed = false;
      }
      vault.close();
      if (!removed) {
        await this.api.send('POST', '/v1/auth/logout', {}).catch(() => {});
        this.api.setTokens(null);
        throw new VeilError('crypto', 'The server refused this device although it is still in your signed device list. Not erasing anything.');
      }
      await this.storage.destroy();
      this.state = null;
      this.pendingPassword = { vaultKek: server.vaultKek, clientSalt: fromB64(pre2.clientSalt), kdf: pre2.kdf, username };
      this.setStatus('needs-link');
      return this.status;
    }
    if (needsRewrap) {
      // The vault was sealed with the previous password. Re-seal it, but never
      // with weaker Argon2 parameters than it had (the server chooses pre.kdf).
      if (argon2ParamsAtLeast(pre.kdf, meta.kdf)) {
        await vault.rewrap(server.vaultKek, fromB64(pre.clientSalt), pre.kdf);
      } else {
        const salt = newClientSalt();
        const k = await derivePasswordKeys(input.password, salt, meta.kdf);
        await vault.rewrap(k.vaultKek, salt, meta.kdf);
        wipe(k.authKey, k.vaultKek);
      }
    }
    wipe(local.authKey, local.vaultKek, server.authKey, server.vaultKek);

    this.state = st;
    await this.afterSignIn();
    this.becomeReady();
    return this.status;
  }

  private async afterSignIn() {
    const account = await this.api.json('GET', '/v1/account', undefined, AccountResponse);
    this.recoveryEnabled = account.recoveryEnabled;
    await this.applyOwnDeviceList(account.deviceList);
  }

  private becomeReady() {
    this.status = 'ready';
    this.emit();
    void this.maintainPrekeys().catch(() => {});
    this.connect();
    void this.drain().catch(() => {});
  }

  async lock(): Promise<void> {
    this.disconnect();
    this.api.setTokens(null);
    if (this.state) {
      this.state.vault.close();
      this.state = null;
    }
    if (this.pendingPassword) wipe(this.pendingPassword.vaultKek);
    this.pendingPassword = null;
    if (this.pendingLink) wipe(this.pendingLink.secret, this.pendingLink.provisioning.privateKey, this.pendingLink.device.signing.privateKey, this.pendingLink.device.dh.privateKey);
    this.pendingLink = null;
    this.linkCode = null;
    this.status = (await LocalVault.isResetPending(this.storage))
      ? 'reset-pending'
      : (await LocalVault.readMeta(this.storage))
        ? 'locked'
        : 'no-vault';
    this.emit();
  }

  async eraseLocalData(): Promise<void> {
    this.disconnect();
    this.api.setTokens(null);
    if (this.state) {
      this.state.vault.close();
      this.state = null;
    }
    if (this.pendingPassword) wipe(this.pendingPassword.vaultKek);
    this.pendingPassword = null;
    await this.storage.destroy();
    this.recoveryEnabled = false;
    this.setStatus('no-vault');
  }

  async signOut(): Promise<void> {
    const st = this.state;
    if (st && !st.identity.identityPrivateKey) {
      await this.api.send('DELETE', '/v1/devices/self');
      this.disconnect();
      this.api.setTokens(null);
      st.vault.close();
      this.state = null;
      await this.storage.destroy();
      this.setStatus('no-vault');
      return;
    }
    await this.api.send('POST', '/v1/auth/logout', {}).catch(() => {});
    await this.lock();
  }

  // ================================================================ realtime

  private connect() {
    if (!this.realtime || !this.WS || this.ws || this.status !== 'ready') return;
    const token = this.api.accessToken();
    if (!token) return;
    this.setConnection('connecting');
    const url = this.api.baseUrl.replace(/^http/, 'ws') + '/v1/ws';
    const ws = new this.WS(url);
    this.ws = ws;
    ws.onopen = async () => {
      // Refresh first so the token in the auth frame is valid.
      await this.api.refresh().catch(() => false);
      const t = this.api.accessToken();
      if (t && ws.readyState === 1) ws.send(JSON.stringify({ type: 'auth', accessToken: t }));
    };
    ws.onmessage = (ev) => {
      let frame: z.infer<typeof WsServerFrame>;
      try {
        frame = WsServerFrame.parse(JSON.parse(String(ev.data)));
      } catch {
        return;
      }
      if (frame.type === 'ready') {
        this.wsRetry = 0;
        this.setConnection('online');
        void this.drain().catch(() => {});
      } else if (frame.type === 'mail') {
        void this.drain().catch(() => {});
      } else if (frame.type === 'link') {
        this.emit();
      } else if (frame.type === 'revoked') {
        void this.lock();
      }
    };
    ws.onclose = () => {
      if (this.ws !== ws) return;
      this.ws = null;
      this.setConnection('offline');
      if (this.status === 'ready') {
        const delay = Math.min(30_000, 1000 * 2 ** this.wsRetry++);
        this.wsTimer = setTimeout(() => this.connect(), delay);
      }
    };
    ws.onerror = () => {
      // onclose follows
    };
  }

  private disconnect() {
    if (this.wsTimer) clearTimeout(this.wsTimer);
    this.wsTimer = null;
    const ws = this.ws;
    this.ws = null;
    if (ws) {
      try {
        ws.close();
      } catch {
        // ignore
      }
    }
    this.setConnection('offline');
  }

  /** Fetches and processes the mailbox until empty. Safe to call concurrently. */
  async drain(): Promise<void> {
    if (this.draining) {
      this.drainAgain = true;
      return;
    }
    this.draining = true;
    try {
      do {
        this.drainAgain = false;
        for (;;) {
          if (this.status !== 'ready') return;
          const box = await this.api.json('GET', '/v1/mailbox?limit=100', undefined, MailboxResponse);
          if (box.envelopes.length === 0) break;
          // Acknowledge only what was actually processed (or is permanently
          // undecryptable). A transient failure leaves the rest on the server.
          const processed: string[] = [];
          let transient: unknown = null;
          for (const env of box.envelopes) {
            try {
              await this.mutex.run(() => this.receiveEnvelope(fromB64(env.payload)));
            } catch (e) {
              if (isTransient(e)) {
                transient = e;
                break;
              }
            }
            processed.push(env.envelopeId);
          }
          if (processed.length) await this.api.send('POST', '/v1/mailbox/ack', { envelopeIds: processed });
          if (transient) throw transient;
          if (!box.more) break;
        }
      } while (this.drainAgain);
    } finally {
      this.draining = false;
    }
  }

  // ================================================================ key maintenance

  private localIdentity(st: Unlocked): LocalIdentity {
    return {
      identityKey: fromB64(st.identity.identityKey),
      deviceId: fromB64(st.identity.device.id),
      dh: { publicKey: fromB64(st.identity.device.dhPub), privateKey: fromB64(st.identity.device.dhPriv) },
    };
  }

  private deviceKeys(st: Unlocked) {
    return {
      deviceId: fromB64(st.identity.device.id),
      signing: { publicKey: fromB64(st.identity.device.signingPub), privateKey: fromB64(st.identity.device.signingPriv) },
      dh: { publicKey: fromB64(st.identity.device.dhPub), privateKey: fromB64(st.identity.device.dhPriv) },
    };
  }

  private async maintainPrekeys() {
    await this.mutex.run(async () => {
      const st = this.requireReady();
      const status = await this.api.json('GET', '/v1/keys/status', undefined, KeyStatus);
      const pk = st.prekeys;
      const current = pk.signed[0]!;
      if (today() - current.day >= SIGNED_PREKEY_ROTATE_DAYS || status.signedPreKeyId !== current.keyId) {
        let next = current;
        if (today() - current.day >= SIGNED_PREKEY_ROTATE_DAYS) {
          const spk = generateSignedPreKey(this.deviceKeys(st), pk.nextSignedId++);
          next = { keyId: spk.keyId, pub: toB64(spk.keyPair.publicKey), priv: toB64(spk.keyPair.privateKey), signature: toB64(spk.signature), day: today() };
          // Keep the previous signed prekey for one more period for in-flight prekey messages.
          pk.signed = [next, current];
          await st.vault.put('prekeys', pk);
        }
        await this.api.send('PUT', '/v1/keys/signed-prekey', { keyId: next.keyId, publicKey: next.pub, signature: next.signature });
      }
      if (status.oneTimePreKeys < ONE_TIME_PREKEY_LOW_WATER) {
        const fresh = generateOneTimePreKeys(pk.nextOneTimeId, ONE_TIME_PREKEY_BATCH);
        pk.nextOneTimeId = (pk.nextOneTimeId + ONE_TIME_PREKEY_BATCH) >>> 0;
        for (const k of fresh) pk.oneTime[String(k.keyId)] = { pub: toB64(k.keyPair.publicKey), priv: toB64(k.keyPair.privateKey) };
        await st.vault.put('prekeys', pk);
        await this.api.send('POST', '/v1/keys/one-time', { preKeys: fresh.map((k) => ({ keyId: k.keyId, publicKey: toB64(k.keyPair.publicKey) })) });
      }
    });
  }

  // ================================================================ device lists

  private async applyOwnDeviceList(list: SignedDeviceListJson) {
    const st = this.state!;
    const parsed = verifyDeviceList({ body: fromB64(list.body), signature: fromB64(list.signature) }, fromB64(st.identity.identityKey));
    const known = verifyDeviceList(
      { body: fromB64(st.identity.deviceList.body), signature: fromB64(st.identity.deviceList.signature) },
      fromB64(st.identity.identityKey),
    );
    if (parsed.version < known.version) throw new VeilError('crypto', 'The server returned an outdated device list.');
    if (parsed.version === known.version && toB64(fromB64(list.body)) !== st.identity.deviceList.body) {
      throw new VeilError('crypto', 'Conflicting device lists with the same version. Refusing to update.');
    }
    const advanced = parsed.version > known.version;
    st.identity.deviceList = list;
    st.ownListStale = false;
    const ownIds = new Set(parsed.devices.map((d) => toB64(d.deviceId)));
    for (const key of [...st.sessions.keys()]) {
      const [name, dev] = key.split('/');
      if (name === st.identity.username && !ownIds.has(dev!)) st.sessions.delete(key);
    }
    await st.vault.put('identity', st.identity);
    await this.persistSessions(st, st.identity.username);
    // The backup remembers the newest confirmed version, so a restore can refuse rolled-back lists.
    if (advanced) await this.updateRecoveryBackup(st).catch(() => {});
  }

  private ownDevices(st: Unlocked): DeviceEntry[] {
    return verifyDeviceList(
      { body: fromB64(st.identity.deviceList.body), signature: fromB64(st.identity.deviceList.signature) },
      fromB64(st.identity.identityKey),
    ).devices;
  }

  private async refreshOwnAccount(_st: Unlocked) {
    const account = await this.api.json('GET', '/v1/account', undefined, AccountResponse);
    this.recoveryEnabled = account.recoveryEnabled;
    await this.applyOwnDeviceList(account.deviceList);
  }

  /**
   * Fetches a contact's directory entry and reconciles it with what we pinned.
   * Returns false if the account is gone. Identity changes never auto-apply.
   */
  private async refreshContactRecord(st: Unlocked, c: ContactRecord): Promise<boolean> {
    let entry: z.infer<typeof DirectoryEntry>;
    try {
      entry = await this.api.json('GET', `/v1/directory/${encodeURIComponent(c.username)}`, undefined, DirectoryEntry);
    } catch (e) {
      if (e instanceof VeilError && e.code === 'not_found') {
        if (!c.accountGone) {
          c.accountGone = true;
          this.addNotice(st, c, 'account-gone', 'This account no longer exists.');
          await this.saveContacts(st);
        }
        return false;
      }
      throw e;
    }
    st.fresh.add(c.username);
    if (entry.identityKey !== c.identityKey) {
      if (c.pendingIdentityKey !== entry.identityKey) {
        c.pendingIdentityKey = entry.identityKey;
        c.verification = 'key-changed';
        this.addNotice(
          st,
          c,
          'key-changed',
          `${c.username}'s safety number changed. They may have reset or deleted their account, or someone may be intercepting. Verify before sending.`,
        );
        await this.saveContacts(st);
      }
      return true;
    }
    await this.applyContactDeviceList(st, c, entry.deviceList);
    if (c.profileKey && entry.profile) c.displayName = decryptProfile(c.profileKey, entry.profile);
    if (!entry.profile) c.displayName = null;
    await this.saveContacts(st);
    return true;
  }

  private async applyContactDeviceList(st: Unlocked, c: ContactRecord, signed: SignedDeviceListJson) {
    const list = verifyDeviceList({ body: fromB64(signed.body), signature: fromB64(signed.signature) }, fromB64(c.identityKey));
    if (list.version < c.deviceListVersion) throw new VeilError('crypto', 'The server returned an outdated device list.');
    const next: DeviceRef[] = list.devices.map((d) => ({ deviceId: toB64(d.deviceId), signingKey: toB64(d.signingKey), dhKey: toB64(d.dhKey) }));
    const fingerprint = (ds: DeviceRef[]) => ds.map((d) => d.deviceId + d.signingKey + d.dhKey).sort().join('|');
    // Same version, different devices: two conflicting lists exist (a fork). Refuse rather than pick one.
    if (c.deviceListVersion > 0 && list.version === c.deviceListVersion && fingerprint(next) !== fingerprint(c.devices)) {
      throw new VeilError('crypto', 'Conflicting device lists with the same version. Refusing to update.');
    }
    if (c.deviceListVersion > 0) {
      const before = new Set(c.devices.map((d) => d.deviceId + d.dhKey));
      const after = new Set(next.map((d) => d.deviceId + d.dhKey));
      if (next.some((d) => !before.has(d.deviceId + d.dhKey))) this.addNotice(st, c, 'device-added', `${c.username} added a device.`);
      if (c.devices.some((d) => !after.has(d.deviceId + d.dhKey))) this.addNotice(st, c, 'device-removed', `${c.username} removed a device.`);
    }
    const keep = new Set(next.map((d) => d.deviceId));
    for (const key of [...st.sessions.keys()]) {
      const [name, dev] = key.split('/');
      if (name === c.username && !keep.has(dev!)) st.sessions.delete(key);
    }
    c.devices = next;
    c.deviceListVersion = list.version;
    await this.persistSessions(st, c.username);
  }

  // ================================================================ conversations (local)

  messages(peer: string): ChatMessage[] {
    const st = this.state;
    if (!st) return [];
    return (st.conversations.get(peer) ?? []).map(({ sortKey: _s, pointers: _p, receiptSent: _r, ...m }) => ({ ...m, attachments: [...m.attachments] }));
  }

  private conv(st: Unlocked, peer: string): StoredMessage[] {
    let list = st.conversations.get(peer);
    if (!list) {
      list = [];
      st.conversations.set(peer, list);
    }
    return list;
  }

  private insertMessage(st: Unlocked, peer: string, m: StoredMessage) {
    const list = this.conv(st, peer);
    if (list.some((x) => x.id === m.id && x.direction !== 'system')) return false;
    list.push(m);
    const rank = (x: StoredMessage) => (x.direction === 'system' ? 1 : 0);
    list.sort((a, b) => a.clock - b.clock || rank(a) - rank(b) || (a.sortKey < b.sortKey ? -1 : a.sortKey > b.sortKey ? 1 : 0));
    return true;
  }

  private addNotice(st: Unlocked, c: ContactRecord, notice: SystemNotice, text: string) {
    const id = toB64(randomBytes(16));
    this.insertMessage(st, c.username, {
      id,
      peer: c.username,
      direction: 'system',
      clock: c.clock,
      text,
      attachments: [],
      status: 'received',
      readByPeer: false,
      notice,
      sortKey: `~${id}`,
      pointers: [],
      receiptSent: true,
    });
    void st.vault.put(`conv:${c.username}`, this.conv(st, c.username));
    this.emitConversation(c.username);
  }

  private async saveConversation(st: Unlocked, peer: string) {
    await st.vault.put(`conv:${peer}`, this.conv(st, peer));
  }

  private async saveContacts(st: Unlocked) {
    await st.vault.put('contacts', [...st.contacts.values()]);
    this.emit();
  }

  private async persistSessions(st: Unlocked, name: string) {
    const out: Record<string, SessionRecord> = {};
    for (const [key, rec] of st.sessions) {
      const [n, dev] = key.split('/');
      if (n === name) out[dev!] = rec;
    }
    await st.vault.put(`sessions:${name}`, out);
  }

  async startConversation(username: string): Promise<void> {
    const st = this.requireReady();
    // Checked locally against the public word lists. The server answers every
    // well-formed name (real account or decoy), so this is the only possible "no".
    const name = canonicalUsername(username);
    if (!name) throw new VeilError('invalid_input', 'That is not a VEIL username. Usernames are two words, like SilentComet.');
    if (name.toLowerCase() === st.identity.username.toLowerCase()) throw new VeilError('invalid_input', 'You cannot start a conversation with yourself.');
    // Usernames are case-insensitive: never create a second record for an existing contact.
    const existing = [...st.contacts.values()].find((c) => c.username.toLowerCase() === name.toLowerCase());
    if (existing) {
      if (existing.hidden) {
        existing.hidden = false;
        await this.saveContacts(st);
      }
      return;
    }
    const contact = await this.mutex.run(async () => {
      let entry: z.infer<typeof DirectoryEntry>;
      try {
        entry = await this.api.json('GET', `/v1/directory/${encodeURIComponent(name)}`, undefined, DirectoryEntry);
      } catch (e) {
        if (e instanceof VeilError && e.code === 'not_found') throw new VeilError('invalid_input', 'That is not a VEIL username.');
        throw e;
      }
      const already = st.contacts.get(entry.username);
      if (already) return already;
      const c = newContact(entry.username, entry.identityKey, 'unverified');
      await this.applyContactDeviceList(st, c, entry.deviceList);
      st.contacts.set(c.username, c);
      st.fresh.add(c.username);
      this.addNotice(st, c, 'session-started', START_NOTICE);
      await this.saveContacts(st);
      return c;
    });
    await this.syncContactToOwnDevices(st, contact).catch(() => {});
    await this.updateRecoveryBackup(st).catch(() => {});
  }

  async deleteConversation(peer: string): Promise<void> {
    const st = this.requireReady();
    await this.mutex.run(async () => {
      // History is erased, but the pinned key and sessions are kept: dropping
      // them would silently black-hole the contact's next messages. The
      // conversation reappears when a new message arrives.
      const c = st.contacts.get(peer);
      if (!c) return;
      c.hidden = true;
      c.preview = null;
      c.unread = 0;
      st.conversations.delete(peer);
      await st.vault.delete(`conv:${peer}`);
      await this.saveContacts(st);
    });
  }

  safetyNumber(peer: string): string {
    const st = this.requireReady();
    const c = st.contacts.get(peer);
    if (!c) throw new VeilError('not_found', 'Unknown conversation.');
    return computeSafetyNumber(
      { identityKey: fromB64(st.identity.identityKey), username: st.identity.username },
      { identityKey: fromB64(c.pendingIdentityKey ?? c.identityKey), username: c.username },
    );
  }

  async setVerified(peer: string, verified: boolean): Promise<void> {
    const st = this.requireReady();
    const c = st.contacts.get(peer);
    if (!c) throw new VeilError('not_found', 'Unknown conversation.');
    if (c.verification === 'key-changed') throw new VeilError('key_changed', 'Review and accept the new key first.');
    c.verification = verified ? 'verified' : 'unverified';
    this.addNotice(st, c, verified ? 'verified' : 'unverified', verified ? 'You marked this contact as verified.' : 'You removed the verified mark.');
    await this.saveContacts(st);
    await this.syncContactToOwnDevices(st, c).catch(() => {});
    await this.updateRecoveryBackup(st).catch(() => {});
  }

  async acceptKeyChange(peer: string): Promise<void> {
    const st = this.requireReady();
    await this.mutex.run(async () => {
      const c = st.contacts.get(peer);
      if (!c || !c.pendingIdentityKey) return;
      c.identityKey = c.pendingIdentityKey;
      c.pendingIdentityKey = null;
      c.verification = 'unverified';
      c.deviceListVersion = 0;
      c.devices = [];
      for (const key of [...st.sessions.keys()]) if (key.startsWith(`${peer}/`)) st.sessions.delete(key);
      await this.persistSessions(st, peer);
      await this.refreshContactRecord(st, c);
    });
    const c = st.contacts.get(peer);
    if (c) await this.syncContactToOwnDevices(st, c).catch(() => {});
  }

  async refreshContact(peer: string): Promise<void> {
    const st = this.requireReady();
    const c = st.contacts.get(peer);
    if (!c) throw new VeilError('not_found', 'Unknown conversation.');
    await this.mutex.run(() => this.refreshContactRecord(st, c));
  }

  async markRead(peer: string): Promise<void> {
    const st = this.requireReady();
    const c = st.contacts.get(peer);
    if (!c) return;
    const unreceipted = this.conv(st, peer).filter((m) => m.direction === 'in' && !m.receiptSent);
    if (c.unread === 0 && unreceipted.length === 0) return;
    c.unread = 0;
    for (const m of unreceipted) m.receiptSent = true;
    await this.saveContacts(st);
    await this.saveConversation(st, peer);
    if (st.settings.readReceipts && unreceipted.length > 0 && !c.accountGone && c.verification !== 'key-changed') {
      await this.sendContent(st, c, { v: 1, t: 'read', ids: unreceipted.slice(-500).map((m) => m.id) }, null).catch(() => {});
    }
  }

  // ================================================================ sending

  async sendText(peer: string, text: string): Promise<void> {
    if (!text.trim()) throw new VeilError('invalid_input', 'Message is empty.');
    if (text.length > 16_000) throw new VeilError('invalid_input', 'Message is too long.');
    await this.sendMessage(peer, text, []);
  }

  async sendAttachment(peer: string, file: { name: string; mime: string; bytes: Uint8Array }): Promise<void> {
    const st = this.requireReady();
    const c = this.sendableContact(st, peer);
    const config = await this.publicConfig();
    if (file.bytes.length > Math.min(config.attachmentMaxBytes, 10 * 1024 * 1024)) throw new VeilError('invalid_input', 'File is too large (max 10 MB).');
    await this.mutex.run(async () => {
      if (!st.fresh.has(c.username)) await this.refreshContactRecord(st, c);
      if (st.ownListStale) await this.refreshOwnAccount(st);
    });
    this.sendableContact(st, peer);
    // Download budget: every recipient device plus our own other devices, once each.
    const targets = Math.min(64, Math.max(1, c.devices.length + this.ownDevices(st).length - 1));
    const enc = encryptAttachment(file.bytes);
    const up = await this.api.upload(`/v1/attachments?downloads=${targets}`, enc.blob, AttachmentUploadResponse);
    st.uploads.push({ attachmentId: up.attachmentId, deleteToken: up.deleteToken });
    if (st.uploads.length > MAX_UPLOAD_RECORDS) st.uploads.splice(0, st.uploads.length - MAX_UPLOAD_RECORDS);
    await st.vault.put('uploads', st.uploads);
    // Keep our own plaintext copy locally: the sending device never downloads its own upload.
    await st.vault.put(`att:${up.attachmentId}`, toB64(file.bytes));
    const pointer: AttachmentPointer = {
      id: up.attachmentId,
      key: toB64(enc.key),
      digest: toB64(enc.digest),
      name: file.name.slice(0, 255) || 'file',
      mime: (file.mime || 'application/octet-stream').slice(0, 127),
      size: file.bytes.length,
    };
    wipe(enc.key);
    await this.sendMessage(peer, '', [pointer]);
  }

  private sendableContact(st: Unlocked, peer: string): ContactRecord {
    const c = st.contacts.get(peer);
    if (!c) throw new VeilError('not_found', 'Unknown conversation.');
    if (c.accountGone) throw new VeilError('account_gone', 'This account no longer exists.');
    if (c.verification === 'key-changed') throw new VeilError('key_changed', `${peer}'s identity key changed. Review it before sending.`);
    return c;
  }

  private async sendMessage(peer: string, text: string, pointers: AttachmentPointer[]): Promise<void> {
    const st = this.requireReady();
    const c = this.sendableContact(st, peer);
    const id = toB64(randomBytes(16));
    const msg: StoredMessage = await this.mutex.run(async () => {
      if (!st.fresh.has(c.username)) await this.refreshContactRecord(st, c);
      if (st.ownListStale) await this.refreshOwnAccount(st);
      this.sendableContact(st, peer);
      c.clock = Math.min(c.clock + 1, MAX_CLOCK);
      const m: StoredMessage = {
        id,
        peer,
        direction: 'out',
        clock: c.clock,
        text,
        attachments: pointers.map((p) => ({ attachmentId: p.id, name: p.name, mime: p.mime, size: p.size })),
        status: 'sending',
        readByPeer: false,
        sortKey: `${st.identity.username}:${id}`,
        pointers,
        receiptSent: true,
      };
      this.insertMessage(st, peer, m);
      c.preview = previewOf(text, pointers);
      await this.saveConversation(st, peer);
      await this.saveContacts(st);
      return m;
    });
    this.emitConversation(peer);
    try {
      const body = { id, clock: msg.clock, text, att: pointers };
      await this.sendContent(st, c, { v: 1, t: 'msg', ...body }, { v: 1, t: 'sent', to: peer, ...body });
      if (!c.profileShared && st.settings.shareProfile) await this.shareProfileWith(st, c).catch(() => {});
      msg.status = 'sent';
    } catch (e) {
      msg.status = 'failed';
      await this.saveConversation(st, peer);
      this.emitConversation(peer);
      throw e;
    }
    await this.saveConversation(st, peer);
    this.emitConversation(peer);
  }

  /**
   * Encrypts `content` for every device of `c` and `ownCopy` for every other
   * device of ours, then submits. Ratchet state is persisted *before* the
   * network call so a message key is never reused, even if sending fails.
   */
  private async sendContent(st: Unlocked, c: ContactRecord, content: Content, ownCopy: Content | null): Promise<void> {
    await this.mutex.run(async () => {
      const served = new Set<string>();
      let peerServed = 0;
      // Second pass only happens if the server reported unknown devices: after
      // reconciling the signed lists, newly discovered devices get the message too.
      for (let attempt = 0; attempt < 2; attempt++) {
        const peerTargets = c.devices.filter((d) => !served.has(d.deviceId));
        const ownTargets = ownCopy
          ? this.ownDevices(st)
              .map((d) => ({ deviceId: toB64(d.deviceId), signingKey: toB64(d.signingKey), dhKey: toB64(d.dhKey) }))
              .filter((d) => d.deviceId !== st.identity.device.id && !served.has(d.deviceId))
          : [];
        await this.ensureSessions(st, c.username, c.identityKey, peerTargets);
        if (ownTargets.length) await this.ensureSessions(st, st.identity.username, st.identity.identityKey, ownTargets);
        const local = this.localIdentity(st);
        const envelopes: OutgoingEnvelope[] = [];
        const targets = [
          ...peerTargets.map((d) => ({ name: c.username, device: d, body: content })),
          ...ownTargets.map((d) => ({ name: st.identity.username, device: d, body: ownCopy! })),
        ];
        for (const t of targets) {
          const rec = st.sessions.get(`${t.name}/${t.device.deviceId}`);
          if (!rec?.current) continue; // no valid prekey bundle for this device
          const inner = encryptWith(rec.current, local, pad(t.body));
          envelopes.push({
            deviceId: t.device.deviceId,
            envelopeId: toB64(randomBytes(16)),
            payload: toB64(
              sealEnvelope(fromB64(t.device.deviceId), fromB64(t.device.dhKey), {
                senderUsername: st.identity.username,
                senderDeviceId: local.deviceId,
                inner,
              }),
            ),
          });
          served.add(t.device.deviceId);
          if (t.name === c.username) peerServed++;
        }
        await this.persistSessions(st, c.username);
        if (ownTargets.length) await this.persistSessions(st, st.identity.username);
        if (envelopes.length === 0) break;

        let unknown: string[] = [];
        for (let i = 0; i < envelopes.length; i += 64) {
          const res = await this.api.json('POST', '/v1/messages', { envelopes: envelopes.slice(i, i + 64) }, SendResponse);
          unknown = unknown.concat(res.unknownDevices);
        }
        if (unknown.length === 0) break;
        for (const id of unknown) if (c.devices.some((d) => d.deviceId === id)) peerServed--;
        await this.refreshContactRecord(st, c);
        if (ownCopy) await this.refreshOwnAccount(st);
      }
      if (peerServed <= 0) throw new VeilError('not_found', `None of ${c.username}'s devices could be reached.`);
    });
  }

  /** Creates X3DH sessions for devices that do not have one yet. */
  private async ensureSessions(st: Unlocked, name: string, identityKey: string, devices: DeviceRef[]) {
    const missing = devices.filter((d) => !st.sessions.get(`${name}/${d.deviceId}`)?.current);
    if (missing.length === 0) return;
    const bundle = await this.api.json('POST', '/v1/keys/bundles', { username: name, deviceIds: missing.map((d) => d.deviceId) }, BundleResponse);
    if (bundle.identityKey !== identityKey) {
      if (name !== st.identity.username) {
        const c = st.contacts.get(name);
        if (c) await this.refreshContactRecord(st, c);
      }
      throw new VeilError('key_changed', `${name}'s identity key changed. Review it before sending.`);
    }
    const list = verifyDeviceList({ body: fromB64(bundle.deviceList.body), signature: fromB64(bundle.deviceList.signature) }, fromB64(identityKey));
    const local = this.localIdentity(st);
    for (const b of bundle.bundles) {
      const dev = missing.find((d) => d.deviceId === b.deviceId);
      const entry = list.devices.find((d) => toB64(d.deviceId) === b.deviceId);
      // The device must be certified by the pinned identity *and* match what we already trust.
      if (!dev || !entry || toB64(entry.dhKey) !== dev.dhKey || toB64(entry.signingKey) !== dev.signingKey) continue;
      try {
        const session = initiateSession(local, {
          identityKey: fromB64(identityKey),
          deviceId: entry.deviceId,
          deviceSigningKey: entry.signingKey,
          deviceDhKey: entry.dhKey,
          signedPreKey: { keyId: b.signedPreKey.keyId, publicKey: fromB64(b.signedPreKey.publicKey), signature: fromB64(b.signedPreKey.signature) },
          oneTimePreKey: b.oneTimePreKey ? { keyId: b.oneTimePreKey.keyId, publicKey: fromB64(b.oneTimePreKey.publicKey) } : undefined,
        });
        st.sessions.set(`${name}/${b.deviceId}`, withNewCurrent(st.sessions.get(`${name}/${b.deviceId}`), session));
      } catch {
        // Invalid signed prekey: skip this device rather than trusting it.
      }
    }
  }

  // ================================================================ receiving

  /**
   * Processes one envelope. Decryption happens *before* any network lookup, so
   * forged or junk envelopes cost nothing and reveal nothing; the claimed sender
   * is checked against the directory only once the message proved to come from
   * the device key it names. Nothing is committed (sessions, one-time prekeys,
   * contacts) until every check passed. Throws only for transient failures, in
   * which case the caller leaves the envelope on the server for a later retry.
   */
  private async receiveEnvelope(payload: Uint8Array): Promise<void> {
    const st = this.state;
    if (!st || this.status !== 'ready') return;
    const local = this.localIdentity(st);
    let env;
    try {
      env = openEnvelope(local.deviceId, local.dh, payload);
    } catch {
      return; // not for us / corrupted: drop
    }
    const name = env.senderUsername;
    const fromSelf = name === st.identity.username;
    const senderDevice = toB64(env.senderDeviceId);
    if (fromSelf && senderDevice === st.identity.device.id) return;
    const known = fromSelf ? null : (st.contacts.get(name) ?? null);
    const key = `${name}/${senderDevice}`;
    const record = st.sessions.get(key);

    // 1. Existing session: it was bound to a certified device when it was created.
    if (record && (fromSelf || known)) {
      const out = decryptExisting(record, env.inner);
      if (out) {
        st.sessions.set(key, out.record);
        await this.persistSessions(st, name);
        await this.dispatch(st, fromSelf, known, out.plaintext);
        return;
      }
    }
    if (env.inner.kind !== 'prekey') return;

    // 2. New session: X3DH + decryption, tentatively.
    const p = env.inner.prekey;
    const baseKey = toB64(p.baseKey);
    if (st.prekeys.seenBaseKeys.includes(baseKey)) return; // replayed session start
    const spk = st.prekeys.signed.find((s) => s.keyId === p.signedPreKeyId);
    if (!spk) return;
    const otk = p.oneTimePreKeyId !== undefined ? st.prekeys.oneTime[String(p.oneTimePreKeyId)] : undefined;
    if (p.oneTimePreKeyId !== undefined && !otk) return; // already consumed: replay
    let res: ReturnType<typeof respondToPreKey>;
    try {
      res = respondToPreKey(
        local,
        p,
        env.senderDeviceId,
        { publicKey: fromB64(spk.pub), privateKey: fromB64(spk.priv) },
        otk ? { publicKey: fromB64(otk.pub), privateKey: fromB64(otk.priv) } : undefined,
      );
    } catch {
      return;
    }

    // 3. The message is authentic for (senderIdentityKey, senderDhKey). Now check
    //    that this key pair really belongs to the claimed sender.
    const senderIk = toB64(p.senderIdentityKey);
    const senderDh = toB64(p.senderDhKey);
    const certifies = (devices: DeviceRef[]) => devices.some((d) => d.deviceId === senderDevice && d.dhKey === senderDh);
    let contact = known;
    let created: ContactRecord | null = null;
    if (fromSelf) {
      if (senderIk !== st.identity.identityKey) return;
      if (!this.findOwnDevice(st, senderDevice)) await this.refreshOwnAccount(st);
      const d = this.findOwnDevice(st, senderDevice);
      if (!d || d.dhKey !== senderDh) return;
    } else if (contact && senderIk === contact.identityKey) {
      if (!certifies(contact.devices)) await this.refreshContactRecord(st, contact);
      if (!certifies(contact.devices)) return;
    } else if (contact) {
      // A different identity key: believable only if the directory agrees, and
      // never applied automatically (the conversation is marked key-changed).
      await this.refreshContactRecord(st, contact);
      if (contact.pendingIdentityKey !== senderIk) return;
      const entry = await this.directory(contact.username);
      if (!entry || entry.identityKey !== senderIk) return;
      const list = verifyDeviceList({ body: fromB64(entry.deviceList.body), signature: fromB64(entry.deviceList.signature) }, p.senderIdentityKey);
      if (!certifies(list.devices.map((d) => ({ deviceId: toB64(d.deviceId), signingKey: toB64(d.signingKey), dhKey: toB64(d.dhKey) })))) return;
    } else {
      // Unknown sender: the directory must list exactly this name (case included)
      // with exactly this identity key and device.
      const entry = await this.directory(name);
      if (!entry || entry.username !== name || entry.identityKey !== senderIk) return;
      created = newContact(entry.username, entry.identityKey, 'unverified');
      await this.applyContactDeviceList(st, created, entry.deviceList);
      if (!certifies(created.devices)) return;
      contact = created;
    }

    // 4. Commit.
    st.sessions.set(key, withNewCurrent(record, res.session));
    if (p.oneTimePreKeyId !== undefined) delete st.prekeys.oneTime[String(p.oneTimePreKeyId)];
    st.prekeys.seenBaseKeys.push(baseKey);
    if (st.prekeys.seenBaseKeys.length > MAX_SEEN_BASE_KEYS) st.prekeys.seenBaseKeys.splice(0, st.prekeys.seenBaseKeys.length - MAX_SEEN_BASE_KEYS);
    await st.vault.put('prekeys', st.prekeys);
    if (created) {
      st.contacts.set(created.username, created);
      st.fresh.add(created.username);
      this.addNotice(st, created, 'session-started', 'Encrypted conversation started. Compare safety numbers to verify who you are talking to.');
      await this.saveContacts(st);
    }
    await this.persistSessions(st, name);
    await this.dispatch(st, fromSelf, contact, res.plaintext);
  }

  /** Directory lookup; null if the account does not exist. Transient errors propagate. */
  private async directory(username: string): Promise<z.infer<typeof DirectoryEntry> | null> {
    try {
      return await this.api.json('GET', `/v1/directory/${encodeURIComponent(username)}`, undefined, DirectoryEntry);
    } catch (e) {
      if (e instanceof VeilError && e.code === 'not_found') return null;
      throw e;
    }
  }

  private async dispatch(st: Unlocked, fromSelf: boolean, contact: ContactRecord | null, plaintext: Uint8Array) {
    let content: Content;
    try {
      content = unpad(plaintext);
    } catch {
      return;
    }
    if (fromSelf) await this.handleOwnContent(st, content);
    else if (contact) await this.handleContactContent(st, contact, content);
  }

  private findOwnDevice(st: Unlocked, deviceId: string): DeviceRef | undefined {
    const d = this.ownDevices(st).find((x) => toB64(x.deviceId) === deviceId);
    return d ? { deviceId, signingKey: toB64(d.signingKey), dhKey: toB64(d.dhKey) } : undefined;
  }

  private async handleContactContent(st: Unlocked, c: ContactRecord, content: Content) {
    switch (content.t) {
      case 'msg': {
        c.clock = Math.max(c.clock, content.clock);
        const inserted = this.insertMessage(st, c.username, {
          id: content.id,
          peer: c.username,
          direction: 'in',
          clock: content.clock,
          text: content.text,
          attachments: content.att.map((p) => ({ attachmentId: p.id, name: p.name, mime: p.mime, size: p.size })),
          status: 'received',
          readByPeer: false,
          sortKey: `${c.username}:${content.id}`,
          pointers: content.att,
          receiptSent: false,
        });
        if (!inserted) return;
        c.hidden = false;
        c.unread += 1;
        c.preview = previewOf(content.text, content.att);
        break;
      }
      case 'read': {
        if (!st.settings.readReceipts) return;
        const ids = new Set(content.ids);
        for (const m of this.conv(st, c.username)) if (m.direction === 'out' && ids.has(m.id)) m.readByPeer = true;
        break;
      }
      case 'profile': {
        c.profileKey = content.key;
        c.displayName = null;
        if (content.key) {
          try {
            const entry = await this.api.json('GET', `/v1/directory/${encodeURIComponent(c.username)}`, undefined, DirectoryEntry);
            if (entry.profile) c.displayName = decryptProfile(content.key, entry.profile);
          } catch {
            // display name stays unknown
          }
        }
        break;
      }
      default:
        return; // 'sent' and 'contact' are only accepted from our own devices
    }
    await this.saveConversation(st, c.username);
    await this.saveContacts(st);
    this.emitConversation(c.username);
  }

  private async handleOwnContent(st: Unlocked, content: Content) {
    if (content.t === 'sent') {
      let c = st.contacts.get(content.to);
      if (!c) {
        try {
          const entry = await this.api.json('GET', `/v1/directory/${encodeURIComponent(content.to)}`, undefined, DirectoryEntry);
          c = newContact(entry.username, entry.identityKey, 'unverified');
          await this.applyContactDeviceList(st, c, entry.deviceList);
          st.contacts.set(c.username, c);
        } catch {
          return;
        }
      }
      c.clock = Math.max(c.clock, content.clock);
      if (
        this.insertMessage(st, c.username, {
          id: content.id,
          peer: c.username,
          direction: 'out',
          clock: content.clock,
          text: content.text,
          attachments: content.att.map((p) => ({ attachmentId: p.id, name: p.name, mime: p.mime, size: p.size })),
          status: 'sent',
          readByPeer: false,
          sortKey: `${st.identity.username}:${content.id}`,
          pointers: content.att,
          receiptSent: true,
        })
      ) {
        c.preview = previewOf(content.text, content.att);
      }
      await this.saveConversation(st, c.username);
      await this.saveContacts(st);
      this.emitConversation(c.username);
    } else if (content.t === 'contact') {
      // Our own (authenticated) device vouches for this key: stronger than TOFU.
      let c = st.contacts.get(content.username);
      if (!c) {
        c = newContact(content.username, content.identityKey, content.verified ? 'verified' : 'unverified');
        st.contacts.set(c.username, c);
      } else if (c.identityKey !== content.identityKey || c.pendingIdentityKey !== null) {
        // Our own device accepted this key (after the user reviewed it there):
        // apply it here too, with fresh sessions.
        c.identityKey = content.identityKey;
        c.pendingIdentityKey = null;
        c.deviceListVersion = 0;
        c.devices = [];
        for (const key of [...st.sessions.keys()]) if (key.startsWith(`${c.username}/`)) st.sessions.delete(key);
        await this.persistSessions(st, c.username);
      }
      c.verification = content.verified ? 'verified' : 'unverified';
      await this.refreshContactRecord(st, c).catch(() => {});
      await this.saveContacts(st);
    }
  }

  private async syncContactToOwnDevices(st: Unlocked, c: ContactRecord) {
    if (st.ownListStale) await this.mutex.run(() => this.refreshOwnAccount(st));
    const others = this.ownDevices(st).filter((d) => toB64(d.deviceId) !== st.identity.device.id);
    if (others.length === 0) return;
    await this.sendToOwnDevices(st, { v: 1, t: 'contact', username: c.username, identityKey: c.identityKey, verified: c.verification === 'verified' });
  }

  private async sendToOwnDevices(st: Unlocked, content: Content) {
    await this.mutex.run(async () => {
      const own = this.ownDevices(st)
        .filter((d) => toB64(d.deviceId) !== st.identity.device.id)
        .map((d) => ({ deviceId: toB64(d.deviceId), signingKey: toB64(d.signingKey), dhKey: toB64(d.dhKey) }));
      if (own.length === 0) return;
      await this.ensureSessions(st, st.identity.username, st.identity.identityKey, own);
      const local = this.localIdentity(st);
      const envelopes: OutgoingEnvelope[] = [];
      for (const d of own) {
        const rec = st.sessions.get(`${st.identity.username}/${d.deviceId}`);
        if (!rec?.current) continue;
        const inner = encryptWith(rec.current, local, pad(content));
        envelopes.push({
          deviceId: d.deviceId,
          envelopeId: toB64(randomBytes(16)),
          payload: toB64(sealEnvelope(fromB64(d.deviceId), fromB64(d.dhKey), { senderUsername: st.identity.username, senderDeviceId: local.deviceId, inner })),
        });
      }
      await this.persistSessions(st, st.identity.username);
      if (envelopes.length) await this.api.json('POST', '/v1/messages', { envelopes }, SendResponse);
    });
  }

  // ================================================================ attachments

  async downloadAttachment(peer: string, messageId: string, attachmentId: string) {
    const st = this.requireReady();
    const m = this.conv(st, peer).find((x) => x.id === messageId);
    const p = m?.pointers.find((x) => x.id === attachmentId);
    if (!m || !p) throw new VeilError('not_found', 'Attachment not found.');
    const cacheKey = `att:${attachmentId}`;
    const cached = await st.vault.get<string>(cacheKey);
    if (cached) return { name: p.name, mime: p.mime, bytes: fromB64(cached) };
    let blob: Uint8Array;
    try {
      blob = await this.api.binary('GET', `/v1/attachments/${attachmentId}`);
    } catch (e) {
      if (e instanceof VeilError && e.code === 'not_found') throw new VeilError('not_found', 'This attachment has expired or was deleted.');
      throw e;
    }
    let bytes: Uint8Array;
    try {
      bytes = decryptAttachment(blob, fromB64(p.key), fromB64(p.digest));
    } catch {
      throw new VeilError('crypto', 'The attachment failed integrity checks.');
    }
    await st.vault.put(cacheKey, toB64(bytes));
    return { name: p.name, mime: p.mime, bytes };
  }

  // ================================================================ profile

  async updateSettings(patch: Partial<PrivacySettings>): Promise<void> {
    const st = this.requireReady();
    const before = { ...st.settings };
    const next: PrivacySettings = { ...st.settings, ...patch };
    next.displayName = next.displayName.trim().slice(0, 64);
    st.settings = next;
    await st.vault.put('settings', next);
    const profileChanged = before.shareProfile !== next.shareProfile || (next.shareProfile && before.displayName !== next.displayName);
    if (profileChanged) {
      if (next.shareProfile && next.displayName) {
        const blob = seal(fromB64(st.identity.profileKey), encodeJson({ v: 1, displayName: next.displayName }), PROFILE_AD);
        await this.api.send('PUT', '/v1/profile', { profile: toB64(blob) });
        for (const c of st.contacts.values()) c.profileShared = false;
        for (const c of st.contacts.values()) if (!c.accountGone && c.verification !== 'key-changed') await this.shareProfileWith(st, c).catch(() => {});
      } else {
        // Stop sharing: delete the server copy and rotate the key so old holders learn nothing new.
        await this.api.send('PUT', '/v1/profile', { profile: null });
        st.identity.profileKey = toB64(randomBytes(32));
        await st.vault.put('identity', st.identity);
        for (const c of st.contacts.values()) {
          if (c.profileShared && !c.accountGone && c.verification !== 'key-changed') await this.sendContent(st, c, { v: 1, t: 'profile', key: null }, null).catch(() => {});
          c.profileShared = false;
        }
      }
      await this.saveContacts(st);
    }
    this.emit();
  }

  private async shareProfileWith(st: Unlocked, c: ContactRecord) {
    await this.sendContent(st, c, { v: 1, t: 'profile', key: st.identity.profileKey }, null);
    c.profileShared = true;
    await this.saveContacts(st);
  }

  // ================================================================ linking (new device)

  async requestLink(): Promise<{ code: string }> {
    if (this.status !== 'needs-link' || !this.pendingPassword) throw new VeilError('forbidden', 'Sign in first.');
    const device = generateDeviceKeys();
    const provisioning = x25519KeyPair();
    // The code never goes to the server; the request carries only a commitment to it.
    const secret = generateLinkSecret();
    const request = encodeLinkRequest(
      { deviceId: device.deviceId, signingKey: device.signing.publicKey, dhKey: device.dh.publicKey, provisioningKey: provisioning.publicKey },
      secret,
    );
    const res = await this.api.json('POST', '/v1/link/requests', { request: toB64(request) }, CreateLinkResponse);
    this.pendingLink = { linkId: res.linkId, request, secret, device, provisioning };
    this.linkCode = formatLinkCode(secret);
    this.emit();
    return { code: this.linkCode };
  }

  async waitForLinkApproval(signal?: AbortSignal): Promise<void> {
    for (;;) {
      const pl = this.pendingLink;
      if (!pl) throw new VeilError('forbidden', 'No link request in progress.');
      if (signal?.aborted) {
        await this.api.send('DELETE', `/v1/link/requests/${pl.linkId}`).catch(() => {});
        this.pendingLink = null;
        this.linkCode = null;
        this.emit();
        throw new VeilError('invalid_input', 'Linking cancelled.');
      }
      const status = await this.api.json('GET', `/v1/link/requests/${pl.linkId}`, undefined, LinkStatus);
      if (status.status === 'approved' && status.payload) {
        await this.completeLink(pl, fromB64(status.payload));
        return;
      }
      await new Promise((r) => setTimeout(r, 1500));
    }
  }

  private async completeLink(pl: NonNullable<VeilClient['pendingLink']>, sealed: Uint8Array) {
    let payload: ProvisioningPayload;
    try {
      payload = ProvisioningPayload.parse(decodeJson(openProvisioning(pl.request, pl.secret, pl.provisioning, sealed)));
    } catch {
      throw new VeilError('crypto', 'The approval could not be verified.');
    }
    const account = await this.api.json('GET', '/v1/account', undefined, AccountResponse);
    if (account.identityKey !== payload.identityKey || account.username !== payload.username) throw new VeilError('crypto', 'Identity mismatch during linking.');
    const list = verifyDeviceList({ body: fromB64(payload.deviceList.body), signature: fromB64(payload.deviceList.signature) }, fromB64(payload.identityKey));
    const me = list.devices.find((d) => constantTimeEqual(d.deviceId, pl.device.deviceId));
    if (!me || !constantTimeEqual(me.dhKey, pl.device.dh.publicKey) || !constantTimeEqual(me.signingKey, pl.device.signing.publicKey)) {
      throw new VeilError('crypto', 'This device is not in the approved device list.');
    }
    await this.enrollDevice({
      device: pl.device,
      deviceList: payload.deviceList,
      identityKey: payload.identityKey,
      identityPrivateKey: null,
      username: payload.username,
      profileKey: payload.profileKey,
      contacts: payload.contacts,
      settings: payload.settings,
      linkId: pl.linkId,
      recoveryBackupKey: null,
      clockJump: 0,
    });
    this.pendingLink = null;
    this.linkCode = null;
  }

  private async enrollDevice(input: {
    device: ReturnType<typeof generateDeviceKeys>;
    deviceList: SignedDeviceListJson;
    identityKey: string;
    identityPrivateKey: string | null;
    username: string;
    profileKey: string;
    contacts: ContactSnapshot[];
    settings: PrivacySettings;
    linkId: string | null;
    recoveryBackupKey: string | null;
    clockJump: number;
  }) {
    const pw = this.pendingPassword;
    if (!pw) throw new VeilError('forbidden', 'Sign in first.');
    const { device } = input;
    const spk = generateSignedPreKey(device, 1);
    const otks = generateOneTimePreKeys(1, ONE_TIME_PREKEY_BATCH);
    const session = await this.api.json(
      'POST',
      '/v1/devices/enroll',
      {
        deviceList: input.deviceList,
        device: { deviceId: toB64(device.deviceId), signingKey: toB64(device.signing.publicKey), dhKey: toB64(device.dh.publicKey) },
        signedPreKey: { keyId: spk.keyId, publicKey: toB64(spk.keyPair.publicKey), signature: toB64(spk.signature) },
        oneTimePreKeys: otks.map((k) => ({ keyId: k.keyId, publicKey: toB64(k.keyPair.publicKey) })),
        ...(input.linkId ? { linkId: input.linkId } : {}),
      },
      SessionResponse,
    );
    this.api.setTokens({ accessToken: session.accessToken, refreshToken: session.refreshToken });
    const vault = await LocalVault.create(this.storage, pw.vaultKek, pw.clientSalt, pw.kdf);
    wipe(pw.vaultKek);
    this.pendingPassword = null;
    const identity: IdentityRecord = {
      username: input.username,
      identityKey: input.identityKey,
      identityPrivateKey: input.identityPrivateKey,
      device: {
        id: toB64(device.deviceId),
        signingPub: toB64(device.signing.publicKey),
        signingPriv: toB64(device.signing.privateKey),
        dhPub: toB64(device.dh.publicKey),
        dhPriv: toB64(device.dh.privateKey),
      },
      deviceList: input.deviceList,
      profileKey: input.profileKey,
      recoveryBackupKey: input.recoveryBackupKey,
    };
    const prekeys: PrekeyRecord = {
      signed: [{ keyId: 1, pub: toB64(spk.keyPair.publicKey), priv: toB64(spk.keyPair.privateKey), signature: toB64(spk.signature), day: today() }],
      oneTime: Object.fromEntries(otks.map((k) => [String(k.keyId), { pub: toB64(k.keyPair.publicKey), priv: toB64(k.keyPair.privateKey) }])),
      nextOneTimeId: ONE_TIME_PREKEY_BATCH + 1,
      nextSignedId: 2,
      seenBaseKeys: [],
    };
    await this.adoptVault(vault, identity, prekeys, input.contacts, input.settings, input.clockJump);
    const st = this.state!;
    for (const c of st.contacts.values()) await this.refreshContactRecord(st, c).catch(() => {});
    const account = await this.api.json('GET', '/v1/account', undefined, AccountResponse);
    this.recoveryEnabled = account.recoveryEnabled;
    this.becomeReady();
  }

  async restoreWithRecoveryKey(recoveryKey: string): Promise<void> {
    if (this.status !== 'needs-link' || !this.pendingPassword) throw new VeilError('forbidden', 'Sign in first.');
    const backup = await this.api.json('GET', '/v1/recovery/backup', undefined, RecoveryBackupResponse).catch((e) => {
      if (e instanceof VeilError && e.code === 'not_found') throw new VeilError('not_found', 'Recovery is not enabled for this account.');
      throw e;
    });
    await this.restoreFromBackup(recoveryKey, backup.backup);
  }

  async recoverAccount(input: { username: string; recoveryKey: string; newPassword: string }): Promise<void> {
    let secret: Bytes;
    try {
      secret = parseRecoveryKey(input.recoveryKey);
    } catch {
      throw new VeilError('invalid_input', 'That recovery key is not valid. Check for typos.');
    }
    const rk = deriveRecoveryKeys(secret);
    wipe(secret);
    const config = await this.publicConfig();
    this.checkKdf(config.recommendedKdf);
    const salt = newClientSalt();
    const pw = await derivePasswordKeys(input.newPassword, salt, config.recommendedKdf);
    let res: z.infer<typeof RecoverResponse>;
    try {
      res = await this.api.json(
        'POST',
        '/v1/auth/recover',
        { username: input.username.trim(), recoveryKey: toB64(rk.recoveryAuthKey), newClientSalt: toB64(salt), newKdf: config.recommendedKdf, newAuthKey: toB64(pw.authKey) },
        RecoverResponse,
        { auth: false },
      );
    } catch (e) {
      if (e instanceof VeilError && (e.code === 'unauthorized' || e.code === 'not_found')) throw new VeilError('invalid_credentials', 'Username or recovery key is incorrect.');
      throw e;
    }
    wipe(pw.authKey);
    this.api.setTokens({ accessToken: res.session.accessToken, refreshToken: res.session.refreshToken });
    // A stale vault from before (if any) is sealed with an unknown password: replace it.
    if (await LocalVault.readMeta(this.storage)) await this.storage.destroy();
    this.pendingPassword = { vaultKek: pw.vaultKek, clientSalt: salt, kdf: config.recommendedKdf, username: res.session.username };
    this.status = 'needs-link';
    await this.restoreFromBackup(input.recoveryKey, res.backup);
  }

  private async restoreFromBackup(recoveryKey: string, backupB64: string) {
    let secret: Bytes;
    try {
      secret = parseRecoveryKey(recoveryKey);
    } catch {
      throw new VeilError('invalid_input', 'That recovery key is not valid. Check for typos.');
    }
    const rk = deriveRecoveryKeys(secret);
    wipe(secret);
    let backup: RecoveryBackup;
    try {
      backup = RecoveryBackup.parse(decodeJson(open(rk.backupKey, fromB64(backupB64), RECOVERY_BACKUP_AD)));
    } catch {
      throw new VeilError('invalid_credentials', 'The recovery key does not match this account.');
    }
    const account = await this.api.json('GET', '/v1/account', undefined, AccountResponse);
    const aikPriv = fromB64(backup.identityPrivateKey);
    if (toB64(ed25519PublicFromPrivate(aikPriv)) !== account.identityKey) throw new VeilError('crypto', 'The backup does not match this account identity.');
    const current = verifyDeviceList({ body: fromB64(account.deviceList.body), signature: fromB64(account.deviceList.signature) }, fromB64(account.identityKey));
    if (backup.deviceListVersion !== undefined && current.version < backup.deviceListVersion) {
      // Re-signing an old list would re-certify devices that were removed (e.g. a stolen phone).
      throw new VeilError('crypto', 'The server returned a device list older than your backup. Refusing to restore from it.');
    }
    const device = generateDeviceKeys();
    const next = signDeviceList(aikPriv, {
      identityKey: fromB64(account.identityKey),
      version: current.version + 1,
      devices: [...current.devices, deviceEntryFor(device, true)],
    });
    await this.enrollDevice({
      device,
      deviceList: { body: toB64(next.body), signature: toB64(next.signature) },
      identityKey: account.identityKey,
      identityPrivateKey: backup.identityPrivateKey,
      username: account.username,
      profileKey: backup.profileKey,
      contacts: backup.contacts,
      settings: { ...DEFAULT_SETTINGS },
      linkId: null,
      recoveryBackupKey: toB64(rk.backupKey),
      // The backup may be older than the newest messages: jump ahead so new messages sort last.
      clockJump: RESTORE_CLOCK_JUMP,
    });
    wipe(aikPriv);
  }

  // ================================================================ linking (primary)

  async pendingLinks(): Promise<PendingLink[]> {
    const st = this.requireReady();
    if (!st.identity.identityPrivateKey) return [];
    const res = await this.api.json('GET', '/v1/link/requests', undefined, PendingLinkRequests);
    this.linkRequests.clear();
    return res.requests.map((r) => {
      this.linkRequests.set(r.linkId, fromB64(r.request));
      return { linkId: r.linkId };
    });
  }

  async approveLink(linkId: string, code: string): Promise<void> {
    const st = this.requireReady();
    if (!st.identity.identityPrivateKey) throw new VeilError('forbidden', 'Only a primary device can approve new devices.');
    const request = this.linkRequests.get(linkId);
    if (!request) throw new VeilError('not_found', 'Link request not found. Refresh the list.');
    let secret: Bytes;
    try {
      secret = parseLinkCode(code);
    } catch {
      throw new VeilError('invalid_input', 'That code is not valid. Check it on the new device.');
    }
    // The code authenticates the request: a request substituted by the server
    // (or any other party) does not match the code shown on the new device.
    if (!verifyLinkRequest(request, secret)) throw new VeilError('crypto', 'The code does not match this request. Do not approve it.');
    const req = decodeLinkRequest(request);
    await this.refreshOwnAccount(st);
    const current = this.ownDevices(st);
    const version = verifyDeviceList(
      { body: fromB64(st.identity.deviceList.body), signature: fromB64(st.identity.deviceList.signature) },
      fromB64(st.identity.identityKey),
    ).version;
    const aikPriv = fromB64(st.identity.identityPrivateKey);
    const next = signDeviceList(aikPriv, {
      identityKey: fromB64(st.identity.identityKey),
      version: version + 1,
      devices: [...current, { deviceId: req.deviceId, signingKey: req.signingKey, dhKey: req.dhKey, primary: false }],
    });
    wipe(aikPriv);
    const payload: ProvisioningPayload = {
      v: 1,
      username: st.identity.username,
      identityKey: st.identity.identityKey,
      deviceList: { body: toB64(next.body), signature: toB64(next.signature) },
      profileKey: st.identity.profileKey,
      contacts: [...st.contacts.values()].filter((c) => !c.accountGone).map((c) => ({ username: c.username, identityKey: c.identityKey, verified: c.verification === 'verified', clock: Math.min(c.clock, MAX_CLOCK) })),
      settings: { ...st.settings },
    };
    await this.api.send('POST', `/v1/link/requests/${linkId}/response`, { payload: toB64(sealProvisioning(request, secret, encodeJson(payload))) });
    wipe(secret);
    this.linkRequests.delete(linkId);
    st.ownListStale = true;
  }

  async rejectLink(linkId: string): Promise<void> {
    this.requireReady();
    await this.api.send('DELETE', `/v1/link/requests/${linkId}`);
    this.linkRequests.delete(linkId);
  }

  // ================================================================ settings: devices, sessions, password, recovery

  async devices(): Promise<DeviceInfo[]> {
    const st = this.requireReady();
    await this.refreshOwnAccount(st).catch(() => {});
    return this.ownDevices(st).map((d) => ({
      deviceId: toB64(d.deviceId),
      primary: d.primary,
      current: toB64(d.deviceId) === st.identity.device.id,
      fingerprint: fingerprintOf(d),
    }));
  }

  async removeDevice(deviceId: string): Promise<void> {
    const st = this.requireReady();
    if (!st.identity.identityPrivateKey) throw new VeilError('forbidden', 'Only a primary device can remove devices.');
    if (deviceId === st.identity.device.id) throw new VeilError('invalid_input', 'You cannot remove the device you are using. Use Panic Reset to abandon the account.');
    await this.refreshOwnAccount(st);
    const current = verifyDeviceList(
      { body: fromB64(st.identity.deviceList.body), signature: fromB64(st.identity.deviceList.signature) },
      fromB64(st.identity.identityKey),
    );
    const remaining = current.devices.filter((d) => toB64(d.deviceId) !== deviceId);
    if (remaining.length === current.devices.length) throw new VeilError('not_found', 'Device not found.');
    const aikPriv = fromB64(st.identity.identityPrivateKey);
    const next = signDeviceList(aikPriv, { identityKey: current.identityKey, version: current.version + 1, devices: remaining });
    wipe(aikPriv);
    const signed = { body: toB64(next.body), signature: toB64(next.signature) };
    await this.api.send('PUT', '/v1/devices/list', { deviceList: signed });
    await this.mutex.run(() => this.applyOwnDeviceList(signed));
  }

  async sessions(): Promise<SessionSummary[]> {
    this.requireReady();
    const res = await this.api.json('GET', '/v1/sessions', undefined, SessionsResponse);
    return res.sessions.map((s) => ({ sessionId: s.sessionId, kind: s.kind, deviceId: s.deviceId, current: s.current }));
  }

  async revokeSession(sessionId: string): Promise<void> {
    this.requireReady();
    await this.api.send('DELETE', `/v1/sessions/${sessionId}`);
  }

  async changePassword(currentPassword: string, newPassword: string): Promise<void> {
    const st = this.requireReady();
    const pre = await this.prelogin(st.identity.username);
    const cur = await derivePasswordKeys(currentPassword, fromB64(pre.clientSalt), pre.kdf);
    const config = await this.publicConfig();
    const kdf = config.recommendedKdf;
    this.checkKdf(kdf);
    const salt = newClientSalt();
    const next = await derivePasswordKeys(newPassword, salt, kdf);
    try {
      const s = await this.api.json(
        'POST',
        '/v1/auth/password',
        { currentAuthKey: toB64(cur.authKey), newClientSalt: toB64(salt), newKdf: kdf, newAuthKey: toB64(next.authKey) },
        SessionResponse,
      );
      this.api.setTokens({ accessToken: s.accessToken, refreshToken: s.refreshToken });
    } catch (e) {
      if (e instanceof VeilError && e.code === 'unauthorized') throw new VeilError('invalid_credentials', 'Your current password is incorrect.');
      throw e;
    } finally {
      wipe(cur.authKey, cur.vaultKek, next.authKey);
    }
    await st.vault.rewrap(next.vaultKek, salt, kdf);
    wipe(next.vaultKek);
  }

  private recoveryBackupPayload(st: Unlocked): RecoveryBackup {
    return {
      v: 1,
      deviceListVersion: verifyDeviceList(
        { body: fromB64(st.identity.deviceList.body), signature: fromB64(st.identity.deviceList.signature) },
        fromB64(st.identity.identityKey),
      ).version,
      identityPrivateKey: st.identity.identityPrivateKey!,
      profileKey: st.identity.profileKey,
      contacts: [...st.contacts.values()].filter((c) => !c.accountGone).map((c) => ({ username: c.username, identityKey: c.identityKey, verified: c.verification === 'verified', clock: Math.min(c.clock, MAX_CLOCK) })),
    };
  }

  async enableRecovery(): Promise<string> {
    const st = this.requireReady();
    if (!st.identity.identityPrivateKey) throw new VeilError('forbidden', 'Recovery can only be set up on a primary device.');
    const secret = generateRecoverySecret();
    const rk = deriveRecoveryKeys(secret);
    const blob = seal(rk.backupKey, encodeJson(this.recoveryBackupPayload(st)), RECOVERY_BACKUP_AD);
    await this.api.send('PUT', '/v1/recovery', { verifierKey: toB64(rk.recoveryAuthKey), backup: toB64(blob) });
    st.identity.recoveryBackupKey = toB64(rk.backupKey);
    await st.vault.put('identity', st.identity);
    this.recoveryEnabled = true;
    this.emit();
    const text = formatRecoveryKey(secret);
    wipe(secret, rk.recoveryAuthKey);
    return text;
  }

  async disableRecovery(): Promise<void> {
    const st = this.requireReady();
    await this.api.send('DELETE', '/v1/recovery');
    st.identity.recoveryBackupKey = null;
    await st.vault.put('identity', st.identity);
    this.recoveryEnabled = false;
    this.emit();
  }

  private async updateRecoveryBackup(st: Unlocked) {
    if (!st.identity.recoveryBackupKey || !st.identity.identityPrivateKey) return;
    const blob = seal(fromB64(st.identity.recoveryBackupKey), encodeJson(this.recoveryBackupPayload(st)), RECOVERY_BACKUP_AD);
    await this.api.send('PUT', '/v1/recovery/backup', { backup: toB64(blob) });
  }

  // ================================================================ export

  async exportServerData() {
    this.requireReady();
    return this.api.json('GET', '/v1/account/export', undefined, AccountExport);
  }

  async exportLocalData(): Promise<unknown> {
    const st = this.requireReady();
    return {
      format: 'veil-local-export-v1',
      warning: 'This file contains your decrypted conversations in plaintext. Store it securely or delete it.',
      username: st.identity.username,
      identityKey: st.identity.identityKey,
      settings: st.settings,
      contacts: [...st.contacts.values()].map((c) => ({
        username: c.username,
        identityKey: c.identityKey,
        verification: c.verification,
        accountGone: c.accountGone,
        displayName: c.displayName,
      })),
      conversations: Object.fromEntries(
        [...st.conversations.entries()].map(([peer, msgs]) => [
          peer,
          msgs.map((m) => ({ id: m.id, direction: m.direction, order: m.clock, text: m.text, attachments: m.attachments.map((a) => a.name), notice: m.notice ?? null })),
        ]),
      ),
    };
  }

  // ================================================================ panic reset

  async panicReset(options: ResetOptions, onProgress: (r: ResetReport) => void): Promise<ResetReport> {
    if (options.createNewIdentity && (!options.newPassword || options.newPassword.length < 10)) {
      throw new VeilError('invalid_input', 'Choose a password of at least 10 characters for the new identity.');
    }
    // A password-only session (all devices lost or seized) may delete the account too.
    // There is no vault yet, so the journal lives in memory only.
    if (this.status === 'needs-link' && this.api.hasSession() && this.pendingPassword) {
      const journal: ResetJournal = {
        jobId: toB64(randomBytes(16)),
        jobSecret: toB64(randomBytes(32)),
        attachments: [],
        old: { username: this.pendingPassword.username, identityKey: '', deviceIds: [] },
      };
      wipe(this.pendingPassword.vaultKek);
      this.pendingPassword = null;
      this.pendingLink = null;
      this.linkCode = null;
      const report: ResetReport = { phase: 'initiated', server: null, localWiped: false, newIdentity: null, problems: [], notes: [] };
      onProgress({ ...report });
      return this.runReset(journal, report, options, onProgress);
    }
    const st = this.requireReady();
    this.disconnect();
    const journal: ResetJournal = {
      jobId: toB64(randomBytes(16)),
      jobSecret: toB64(randomBytes(32)),
      attachments: st.uploads.map((u) => ({ attachmentId: u.attachmentId, deleteToken: u.deleteToken })),
      old: {
        username: st.identity.username,
        identityKey: st.identity.identityKey,
        deviceIds: this.ownDevices(st).map((d) => toB64(d.deviceId)),
      },
    };
    await st.vault.put('reset-journal', journal);
    await LocalVault.setResetPending(this.storage, true);
    this.status = 'reset-pending';
    const report: ResetReport = { phase: 'initiated', server: null, localWiped: false, newIdentity: null, problems: [], notes: [] };
    onProgress({ ...report });
    return this.runReset(journal, report, options, onProgress);
  }

  async resumeReset(password: string, onProgress: (r: ResetReport) => void): Promise<ResetReport> {
    const meta = await LocalVault.readMeta(this.storage);
    if (!meta) {
      // No vault, so no journal: we have no evidence the server deleted anything.
      await LocalVault.setResetPending(this.storage, false);
      const r: ResetReport = {
        phase: 'partial',
        server: null,
        localWiped: true,
        newIdentity: null,
        problems: ['This device holds no VEIL data, but server-side deletion could not be confirmed. Sign in with your password and run Panic Reset to make sure the account is deleted.'],
        notes: [],
      };
      this.setStatus('no-vault');
      return r;
    }
    const keys = await derivePasswordKeys(password, fromB64(meta.clientSalt), meta.kdf);
    let vault: LocalVault;
    try {
      vault = await LocalVault.unlock(this.storage, keys.vaultKek);
    } catch {
      throw new VeilError('invalid_credentials', 'Incorrect password.');
    } finally {
      wipe(keys.vaultKek);
    }
    const st = await this.loadVault(vault);
    this.state = st;
    const journal = await vault.get<ResetJournal>('reset-journal');
    if (!journal) {
      // Flag without journal: the reset never got past step 1. Nothing was sent.
      await LocalVault.setResetPending(this.storage, false);
      wipe(keys.authKey);
      vault.close();
      this.state = null;
      this.setStatus('locked');
      return { phase: 'failed', server: null, localWiped: false, newIdentity: null, problems: ['The reset was cancelled before anything was deleted. Sign in normally.'], notes: [] };
    }
    const report: ResetReport = { phase: 'initiated', server: null, localWiped: false, newIdentity: null, problems: [], notes: [] };
    onProgress({ ...report });
    // A device login may be needed if the server never processed the reset.
    const authed = async () => {
      if (this.api.hasSession()) return;
      const pre = await this.prelogin(st.identity.username);
      const k = pre.clientSalt === meta.clientSalt ? keys : await derivePasswordKeys(password, fromB64(pre.clientSalt), pre.kdf);
      await this.login(st.identity.username, k.authKey, pre.nonce, st.identity.device);
    };
    return this.runReset(journal, report, { createNewIdentity: false, wipeLocallyIfServerUnreachable: false }, onProgress, authed).finally(() => wipe(keys.authKey));
  }

  private async runReset(
    journal: ResetJournal,
    report: ResetReport,
    options: ResetOptions,
    onProgress: (r: ResetReport) => void,
    ensureAuth?: () => Promise<void>,
  ): Promise<ResetReport> {
    const step = (patch: Partial<ResetReport>) => {
      Object.assign(report, patch);
      onProgress({ ...report, problems: [...report.problems], notes: [...report.notes] });
    };
    const config = await this.publicConfig().catch(() => null);

    // --- server deletion (idempotent by jobId)
    step({ phase: 'server-deleting' });
    let server: z.infer<typeof ResetStatus> | null = null;
    let lastError: unknown = null;
    for (let attempt = 0; attempt < 4 && !server; attempt++) {
      try {
        // The reset call is idempotent by jobId. With a live session we call it
        // directly; when resuming without one, the job secret alone can read
        // the status of a reset the server already processed.
        const submit = () =>
          this.api.json('POST', '/v1/reset', { jobId: journal.jobId, jobSecret: journal.jobSecret, attachments: journal.attachments }, ResetStatus);
        // On retries the first attempt may already have committed (and revoked our session).
        server = attempt === 0 && this.api.hasSession()
          ? await submit()
          : await this.api
              .json('POST', '/v1/reset/status', { jobId: journal.jobId, jobSecret: journal.jobSecret }, ResetStatus, { auth: false })
              .catch(async (e) => {
                if (!(e instanceof VeilError) || (e.code !== 'not_found' && e.code !== 'unauthorized')) throw e;
                if (ensureAuth) await ensureAuth();
                return submit();
              });
      } catch (e) {
        lastError = e;
        if (e instanceof VeilError && e.code !== 'network' && e.code !== 'internal' && e.code !== 'rate_limited') break;
        await new Promise((r) => setTimeout(r, 500 * 2 ** attempt));
      }
    }

    if (server?.accountRecordsDeleted) {
      step({ phase: 'server-deleted', server });
      if (server.state === 'partial') {
        report.problems.push(
          `${server.attachmentsPending} attachment file(s) could not be deleted yet. The server retries automatically; they expire within ${server.attachmentRetentionDays} days regardless.`,
        );
      }
      if (server.attachmentsNotFound > 0) {
        report.notes.push(`${server.attachmentsNotFound} attachment(s) were already gone (downloaded by all recipients or expired).`);
      }
    } else {
      const unreachable = lastError instanceof VeilError && (lastError.code === 'network' || lastError.code === 'internal' || lastError.code === 'rate_limited');
      if (!(unreachable && options.wipeLocallyIfServerUnreachable)) {
        report.problems.push(
          unreachable
            ? 'The server could not be reached. Nothing has been deleted yet; your account still exists. Try again, or choose to wipe this device anyway.'
            : 'The server refused the reset request. Nothing has been deleted.',
        );
        step({ phase: 'failed' });
        return { ...report };
      }
      report.problems.push(
        'The server could not be reached. Your account and its server-side data STILL EXIST. Sign in with your password from any device and run Panic Reset again to delete them.',
      );
    }

    // --- local wipe
    const st = this.state;
    this.api.setTokens(null);
    if (st) {
      st.vault.close();
      this.state = null;
    }
    await this.storage.destroy();
    const leftovers = (await this.storage.keys('meta')).length + (await this.storage.keys('records')).length;
    const localWiped = leftovers === 0;
    if (!localWiped) report.problems.push('Some local records could not be removed. Clear this site’s data in your browser settings.');
    step({ phase: 'local-wiped', localWiped });
    this.status = 'no-vault';
    this.recoveryEnabled = false;
    this.emit();

    if (config) {
      report.notes.push(
        `Server backups may contain the old account for up to ${config.retention.backupDays} days; deletions are re-applied if a backup is ever restored. Messages you sent that are still queued for recipients cannot be identified by the server and are delivered or expire within ${config.retention.undeliveredMessageDays} days. Copies already on your contacts’ devices are not affected.`,
      );
    }

    // --- optional replacement identity
    if (options.createNewIdentity && options.newPassword) {
      try {
        const suggestion = await this.suggestUsername();
        const reg = await this.register({ reservation: suggestion.reservation, password: options.newPassword, enableRecovery: !!options.enableRecovery }).catch(async (e) => {
          if (e instanceof VeilError && e.code === 'conflict') {
            const again = await this.suggestUsername();
            return this.register({ reservation: again.reservation, password: options.newPassword!, enableRecovery: !!options.enableRecovery });
          }
          throw e;
        });
        const ns = this.state as Unlocked | null;
        const distinct =
          !!ns &&
          reg.username !== journal.old.username &&
          ns.identity.identityKey !== journal.old.identityKey &&
          !journal.old.deviceIds.includes(ns.identity.device.id);
        if (!distinct) report.problems.push('The new identity could not be verified as distinct from the old one.');
        step({ phase: 'new-identity', newIdentity: { username: reg.username, distinctFromOld: distinct, recoveryKey: reg.recoveryKey } });
      } catch {
        report.problems.push('The new identity could not be created. You can create one from the welcome screen.');
      }
    }

    const fullyConfirmed = !!server?.accountRecordsDeleted && server.state === 'completed' && localWiped;
    step({ phase: fullyConfirmed ? 'completed' : 'partial' });
    return { ...report };
  }
}

// ---------------------------------------------------------------- helpers

/**
 * Failures worth retrying later (network, rate limits, server errors, a locked
 * vault). Verification failures (CryptoError) and missing accounts are final.
 */
function isTransient(e: unknown): boolean {
  if (e instanceof CryptoError) return false;
  if (e instanceof VeilError) return !['crypto', 'not_found', 'invalid_input', 'key_changed', 'account_gone'].includes(e.code);
  return true;
}

function newContact(username: string, identityKey: string, verification: Verification): ContactRecord {
  return {
    username,
    identityKey,
    pendingIdentityKey: null,
    verification,
    devices: [],
    deviceListVersion: 0,
    accountGone: false,
    profileKey: null,
    displayName: null,
    profileShared: false,
    clock: 0,
    unread: 0,
    preview: null,
  };
}

function previewOf(text: string, att: AttachmentPointer[]): string {
  const t = text.trim();
  if (t) return t.length > 80 ? `${t.slice(0, 80)}…` : t;
  return att.length ? `Attachment: ${att[0]!.name}` : '';
}

function decryptProfile(profileKey: string, blob: string): string | null {
  try {
    return Profile.parse(decodeJson(open(fromB64(profileKey), fromB64(blob), PROFILE_AD))).displayName || null;
  } catch {
    return null;
  }
}

function fingerprintOf(d: DeviceEntry): string {
  const h = sha256(new Uint8Array([...d.signingKey, ...d.dhKey]));
  const hex = [...h.subarray(0, 8)].map((b) => b.toString(16).padStart(2, '0')).join('');
  return hex.match(/.{4}/g)!.join(' ').toUpperCase();
}

