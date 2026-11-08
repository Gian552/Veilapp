// Per-device Double Ratchet session bookkeeping on top of @veil/crypto.
// A remote device may have one current session and a few previous ones
// (simultaneous initiation, delayed messages); the newest successful one wins.

import {
  type InnerMessage,
  type KeyPair,
  type PreKeyBundle,
  type PreKeyMessage,
  type SerializedRatchetState,
  deserializeState,
  fromB64,
  initRatchetInitiator,
  initRatchetResponder,
  ratchetDecrypt,
  ratchetEncrypt,
  serializeState,
  toB64,
  x3dhInitiate,
  x3dhRespond,
} from '@veil/crypto';

export interface StoredSession {
  ratchet: SerializedRatchetState;
  /** X3DH base key (initiator's ephemeral key) identifying this session. */
  baseKey: string;
  /** Set on the initiator until the first reply: every message re-sends the X3DH header. */
  pendingPreKey: { baseKey: string; signedPreKeyId: number; oneTimePreKeyId: number | null } | null;
  remoteDhKey: string;
}

export interface SessionRecord {
  current: StoredSession | null;
  previous: StoredSession[];
}

export const MAX_PREVIOUS_SESSIONS = 3;

export interface LocalIdentity {
  identityKey: Uint8Array;
  deviceId: Uint8Array;
  dh: KeyPair;
}

export function initiateSession(local: LocalIdentity, bundle: PreKeyBundle): StoredSession {
  const init = x3dhInitiate(local, bundle);
  const ratchet = initRatchetInitiator(init.sharedKey, init.remoteSignedPreKey, init.associatedData);
  init.sharedKey.fill(0);
  return {
    ratchet: serializeState(ratchet),
    baseKey: toB64(init.baseKey),
    pendingPreKey: { baseKey: toB64(init.baseKey), signedPreKeyId: init.signedPreKeyId, oneTimePreKeyId: init.oneTimePreKeyId ?? null },
    remoteDhKey: toB64(bundle.deviceDhKey),
  };
}

/** Encrypts with the session (mutating it) and returns the inner message to seal. */
export function encryptWith(session: StoredSession, local: LocalIdentity, plaintext: Uint8Array): InnerMessage {
  const state = deserializeState(session.ratchet);
  const message = ratchetEncrypt(state, plaintext);
  session.ratchet = serializeState(state);
  if (!session.pendingPreKey) return { kind: 'ratchet', message };
  const p = session.pendingPreKey;
  return {
    kind: 'prekey',
    prekey: {
      senderIdentityKey: local.identityKey,
      senderDhKey: local.dh.publicKey,
      baseKey: fromB64(p.baseKey),
      signedPreKeyId: p.signedPreKeyId,
      oneTimePreKeyId: p.oneTimePreKeyId ?? undefined,
      message,
    },
  };
}

/** Tries current then previous sessions; on success promotes the session and returns the new record. */
export function decryptExisting(record: SessionRecord, message: InnerMessage): { plaintext: Uint8Array; record: SessionRecord } | null {
  const ratchetMessage = message.kind === 'ratchet' ? message.message : message.prekey.message;
  const candidates = [record.current, ...record.previous].filter((s): s is StoredSession => s !== null);
  for (const s of candidates) {
    if (message.kind === 'prekey' && s.baseKey !== toB64(message.prekey.baseKey)) continue;
    try {
      const out = ratchetDecrypt(deserializeState(s.ratchet), ratchetMessage);
      const updated: StoredSession = {
        ...s,
        ratchet: serializeState(out.state),
        // A decryptable reply proves the responder has the session: stop re-sending X3DH data.
        pendingPreKey: message.kind === 'ratchet' ? null : s.pendingPreKey,
      };
      return { plaintext: out.plaintext, record: promote(record, s, updated) };
    } catch {
      // try the next candidate
    }
  }
  return null;
}

export function respondToPreKey(
  local: LocalIdentity,
  prekey: PreKeyMessage,
  senderDeviceId: Uint8Array,
  signedPreKey: KeyPair,
  oneTimePreKey: KeyPair | undefined,
): { plaintext: Uint8Array; session: StoredSession } {
  const { sharedKey, associatedData } = x3dhRespond({
    local,
    signedPreKey,
    oneTimePreKey,
    remote: { identityKey: prekey.senderIdentityKey, deviceId: senderDeviceId, dhKey: prekey.senderDhKey, baseKey: prekey.baseKey },
  });
  const state = initRatchetResponder(sharedKey, signedPreKey, associatedData);
  sharedKey.fill(0);
  const out = ratchetDecrypt(state, prekey.message);
  return {
    plaintext: out.plaintext,
    session: { ratchet: serializeState(out.state), baseKey: toB64(prekey.baseKey), pendingPreKey: null, remoteDhKey: toB64(prekey.senderDhKey) },
  };
}

export function withNewCurrent(record: SessionRecord | undefined, session: StoredSession): SessionRecord {
  const previous = record ? [record.current, ...record.previous].filter((s): s is StoredSession => s !== null) : [];
  return { current: session, previous: previous.slice(0, MAX_PREVIOUS_SESSIONS) };
}

function promote(record: SessionRecord, old: StoredSession, updated: StoredSession): SessionRecord {
  const rest = [record.current, ...record.previous].filter((s): s is StoredSession => s !== null && s !== old);
  return { current: updated, previous: rest.slice(0, MAX_PREVIOUS_SESSIONS) };
}
