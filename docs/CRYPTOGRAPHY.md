# VEIL Cryptography

All cryptography lives in `packages/crypto` (≈1,000 lines). It uses only the published, independently audited
primitives of `@noble/curves`, `@noble/hashes` and `@noble/ciphers`, plus `hash-wasm` for client-side Argon2id.
VEIL implements published protocols (X3DH, Double Ratchet) and standard constructions (HKDF domain separation,
ECIES-style sealed boxes). It does not define new primitives.

> **Status.** The protocol *composition* in this repository has not been independently audited. The primitives have been.
> Treat this as pre-production until a third-party audit of `packages/crypto` and `packages/client` is done.

## Primitives

| Purpose | Algorithm | Source | Known-answer test |
|---|---|---|---|
| Key agreement | X25519 | RFC 7748 | RFC 7748 §6.1 (`vectors.test.ts`) |
| Signatures | Ed25519, strict verification (`zip215: false`) | RFC 8032 | RFC 8032 §7.1 TEST 1 |
| KDF | HKDF-SHA-256 | RFC 5869 | RFC 5869 A.1 |
| AEAD | XChaCha20-Poly1305 (192-bit nonce) | draft-irtf-cfrg-xchacha-03 | A.3.1 |
| Password hashing | Argon2id v1.3 | RFC 9106 | RFC 9106 §5.3 (via `@noble/hashes`), cross-checked against `hash-wasm` |
| Fingerprints | SHA-512 iterated (Signal NumericFingerprint v1 construction) | Signal | symmetry/change tests |

Every signature is computed over `context ‖ 0x00 ‖ message` with a distinct context string per purpose
(`VEIL/v1/device-list`, `VEIL/v1/signed-prekey`, `VEIL/v1/device-login`), so a signature can never be
replayed for a different purpose. Every HKDF call uses a distinct, versioned `info` label. Everything that is signed or
used as associated data is serialised with a deterministic length-prefixed encoding (`encoding.ts`). Decoders reject trailing
bytes, and device lists must be canonical.

## Key hierarchy

```
password ──Argon2id(clientSalt, server-recommended 64 MiB/t=3/p=4, client floor 19 MiB/t=2)──► master
  master ─HKDF "VEIL/v1/auth-key"────────► authKey ──► server ──Argon2id(random salt, 19 MiB, t=2)──► verifier
  master ─HKDF "VEIL/v1/local-vault-kek"─► vaultKek ──wraps──► vault DEK (random) ──HKDF──► record key, index key

recovery secret (240 bits, shown once)
  ─HKDF "VEIL/v1/recovery-auth"───► recoveryAuthKey ──► server Argon2id verifier
  ─HKDF "VEIL/v1/recovery-backup"─► backupKey ──encrypts──► {AIK private key, profile key, contacts}

Account Identity Key (Ed25519, primary devices + encrypted recovery backup only)
  └─signs─► Device list {version, [deviceId, Ed25519 signing key, X25519 identity key, primary flag]}
               └─ device signing key ─signs─► Signed prekey (X25519, rotated weekly)
                                              One-time prekeys (X25519, unsigned, as in Signal)
```

Properties:

* **Password ≠ encryption key.** The server sees only `authKey`. It cannot derive `vaultKek` or the backup key from it.
* **Server-side reset cannot open data.** The server never holds a key that decrypts the vault, messages or the recovery backup.
  A forgotten-password reset requires the recovery key, and that key also decrypts the identity backup.
* **Client downgrade protection.** The client refuses Argon2 parameters below a hard-coded floor
  (`CLIENT_ARGON2_MINIMUM`, 19 MiB / t=2), so a malicious server cannot weaken the stretch that protects `authKey`. The parameters
  themselves come from the server (default 64 MiB / t=3 / p=4). The local vault is never re-wrapped with weaker parameters than it already has.

## X3DH

Implemented per the Signal X3DH specification (`x3dh.ts`), using X25519, SHA-256, and `info = "VEIL_X3DH_v1"`.

Deviations, all of which keep the security argument intact:

1. **Identity key split.** Signal uses one X25519 identity key and XEdDSA to sign with it. VEIL uses a per-device X25519
   identity key `IK`, certified by the account's Ed25519 key through the signed device list. The signed prekey is signed by the device's
   Ed25519 key. This avoids implementing XEdDSA while keeping the same binding: the responder's `IK` and `SPK` are
   authenticated by the account identity the user verifies.
2. **AD extension.** `AD = "VEIL-X3DH-AD" ‖ AIK_A ‖ deviceId_A ‖ IK_A ‖ AIK_B ‖ deviceId_B ‖ IK_B`. The spec explicitly allows
   additional data in AD.
3. **Initial message.** Until the initiator receives a reply, every message carries the X3DH header (identity key, base key,
   prekey ids), as Signal does. The responder accepts it only if `IK_A` matches the sender's device in the sender's
   AIK-signed device list.

One-time prekeys are consumed atomically on the server (`DELETE … RETURNING` with `SKIP LOCKED`). The private half is deleted
on first use. If none are available the handshake proceeds without DH4, as the spec allows. Each responder remembers the base keys of
sessions it accepted (bounded list), so a replayed initial message is rejected even when no one-time prekey was used.

## Double Ratchet

Implemented per the Signal Double Ratchet specification, rev. 1, §3 (`ratchet.ts`):

* `KDF_RK`: HKDF-SHA-256 with `salt = RK`, `ikm = DH output`, 64 bytes split into the new RK and CK.
* `KDF_CK`: `MK = HMAC(CK, 0x01)`, `CK' = HMAC(CK, 0x02)`.
* `ENCRYPT`: `HKDF(MK, info "VEIL_DR_MSG_v1")` yields a 32-byte key and a 24-byte nonce for XChaCha20-Poly1305. Because every MK is used
  exactly once, a derived nonce is safe. The associated data is `AD ‖ encoded header`. This assumes ratchet state is never rolled back:
  restoring an old copy of a session record (for example from a disk snapshot) and sending again would reuse a key/nonce pair. Local
  records have no rollback protection, so do not restore VEIL browser data from backups.
* `MAX_SKIP = 1000` per chain and at most 2,000 stored skipped keys (oldest evicted).
* **Transactional decryption.** `ratchetDecrypt` works on a copy and returns the successor state. A failed decryption
  (tampering, wrong session, replay) leaves the stored state untouched, as the specification requires.
* **No header encryption.** Ratchet public keys and counters are visible inside the sealed envelope to the recipient device only.
  They are not visible to the server, because the whole ratchet message sits inside the sealed sender layer.

**Properties provided (and tested in `ratchet.test.ts`):** confidentiality and integrity per message; forward secrecy (a
snapshot of the current state cannot decrypt earlier messages); post-compromise security after a DH ratchet round trip
(a property of the Double Ratchet); replay rejection; out-of-order delivery across ratchet steps.

**Not provided:** post-quantum security (X3DH, not PQXDH); deniability guarantees beyond those of X3DH; protection of
messages on an endpoint that is already compromised.

## Sealed sender envelope

`sealed.ts`: an ECIES-style sealed box built from an ephemeral X25519 key, HKDF-SHA-256 (with salt `eph_pub ‖ recipient_pub`) and
XChaCha20-Poly1305. The associated data is the recipient device id. It carries `{senderUsername, senderDeviceId, inner}`, where `inner` is a
ratchet or prekey message. The construction resembles libsodium's `crypto_box_seal` and the outer layer of Signal's sealed sender.
The sealed box does **not** authenticate the sender. Authenticity comes from the inner layer: a ratchet message only decrypts under the
session established with that sender's certified device.

## Multi-device

* Every device has its own keys and its own pairwise sessions. Messages are fanned out per device, and the sender's own other devices receive
  a `sent` transcript.
* **Device linking** (`link.ts`). The new device (password-authenticated *link* session) generates a random **80-bit link code** C,
  which it displays and never sends. It uploads `{deviceId, signing key, DH key, ephemeral provisioning key}` plus a commitment
  `HMAC(HKDF(C), request)`. The user **types C on the primary device**, which checks the commitment, so a request substituted by the
  server does not match. The primary then signs a new device list, seals a provisioning payload (contacts, profile key, settings,
  signed list) to the provisioning key with the request as AD, and appends `HMAC(HKDF(C), request ‖ sealed)`. The new device verifies
  that MAC before opening anything, so the server cannot forge an approval even though it relayed the provisioning key.
  Forging either direction needs C (online guessing against 2^80). An earlier design that only compared a hash of the request was
  vulnerable to a forged approval; the internal review found this (SECURITY_REVIEW.md, finding 1).
* **Only primary devices hold the AIK**, so only they can add or remove devices. Removal is a new signed list without the device.
  The server deletes the device's sessions, prekeys and mailbox.
* **Contacts' devices** are accepted only if they appear in a device list signed by the contact's pinned AIK. Lists with a lower version
  are rejected, and so are lists with the *same* version but different devices (a fork). The recovery backup records the newest
  confirmed version of your own list, and a restore refuses a server-supplied list older than that (otherwise a removed device
  could be re-certified).

## Verification and key changes

* The safety number is 60 digits: two halves of six 5-digit groups, one per party, using the Signal NumericFingerprint construction over the
  AIK and username with 5,200 iterations of SHA-512. It is symmetric, and users compare it out of band.
* First contact is trust-on-first-use (TOFU), as in Signal: whether you start the conversation, receive a first message, or learn of the
  contact from your own device's `sent` transcript, the key comes from the directory. Contacts vouched for by one of your own devices
  via an E2E `contact` sync (sent when you start a conversation, verify or accept a key) are pinned from that device instead.
  Usernames are not bound into the keys: on first contact a malicious server could map a username to someone else's identity.
  Only comparing safety numbers detects this.
* A different AIK from the directory or in a prekey message is **never applied automatically** on the device that sees it. The
  conversation is marked `key-changed`, a notice is shown, the verified mark is cleared and sending is blocked until the user accepts
  the new key. Two deliberate exceptions: (1) when you accept a key on one of your devices, that device's authenticated `contact` sync
  applies it on your other devices; (2) while a change is pending, incoming messages under the new key are shown (as in Signal),
  but nothing is sent until you accept.
* **Receiving is decrypt-first.** The sender name inside a sealed envelope is unauthenticated until the inner message decrypts. The client
  therefore runs X3DH and decrypts *before* any directory lookup, and checks the claimed sender only afterwards (exact username, identity
  key and certified device). A failed check commits nothing. Junk or forged envelopes cause no lookups, no contacts and no state changes.
  A device the server injects without a valid AIK signature is rejected (`messaging.test.ts › malicious-server detection`).

## Attachments

Each attachment uses a fresh 32-byte key with XChaCha20-Poly1305. The key and the SHA-256 digest of the ciphertext travel inside the E2E message, and the digest is checked before
decryption. The server stores only the opaque blob, with a download budget and a 30-day expiry and no owner. Maximum size is 10 MiB.

## Local storage

The IndexedDB vault holds only ciphertext. Records are encrypted under a random DEK (XChaCha20-Poly1305), with the record's HMAC'd name
bound as AD so records cannot be swapped. The DEK is wrapped by `vaultKek`. Plaintext metadata holds only a `reset-pending` flag, the wrapped DEK, the client salt
and the Argon2 parameters. Access and refresh tokens are kept in memory only, never in storage.

**Residual risks, honestly stated.** JavaScript cannot guarantee that secrets are erased from memory: the GC may copy buffers, and strings are
immutable. `wipe()` reduces exposure; it is not a guarantee. A browser profile or disk image taken while VEIL is unlocked can contain keys.
Flash storage may physically retain deleted IndexedDB pages; destroying the wrapped DEK is what makes those remnants undecryptable,
*unless the attacker also learns the password and recovers the old wrapped-DEK page*.

## Padding

Plaintext content is padded with ISO/IEC 7816-4 padding to a multiple of 256 bytes before encryption, so ciphertext size reveals only a coarse bucket.

## Known limitations and future work

* No independent audit yet.
* No post-quantum key agreement (PQXDH) yet.
* No header encryption. Its benefit is limited here, because headers are already inside the sealed envelope.
* Web delivery: the server that serves the JavaScript could serve a malicious client. See THREAT_MODEL.md T11. Mitigations are reproducible
  builds, published hashes, and installing as a packaged app in the future.
* Group messaging is out of scope (1:1 only). MLS (RFC 9420) would be the right basis.
