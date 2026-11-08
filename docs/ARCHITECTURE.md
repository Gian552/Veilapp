# VEIL Architecture

VEIL is a privacy-first, end-to-end encrypted messenger built on one rule:

> Collect as little as possible, and make whatever is collected worth as little as possible to an attacker.

This document is the authoritative design. `docs/CRYPTOGRAPHY.md`, `docs/THREAT_MODEL.md`,
`docs/METADATA.md`, `docs/PANIC_RESET.md` and `docs/DEPLOYMENT.md` go deeper on individual topics.

## 1. Repository layout and stack

| Path | Package | Role |
|---|---|---|
| `packages/crypto` | `@veil/crypto` | All cryptography. Pure TypeScript on audited primitives (`@noble/curves`, `@noble/hashes`, `@noble/ciphers`) plus `hash-wasm` Argon2id. **The audit target.** |
| `packages/shared` | `@veil/shared` | API contract (zod schemas, strict), username word lists. |
| `packages/client` | `@veil/client` | Headless client engine: vault, sessions, X3DH/ratchet session management, fan-out, sync, linking, recovery, Panic Reset orchestration. Runs in browsers and Node (integration tests). |
| `apps/server` | `@veil/server` | Fastify 5 HTTP + WebSocket server, PostgreSQL (PGlite in tests/dev). |
| `apps/web` | `@veil/web` | React 19 + Vite single-page app. No third-party network resources. |
| `deploy/` | | Caddy reverse proxy (access logging off), Docker Compose, Postgres role hardening, backup scripts. |

Why this stack: one language for client and server gives one auditable crypto implementation;
`@noble/*` are widely used and independently audited, dependency-free libraries;
Fastify has a small dependency tree, built-in schema-friendly design and a logger that can be fully disabled;
PostgreSQL gives transactional deletes (Panic Reset is a single transaction), constraints and per-schema permissions.
No native dependencies except `@node-rs/argon2` (prebuilt, server only), which keeps builds reproducible (`package-lock.json`, exact versions).

## 2. Identities and keys

| Item | Where generated | Where stored | Server sees |
|---|---|---|---|
| Internal account id (UUIDv4, CSPRNG) | server | `identity.accounts.id` | yes (never returned by the API) |
| Username, two random words (`VelvetFalcon`) | server, CSPRNG | `identity.accounts.username` | yes (public address) |
| Account Identity Key (AIK), Ed25519 | primary device | primary device vault, optional recovery backup (encrypted) | public key only |
| Device keys: id (16 B), Ed25519 signing, X25519 DH identity | each device | device vault | public keys |
| Signed prekey (X25519) and one-time prekeys | each device | device vault | public keys |
| Ratchet sessions, contacts, messages | each device | device vault | nothing |
| Profile key (random 32 B) | primary | vault, shared with contacts in E2E messages if the user opts in | nothing |

Usernames are generated server-side by choosing an adjective and a noun uniformly at random (`crypto.randomInt`).
The client receives a signed, short-lived *reservation* and may re-roll. On registration the unique constraint
decides collisions. On a race the client gets `409` and re-rolls. Usernames of deleted accounts are retired
(keyed hash in `identity.retired_usernames`) and never reissued, so nobody can take over an abandoned address.

**Account existence is never revealed (§2a).** For every well-formed username (two words from the public lists) the
directory, the prekey-bundle endpoint and the send endpoint behave identically whether or not an account exists. Unassigned
and retired names are answered with a deterministic *decoy*: an identity key, a signed one-device list and a signed prekey
derived from the server secret (`apps/server/src/decoy.ts`). Decoy device ids carry a MAC tag, and envelopes sent to them are
accepted and discarded. The client checks only the name format, locally. The UI says "If this person exists, they will receive
your messages."

**Trust anchor.** Contacts verify the AIK (60-digit safety number, Signal NumericFingerprint construction).
The AIK signs the **device list** `{version, devices[]}`. Only *primary* devices hold the AIK private key, so neither the server nor
a password-only attacker can add a device: clients reject any device not in a list signed by the pinned AIK and
reject list version rollbacks and same-version forks. New devices are linked by typing an 80-bit code from the new device into a primary device; the code authenticates both the request and the approval (CRYPTOGRAPHY.md).

## 3. Authentication (separate from encryption keys)

```
password ─Argon2id(clientSalt, m=64MiB,t=3,p=4)─► master
master ─HKDF("VEIL/v1/auth-key")──────► authKey   ──► server: Argon2id(authKey, random server salt) = verifier
master ─HKDF("VEIL/v1/local-vault-kek")► vaultKek  (never leaves the device; wraps the local vault DEK)
```

* The password never leaves the device. The server stores a PHC Argon2id verifier (`@node-rs/argon2`, m=19 MiB, t=2, p=1,
  the OWASP baseline, measured at ~30–60 ms per hash on commodity hardware) of `authKey`, with its own random salt.
* A full DB dump gives an attacker the client salt and the verifier, so an offline guess costs client Argon2id plus server Argon2id per candidate.
* `prelogin` returns `{clientSalt, kdf, nonce}`. For unknown usernames it returns a deterministic fake salt
  (`HMAC(serverKey, username)`) and default params, so responses do not reveal account existence. `login` failures
  are generic and run a dummy Argon2id verification to equalise timing.
* **Device sessions** require proof of possession: the device signs `deviceLoginMessage(nonce, username)` with its Ed25519 key.
  A password alone yields only a **link session**, which can request linking, restore from a recovery key, read the
  (encrypted) recovery backup, or start a Panic Reset. It cannot read any mailbox or change devices.
* Tokens: access token `va1.<b64(sessionId‖generation‖exp)>.<HMAC>` (10 min, verified statelessly + session row
  existence check, so revocation is immediate). Refresh token `vr1.<sessionId>.<random>`, stored as SHA-256, rotated
  on every use; presenting the previous refresh token revokes the session (theft detection). Device sessions have an
  absolute lifetime of 30 days, password-only link sessions 1 day, stored as a coarse day number. One session per device:
  a new device login replaces the old one.
* Usernames are matched case-insensitively (unique index on `lower(username)`); responses use the canonical form.
* The server Argon2id-hashes the base64url text of `authKey` (`@node-rs/argon2` accepts only UTF-8 input). This is lossless.
* Tokens are held **in memory only** on the client. Every app start requires the password (the vault must be unlocked anyway).
* Password change re-wraps the local vault, rotates the verifier and revokes all other sessions.
* Recovery: an optional 240-bit recovery key (Crockford base32, 13×4 chars incl. checksum) derives
  `recoveryAuthKey` (server keeps an Argon2id verifier) and `backupKey` (encrypts the identity backup: AIK, profile key, contacts).
  A forgotten password can be reset **only** with the recovery key. Without it, the account can be signed into
  with the password, but the identity can be recovered only from a still-enrolled primary device. **Losing every primary device
  and the recovery key makes the identity and all history unrecoverable. This is by design.**

## 4. Messaging protocol

* **X3DH** (Signal spec) for session setup, **Double Ratchet** (Signal spec, rev. 1) for messages: forward secrecy
  and post-compromise security for 1:1 device-to-device sessions, as provided by that protocol. No header encryption.
* **Multi-device by client fan-out**: a message is encrypted separately for every device of the recipient
  (from their verified device list) and for every *other* device of the sender (as a `sent` transcript).
* **Sealed sender**: each per-device ciphertext is wrapped in a sealed box to the recipient device's X25519 identity
  key containing `{senderUsername, senderDeviceId, inner}`. The server stores `(recipientDeviceId, envelopeId, blob)`
  and **never stores who sent a message**. The sending request is authenticated, so the server knows the sender
  transiently while handling it. That fact is neither logged nor persisted.
* **Ordering**: no timestamps. Every content message carries a random 128-bit id and a per-conversation **Lamport clock**
  (`clock = max(seen) + 1`). Display order is `(clock, senderDeviceId, id)`, a total order consistent with
  causality across concurrent devices. Duplicate ids are dropped client-side; the server deduplicates retries
  by `(deviceId, envelopeId)` (client-generated random id, idempotent `INSERT ... ON CONFLICT DO NOTHING`).
  The server mailbox is ordered by a **per-device** counter (`keys.devices.mailbox_seq`), not a global sequence,
  and rows are deleted on acknowledgement.
* **Replay protection**: ratchet message keys are deleted after use, so replays fail to decrypt. Prekey-message base keys
  are remembered per signed prekey. One-time prekey private keys are deleted after first use.
* **Attachments**: encrypted client-side with a random key (XChaCha20-Poly1305), uploaded as an opaque blob with a
  download budget equal to the number of target devices. Key, SHA-256 digest, name and type travel inside the E2E message.
  Blobs are deleted when the budget is exhausted or after 30 days. Blobs have **no owner column**. The uploader keeps a delete token.
* **Key changes**: an AIK change marks the conversation `key-changed`, blocks sending until the user explicitly accepts,
  and resets verification. Device additions/removals in a contact's signed list produce visible notices.

## 5. Server data model (PostgreSQL)

Schemas separate concerns and permissions: `identity`, `auth`, `keys`, `mailbox`, `media`, `ops`.
No table has `created_at`/`updated_at`/IP/user-agent columns. Ids are random. Expiry uses coarse **day numbers**
(`floor(unix/86400)`), except link requests (10-minute lifetime, seconds, deleted on completion).

```
identity.accounts(id uuid pk, username text unique, identity_key bytea, device_list bytea, device_list_sig bytea,
                  device_list_version bigint, profile bytea null)
identity.retired_usernames(tag bytea pk)                                -- HMAC(serverKey, username)
auth.credentials(account_id pk→accounts cascade, client_salt bytea, kdf_memory int, kdf_iterations int,
                 kdf_parallelism int, verifier text)
auth.recovery(account_id pk→accounts cascade, verifier text, backup bytea)
auth.sessions(id bytea pk, account_id→accounts cascade, device_id→keys.devices cascade null,
              kind text, refresh_hash bytea unique, prev_refresh_hash bytea null, generation int, expires_day int)
keys.devices(id bytea pk, account_id→accounts cascade, signing_key bytea, dh_key bytea, mailbox_seq bigint)
keys.signed_prekeys(device_id pk→devices cascade, key_id bigint, public_key bytea, signature bytea)
keys.one_time_prekeys(device_id→devices cascade, key_id bigint, public_key bytea, pk(device_id,key_id))
keys.link_requests(id bytea pk, account_id→accounts cascade, session_id bytea, request bytea, response bytea null, expires_at bigint)
mailbox.envelopes(device_id→devices cascade, envelope_id bytea, seq bigint, payload bytea, expires_day int,
                  pk(device_id, envelope_id), unique(device_id, seq))
media.attachments(id bytea pk, delete_token_hash bytea, remaining_downloads int, size int, expires_day int)
ops.reset_jobs(id bytea pk, secret_hash bytea, state text, deleted int, pending int, not_found int, expires_day int)
ops.pending_blob_deletions(blob_id bytea pk, job_id bytea null)
ops.deletion_ledger(account_tag bytea pk, username_tag bytea, expires_day int)
ops.schema_migrations(version int pk)
```

What a full dump reveals is analysed in `docs/METADATA.md`.

## 6. Panic Reset

Client state machine (journal stored encrypted in the vault, plus a non-secret `reset-pending` flag in `meta`):

1. **initiated**: user typed the confirmation phrase. Client writes the journal `{jobId, jobSecret, attachment delete tokens, old identity fingerprints}`.
2. **server-deleting**: `POST /v1/reset {jobId, jobSecret, attachments}` (retried with backoff; idempotent by `jobId`).
   In **one transaction** the server: deletes the attachments named by valid delete tokens (queuing blob deletion),
   writes a deletion-ledger entry and retired-username tag, deletes the account row (cascading to credentials, recovery,
   sessions, devices, prekeys, signed prekeys, mailboxes, link requests, profile) and records the job.
   After commit it closes all WebSockets of the old sessions and deletes blobs. Failures stay in `ops.pending_blob_deletions`,
   the job reports `partial`, and a sweeper retries. `POST /v1/reset/status {jobId, jobSecret}` reports progress (and retries).
3. **server-deleted**: server confirmed `accountRecordsDeleted: true`.
4. **local-wiped**: the client destroys the IndexedDB database (vault DEK first, then everything), clears in-memory keys.
5. **new-identity** (optional, or later): ordinary registration with a fresh reservation, fresh keys, fresh salt,
   fresh recovery key. The client verifies the new username, AIK and device ids differ from the old ones.
6. **completed**, or **partial**/**failed** with the specific unconfirmed items listed.

If the server is unreachable the user may choose "wipe this device anyway". The UI then states that server data
still exists and can be deleted later by signing in with the password from any device (a link session may reset).

Contacts are **not** notified. Notifying them would link old and new identity. Because the directory never reveals
whether an account exists (§2a), the retired username now resolves to a decoy, so contacts see a safety-number change
("they may have reset or deleted their account") and cannot send until they review it. Copies of messages already delivered to
contacts stay on their devices. The server cannot identify messages the user sent that still sit in contacts'
mailboxes (sealed sender), so those are delivered or expire within 30 days.

Backups: DB backups (data schemas only: `identity auth keys mailbox media`) are retained ≤ 7 days. The `ops` schema is
not restored from backup. After any restore, `veil-admin replay-deletions` re-applies every ledger entry
(accounts whose HMAC tag is in the ledger are deleted again, usernames re-retired). Ledger rows expire after the backup window.

## 7. Server hardening

* Fastify `logger: false` plus a custom minimal error logger: error code and route template only. Never bodies, headers, IPs, URLs with params, or tokens.
* `trustProxy` only if `VEIL_TRUST_PROXY=true`. Client addresses are used **only** for in-memory rate-limit buckets, keyed by
  `HMAC(ephemeralKey, ip)` with a key that exists only in memory and rotates every 24 h.
* Rate limits (in-memory token buckets): per address tag for all routes; stricter for auth; per username tag with
  exponential back-off for login failures; per account for bundle fetches, sends and uploads; proof-of-work for registration.
* Strict zod validation (unknown fields rejected), body size limits, generic error messages, `Cache-Control: no-store`.
* Security headers on everything; strict CSP for the SPA (`default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; …; frame-ancestors 'none'`).
* `GET /healthz` returns `{ok:true}` only.
* Sweeper (hourly): expired envelopes, attachments, sessions, link requests, reset jobs, ledger rows, pending blob deletions.

## 8. Configuration

| Variable | Default | Meaning |
|---|---|---|
| `VEIL_SERVER_SECRET` | required in production | ≥32 random bytes (base64url). All server MAC keys are HKDF-derived from it with distinct labels. |
| `DATABASE_URL` | unset → embedded PGlite in `VEIL_DATA_DIR/pg` | PostgreSQL connection string. |
| `VEIL_DATA_DIR` | `./.veil-data` | Attachment blobs (and PGlite data in dev). |
| `HOST` / `PORT` | `127.0.0.1` / `8787` | Listen address. |
| `VEIL_TRUST_PROXY` | `false` | Use `X-Forwarded-For` from the reverse proxy for transient rate limiting only. |
| `VEIL_POW_DIFFICULTY` | `18` | Leading zero bits required for registration. |
| `VEIL_WEB_DIST` | `apps/web/dist` if present | Serve the built SPA with security headers. |
| `VEIL_BACKUP_RETENTION_DAYS` | `7` | Communicated to users and used for ledger expiry. |
| `VEIL_MIGRATION_DATABASE_URL` | `DATABASE_URL` | Schema-owner connection used only for migrations, so the app can run as the DML-only `veil_app` role. |
| `VEIL_RATE_LIMIT` | enabled | `off` disables rate limiting for local development; refused when `NODE_ENV=production`. |
