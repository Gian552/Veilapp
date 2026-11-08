# VEIL Threat Model

**Assets:** message plaintext; private keys; the link between a VEIL identity and a real person (IP address,
device, payment, social graph); who talks to whom and when; the ability to abandon an identity.

**Assumptions:** user devices are not compromised while VEIL is unlocked; the user obtained an authentic client build
(see T11); the noble/hash-wasm primitives are correct; TLS terminates at the operator's reverse proxy.

Test references: `crypto:` = `packages/crypto/test`, `client:` = `packages/client/test`, `server:` = `apps/server/test`.

---

### T1. Complete database dump

* **Observes:** usernames; public identity, device and prekey keys; signed device lists (number of devices per account);
  Argon2id verifiers and client salts; encrypted recovery backups and profiles; session rows (account, device, coarse expiry
  day); undelivered envelopes per *recipient device* with per-device order and coarse expiry day; attachment blobs (sizes,
  remaining downloads); reset jobs (no account link); ledger HMAC tags; pending link requests (≤ 10 min).
* **Cannot observe:** message or attachment plaintext; private keys; passwords or anything that decrypts local vaults;
  **who sent any queued message**; contact lists; IP addresses; message or login timestamps; read state; delivered-message history.
* **Reduces exposure:** data minimisation (`docs/METADATA.md`); random ids; no timestamps (day-granular expiry only);
  sealed sender; delete-on-ack; two layers of Argon2id before any offline guess can be checked.
* **Limitations:** an offline dictionary attack on weak passwords is possible (cost: client Argon2id, 64 MiB by default and never below 19 MiB, plus server Argon2id
  per guess); the per-device mailbox order and size buckets of *undelivered* envelopes are visible; registered usernames are not in the dump's directory API, but anyone with the dump sees the `identity.accounts` table.
* **Tests:** `client: messaging › messages persist only encrypted…` (scans a full DB dump for plaintext and password);
  `server: leakage` (DB dump + logs contain no password, authKey, tokens, plaintext, IP); `server: migrations` (no time, IP or agent columns).

### T2. Compromised application server (live)

* **Observes (live):** everything in T1, plus the source IP of each connection, which account is authenticated on each request, which devices
  an authenticated sender submits envelopes to (so the sender→recipient pairing *at send time*), request timing and sizes,
  directory and bundle lookups, and the `authKey` sent at login (not the password).
* **Cannot:** decrypt messages, attachments, backups or vaults; forge messages from a user; add a device to an account;
  silently swap a contact's identity key; downgrade the client's password stretching below its floor.
* **Reduces exposure:** E2E encryption; AIK-signed device lists with rollback and fork rejection; key-change blocking;
  typed link codes that authenticate both the request and the approval; decrypt-first receiving; client-side Argon2 floor; the server is designed not to *persist* what it sees transiently.
* **Limitations:** a malicious server can drop or delay messages (denial of service), refuse service, track IPs live, perform
  TOFU substitution on a *first* contact until users compare safety numbers, and serve a malicious web client (T11).
* **Tests:** `client: malicious-server detection` (identity substitution → `key-changed` and sending blocked; injected unsigned device
  rejected); `client: multi-device` (typed link code; wrong code refused); `client: security-review` (forged approval rejected, forged sender names ignored, list forks and rolled-back restores refused); `client: downgrade protection`.

### T3. Malicious or curious administrator

Same capabilities as T1/T2 for someone with DB or host access. Additional mitigations: per-schema roles (`deploy/postgres/roles.sql`);
no request logging anywhere in the stack; `GET /healthz` reveals nothing; no admin endpoint to read user data (the only admin CLI
operations are `sweep` and `replay-deletions`). An admin can still change code (T2/T11).

### T4. Stolen user device

* **Locked (or powered off):** the attacker gets the IndexedDB ciphertext, the client salt and the Argon2 parameters. Unlocking requires the password;
  guessing costs one client Argon2id (64 MiB by default) per attempt offline. Record names are HMACs, so not even contact names leak. Tokens are never stored.
* **Unlocked:** full access to that device's messages and keys. Mitigations: auto-lock after 15 minutes idle; the user (from another primary
  device) removes the device, which revokes its sessions and drops it from the signed device list, so contacts stop encrypting to it. Panic Reset abandons the identity.
* **Limitations:** a device left unlocked is compromised; data the browser swapped to disk while unlocked may persist.
* **Tests:** `client: messaging › persist only encrypted` (storage dump has no plaintext, password or usernames);
  `client: a wrong password cannot unlock the local vault`; `client: a removed device loses access…`.

### T5. Compromised recipient device

The attacker reads everything that recipient can read: messages already delivered, including yours. Encryption cannot prevent this.
The Double Ratchet's post-compromise security limits *future* exposure once the attacker loses access and a DH ratchet step completes.
Safety numbers do not help against a compromised endpoint. **Limitation, stated in the UI.**
Tests: `crypto: forward secrecy…`, `crypto: replay…`.

### T6. Network observers (between client and server)

* **Observe:** that a client talks to the VEIL server, when, how often, and ciphertext sizes (256-byte padding buckets for content;
  attachment sizes in coarse AEAD-overhead form).
* **Cannot:** read content or tokens (TLS, HSTS); see usernames in URLs (credentials are never in URLs; directory lookups are
  path parameters protected by TLS).
* **Limitations:** VEIL does not hide that you use VEIL, nor timing. Users who need that should connect over Tor or a VPN.
  The server works behind Tor; nothing requires a stable IP.

### T7. Malicious hosting provider

Can image disks and RAM and observe traffic: effectively T1 + T2 + T6. Mitigations are the same; additionally, attachment blobs and DB
backups contain only ciphertext, and backups are encrypted with a key the provider does not hold (`deploy/backup.sh`).

### T8. Compromised third-party infrastructure (CDN, DDoS protection, monitoring)

VEIL ships with **no** CDN, analytics, error tracker or third-party font or script: the CSP is `default-src 'self'` and the web bundle makes no
external requests. If an operator adds a TLS-terminating CDN, that CDN becomes a T2-class observer of IPs and timing (still not content).
Documented in `docs/DEPLOYMENT.md`. Test: the web build is checked for external URLs and inline scripts (`apps/web` build check in the review).

### T9. Account enumeration and brute force

* **Enumeration:** `prelogin` returns a deterministic fake salt with identical parameters for unknown usernames; login failures share one
  generic response and run a dummy Argon2id; registration conflicts surface only as a rare race. **The directory does not reveal existence either:** every well-formed
  name resolves to a real account or an indistinguishable decoy (signed keys, accepted sends). Residual signals: decoys never reply,
  never add devices and never publish a profile; a name's keys change if it is later assigned; lookup timing may differ slightly
  (a decoy needs Ed25519 signing instead of a row fetch). Tests: `server: decoy`, `client: account existence is never revealed`.
* **Brute force:** per-address token buckets (in memory, HMAC'd addresses with a rotating in-memory key), per-username exponential
  back-off after failures, proof-of-work on registration, and per-account limits on bundle fetches, sends and uploads.
* **Tests:** `server: enumeration` (same shape and fake salt; identical error bodies); `server: rate limits`; `client: wrong password and
  unknown username produce the same generic error`.

### T10. Traffic correlation and timing analysis

Not solved by encryption. A global passive observer, or the server operator, can correlate when Alice sends and Bob receives.
Mitigations within scope: no persisted timestamps or delivery history; sealed sender (nothing about senders is stored); per-device (not global) mailbox
ordering; padding; delete-on-ack; no presence, typing or last-seen signals; read receipts off by default. Documented as a residual risk in the
Security screen. Cover traffic and mixnets are out of scope.

### T11. Malicious updates or compromised client builds

A web app is served by the same party you are trying not to trust. Mitigations: exact-pinned dependencies with a lockfile; few runtime
dependencies; no CDN; reproducible Vite build (content-hashed assets) so independent parties can compare published hashes; strict CSP
limits injection from other origins. **Residual risk:** a malicious operator can serve a malicious bundle to specific users.
Packaged clients (signed desktop or mobile builds with reproducible-build verification) are the real fix and are future work.

### T12. Legal requests

The operator can only disclose what exists: everything in T1 (no IPs, no timestamps, no sender of any queued message, no contact lists, no
message content), plus live observation going forward if compelled (T2). `GET /v1/account/export` shows users exactly what the server holds about them.

### T13. Partial failures during Panic Reset

Single-transaction server deletion; idempotent job id; encrypted local journal plus `reset-pending` flag; explicit `partial` and `failed`
states; blob deletions are retried by the sweeper; deletion is never claimed without server evidence.
Tests: `client: panic-reset` (network interruption, lost response, crash before wipe, blob failure → partial → sweep, unreachable plus wipe
anyway); `server: reset` (idempotency, partial, old tokens rejected, every table emptied).

### T14. Backup and replica retention

Backups hold only data schemas, are encrypted, and are retained ≤ 7 days (communicated to users). The deletion ledger (outside the backup set)
re-applies resets after a restore. Replicas receive the deletion through normal replication. Residual: loss of the `ops` schema together
with the database. Test: `server: backup-restore replay`.

### T15. Malicious or compromised communication partner

A partner can leak what you send them (no technical protection), send malformed content (all decrypted content is schema-validated;
unknown types are ignored; `sent`/`contact` sync messages are accepted only from your *own* devices), replay messages (rejected by
the ratchet and message-id dedupe), or flood you (server rate limits; MAX_SKIP bounds skipped-key memory). A partner sees your username,
your identity key and the number of your devices (from the signed device list), and, only if you opt in, your display name and read receipts.
Tests: `client: ignores a replayed envelope and survives a tampered one`; `crypto: MAX_SKIP`; `crypto: tamper`.

---

## Out of scope

Global passive adversaries; compromised operating systems or browsers; physical coercion; side channels in JavaScript engines;
quantum adversaries (no PQXDH yet).
