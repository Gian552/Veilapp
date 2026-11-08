# Internal Security Review

An independent reviewer (who did not write the code) examined `packages/crypto` and `packages/client` adversarially,
wrote exploit tests, and checked the documentation against the code. Every finding below has a test in
`packages/client/test/security-review.test.ts` or `packages/crypto/test/security-review.test.ts`. Each test failed on the reviewed
code and passes now. **This internal review is not a substitute for an external audit.**

## Findings and fixes

Reviewer's numbering. Its test file numbers these differently (that file's "FINDING n" labels in parentheses).

| # | Severity | Finding | Fix |
|---|---|---|---|
| 1 (test 2) | High | A malicious server could forge the device-linking approval: the provisioning payload was sealed to a key the server relays, and users only compared a hash of the request. | The new device shows a random 80-bit code that never leaves it; the request carries a commitment, and the approval is MACed under a key derived from the code. The user types the code on the primary. Both directions are now authenticated. |
| 2 (test 3) | High | The unauthenticated sender name in a sealed envelope (case variants included) could create contacts, or overwrite a pinned contact before anything was decrypted. This could reset verification or lift a key-change block. | Decrypt-first receiving: X3DH and decryption run before any lookup; the claimed sender must then match the directory exactly (name, identity key, certified device); existing contacts are never replaced; nothing is committed on failure. `startConversation` matches usernames case-insensitively. |
| 3 (test 1) | High | After `lock()` or Panic Reset, in-flight operations kept writing vault records under the zeroed key, so anyone could decrypt them, including old identity keys after a "verified" wipe. | `LocalVault` and `VaultCipher` refuse all use once closed. Writes in flight now fail instead of leaking. |
| 4 (test 6) | Medium | A recovery restore re-signed whatever device list the server served, which could re-certify a removed (stolen) device. Same-version list forks were accepted. | The backup records the newest confirmed list version (updated whenever it advances); a restore refuses older lists; same-version lists with different devices are rejected for contacts and for your own list. |
| 5 (test 4) | Medium | A transient lookup failure (for example a 429 induced by junk envelopes) dropped and acknowledged the message. | Only processed envelopes are acknowledged; transient errors leave the rest queued. Decrypt-first also means junk causes no lookups. |
| 6 (test 5) | Medium | A contact-chosen Lamport clock above 2^50 broke recovery backups and device linking. | Clocks in messages are capped at 2^40 and clamped in snapshots. |
| 7 (test 7) | Medium | Panic Reset was impossible from a password-only session, although the docs promised it. | Supported in the engine and the "Add this device" screen ("Delete this account"). |
| 8 (test 8) | Medium/Low | Deleting a conversation dropped its sessions, which silently black-holed the contact's next messages. | Deletion now clears history and hides the conversation but keeps the pinned key and sessions; it reappears on the next message. |
| 9 (test 9) | Low | After accepting a key change on one device, another device could stay stuck in `key-changed`. | An authenticated own-device `contact` sync now fully applies the accepted key and resets sessions. |
| 10 (test 10) | Low | Resuming a reset without local data reported `completed` without server evidence. | Reports `partial` and tells the user to confirm the deletion. |

Also fixed:
* The recovery key parser rejects trailing characters.
* The local vault is never re-wrapped with weaker server-chosen Argon2 parameters.
* HTTP requests time out (30 s; 120 s for uploads).
* Own-device contact syncs refresh a stale own device list first.
* Pending link secrets are wiped on lock.
* The Panic Reset report separates unconfirmed `problems` from inherent `notes`.
* Server shutdown is bounded (5 s).

## Remaining risks (accepted or future work)

| Risk | Status |
|---|---|
| No external audit of the protocol composition | **Required before high-risk use** |
| Web delivery: the server can serve a malicious client (THREAT_MODEL T11) | Packaged, reproducibly built clients are future work |
| First contact is TOFU; usernames are not bound into keys | Same as Signal; safety-number comparison is the mitigation |
| Live server sees sender→recipient-device pairing at send time, IPs and timing | Not persisted; inherent to an authenticated relay. Unidentified-delivery tokens would reduce it |
| After linking or a restore, the new device looks up all contacts at once (reveals the contact list to a live server); `?downloads=N` reveals device counts | Low; batching and cover lookups are future work |
| JavaScript cannot guarantee zeroisation; some error paths do not wipe derived keys | Low; documented in CRYPTOGRAPHY.md |
| No rollback protection for local records (a restored session snapshot could reuse a message key) | Info; do not restore browser data from backups |
| Rate limits are in memory per instance | Documented in DEPLOYMENT.md |
| `PUT /v1/recovery` is accepted from any enrolled device (the client restricts it to primaries) | Low |
| Retrying pending blob deletions via `/v1/reset/status` is not rate limited | Low |
| The full Docker Compose stack (Postgres + app + Caddy with TLS) was not run end to end; the image itself was built and smoke-tested, and the Postgres role setup and real-Postgres tests pass | Verify on first deployment |
| No group messaging, no post-quantum key agreement | Out of scope (MLS, PQXDH are the right bases) |
