# Metadata Inventory and Retention

Principle: a field exists only if a feature cannot work without it. Fields that could be removed were removed,
not encrypted. This is the complete list of what the server stores (`apps/server/src/migrations.ts`).
The test `apps/server/test/schema.test.ts` fails if any column name suggests timestamps, IPs or user agents.

## Stored fields

| Table | Field | Why it must exist | What a dump reveals |
|---|---|---|---|
| `identity.accounts` | `id` (random UUID) | internal key; never returned by the API | nothing |
| | `username` | public address | the random two-word name |
| | `identity_key`, `device_list`, `device_list_sig`, `device_list_version` | contacts verify devices | public keys, **number of devices**, how many times the device list changed |
| | `profile` (nullable) | opt-in display name | ciphertext size only (server lacks the profile key) |
| `identity.retired_usernames` | `tag` = HMAC(server key, username) | never reissue a deleted name | that *some* name was retired, not which, without the server key |
| `auth.credentials` | `client_salt`, `kdf_*`, `verifier` (Argon2id of `authKey`) | sign-in | enables offline guessing, at two Argon2id costs per guess |
| `auth.recovery` | `verifier`, `backup` | optional recovery | that recovery is enabled; backup ciphertext size |
| `auth.sessions` | `id`, `account_id`, `device_id`, `kind`, `refresh_hash`, `prev_refresh_hash`, `generation`, `expires_day` | revocable sessions | number of active sessions; the **day** of the last sign-in (expiry − 30, or − 1 for link sessions); refresh count |
| `keys.devices` | `id`, `account_id`, `signing_key`, `dh_key`, `mailbox_seq` | routing, key directory | device→account link; total envelopes ever queued for the device |
| `keys.signed_prekeys` / `keys.one_time_prekeys` | public keys | X3DH | how many one-time prekeys remain, which roughly tracks new sessions started with the device |
| `keys.link_requests` | request, encrypted response, `expires_at` (seconds) | device linking | a link in progress (deleted within 10 minutes) |
| `mailbox.envelopes` | `device_id`, `envelope_id`, `seq`, `payload`, `expires_day` | store and forward | **undelivered** ciphertext per recipient device, its order and size bucket, and the day it was queued. **No sender.** Deleted on acknowledgement. |
| `media.attachments` | `id`, `delete_token_hash`, `remaining_downloads`, `size`, `expires_day` | encrypted attachments | blob sizes, number of intended recipient devices. **No owner, no sender, no recipient.** |
| `ops.reset_jobs` | `id`, `secret_hash`, state, counts, `expires_day` | idempotent Panic Reset | that a reset happened on a day; **not linked to any account** |
| `ops.pending_blob_deletions` | blob id, job id | retry failed deletions | transient |
| `ops.deletion_ledger` | HMAC(account id), HMAC(username), `expires_day` | re-apply resets after a backup restore | removed after the backup window |
| `ops.schema_migrations` | version | migrations | nothing |

## Existence of an account

The API never confirms or denies that a username exists: unassigned names are served deterministic decoys
(see ARCHITECTURE.md §2a). Only the database itself (T1) or the operator (T2) can tell real from decoy.

## Not stored anywhere

IP addresses; user agents; request or access logs; login history; message timestamps; sender of any message;
delivery or read history; contact lists; conversation lists; presence, last-seen or typing state; push tokens;
email or phone numbers; device fingerprints; analytics.

## Transient data (memory only, never persisted)

| Data | Purpose | Lifetime |
|---|---|---|
| `HMAC(rotating in-memory key, client IP)` | rate-limit buckets | rotates every 24 h; lost on restart |
| `HMAC(in-memory key, username)` | login back-off | minutes |
| used PoW challenges and login nonces | replay prevention | ≤ 5 minutes |
| WebSocket registry (session → socket) | "you have mail" pushes | connection lifetime |
| who is sending, during a send request | authorisation | one request |

The network stack, TLS terminator and kernel necessarily see client IPs while a connection is open. VEIL does not *store* them.
That is a weaker claim than "never processed", and it is the true one.

## Residual metadata

* **Server operator, live:** sender→recipient-device pairing at send time, IP and timing of every request, directory
  and prekey lookups (which reveal whom you are about to message). Not persisted, but observable by a compromised server.
* **Database dump:** the items in the table above, especially queued-message counts per device, device counts per account,
  remaining prekeys and session expiry days.
* **PostgreSQL internals:** transaction ids (`xmin`), WAL and dead tuples can reveal write ordering until vacuum and WAL recycling.
  Operators should enable regular `VACUUM` and avoid long WAL archiving. See DEPLOYMENT.md.
* **Network observers:** see THREAT_MODEL.md T6 and T10.

## Optional features that reveal metadata (all off by default)

| Feature | Reveals | To whom |
|---|---|---|
| Read receipts | when you read messages | the contact (E2E); the server sees an extra encrypted message |
| Display name | the name you choose | contacts you share the profile key with; the server stores only ciphertext |

Typing indicators, presence, last-seen and push notifications are not implemented.

## Retention

| Data | Retention |
|---|---|
| Undelivered envelopes | until acknowledged, at most 30 days |
| Attachment blobs | until every intended device downloaded them, at most 30 days |
| Device sessions / link sessions | 30 days / 1 day (absolute; no sliding renewal) |
| Link requests | 10 minutes |
| Reset jobs | 7 days |
| Deletion ledger | backup retention + 1 day (8 days) |
| Database backups | ≤ 7 days, encrypted, data schemas only |
| Retired-username tags | indefinitely (32-byte keyed hash, needed to prevent reuse) |

The sweeper enforces these hourly (`sweep()`, also `veil-admin sweep`).
