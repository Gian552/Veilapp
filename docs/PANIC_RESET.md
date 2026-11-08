# Panic Reset

Panic Reset abandons an identity: it deletes the account on the server, destroys the keys and data on the device,
and optionally creates a new, unrelated identity. This document defines exactly what it does, what it cannot do,
and how it behaves when things fail.

## What it guarantees (when the report says `completed`)

| Item | Result | Evidence the client waits for |
|---|---|---|
| Account row, username, identity key, device list, profile | deleted | `accountRecordsDeleted: true` (one committed DB transaction) |
| Password verifier, recovery verifier, encrypted recovery backup | deleted | same transaction (FK cascade) |
| All sessions, access and refresh tokens of every device | invalid immediately | session rows deleted in the same transaction; open WebSockets are closed |
| All devices, signed and one-time prekeys, pending link requests | deleted | same transaction |
| Messages queued *for* this account (all its devices' mailboxes) | deleted | same transaction |
| Attachments this device uploaded (and still has delete tokens for) | deleted | `attachmentsDeleted`, `attachmentsPending == 0` |
| Old username | retired forever (keyed hash), never reissued | `identity.retired_usernames` |
| Local vault on this device | destroyed (wrapped DEK first, then the database) | storage reports zero remaining keys |
| New identity (optional) | fresh username, salt, AIK, device keys, prekeys, recovery key | client compares username, AIK and device ids with the old ones |

## What it cannot do (shown to the user before confirming)

* **Messages already delivered to contacts stay on their devices.** Their plaintext copies, screenshots and exports are outside
  VEIL's control. Contacts are not notified, because notifying them would link the old and new identities. Because VEIL never
  reveals whether an account exists, your old username now resolves to a decoy: contacts see a safety-number change the next
  time they refresh your keys, and VEIL blocks sending until they review it. Anything they send anyway goes nowhere.
* **Messages you sent that are still queued for recipients** cannot be identified. The server never stored who sent a message
  (sealed sender), so they are delivered or expire after `undeliveredMessageDays` (30).
* **Other devices of yours that are offline** keep their local encrypted vault until they next start. Their sessions are revoked, so they
  can no longer sign in and the user can erase them ("Can't sign in on this device?" → Erase). A stolen, never-reconnected device
  keeps its (password-encrypted) vault.
* **Database backups** taken before the reset still contain the account for up to `backupDays` (7). The deletion ledger
  re-applies the deletion if a backup is ever restored (see below).
* **Attachments** uploaded by other devices of yours, or whose delete token was lost, expire after `attachmentDays` (30) or once
  every recipient has downloaded them.
* **Network-level observers and the server operator at that moment** can correlate the reset request with a subsequent
  registration from the same connection. The user can create the new identity later, from another network.
* Destroying keys does not erase plaintext someone already decrypted.

## Workflow and states

```
initiated ──► server-deleting ──► server-deleted ──► local-wiped ──► [new-identity] ──► completed
     │               │                                                      │
     │               └─(unreachable, user chose "wipe anyway")─► local-wiped ─► partial
     │               └─(unreachable / refused)──────────────────────────────► failed (nothing deleted)
     └─ crash at any point: `reset-pending` flag + encrypted journal ──► resumeReset(password)
```

1. **initiated.** The user reads the consequences and types `RESET`. The client writes an encrypted journal to the vault
   (`jobId`, random `jobSecret`, attachment delete tokens, fingerprints of the old identity) and a non-secret
   `reset-pending` flag. From here on, every restart offers to resume.
2. **server-deleting.** The client sends `POST /v1/reset {jobId, jobSecret, attachments}`, retried with back-off.
   * The server runs **one transaction**: it validates the attachment delete tokens, writes the ledger entry and the retired-username tag, deletes the
     account row (cascading to every dependent table) and records the job with `sha256(jobSecret)`.
   * After commit it closes all WebSockets of the old sessions and deletes the attachment blobs. Failures go to
     `ops.pending_blob_deletions`, the job state becomes `partial`, and the hourly sweeper retries.
   * **Idempotent:** a retry with the same `jobId` returns the existing job's status and needs no session, only the secret.
     A lost response is therefore harmless (tested).
3. **server-deleted.** The server confirmed the transaction.
4. **local-wiped.** Tokens are dropped, the vault is closed and keys zeroised, and `storage.destroy()` clears both object stores
   (wrapped DEK included) and deletes the IndexedDB database. The client then verifies that nothing is left.
5. **new-identity** (optional). A normal registration with entirely fresh material. The client checks it is distinct.
6. **completed** only if the server reports `completed` (no pending blobs) **and** the local wipe was verified.
   Anything less is `partial`, with each unconfirmed item listed verbatim in `problems[]`.

The UI never shows "deleted" for a step that has no evidence.

## Failure handling (all covered by `packages/client/test/panic-reset.test.ts` and `apps/server/test/reset.test.ts`)

| Failure | Behaviour |
|---|---|
| Network down before the request reaches the server | `failed`, nothing deleted, journal kept; `resumeReset` later completes it |
| Response lost after the server committed | retry hits the same `jobId`: one job, status returned |
| App crash after server deletion, before local wipe | next start shows `reset-pending`; `resumeReset(password)` confirms via `/v1/reset/status` and wipes |
| Blob store failure | job `partial`, `attachmentsPending > 0`, reported; the sweeper finishes later |
| Server unreachable and the user needs the device clean now | optional "wipe anyway": device wiped, report says **server data still exists** and how to delete it later (sign in with the password from any device; a password-only session may run Panic Reset) |
| Old session or refresh token used after reset | rejected: session rows are gone |

## Backups and restore

* Backups (`deploy/backup.sh`) dump only the data schemas `identity auth keys mailbox media`, are encrypted, and are kept ≤ 7 days.
* `ops.deletion_ledger` stores `HMAC(serverKey, accountId)` and the retired-username tag for every reset, for the backup window plus one day.
  The `ops` schema is **never restored from a backup**.
* After any restore, run `veil-admin replay-deletions`. It deletes every restored account whose tag is in the ledger and re-retires the usernames.
* Residual risk: if the live `ops` schema is lost *together with* the database, accounts reset within the last 7 days could reappear
  from a backup. Operators must back up `ops` separately or keep it replicated.

## Who can trigger it

Any authenticated session of the account: a device session, or a password-only *link* session. Someone who knows the password can therefore
delete the account (but cannot read anything). This is deliberate: a user whose devices were all seized must still be able to delete
the account from a new device.
