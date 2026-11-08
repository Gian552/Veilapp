// Schema migrations, embedded so the bundled server is self-contained.
// Rules for every migration (enforced by test/schema.test.ts):
//  - no wall-clock creation/modification timestamps, IP addresses or user agents
//  - expiry is a coarse day number, except short-lived link requests
//  - every table referencing an account cascades on delete (Panic Reset is one DELETE)

import type { Db } from './db.js';

export interface Migration {
  version: number;
  sql: string;
}

export const MIGRATIONS: Migration[] = [
  {
    version: 1,
    sql: `
CREATE SCHEMA identity;
CREATE SCHEMA auth;
CREATE SCHEMA keys;
CREATE SCHEMA mailbox;
CREATE SCHEMA media;

CREATE TABLE identity.accounts (
  id uuid PRIMARY KEY,
  username text NOT NULL CHECK (username ~ '^[A-Z][a-z]{2,8}[A-Z][a-z]{2,8}$'),
  identity_key bytea NOT NULL CHECK (octet_length(identity_key) = 32),
  device_list bytea NOT NULL CHECK (octet_length(device_list) BETWEEN 1 AND 2048),
  device_list_sig bytea NOT NULL CHECK (octet_length(device_list_sig) = 64),
  device_list_version bigint NOT NULL CHECK (device_list_version >= 0),
  profile bytea CHECK (profile IS NULL OR octet_length(profile) BETWEEN 1 AND 4096)
);
CREATE UNIQUE INDEX accounts_username_ci ON identity.accounts (lower(username));

-- HMAC(serverKey, lower(username)) of usernames that must never be reissued.
CREATE TABLE identity.retired_usernames (
  tag bytea PRIMARY KEY CHECK (octet_length(tag) = 32)
);

CREATE TABLE auth.credentials (
  account_id uuid PRIMARY KEY REFERENCES identity.accounts(id) ON DELETE CASCADE,
  client_salt bytea NOT NULL CHECK (octet_length(client_salt) = 16),
  kdf_memory integer NOT NULL CHECK (kdf_memory > 0),
  kdf_iterations integer NOT NULL CHECK (kdf_iterations > 0),
  kdf_parallelism integer NOT NULL CHECK (kdf_parallelism > 0),
  verifier text NOT NULL CHECK (verifier LIKE '$argon2id$%')
);

CREATE TABLE auth.recovery (
  account_id uuid PRIMARY KEY REFERENCES identity.accounts(id) ON DELETE CASCADE,
  verifier text NOT NULL CHECK (verifier LIKE '$argon2id$%'),
  backup bytea NOT NULL CHECK (octet_length(backup) BETWEEN 1 AND 262144)
);

CREATE TABLE keys.devices (
  id bytea PRIMARY KEY CHECK (octet_length(id) = 16),
  account_id uuid NOT NULL REFERENCES identity.accounts(id) ON DELETE CASCADE,
  signing_key bytea NOT NULL CHECK (octet_length(signing_key) = 32),
  dh_key bytea NOT NULL CHECK (octet_length(dh_key) = 32),
  mailbox_seq bigint NOT NULL DEFAULT 0 CHECK (mailbox_seq >= 0)
);
CREATE INDEX devices_account ON keys.devices (account_id);

CREATE TABLE auth.sessions (
  id bytea PRIMARY KEY CHECK (octet_length(id) = 16),
  account_id uuid NOT NULL REFERENCES identity.accounts(id) ON DELETE CASCADE,
  device_id bytea REFERENCES keys.devices(id) ON DELETE CASCADE,
  kind text NOT NULL CHECK (kind IN ('device', 'link')),
  refresh_hash bytea NOT NULL UNIQUE CHECK (octet_length(refresh_hash) = 32),
  prev_refresh_hash bytea CHECK (prev_refresh_hash IS NULL OR octet_length(prev_refresh_hash) = 32),
  generation integer NOT NULL CHECK (generation > 0),
  expires_day integer NOT NULL,
  CHECK ((kind = 'device') = (device_id IS NOT NULL))
);
CREATE UNIQUE INDEX sessions_one_per_device ON auth.sessions (device_id) WHERE kind = 'device';
CREATE INDEX sessions_account ON auth.sessions (account_id);

CREATE TABLE keys.signed_prekeys (
  device_id bytea PRIMARY KEY REFERENCES keys.devices(id) ON DELETE CASCADE,
  key_id bigint NOT NULL CHECK (key_id BETWEEN 0 AND 4294967295),
  public_key bytea NOT NULL CHECK (octet_length(public_key) = 32),
  signature bytea NOT NULL CHECK (octet_length(signature) = 64)
);

CREATE TABLE keys.one_time_prekeys (
  device_id bytea NOT NULL REFERENCES keys.devices(id) ON DELETE CASCADE,
  key_id bigint NOT NULL CHECK (key_id BETWEEN 0 AND 4294967295),
  public_key bytea NOT NULL CHECK (octet_length(public_key) = 32),
  PRIMARY KEY (device_id, key_id)
);

-- Short-lived (10 min) device-linking relay; deleted on completion.
CREATE TABLE keys.link_requests (
  id bytea PRIMARY KEY CHECK (octet_length(id) = 16),
  account_id uuid NOT NULL REFERENCES identity.accounts(id) ON DELETE CASCADE,
  session_id bytea NOT NULL REFERENCES auth.sessions(id) ON DELETE CASCADE,
  request bytea NOT NULL CHECK (octet_length(request) BETWEEN 1 AND 1024),
  response bytea CHECK (response IS NULL OR octet_length(response) BETWEEN 1 AND 524288),
  expires_at bigint NOT NULL
);
CREATE INDEX link_requests_account ON keys.link_requests (account_id);

-- No sender column, by design (sealed sender).
CREATE TABLE mailbox.envelopes (
  device_id bytea NOT NULL REFERENCES keys.devices(id) ON DELETE CASCADE,
  envelope_id bytea NOT NULL CHECK (octet_length(envelope_id) = 16),
  seq bigint NOT NULL,
  payload bytea NOT NULL CHECK (octet_length(payload) BETWEEN 1 AND 262144),
  expires_day integer NOT NULL,
  PRIMARY KEY (device_id, envelope_id),
  UNIQUE (device_id, seq)
);

-- No owner column, by design: capability (id) + delete token only.
CREATE TABLE media.attachments (
  id bytea PRIMARY KEY CHECK (octet_length(id) = 16),
  delete_token_hash bytea NOT NULL CHECK (octet_length(delete_token_hash) = 32),
  remaining_downloads integer NOT NULL CHECK (remaining_downloads BETWEEN 0 AND 64),
  size integer NOT NULL CHECK (size >= 0),
  expires_day integer NOT NULL
);

-- ops is operational state; it is NOT restored from data backups.
CREATE TABLE ops.reset_jobs (
  id bytea PRIMARY KEY CHECK (octet_length(id) = 16),
  secret_hash bytea NOT NULL CHECK (octet_length(secret_hash) = 32),
  state text NOT NULL CHECK (state IN ('account_deleted', 'completed', 'partial')),
  deleted integer NOT NULL DEFAULT 0,
  pending integer NOT NULL DEFAULT 0,
  not_found integer NOT NULL DEFAULT 0,
  expires_day integer NOT NULL
);

CREATE TABLE ops.pending_blob_deletions (
  blob_id bytea PRIMARY KEY CHECK (octet_length(blob_id) = 16),
  job_id bytea
);

CREATE TABLE ops.deletion_ledger (
  account_tag bytea PRIMARY KEY CHECK (octet_length(account_tag) = 32),
  username_tag bytea NOT NULL CHECK (octet_length(username_tag) = 32),
  expires_day integer NOT NULL
);
`,
  },
];

export async function migrate(db: Db): Promise<void> {
  // Bootstrap DDL only when needed, so an up-to-date database can be used by a
  // role without CREATE privileges (deploy/postgres/roles.sql).
  const boot = await db.query<{ t: string | null }>("SELECT to_regclass('ops.schema_migrations')::text AS t");
  if (!boot.rows[0]?.t) {
    await db.exec('CREATE SCHEMA IF NOT EXISTS ops; CREATE TABLE IF NOT EXISTS ops.schema_migrations (version integer PRIMARY KEY);');
  }
  const applied = new Set((await db.query<{ version: number }>('SELECT version FROM ops.schema_migrations')).rows.map((r) => Number(r.version)));
  for (const m of MIGRATIONS) {
    if (applied.has(m.version)) continue;
    await db.transaction(async (tx) => {
      await tx.exec(m.sql);
      await tx.query('INSERT INTO ops.schema_migrations (version) VALUES ($1)', [m.version]);
    });
  }
}
