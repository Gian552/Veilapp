-- Re-runnable grants for the backup role, after migrations created the schemas:
--   psql -U veil_owner -d veil -f deploy/postgres/grants.sql
\set ON_ERROR_STOP on
GRANT USAGE ON SCHEMA identity, auth, keys, mailbox, media TO veil_backup;
GRANT SELECT ON ALL TABLES IN SCHEMA identity, auth, keys, mailbox, media TO veil_backup;
REVOKE ALL ON SCHEMA ops FROM veil_backup;
REVOKE ALL ON ALL TABLES IN SCHEMA ops FROM veil_backup;
-- veil_app must never create objects.
REVOKE CREATE ON SCHEMA identity, auth, keys, mailbox, media, ops FROM veil_app;
