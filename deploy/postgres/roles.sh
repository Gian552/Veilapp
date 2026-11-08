#!/usr/bin/env bash
# Least-privilege roles for VEIL, run once by the postgres image on first start
# (docker-entrypoint-initdb.d) as the owner role `veil_owner`.
#
#   veil_owner  owns all schemas; used only to apply migrations at server start
#               (VEIL_MIGRATION_DATABASE_URL).
#   veil_app    DML only on VEIL tables; no DDL, cannot create schemas or tables.
#   veil_backup read-only on the DATA schemas (identity auth keys mailbox media);
#               no access to `ops` (deletion ledger, reset jobs), which must never
#               be restored from a backup. Grant it with grants.sql after the first
#               migration has created the schemas.
set -euo pipefail
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v app_pw="$VEIL_APP_DB_PASSWORD" -v backup_pw="$VEIL_BACKUP_DB_PASSWORD" <<'SQL'
CREATE ROLE veil_app LOGIN PASSWORD :'app_pw';
CREATE ROLE veil_backup LOGIN PASSWORD :'backup_pw';
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE CREATE ON DATABASE veil FROM PUBLIC;
-- Schemas and tables created later by veil_owner (migrations) are usable by veil_app.
ALTER DEFAULT PRIVILEGES FOR ROLE veil_owner GRANT USAGE ON SCHEMAS TO veil_app;
ALTER DEFAULT PRIVILEGES FOR ROLE veil_owner GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO veil_app;
-- Logging hardening (also passed as command flags in docker-compose.yml).
ALTER SYSTEM SET log_connections = off;
ALTER SYSTEM SET log_disconnections = off;
ALTER SYSTEM SET log_statement = 'none';
ALTER SYSTEM SET log_min_error_statement = 'panic';
ALTER SYSTEM SET log_line_prefix = '';
ALTER SYSTEM SET track_activities = off;
SQL
