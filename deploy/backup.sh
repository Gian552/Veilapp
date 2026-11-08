#!/usr/bin/env bash
# Encrypted backup of VEIL's DATA schemas, with a hard retention window.
#
#  - Dumps only identity, auth, keys, mailbox, media. The `ops` schema (deletion
#    ledger, reset jobs) is deliberately excluded and must never be restored over
#    the live one: after a restore, `veil-admin replay-deletions` re-applies every
#    Panic Reset that happened after the backup was taken.
#  - Encrypts with age (https://age-encryption.org) to an offline recipient key;
#    the backup host never holds the decryption key. gpg works the same way.
#  - Deletes backups older than VEIL_BACKUP_RETENTION_DAYS (default 7). This value
#    is shown to users as the maximum time a deleted account can persist in backups.
#
# Restore (summary, see docs/DEPLOYMENT.md):
#   age -d -i key.txt veil-YYYYmmdd.dump.age > veil.dump
#   pg_restore --clean --if-exists -n identity -n auth -n keys -n mailbox -n media -d veil veil.dump
#   VEIL_SERVER_SECRET=... DATABASE_URL=... node apps/server/dist/admin.js replay-deletions
set -euo pipefail

: "${DATABASE_URL:?DATABASE_URL (veil_backup role, data schemas only) is required}"
: "${BACKUP_AGE_RECIPIENT:?BACKUP_AGE_RECIPIENT (age public key) is required}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/veil}"
RETENTION_DAYS="${VEIL_BACKUP_RETENTION_DAYS:-7}"

umask 077
mkdir -p "$BACKUP_DIR"
# Day granularity only: the file name must not reveal more than the backup schedule.
out="$BACKUP_DIR/veil-$(date -u +%Y%m%d).dump.age"

pg_dump "$DATABASE_URL" --format=custom --no-owner --no-privileges \
  -n identity -n auth -n keys -n mailbox -n media \
  | age -r "$BACKUP_AGE_RECIPIENT" > "$out.tmp"
mv "$out.tmp" "$out"

# Retention: anything older than the window is removed (shred where supported).
find "$BACKUP_DIR" -name 'veil-*.dump.age' -type f -mtime +"$((RETENTION_DAYS - 1))" -print0 \
  | xargs -0 -r sh -c 'for f; do shred -u "$f" 2>/dev/null || rm -f "$f"; done' sh
