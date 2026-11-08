# Deploying VEIL

## Topology

```
client ──TLS──► Caddy (TLS, HSTS, no logs, strips identifying headers)
                 └──► veil server (Node 22, serves API + WebSocket + built SPA)
                        └──► PostgreSQL (internal network only, logging off)
                        └──► /data/blobs (encrypted attachment blobs)
```

`deploy/docker-compose.yml` implements exactly this. The server container is read-only, drops all capabilities and runs as non-root.

## Steps

1. `cp deploy/.env.example deploy/.env`, then fill it in. Generate the secret with
   `node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"`.
   **`VEIL_SERVER_SECRET` must be stable.** Changing it invalidates all sessions, makes fake prelogin salts differ (an
   enumeration signal during the switch), and breaks retired-username and ledger tags. Keep it in a secrets manager.
2. Point DNS for `VEIL_DOMAIN` at the host. Then run `docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d --build`.
3. On first start, Postgres runs `deploy/postgres/roles.sh`. It creates `veil_owner` (migrations), `veil_app` (DML only)
   and `veil_backup` (read access to data schemas only, no `ops`). The server applies migrations with
   `VEIL_MIGRATION_DATABASE_URL`, then serves as `veil_app`.
4. Check `https://VEIL_DOMAIN/healthz` → `{"ok":true}`, and that the response carries the CSP and HSTS headers.

Without Docker: `npm ci && npm run build`, then `NODE_ENV=production VEIL_SERVER_SECRET=… DATABASE_URL=… VEIL_WEB_DIST=apps/web/dist node apps/server/dist/main.js`
behind any TLS reverse proxy configured like `deploy/Caddyfile`.

## Logging policy (verify on every deployment)

| Layer | Setting |
|---|---|
| Caddy | no `log` directive (no access log); default logger `output discard`; admin API off |
| Docker | Caddy `logging: none`; app and Postgres use `local` with 1 MB rotation |
| VEIL server | Fastify logger disabled; only startup lines and `{level, code, route}` for errors |
| PostgreSQL | `log_connections=off`, `log_disconnections=off`, `log_statement=none`, `log_min_duration_statement=-1`, `track_activities=off` |
| Host | do not install log shippers, APM agents, error trackers or "security" agents that capture HTTP metadata |

**CDNs and DDoS protection** in front of VEIL terminate TLS and see client IPs and timing. If you must use one, choose one
that you can configure not to log, and document it publicly. The operator's privacy notice must name every such processor.

**Hosting provider:** the kernel, load balancer and provider network process client IPs transiently. This cannot be avoided
and should be stated honestly. Offering the service as a Tor onion service as well lets users avoid revealing their IP entirely.

## Configuration reference

See `docs/ARCHITECTURE.md` §8. Production refuses to start without `VEIL_SERVER_SECRET` and refuses `VEIL_RATE_LIMIT=off`.
Set `VEIL_TRUST_PROXY=true` only when a reverse proxy overwrites `X-Forwarded-For` (the provided Caddyfile does).
Client addresses are used only for in-memory rate-limit buckets under a rotating HMAC key.

Rate limits are kept **in memory per instance**. Running several instances requires sticky routing or a shared store,
which must keep the same no-persistence property (for example Redis with persistence off and short TTLs).

## Backups and restore

* `deploy/backup.sh` (cron, daily): `pg_dump` of the data schemas `identity auth keys mailbox media`, encrypted with
  `age` to an offline recipient key, with filenames at day precision. Files older than `VEIL_BACKUP_RETENTION_DAYS` (7) are shredded.
* The `ops` schema (deletion ledger, reset jobs) is **not** in the backup and must never be overwritten by a restore.
  Back it up separately or keep it replicated, because losing it together with the database weakens Panic Reset guarantees (PANIC_RESET.md).
* Restore:
  ```sh
  age -d -i key.txt veil-YYYYmmdd.dump.age > veil.dump
  pg_restore --clean --if-exists -n identity -n auth -n keys -n mailbox -n media -d veil veil.dump
  node apps/server/dist/admin.js replay-deletions   # mandatory: re-applies Panic Resets since the backup
  ```
* Attachment blobs (`/data/blobs`) hold only ciphertext and expire within 30 days. Back them up only if you must,
  and with the same retention.

## Operations

* `node apps/server/dist/admin.js sweep` runs retention cleanup on demand. It also runs hourly inside the server.
* PostgreSQL: keep autovacuum on. Old row versions and WAL can retain deleted data until vacuumed and recycled.
  Avoid long-term WAL archiving, or apply the backup retention to it too.
* Upgrades: rebuild from a tagged commit with `npm ci` (exact lockfile). Publish the SHA-256 of `apps/web/dist/assets/*`
  so users and auditors can compare it against their own reproducible build.
* `npm run audit:deps` before every release. The dependency surface is small on purpose; keep it that way.

## Local development

```sh
npm ci
VEIL_RATE_LIMIT=off npm run dev:server   # embedded PGlite in .veil-data/, ephemeral secret
npm run dev:web                          # Vite on :5173, proxies /v1 and the WebSocket
```
