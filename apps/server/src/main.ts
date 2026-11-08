// Production entrypoint. Configuration comes from the environment only
// (docs/ARCHITECTURE.md §8). Nothing about requests is ever printed.

import { join } from 'node:path';
import { existsSync, mkdirSync } from 'node:fs';
import { loadConfigFromEnv } from './config.js';
import { createPGliteDb, createPostgresDb } from './db.js';
import { FsBlobStore } from './blobstore.js';
import { createServer } from './server.js';

async function main(): Promise<void> {
  const { config, databaseUrl, ephemeralSecret } = loadConfigFromEnv();
  if (ephemeralSecret) {
    console.warn('[veil] VEIL_SERVER_SECRET not set: using an ephemeral secret (development only; sessions end on restart).');
  }
  mkdirSync(config.dataDir, { recursive: true, mode: 0o700 });
  if (process.env.VEIL_MIGRATION_DATABASE_URL) {
    // Apply migrations with the schema-owner role; the app itself runs as a DML-only role.
    const owner = await createPostgresDb(process.env.VEIL_MIGRATION_DATABASE_URL);
    await owner.close();
  }
  const db = databaseUrl ? await createPostgresDb(databaseUrl) : await createPGliteDb(join(config.dataDir, 'pg'));
  const server = await createServer({ config, db, blobStore: new FsBlobStore(join(config.dataDir, 'blobs')) });
  await server.sweep();
  const url = await server.listen({ host: config.host, port: config.port });
  const servingWeb = !!config.webDist && existsSync(join(config.webDist, 'index.html'));
  console.log(`[veil] listening on ${url}${servingWeb ? ' (serving web app)' : ''}`);

  let stopping = false;
  const shutdown = async () => {
    if (stopping) return;
    stopping = true;
    // Bounded graceful shutdown: lingering keep-alive or WebSocket peers must
    // not keep the process (and the port) alive indefinitely.
    setTimeout(() => process.exit(0), 5000).unref();
    await server.close().catch(() => {});
    await db.close().catch(() => {});
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

main().catch((e: Error) => {
  // Startup errors only (config / database); no request data can be involved.
  console.error(`[veil] failed to start: ${e.message}`);
  process.exit(1);
});
