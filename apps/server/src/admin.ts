// Operator CLI.
//
//   veil-admin replay-deletions   Re-apply Panic Reset deletions after restoring
//                                 data schemas from a backup (see DEPLOYMENT.md).
//   veil-admin sweep              Run the retention sweeper once.
//   veil-admin migrate            Apply pending schema migrations.

import { join } from 'node:path';
import { loadConfigFromEnv } from './config.js';
import { createPGliteDb, createPostgresDb } from './db.js';
import { FsBlobStore } from './blobstore.js';
import { replayDeletions } from './reset.js';
import { createServer } from './server.js';
import { deriveServerKeys } from './tokens.js';

async function main(): Promise<void> {
  const command = process.argv[2];
  const { config, databaseUrl, ephemeralSecret } = loadConfigFromEnv();
  if (command !== 'migrate' && ephemeralSecret) {
    throw new Error('VEIL_SERVER_SECRET must be set to the production secret for this command');
  }
  const db = databaseUrl ? await createPostgresDb(databaseUrl) : await createPGliteDb(join(config.dataDir, 'pg'));
  try {
    switch (command) {
      case 'migrate':
        console.log('migrations applied');
        break;
      case 'replay-deletions': {
        const r = await replayDeletions(db, deriveServerKeys(config.serverSecret));
        console.log(`replayed ledger: ${r.accountsDeleted} account(s) deleted again, ${r.usernamesRetired} username tag(s) re-retired`);
        break;
      }
      case 'sweep': {
        const server = await createServer({ config, db, blobStore: new FsBlobStore(join(config.dataDir, 'blobs')), sweepIntervalMs: 0 });
        await server.sweep();
        await server.close();
        console.log('sweep complete');
        break;
      }
      default:
        console.log('usage: veil-admin <migrate|replay-deletions|sweep>');
        process.exitCode = 2;
    }
  } finally {
    await db.close();
  }
}

main().catch((e: Error) => {
  console.error(`[veil-admin] ${e.message}`);
  process.exit(1);
});
