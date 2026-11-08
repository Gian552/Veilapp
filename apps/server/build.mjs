// Bundles the server and the admin CLI into self-contained ESM files.
// Native / WASM-heavy packages stay external and are installed via npm ci.
import { build } from 'esbuild';

await build({
  entryPoints: { main: 'src/main.ts', admin: 'src/admin.ts' },
  outdir: 'dist',
  bundle: true,
  platform: 'node',
  target: 'node22',
  format: 'esm',
  sourcemap: false,
  legalComments: 'none',
  external: ['@node-rs/argon2', 'pg', '@electric-sql/pglite', 'pg-native'],
  banner: { js: "import { createRequire as __veilCreateRequire } from 'node:module'; const require = __veilCreateRequire(import.meta.url);" },
  logLevel: 'warning',
});
console.log('built apps/server/dist/{main,admin}.js');
