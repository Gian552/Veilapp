import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// The dev server proxies the API so the app is always same-origin (no CORS,
// connect-src 'self'). Production serves the built files from the VEIL server
// or the reverse proxy with the strict CSP from docs/DEPLOYMENT.md.
const api = process.env.VEIL_DEV_API ?? 'http://127.0.0.1:8787';

export default defineConfig({
  plugins: [react()],
  server: {
    host: '127.0.0.1',
    port: 5173,
    proxy: {
      '/v1': { target: api, ws: true, changeOrigin: false },
      '/healthz': { target: api },
    },
  },
  build: {
    sourcemap: false,
    target: 'es2022',
    modulePreload: { polyfill: false },
    assetsInlineLimit: 0,
    // One bundle on purpose (crypto, Argon2id WASM, schemas): no lazy chunks fetched later.
    chunkSizeWarningLimit: 800,
  },
});
