// Assembles the Fastify application. Logging is disabled at the framework
// level; the only log sink is `ctx.log`, which receives event names and error
// codes, never request data (docs/ARCHITECTURE.md §7).

import { existsSync } from 'node:fs';
import { join } from 'node:path';
import fastifyStatic from '@fastify/static';
import fastifyWebsocket from '@fastify/websocket';
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify';
import { type PublicConfig, WsClientFrame, type WsServerFrame } from '@veil/shared';
import { type BlobStore, FsBlobStore, MemoryBlobStore } from './blobstore.js';
import { type ServerConfig, defaultConfig, mergeConfig } from './config.js';
import { type Ctx, type LogEntry, PasswordHasher, authenticateToken, limitByAddress } from './context.js';
import { type Db, createMemoryDb } from './db.js';
import { ApiError } from './errors.js';
import { Hub } from './hub.js';
import { ExpiringSet, RateLimiter } from './ratelimit.js';
import { registerResetRoutes, sweep } from './reset.js';
import { registerAccountRoutes } from './routes/account.js';
import { registerAuthRoutes } from './routes/auth.js';
import { registerMessagingRoutes } from './routes/messaging.js';
import { deriveServerKeys } from './tokens.js';

export interface ServerOptions {
  config?: Partial<ServerConfig>;
  /** If omitted, an in-memory PGlite database (and in-memory blob store) is used. */
  db?: Db;
  blobStore?: BlobStore;
  /** Clock in milliseconds (tests inject this to exercise expiry). */
  now?: () => number;
  log?: (e: LogEntry) => void;
  /** Interval for the retention sweeper; 0 disables the timer (sweep() can still be called). */
  sweepIntervalMs?: number;
}

export interface VeilServer {
  app: FastifyInstance;
  db: Db;
  config: ServerConfig;
  listen(o?: { host?: string; port?: number }): Promise<string>;
  close(): Promise<void>;
  sweep(): Promise<void>;
}

export const CONTENT_SECURITY_POLICY = [
  "default-src 'self'",
  "script-src 'self' 'wasm-unsafe-eval'",
  "style-src 'self'",
  "img-src 'self' blob: data:",
  "media-src 'self' blob:",
  "font-src 'self'",
  "connect-src 'self'",
  "worker-src 'self' blob:",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join('; ');

const SECURITY_HEADERS: Record<string, string> = {
  'content-security-policy': CONTENT_SECURITY_POLICY,
  'referrer-policy': 'no-referrer',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-resource-policy': 'same-origin',
  'permissions-policy':
    'camera=(), microphone=(), geolocation=(), payment=(), usb=(), bluetooth=(), serial=(), hid=(), interest-cohort=(), browsing-topics=()',
  'x-dns-prefetch-control': 'off',
};

function defaultLog(e: LogEntry): void {
  console.error(JSON.stringify(e));
}

function sendError(reply: FastifyReply, err: ApiError): FastifyReply {
  if (err.retryAfter !== undefined) reply.header('retry-after', String(err.retryAfter));
  return reply.code(err.status).send({ error: { code: err.code, message: err.message } });
}

export async function createServer(opts: ServerOptions = {}): Promise<VeilServer> {
  const config = mergeConfig(defaultConfig(), opts.config);
  const now = opts.now ?? (() => Date.now());
  const ownDb = !opts.db;
  const db = opts.db ?? (await createMemoryDb());
  const blobs = opts.blobStore ?? (ownDb ? new MemoryBlobStore() : new FsBlobStore(join(config.dataDir, 'blobs')));
  const hub = new Hub();

  const ctx: Ctx = {
    db,
    config,
    keys: deriveServerKeys(config.serverSecret),
    blobs,
    hub,
    limiter: new RateLimiter(now, config.rateLimit.enabled),
    usedChallenges: new ExpiringSet(now),
    usedNonces: new ExpiringSet(now),
    passwords: new PasswordHasher(config.serverArgon2),
    now,
    log: opts.log ?? defaultLog,
  };

  const app = Fastify({
    // No framework logger at all (this also means no request logging);
    // errors go only to ctx.log, which never receives request data.
    logger: false,
    trustProxy: config.trustProxy,
    bodyLimit: 1024 * 1024,
    requestIdHeader: false,
    return503OnClosing: true,
  });

  app.addContentTypeParser('application/octet-stream', { parseAs: 'buffer', bodyLimit: config.attachmentMaxBytes }, (_req, body, done) => {
    done(null, new Uint8Array(body as Buffer));
  });

  app.addHook('onRequest', async (req: FastifyRequest) => {
    if (req.url.startsWith('/v1/')) limitByAddress(req, ctx, 'global');
  });

  app.addHook('onSend', async (req, reply, payload) => {
    for (const [k, v] of Object.entries(SECURITY_HEADERS)) reply.header(k, v);
    if (req.url.startsWith('/v1') || req.url === '/healthz') {
      reply.header('cache-control', 'no-store');
      reply.header('pragma', 'no-cache');
    }
    reply.removeHeader('x-powered-by');
    return payload;
  });

  app.setErrorHandler((err: Error & { statusCode?: number; code?: string }, req, reply) => {
    if (err instanceof ApiError) return sendError(reply, err);
    if (err.statusCode === 413 || err.code === 'FST_ERR_CTP_BODY_TOO_LARGE') {
      return sendError(reply, new ApiError('payload_too_large', 'Request too large.'));
    }
    if (err.statusCode && err.statusCode >= 400 && err.statusCode < 500) {
      return sendError(reply, new ApiError('bad_request', 'Invalid request.'));
    }
    ctx.log({ level: 'error', event: 'unhandled_error', code: err.code ?? err.name, route: req.routeOptions?.url });
    return sendError(reply, new ApiError('internal', 'Internal error.'));
  });

  await app.register(fastifyWebsocket, { options: { maxPayload: 4096 } });

  app.get('/healthz', async () => ({ ok: true }));

  app.get('/v1/config', async (): Promise<PublicConfig> => {
    const r = config.retention;
    return {
      registrationPowDifficulty: config.powDifficulty,
      minimumKdf: { ...config.minimumKdf },
      recommendedKdf: { ...config.recommendedKdf },
      attachmentMaxBytes: config.attachmentMaxBytes,
      retention: {
        undeliveredMessageDays: r.undeliveredMessageDays,
        attachmentDays: r.attachmentDays,
        sessionDays: r.sessionDays,
        backupDays: r.backupDays,
        resetJobDays: r.resetJobDays,
      },
    };
  });

  app.get('/v1/ws', { websocket: true }, (socket, _req) => {
    let authed = false;
    let detach: (() => void) | null = null;
    const send = (f: WsServerFrame) => socket.send(JSON.stringify(f));
    const timer = setTimeout(() => {
      if (!authed) socket.close(4000, 'auth timeout');
    }, 10_000);
    socket.on('message', async (raw: Buffer) => {
      let frame: WsClientFrame;
      try {
        frame = WsClientFrame.parse(JSON.parse(raw.toString('utf8')));
      } catch {
        socket.close(4002, 'bad frame');
        return;
      }
      if (frame.type === 'ping') {
        if (authed) send({ type: 'pong' });
        return;
      }
      if (authed) return;
      const s = await authenticateToken(frame.accessToken, ctx).catch(() => null);
      if (!s) {
        socket.close(4001, 'unauthorized');
        return;
      }
      authed = true;
      clearTimeout(timer);
      detach = hub.add(socket, s.sessionId, s.accountId, s.deviceId);
      send({ type: 'ready' });
    });
    socket.on('close', () => {
      clearTimeout(timer);
      detach?.();
    });
  });

  registerAuthRoutes(app, ctx);
  registerAccountRoutes(app, ctx);
  registerMessagingRoutes(app, ctx);
  registerResetRoutes(app, ctx);

  const webDist = config.webDist && existsSync(join(config.webDist, 'index.html')) ? config.webDist : undefined;
  if (webDist) {
    await app.register(fastifyStatic, {
      root: webDist,
      prefix: '/',
      index: false,
      setHeaders(res, path) {
        res.header('cache-control', path.endsWith('.html') ? 'no-cache' : 'public, max-age=31536000, immutable');
      },
    });
    app.get('/', (_req, reply) => reply.header('cache-control', 'no-cache').sendFile('index.html'));
  }

  app.setNotFoundHandler((req, reply) => {
    if (webDist && req.method === 'GET' && !req.url.startsWith('/v1') && req.url !== '/healthz') {
      return reply.header('cache-control', 'no-cache').sendFile('index.html');
    }
    return sendError(reply, new ApiError('not_found', 'Not found.'));
  });

  const interval = opts.sweepIntervalMs ?? 3_600_000;
  const timer = interval > 0 ? setInterval(() => sweep(ctx).catch(() => ctx.log({ level: 'error', event: 'sweep_failed' })), interval) : null;
  timer?.unref();

  return {
    app,
    db,
    config,
    async listen(o = {}) {
      const host = o.host ?? config.host;
      await app.listen({ host, port: o.port ?? 0 });
      const addr = app.server.address();
      const port = typeof addr === 'object' && addr ? addr.port : config.port;
      return `http://${host.includes(':') ? `[${host}]` : host}:${port}`;
    },
    async close() {
      if (timer) clearInterval(timer);
      hub.closeAll();
      await app.close();
      if (ownDb) await db.close();
    },
    sweep: () => sweep(ctx),
  };
}
