// HTTP transport. Tokens live only in this object's memory. Every response is
// validated against the shared contract before the engine uses it.

import { ErrorResponse, SessionResponse } from '@veil/shared';
import type { z } from '@veil/shared';
import { VeilError, type VeilErrorCode } from './errors.js';

export interface Tokens {
  accessToken: string;
  refreshToken: string;
}

const REQUEST_TIMEOUT_MS = 30_000;
const UPLOAD_TIMEOUT_MS = 120_000;

const CODE_MAP: Record<string, VeilErrorCode> = {
  unauthorized: 'unauthorized',
  forbidden: 'forbidden',
  not_found: 'not_found',
  conflict: 'conflict',
  rate_limited: 'rate_limited',
  bad_request: 'invalid_input',
  payload_too_large: 'invalid_input',
  internal: 'internal',
};

export class Api {
  private tokens: Tokens | null = null;
  private refreshing: Promise<boolean> | null = null;
  /** Called when the session can no longer be refreshed (revoked/expired). */
  onSessionLost: () => void = () => {};

  constructor(
    readonly baseUrl: string,
    private readonly fetchImpl: typeof fetch = globalThis.fetch.bind(globalThis),
  ) {}

  setTokens(t: Tokens | null) {
    this.tokens = t;
  }

  hasSession() {
    return this.tokens !== null;
  }

  accessToken() {
    return this.tokens?.accessToken ?? null;
  }

  async json<S extends z.ZodTypeAny>(
    method: string,
    path: string,
    body: unknown,
    schema: S,
    opts: { auth?: boolean } = {},
  ): Promise<z.infer<S>> {
    const res = await this.raw(method, path, body === undefined ? undefined : JSON.stringify(body), 'application/json', opts.auth ?? true);
    const data = res.status === 204 ? {} : await res.json().catch(() => ({}));
    const parsed = schema.safeParse(data);
    if (!parsed.success) throw new VeilError('internal', 'Unexpected response from server.');
    return parsed.data;
  }

  async send(method: string, path: string, body?: unknown, opts: { auth?: boolean } = {}): Promise<void> {
    await this.raw(method, path, body === undefined ? undefined : JSON.stringify(body), 'application/json', opts.auth ?? true);
  }

  /** Uploads raw bytes and parses a JSON response. */
  async upload<S extends z.ZodTypeAny>(path: string, bytes: Uint8Array, schema: S): Promise<z.infer<S>> {
    const res = await this.raw('POST', path, bytes, 'application/octet-stream', true);
    const parsed = schema.safeParse(await res.json().catch(() => ({})));
    if (!parsed.success) throw new VeilError('internal', 'Unexpected response from server.');
    return parsed.data;
  }

  async binary(method: string, path: string, body?: Uint8Array): Promise<Uint8Array> {
    const res = await this.raw(method, path, body, 'application/octet-stream', true);
    return new Uint8Array(await res.arrayBuffer());
  }

  private async raw(method: string, path: string, body: BodyInit | Uint8Array | undefined, contentType: string, auth: boolean, retried = false): Promise<Response> {
    const headers: Record<string, string> = {};
    if (body !== undefined) headers['content-type'] = contentType;
    if (auth && this.tokens) headers.authorization = `Bearer ${this.tokens.accessToken}`;
    let res: Response;
    try {
      res = await this.fetchImpl(this.baseUrl + path, {
        method,
        headers,
        body: body as BodyInit | undefined,
        credentials: 'omit',
        cache: 'no-store',
        referrerPolicy: 'no-referrer',
        // A stalled request must not hold the engine's mutex forever.
        signal: AbortSignal.timeout(contentType === 'application/octet-stream' ? UPLOAD_TIMEOUT_MS : REQUEST_TIMEOUT_MS),
      });
    } catch {
      throw new VeilError('network', 'The server could not be reached.');
    }
    if (res.status === 401 && auth && this.tokens && !retried) {
      if (await this.refresh()) return this.raw(method, path, body, contentType, auth, true);
    }
    if (!res.ok) throw await toError(res);
    return res;
  }

  /** Rotates the refresh token. Concurrent callers share one refresh. */
  async refresh(): Promise<boolean> {
    if (!this.tokens) return false;
    if (!this.refreshing) {
      const refreshToken = this.tokens.refreshToken;
      this.refreshing = (async () => {
        try {
          const res = await this.fetchImpl(this.baseUrl + '/v1/auth/refresh', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ refreshToken }),
            credentials: 'omit',
            cache: 'no-store',
            signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
          });
          if (!res.ok) {
            if (res.status === 401) {
              this.tokens = null;
              this.onSessionLost();
            }
            return false;
          }
          const s = SessionResponse.parse(await res.json());
          this.tokens = { accessToken: s.accessToken, refreshToken: s.refreshToken };
          return true;
        } catch {
          return false;
        } finally {
          this.refreshing = null;
        }
      })();
    }
    return this.refreshing;
  }
}

async function toError(res: Response): Promise<VeilError> {
  const retryAfter = Number(res.headers.get('retry-after')) || undefined;
  let code: VeilErrorCode = res.status === 429 ? 'rate_limited' : res.status >= 500 ? 'internal' : 'invalid_input';
  let message = 'The request failed.';
  try {
    const parsed = ErrorResponse.safeParse(await res.json());
    if (parsed.success) {
      code = CODE_MAP[parsed.data.error.code] ?? code;
      message = parsed.data.error.message;
    }
  } catch {
    // keep generic message
  }
  if (code === 'rate_limited') message = 'Too many attempts. Please wait and try again.';
  if (code === 'internal') message = 'The server encountered an error.';
  return new VeilError(code, message, retryAfter);
}
