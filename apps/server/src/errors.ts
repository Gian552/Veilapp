import type { ErrorCode, z } from '@veil/shared';

const STATUS: Record<ErrorCode, number> = {
  bad_request: 400,
  unauthorized: 401,
  forbidden: 403,
  not_found: 404,
  conflict: 409,
  payload_too_large: 413,
  rate_limited: 429,
  internal: 500,
};

/** An error whose code and message are safe to send to clients. */
export class ApiError extends Error {
  readonly status: number;

  constructor(
    readonly code: ErrorCode,
    message: string,
    readonly retryAfter?: number,
  ) {
    super(message);
    this.status = STATUS[code];
  }
}

export const Errors = {
  badRequest: () => new ApiError('bad_request', 'Invalid request.'),
  /** The single message used for every credential failure. */
  invalidCredentials: () => new ApiError('unauthorized', 'Invalid username or password.'),
  unauthorized: () => new ApiError('unauthorized', 'Authentication required.'),
  forbidden: (msg = 'Not allowed.') => new ApiError('forbidden', msg),
  notFound: () => new ApiError('not_found', 'Not found.'),
  conflict: (msg = 'Conflict.') => new ApiError('conflict', msg),
  rateLimited: (retryAfter: number) => new ApiError('rate_limited', 'Too many requests. Try again later.', retryAfter),
};

export function parse<T>(schema: z.ZodType<T>, data: unknown): T {
  const r = schema.safeParse(data);
  if (!r.success) throw Errors.badRequest();
  return r.data;
}
