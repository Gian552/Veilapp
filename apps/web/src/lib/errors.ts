// Maps engine errors to user-facing text. Engine messages are already safe to
// show, but we prefer fixed wording for the common, security-relevant cases.

interface CodedError {
  code: string;
  message: string;
  retryAfterSeconds?: number;
}

function isCoded(err: unknown): err is CodedError {
  return typeof err === 'object' && err !== null && typeof (err as CodedError).code === 'string';
}

export function errorCode(err: unknown): string | null {
  return isCoded(err) ? err.code : null;
}

export function describeError(err: unknown): string {
  if (!isCoded(err)) return 'Something went wrong. Please try again.';
  switch (err.code) {
    case 'network':
      return 'The server could not be reached. Check your connection and try again.';
    case 'invalid_credentials':
      return 'Those credentials did not work.';
    case 'rate_limited':
      return err.retryAfterSeconds
        ? `Too many attempts. Try again in ${formatDuration(err.retryAfterSeconds)}.`
        : 'Too many attempts. Please wait a moment and try again.';
    case 'unauthorized':
      return 'Your session ended. Please sign in again.';
    case 'locked':
      return 'This device is locked. Unlock it with your password.';
    case 'internal':
      return 'Something went wrong. Please try again.';
    default:
      return err.message || 'Something went wrong. Please try again.';
  }
}

export function formatDuration(seconds: number): string {
  if (seconds < 60) return `${Math.ceil(seconds)} s`;
  const m = Math.ceil(seconds / 60);
  return m === 1 ? '1 minute' : `${m} minutes`;
}
