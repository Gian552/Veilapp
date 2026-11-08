import { describeError } from '../lib/errors';

export function ErrorText({ error }: { error: unknown }) {
  if (error === null || error === undefined) return null;
  return (
    <p className="error-text" role="alert">
      {describeError(error)}
    </p>
  );
}
