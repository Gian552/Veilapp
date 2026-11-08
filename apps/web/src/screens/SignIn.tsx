import { type FormEvent, useState } from 'react';
import { FlowLayout } from '../components/FlowLayout';
import { ErrorText } from '../components/ErrorText';
import { ProgressSteps } from '../components/ProgressSteps';
import { useClient } from '../lib/context';
import { errorCode, formatDuration } from '../lib/errors';
import { useRetryAfter } from '../lib/useRetryAfter';
import { Recover } from './Recover';

interface Props {
  /** 'unlock': this device has a locked vault. 'signin': no vault here yet. */
  mode: 'unlock' | 'signin';
  onCreateInstead?: () => void;
}

export function SignIn({ mode, onCreateInstead }: Props) {
  const client = useClient();
  const [view, setView] = useState<'form' | 'recover'>('form');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [previousPassword, setPreviousPassword] = useState('');
  const [trouble, setTrouble] = useState(false);
  const [eraseConfirm, setEraseConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  const retry = useRetryAfter();

  if (view === 'recover') return <Recover onBack={() => setView('form')} />;

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!username.trim() || !password || retry.blocked) return;
    setBusy(true);
    setError(null);
    try {
      await client.signIn({
        username: username.trim(),
        password,
        ...(previousPassword ? { previousPassword } : {}),
        onProgress: setProgress,
      });
      // The snapshot status now drives the next screen.
    } catch (err) {
      setError(err);
      if (errorCode(err) === 'rate_limited') retry.block((err as { retryAfterSeconds?: number }).retryAfterSeconds);
      setPassword('');
      setPreviousPassword('');
      // This device was refused although the password unlocked it: offer the recovery options.
      if (mode === 'unlock' && errorCode(err) === 'unauthorized') setTrouble(true);
    } finally {
      setBusy(false);
      setProgress(null);
    }
  }

  async function erase() {
    if (eraseConfirm !== 'ERASE') return;
    setBusy(true);
    setError(null);
    try {
      await client.eraseLocalData();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <FlowLayout>
      <h1>{mode === 'unlock' ? 'Unlock VEIL' : 'Sign in'}</h1>
      <p className="flow-lede">
        {mode === 'unlock'
          ? 'Your data on this device is encrypted. Enter your username and password to unlock it.'
          : 'Sign in on this device. You will then link it from a device you already use, or restore it with your recovery key.'}
      </p>
      <form onSubmit={submit} noValidate aria-busy={busy}>
        <div className="field">
          <label htmlFor="signin-username">Username</label>
          <input
            id="signin-username"
            className="input"
            autoComplete="username"
            autoCapitalize="none"
            spellCheck={false}
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
          />
        </div>
        <div className="field">
          <label htmlFor="signin-password">Password</label>
          <input
            id="signin-password"
            className="input"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        </div>
        {mode === 'unlock' && trouble && (
          <div className="field">
            <label htmlFor="signin-previous">Previous password (only if you changed it on another device)</label>
            <input
              id="signin-previous"
              className="input"
              type="password"
              autoComplete="off"
              value={previousPassword}
              onChange={(e) => setPreviousPassword(e.target.value)}
            />
            <p className="field-hint">
              This device is still sealed with the password it had when you last unlocked it here. Enter your current password above and the
              previous one here, once.
            </p>
          </div>
        )}
        {errorCode(error) === 'unauthorized' ? (
          <p className="error-text" role="alert">
            {(error as Error).message}
          </p>
        ) : (
          <ErrorText error={error} />
        )}
        {retry.blocked && (
          <p className="field-hint" aria-live="polite">
            You can try again in {formatDuration(retry.remaining)}.
          </p>
        )}
        {busy && (
          <div aria-live="polite">
            <ProgressSteps label="Sign-in progress" steps={[{ label: progress ?? 'Deriving keys from your password', state: 'active' }]} />
          </div>
        )}
        <button type="submit" className="btn btn-primary btn-block" disabled={busy || retry.blocked || !username.trim() || !password}>
          {busy ? 'Working…' : mode === 'unlock' ? 'Unlock' : 'Sign in'}
        </button>
      </form>
      {mode === 'unlock' && trouble && (
        <section className="card danger-zone" aria-labelledby="erase-heading">
          <h3 id="erase-heading">Erase this device</h3>
          <p>
            If you used Panic Reset on another device, this device can no longer sign in. Erasing removes every VEIL key and message stored
            here. It cannot be undone, and it does not delete anything on the server.
          </p>
          <div className="field">
            <label htmlFor="erase-confirm">
              Type <strong>ERASE</strong> to confirm
            </label>
            <input id="erase-confirm" className="input" autoComplete="off" value={eraseConfirm} onChange={(e) => setEraseConfirm(e.target.value)} />
          </div>
          <button type="button" className="btn btn-danger" disabled={busy || eraseConfirm !== 'ERASE'} onClick={erase}>
            Erase this device
          </button>
        </section>
      )}
      <div className="flow-foot">
        <button type="button" className="link-btn" onClick={() => setView('recover')}>
          Forgot your password?
        </button>
        {mode === 'unlock' && !trouble && (
          <>
            {' · '}
            <button type="button" className="link-btn" onClick={() => setTrouble(true)}>
              Can’t sign in on this device?
            </button>
          </>
        )}
        {onCreateInstead && (
          <>
            {' · '}
            <button type="button" className="link-btn" onClick={onCreateInstead}>
              Create a new identity
            </button>
          </>
        )}
      </div>
    </FlowLayout>
  );
}
