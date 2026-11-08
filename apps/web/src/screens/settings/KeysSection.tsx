import { type FormEvent, useState } from 'react';
import { ErrorText } from '../../components/ErrorText';
import { PasswordFields, passwordsValid } from '../../components/PasswordFields';
import { RecoveryKeyConfirm, RecoveryKeyDisplay } from '../../components/RecoveryKey';
import { useClient, useSnapshot } from '../../lib/context';

export function KeysSection() {
  return (
    <>
      <h1>Keys &amp; recovery</h1>
      <p className="page-lede">Your password protects this device's vault and your sign-in. Your recovery key is the only fallback.</p>
      <Recovery />
      <ChangePassword />
    </>
  );
}

function Recovery() {
  const client = useClient();
  const snap = useSnapshot();
  const [newKey, setNewKey] = useState<string | null>(null);
  const [stage, setStage] = useState<'idle' | 'show' | 'confirm' | 'done' | 'confirm-disable'>('idle');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  async function create() {
    setBusy(true);
    setError(null);
    try {
      setNewKey(await client.enableRecovery());
      setStage('show');
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  async function disable() {
    setBusy(true);
    setError(null);
    try {
      await client.disableRecovery();
      setStage('idle');
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card" aria-labelledby="recovery-h">
      <div className="card-title">
        <h3 id="recovery-h">Recovery key</h3>
        {snap.recoveryEnabled ? <span className="badge">Enabled</span> : <span className="badge badge-warn">Not set up</span>}
      </div>
      <p className="small">
        The recovery key resets a forgotten password and restores your identity on a new device. The server stores only an
        encrypted backup it cannot open, plus a verifier for the key.
      </p>
      <div className="notice notice-warn">
        <div>
          <p>
            If you lose your password <em>and</em> your recovery key, or lose every primary device <em>and</em> your recovery key,
            your identity and message history are gone permanently. Nobody can restore them.
          </p>
        </div>
      </div>

      {stage === 'show' && newKey && (
        <>
          <p className="small">Write this key down now. It replaces any previous recovery key and is shown only once.</p>
          <RecoveryKeyDisplay recoveryKey={newKey} />
          <button type="button" className="btn btn-primary" onClick={() => setStage('confirm')}>
            I have written it down
          </button>
        </>
      )}
      {stage === 'confirm' && newKey && (
        <>
          <RecoveryKeyConfirm
            recoveryKey={newKey}
            onConfirmed={() => {
              setNewKey(null);
              setStage('done');
            }}
          />
          <button type="button" className="link-btn small" onClick={() => setStage('show')}>
            Show the key again
          </button>
        </>
      )}
      {stage === 'done' && (
        <p className="small" role="status">
          Recovery key confirmed. Any previous recovery key no longer works.
        </p>
      )}
      {stage === 'confirm-disable' && (
        <div className="notice notice-danger">
          <div>
            <strong>Disable recovery?</strong>
            <p>The encrypted backup and verifier are deleted from the server. A forgotten password can then never be reset.</p>
            <div className="btn-row">
              <button type="button" className="btn btn-danger-solid btn-sm" onClick={disable} disabled={busy}>
                Disable recovery
              </button>
              <button type="button" className="btn btn-ghost btn-sm" onClick={() => setStage('idle')}>
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
      {(stage === 'idle' || stage === 'done') && (
        <div className="btn-row">
          <button type="button" className="btn" onClick={create} disabled={busy || !snap.isPrimary}>
            {snap.recoveryEnabled ? 'Replace recovery key' : 'Create recovery key'}
          </button>
          {snap.recoveryEnabled && (
            <button type="button" className="btn btn-danger" onClick={() => setStage('confirm-disable')} disabled={busy || !snap.isPrimary}>
              Disable
            </button>
          )}
        </div>
      )}
      {!snap.isPrimary && <p className="xsmall muted">Recovery can only be managed from a primary device, which holds the identity key.</p>}
      <ErrorText error={error} />
    </section>
  );
}

function ChangePassword() {
  const client = useClient();
  const [current, setCurrent] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [submitted, setSubmitted] = useState(false);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState<unknown>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setSubmitted(true);
    setDone(false);
    if (!current || !passwordsValid(password, confirm)) return;
    setBusy(true);
    setError(null);
    try {
      await client.changePassword(current, password);
      setCurrent('');
      setPassword('');
      setConfirm('');
      setSubmitted(false);
      setDone(true);
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card" aria-labelledby="pw-h">
      <h3 id="pw-h">Change password</h3>
      <p className="small muted">
        Changing your password re-encrypts this device's vault and signs out every other session. Other devices will ask for the
        new password when they sign in again.
      </p>
      <form onSubmit={submit} noValidate aria-busy={busy}>
        <div className="field">
          <label htmlFor="pw-current">Current password</label>
          <input id="pw-current" className="input" type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} />
        </div>
        <PasswordFields password={password} confirm={confirm} onPassword={setPassword} onConfirm={setConfirm} label="New password" showErrors={submitted} />
        <ErrorText error={error} />
        {done && (
          <p className="field-hint" role="status">
            Password changed. Other sessions were signed out.
          </p>
        )}
        <button type="submit" className="btn btn-primary" disabled={busy}>
          {busy ? 'Changing…' : 'Change password'}
        </button>
      </form>
    </section>
  );
}
