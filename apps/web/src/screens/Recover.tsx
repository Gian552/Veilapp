import { type FormEvent, useState } from 'react';
import { FlowLayout } from '../components/FlowLayout';
import { IconBack } from '../components/Icons';
import { ErrorText } from '../components/ErrorText';
import { PasswordFields, passwordsValid } from '../components/PasswordFields';
import { useClient } from '../lib/context';

/** Forgotten password: only possible with the recovery key. */
export function Recover({ onBack }: { onBack: () => void }) {
  const client = useClient();
  const [username, setUsername] = useState('');
  const [recoveryKey, setRecoveryKey] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [submitted, setSubmitted] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setSubmitted(true);
    if (!username.trim() || !recoveryKey.trim() || !passwordsValid(password, confirm)) return;
    setBusy(true);
    setError(null);
    try {
      await client.recoverAccount({ username: username.trim(), recoveryKey: recoveryKey.trim(), newPassword: password });
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <FlowLayout>
      <div className="back-row">
        <button type="button" className="btn btn-ghost btn-sm" onClick={onBack}>
          <IconBack size={16} />
          Back to sign in
        </button>
      </div>
      <h1>Recover your account</h1>
      <p className="flow-lede">
        Your password can only be replaced with your recovery key. The key also decrypts the backup of your identity, so
        this device becomes your primary device.
      </p>
      <div className="notice notice-info">
        <div>
          <p>
            Message history is stored only on your devices and is not part of the backup. Devices that are still signed in
            will be signed out. Without the recovery key, there is no way to reset the password.
          </p>
        </div>
      </div>
      <form onSubmit={submit} noValidate aria-busy={busy}>
        <div className="field">
          <label htmlFor="recover-username">Username</label>
          <input
            id="recover-username"
            className="input"
            autoComplete="username"
            autoCapitalize="none"
            spellCheck={false}
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
        </div>
        <div className="field">
          <label htmlFor="recover-key">Recovery key</label>
          <textarea
            id="recover-key"
            className="textarea input mono"
            rows={3}
            autoComplete="off"
            autoCapitalize="characters"
            spellCheck={false}
            value={recoveryKey}
            onChange={(e) => setRecoveryKey(e.target.value)}
          />
          <span className="field-hint">13 groups of 4 characters. Dashes and spaces are optional.</span>
        </div>
        <PasswordFields password={password} confirm={confirm} onPassword={setPassword} onConfirm={setConfirm} label="New password" showErrors={submitted} />
        <ErrorText error={error} />
        <button type="submit" className="btn btn-primary btn-block" disabled={busy}>
          {busy ? 'Recovering…' : 'Recover account'}
        </button>
      </form>
    </FlowLayout>
  );
}
